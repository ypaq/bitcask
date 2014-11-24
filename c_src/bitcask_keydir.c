// -------------------------------------------------------------------
//
// Copyright (c) 2014 Basho Technologies, Inc. All Rights Reserved.
//
// This file is provided to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file
// except in compliance with the License.  You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//
// -------------------------------------------------------------------

#include "bitcask_keydir.h"
#include "bitcask_atomic.h"
//#define BITCASK_DEBUG
#include "bitcask_debug.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/mman.h>
                           
#include "murmurhash.h"

// These correspond with entry layout in memory
#define ENTRY_FILE_ID_OFFSET 0
#define ENTRY_TOTAL_SIZE_OFFSET 4
#define ENTRY_EPOCH_OFFSET 8
#define ENTRY_OFFSET_OFFSET 16
#define ENTRY_TIMESTAMP_OFFSET 24
#define ENTRY_NEXT_OFFSET 28
#define ENTRY_KEY_SIZE_OFFSET 32
#define ENTRY_KEY_OFFSET 36

// The size of a zero length key entry
#define BASE_ENTRY_SIZE ENTRY_KEY_OFFSET

#define PAGE_SIZE 4096

#define kh_put2(name, h, k, v) {                        \
        int itr_status;                                 \
        khiter_t itr = kh_put(name, h, k, &itr_status); \
        kh_val(h, itr) = v; }

static void free_swap_array(swap_array_t * swap_array)
{
    uint32_t idx;

    if (swap_array)
    {
        free_swap_array(swap_array->next);

        for (idx = 0; idx < swap_array->size; ++idx)
        {
            munmap(swap_array->pages[idx].data, PAGE_SIZE);
        }

        free(swap_array->pages);
        free(swap_array);
    }
}

static void free_fstats_handle(fstats_handle_t * handle)
{
    if (handle->fstats)
    {
        free_fstats(handle->fstats);
    }

    if (handle->mutex)
    {
        enif_mutex_destroy(handle->mutex);
    }
}

void free_fstats(fstats_hash_t * fstats)
{
    kh_destroy(fstats, fstats);
}

static void keydir_free_memory(bitcask_keydir * keydir)
{
    uint32_t idx;

    if (keydir->swap_file_desc > -1)
    {
        // Truncating will avoid dirty memory mapped pages from being written
        // to disk unnecessarily.
        ftruncate(keydir->swap_file_desc, 0);
        close(keydir->swap_file_desc);
    }

    for(idx = 0; idx < keydir->num_pages; ++idx)
    {
        free(keydir->mem_pages[idx].itr_array.items);
    }

    if (keydir->mutex)
    {
        enif_mutex_destroy(keydir->mutex);
        keydir->mutex = NULL;
    }

    if (keydir->swap_grow_mutex)
    {
        enif_mutex_destroy(keydir->swap_grow_mutex);
        keydir->swap_grow_mutex = NULL;
    }

    for (idx = 0; idx < keydir->num_fstats; ++idx)
    {
        free_fstats_handle(keydir->fstats_array + idx);
    }

    free(keydir->mem_pages);
    keydir->mem_pages = NULL;
    free(keydir->fstats_array);
    keydir->fstats_array = NULL;
    free(keydir->buffer);
    keydir->buffer = NULL;
    free_swap_array(keydir->swap_pages);
    keydir->swap_pages = NULL;
    free(keydir->tmp_fstats);
    keydir->tmp_fstats = NULL;
    free_fstats(keydir->fstats);
    keydir->fstats = NULL;
    free(keydir->name);
    keydir->name = NULL;
    free(keydir->dirname);
    keydir->dirname = NULL;
}

static void keydir_init_free_list(bitcask_keydir * keydir)
{
    // Skip around the pages array to populate
    uint32_t idx = 0;
    uint32_t next_idx;
    uint32_t n = keydir->num_pages;
    const uint32_t step = 16;
    uint32_t offset = 0;

    // Notice this will fail miserably if num_pages is ever zero
    keydir->free_list_head = 0;

    // Set next index on all but last page in sequence
    while (--n)
    {
        next_idx = idx + step;
        if (next_idx >= keydir->num_pages)
        {
            next_idx = ++offset;
        }
        keydir->mem_pages[idx].page.next_free = next_idx;
        idx = next_idx;
    }

    // And point the last one to nowhere
    keydir->mem_pages[idx].page.next_free = MAX_PAGE_IDX;
}

void keydir_init_mem_pages(bitcask_keydir * keydir)
{
    uint32_t idx;
    mem_page_t * p;

    for (idx = 0, p= keydir->mem_pages;
         idx < keydir->num_pages;
         ++idx, ++p)
    {
        p->page.mutex = enif_mutex_create(0);
        p->page.data  = keydir->buffer + PAGE_SIZE * idx;
        p->page.prev = MAX_PAGE_IDX;
        p->page.next = MAX_PAGE_IDX;
        p->page.next_free = MAX_PAGE_IDX;
        p->page.is_free = 1;

        p->size = 0;
        p->alt_idx = MAX_PAGE_IDX;
        p->dead_bytes = 0;
        p->is_borrowed = 0;

        p->itr_array.count = 0;
        p->itr_array.size = 0;
        p->itr_array.items = NULL;
    }
}

static int open_swap_file(const char * basedir)
{
    int swap_fd;
    // The joy that is manipulating strings in C
    const char * extra_path = "/bitcask.swap";
    const int extra_length = strlen(extra_path);
    const int basedir_length = strlen(basedir);
    char * swap_path = malloc(basedir_length + extra_length + 1);

    if (swap_path)
    {
        strcpy(swap_path, basedir);
        memcpy(swap_path + basedir_length, extra_path, extra_length + 1);
        swap_fd = open(swap_path, O_CREAT|O_TRUNC|O_RDWR, 0600);

        // Hide swap file from users.
        // TODO: Add option to keep it visible for debugging.
        if (swap_fd >= 0)
        {
            unlink(swap_path);
        }
    
        free(swap_path);
    }
    else
    {
        swap_fd = -1;
    }

    return swap_fd;
}

static unsigned default_fstats_idx_fun()
{
    return rand();
}

#define KEYDIR_DEFAULT_NUM_PAGES 1024
#define KEYDIR_DEFAULT_NUM_INITIAL_SWAP_PAGES 1024

void keydir_default_init_params(keydir_init_params_t * params)
{
    params->basedir = ".";
    params->num_pages = KEYDIR_DEFAULT_NUM_PAGES;
    params->initial_num_swap_pages = KEYDIR_DEFAULT_NUM_INITIAL_SWAP_PAGES;
    params->fstats_idx_fun = default_fstats_idx_fun;
    params->num_fstats = 64;
}

/*
 * Returns an errno code or zero if successful. 
 */
static int keydir_init(bitcask_keydir * keydir,
                       const char * name,
                       global_keydir_data * global_data,
                       keydir_init_params_t * params)

{
    uint32_t i;

    // Init pointers to NULL so it's safe to call keydir_free_memory() when
    // only partially initialized.
    keydir->mutex = NULL;
    keydir->swap_grow_mutex = NULL;
    keydir->swap_pages = NULL;
    keydir->swap_file_desc = -1;
    keydir->swap_free_list_head = MAX_PAGE_IDX;
    keydir->buffer = NULL;
    keydir->mem_pages = NULL;
    keydir->tmp_fstats = NULL;
    keydir->fstats_array = NULL;
    keydir->fstats = NULL;
    // Assuming global_data is never freed with keydirs around.
    // Seems unloading the bitcask_nifs module with bitcask refs around could
    // be bad, but not sure if that is a problem in practice.
    keydir->global_data = global_data;

    keydir->itr_array.items = NULL;
    keydir->itr_array.count = 0;
    keydir->itr_array.size = 0;

    keydir->refcount = 1;
    keydir->num_pages = params->num_pages;
    keydir->num_swap_pages = 0;
    keydir->epoch = 0;
    keydir->min_epoch = MAX_EPOCH;
    keydir->num_fstats = params->num_fstats;
    keydir->fstats_idx_fun = params->fstats_idx_fun;

    keydir->mutex = enif_mutex_create(keydir->name);
    keydir->swap_grow_mutex = enif_mutex_create(0);

    keydir->name = name ? strdup(name) : NULL;
    keydir->dirname = strdup(params->basedir);
    keydir->buffer = malloc(PAGE_SIZE * params->num_pages);
    keydir->mem_pages = malloc(sizeof(mem_page_t) * params->num_pages);
    keydir->tmp_fstats = kh_init(fstats);
    keydir->fstats = kh_init(fstats);
    keydir->fstats_array = calloc(params->num_fstats, sizeof(fstats_handle_t));
    
    if (!keydir->mutex || !keydir->swap_grow_mutex || !keydir->buffer
        || !keydir->mem_pages || !keydir->tmp_fstats || !keydir->fstats_array)
    {
        keydir_free_memory(keydir);
        return ENOMEM;
    }

    keydir_init_mem_pages(keydir);
    keydir_init_free_list(keydir);

    for (i = 0; i < keydir->num_fstats; ++i)
    {
        keydir->fstats_array[i].mutex = enif_mutex_create(0);
        keydir->fstats_array[i].fstats = kh_init(fstats);
    }

    return 0; // Sweet success!!
}

/*
 * Fetch existing keydir from the global registry or create a new one.
 * If params is NULL, no new keydir will be created.
 */
bitcask_keydir * keydir_acquire(global_keydir_data * gkd,
                                const char * name,
                                keydir_init_params_t * params,
                                int * created_out)
{
    bitcask_keydir * keydir = NULL;
    int use_global = gkd && name;

    if (created_out)
    {
        *created_out = 0;
    }

    if (use_global)
    {
        khiter_t itr;
        enif_mutex_lock(gkd->mutex);

        itr = kh_get(global_keydirs, gkd->keydirs, name);

        if (itr != kh_end(gkd->keydirs))
        {
            keydir = kh_val(gkd->keydirs, itr);
            enif_mutex_lock(keydir->mutex);
            ++keydir->refcount;
            enif_mutex_unlock(keydir->mutex);
        }
    }

    // If creating it.
    if (!keydir && params)
    {
        keydir = calloc(1, sizeof(bitcask_keydir));
        keydir_init(keydir, name, gkd, params);
        // Notice that keydirs start with refcount = 1, so no update

        if (created_out)
        {
            *created_out = 1;
        }

        if (use_global)
        {
            kh_put2(global_keydirs, gkd->keydirs, keydir->name, keydir);
        }
    }

    if (use_global)
    {
        enif_mutex_unlock(gkd->mutex);
    }

    return keydir;
}

static void init_fstats_entry(bitcask_fstats_entry * entry, int file_id)
{
    memset(entry, '\0', sizeof(bitcask_fstats_entry));
    entry->file_id = file_id;
}

void keydir_add_file(bitcask_keydir * keydir, uint32_t file_id)
{
    khiter_t itr;

    enif_mutex_lock(keydir->mutex);
    itr = kh_get(fstats, keydir->fstats, file_id);

    if (itr == kh_end(keydir->fstats))
    {
        int itr_status;
        khiter_t itr = kh_put(fstats, keydir->fstats, file_id, &itr_status);
        init_fstats_entry(&kh_val(keydir->fstats, itr), file_id);

        if (file_id > keydir->biggest_file_id)
        {
            keydir->biggest_file_id = file_id;
        }
    }

    enif_mutex_unlock(keydir->mutex);
}

void keydir_remove_file(bitcask_keydir * keydir, uint32_t file_id)
{
    khiter_t itr;
    enif_mutex_lock(keydir->mutex);
    itr = kh_get(fstats, keydir->fstats, file_id);

    if (itr != kh_end(keydir->fstats))
    {
        kh_del(fstats, keydir->fstats, itr);
    }

    enif_mutex_unlock(keydir->mutex);
}

static uint32_t oldest_timestamp(uint32_t oldest, uint32_t tstamp)
{
    if ((tstamp && tstamp < oldest) || !oldest)
    {
        return tstamp;
    }

    return oldest;
}


static uint32_t newest_timestamp(uint32_t newest, uint32_t tstamp)
{
    if ((tstamp && tstamp > newest) || !newest)
    {
        return tstamp;
    }

    return newest;
}

void update_fstats(fstats_hash_t * fstats,
                   ErlNifMutex * mutex,
                   uint32_t file_id,
                   uint32_t tstamp,
                   int32_t live_increment,
                   int32_t total_increment,
                   int32_t live_bytes_increment,
                   int32_t total_bytes_increment)
{
    bitcask_fstats_entry* entry = 0;

    if (mutex)
    {
        enif_mutex_lock(mutex);
    }

    khiter_t itr = kh_get(fstats, fstats, file_id);

    if (itr == kh_end(fstats))
    {
        int itr_status;
        itr = kh_put(fstats, fstats, file_id, &itr_status);
        entry = &kh_val(fstats, itr);
        init_fstats_entry(entry, file_id);
    }
    else
    {
        entry = &kh_val(fstats, itr);
    }

    entry->live_keys   += live_increment;
    entry->total_keys  += total_increment;
    entry->live_bytes  += live_bytes_increment;
    entry->total_bytes += total_bytes_increment;
    entry->oldest_tstamp = oldest_timestamp(entry->oldest_tstamp, tstamp);
    entry->newest_tstamp = newest_timestamp(entry->newest_tstamp, tstamp);

    if (mutex)
    {
        enif_mutex_unlock(mutex);
    }
}

static void merge_fstats_entry(bitcask_fstats_entry * partial,
                               bitcask_fstats_entry * total)
{
    total->live_keys += partial->live_keys;
    total->live_bytes += partial->live_bytes;
    total->total_keys += partial->total_keys;
    total->total_bytes += partial->total_bytes;
    total->oldest_tstamp = oldest_timestamp(total->oldest_tstamp,
                                            partial->oldest_tstamp);
    total->newest_tstamp = newest_timestamp(total->newest_tstamp,
                                            partial->newest_tstamp);
}

void keydir_aggregate_fstats(bitcask_keydir * keydir)
{
    unsigned idx;
    fstats_hash_t * fstats, * kd_fstats;
    // Lock in this order to avoid deadlock: keydir -> fstats handle
    enif_mutex_lock(keydir->mutex);
    kd_fstats = keydir->fstats;

    for (idx = 0; idx < keydir->num_fstats; ++idx)
    {
        fstats_handle_t * h = keydir->fstats_array + idx;
        khiter_t pitr;

        // Quickly swap partial stats with empty temporary to avoid blocking
        // gets and puts.
        enif_mutex_lock(h->mutex);
        fstats = h->fstats;
        h->fstats = keydir->tmp_fstats;
        enif_mutex_unlock(h->mutex);

        keydir->tmp_fstats = fstats;
        
        for (pitr = kh_begin(fstats); pitr != kh_end(fstats); ++pitr)
        {
            if (kh_exist(fstats, pitr))
            {
                bitcask_fstats_entry * pentry = &kh_val(fstats, pitr);
                khiter_t gitr = kh_get(fstats, kd_fstats, pentry->file_id);

                if (gitr != kh_end(kd_fstats))
                {
                    bitcask_fstats_entry * gentry = &kh_val(kd_fstats, gitr);
                    merge_fstats_entry(pentry, gentry);
                }

                kh_del(fstats, fstats, pitr);
            }
        }
    }

    enif_mutex_unlock(keydir->mutex);
}

static int hash_key(uint8_t * key, uint32_t key_sz)
{
    return MURMUR_HASH(key, key_sz, 42);
}

static page_t * get_swap_page(uint32_t idx, swap_array_t * swap_pages)
{
    if (idx < swap_pages->size)
    {
        return &swap_pages->pages[idx];
    }

    // assert swap_pages->next
    // Can't call this function with an invalid index yo.
    return get_swap_page(idx - swap_pages->size, swap_pages->next);
}

static swap_array_t * get_last_swap_array(swap_array_t * swap_pages)
{
    swap_array_t * p = swap_pages;
    while(p->next)
    {
        p = p->next;
    }
    return p;
}

// Per page info in iterators.
typedef struct
{
    page_t *        page;
    mem_page_t *    mem_page;
    uint32_t        page_idx;
} page_info_t;

#define SCAN_INITIAL_PAGE_ARRAY_SIZE 16

typedef struct
{
    int                 found;
    uint32_t            offset;
    uint32_t            num_pages;
    uint32_t            page_array_size;
    page_info_t *       pages;
    page_info_t         pages0[SCAN_INITIAL_PAGE_ARRAY_SIZE];
} scan_iter_t;

static uint8_t * scan_get_field(scan_iter_t * iter, int field_offset)
{
    int chain_ofs = iter->offset + field_offset;
    int idx = chain_ofs / PAGE_SIZE;
    int ofs = chain_ofs % PAGE_SIZE;
    return iter->pages[idx].page->data + ofs;
}

static uint64_t scan_get_epoch(scan_iter_t * result)
{
    return *((uint64_t*)scan_get_field(result, ENTRY_EPOCH_OFFSET));
}

static uint32_t scan_get_file_id(scan_iter_t * result)
{
    return *((uint32_t*)scan_get_field(result, ENTRY_FILE_ID_OFFSET));
}

static uint32_t scan_get_key_size(scan_iter_t * result)
{
    return *((uint32_t*)scan_get_field(result, ENTRY_KEY_SIZE_OFFSET));
}

static uint32_t scan_get_timestamp(scan_iter_t * result)
{
    return *((uint32_t*)scan_get_field(result, ENTRY_TIMESTAMP_OFFSET));
}

static uint32_t scan_get_total_size(scan_iter_t * result)
{
    return *((uint32_t*)scan_get_field(result, ENTRY_TOTAL_SIZE_OFFSET));
}

static uint32_t scan_get_next(scan_iter_t * result)
{
    return *((uint32_t*)scan_get_field(result, ENTRY_NEXT_OFFSET));
}

static uint64_t scan_get_offset(scan_iter_t * result)
{
    return *((uint64_t*)scan_get_field(result, ENTRY_OFFSET_OFFSET));
}

static void scan_set_uint64(scan_iter_t * iter, int offset, uint64_t val)
{
    *((uint64_t*)scan_get_field(iter, offset)) = val;
}

static void scan_set_uint32(scan_iter_t * iter, int offset, uint32_t val)
{
    *((uint32_t*)scan_get_field(iter, offset)) = val;
}

static void scan_set_file_id(scan_iter_t * iter, uint32_t v)
{
    scan_set_uint32(iter, ENTRY_FILE_ID_OFFSET, v);
}

static void scan_set_total_size(scan_iter_t * iter, uint32_t v)
{
    scan_set_uint32(iter, ENTRY_TOTAL_SIZE_OFFSET, v);
}

static void scan_set_timestamp(scan_iter_t * iter, uint32_t v)
{
    scan_set_uint32(iter, ENTRY_TIMESTAMP_OFFSET, v);
}

static void scan_set_epoch(scan_iter_t * iter, uint64_t v)
{
    scan_set_uint64(iter, ENTRY_EPOCH_OFFSET, v);
}

static void scan_set_offset(scan_iter_t * iter, uint64_t v)
{
    scan_set_uint64(iter, ENTRY_OFFSET_OFFSET, v);
}

static void scan_set_next(scan_iter_t * iter, uint32_t v)
{
    scan_set_uint32(iter, ENTRY_NEXT_OFFSET, v);
}

static void scan_set_key_size(scan_iter_t * iter, uint32_t v)
{
    scan_set_uint32(iter, ENTRY_KEY_SIZE_OFFSET, v);
}

static void scan_set_key(scan_iter_t * iter,
                         const uint8_t * key,
                         uint32_t key_size)
{
    // Split key along potentially multiple pages.
    // Pages are assumed to be already allocated.
    int key_offset      = iter->offset + ENTRY_KEY_OFFSET;
    int page_idx        = key_offset / PAGE_SIZE;
    int page_offset     = key_offset % PAGE_SIZE;
    int space_in_page   = PAGE_SIZE - page_offset;
    size_t section_size = key_size < space_in_page ? key_size : space_in_page;
    uint32_t remainder  = key_size;
    const uint8_t * src = key;
    uint8_t * dst       = iter->pages[page_idx].page->data + page_offset;

    memcpy(dst, src, section_size);
    remainder -= section_size;

    while (remainder > 0)
    {
        dst = iter->pages[++page_idx].page->data;
        src += section_size;
        section_size = remainder > PAGE_SIZE ? PAGE_SIZE : remainder;
        memcpy(dst, src, section_size);
        remainder -= section_size;
    }
}

/*
 * Key should have enough space for key data.
 */
static void scan_get_key(scan_iter_t * iter, uint8_t * key)
{
    // Split key along potentially multiple pages.
    // Pages are assumed to be already allocated.
    int key_offset      = iter->offset + ENTRY_KEY_OFFSET;
    uint32_t key_size   = scan_get_key_size(iter);
    int page_idx        = key_offset / PAGE_SIZE;
    int page_offset     = key_offset % PAGE_SIZE;
    int space_in_page   = PAGE_SIZE - page_offset;
    size_t section_size = key_size < space_in_page ? key_size : space_in_page;
    uint32_t remainder  = key_size;
    uint8_t * dst       = key;
    const uint8_t * src = iter->pages[page_idx].page->data + page_offset;

    memcpy(dst, src, section_size);
    remainder -= section_size;

    while (remainder > 0)
    {
        src = iter->pages[++page_idx].page->data;
        dst += section_size;
        section_size = remainder > PAGE_SIZE ? PAGE_SIZE : remainder;
        memcpy(dst, src, section_size);
        remainder -= section_size;
    }
}

static int scan_is_tombstone(scan_iter_t * iter)
{
    return scan_get_offset(iter) == MAX_OFFSET;
}

static void scan_make_tombstone(scan_iter_t * iter)
{
    scan_set_offset(iter, MAX_OFFSET);
}

/*
 * Ensures there is space for at least one extra entry in the
 * iterator's page array.
 * Returns 0 on success, non-zero on out of memory.
 */
static int scan_expand_page_array(scan_iter_t * iter)
{
    size_t old_size, new_size;
    page_info_t * new_pages;

    // This assumes we only add one item at a time and
    // resize when old size is full.
    if (iter->num_pages >= iter->page_array_size)
    {
        old_size = sizeof(page_info_t) * iter->page_array_size;
        iter->page_array_size *= 2;
        new_size = sizeof(page_info_t) * iter->page_array_size;
        // If old array was initial static array, don't deallocate! 
        if (iter->page_array_size == 2 * SCAN_INITIAL_PAGE_ARRAY_SIZE)
        {
            iter->pages = malloc(new_size);
            if (!iter->pages)
            {
                return ENOMEM;
            }
            memcpy(iter->pages, iter->pages0, old_size);
        }
        else
        {
            new_pages = realloc(iter->pages, new_size);
            if (!new_pages)
            {
                return ENOMEM;
            }
            iter->pages = new_pages;
        }
    }

    return 0;
}

/*
 * Returns the next page in the free list or NULL if none found.
 * It may find any number of pages that are marked as deleted in the list,
 * so may iterate for a bit before returning.
 * TODO: May need a fancier free list with lock-free internal deletions
 * if one exists to avoid skipping over unbounded number of pages in the free
 * list marked as used.
 */
static mem_page_t * allocate_mem_page(bitcask_keydir * keydir,
                                      scan_iter_t * iter)
{
    uint32_t first;
    mem_page_t * mem_page;
    page_t * page;

    // Operation may retry a bunch.
    while(1)
    {
        first = keydir->free_list_head;
        if (first == MAX_PAGE_IDX)
        {
            return NULL;
        }

        mem_page = &keydir->mem_pages[first];
        page = &mem_page->page;

        if (bc_atomic_cas_32(&keydir->free_list_head, first, page->next_free))
        {
            // But is it a page already in our chain?
            uint32_t i, already_locked = 0;
            for (i = 0; i < iter->num_pages; ++i)
            {
                if (iter->pages[i].mem_page == mem_page)
                {
                    already_locked = 1;
                    break;
                }
            }

            if (already_locked)
            {
                continue;
            }
            
            enif_mutex_lock(page->mutex);
            if (page->is_free)
            {
                mem_page->is_borrowed = 1;
                page->is_free = 0;
                return mem_page;
            }
            else // Actually page has been taken already, try next one.
            {
                enif_mutex_unlock(page->mutex);
            }
        }
    }
}

/*
 * Returns 0 if successful, other if memory allocation failed.
 */
static int expand_swap_file(bitcask_keydir * keydir, uint32_t old_num_pages)
{
    off_t new_file_size, page_offset;
    uint32_t new_num_pages, num_extra, i, old_head_idx;
    page_t * page;
    swap_array_t * new_array, * last_array;

    enif_mutex_lock(keydir->swap_grow_mutex);

    // Checking the size observed before caller tried to pull from the
    // swap free list helps avoid multiple threads expand in quick sequence
    // upon concurrently finding the list empty.
    if (keydir->num_swap_pages == old_num_pages)
    {
        // Expand or create swap file.
        if (old_num_pages)
        {
            num_extra = old_num_pages;
        }
        else
        {
            num_extra = KEYDIR_DEFAULT_NUM_INITIAL_SWAP_PAGES;

            if ((keydir->swap_file_desc = open_swap_file(keydir->dirname)) < 0)
            {
                enif_mutex_unlock(keydir->swap_grow_mutex);
                return 1;
            }
        }

        new_num_pages = old_num_pages + num_extra;
        new_file_size = new_num_pages * PAGE_SIZE;

        if (ftruncate(keydir->swap_file_desc, new_file_size))
        {
            // Failed file expansion. This ship is going down. 
            enif_mutex_unlock(keydir->swap_grow_mutex);
            return 1;
        }

        new_array = malloc(sizeof(swap_array_t));
        // We are doubling, so new array is as big as old # of pages
        new_array->size = num_extra;
        new_array->pages = malloc(num_extra * sizeof(page_t));
        new_array->next = NULL;
        page_offset = old_num_pages * PAGE_SIZE;

        for(i = 0; i < new_array->size; ++i, page_offset += PAGE_SIZE)
        {
            page = new_array->pages + i;
            page->prev = MAX_PAGE_IDX;
            page->next = MAX_PAGE_IDX;
            page->is_free = 1;
            page->data = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED,
                              keydir->swap_file_desc, page_offset);

            // Truncate pages list if memory mapping fails.
            // We're likely going down in flames anyway.
            if (page->data == MAP_FAILED)
            {
                if (i == 0)
                {
                    free(new_array->pages);
                    free(new_array);
                    new_array = NULL;
                }
                else
                {
                    new_array->pages = realloc(new_array->pages,
                                               sizeof(page_t) * i);
                    new_array->size = i;
                }

                break;
            }
            else
            {
                // The last next index will be invalid until corrected below,
                // when adding new pages to the list.
                page->next_free = keydir->num_pages + old_num_pages + i + 1;
                page->mutex = enif_mutex_create(0);
            }
        }

        if (new_array)
        {
            keydir->num_swap_pages += new_array->size;
            new_array->pages[new_array->size - 1].next = MAX_PAGE_IDX;

            if (keydir->swap_pages)
            {
                last_array = get_last_swap_array(keydir->swap_pages);
                last_array->next = new_array;
            }
            else
            {
                keydir->swap_pages = new_array;
            }

            // Atomically insert new entries at the head of the list.
            while (1)
            {
                old_head_idx = keydir->swap_free_list_head;
                new_array->pages[new_array->size - 1].next_free = old_head_idx;
                if (bc_atomic_cas_32(&keydir->swap_free_list_head,
                                     old_head_idx,
                                     keydir->num_pages + old_num_pages))
                {
                    break;
                }
            }
        }
        else
        {
            enif_mutex_unlock(keydir->swap_grow_mutex);
            return 1;
        }
    }

    enif_mutex_unlock(keydir->swap_grow_mutex);
    return 0;
}

static page_t * allocate_swap_page(bitcask_keydir * keydir, uint32_t * idx_out)
{
    uint32_t head_idx, num_pages;
    page_t * head_page;

    // May need to be retried
    while(1)
    {
        num_pages = keydir->num_swap_pages;

        // Ensure the number of pages is loaded before looking at the list
        // so we can avoid many threads expanding the pages at once when
        // the list goes empty.
        // TODO: We only need a StoreStore barrier here, not a full one.
        bc_full_barrier();
        head_idx = keydir->swap_free_list_head;

        // If list empty, expand swap file and retry.
        if (head_idx == MAX_PAGE_IDX)
        {
            if(expand_swap_file(keydir, num_pages)
               || keydir->swap_free_list_head == MAX_PAGE_IDX)
            {
                // Oops, expansion failed. Women and children first.
                return (page_t*)0;
            }
            continue; // Retry. I'm feeling lucky now!
        }

        head_page = get_swap_page(head_idx - keydir->num_pages,
                                  keydir->swap_pages);
        // Swap page lookup is non-trivial log(n) search.
        // Consider using pointers and pointer CAS if that becomes a problem.

        if (bc_atomic_cas_32(&keydir->swap_free_list_head,
                          head_idx, head_page->next_free))
        {
            *idx_out = head_idx;
            head_page->is_free = 0;
            // TODO: Figure out if we really need to lock it.
            // Unlike memory pages, no thread should be trying to change
            // a swap page placed in the free list.
            enif_mutex_lock(head_page->mutex);
            return head_page;
        }
    }
}

static void allocate_page(bitcask_keydir * keydir,
                          scan_iter_t * iter,
                          page_info_t * page_info)
{
    page_info->mem_page = allocate_mem_page(keydir, iter);

    if (page_info->mem_page)
    {
        page_info->page = &page_info->mem_page->page;
        page_info->page_idx = page_info->mem_page - keydir->mem_pages;
    }
    // TODO: Pick from underutilized pages first if none free
    else
    {
        page_info->page = allocate_swap_page(keydir, &page_info->page_idx);
    }
}

/*
 * Extends the iterator's list of pages in the chain to include an extra n
 * pages.  It will not add more pages than already belong to the chain, so
 * passing a large n is a way to include all pages in the chain.
 * Returns zero on success, an errno code otherwise.
 */
static int extend_iter_chain(bitcask_keydir * keydir,
                             scan_iter_t * iter,
                             uint32_t n)
{
    uint32_t next;
    page_t * page;
    page_info_t * new_page;
    mem_page_t * mem_page;

    while(n)
    {
        next = iter->pages[iter->num_pages-1].page->next;

        // Reached last page in chain.
        if (next == MAX_PAGE_IDX)
        {
            break;
        }

        // if memory page
        if (next < keydir->num_pages)
        {
            mem_page = keydir->mem_pages + next;
            page = &mem_page->page;
        }
        else // if swap page
        {
            mem_page = NULL;
            page = get_swap_page(next - keydir->num_pages, keydir->swap_pages);
        }

        enif_mutex_lock(page->mutex);
        scan_expand_page_array(iter);
        new_page = iter->pages + iter->num_pages;
        new_page->page = page;
        new_page->mem_page = mem_page;
        new_page->page_idx = next;
        ++iter->num_pages;
        --n;
    }

    // Extend chain beyond last page, allocate extra ones and link them.
    while (n--)
    {
        if (scan_expand_page_array(iter))
        {
            return ENOMEM;
        }

        new_page = iter->pages + iter->num_pages;
        allocate_page(keydir, iter, new_page);

        if (!new_page->page)
        {
            return ENOMEM;
        }

        ++iter->num_pages;
        // Link new page to chain
        new_page[-1].page->next = new_page->page_idx;
        new_page->page->prev = new_page[-1].page_idx;
        new_page->page->next = MAX_PAGE_IDX;
    }

    return 0;
}

static page_t * get_page(bitcask_keydir * keydir,
                         uint32_t idx)
{
    if (idx < keydir->num_pages)
    {
        return &keydir->mem_pages[idx].page;
    }

    return get_swap_page(idx - keydir->num_pages, keydir->swap_pages);
}

/* 
 * Ensures that we have all pages containing data for the entry the
 * iterator points to.
 */
static int lock_pages_to_scan_entry(bitcask_keydir * keydir,
                                    scan_iter_t * iter)
{
    uint32_t needed_pages, key_size;

    needed_pages = (iter->offset + ENTRY_KEY_OFFSET) / PAGE_SIZE + 1;

    // First allocate all pages to include this entry up to the key start.
    if (needed_pages > iter->num_pages)
    {
        if (extend_iter_chain(keydir, iter, needed_pages - iter->num_pages))
        {
            return ENOMEM;
        }
    }

    // Read the key size and allocate any extra pages needed to include it.
    key_size     = scan_get_key_size(iter);
    needed_pages = (iter->offset + ENTRY_KEY_OFFSET + key_size) / PAGE_SIZE
        + 1;
    if (extend_iter_chain(keydir, iter, needed_pages - iter->num_pages))
    {
        return ENOMEM;
    }

    return 0;
}

static void init_scan_iterator(scan_iter_t * scan_iter,
                               bitcask_keydir * keydir,
                               uint32_t base_idx)
{
    page_t * first_page;

    mem_page_t * first_mem_page = keydir->mem_pages + base_idx;
    enif_mutex_lock(first_mem_page->page.mutex);

    if (first_mem_page->alt_idx == MAX_PAGE_IDX)
    {
        first_page = &first_mem_page->page;
    }
    else // Page has been moved to swap.
    {
        first_page = get_swap_page(first_mem_page->alt_idx, keydir->swap_pages);
        enif_mutex_lock(first_page->mutex);
        enif_mutex_unlock(first_mem_page->page.mutex);
    }

    scan_iter->found = 0;
    scan_iter->offset = 0;
    scan_iter->num_pages = 1;
    scan_iter->page_array_size = SCAN_INITIAL_PAGE_ARRAY_SIZE;
    scan_iter->pages = scan_iter->pages0;
    scan_iter->pages[0].page = first_page;
    scan_iter->pages[0].mem_page = first_mem_page;
    scan_iter->pages[0].page_idx = base_idx;
}


/*
 * Returns 1 if the key matches the entry the iterator points to.
 * It takes care of comparing a key that may be split along potentially
 * multiple pages.
 */
static int scan_keys_equal(const uint8_t * key,
                           uint32_t key_size,
                           scan_iter_t * iter)
{
    uint32_t iter_key_size = scan_get_key_size(iter);
    uint32_t offset, page_offset, page_idx, remaining, len;
    uint8_t * entry_key;
    
    if (iter_key_size != key_size)
    {
        return 0;
    }

    offset = iter->offset + ENTRY_KEY_OFFSET;
    page_offset = offset % PAGE_SIZE;
    page_idx = offset / PAGE_SIZE;
    remaining = key_size;
    len = PAGE_SIZE - page_offset; // potentially rest of first page
    entry_key = iter->pages[page_idx].page->data + page_offset;

    if (len > remaining)
    {
        len = remaining;
    }

    if (memcmp(key, entry_key, len) != 0)
    {
        return 0;
    }

    remaining -= len;

    len = PAGE_SIZE;
    // This first compares the first bit of the key contained in the first
    // page, then pieces of (or potentially entire) subsequent pages.
    for(; remaining > 0;
        // After first page, comparison starts at beginning of page
        entry_key = iter->pages[++page_idx].page->data)
    {
        if (len > remaining)
        {
            len = remaining;
        }

        if (memcmp(key, entry_key, len) != 0)
        {
            return 0;
        }

        remaining -= len;
    }

    // keys match
    return remaining == 0;
}

/*
 * If current entry has multiple versions, it jumps to the one with the
 * highest epoch that is lower than the input epoch.
 * This function sets the iterator's found flag if a value exists for the
 * given epoch.
 */
static void scan_to_epoch(bitcask_keydir * keydir,
                          scan_iter_t * iter,
                          uint64_t      epoch)
{
    uint32_t last_offset, next;
    uint64_t entry_epoch;

    entry_epoch = scan_get_epoch(iter);

    if (entry_epoch >= epoch)
    {
        iter->found = entry_epoch == epoch;
        return;
    }

    // Whatever happens, we have one entry below epoch, so found it!
    iter->found = 1;
    last_offset = iter->offset;
    next = scan_get_next(iter);

    while(next)
    {
        iter->offset = next;
        lock_pages_to_scan_entry(keydir, iter);
        entry_epoch = scan_get_epoch(iter);

        if (entry_epoch == epoch)
        {
            return;
        }

        if (entry_epoch > epoch)
        {   // Past epoch, so previous was the one
            iter->offset = last_offset;
            return;
        }

        last_offset = iter->offset;
        next = scan_get_next(iter);
    }
}

static uint32_t entry_size_for_key(uint32_t key_size)
{
    // This actually fails if the key_size is close to 4G. Don't do that.
    uint32_t unpadded_size = ENTRY_KEY_OFFSET + key_size;
    // Pad to next 8 byte boundary so data is aligned properly
    return (unpadded_size + 7) & ~7u;
}

/*
 * Scans pages looking for the entry with the given key closest to, but not
 * greater than, the given epoch.
 * Assumes that the iterator already contains the first page.
 */
static void scan_pages(bitcask_keydir * keydir,
                       uint8_t * key,
                       uint32_t key_size,
                       uint64_t epoch,
                       scan_iter_t * scan_iter)
{
    uint32_t entry_size;
    uint32_t data_size = scan_iter->pages[0].mem_page->size;

    if (data_size == 0)
    {
        return;
    }

    for(;;)
    {
        lock_pages_to_scan_entry(keydir, scan_iter);

        // Current entry matches key?
        if (scan_keys_equal(key, key_size, scan_iter))
        {   
            if (scan_get_epoch(scan_iter) > epoch)
            {
                // Entry added after requested snapshot. Ignore.
                return;
            }

            scan_to_epoch(keydir, scan_iter, epoch);
            return;
        }

        // Point offset to next entry
        entry_size = entry_size_for_key(scan_get_key_size(scan_iter));
        scan_iter->offset += entry_size;

        if (scan_iter->offset >= data_size)
        {
            // No more entries
            return;
        }
    }
}

/*
 * Populate return entry fields from scan data.
 * It handles entries split across page boundaries.
 * Notice that the key and its size are left out.
 */
static void scan_iter_to_entry(scan_iter_t * iter,
                               keydir_entry_t * return_entry)
{
    return_entry->file_id       = scan_get_file_id(iter);
    return_entry->total_size    = scan_get_total_size(iter);
    return_entry->epoch         = scan_get_epoch(iter);
    return_entry->offset        = scan_get_offset(iter);
    return_entry->timestamp     = scan_get_timestamp(iter);
}

int is_tombstone_entry(keydir_entry_t * entry)
{
    return entry->offset == MAX_OFFSET;
}

static void unlock_pages(int num_pages, page_info_t * pages)
{
    while(num_pages--)
    {
        enif_mutex_unlock((*pages++).page->mutex);
    }
}

static void free_scan_iter(scan_iter_t * iter)
{
    unlock_pages(iter->num_pages, iter->pages);

    if (iter->page_array_size > SCAN_INITIAL_PAGE_ARRAY_SIZE)
    {
        free(iter->pages);
    }
}

/*
 * Scans chain looking for a key. If multiple entries exist for the key,
 * it finds the one with the largest epoch that is smaller than the given
 * epoch. Multi-entries are always ordered by epoch, with most recent
 * ones first. If the key exists but all entries have a higher epoch,
 * the found flag is not set.  If the found flag is set, the offset in the
 * iterator points at the beginning of the matching entry.
 * Otherwise, it might be pointing at the end of the chain or the first
 * of a group of multi-entries if its epoch is too big.
 */
static void scan_for_key(bitcask_keydir *  keydir,
                         uint8_t *         key,
                         uint32_t          key_size,
                         uint64_t          epoch,
                         scan_iter_t *     scan_iter)
{
    uint32_t base_idx = hash_key(key, key_size) % keydir->num_pages;

    init_scan_iterator(scan_iter, keydir, base_idx);
    scan_pages(keydir, key, key_size, epoch, scan_iter);
}

KeydirGetCode keydir_get(bitcask_keydir *    keydir,
                         uint8_t *           key,
                         uint32_t            key_size,
                         uint64_t            epoch,
                         keydir_entry_t *    return_entry)
{
    scan_iter_t scan_iter;
    scan_for_key(keydir, key, key_size, epoch, &scan_iter);
    int found = scan_iter.found && !scan_is_tombstone(&scan_iter);

    if (found)
    {
        scan_iter_to_entry(&scan_iter, return_entry);
    }

    free_scan_iter(&scan_iter);
    // The free operation only frees allocated memory and releases locks.
    // It is safe to check the found flag afterwards.
    return found ? KEYDIR_GET_FOUND : KEYDIR_GET_NOT_FOUND;
}

/**
 * True if the base of the page chain is a memory page.
 */
static int scan_is_first_in_memory(scan_iter_t * iter)
{
    return iter->pages[0].page == &iter->pages[0].mem_page->page;
}

typedef enum {
    WRITE_PREP_OK = 0,
    WRITE_PREP_RESTART = 1,
    WRITE_PREP_NO_MEM =  2
} WritePrepCode;

static WritePrepCode reclaim_borrowed_page(bitcask_keydir * keydir,
                                           scan_iter_t * iter,
                                           mem_page_t * base_page)
{
    page_t * borrowed_prev, * borrowed_next;
    page_info_t replacement_page;

    borrowed_prev = get_page(keydir, base_page->page.prev);

    // To claim, lock previous and next pages to swap it out.
    // Need to do it in chain order to avoid deadlock, but first be
    // optimistic and try non-blocking lock first in case that's enough.
    if (enif_mutex_trylock(borrowed_prev->mutex))
    {
        uint32_t base_idx = base_page - keydir->mem_pages;
        enif_mutex_unlock(base_page->page.mutex);
        enif_mutex_lock(borrowed_prev->mutex);

        // Restart if chain has changed since unlocking base page.
        if (borrowed_prev->next != base_idx)
        {
            enif_mutex_unlock(borrowed_prev->mutex);
            return WRITE_PREP_RESTART;
        }

        enif_mutex_lock(base_page->page.mutex);
    }

    allocate_page(keydir, iter, &replacement_page);
    if (!replacement_page.page)
    {
        enif_mutex_unlock(base_page->page.mutex);
        enif_mutex_unlock(borrowed_prev->mutex);
        return WRITE_PREP_NO_MEM;
    }

    if (base_page->page.next != MAX_PAGE_IDX)
    {
        borrowed_next = get_page(keydir, base_page->page.next);
        enif_mutex_lock(borrowed_next->mutex);
        borrowed_next->prev = replacement_page.page_idx;
    }
    else
    {
        borrowed_next = NULL;
    }

    // TODO: If we are re-using a swap page we may trigger I/O here.
    // We may need a way to minimize that (prefer fresh new pages?
    // maybe refresh swap pages by rotating through files?)
    // TODO: We are copying an entire page, but it might be partially 
    // filled only. Should each page point to base, hold its own size?
    memcpy(replacement_page.page->data, base_page->page.data, PAGE_SIZE);
    replacement_page.page->prev = base_page->page.prev; 
    replacement_page.page->next = base_page->page.next; 
    borrowed_prev->next = replacement_page.page_idx;

    if (borrowed_next)
    {
        enif_mutex_unlock(borrowed_next->mutex);
    }

    // TODO: If it turns out we don't need to lock swap pages taken from
    // the free list, we should not unlock the new page here if from swap.
    enif_mutex_unlock(replacement_page.page->mutex);
    enif_mutex_unlock(borrowed_prev->mutex);

    return WRITE_PREP_OK;
}

/*
 * Prepare chain to append a new entry.
 * The chain size will be updated. The caller just needs to fill it up.
 * If base page is free, remove from free list.
 * If base page is borrowed, need to claim it and find home to previous tenant.
 * If no space for new entry, allocate extra pages.
 */
static WritePrepCode write_prep(bitcask_keydir *   keydir,
                                scan_iter_t *      iter,
                                uint32_t           key_size)
{
    mem_page_t * base_page = iter->pages[0].mem_page;
    uint32_t wanted_size = base_page->size + entry_size_for_key(key_size);
    uint32_t wanted_pages = (wanted_size + PAGE_SIZE - 1) / PAGE_SIZE;

    // If size overflow (> 4G) give up on life!
    if (wanted_size < base_page->size)
    {
        return WRITE_PREP_NO_MEM;
    }

    if (scan_is_first_in_memory(iter) && base_page->page.is_free)
    {
        base_page->page.is_free = 0;
    }

    if (base_page->size == 0 && base_page->is_borrowed)
    {
        WritePrepCode ret = reclaim_borrowed_page(keydir, iter, base_page);

        if (ret)
        {
            return ret;
        }
    }

    // Allocate entire chain + extra pages.
    if (extend_iter_chain(keydir, iter, wanted_pages - iter->num_pages))
    {
        return WRITE_PREP_NO_MEM;
    }

    return WRITE_PREP_OK;
}

static void append_entry(scan_iter_t * iter, keydir_entry_t * entry)
{
    page_info_t * base_page = &iter->pages[0];

    BC_DEBUG_BIN(dbg_key, entry->key, entry->key_size);
    BC_DEBUG("Append entry %s to page %u at position %u\r\n", dbg_key,
             base_page->page_idx, base_page->mem_page->size);

    iter->offset = base_page->mem_page->size;
    scan_set_file_id(iter, entry->file_id);
    scan_set_total_size(iter, entry->total_size);
    scan_set_epoch(iter, entry->epoch);
    scan_set_offset(iter, entry->offset);
    scan_set_timestamp(iter, entry->timestamp);
    scan_set_next(iter, 0);
    scan_set_key_size(iter, entry->key_size);
    scan_set_key(iter, entry->key, entry->key_size);
    base_page->mem_page->size += entry_size_for_key(entry->key_size);
}

static void append_version(scan_iter_t * iter, keydir_entry_t * entry)
{
    page_info_t * base_page = &iter->pages[0];

    BC_DEBUG_BIN(dbg_key, entry->key, entry->key_size);
    BC_DEBUG("Append version %s to page %u at position %u\r\n", dbg_key,
             base_page->page_idx, base_page->mem_page->size);

    iter->offset = base_page->mem_page->size;
    scan_set_file_id(iter, entry->file_id);
    scan_set_offset(iter, entry->offset);
    scan_set_total_size(iter, entry->total_size);
    scan_set_timestamp(iter, entry->timestamp);
    scan_set_epoch(iter, entry->epoch);
    scan_set_next(iter, 0);
    // Key only in first version, not here.
    scan_set_key_size(iter, 0);
    base_page->mem_page->size += BASE_ENTRY_SIZE;
}

static void update_entry(scan_iter_t * iter, keydir_entry_t * entry)
{
    BC_DEBUG_BIN(dbg_key, entry->key, entry->key_size);
    BC_DEBUG("Update %s in page %u at position %u\r\n", dbg_key,
             iter->pages[0].page_idx, iter->offset);

    scan_set_file_id(iter, entry->file_id);
    scan_set_offset(iter, entry->offset);
    scan_set_total_size(iter, entry->total_size);
    scan_set_timestamp(iter, entry->timestamp);
    scan_set_epoch(iter, entry->epoch);
}

/**
 * If old_file_id and old_offset are given, caller wants to update an existing
 * version of a value. The operation should fail if the latest version of the
 * entry has differend file/offset or entry has been removed.
 *
 * Returns 1 if write succeeded,
 * 0 if conditional write failed since the current entry doesn't match.
 */
KeydirPutCode keydir_put(bitcask_keydir * keydir,
                         keydir_entry_t * entry,
                         uint32_t         old_file_id,
                         uint64_t         old_offset)
{
    scan_iter_t iter;
    uint32_t found_file_id, found_size = 0;
    int added = 0;
    KeydirPutCode ret_code = KEYDIR_PUT_OK;
    unsigned fstats_index = keydir->fstats_idx_fun() % keydir->num_fstats;
    fstats_handle_t * fstats_handle = keydir->fstats_array + fstats_index;

    while (1)
    {
        entry->epoch = bc_atomic_incr_64(&keydir->epoch);
        scan_for_key(keydir, entry->key, entry->key_size, entry->epoch, &iter);

        if (iter.found)
        {
            int is_tombstone = scan_is_tombstone(&iter);
            uint64_t file_offset = scan_get_offset(&iter);

            found_size = is_tombstone ? 0 : scan_get_total_size(&iter);
            found_file_id = scan_get_file_id(&iter);

            // If CAS, but entry deleted or changed.
            // TODO: Original code had a shady comment (by yours truly) about
            // the conditional logic and merges finding two current values for
            // the same because they were in the same second. I think it's not
            // needed, but need to verify carefully.
            if (old_file_id &&
                (is_tombstone ||
                 found_file_id != old_file_id || file_offset != old_offset))
            {
                ret_code = KEYDIR_PUT_MODIFIED;
            }
            // if we can update entry in place
            else if (keydir->min_epoch > entry->epoch)
            {
                added = 1;
                update_entry(&iter, entry);
            }
            else // Adding extra version
            {
                uint64_t chain_size;
                // Expand to fit extra version
                switch(write_prep(keydir, &iter, 0/* no key */))
                {
                    case WRITE_PREP_NO_MEM:
                        ret_code = KEYDIR_PUT_OUT_OF_MEMORY;
                        break;
                    case WRITE_PREP_RESTART:
                        continue; // Concurrency conflict, retry.
                    case WRITE_PREP_OK:
                        // Point previous version to new one.
                        chain_size = iter.pages[0].mem_page->size;
                        scan_set_next(&iter, chain_size);
                        append_version(&iter, entry);
                        added = 1;
                        break;
                }
            }
        }
        else if(old_file_id) // CAS but entry removed
        {
            ret_code = KEYDIR_PUT_MODIFIED;
        }
        else // not found, append
        {
            switch(write_prep(keydir, &iter, entry->key_size))
            {
                case WRITE_PREP_NO_MEM:
                    ret_code = KEYDIR_PUT_OUT_OF_MEMORY;
                    break;
                case WRITE_PREP_RESTART:
                    continue;
                case WRITE_PREP_OK:
                    entry->next = 0;
                    append_entry(&iter, entry);
                    added = 1;
                    break;
            }
        }
        break;
    }

    free_scan_iter(&iter);

    if (added)
    {
        // Update file key/bytes stats
        enif_mutex_lock(fstats_handle->mutex);

        if (found_size)
        {
            update_fstats(fstats_handle->fstats, NULL /* don't lock */,
                          found_file_id, 0, -1, 0, -found_size, 0); 
        }
        else
        {
            bc_atomic_add_64(&keydir->key_count, 1);
            bc_atomic_add_64(&keydir->key_bytes, (int64_t)entry->key_size);
        }

        update_fstats(fstats_handle->fstats, NULL /* don't lock */,
                      entry->file_id, entry->timestamp,
                      1, 1, (int32_t)entry->total_size,
                      (int32_t)entry->total_size ); 
        enif_mutex_unlock(fstats_handle->mutex);

    }

    return ret_code;
}

static void append_deleted_version(scan_iter_t * iter, uint64_t epoch)
{
    scan_set_file_id(iter, MAX_FILE_ID);
    scan_set_offset(iter, MAX_OFFSET);
    scan_set_total_size(iter, 0);
    scan_set_timestamp(iter, 0);
    scan_set_epoch(iter, epoch);
    scan_set_next(iter, 0);
    scan_set_key_size(iter, 0);
}


KeydirPutCode keydir_remove(bitcask_keydir * keydir,
                            uint8_t * key,
                            uint32_t key_size,
                            // conditional remove options
                            uint32_t old_file_id,
                            uint64_t old_offset)
{
    scan_iter_t iter;
    uint64_t epoch;
    KeydirPutCode ret_code = KEYDIR_PUT_OK;
    unsigned fstats_index = keydir->fstats_idx_fun() % keydir->num_fstats;
    fstats_handle_t * fstats_handle = keydir->fstats_array + fstats_index;
    uint32_t found_file_id = 0, found_size = 0;

    while (1)
    {
        epoch = bc_atomic_incr_64(&keydir->epoch);
        scan_for_key(keydir, key, key_size, epoch, &iter);

        if (iter.found & !scan_is_tombstone(&iter))
        {
            found_file_id = scan_get_file_id(&iter);
            uint64_t file_offset = scan_get_offset(&iter);
            // If conditional remove, verify entry has not changed
            if (old_file_id &&
                (found_file_id != old_file_id || file_offset != old_offset))
            {
                ret_code = KEYDIR_PUT_MODIFIED;
            }
            else if (keydir->min_epoch > epoch)
            {
                found_size = scan_get_total_size(&iter);
                // safe to update in place, no snapshots will need this entry.
                scan_make_tombstone(&iter);
                scan_set_epoch(&iter, epoch);

            }
            else // Adding extra version for this key.
            {
                uint32_t chain_size;
                // Expand to fit extra version, no extra copy of key needed.
                switch(write_prep(keydir, &iter, 0))
                {
                    case WRITE_PREP_NO_MEM:
                        ret_code = KEYDIR_PUT_OUT_OF_MEMORY;
                        break;
                    case WRITE_PREP_RESTART:
                        continue;
                    case WRITE_PREP_OK:
                        // Point previous version to extra version.
                        chain_size = iter.pages[0].mem_page->size;
                        scan_set_next(&iter, chain_size);
                        found_size = scan_get_total_size(&iter);
                        iter.offset = chain_size;
                        append_deleted_version(&iter, epoch);
                        break;
                    default:
                        // Failed to account for a new write prep code
                        break;
                }
            }
        }
        else if(old_file_id) // Conditional remove, but entry was removed.
        {
            ret_code = KEYDIR_PUT_MODIFIED;
        }
        break;
    }

    free_scan_iter(&iter);

    // Update file stats
    if (found_size)
    {
        update_fstats(fstats_handle->fstats, fstats_handle->mutex,
                      found_file_id, 0, -1, 0, -found_size, 0);
        bc_atomic_add_64(&keydir->key_count, -1);
        bc_atomic_add_64(&keydir->key_bytes, -(int64_t)key_size);
    }

    return ret_code;
}

/*
 * Adds a memory page to the front of the free list.
 */
// chang to static when used
void add_free_page(bitcask_keydir * keydir, uint32_t page_idx)
{
    mem_page_t * mem_page;
    uint32_t first_free_idx;

    mem_page = keydir->mem_pages + page_idx;
    mem_page->page.is_free = 1;

    while (1)
    {
        first_free_idx = keydir->free_list_head;
        mem_page->page.next_free = first_free_idx;
        if (bc_atomic_cas_32(&keydir->free_list_head, first_free_idx, page_idx))
        {
            break;
        }
    }
}

void keydir_release(bitcask_keydir* keydir)
{
    int should_delete = 1;

    if (keydir->global_data && keydir->name)
    {
        global_keydir_data * gkd = keydir->global_data;

        enif_mutex_lock(gkd->mutex);
        enif_mutex_lock(keydir->mutex);
        keydir->refcount--;

        if (keydir->refcount == 0)
        {
            // Remember biggest_file_id in case someone re-opens the same name
            uint32_t global_biggest = 0, the_biggest = 0;
            khiter_t itr_biggest_file_id = kh_get(global_biggest_file_id,
                                                  gkd->global_biggest_file_id,
                                                  keydir->name);

            if (itr_biggest_file_id != kh_end(gkd->global_biggest_file_id))
            {
                global_biggest = kh_val(gkd->global_biggest_file_id,
                                        itr_biggest_file_id);
            }
            the_biggest = (global_biggest > keydir->biggest_file_id) ? \
                          global_biggest : keydir->biggest_file_id;
            kh_put2(global_biggest_file_id, gkd->global_biggest_file_id,
                    strdup(keydir->name), the_biggest);

            // This is the last reference to the named keydir. As such,
            // remove it from the hashtable so no one else tries to use it
            khiter_t itr = kh_get(global_keydirs, gkd->keydirs,
                                  keydir->name);
            kh_del(global_keydirs, gkd->keydirs, itr);
        }
        else
        {
            should_delete = 0;
        }

        enif_mutex_unlock(keydir->mutex);
        enif_mutex_unlock(gkd->mutex);
    }

    if (should_delete)
    {
        keydir_free_memory(keydir);
        free(keydir);
    }
}

#define INITIAL_ITER_ARRAY_SIZE 16

static int maybe_expand_itr_array(keydir_itr_array_t * itr_array)
{

    if (itr_array->size > itr_array->count)
    {
        return 0;
    }

    if (itr_array->size == 0)
    {
        itr_array->size = INITIAL_ITER_ARRAY_SIZE;
        itr_array->items = malloc(sizeof(keydir_itr_t*)
                                         * itr_array->size);
    }
    else
    {
        keydir_itr_t ** tmp_array;

        itr_array->size *= 2;
        tmp_array = realloc(itr_array->items,
                            sizeof(keydir_itr_t*) * itr_array->size);
        if (!tmp_array)
        {
            return ENOMEM;
        }

        itr_array->items = tmp_array;
    }

    return 0;
}

static void itr_array_insert(keydir_itr_array_t * itr_array,
                             keydir_itr_t * itr)
{
    unsigned i;
    maybe_expand_itr_array(itr_array);

    if (itr_array->count == 0)
    {
        itr_array->items[0] = itr;
        ++itr_array->count;
        return;
    }

    // List is in ascending epoch order, and epochs grow monotonically,
    // so inserts go at the end or near it.
    i = itr_array->count;
    do {
        if (itr_array->items[i-1]->epoch <= itr->epoch)
        {
            memmove(itr_array->items + i + 1, itr_array->items + i,
                    sizeof(keydir_itr_t*) * (itr_array->count - i));
            itr_array->items[i] = itr;
            ++itr_array->count;
            return;
        }
    } while(--i > 0);
}

void keydir_itr_init(bitcask_keydir * keydir,
                     KeydirItrSnapshotFlag snapshot_flag,
                     keydir_itr_t * itr)
{
    enif_mutex_lock(keydir->mutex);
    itr->keydir = keydir;
    itr->page_idx = MAX_PAGE_IDX;
    itr->offset = 0;
    itr->num_visited_offsets = 0;
    itr->visited_offsets = NULL;

    if (snapshot_flag == KEYDIR_ITR_NO_SNAPSHOT)
    {
       itr->epoch = MAX_EPOCH;
    }
    else
    {
        itr->epoch = bc_atomic_incr_64(&keydir->epoch);
    }

    // Ensure space for another iterator
    itr_array_insert(&keydir->itr_array, itr);

    if (keydir->min_epoch > itr->epoch)
    {
        keydir->min_epoch = itr->epoch;
    }

    ++keydir->refcount;
    enif_mutex_unlock(keydir->mutex);
}

keydir_itr_t * keydir_itr_create(bitcask_keydir * keydir,
                                 KeydirItrSnapshotFlag snapshot_flag)
{
    keydir_itr_t * itr = malloc(sizeof(keydir_itr_t));
    if (itr)
    {
        keydir_itr_init(keydir, snapshot_flag, itr);
    }
    return itr;
}

static void itr_array_delete(keydir_itr_array_t * itr_array,
                             keydir_itr_t * itr)
{
    unsigned i, last_i = itr_array->count - 1;
    keydir_itr_t ** p = itr_array->items;

    // TODO: Switch to binary search to handle large numbers of iterators.
    for (i = 0; i < itr_array->count; ++i, ++p)
    {
        if (*p == itr)
        {
            if (i < last_i)
            {
                memmove(p, p + 1, sizeof(keydir_itr_t*) * (last_i - i));
            }
            --itr_array->count;
        }
    }
}

void keydir_itr_release(keydir_itr_t * itr)
{
    if (itr->keydir)
    {
        bitcask_keydir * keydir = itr->keydir;

        enif_mutex_lock(keydir->mutex);
        itr_array_delete(&keydir->itr_array, itr);

        // Are we the lowest epoch? if so, update.
        if (keydir->min_epoch != MAX_EPOCH
            && keydir->min_epoch == itr->epoch)
        {
            if (keydir->itr_array.count == 0)
            {
                keydir->min_epoch = MAX_EPOCH;
            }
            else
            {
                keydir->min_epoch = keydir->itr_array.items[0]->epoch;
            }
        }

        enif_mutex_unlock(keydir->mutex);

        keydir_release(keydir);
        keydir = NULL;
        free(itr->visited_offsets);
        itr->visited_offsets = NULL;
    }
}

KeydirItrCode keydir_itr_next(keydir_itr_t * itr,
                              keydir_entry_t * entry)
{
    scan_iter_t scan_iter;
    mem_page_t * base_page;
    bitcask_keydir * keydir = itr->keydir;
    int insert_in_page;

    if (!keydir)
    {
        return KEYDIR_ITR_INVALID;
    }

    if (itr->page_idx == keydir->num_pages)
    {
        return KEYDIR_ITR_END;
    }

    // If iteration not started, visit first page
    if (itr->page_idx == MAX_PAGE_IDX)
    {
        insert_in_page = 1;
        itr->page_idx = 0;
    }
    else
    {
        insert_in_page = 0;
    }

    // Per page loop
    while (1)
    {
        init_scan_iterator(&scan_iter, keydir, itr->page_idx);
        scan_iter.offset = itr->offset;
        base_page = scan_iter.pages[0].mem_page;

        if (insert_in_page)
        {
            itr_array_insert(&base_page->itr_array, itr);
        }

        // If we come back here (move to next page), definitely insert.
        insert_in_page = 1;

        if (itr->offset >= base_page->size)
        {
            // move to next page
            itr_array_delete(&base_page->itr_array, itr);
            free_scan_iter(&scan_iter);

            if (++itr->page_idx == keydir->num_pages)
            {
                return KEYDIR_ITR_END;
            }
            
            itr->offset = 0;
            continue; // Restart on next page.
        }

        while (1)
        {
            if (ENOMEM == lock_pages_to_scan_entry(keydir, &scan_iter))
            {
                free_scan_iter(&scan_iter);
                return KEYDIR_ITR_OUT_OF_MEMORY;
            }

            entry->key_size = scan_get_key_size(&scan_iter);
            // Skip extra versions (no key), just process base versions.
            while (!entry->key_size)
            {
                scan_iter.offset += BASE_ENTRY_SIZE;

                if (scan_iter.offset >= base_page->size)
                {
                    break;
                }

                entry->key_size = scan_get_key_size(&scan_iter);
            }

            itr->offset = scan_iter.offset;
            if (itr->offset >= base_page->size)
            {
                itr_array_delete(&base_page->itr_array, itr);
                free_scan_iter(&scan_iter);

                if (++itr->page_idx == keydir->num_pages)
                {
                    return KEYDIR_ITR_END;
                }

                itr->offset = 0;
                break; // move to next page
            }

            scan_to_epoch(keydir, &scan_iter, itr->epoch);
            itr->offset += entry_size_for_key(entry->key_size);

            if (scan_iter.found && !scan_is_tombstone(&scan_iter))
            {
                scan_iter_to_entry(&scan_iter, entry);
                entry->key_size = scan_get_key_size(&scan_iter);
                // TODO: Optimize to copy key only once if possible.
                entry->key = malloc(entry->key_size);
                scan_get_key(&scan_iter, entry->key);
                free_scan_iter(&scan_iter);

                return KEYDIR_ITR_OK;
            }

            scan_iter.offset = itr->offset;
        }
    }
}
