// -------------------------------------------------------------------
//
// Copyright (c) 2010 Basho Technologies, Inc. All Rights Reserved.
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

#define PAGE_SIZE 4096

#define SCAN_INITIAL_PAGE_ARRAY_SIZE 64

#define kh_put2(name, h, k, v) {                        \
        int itr_status;                                 \
        khiter_t itr = kh_put(name, h, k, &itr_status); \
        kh_val(h, itr) = v; }

static void free_swap_pages_array(swap_array_t * swap_array)
{
    if (swap_array)
    {
        if (swap_array->next)
        {
            free_swap_pages_array(swap_array->next);
        }

        free(swap_array->pages);
    }
}

static void keydir_free_memory(bitcask_keydir * keydir)
{
    bitcask_fstats_entry* curr_f;
    khiter_t itr;

    if (keydir->fstats)
    {
        for (itr = kh_begin(keydir->fstats); itr != kh_end(keydir->fstats); ++itr)
        {
            if (kh_exist(keydir->fstats, itr))
            {
                curr_f = kh_val(keydir->fstats, itr);
                free(curr_f);
            }
        }
    }

    kh_destroy(fstats, keydir->fstats);

    if (keydir->swap_file_desc > -1)
    {
        ftruncate(keydir->swap_file_desc, 0);
    }

    if (keydir->swap_pages)
    {
        free(keydir->swap_pages->pages);
    }

    free_swap_pages_array(keydir->swap_pages);
    free(keydir->mem_pages);
    free(keydir->buffer);

    keydir->swap_pages = NULL;
    keydir->mem_pages = NULL;
    keydir->buffer = NULL;
}

static void keydir_init_free_list(bitcask_keydir * keydir)
{
    // Skip around the pages array to populate
    uint32_t idx = 0;
    uint32_t next_idx;
    uint32_t n = keydir->num_pages;
    const uint32_t step = 16;
    uint32_t offset = 0;
    keydir->free_list_head = 0;

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

    keydir->mem_pages[idx].page.next_free = MAX_PAGE_IDX;
}

#define KEYDIR_INIT_PATH_BUFFER_LENGTH 1024

/*
 * Returns an errno code or zero if successful. 
 */
int keydir_common_init(bitcask_keydir * keydir,
                               const char * basedir,
                               uint32_t num_pages,
                               uint32_t initial_num_swap_pages)

{
    char swap_path[KEYDIR_INIT_PATH_BUFFER_LENGTH];

    // Avoid unitialized pointers in case we call keydir_free_memory()
    keydir->buffer = NULL;
    keydir->mem_pages = NULL;
    keydir->swap_pages = NULL;
    
    keydir->buffer = malloc(PAGE_SIZE * num_pages);

    if (!keydir->buffer)
    {
        keydir_free_memory(keydir);
        return ENOMEM;
    }

    keydir->mem_pages = malloc(sizeof(mem_page_t) * num_pages);

    if (!keydir->mem_pages)
    {
        keydir_free_memory(keydir);
        return ENOMEM;
    }

    keydir->swap_pages = malloc(sizeof(swap_array_t));

    if (!keydir->swap_pages)
    {
        keydir_free_memory(keydir);
        return ENOMEM;
    }

    keydir->swap_pages->next = NULL;
    keydir->swap_pages->size = initial_num_swap_pages;
    keydir->swap_pages->pages = malloc(sizeof(page_t)* initial_num_swap_pages);

    if (!keydir->swap_pages->pages)
    {
        keydir_free_memory(keydir);
        return ENOMEM;
    }

    keydir_init_free_list(keydir);

    // create swap file.
    const char * extra_path = "/bitcask.swap";
    const int extra_length = strlen(extra_path);

    if (strlen(basedir) + extra_length + 1 > KEYDIR_INIT_PATH_BUFFER_LENGTH)
    {
        keydir_free_memory(keydir);
        return ENAMETOOLONG;
    }

    strcpy(swap_path, basedir);
    strcat(swap_path, "/bitcask.swap");
    keydir->swap_file_desc = open(swap_path, O_CREAT|O_TRUNC, 0600);

    if (keydir->swap_file_desc < 0)
    {
        keydir_free_memory(keydir);
        return errno;
    }
    
    // Hide swap file from users.
    // TODO: Add option to keep it visible for debugging.
    if (unlink(swap_path))
    {
        keydir_free_memory(keydir);
        return errno;
    }
    
    if (ftruncate(keydir->swap_file_desc, initial_num_swap_pages * PAGE_SIZE))
    {
        keydir_free_memory(keydir);
        return errno;
    }

    return 0; // Sweet success!!
}

void update_fstats(fstats_hash_t * fstats,
                   ErlNifMutex * mutex,
                   uint32_t file_id, uint32_t tstamp,
                   uint64_t expiration_epoch,
                   int32_t live_increment, int32_t total_increment,
                   int32_t live_bytes_increment, int32_t total_bytes_increment,
                   int32_t should_create)
{
    bitcask_fstats_entry* entry = 0;

    if (mutex)
    {
        enif_mutex_lock(mutex);
    }

    khiter_t itr = kh_get(fstats, fstats, file_id);

    if (itr == kh_end(fstats))
    {
        if (!should_create)
        {
            if (mutex)
            {
                enif_mutex_unlock(mutex);
            }
            return;
        }

        // Need to initialize new entry and add to the table
        entry = malloc(sizeof(bitcask_fstats_entry));
        memset(entry, '\0', sizeof(bitcask_fstats_entry));
        entry->expiration_epoch = MAX_EPOCH;
        entry->file_id = file_id;

        kh_put2(fstats, fstats, file_id, entry);
    }
    else
    {
        entry = kh_val(fstats, itr);
    }

    entry->live_keys   += live_increment;
    entry->total_keys  += total_increment;
    entry->live_bytes  += live_bytes_increment;
    entry->total_bytes += total_bytes_increment;

    if (expiration_epoch < entry->expiration_epoch)
    {
        entry->expiration_epoch = expiration_epoch;
    }

    if ((tstamp != 0 && tstamp < entry->oldest_tstamp) ||
        entry->oldest_tstamp == 0)
    {
        entry->oldest_tstamp = tstamp;
    }

    if ((tstamp != 0 && tstamp > entry->newest_tstamp) ||
        entry->newest_tstamp == 0)
    {
        entry->newest_tstamp = tstamp;
    }

    if (mutex)
    {
        enif_mutex_unlock(mutex);
    }
}

static int hash_key(char * key, uint32_t key_sz)
{
    return MURMUR_HASH(key, key_sz, 42);
}


static int is_page_borrowed(mem_page_t * page)
{
    return page->is_borrowed;
}

static int is_page_free(page_t * page)
{
    return page->is_free;
}

static void set_borrowed(mem_page_t * page)
{
    page->is_borrowed = 1;
}

static page_t * get_swap_page(uint32_t idx, swap_array_t * swap_pages)
{
    if (idx < swap_pages->size)
    {
        return &swap_pages->pages[idx];
    }

    // assert(idx > swap_pages->size)
    // We never call this function with out of bounds indices
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

typedef struct
{
    int                 found;
    uint32_t            base_idx;
    uint32_t            offset;
    uint32_t            num_pages;
    uint32_t            page_array_size;
    page_t **           pages;
    mem_page_t **       mem_pages;
    page_t *            pages0[SCAN_INITIAL_PAGE_ARRAY_SIZE];
    mem_page_t *        mem_pages0[SCAN_INITIAL_PAGE_ARRAY_SIZE];
} scan_iter_t;

static void* scan_get_field(scan_iter_t * result, int field_offset)
{
    int chain_ofs = result->offset + field_offset;
    int idx = chain_ofs / PAGE_SIZE;
    int ofs = chain_ofs % PAGE_SIZE;
    return result->pages[idx]->data + ofs;
}

static void scan_set_key(scan_iter_t * iter, const char * key, uint32_t key_size)
{
    // Split key along potentially multiple pages.
    // Pages are assumed to be already allocated.
    int key_offset      = iter->offset + ENTRY_KEY_OFFSET;
    int page_idx        = key_offset / PAGE_SIZE;
    int page_offset     = key_offset % PAGE_SIZE;
    int space_in_page   = PAGE_SIZE - page_offset;
    size_t section_size = key_size < space_in_page ? key_size : space_in_page;
    uint32_t remainder  = key_size;
    const char * src    = key;
    char * dst          = (char*)iter->pages[page_idx]->data + page_offset;

    memcpy(dst, src, section_size);
    remainder -= section_size;

    while (remainder > 0)
    {
        ++page_idx;
        src += section_size;
        section_size = remainder > PAGE_SIZE ? PAGE_SIZE : remainder;
        memcpy(dst, src, section_size);
        remainder -= section_size;
    }
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
    scan_set_uint64(iter, ENTRY_NEXT_OFFSET, v);
}

static void scan_set_key_size(scan_iter_t * iter, uint32_t v)
{
    scan_set_uint32(iter, ENTRY_KEY_SIZE_OFFSET, v);
}

static void scan_expand_page_array(scan_iter_t * iter)
{
    size_t byte_size;

    if (iter->num_pages >= iter->page_array_size)
    {
        iter->page_array_size *= 2;
        byte_size = sizeof(void*)*iter->page_array_size;
        // If pointing to static array, switch to dynamic.
        if (iter->page_array_size == SCAN_INITIAL_PAGE_ARRAY_SIZE)
        {
            iter->pages = malloc(byte_size);
            iter->mem_pages = malloc(byte_size);
        }
        else
        {
            iter->pages = realloc(iter->pages, byte_size);
            iter->mem_pages = realloc(iter->mem_pages, byte_size);
        }
    }
}

static void add_pages_to_scan(bitcask_keydir * keydir,
                              scan_iter_t * iter,
                              int n)
{
    uint32_t next;
    page_t * page;
    mem_page_t * mem_page;

    while(n--)
    {
        next = iter->pages[iter->num_pages-1]->next;
        if (next < keydir->num_pages)
        {   // memory page
            mem_page = keydir->mem_pages + next;
            page = &mem_page->page;
        }
        else // swap page
        {
            mem_page = (mem_page_t*)0;
            page = get_swap_page(next - keydir->num_pages, keydir->swap_pages);
        }

        enif_mutex_lock(page->mutex);

        scan_expand_page_array(iter);

        iter->pages[iter->num_pages] = page;
        iter->mem_pages[iter->num_pages] = mem_page;
        ++iter->num_pages;
    }
}

/* 
 * Ensures that we have all pages containing data for the entry we are
 * pointing to.
 */
static void lock_pages_to_scan_entry(bitcask_keydir * keydir,
                                     scan_iter_t * scan)
{
    int needed_pages = (scan->offset + ENTRY_KEY_OFFSET) / PAGE_SIZE + 1;
    uint32_t key_size;

    if (needed_pages > scan->num_pages)
    {
        add_pages_to_scan(keydir, scan, 1);
    }

    key_size     = scan_get_key_size(scan);
    needed_pages = (scan->offset + ENTRY_KEY_OFFSET + key_size) / PAGE_SIZE;
    add_pages_to_scan(keydir, scan, needed_pages - scan->num_pages);
}

static void init_scan_iterator(scan_iter_t * scan_iter,
                               uint32_t base_idx,
                               page_t * first_page,
                               mem_page_t * first_mem_page)
{
    scan_iter->base_idx = base_idx;
    scan_iter->found = 0;
    scan_iter->offset = 0;
    scan_iter->num_pages = 1;
    scan_iter->page_array_size = SCAN_INITIAL_PAGE_ARRAY_SIZE;
    scan_iter->pages = scan_iter->pages0;
    scan_iter->mem_pages = scan_iter->mem_pages0;
    scan_iter->pages[0] = first_page;
    scan_iter->mem_pages[0] = first_mem_page;
}


static int scan_keys_equal(const char * key,
                           uint32_t key_size,
                           scan_iter_t * iter)
{
    // compare bit in first page, then in up to PAGE_SIZE length chunks.
    
    uint32_t offset = iter->offset;
    uint32_t page_offset = offset % PAGE_SIZE;
    uint32_t page_idx = offset / PAGE_SIZE;
    uint32_t remaining = key_size;
    int next_size = PAGE_SIZE - page_offset; // potentially rest of first page
    char * entry_key;

    // This first compares the first bit of the key contained in the first
    // page, then pieces of (or potentially entire) subsequent pages.
    for(entry_key = (char*)iter->pages[page_idx]->data + page_offset;
        remaining > 0;
        next_size = PAGE_SIZE,
        entry_key = (char*)iter->pages[++page_idx]->data)
    {
        if (next_size > remaining)
        {
            next_size = remaining;
        }

        if (strncmp(key, entry_key, next_size) != 0)
        {
            // Difference found
            return 0;
        }
    }

    // keys match
    return 1;
}

/*
 * Skips to next entry in a multi-entry chain if there is any.
 * Returns 1 if should keep going
 */
static void scan_to_epoch(bitcask_keydir * keydir,
                          scan_iter_t * iter,
                          uint64_t      epoch)
{
    uint32_t last_offset;
    uint32_t next;
    uint64_t entry_epoch;

    next = scan_get_next(iter);

    while (next)
    {
        last_offset = iter->offset;
        iter->offset = next;
        lock_pages_to_scan_entry(keydir, iter);
        entry_epoch = scan_get_epoch(iter);
        if (entry_epoch >= epoch)
        {
            return;
        }
    }
}

static void scan_pages(bitcask_keydir * keydir,
                       char * key,
                       uint32_t key_size,
                       uint64_t epoch,
                       scan_iter_t * scan_iter)
{
    uint32_t entry_size;
    uint32_t data_size = scan_iter->mem_pages[0]->size;

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
            scan_iter->found = 1;
            return;
        }

        // Point offset to next entry
        entry_size = ENTRY_KEY_OFFSET + scan_get_key_size(scan_iter);
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
 */
static void scan_iter_to_entry(scan_iter_t * scan_iter,
                               basic_entry_t * return_entry)
{
    return_entry->epoch         = scan_get_epoch(scan_iter);
    return_entry->file_id       = scan_get_file_id(scan_iter);
    return_entry->total_size    = scan_get_total_size(scan_iter);
    return_entry->offset        = scan_get_offset(scan_iter);
    return_entry->timestamp     = scan_get_timestamp(scan_iter);
    return_entry->is_tombstone  = return_entry->offset == MAX_OFFSET;
}

static void unlock_pages(int num_pages, page_t ** pages)
{
    while(num_pages--)
    {
        enif_mutex_unlock((*pages++)->mutex);
    }
}

#define FREE_SCAN_DEFAULT 0
#define FREE_SCAN_LEAVE_BASE_LOCKED 1

static void free_scan_iter(scan_iter_t * scan_iter, int flags)
{
    if (flags & FREE_SCAN_LEAVE_BASE_LOCKED)
    {
        unlock_pages(scan_iter->num_pages - 1, scan_iter-> pages + 1);
    }
    else
    {
        unlock_pages(scan_iter->num_pages, scan_iter->pages);
    }

    if (scan_iter->page_array_size > SCAN_INITIAL_PAGE_ARRAY_SIZE)
    {
        free(scan_iter->pages);
        free(scan_iter->mem_pages);
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
static void scan_for_key( bitcask_keydir *  keydir,
                          char *            key,
                          uint32_t          key_size,
                          uint64_t          epoch,
                          scan_iter_t *     scan_iter)
{
    uint32_t base_idx;
    mem_page_t * base_page;
    page_t * first_page;
   
    base_idx = hash_key(key, key_size) % keydir->num_pages;
    base_page = keydir->mem_pages + base_idx;
    enif_mutex_lock(base_page->page.mutex);

    while (1)
    {
        if (base_page->alt_idx)
        {
            if (is_page_free(&base_page->page))
            {
                // Avoid locking a free page for too long.
                enif_mutex_unlock(base_page->page.mutex);
                first_page = get_swap_page(base_page->alt_idx, keydir->swap_pages);
                enif_mutex_lock(first_page->mutex);
                if (first_page->prev != base_idx)
                {
                    enif_mutex_unlock(first_page->mutex);
                    continue; // retry
                }
            }
            else
            {
                first_page = get_swap_page(base_page->alt_idx, keydir->swap_pages);
                enif_mutex_lock(first_page->mutex);
                enif_mutex_unlock(base_page->page.mutex);
                break;
            }
        }
        else
        {
            first_page = &base_page->page;
            break;
        }
    }

    init_scan_iterator(scan_iter, base_idx, first_page, base_page);
    scan_pages(keydir, key, key_size, epoch, scan_iter);
}

KeydirGetCode keydir_get(bitcask_keydir *    keydir,
                         char *              key,
                         uint32_t            key_size,
                         uint64_t            epoch,
                         basic_entry_t *     return_entry)
{
    scan_iter_t scan_iter;
    scan_for_key(keydir, key, key_size, epoch, &scan_iter);

    if (scan_iter.found)
    {
        scan_iter_to_entry(&scan_iter, return_entry);
    }

    free_scan_iter(&scan_iter, FREE_SCAN_DEFAULT);
    // The free operation only frees allocated memory and releases locks.
    // It is still safe to use simple fields in the iterator, like found.
    return scan_iter.found ? KEYDIR_GET_FOUND : KEYDIR_GET_NOT_FOUND;
}

static uint32_t entry_size_for_key(uint32_t key_size)
{
    // This actually fails if the key_size is close to 4G. Don't do that.
    uint32_t unpadded_size = ENTRY_KEY_OFFSET + key_size;
    // Pad to next 8 byte boundary so data is aligned properly
    return (unpadded_size + 7) / 8 * 8;
}

static int scan_is_first_in_memory(scan_iter_t * iter)
{
    return iter->pages[0] == &iter->mem_pages[0]->page;
}

/*
 * Returns the next page in the free list or NULL if none found.
 * It may find any number of pages that are marked as deleted in the list,
 * so may iterate for a bit before returning.
 * TODO: May need a fancier free list with lock-free internal deletions
 * if one exists or a regular cleanup sweep.
 */
static mem_page_t * allocate_free_page(bitcask_keydir * keydir)
{
    uint32_t first;
    mem_page_t * mem_page;
    page_t * page;

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
            enif_mutex_lock(page->mutex);
            if (page->is_free)
            {
                return mem_page;
            }
            else
            {
                enif_mutex_unlock(page->mutex);
            }
        }
    }
}

/*
 * Returns 0 if successful, other if memory allocation failed.
 */
static void expand_swap_file(bitcask_keydir * keydir, uint32_t old_num_pages)
{
    off_t new_file_size, page_offset;
    size_t new_num_pages, new_array_size;
    uint32_t i, new_head_idx = old_num_pages;
    page_t * page;
    swap_array_t * new_swap_array, * last_array;

    enif_mutex_lock(keydir->swap_grow_mutex);

    // Avoid having two threads expand the file in quick sequence
    if (keydir->num_swap_pages == old_num_pages)
    {
        new_num_pages = 2 * old_num_pages;
        new_file_size = new_num_pages * PAGE_SIZE;
        ftruncate(keydir->swap_file_desc, new_file_size);

        last_array = get_last_swap_array(keydir->swap_pages);
        new_swap_array = malloc(sizeof(swap_array_t));
        new_swap_array->size = new_num_pages;
        new_array_size = new_num_pages * sizeof(page_t);
        page_t * new_pages = malloc(new_array_size);
        page_offset = old_num_pages * PAGE_SIZE;

        for(i = 0; i < new_num_pages; ++i, page_offset += PAGE_SIZE)
        {
            page = &new_pages[i];
            page->mutex = enif_mutex_create(0);
            page->data = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
                              keydir->swap_file_desc, page_offset);
            page->next_free = new_num_pages + i + 1;

            if (page->data == MAP_FAILED)
            {
                new_pages = realloc(new_pages, sizeof(page_t)*i);

                if (i == 0)
                {
                    free(new_pages);
                    new_pages = 0;
                    free(new_swap_array);
                    new_swap_array = NULL;
                    new_head_idx = MAX_PAGE_IDX;
               }
               else
               {
                   new_swap_array->size = (uint32_t)i;
               }
               break;
           }
       }

       last_array->next = new_swap_array;
    }

    if (new_swap_array)
    {

        new_swap_array->pages[new_swap_array->size - 1].next = MAX_PAGE_IDX;
        // Atomically insert new entries at the head of the list.
        while (1)
        {
            if (bc_atomic_cas_32(&keydir->swap_free_list_head,
                                 keydir->swap_free_list_head,
                                 new_head_idx))
            {
                break;
            }
        }
    }

    enif_mutex_unlock(keydir->swap_grow_mutex);
}

static page_t * allocate_swap_page(bitcask_keydir * keydir, uint32_t * idx_out)
{
    uint32_t head_idx, num_swap_pages;
    page_t * head_page;

    // May need to be retried
    while(1)
    {
        num_swap_pages = keydir->num_swap_pages;

        // Ensure the number of pages is loaded before looking at the list
        // so we can avoid many threads expanding the pages at once when
        // the list goes empty.
        bc_full_barrier();

        head_idx = keydir->swap_free_list_head;

        // If list empty, expand swap file.
        if (head_idx == MAX_PAGE_IDX)
        {
            expand_swap_file(keydir, num_swap_pages);

            if (head_idx == MAX_PAGE_IDX)
            {
                // Oops, allocation failed.
                return (page_t*)0;
            }
            continue; // retry
        }

        head_page = get_swap_page(head_idx, keydir->swap_pages);

        if (bc_atomic_cas_32(&keydir->swap_free_list_head,
                          head_idx, head_page->next_free))
        {
            // We got the page!
            *idx_out = head_idx;
            return head_page;
        }
    }
}

#define WRITE_PREP_OK 0 
#define WRITE_PREP_NO_MEM 2

/*
 * Prepare chain to do a write.
 * If base page is free, remove from free list.
 * If base page is borrowed, need to claim it and find home to previous tenant.
 * If no space for new entry, allocate needed pages.
 */
static int write_prep(bitcask_keydir *   keydir,
                      scan_iter_t *      iter,
                      uint32_t           key_size)
{
    uint32_t size = iter->mem_pages[0]->size;
    uint32_t entry_size = entry_size_for_key(key_size);
    uint32_t wanted_size = iter->offset + entry_size;
    mem_page_t * new_mem_page, * base_page;
    uint32_t new_page_idx, num_pages, wanted_pages, num_extra_pages;
    page_t * new_page;

    if (wanted_size < size)
    {
        // Size overflow (> 4G). Give up on life!
        return WRITE_PREP_NO_MEM;
    }

    num_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE; 
    wanted_pages = (wanted_size + PAGE_SIZE - 1) / PAGE_SIZE;
    num_extra_pages = wanted_pages - num_pages;

    base_page = iter->mem_pages[0];

    // If writing on a free page, mark it as not free anymore.
    if (scan_is_first_in_memory(iter)
        && is_page_free(&iter->mem_pages[0]->page))
    {
        base_page->page.is_free = 1;
    }

    // If base page borrowed by another chain, claim it.
    if (size == 0 && is_page_borrowed(iter->mem_pages[0]))
    {
        // Try to allocate another page and transfer data.
        if (enif_mutex_trylock(iter->mem_pages[0]->page.mutex))
        {
            // Oops. Likely a thread is trying to lock our page.
            // For now, let's take the latency hit and let the other guy do
            // its thing, try again later.
            // TODO: Consider simply using an alternate memory or swap page
            // if this becomes a problem. We are most likely blocking an Erlang
            // scheduler here and wasting CPU.
            // TODO: Maybe simply signal that the operation should by tried
            // later, maybe in an async thread.
            enif_mutex_unlock(base_page->page.mutex);
            //enif_mutex_lock(
        }
    }

    while (num_extra_pages--)
    {
        new_mem_page = allocate_free_page(keydir);

        if (new_mem_page)
        {
            new_page = &new_mem_page->page;
            new_page_idx = new_mem_page - keydir->mem_pages;
        }
        // TODO: Pick from underutilized pages first if none free
        else
        {
            new_mem_page = (mem_page_t*)0;
            new_page = allocate_swap_page(keydir, &new_page_idx);
            if (!new_page)
            {
                return WRITE_PREP_NO_MEM;
            }
            // Note: swap pages are not locked. Nobody can get to them
            // once taken out of the swap free list and before they get
            // access to a chain containing them, which we have locked.
        }

        scan_expand_page_array(iter);

        iter->pages[iter->num_pages-1]->next = new_page_idx;
        iter->pages[iter->num_pages] = new_page;
        iter->mem_pages[iter->num_pages] = new_mem_page;
        ++iter->num_pages;
    }

    return WRITE_PREP_OK;
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
                         char *           key,
                         uint32_t         key_size,
                         uint32_t         file_id,
                         uint64_t         total_size,
                         uint64_t         offset,
                         uint32_t         timestamp,
                         uint32_t         old_file_id,
                         uint64_t         old_offset)
{
    scan_iter_t iter;
    uint64_t epoch;
    int can_update_in_place;
    KeydirPutCode ret_code = KEYDIR_PUT_OK;
    uint32_t chain_size;
    int write_prep_ret;

    epoch = bc_atomic_incr64(&keydir->epoch);
    can_update_in_place = keydir->min_epoch > epoch;
    scan_for_key(keydir, key, key_size, epoch, &iter);

    if (iter.found)
    {
        // If conditional put, verify entry has not changed
        // TODO: Original code had a shady comment (by yours truly) about the
        // conditional logic and merges finding two current values for the
        // same because they were in the same second. I think it's not needed,
        // but need to verify carefully.
        if (old_file_id &&
            (scan_get_file_id(&iter) != old_file_id ||
             scan_get_offset(&iter) != old_offset))
        {
            ret_code = KEYDIR_PUT_MODIFIED;
        }
        else if (can_update_in_place)
        {
            scan_set_file_id(&iter, file_id);
            scan_set_offset(&iter, offset);
            scan_set_total_size(&iter, total_size);
            scan_set_timestamp(&iter, timestamp);
            scan_set_epoch(&iter, epoch);
        }
        else // Adding extra version for this key.
        {
            chain_size = iter.mem_pages[0]->size;
            // Point previous version to extra version.
            scan_set_next(&iter, chain_size);
            // Expand to fit extra version, no extra copy of key needed.
            write_prep_ret = write_prep(keydir, &iter, 0);

            if (write_prep_ret == WRITE_PREP_NO_MEM)
            {
                ret_code = KEYDIR_PUT_OUT_OF_MEMORY;
            }
            else
            {
                // Point to new entry to modify with scan_* functions.
                iter.offset = chain_size;

                scan_set_file_id(&iter, file_id);
                scan_set_offset(&iter, offset);
                scan_set_total_size(&iter, total_size);
                scan_set_timestamp(&iter, timestamp);
                scan_set_epoch(&iter, epoch);
                scan_set_key_size(&iter, 0);
            }
        }
    }
    else if(old_file_id)
    {
        // Conditional put, but entry was removed.
        ret_code = KEYDIR_PUT_MODIFIED;
    }
    else
    {
        write_prep_ret = write_prep(keydir, &iter, key_size);
        scan_set_file_id(&iter, file_id);
        scan_set_offset(&iter, offset);
        scan_set_total_size(&iter, total_size);
        scan_set_timestamp(&iter, timestamp);
        scan_set_epoch(&iter, epoch);
        scan_set_key_size(&iter, key_size);
        scan_set_key(&iter, key, key_size);
    }

    free_scan_iter(&iter, FREE_SCAN_DEFAULT);

    return ret_code;
}


KeydirPutCode keydir_remove(bitcask_keydir * keydir,
                            char * key,
                            uint32_t key_size,
                            // conditional remove options
                            uint32_t old_file_id,
                            uint64_t old_offset)
{
    scan_iter_t iter;
    uint64_t epoch;
    int can_update_in_place;
    KeydirPutCode ret_code = KEYDIR_PUT_OK;
    uint32_t chain_size;
    int write_prep_ret;

    epoch = bc_atomic_incr64(&keydir->epoch);
    can_update_in_place = keydir->min_epoch > epoch;
    scan_for_key(keydir, key, key_size, epoch, &iter);

    if (iter.found)
    {
        // If conditional remove, verify entry has not changed
        if (old_file_id &&
            (scan_get_file_id(&iter) != old_file_id ||
             scan_get_offset(&iter) != old_offset))
        {
            ret_code = KEYDIR_PUT_MODIFIED;
        }
        else if (can_update_in_place)
        {
            scan_set_offset(&iter, MAX_OFFSET);
            scan_set_epoch(&iter, epoch);
        }
        else // Adding extra version for this key.
        {
            chain_size = iter.mem_pages[0]->size;
            // Point previous version to extra version.
            scan_set_next(&iter, chain_size);
            // Expand to fit extra version, no extra copy of key needed.
            write_prep_ret = write_prep(keydir, &iter, 0);

            if (write_prep_ret == WRITE_PREP_NO_MEM)
            {
                ret_code = KEYDIR_PUT_OUT_OF_MEMORY;
            }
            else
            {
                // Point to new entry to modify with scan_* functions.
                iter.offset = chain_size;

                scan_set_file_id(&iter, MAX_FILE_ID);
                scan_set_offset(&iter, MAX_OFFSET);
                scan_set_total_size(&iter, 0);
                scan_set_timestamp(&iter, 0);
                scan_set_epoch(&iter, epoch);
                scan_set_key_size(&iter, 0);
            }
        }
    }
    else if(old_file_id)
    {
        // Conditional remove, but entry was removed.
        ret_code = KEYDIR_PUT_MODIFIED;
    }

    free_scan_iter(&iter, FREE_SCAN_DEFAULT);

    return ret_code;
}

                  

/*
 * Adds a page to the front of the free list.
 * Should only be called on a locked page.
 */
static void add_free_page(bitcask_keydir * keydir, uint32_t page_idx)
{
    mem_page_t * mem_page;
    page_t * page;
    uint32_t first_free_idx;

    mem_page = keydir->mem_pages + page_idx;
    page = &mem_page->page;
    page->is_free = 1;

    while (1)
    {
        first_free_idx = keydir->free_list_head;
        page->next_free = first_free_idx;
        if (bc_atomic_cas_32(&keydir->free_list_head, first_free_idx, page_idx))
        {
            break;
        }
    }
}

void free_keydir(bitcask_keydir* keydir)
{
    keydir_free_memory(keydir);
    free(keydir);
}
