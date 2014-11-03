// -------------------------------------------------------------------
//
// bitcask: Eric Brewer-inspired key/value store
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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <assert.h>

#include "erl_nif.h"
#include "erl_driver.h"
#include "erl_nif_compat.h"
#include "erl_nif_util.h"

#include "khash.h"
#include "murmurhash.h"

#include <stdio.h>

#if defined(OS_SOLARIS) || defined(SOLARIS) || defined(sun)
 #define BITCASK_IS_SOLARIS 1
#else
 #undef BITCASK_IS_SOLARIS
#endif

#ifdef BITCASK_IS_SOLARIS
 #include <atomic.h>
#endif

//typesystem hack to avoid some incorrect errors.
typedef ErlNifUInt64 uint64;

#ifdef BITCASK_DEBUG
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
void DEBUG(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
int erts_snprintf(char *, size_t, const char *, ...); 
#define MAX_DEBUG_STR 128
#define DEBUG_STR(N, V) \
    char N[MAX_DEBUG_STR];\
    erts_snprintf(N, MAX_DEBUG_STR, "%s", V)

#define DEBUG_BIN(N, V, S) \
    char N[MAX_DEBUG_STR];\
    format_bin(N, MAX_DEBUG_STR, (unsigned char*)V, (size_t)S)

#define DEBUG2 DEBUG
#else
void DEBUG2(const char *fmt, ...) { }
#define DEBUG_STR(A, B)
#define DEBUG_BIN(N, V, S)
#  define DEBUG(X, ...) {}
#endif

#if defined(BITCASK_DEBUG) && defined(BITCASK_DEBUG_KEYDIR)
#  define DEBUG_KEYDIR(KD) print_keydir((KD))
#  define DEBUG_ENTRY(E) print_entry((E))
#else
#  define DEBUG_KEYDIR(X) {}
#  define DEBUG_ENTRY(E) {}
#endif

#ifdef PULSE
#include "pulse_c_send.h"
#endif

#ifdef BITCASK_DEBUG
void format_bin(char * buf, size_t buf_size, const unsigned char * bin, size_t bin_size)
{
    char cbuf[4]; // up to 3 digits + \0
    int is_printable = 1;
    int i, n;
    size_t av_size = buf_size;

    for (i=0;i<bin_size;++i)
    {
        if (!isprint(bin[i]))
        {
            is_printable = 0;
            break;
        }
    }

    buf[0] = '\0';

    // TODO: Protect against overriding that buffer yo!
    if (is_printable)
    {
        strcat(buf, "<<\"");
        av_size -= 3;
        n = av_size < bin_size ? av_size : bin_size;
        strncat(buf, (char*)bin, n);
        strcat(buf, "\">>");
    }
    else
    {
        strcat(buf, "<<");
        for (i=0;i<bin_size;++i)
        {
            if (i>0)
            {
                strcat(buf, ",");
            }
            sprintf(cbuf, "%u", bin[i]);
            strcat(buf, cbuf);
        }
        strcat(buf, ">>");
    }

}
#endif

static ErlNifResourceType* bitcask_keydir_RESOURCE;

static ErlNifResourceType* bitcask_lock_RESOURCE;

static ErlNifResourceType* bitcask_file_RESOURCE;

typedef struct
{
    int fd;
} bitcask_file_handle;

typedef struct
{
    uint32_t file_id;
    uint64_t live_keys;   // number of 'live' keys in entries and pending
    uint64_t live_bytes;  // number of 'live' bytes
    uint64_t total_keys;  // total number of keys written to file
    uint64_t total_bytes; // total number of bytes written to file
    uint32_t oldest_tstamp; // oldest observed tstamp in a file
    uint32_t newest_tstamp; // newest observed tstamp in a file
    uint64_t expiration_epoch; // file obsolete at this epoch
} bitcask_fstats_entry;

struct bitcask_keydir_entry_sib
{
    uint32_t file_id;
    uint32_t total_sz;
    uint64_t offset;
    uint64_t epoch;
    uint32_t tstamp;
    struct bitcask_keydir_entry_sib * next;
};
typedef struct bitcask_keydir_entry_sib bitcask_keydir_entry_sib;

typedef struct
{
    bitcask_keydir_entry_sib * sibs;
    uint16_t key_sz;
    char     key[0];
} bitcask_keydir_entry_head;

// These correspond with entry layout in memory
#define ENTRY_FILE_ID_OFFSET 0
#define ENTRY_TOTAL_SZ_OFFSET 4
#define ENTRY_EPOCH_OFFSET 8
#define ENTRY_OFFSET_OFFSET 16
#define ENTRY_TIMESTAMP_OFFSET 24
#define ENTRY_NEXT_OFFSET 28
#define ENTRY_KEY_SIZE_OFFSET 32
#define ENTRY_KEY_OFFSET 36

#define PAGE_SIZE 4096

#define SCAN_INITIAL_PAGE_ARRAY_SIZE 64

// Entry fields carefully laid out to correspond with ENTRY_*_OFFSET
// constaints and layout in pages. Change with care!
typedef struct
{
    uint32_t file_id;
    uint32_t total_size;
    uint64_t epoch;
    uint64_t offset;
    uint32_t timestamp;
} basic_entry_t;

#define MAX_TIME ((uint32_t)-1)
#define MAX_EPOCH ((uint64_t)-1)
#define MAX_SIZE ((uint32_t)-1)
#define MAX_FILE_ID ((uint32_t)-1)
#define MAX_OFFSET ((uint64_t)-1)
#define MAX_PAGE_IDX ((uint32_t)-1)

KHASH_MAP_INIT_INT(fstats, bitcask_fstats_entry*);

typedef khash_t(fstats) fstats_hash_t;

// Make sure fields are aligned properly on the page structs!
// Don't modify willy-nilly!

typedef struct
{
    ErlNifMutex *   mutex;
    void *          data;
    uint32_t        prev;
    uint32_t        next;
    uint32_t        next_free;
} page_t;

typedef struct
{
    page_t   page;
    uint32_t size;
    uint32_t alt_idx;
    uint32_t dead_bytes;
    uint8_t  is_free;
    uint8_t  is_borrowed;
} mem_page_t;

struct swap_array_struct
{
    page_t *                    pages;
    struct swap_array_struct *  next;
    uint32_t                    size;
};

typedef struct swap_array_struct swap_array_t;

typedef struct
{
    ErlNifMutex *     mutex;
    void *            buffer;
    mem_page_t *      mem_pages;
    uint32_t          num_pages;
    volatile uint32_t free_list_head;
    swap_array_t *    swap_pages;
    uint32_t          num_swap_pages;
    volatile uint32_t swap_free_list_head;
    ErlNifMutex*      swap_grow_mutex;
    int               swap_file_desc;

    volatile uint64_t epoch;
    volatile uint64_t min_epoch;

    volatile uint64_t key_count;
    volatile uint64_t key_bytes;
    fstats_hash_t*    fstats;
    uint32_t          biggest_file_id;
    unsigned int      refcount;
    char              is_ready;
    char              name[0];
} bitcask_keydir;

typedef struct
{
    bitcask_keydir* keydir;
    uint64_t        iterator_epoch;
    uint32_t        iterator_page;
    int             iterating;
    fstats_hash_t*  fstats;
    ErlNifMutex *   fstats_mutex;
} bitcask_keydir_handle;

typedef struct
{
    int   fd;
    int   is_write_lock;
    char  filename[0];
} bitcask_lock_handle;

KHASH_INIT(global_biggest_file_id, char*, uint32_t, 1, kh_str_hash_func, kh_str_hash_equal);
KHASH_INIT(global_keydirs, char*, bitcask_keydir*, 1, kh_str_hash_func, kh_str_hash_equal);

typedef struct
{
    khash_t(global_biggest_file_id)* global_biggest_file_id;
    khash_t(global_keydirs)* global_keydirs;
    ErlNifMutex*             global_keydirs_lock;
} bitcask_priv_data;

#define kh_put2(name, h, k, v) {                        \
        int itr_status;                                 \
        khiter_t itr = kh_put(name, h, k, &itr_status); \
        kh_val(h, itr) = v; }                           \

#define kh_put_set(name, h, k) {                        \
        int itr_status;                                 \
        kh_put(name, h, k, &itr_status); }


// Handle lock helper functions
#define LOCK(keydir)      { if (keydir->mutex) enif_mutex_lock(keydir->mutex); }
#define UNLOCK(keydir)    { if (keydir->mutex) enif_mutex_unlock(keydir->mutex); }

// Atoms (initialized in on_load)
static ERL_NIF_TERM ATOM_ALLOCATION_ERROR;
static ERL_NIF_TERM ATOM_ALREADY_EXISTS;
static ERL_NIF_TERM ATOM_BITCASK_ENTRY;
static ERL_NIF_TERM ATOM_ERROR;
static ERL_NIF_TERM ATOM_FALSE;
static ERL_NIF_TERM ATOM_FSTAT_ERROR;
static ERL_NIF_TERM ATOM_FTRUNCATE_ERROR;
static ERL_NIF_TERM ATOM_GETFL_ERROR;
static ERL_NIF_TERM ATOM_ILT_CREATE_ERROR; /* Iteration lock thread creation error */
static ERL_NIF_TERM ATOM_ITERATION_IN_PROCESS;
static ERL_NIF_TERM ATOM_ITERATION_NOT_PERMITTED;
static ERL_NIF_TERM ATOM_ITERATION_NOT_STARTED;
static ERL_NIF_TERM ATOM_LOCK_NOT_WRITABLE;
static ERL_NIF_TERM ATOM_NOT_FOUND;
static ERL_NIF_TERM ATOM_NOT_READY;
static ERL_NIF_TERM ATOM_OK;
static ERL_NIF_TERM ATOM_OUT_OF_DATE;
static ERL_NIF_TERM ATOM_PREAD_ERROR;
static ERL_NIF_TERM ATOM_PWRITE_ERROR;
static ERL_NIF_TERM ATOM_READY;
static ERL_NIF_TERM ATOM_SETFL_ERROR;
static ERL_NIF_TERM ATOM_TRUE;
static ERL_NIF_TERM ATOM_UNDEFINED;
static ERL_NIF_TERM ATOM_EOF;
static ERL_NIF_TERM ATOM_CREATE;
static ERL_NIF_TERM ATOM_READONLY;
static ERL_NIF_TERM ATOM_O_SYNC;
// lseek equivalents for file_position
static ERL_NIF_TERM ATOM_CUR;
static ERL_NIF_TERM ATOM_BOF;

// Prototypes
ERL_NIF_TERM bitcask_nifs_keydir_new0(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_keydir_new1(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_maybe_keydir_new1(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_keydir_mark_ready(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_keydir_get_int(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_keydir_get_epoch(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_keydir_put_int(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_keydir_remove(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_keydir_copy(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_keydir_itr(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_keydir_itr_next(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_keydir_itr_release(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_keydir_info(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_keydir_release(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_keydir_trim_fstats(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

ERL_NIF_TERM bitcask_nifs_increment_file_id(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

ERL_NIF_TERM bitcask_nifs_create_tmp_file(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

ERL_NIF_TERM bitcask_nifs_lock_acquire(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_lock_release(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_lock_readdata(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_lock_writedata(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

ERL_NIF_TERM bitcask_nifs_file_open(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_file_close(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_file_sync(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_file_pread(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_file_pwrite(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_file_read(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_file_write(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_file_position(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_file_seekbof(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_file_truncate(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

ERL_NIF_TERM bitcask_nifs_update_fstats(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_set_pending_delete(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

ERL_NIF_TERM errno_atom(ErlNifEnv* env, int error);
ERL_NIF_TERM errno_error_tuple(ErlNifEnv* env, ERL_NIF_TERM key, int error);

static void lock_release(bitcask_lock_handle* handle);

static void bitcask_nifs_keydir_resource_cleanup(ErlNifEnv* env, void* arg);
static void bitcask_nifs_file_resource_cleanup(ErlNifEnv* env, void* arg);

static ErlNifFunc nif_funcs[] =
{
#ifdef PULSE
    {"set_pulse_pid", 1, set_pulse_pid},
#endif
    {"keydir_new", 0, bitcask_nifs_keydir_new0},
    {"keydir_new", 1, bitcask_nifs_keydir_new1},
    {"maybe_keydir_new", 1, bitcask_nifs_maybe_keydir_new1},
    {"keydir_mark_ready", 1, bitcask_nifs_keydir_mark_ready},
    {"keydir_put_int", 10, bitcask_nifs_keydir_put_int},
    {"keydir_get_int", 3, bitcask_nifs_keydir_get_int},
    {"keydir_get_epoch", 1, bitcask_nifs_keydir_get_epoch},
    {"keydir_remove", 3, bitcask_nifs_keydir_remove},
    {"keydir_remove_int", 6, bitcask_nifs_keydir_remove},
    {"keydir_copy", 1, bitcask_nifs_keydir_copy},
    {"keydir_itr_int", 4, bitcask_nifs_keydir_itr},
    {"keydir_itr_next_int", 1, bitcask_nifs_keydir_itr_next},
    {"keydir_itr_release", 1, bitcask_nifs_keydir_itr_release},
    {"keydir_info", 1, bitcask_nifs_keydir_info},
    {"keydir_release", 1, bitcask_nifs_keydir_release},
    {"keydir_trim_fstats", 2, bitcask_nifs_keydir_trim_fstats},

    {"increment_file_id", 1, bitcask_nifs_increment_file_id},
    {"increment_file_id", 2, bitcask_nifs_increment_file_id},

    {"lock_acquire_int",   2, bitcask_nifs_lock_acquire},
    {"lock_release_int",   1, bitcask_nifs_lock_release},
    {"lock_readdata_int",  1, bitcask_nifs_lock_readdata},
    {"lock_writedata_int", 2, bitcask_nifs_lock_writedata},

    {"file_open_int",   2, bitcask_nifs_file_open},
    {"file_close_int",  1, bitcask_nifs_file_close},
    {"file_sync_int",   1, bitcask_nifs_file_sync},
    {"file_pread_int",  3, bitcask_nifs_file_pread},
    {"file_pwrite_int", 3, bitcask_nifs_file_pwrite},
    {"file_read_int",   2, bitcask_nifs_file_read},
    {"file_write_int",  2, bitcask_nifs_file_write},
    {"file_position_int",  2, bitcask_nifs_file_position},
    {"file_seekbof_int", 1, bitcask_nifs_file_seekbof},
    {"file_truncate_int", 1, bitcask_nifs_file_truncate},
    {"update_fstats", 8, bitcask_nifs_update_fstats},
    {"set_pending_delete", 2, bitcask_nifs_set_pending_delete}
};

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
static int keydir_common_init(bitcask_keydir * keydir,
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


ERL_NIF_TERM bitcask_nifs_keydir_new0(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    // First, setup a resource for our handle
    bitcask_keydir_handle* handle = enif_alloc_resource_compat(env,
                                                               bitcask_keydir_RESOURCE,
                                                               sizeof(bitcask_keydir_handle));
    memset(handle, '\0', sizeof(bitcask_keydir_handle));

    // Now allocate the actual keydir instance. Because it's unnamed/shared, we'll
    // leave the name and lock portions null'd out
    bitcask_keydir* keydir = malloc(sizeof(bitcask_keydir));
    memset(keydir, '\0', sizeof(bitcask_keydir));

    // Assign the keydir to our handle and hand it back
    handle->keydir = keydir;
    ERL_NIF_TERM result = enif_make_resource(env, handle);
    enif_release_resource_compat(env, handle);
    return enif_make_tuple2(env, ATOM_OK, result);
}

ERL_NIF_TERM bitcask_nifs_maybe_keydir_new1(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    char name[4096];
    if (enif_get_string(env, argv[0], name, sizeof(name), ERL_NIF_LATIN1))
    {
        // Get our private stash and check the global hash table for this entry
        bitcask_priv_data* priv = (bitcask_priv_data*)enif_priv_data(env);
        
        enif_mutex_lock(priv->global_keydirs_lock);
        khiter_t itr = kh_get(global_keydirs, priv->global_keydirs, name);
        khiter_t table_end = kh_end(priv->global_keydirs); /* get end while lock is held! */
        enif_mutex_unlock(priv->global_keydirs_lock);
        if (itr != table_end)
        {
            return bitcask_nifs_keydir_new1(env, argc, argv);
        } 
        else
        {
            return enif_make_tuple2(env, ATOM_ERROR, ATOM_NOT_READY);
        }
    } 
    else 
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_keydir_new1(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    char name[4096];
    size_t name_sz;
    if (enif_get_string(env, argv[0], name, sizeof(name), ERL_NIF_LATIN1))
    {
        name_sz = strlen(name);

        // Get our private stash and check the global hash table for this entry
        bitcask_priv_data* priv = (bitcask_priv_data*)enif_priv_data(env);
        enif_mutex_lock(priv->global_keydirs_lock);

        bitcask_keydir* keydir;
        khiter_t itr = kh_get(global_keydirs, priv->global_keydirs, name);
        if (itr != kh_end(priv->global_keydirs))
        {
            keydir = kh_val(priv->global_keydirs, itr);
            // Existing keydir is available. Check the is_ready flag to determine if
            // the original creator is ready for other processes to use it.
            if (!keydir->is_ready)
            {
                // Notify the caller that while the requested keydir exists, it's not
                // ready for public usage.
                enif_mutex_unlock(priv->global_keydirs_lock);
                return enif_make_tuple2(env, ATOM_ERROR, ATOM_NOT_READY);
            }
            else
            {
                keydir->refcount++;
            }
        }
        else
        {
            // No such keydir, create a new one and add to the globals list. Make sure
            // to allocate enough room for the name.
            keydir = malloc(sizeof(bitcask_keydir) + name_sz + 1);
            memset(keydir, '\0', sizeof(bitcask_keydir) + name_sz + 1);
            strncpy(keydir->name, name, name_sz + 1);

            // Be sure to initialize the mutex and set our refcount
            keydir->mutex = enif_mutex_create(name);
            keydir->refcount = 1;

            keydir_common_init(keydir, ".", 1024, 1024);

            // Finally, register this new keydir in the globals
            kh_put2(global_keydirs, priv->global_keydirs, keydir->name, keydir);

            khiter_t itr_biggest_file_id = kh_get(global_biggest_file_id, priv->global_biggest_file_id, name);
            if (itr_biggest_file_id != kh_end(priv->global_biggest_file_id)) {
                uint32_t old_biggest_file_id = kh_val(priv->global_biggest_file_id, itr_biggest_file_id);
                keydir->biggest_file_id = old_biggest_file_id;
            }
        }

        enif_mutex_unlock(priv->global_keydirs_lock);

        // Setup a resource for the handle
        bitcask_keydir_handle* handle = enif_alloc_resource_compat(env,
                                                                   bitcask_keydir_RESOURCE,
                                                                   sizeof(bitcask_keydir_handle));
        memset(handle, '\0', sizeof(bitcask_keydir_handle));
        handle->keydir = keydir;
        ERL_NIF_TERM result = enif_make_resource(env, handle);
        enif_release_resource_compat(env, handle);

        // Return to the caller a tuple with the reference and an atom
        // indicating if the keydir is ready or not.
        ERL_NIF_TERM is_ready_atom = keydir->is_ready ? ATOM_READY : ATOM_NOT_READY;
        return enif_make_tuple2(env, is_ready_atom, result);
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_keydir_mark_ready(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;

    if (enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE, (void**)&handle))
    {
        bitcask_keydir* keydir = handle->keydir;
        LOCK(keydir);
        keydir->is_ready = 1;
        UNLOCK(keydir);
        return ATOM_OK;
    }
    else
    {
        return enif_make_badarg(env);
    }
}

// TODO: Update to take keydir handle instead and update
// per thread stats, not global keydir stats which will not be shared.
static void update_fstats(fstats_hash_t * fstats,
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

// NIF wrapper around update_fstats().
ERL_NIF_TERM bitcask_nifs_update_fstats(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;
    uint32_t file_id, tstamp;
    int32_t live_increment, total_increment;
    int32_t live_bytes_increment, total_bytes_increment;
    int32_t should_create;

    if (argc == 8
            && enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE,
                (void**)&handle)
            && enif_get_uint(env, argv[1], &file_id)
            && enif_get_uint(env, argv[2], &tstamp)
            && enif_get_int(env, argv[3], &live_increment)
            && enif_get_int(env, argv[4], &total_increment)
            && enif_get_int(env, argv[5], &live_bytes_increment)
            && enif_get_int(env, argv[6], &total_bytes_increment)
            && enif_get_int(env, argv[7], &should_create))
    {
        update_fstats(handle->fstats, handle->fstats_mutex,
                      file_id, tstamp, MAX_EPOCH,
                      live_increment, total_increment,
                      live_bytes_increment, total_bytes_increment,
                      should_create);
        return ATOM_OK;
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_set_pending_delete(ErlNifEnv* env, int argc,
        const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;
    uint32_t file_id;

    if (argc == 2
            && enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE,
                (void**)&handle)
            && enif_get_uint(env, argv[1], &file_id))
    {
        // TODO: Should we really do this on the global fstats?
        update_fstats(handle->keydir->fstats, handle->keydir->mutex,
                      file_id, 0, handle->keydir->epoch,
                      0, 0, 0, 0, 0);
        return ATOM_OK;
    }
    else
    {
        return enif_make_badarg(env);
    }
}

static int hash_key(char * key, uint32_t key_sz)
{
    return MURMUR_HASH(key, key_sz, 42);
}

static khint_t keydir_entry_hash(bitcask_keydir_entry* entry)
{
    khint_t h;
    if (IS_ENTRY_LIST(entry))
    {
        bitcask_keydir_entry_head* par = GET_ENTRY_LIST_POINTER(entry);
        h = MURMUR_HASH(par->key, par->key_sz, 42);
    }
    else
    {
        h = MURMUR_HASH(entry->key, entry->key_sz, 42);
    }
    return h;
}


static khint_t keydir_entry_equal(bitcask_keydir_entry* lhs,
                                  bitcask_keydir_entry* rhs)
{
    char* lkey;
    char* rkey;
    int lsz, rsz;

    if (IS_ENTRY_LIST(lhs)) {
        bitcask_keydir_entry_head* h = GET_ENTRY_LIST_POINTER(lhs);
        lkey = &h->key[0];
        lsz = h->key_sz;
    }
    else
    {
        lkey = &lhs->key[0];
        lsz = lhs->key_sz;
    }
    if (IS_ENTRY_LIST(rhs)) {
        bitcask_keydir_entry_head* h = GET_ENTRY_LIST_POINTER(rhs);
        rkey = &h->key[0];
        rsz = h->key_sz;
    }
    else
    {
        rkey = &rhs->key[0];
        rsz = rhs->key_sz;
    }

    if (lsz != rsz)
    {
        return 0;
    }
    else
    {
        return (memcmp(lkey, rkey, lsz) == 0);
    }
}

// Custom hash function to be able to look up entries using a
// ErlNifBinary without allocating a new entry just for that.
static khint_t nif_binary_hash(void* void_bin)
{
    ErlNifBinary * bin =(ErlNifBinary*)void_bin;
    return MURMUR_HASH(bin->data, bin->size, 42);
}

// Custom equals function to be able to look up entries using a
// ErlNifBinary without allocating a new entry just for that.
static khint_t nif_binary_entry_equal(bitcask_keydir_entry* lhs,
        void * void_rhs)
{
    char* lkey;
    int lsz;

    if (IS_ENTRY_LIST(lhs)) {
        bitcask_keydir_entry_head* h = GET_ENTRY_LIST_POINTER(lhs);
        lkey = &h->key[0];
        lsz = h->key_sz;
    }
    else
    {
        lkey = &lhs->key[0];
        lsz = lhs->key_sz;
    }

    ErlNifBinary * rhs = (ErlNifBinary*)void_rhs;

    if (lsz != rhs->size)
    {
        return 0;
    }
    else
    {
        return (memcmp(lkey, rhs->data, lsz) == 0);
    }
}

#ifdef BITCASK_DEBUG
void print_keydir(bitcask_keydir* keydir)
{
}
#endif

ERL_NIF_TERM bitcask_nifs_keydir_put_int(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;
    bitcask_keydir_entry_proxy entry;
    ErlNifBinary key;
    uint32_t nowsec;
    uint32_t newest_put;
    uint32_t old_file_id;
    uint64_t old_offset;

    if (enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE, (void**)&handle) &&
        enif_inspect_binary(env, argv[1], &key) &&
        enif_get_uint(env, argv[2], &(entry.file_id)) &&
        enif_get_uint(env, argv[3], &(entry.total_sz)) &&
        enif_get_uint64_bin(env, argv[4], &(entry.offset)) &&
        enif_get_uint(env, argv[5], &(entry.tstamp)) &&
        enif_get_uint(env, argv[6], &(nowsec)) &&
        enif_get_uint(env, argv[7], &(newest_put)) &&
        enif_get_uint(env, argv[8], &(old_file_id)) &&
        enif_get_uint64_bin(env, argv[9], &(old_offset)))
    {
        bitcask_keydir* keydir = handle->keydir;
        entry.key = (char*)key.data;
        entry.key_sz = key.size;

        DEBUG2("LINE %d put\r\n", __LINE__);

        DEBUG_BIN(dbgKey, key.data, key.size);
        DEBUG("+++ Put key = %s file_id=%d offset=%d total_sz=%d tstamp=%u old_file_id=%d\r\n",
                dbgKey,
              (int) entry.file_id, (int) entry.offset,
              (int)entry.total_sz, (unsigned) entry.tstamp, (int)old_file_id);
        DEBUG_KEYDIR(keydir);

    }
    else
    {
        return enif_make_badarg(env);
    }
}

static int is_page_borrowed(mem_page_t * page)
{
    return page->is_borrowed;
}

static int is_page_free(mem_page_t * page)
{
    return page->prev_free != 0 || page->next_free != 0;
}

static void unset_free(mem_page_t * page)
{
    page->is_free = 0;
    page->page.prev_free = 0;
    page->page.next_free = 0;
}

static void set_borrowed(mem_page_t * page)
{
    page->is_borrowed = 1;
}

static page_t * get_swap_page(uint32_t idx, swap_array_t * swap_pages)
{
    if (idx < swap_pages->size)
    {
        return swap_pages->pages[idx];
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
    page_t              pages0[SCAN_INITIAL_PAGE_ARRAY_SIZE]
    page_t              mem_pages0[SCAN_INITIAL_PAGE_ARRAY_SIZE]
} scan_iter_t;

static void* scan_get_field(scan_iter_t * result, int field_offset)
{
    int chain_ofs = result->offset + field_offset;
    int idx = chain_ofs / PAGE_SIZE;
    int ofs = chain_ofs % PAGE_SIZE;
    return pages[idx]->data + ofs;
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

static void scan_set_uint64(scan_iter_t * iter, int offset, uint64_t val)
{
    *((uint64_t*)scan_get_field(iter, offset)) = val;
}

static void scan_set_uint32(scan_iter_t * iter, int offset, uint32_t val)
{
    *((uint32_t*)scan_get_field(iter, offset)) = val;
}

static void scan_set_uint16(scan_iter_t * iter, int offset, uint16_t val)
{
    *((uint16_t*)scan_get_field(iter, offset)) = val;
}

static void scan_set_file_id(scan_iter_t * iter, uint32_t v)
{
    scan_set_uint32(iter, ENTRY_FILE_ID_OFFSET, v);
}

static void scan_set_total_size(scan_iter_t * iter, uint32_t v)
{
    scan_set_uint32(iter, ENTRY_TOTAL_SZ_OFFSET, v);
}

static void scan_set_timestamp(scan_iter_t * iter, uint32_t v)
{
    scan_set_uint32(iter, ENTRY_TOTAL_TIMESTAMP_OFFSET, v);
}

static void scan_set_epoch(scan_iter_t * iter, uint64_t v)
{
    scan_set_uint64(iter, ENTRY_TOTAL_EPOCH_OFFSET, v);
}

static void scan_set_offset(scan_iter_t * iter, uint64_t v)
{
    scan_set_uint64(iter, ENTRY_TOTAL_OFFSET_OFFSET, v);
}

static void scan_set_key_size(scan_iter_t * iter, uint32_t v)
{
    scan_set_uint32(iter, ENTRY_TOTAL_KEY_SIZE_OFFSET, v);
}

static void init_scan_iterator(scan_iter_t & scan_iter,
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

static void scan_pages(char * key,
                       uint32_t key_size,
                       uint64_t epoch,
                       int data_size,
                       scan_iter_t * scan_iter)
{
    if (scan_iter->mem_pages[0]->size == 0)
    {
        return;
    }

    for(;;)
    {
        lock_pages_to_scan_entry(scan_iter);

        // Current entry matches key?
        if (scan_cmp_keys(key, key_size, scan_iter))
        {   
            if (scan_get_epoch(scan_iter) > epoch)
            {
                // Entry added after requested snapshot. Ignore.
                return;
            }

            scan_to_epoch(scan_iter, epoch);
            scan_iter->found = 1;
            return;
        }

        // Point offset to next entry
        entry_size = ENTRY_FILE_KEY_OFFSET + scan_get_key_size(scan_iter);
        scan_iter->offset += entry_size;

        if (scan_iter->offset >= data_size)
        {
            // No more entries
            return;
        }
    }
}

static void allocate_pages_for_entry(
        scan_iter_t * scan_iter,
        int entry_size)
{
}


/* 
 * Ensures that we have all pages containing data for the entry we are
 * pointing to.
 */
static void lock_pages_to_scan_entry(scan_iter_t * scan)
{
    mem_page_t * next_mem_page;
    page_t * next_page;
    int needed_pages = (scan->offset + ENTRY_KEY_OFFSET) / PAGE_SIZE + 1;
    uint32_t key_size;

    if (needed_pages > scan->num_pages)
    {
        add_pages_to_scan(scan, 1);
    }

    key_size     = scan_get_key_size(result);
    needed_pages = (scan->offset + ENTRY_KEY_OFFSET + key_size) / PAGE_SIZE;
    add_pages_to_scan(scan, needed_pages - scan->num_pages);
}

static void add_pages_to_scan(
        bitcask_keydir * keydir,
        scan_iter_t * scan,
        int n)
{
    uint32_t next;
    page_t * page;
    mem_page_t * mem_page;
    int byte_size;

    while(n--)
    {
        next = scan->pages[scan->num_pages-1]->next;
        if (next < keydir->num_pages)
        {
            // memory page
            mem_page = keydir->pages[next];
            page = &mem_page->page;
        }
        else
        {
            // swap page
            mem_page = (mem_page_t*)0;
            page = get_swap_page(next - keydir->num_pages,
                    keydir->swap_pages, next);
        }

        enif_mutex_lock(page->mutex);

        scan_expand_page_array(iter);

        scan->pages[scan->num_pages] = page;
        scan->mem_pages[scan->num_pages] = mem_page;
        ++scan->num_pages;
    }
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

/*
 * Skips to next entry in a multi-entry chain if there is any.
 * Returns 1 if should keep going
 */
static void scan_to_epoch(scan_iter_t * scan_iter,
                          uint64_t      epoch)
{
    uint32_t last_offset;
    uint32_t next;
    uint64_t entry_epoch;

    next = scan_get_next(result);

    while (next)
    {
        last_offset = scan_iter->offset;
        scan_iter->offset = next;
        lock_pages_to_scan_entry(scan_iter);
        entry_epoch = scan_get_epoch(scan_iter);
        if (entry_epoch >= epoch)
        {
            return;
        }
    }
}

/*
 * Populate return entry fields from scan data.
 * It handles entries split across page boundaries.
 */
static void scan_iter_to_entry(
        scan_iter_t * scan_iter,
        basic_entry_t * return_entry)
{
    return_entry->epoch    = scan_get_epoch(scan_iter);
    return_entry->file_id  = scan_get_file_id(scan_iter);
    return_entry->total_sz = scan_get_total_sz(scan_iter);
    return_entry->offset   = scan_get_offset(scan_iter);
    return_entry->tstamp   = scan_get_timestamp(scan_iter);
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
    base_page = keydir->mem_pages[base_idx];
    enif_mutex_lock(base_page->mutex);

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
    scan_pages(key, key_size, epoch, &scan_iter);
}

static int keydir_get(bitcask_keydir *    keydir,
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
    return scan_iter.found;
}

static uint64_t atomic_incr64(volatile uint64_t * ptr)
{
#if BITCASK_IS_SOLARIS
    return atomic_inc_64_nv(ptr);
#else
    return __sync_add_and_fetch(ptr, 1);
#endif
}

static uint32_t atomic_incr32(volatile uint32_t * ptr)
{
#if BITCASK_IS_SOLARIS
    return atomic_inc_32_nv(ptr);
#else
    return __sync_add_and_fetch(ptr, 1);
#endif
}

static bool atomic_cas_32(volatile uint32_t * ptr,
                          uint32_t comp_val,
                          uint32_t exchange_val)
{
#if LEVELDB_IS_SOLARIS
    return (comp_val==atomic_cas_32(ptr, comp_val, exchange_val));
#else
    return __sync_bool_compare_and_swap(ptr, comp_val, exchange_val);
#endif
}

static bool atomic_cas_64(volatile uint64_t * ptr,
                          uint64_t comp_val,
                          uint64_t exchange_val)
{
#if LEVELDB_IS_SOLARIS
    return (comp_val==atomic_cas_ptr(ptr, comp_val, exchange_val));
#else
    return __sync_bool_compare_and_swap(ptr, comp_val, exchange_val);
#endif
}

static bool atomic_cas_ptr(volatile void ** ptr,
                           void* comp_val,
                           void* exchange_val)
{
#if LEVELDB_IS_SOLARIS
    return (comp_val==atomic_cas_ptr(ptr, comp_val, exchange_val));
#else
    return __sync_bool_compare_and_swap(ptr, comp_val, exchange_val);
#endif
}

static uint32_t entry_size_for_key(uint32_t key_size)
{
    // This actually fails if the key_size is close to 4G. Don't do that.
    uint32_t unpadded_size = ENTRY_KEY_OFFSET + key_size;
    // Pad to next 8 byte boundary so data is aligned properly
    return (unpadded_size + 7) / 8 * 8;
}

#define WRITE_PREP_OK 0 
#define WRITE_PREP_RESTART 1
#define WRITE_PREP_NO_MEM 2

/**
 * If old_file_id and old_offset are given, caller wants to update an existing
 * version of a value. The operation should fail if the latest version of the
 * entry has differend file/offset or entry has been removed.
 *
 * Returns 1 if write succeeded,
 * 0 if conditional write failed since the current entry doesn't match.
 */
static int keydir_put(bitcask_keydir * keydir,
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
    int write_ok = 1;
    uint32_t chain_size;
    int write_prep_ret;

    // May need to retry whole operation sometimes when
    // avoiding deadlocks allocating pages requires us to undo locks
    // and re-lock again, which may allow a different thread to change things
    // under us. Just rety with a higher epoch.
    while(1)
    {
        epoch = atomic_incr64(&keydir->epoch);
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
                 scan_get_offet(&iter) != old_offset))
            {
                write_ok = 0;
            }
            else if (can_update_in_place)
            {
                scan_set_file_id(&iter, file_id);
                scan_set_offset(&iter, offset);
                scan_set_total_size(&iter, total_sz);
                scan_set_timestamp(&iter, timestamp);
                scan_set_epoch(&iter, epoch);
            }
            else // Adding extra version for this key.
            {
                chain_size = iter.mem_pages[0].size;
                // Point previous version to extra version.
                scan_set_next(&iter, chain_size);
                // Expand to fit extra version, no extra copy of key needed.
                write_prep_ret = write_prep(keydir, &iter, 0);

                if (write_prep_ret == WRITE_PREP_NO_MEM)
                {
                    write_ok = 0;
                    break;
                }

                if (write_prep_ret == WRITE_PREP_RESTART)
                {
                    // Iterator has been freed. Retry scanning and locking.
                    continue;
                }

                // Point to new entry to modify with scan_* functions.
                iter.offset = chain_size;

                scan_set_file_id(&iter, file_id);
                scan_set_offset(&iter, offset);
                scan_set_total_size(&iter, total_sz);
                scan_set_timestamp(&iter, timestamp);
                scan_set_epoch(&iter, epoch);
                scan_set_key_size(&iter, 0);
            }
        }
        else if(old_file_id)
        {
            // Conditional put, but entry was removed.
            write_ok = 0;
        }
        else
        {
            write_prep_ret = write_prep(keydir, &iter, key_size);
            if (write_prep_ret == WRITE_PREP_RESTART)
            {
                continue;
            }
            scan_set_file_id(&iter, file_id);
            scan_set_offset(&iter, offset);
            scan_set_total_size(&iter, total_sz);
            scan_set_timestamp(&iter, timestamp);
            scan_set_epoch(&iter, epoch);
            scan_set_key_size(&iter, key_size);
            scan_set_key(&iter, key, key_size);
        }
        break;
    }

    free_scan_iter(&iter, FREE_SCAN_DEFAULT);

    return write_ok;
}

static int scan_is_first_in_memory(scan_iter_t * iter)
{
    return iter->pages[0] == &iter->mem_pages[0]->page;
}

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

    if (scan_is_first_in_memory(iter) && is_page_free(iter->mem_pages[0]))
    {
        free_scan_iter(iter, FREE_SCAN_LEAVE_BASE_LOCKED);
        base_page->page.is_free = 1;
        return WRITE_PREP_RESTART;
    }

    // If base page borrowed by another chain, claim it.
    if (size == 0 && is_page_borrowed(iter->mem_pages[0]))
    {
        // Try to allocate another page and transfer data.
        if (enif_mutex_trylock(iter->mem_pages[0].page.mutex))
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

        scan->pages[scan->num_pages-1].next = next_page_idx;
        scan->pages[scan->num_pages] = new_page;
        scan->mem_pages[scan->num_pages] = new_mem_page;
        ++scan->num_pages;
    }

    return WRITE_PREP_OK;
}

/*
 * Adds a page to the front of the free list.
 * Should only be called on a locked page.
 */
static void add_free_page(bitcask_keydir * keydir, uint32_t page_idx)
{
    mem_page_t * mem_page, first_free_page;
    page_t * page;
    uint32_t first_free_idx;

    mem_page = keydir->mem_pages[page_idx];
    page = &mem_page.page;
    page->is_free = 1;

    while (1)
    {
        first_free_idx = keydir->free_list_head;
        page->next_free = first_free_idx;
        if (atomic_cas_32(&keydir->free_list_head, first_free_idx, page_idx))
        {
            break;
        }
    }
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
    uint32_t first, second;
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

        if (atomic_cas_32(&keydir->free_list_head, first, page.next_free))
        {
            enif_mutex_lock(page.mutex);
            if (mem_page->is_free)
            {
                return mem_page;
            }
            else
            {
                enif_mutex_unlock(page.mutex);
            }
        }
    }
}

static page_t * allocate_swap_page(bitcask_keydir * keydir, int * idx_out)
{
    uint32_t head_idx, num_swap_pages;
    page_t * head_page;

    // May need to be retried
    while(1)
    {
        head_idx = keydir->swap_free_list_head;

        // If list empty, expand swap file.
        if (head_idx == MAX_PAGE_IDX)
        {
            expand_swap_file(keydir);

            if (head_idx == MAX_PAGE_IDX)
            {
                // Oops, allocation failed.
                return (page_t*)0;
            }
            continue; // retry
        }

        head_page = get_swap_page(head_idx, keydir->swap_pages);

        if (atomic_cas_32(&keydir->swap_free_list_head,
                          head_idx, head_page->next_free))
        {
            // We got the page!
            *idx_out = head_idx;
            return head_page;
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
    swap_array_t new_swap_array;

    enif_mutex_lock(keydir->swap_grow_mutex);

    // Avoid having two threads expand the file in quick sequence
    if (keydir->num_swap_pages == old_num_pages)
    {
       new_file_size = 2 * old_num_pages * PAGE_SIZE;
       ftruncate(keydir->swap_file_desc, new_file_size);

       swap_array_t last_array = get_last_swap_array(keydir->swap_pages);
       new_swap_array = malloc(sizeof(swap_array_t));
       new_swap_array.size = new_num_pages;
       new_array_size = new_num_pages * sizeof(page_t);
       page_t * new_pages = malloc(new_array_size);
       page_offset = old_num_pages * PAGE_SIZE;

       for(i = 0; i < new_num_pages; ++i, page_offset += PAGE_SIZE)
       {
           page = &new_pages[i];
           page->mutex = enif_mutex_create(0);
           page->data = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
                             keydir->swap_file_desc, page_offset);
           page->prev_free = new_num_pages + i - 1;
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
                   new_swap_array.size = (uint32_t)i;
               }
               break;
           }
       }

       last_array->next = new_swap_array;
    }

    if (new_swap_array)
    {
        new_swap_array->pages[new_swap_array.size - 1].next = MAX_PAGE_IDX;
        // Atomically insert new entries at the head of the list.
        while (1)
        {
            new_swap_array->pages[0].prev_free = MAX_PAGE_IDX;

            if (atomic_cas_32(&keydir->swap_free_list_head,
                              keydir->swap_free_list_head,
                              new_head_idx))
            {
                break;
            }
        }
    }

    enif_mutex_unlock(keydir->swap_grow_mutex);
}

/* int erts_printf(const char *, ...); */

ERL_NIF_TERM bitcask_nifs_keydir_get_int(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;
    ErlNifBinary key;
    uint64 epoch; //intentionally odd type to get around warnings

    if (enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE, (void**)&handle) &&
        enif_inspect_binary(env, argv[1], &key) &&
        enif_get_uint64(env, argv[2], &epoch))
    {
        bitcask_keydir* keydir = handle->keydir;
        LOCK(keydir);

        DEBUG_BIN(dbgKey, key.data, key.size);
        DEBUG("+++ Get %s time = %lu\r\n", dbgKey, epoch);

        perhaps_sweep_siblings(handle->keydir);

        find_result f;
        find_keydir_entry(keydir, &key, epoch, &f);

        if (f.found && !f.proxy.is_tombstone)
        {
            ERL_NIF_TERM result;
            result = enif_make_tuple6(env,
                                      ATOM_BITCASK_ENTRY,
                                      argv[1], /* Key */
                                      enif_make_uint(env, f.proxy.file_id),
                                      enif_make_uint(env, f.proxy.total_sz),
                                      enif_make_uint64_bin(env, f.proxy.offset),
                                      enif_make_uint(env, f.proxy.tstamp));
            DEBUG(" ... returned value file id=%u size=%u ofs=%u tstamp=%u tomb=%u\r\n",
                  f.proxy.file_id, f.proxy.total_sz, f.proxy.offset, f.proxy.tstamp,
                  (unsigned)f.proxy.is_tombstone);
            DEBUG_ENTRY(f.entries_entry ? f.entries_entry : f.pending_entry);
            UNLOCK(keydir);
            return result;
        }
        else
        {
            DEBUG(" ... not_found\r\n");
            UNLOCK(keydir);
            return ATOM_NOT_FOUND;
        }
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_keydir_get_epoch(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;

    if (enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE, (void**)&handle))
    {
        LOCK(handle->keydir);
        uint64 epoch = handle->keydir->epoch;
        UNLOCK(handle->keydir);
        return enif_make_uint64(env, epoch);
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_keydir_remove(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;
    ErlNifBinary key;
    uint32_t tstamp;
    uint32_t file_id;
    uint64_t offset;
    uint32_t remove_time;
    // If this call has 6 arguments, this is a conditional removal. We
    // only want to actually remove the entry if the tstamp, fileid and
    // offset matches the one provided. A sort of poor-man's CAS.
    int is_conditional = argc == 6;
    int common_args_ok =
        enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE, (void**)&handle) &&
        enif_inspect_binary(env, argv[1], &key);
    int other_args_ok =
        is_conditional ?
        (enif_get_uint(env, argv[2], (unsigned int*)&tstamp) &&
         enif_get_uint(env, argv[3], (unsigned int*)&file_id) &&
         enif_get_uint64_bin(env, argv[4], (uint64_t*)&offset) &&
         enif_get_uint(env, argv[5], &remove_time))
        :
        ( enif_get_uint(env, argv[2], &remove_time));

    if (common_args_ok && other_args_ok)
    {
        bitcask_keydir* keydir = handle->keydir;

        DEBUG("+++ Remove %s\r\n", is_conditional ? "conditional" : "");
        DEBUG_KEYDIR(keydir);
        // TODO: call new remove function here

    } // if args OK

    return enif_make_badarg(env);
}

ERL_NIF_TERM bitcask_nifs_keydir_itr(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;

    if (enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE, (void**)&handle))
    {
        uint32_t ts;
        int maxage;
        int maxputs;

        LOCK(handle->keydir);
        DEBUG("+++ itr\r\n");
        bitcask_keydir* keydir = handle->keydir;

        // If a iterator thread is already active for this keydir, bail
        if (handle->iterating)
        {
            UNLOCK(handle->keydir);
            return enif_make_tuple2(env, ATOM_ERROR, ATOM_ITERATION_IN_PROCESS);
        }

        if (!(enif_get_uint(env, argv[1], &ts) &&
              enif_get_int(env, argv[2], (int*)&maxage) &&
              enif_get_int(env, argv[3], (int*)&maxputs)))
        {
            UNLOCK(handle->keydir);
            return enif_make_badarg(env);
        }

        // TODO: Add new iterator creation here.
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_keydir_itr_next(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;

    if (enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE, (void**)&handle))
    {
        DEBUG("+++ itr next\r\n");
        bitcask_keydir* keydir = handle->keydir;

        if (handle->iterating != 1)
        {
            DEBUG("Itr not started\r\n");
            // Iteration not started!
            return enif_make_tuple2(env, ATOM_ERROR, ATOM_ITERATION_NOT_STARTED);
        }

        // TODO: Add new iterator next operation here

        // The iterator is at the end of the table
        return ATOM_NOT_FOUND;
    }
    else
    {
        return enif_make_badarg(env);
    }
}

void itr_release_internal(ErlNifEnv* env, bitcask_keydir_handle* handle)
{
    handle->iterating = 0;
    handle->keydir->keyfolders--;
    handle->epoch = MAX_EPOCH;

    // TODO: Remove iterator data from keydir
}

ERL_NIF_TERM bitcask_nifs_keydir_itr_release(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;

    if (enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE, (void**)&handle))
    {
        LOCK(handle->keydir);
        if (handle->iterating != 1)
        {
            // Iteration not started!
            UNLOCK(handle->keydir);
            return enif_make_tuple2(env, ATOM_ERROR, ATOM_ITERATION_NOT_STARTED);
        }

        itr_release_internal(env, handle);

        UNLOCK(handle->keydir);
        return ATOM_OK;
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_keydir_info(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;

    if (enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE, (void**)&handle))
    {
        bitcask_keydir* keydir = handle->keydir;

        if (keydir == NULL)
        {
            return enif_make_badarg(env);
        }
        LOCK(keydir);

        // TODO: Add fstats aggreation for all Bitcask handles here

        // Dump fstats info into a list of [{file_id, live_keys, total_keys,
        //                                   live_bytes, total_bytes,
        //                                   oldest_tstamp, newest_tstamp,
        //                                   expiration_epoch}]
        ERL_NIF_TERM fstats_list = enif_make_list(env, 0);
        khiter_t itr;
        bitcask_fstats_entry* curr_f;
        for (itr = kh_begin(keydir->fstats); itr != kh_end(keydir->fstats); ++itr)
        {
            if (kh_exist(keydir->fstats, itr))
            {
                curr_f = kh_val(keydir->fstats, itr);
                ERL_NIF_TERM fstat =
                    enif_make_tuple8(env,
                                     enif_make_uint(env, curr_f->file_id),
                                     enif_make_ulong(env, curr_f->live_keys),
                                     enif_make_ulong(env, curr_f->total_keys),
                                     enif_make_ulong(env, curr_f->live_bytes),
                                     enif_make_ulong(env, curr_f->total_bytes),
                                     enif_make_uint(env, curr_f->oldest_tstamp),
                                     enif_make_uint(env, curr_f->newest_tstamp),
                                     enif_make_uint64(env, (ErlNifUInt64)curr_f->expiration_epoch));
                fstats_list = enif_make_list_cell(env, fstat, fstats_list);
            }
        }

        ERL_NIF_TERM iter_info =
            enif_make_tuple4(env,
                             enif_make_uint64(env, keydir->iter_generation),
                             enif_make_ulong(env, keydir->keyfolders),
                             keydir->pending == NULL ? ATOM_FALSE : ATOM_TRUE,
                             keydir->pending == NULL ? ATOM_UNDEFINED :
                             enif_make_uint64(env, keydir->pending_start_epoch));

        ERL_NIF_TERM result = enif_make_tuple5(env,
                                               enif_make_uint64(env, keydir->key_count),
                                               enif_make_uint64(env, keydir->key_bytes),
                                               fstats_list,
                                               iter_info,
                                               enif_make_uint64(env, keydir->epoch));
        UNLOCK(keydir);
        return result;
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_keydir_release(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;

    if (enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE, (void**)&handle))
    {
        bitcask_nifs_keydir_resource_cleanup(env, handle);
        return ATOM_OK;
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_increment_file_id(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;
    uint32_t conditional_file_id = 0;

    if (enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE, (void**)&handle))
    {

        if (argc == 2)
        {
            enif_get_uint(env, argv[1], &(conditional_file_id));
        }
        LOCK(handle->keydir);
        if (conditional_file_id == 0)
        {
            (handle->keydir->biggest_file_id)++;
        }
        else
        {
            if (conditional_file_id > handle->keydir->biggest_file_id)
            {
                handle->keydir->biggest_file_id = conditional_file_id;
            }
        }
        uint32_t id = handle->keydir->biggest_file_id;
        UNLOCK(handle->keydir);
        return enif_make_tuple2(env, ATOM_OK, enif_make_uint(env, id));
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_keydir_trim_fstats(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;
    ERL_NIF_TERM head, tail, list;
    uint32_t non_existent_entries = 0;

    if (enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE, (void**)&handle)&&
        enif_is_list(env, argv[1]))
    {
        bitcask_keydir* keydir = handle->keydir;
        
        LOCK(keydir);
        uint32_t file_id;

        list = argv[1];

        while (enif_get_list_cell(env, list, &head, &tail))
        {
            enif_get_uint(env, head, &file_id);

            khiter_t itr = kh_get(fstats, keydir->fstats, file_id);
            if (itr != kh_end(keydir->fstats))
            {
                bitcask_fstats_entry* curr_f;
                curr_f = kh_val(keydir->fstats, itr);
                free(curr_f);
                kh_del(fstats, keydir->fstats, itr);
            }
            else
            {
                non_existent_entries++;
            }
            // if not found, noop, but shouldn't happen.
            // think about chaning the retval to signal for warning?
            list = tail;
        }
        UNLOCK(keydir);
        return enif_make_tuple2(env, ATOM_OK, 
                                enif_make_uint(env, non_existent_entries));
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_lock_acquire(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    char filename[4096];
    int is_write_lock = 0;
    if (enif_get_string(env, argv[0], filename, sizeof(filename), ERL_NIF_LATIN1) > 0 &&
        enif_get_int(env, argv[1], &is_write_lock))
    {
        // Setup the flags for the lock file
        int flags = O_RDONLY;
        if (is_write_lock)
        {
            // Use O_SYNC (in addition to other flags) to ensure that when we write
            // data to the lock file it is immediately (or nearly) available to any
            // other reading processes
            flags = O_CREAT | O_EXCL | O_RDWR | O_SYNC;
        }

        // Try to open the lock file -- allocate a resource if all goes well.
        int fd = open(filename, flags, 0600);
        if (fd > -1)
        {
            // Successfully opened the file -- setup a resource to track the FD.
            unsigned int filename_sz = strlen(filename) + 1;
            bitcask_lock_handle* handle = enif_alloc_resource_compat(env, bitcask_lock_RESOURCE,
                                                                     sizeof(bitcask_lock_handle) +
                                                                     filename_sz);
            handle->fd = fd;
            handle->is_write_lock = is_write_lock;
            strncpy(handle->filename, filename, filename_sz);
            ERL_NIF_TERM result = enif_make_resource(env, handle);
            enif_release_resource_compat(env, handle);

            return enif_make_tuple2(env, ATOM_OK, result);
        }
        else
        {
            return enif_make_tuple2(env, ATOM_ERROR, errno_atom(env, errno));
        }
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_lock_release(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_lock_handle* handle;

    if (enif_get_resource(env, argv[0], bitcask_lock_RESOURCE, (void**)&handle))
    {
        lock_release(handle);
        return ATOM_OK;
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_lock_readdata(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_lock_handle* handle;

    if (enif_get_resource(env, argv[0], bitcask_lock_RESOURCE, (void**)&handle))
    {
        // Stat the filehandle so we can read the entire contents into memory
        struct stat sinfo;
        if (fstat(handle->fd, &sinfo) != 0)
        {
            return errno_error_tuple(env, ATOM_FSTAT_ERROR, errno);
        }

        // Allocate a binary to hold the contents of the file
        ErlNifBinary data;
        if (!enif_alloc_binary_compat(env, sinfo.st_size, &data))
        {
            return enif_make_tuple2(env, ATOM_ERROR, ATOM_ALLOCATION_ERROR);
        }

        // Read the whole file into our binary
        if (pread(handle->fd, data.data, data.size, 0) == -1)
        {
            return errno_error_tuple(env, ATOM_PREAD_ERROR, errno);
        }

        return enif_make_tuple2(env, ATOM_OK, enif_make_binary(env, &data));
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_lock_writedata(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_lock_handle* handle;
    ErlNifBinary data;

    if (enif_get_resource(env, argv[0], bitcask_lock_RESOURCE, (void**)&handle) &&
        enif_inspect_binary(env, argv[1], &data))
    {
        if (handle->is_write_lock)
        {
            // Truncate the file first, to ensure that the lock file only contains what
            // we're about to write
            if (ftruncate(handle->fd, 0) == -1)
            {
                return errno_error_tuple(env, ATOM_FTRUNCATE_ERROR, errno);
            }

            // Write the new blob of data to the lock file. Note that we use O_SYNC to
            // ensure that the data is available ASAP to reading processes.
            if (pwrite(handle->fd, data.data, data.size, 0) == -1)
            {
                return errno_error_tuple(env, ATOM_PWRITE_ERROR, errno);
            }

            return ATOM_OK;
        }
        else
        {
            // Tried to write data to a read lock
            return enif_make_tuple2(env, ATOM_ERROR, ATOM_LOCK_NOT_WRITABLE);
        }
    }
    else
    {
        return enif_make_badarg(env);
    }
}

int get_file_open_flags(ErlNifEnv* env, ERL_NIF_TERM list)
{
    int flags = O_RDWR | O_APPEND;
    ERL_NIF_TERM head, tail;
    while (enif_get_list_cell(env, list, &head, &tail))
    {
        if (head == ATOM_CREATE)
        {
            flags = O_CREAT | O_EXCL | O_RDWR | O_APPEND;
        }
        else if (head == ATOM_READONLY)
        {
            flags = O_RDONLY;
        }
        else if (head == ATOM_O_SYNC)
        {
            flags |= O_SYNC;
        }

        list = tail;
    }
    return flags;
}


ERL_NIF_TERM bitcask_nifs_file_open(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    char filename[4096];
    if (enif_get_string(env, argv[0], filename, sizeof(filename), ERL_NIF_LATIN1) &&
        enif_is_list(env, argv[1]))
    {
        int flags = get_file_open_flags(env, argv[1]);
        int fd = open(filename, flags, S_IREAD | S_IWRITE);
        if (fd > -1)
        {
            // Setup a resource for our handle
            bitcask_file_handle* handle = enif_alloc_resource_compat(env,
                                                                     bitcask_file_RESOURCE,
                                                                     sizeof(bitcask_file_handle));
            memset(handle, '\0', sizeof(bitcask_file_handle));
            handle->fd = fd;

            ERL_NIF_TERM result = enif_make_resource(env, handle);
            enif_release_resource_compat(env, handle);
            return enif_make_tuple2(env, ATOM_OK, result);
        }
        else
        {
            return enif_make_tuple2(env, ATOM_ERROR, errno_atom(env, errno));
        }
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_file_close(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_file_handle* handle;
    if (enif_get_resource(env, argv[0], bitcask_file_RESOURCE, (void**)&handle))
    {
        if (handle->fd > 0)
        {
            /* TODO: Check for EIO */
            close(handle->fd);
            handle->fd = -1;
        }
        return ATOM_OK;
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_file_sync(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_file_handle* handle;
    if (enif_get_resource(env, argv[0], bitcask_file_RESOURCE, (void**)&handle))
    {
        int rc = fsync(handle->fd);
        if (rc != -1)
        {
            return ATOM_OK;
        }
        else
        {
            return enif_make_tuple2(env, ATOM_ERROR, errno_atom(env, errno));
        }
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_file_pread(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_file_handle* handle;
    unsigned long offset_ul;
    unsigned long count_ul;
    if (enif_get_resource(env, argv[0], bitcask_file_RESOURCE, (void**)&handle) &&
        enif_get_ulong(env, argv[1], &offset_ul) && /* Offset */
        enif_get_ulong(env, argv[2], &count_ul))    /* Count */
    {
        ErlNifBinary bin;
        off_t offset = offset_ul;
        size_t count = count_ul;
        if (!enif_alloc_binary(count, &bin))
        {
            return enif_make_tuple2(env, ATOM_ERROR, ATOM_ALLOCATION_ERROR);
        }

        ssize_t bytes_read = pread(handle->fd, bin.data, count, offset);
        if (bytes_read == count)
        {
            /* Good read; return {ok, Bin} */
            return enif_make_tuple2(env, ATOM_OK, enif_make_binary(env, &bin));
        }
        else if (bytes_read > 0)
        {
            /* Partial read; need to resize our binary (bleh) and return {ok, Bin} */
            if (enif_realloc_binary(&bin, bytes_read))
            {
                return enif_make_tuple2(env, ATOM_OK, enif_make_binary(env, &bin));
            }
            else
            {
                /* Realloc failed; cleanup and bail */
                enif_release_binary(&bin);
                return enif_make_tuple2(env, ATOM_ERROR, ATOM_ALLOCATION_ERROR);
            }
        }
        else if (bytes_read == 0)
        {
            /* EOF */
            enif_release_binary(&bin);
            return ATOM_EOF;
        }
        else
        {
            /* Read failed altogether */
            enif_release_binary(&bin);
            return enif_make_tuple2(env, ATOM_ERROR, errno_atom(env, errno));
        }
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_file_pwrite(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_file_handle* handle;
    unsigned long offset_ul;
    ErlNifBinary bin;

    if (enif_get_resource(env, argv[0], bitcask_file_RESOURCE, (void**)&handle) &&
        enif_get_ulong(env, argv[1], &offset_ul) && /* Offset */
        enif_inspect_iolist_as_binary(env, argv[2], &bin)) /* Bytes to write */
    {
        unsigned char* buf = bin.data;
        ssize_t bytes_written = 0;
        ssize_t count = bin.size;
        off_t offset = offset_ul;

        while (count > 0)
        {
            bytes_written = pwrite(handle->fd, buf, count, offset);
            if (bytes_written > 0)
            {
                count -= bytes_written;
                offset += bytes_written;
                buf += bytes_written;
            }
            else
            {
                /* Write failed altogether */
                return enif_make_tuple2(env, ATOM_ERROR, errno_atom(env, errno));
            }
        }

        /* Write done */
        return ATOM_OK;
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_file_read(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_file_handle* handle;
    size_t count;

    if (enif_get_resource(env, argv[0], bitcask_file_RESOURCE, (void**)&handle) &&
        enif_get_ulong(env, argv[1], &count))    /* Count */
    {
        ErlNifBinary bin;
        if (!enif_alloc_binary(count, &bin))
        {
            return enif_make_tuple2(env, ATOM_ERROR, ATOM_ALLOCATION_ERROR);
        }

        ssize_t bytes_read = read(handle->fd, bin.data, count);
        if (bytes_read == count)
        {
            /* Good read; return {ok, Bin} */
            return enif_make_tuple2(env, ATOM_OK, enif_make_binary(env, &bin));
        }
        else if (bytes_read > 0)
        {
            /* Partial read; need to resize our binary (bleh) and return {ok, Bin} */
            if (enif_realloc_binary(&bin, bytes_read))
            {
                return enif_make_tuple2(env, ATOM_OK, enif_make_binary(env, &bin));
            }
            else
            {
                /* Realloc failed; cleanup and bail */
                enif_release_binary(&bin);
                return enif_make_tuple2(env, ATOM_ERROR, ATOM_ALLOCATION_ERROR);
            }
        }
        else if (bytes_read == 0)
        {
            /* EOF */
            enif_release_binary(&bin);
            return ATOM_EOF;
        }
        else
        {
            /* Read failed altogether */
            enif_release_binary(&bin);
            return enif_make_tuple2(env, ATOM_ERROR, errno_atom(env, errno));
        }
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_file_write(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_file_handle* handle;
    ErlNifBinary bin;

    if (enif_get_resource(env, argv[0], bitcask_file_RESOURCE, (void**)&handle) &&
        enif_inspect_iolist_as_binary(env, argv[1], &bin)) /* Bytes to write */
    {
        unsigned char* buf = bin.data;
        ssize_t bytes_written = 0;
        ssize_t count = bin.size;
        while (count > 0)
        {
            bytes_written = write(handle->fd, buf, count);
            if (bytes_written > 0)
            {
                count -= bytes_written;
                buf += bytes_written;
            }
            else
            {
                /* Write failed altogether */
                return enif_make_tuple2(env, ATOM_ERROR, errno_atom(env, errno));
            }
        }

        /* Write done */
        return ATOM_OK;
    }
    else
    {
        return enif_make_badarg(env);
    }
}

// Returns 0 if failed to parse lseek style argument for file_position
static int parse_seek_offset(ErlNifEnv* env, ERL_NIF_TERM arg, off_t * ofs, int * whence)
{
    long long_ofs;
    int arity;
    const ERL_NIF_TERM* tuple_elements;
    if (enif_get_long(env, arg, &long_ofs))
    {
        *whence = SEEK_SET;
        *ofs = (off_t)long_ofs;
        return 1;
    }
    else if (enif_get_tuple(env, arg, &arity, &tuple_elements) && arity == 2
            && enif_get_long(env, tuple_elements[1], &long_ofs))
    {
        *ofs = (off_t)long_ofs;
        if (tuple_elements[0] == ATOM_CUR)
        {
            *whence = SEEK_CUR;
        }
        else if (tuple_elements[0] == ATOM_BOF)
        {
            *whence = SEEK_SET;
        }
        else if (tuple_elements[0] == ATOM_EOF)
        {
            *whence = SEEK_END;
        }
        else
        {
            return 0;
        }
        return 1;
    }
    else
    {
        return 0;
    }
}

ERL_NIF_TERM bitcask_nifs_file_position(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_file_handle* handle;
    off_t offset;
    int whence;

    if (enif_get_resource(env, argv[0], bitcask_file_RESOURCE, (void**)&handle) &&
        parse_seek_offset(env, argv[1], &offset, &whence))
    {

        off_t new_offset = lseek(handle->fd, offset, whence);
        if (new_offset != -1)
        {
            return enif_make_tuple2(env, ATOM_OK, enif_make_ulong(env, new_offset));
        }
        else
        {
            /* Write failed altogether */
            return enif_make_tuple2(env, ATOM_ERROR, errno_atom(env, errno));
        }
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_file_seekbof(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_file_handle* handle;

    if (enif_get_resource(env, argv[0], bitcask_file_RESOURCE, (void**)&handle))
    {
        if (lseek(handle->fd, 0, SEEK_SET) != (off_t)-1)
        {
            return ATOM_OK;
        }
        else
        {
            /* Write failed altogether */
            return enif_make_tuple2(env, ATOM_ERROR, errno_atom(env, errno));
        }
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_file_truncate(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_file_handle* handle;

    if (enif_get_resource(env, argv[0], bitcask_file_RESOURCE, (void**)&handle))
    {
        off_t ofs = lseek(handle->fd, 0, SEEK_CUR);
        if (ofs == (off_t)-1)
        {
            return enif_make_tuple2(env, ATOM_ERROR, errno_atom(env, errno));
        }

        if (ftruncate(handle->fd, ofs) == -1)
        {
            return errno_error_tuple(env, ATOM_FTRUNCATE_ERROR, errno);
        }

        return ATOM_OK;
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM errno_atom(ErlNifEnv* env, int error)
{
    return enif_make_atom(env, erl_errno_id(error));
}

ERL_NIF_TERM errno_error_tuple(ErlNifEnv* env, ERL_NIF_TERM key, int error)
{
    // Construct a tuple of form: {error, {Key, ErrnoAtom}}
    return enif_make_tuple2(env, ATOM_ERROR,
                            enif_make_tuple2(env, key, errno_atom(env, error)));
}

static void lock_release(bitcask_lock_handle* handle)
{
    if (handle->fd > 0)
    {
        // If this is a write lock, we need to delete the file as part of cleanup. But be
        // sure to do this BEFORE letting go of the file handle so as to ensure consistency
        // with other readers.
        if (handle->is_write_lock)
        {
            // TODO: Come up with some way to complain/error log if this unlink failed for some
            // reason!!
            unlink(handle->filename);
        }

        close(handle->fd);
        handle->fd = -1;
    }
}

static void free_keydir(bitcask_keydir* keydir)
{
    keydir_free_memory(keydir);

    free(keydir);
}


static void bitcask_nifs_keydir_resource_cleanup(ErlNifEnv* env, void* arg)
{
    bitcask_keydir_handle* handle = (bitcask_keydir_handle*)arg;
    bitcask_keydir* keydir = handle->keydir;

    // First, check that there is even a keydir available. If keydir_release
    // was invoked manually, we might have already cleaned up the keydir
    // and this round of cleanup can noop. Otherwise, clear out the handle's
    // reference to the keydir so that repeat calls function as expected
    if (!handle->keydir)
    {
        return;
    }
    else
    {
        if (handle->iterating)
        {
            LOCK(handle->keydir);

            itr_release_internal(env, handle);

            UNLOCK(handle->keydir);
        }

        handle->keydir = 0;
    }

    // If the keydir has a lock, we need to decrement the refcount and
    // potentially release it
    if (keydir->mutex)
    {
        bitcask_priv_data* priv = (bitcask_priv_data*)enif_priv_data(env);
        enif_mutex_lock(priv->global_keydirs_lock);

        // Remember biggest_file_id in case someone re-opens the same name
        uint32_t global_biggest = 0, the_biggest = 0;
        khiter_t itr_biggest_file_id = kh_get(global_biggest_file_id, priv->global_biggest_file_id, keydir->name);
        if (itr_biggest_file_id != kh_end(priv->global_biggest_file_id)) {
            global_biggest = kh_val(priv->global_biggest_file_id, itr_biggest_file_id);
        }
        the_biggest = (global_biggest > keydir->biggest_file_id) ? \
            global_biggest : keydir->biggest_file_id;
        the_biggest++;
        kh_put2(global_biggest_file_id, priv->global_biggest_file_id, strdup(keydir->name), the_biggest);

        keydir->refcount--;
        if (keydir->refcount == 0)
        {
            // This is the last reference to the named keydir. As such,
            // remove it from the hashtable so no one else tries to use it
            khiter_t itr = kh_get(global_keydirs, priv->global_keydirs, keydir->name);
            kh_del(global_keydirs, priv->global_keydirs, itr);
        }
        else
        {
            // At least one other reference; just throw away our keydir pointer
            // so the check below doesn't release the memory.
            keydir = 0;
        }

        // Unlock ASAP. Wanted to avoid holding this mutex while we clean up the
        // keydir, since it may take a while to walk a large keydir and free each
        // entry.
        enif_mutex_unlock(priv->global_keydirs_lock);
    }

    // If keydir is still defined, it's either privately owned or has a
    // refcount of 0. Either way, we want to release it.
    if (keydir)
    {
        if (keydir->mutex)
        {
            enif_mutex_destroy(keydir->mutex);
        }

        free_keydir(keydir);
    }
}

static void bitcask_nifs_lock_resource_cleanup(ErlNifEnv* env, void* arg)
{
    bitcask_lock_handle* handle = (bitcask_lock_handle*)arg;
    lock_release(handle);
}

static void bitcask_nifs_file_resource_cleanup(ErlNifEnv* env, void* arg)
{
    bitcask_file_handle* handle = (bitcask_file_handle*)arg;
    if (handle->fd > -1)
    {
        close(handle->fd);
    }
}


#ifdef BITCASK_DEBUG
void dump_fstats(bitcask_keydir* keydir)
{
    bitcask_fstats_entry* curr_f;
    khiter_t itr;
    for (itr = kh_begin(keydir->fstats); itr != kh_end(keydir->fstats); ++itr)
    {
        if (kh_exist(keydir->fstats, itr))
        {
            curr_f = kh_val(keydir->fstats, itr);
            DEBUG("fstats %d live=(%d,%d) total=(%d,%d)\r\n",
                    (int) curr_f->file_id,
                    (int) curr_f->live_keys,
                    (int) curr_f->live_bytes,
                    (int) curr_f->total_keys,
                    (int) curr_f->total_bytes);
        }
    }
}
#endif

static int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
    bitcask_keydir_RESOURCE = enif_open_resource_type_compat(env, "bitcask_keydir_resource",
                                                      &bitcask_nifs_keydir_resource_cleanup,
                                                      ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
                                                      0);

    bitcask_lock_RESOURCE = enif_open_resource_type_compat(env, "bitcask_lock_resource",
                                                    &bitcask_nifs_lock_resource_cleanup,
                                                    ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
                                                    0);

    bitcask_file_RESOURCE = enif_open_resource_type_compat(env, "bitcask_file_resource",
                                                    &bitcask_nifs_file_resource_cleanup,
                                                    ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
                                                    0);

    // Initialize shared keydir hashtable
    bitcask_priv_data* priv = malloc(sizeof(bitcask_priv_data));
    priv->global_biggest_file_id = kh_init(global_biggest_file_id);
    priv->global_keydirs = kh_init(global_keydirs);
    priv->global_keydirs_lock = enif_mutex_create("bitcask_global_handles_lock");
    *priv_data = priv;

    // Initialize atoms that we use throughout the NIF.
    ATOM_ALLOCATION_ERROR = enif_make_atom(env, "allocation_error");
    ATOM_ALREADY_EXISTS = enif_make_atom(env, "already_exists");
    ATOM_BITCASK_ENTRY = enif_make_atom(env, "bitcask_entry");
    ATOM_ERROR = enif_make_atom(env, "error");
    ATOM_FALSE = enif_make_atom(env, "false");
    ATOM_FSTAT_ERROR = enif_make_atom(env, "fstat_error");
    ATOM_FTRUNCATE_ERROR = enif_make_atom(env, "ftruncate_error");
    ATOM_GETFL_ERROR = enif_make_atom(env, "getfl_error");
    ATOM_ILT_CREATE_ERROR = enif_make_atom(env, "ilt_create_error");
    ATOM_ITERATION_IN_PROCESS = enif_make_atom(env, "iteration_in_process");
    ATOM_ITERATION_NOT_PERMITTED = enif_make_atom(env, "iteration_not_permitted");
    ATOM_ITERATION_NOT_STARTED = enif_make_atom(env, "iteration_not_started");
    ATOM_LOCK_NOT_WRITABLE = enif_make_atom(env, "lock_not_writable");
    ATOM_NOT_FOUND = enif_make_atom(env, "not_found");
    ATOM_NOT_READY = enif_make_atom(env, "not_ready");
    ATOM_OK = enif_make_atom(env, "ok");
    ATOM_OUT_OF_DATE = enif_make_atom(env, "out_of_date");
    ATOM_PREAD_ERROR = enif_make_atom(env, "pread_error");
    ATOM_PWRITE_ERROR = enif_make_atom(env, "pwrite_error");
    ATOM_READY = enif_make_atom(env, "ready");
    ATOM_SETFL_ERROR = enif_make_atom(env, "setfl_error");
    ATOM_TRUE = enif_make_atom(env, "true");
    ATOM_UNDEFINED = enif_make_atom(env, "undefined");
    ATOM_EOF = enif_make_atom(env, "eof");
    ATOM_CREATE = enif_make_atom(env, "create");
    ATOM_READONLY = enif_make_atom(env, "readonly");
    ATOM_O_SYNC = enif_make_atom(env, "o_sync");
    ATOM_CUR = enif_make_atom(env, "cur");
    ATOM_BOF = enif_make_atom(env, "bof");

#ifdef PULSE
    pulse_c_send_on_load(env);
#endif

    return 0;
}

ERL_NIF_INIT(bitcask_nifs, nif_funcs, &on_load, NULL, NULL, NULL);
