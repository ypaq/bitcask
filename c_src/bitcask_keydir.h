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
#ifndef BITCASK_KEYDIR_H
#define BITCASK_KEYDIR_H

#include <stdint.h>
#include "khash.h"
// TODO: replace nif utilities from definitions from pthreads, etc
// to remove this include and keep things separated.
#include "erl_nif.h"

#define MAX_TIME ((uint32_t)-1)
#define MAX_EPOCH ((uint64_t)-1)
#define MAX_SIZE ((uint32_t)-1)
#define MAX_FILE_ID ((uint32_t)-1)
#define MAX_OFFSET ((uint64_t)-1)
#define MAX_PAGE_IDX ((uint32_t)-1)

// Entry fields carefully laid out to correspond with ENTRY_*_OFFSET
// constants and layout in pages. Change with care!
typedef struct
{
    uint32_t file_id;
    uint32_t total_size;
    uint64_t epoch;
    uint64_t offset;
    uint32_t timestamp;
    uint32_t next;
    uint32_t key_size;
    uint8_t *key;
} keydir_entry_t;

int is_tombstone_entry(keydir_entry_t * entry);

typedef struct
{
    uint32_t file_id;
    int64_t live_keys;   // number of 'live' keys in entries and pending
    int64_t live_bytes;  // number of bytes used by 'live' keys
    int64_t total_keys;  // total number of keys written to file
    int64_t total_bytes; // total number of bytes written to file
    uint32_t oldest_tstamp; // oldest observed tstamp in a file
    uint32_t newest_tstamp; // newest observed tstamp in a file
} bitcask_fstats_entry;

KHASH_MAP_INIT_INT(fstats, bitcask_fstats_entry);
typedef khash_t(fstats) fstats_hash_t;

typedef struct
{
    fstats_hash_t*  fstats;
    ErlNifMutex *   mutex;
} fstats_handle_t;

typedef struct keydir_itr_struct keydir_itr_t;

// Make sure fields are aligned properly on the page structs!
// Don't modify willy-nilly!

typedef struct
{
    ErlNifMutex *   mutex;
    uint8_t *       data;
    uint32_t        prev;
    uint32_t        next;
    uint32_t        next_free;
    uint8_t         is_free;
} page_t;

typedef struct
{
    unsigned        count;
    unsigned        size;
    keydir_itr_t ** items;
} keydir_itr_array_t;


typedef struct
{
    page_t          page;
    uint32_t        size;
    uint32_t        alt_idx;
    uint32_t        dead_bytes;
    uint8_t         is_borrowed;
    keydir_itr_array_t itr_array;
} mem_page_t;

struct swap_array_struct
{
    page_t *                    pages;
    struct swap_array_struct *  next;
    uint32_t                    size;
};

typedef struct swap_array_struct swap_array_t;

typedef unsigned (*fstats_idx_fun_t)();

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
    // Already aggregated file stats
    fstats_hash_t *   fstats;
    // Partial file stats that will be aggregated into the global ones
    // on demand so they can be concurrently updated.
    unsigned          num_fstats;
    fstats_handle_t * fstats_array;
    // Re-used by fstats aggregation
    fstats_hash_t *   tmp_fstats;

    // Function that returns the index of the partial file stats object to use
    // Either random or mapping to a fixed number of logical threads to avoid
    // contention.
    fstats_idx_fun_t fstats_idx_fun;

    keydir_itr_array_t itr_array;

    uint32_t          biggest_file_id;
    unsigned          refcount;
    char              is_ready;
    char              name[0];
} bitcask_keydir;

typedef struct
{
    keydir_itr_t * itr;
    // Iterators are not multi-thread safe. Lock to use.
    // Should we just assume multi-thread use and move mutex to iterator?
    ErlNifMutex *  mutex;
} bitcask_iterator_handle;

/////////////////////////////////////////////////////////////////////////
// Public Keydir API

typedef struct
{
    const char * basedir;
    uint32_t num_pages;
    uint32_t initial_num_swap_pages;
    fstats_idx_fun_t fstats_idx_fun;
} keydir_init_params_t;

void keydir_default_init_params(keydir_init_params_t * params);

int keydir_common_init(bitcask_keydir * keydir, keydir_init_params_t * params);

void free_keydir(bitcask_keydir* keydir);

void keydir_add_file(bitcask_keydir * keydir, uint32_t file_id);

void keydir_remove_file(bitcask_keydir * keydir, uint32_t file_id);

void update_fstats(fstats_hash_t * fstats,
                   ErlNifMutex * mutex,
                   uint32_t file_id,
                   uint32_t tstamp,
                   int32_t live_increment,
                   int32_t total_increment,
                   int32_t live_bytes_increment,
                   int32_t total_bytes_increment);

void keydir_aggregate_fstats(bitcask_keydir * keydir);

void free_fstats(fstats_hash_t * fstats);

typedef enum {
    KEYDIR_GET_FOUND = 0,
    KEYDIR_GET_NOT_FOUND
} KeydirGetCode;

KeydirGetCode keydir_get(bitcask_keydir *    keydir,
                         uint8_t *           key,
                         uint32_t            key_size,
                         uint64_t            epoch,
                         keydir_entry_t *     return_entry);

typedef enum {
    KEYDIR_PUT_OK = 0,
    KEYDIR_PUT_MODIFIED,      // CAS failure
    KEYDIR_PUT_OUT_OF_MEMORY, // Oh shit
    KEYDIR_PUT_RETRY          // Retry asynchronously, long operation expected.
} KeydirPutCode;

KeydirPutCode keydir_put(bitcask_keydir * keydir,
                         keydir_entry_t * entry,
                         uint32_t         old_file_id,
                         uint64_t         old_offset);

KeydirPutCode keydir_remove(bitcask_keydir * keydir,
                            uint8_t * key,
                            uint32_t key_size,
                            // conditional remove options
                            uint32_t old_file_id,
                            uint64_t old_offset);

//////////////////////////////////////////////////////////
// Iterators
struct keydir_itr_struct
{
    bitcask_keydir * keydir;
    // Defines the snapshot to iterate over. If set to MAX_EPOCH, the most
    // recent entries will be observed in an undefined visit order.
    uint64_t epoch;
    // Page we are currently visiting. If MAX_PAGE_IDX, iteration has not
    // started. If equal to keydir->num_pages, iteration has ended. 
    uint32_t page_idx;
    uint32_t offset;
    uint32_t num_visited_offsets;
    uint32_t * visited_offsets;
};

typedef enum {
    KEYDIR_ITR_NO_SNAPSHOT = 0,
    KEYDIR_ITR_USE_SNAPSHOT = 1
} KeydirItrSnapshotFlag;

keydir_itr_t * keydir_itr_create(bitcask_keydir * keydir,
                                 KeydirItrSnapshotFlag snapshot_flag);

void keydir_itr_init(bitcask_keydir * keydir,
                     KeydirItrSnapshotFlag snapshot_flag,
                     keydir_itr_t * itr);

typedef enum {
    KEYDIR_ITR_OK = 0,
    KEYDIR_ITR_END,
    KEYDIR_ITR_INVALID,
    KEYDIR_ITR_OUT_OF_MEMORY
} KeydirItrCode;

KeydirItrCode keydir_itr_next(keydir_itr_t * keydir_itr,
                              keydir_entry_t * entry);

void keydir_itr_release(keydir_itr_t * keydir_itr);

#endif
