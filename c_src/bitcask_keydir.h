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

// Entry fields carefully laid out to correspond with ENTRY_*_OFFSET
// constaints and layout in pages. Change with care!
typedef struct
{
    uint32_t file_id;
    uint32_t total_size;
    uint64_t epoch;
    uint64_t offset;
    uint32_t timestamp;
    uint8_t  is_tombstone;
} basic_entry_t;

KHASH_MAP_INIT_INT(fstats, bitcask_fstats_entry*);

typedef khash_t(fstats) fstats_hash_t;

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
    page_t   page;
    uint32_t size;
    uint32_t alt_idx;
    uint32_t dead_bytes;
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

    int               num_iterators;
    uint32_t          biggest_file_id;
    unsigned int      refcount;
    char              is_ready;
    char              name[0];
} bitcask_keydir;

#define SCAN_INITIAL_PAGE_ARRAY_SIZE 16

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

/////////////////////////////////////////////////////////////////////////
// Public Keydir API

int keydir_common_init(bitcask_keydir * keydir,
                               const char * basedir,
                               uint32_t num_pages,
                               uint32_t initial_num_swap_pages);

void update_fstats(fstats_hash_t * fstats,
                   ErlNifMutex * mutex,
                   uint32_t file_id,
                   uint32_t tstamp,
                   uint64_t expiration_epoch,
                   int32_t live_increment,
                   int32_t total_increment,
                   int32_t live_bytes_increment,
                   int32_t total_bytes_increment,
                   int32_t should_create);

void free_keydir(bitcask_keydir* keydir);

typedef enum {
    KEYDIR_GET_FOUND = 0,
    KEYDIR_GET_NOT_FOUND
} KeydirGetCode;

KeydirGetCode keydir_get(bitcask_keydir *    keydir,
                         char *              key,
                         uint32_t            key_size,
                         uint64_t            epoch,
                         basic_entry_t *     return_entry);

typedef enum {
    KEYDIR_PUT_OK = 0,
    KEYDIR_PUT_MODIFIED,      // CAS failure
    KEYDIR_PUT_OUT_OF_MEMORY, // Oh shit
    KEYDIR_PUT_RETRY          // Retry asynchronously, long operation expected.
} KeydirPutCode;

KeydirPutCode keydir_put(bitcask_keydir * keydir,
                         char *           key,
                         uint32_t         key_size,
                         uint32_t         file_id,
                         uint64_t         total_size,
                         uint64_t         offset,
                         uint32_t         timestamp,
                         uint32_t         old_file_id,
                         uint64_t         old_offset);

KeydirPutCode keydir_remove(bitcask_keydir * keydir,
                            char * key,
                            uint32_t key_size,
                            // conditional remove options
                            uint32_t old_file_id,
                            uint64_t old_offset);

#endif
