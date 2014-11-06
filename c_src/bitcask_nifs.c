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
#include "bitcask_atomic.h"
#include "bitcask_keydir.h"

#include "khash.h"
#include "murmurhash.h"

#include <stdio.h>

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


// Handle lock helper functions
#define LOCK(keydir)      { if (keydir->mutex) enif_mutex_lock(keydir->mutex); }
#define UNLOCK(keydir)    { if (keydir->mutex) enif_mutex_unlock(keydir->mutex); }

// Atoms (initialized in on_load)
static ERL_NIF_TERM ATOM_ALLOCATION_ERROR;
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
static ERL_NIF_TERM ATOM_MODIFIED;
static ERL_NIF_TERM ATOM_NOT_FOUND;
static ERL_NIF_TERM ATOM_NOT_READY;
static ERL_NIF_TERM ATOM_OK;
static ERL_NIF_TERM ATOM_OUT_OF_DATE;
static ERL_NIF_TERM ATOM_OUT_OF_MEMORY;
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

#ifdef BITCASK_DEBUG
void print_keydir(bitcask_keydir* keydir)
{
}
#endif

ERL_NIF_TERM bitcask_nifs_keydir_put_int(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;
    ErlNifBinary key;
    char * entry_key;
    int entry_key_sz;
    uint32_t entry_file_id;
    uint32_t entry_total_sz;
    uint32_t entry_tstamp;
    uint64_t entry_offset;
    uint32_t newest_put;
    uint32_t old_file_id;
    uint64_t old_offset;
    KeydirPutCode ret_code;

    if (enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE, (void**)&handle) &&
        enif_inspect_binary(env, argv[1], &key) &&
        enif_get_uint(env, argv[2], &(entry_file_id)) &&
        enif_get_uint(env, argv[3], &(entry_total_sz)) &&
        enif_get_uint64_bin(env, argv[4], &(entry_offset)) &&
        enif_get_uint(env, argv[5], &(entry_tstamp)) &&
        enif_get_uint(env, argv[6], &(newest_put)) &&
        enif_get_uint(env, argv[7], &(old_file_id)) &&
        enif_get_uint64_bin(env, argv[8], &(old_offset)))
    {
        bitcask_keydir* keydir = handle->keydir;
        entry_key = (char*)key.data;
        entry_key_sz = key.size;

        DEBUG2("LINE %d put\r\n", __LINE__);

        DEBUG_BIN(dbgKey, key.data, key.size);
        DEBUG("+++ Put key = %s file_id=%d offset=%d total_sz=%d tstamp=%u old_file_id=%d\r\n",
                dbgKey,
              (int) entry.file_id, (int) entry.offset,
              (int)entry.total_sz, (unsigned) entry.tstamp, (int)old_file_id);
        DEBUG_KEYDIR(keydir);


        ret_code = keydir_put(keydir, key.data, key.size,
                              entry_file_id, entry_total_sz,
                              entry_offset, entry_tstamp,
                              old_file_id, old_offset);

        switch(ret_code)
        {
            case KEYDIR_PUT_OK:
                return ATOM_OK;
            case KEYDIR_PUT_MODIFIED:
                return ATOM_MODIFIED;
            case KEYDIR_PUT_OUT_OF_MEMORY:
                return ATOM_OUT_OF_MEMORY;
            default:
                return enif_make_badarg(env);
        }
    }
    else
    {
        return enif_make_badarg(env);
    }
}

/* int erts_printf(const char *, ...); */

ERL_NIF_TERM bitcask_nifs_keydir_get_int(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;
    ErlNifBinary key;
    basic_entry_t entry;
    KeydirGetCode ret_code;
    uint64 epoch; //intentionally odd type to get around warnings

    if (enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE, (void**)&handle) &&
        enif_inspect_binary(env, argv[1], &key) &&
        enif_get_uint64(env, argv[2], &epoch))
    {
        bitcask_keydir* keydir = handle->keydir;

        DEBUG_BIN(dbgKey, key.data, key.size);
        DEBUG("+++ Get %s time = %lu\r\n", dbgKey, epoch);

        ret_code = keydir_get(keydir, key.data, key.size, epoch, &entry);

        if (ret_code == KEYDIR_GET_FOUND && !entry.is_tombstone)
        {
            ERL_NIF_TERM result;
            result = enif_make_tuple6(env,
                                      ATOM_BITCASK_ENTRY,
                                      argv[1], // Key 
                                      enif_make_uint(env, entry.file_id),
                                      enif_make_uint(env, entry.total_size),
                                      enif_make_uint64_bin(env, entry.offset),
                                      enif_make_uint(env, entry.timestamp));

            DEBUG(" ... returned value file id=%u size=%u ofs=%u tstamp=%u"
                  " tomb=%u\r\n", entry.file_id, entry.total_size,
                  entry.offset, entry.timestamp, (unsigned)entry.is_tombstone);

            return result;
        }
        else
        {
            DEBUG(" ... not_found\r\n");
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
        uint64 epoch = handle->keydir->epoch;
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
    KeydirPutCode ret_code;
    ErlNifBinary key;
    uint32_t file_id;
    uint64_t offset;
    // If this call has 5 arguments, this is a conditional removal. We
    // only want to actually remove the entry if the tstamp, fileid and
    // offset matches the one provided. A sort of poor-man's CAS.
    int is_conditional = argc == 4;
    int common_args_ok =
        enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE, (void**)&handle) &&
        enif_inspect_binary(env, argv[1], &key);
    int other_args_ok;
   
    if (is_conditional)
    {
        other_args_ok =
            enif_get_uint(env, argv[3], (unsigned int*)&file_id)
            && enif_get_uint64_bin(env, argv[4], (uint64_t*)&offset);

    }
    else
    {
        file_id = 0;
        offset = 0; // Not really used though.
        other_args_ok = 1;
    }

    if (common_args_ok && other_args_ok)
    {
        bitcask_keydir* keydir = handle->keydir;

        DEBUG("+++ Remove %s\r\n", is_conditional ? "conditional" : "");
        DEBUG_KEYDIR(keydir);

        ret_code = keydir_remove(keydir, key.data, key.size, file_id, offset);

        switch(ret_code)
        {
            case KEYDIR_PUT_OK:
                return ATOM_OK;
            case KEYDIR_PUT_MODIFIED:
                return ATOM_MODIFIED;
            case KEYDIR_PUT_OUT_OF_MEMORY:
                return ATOM_OUT_OF_MEMORY;
            default:
                // new put code we forgot to add here?
                return enif_make_badarg(env);
        }

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
    //handle->keydir->keyfolders--;
    handle->iterator_epoch = MAX_EPOCH;

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
                             enif_make_int(env, 0),
                             enif_make_int(env, keydir->num_iterators),
                             ATOM_FALSE,
                             ATOM_UNDEFINED);

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
    ATOM_MODIFIED = enif_make_atom(env, "modified");
    ATOM_NOT_FOUND = enif_make_atom(env, "not_found");
    ATOM_NOT_READY = enif_make_atom(env, "not_ready");
    ATOM_OK = enif_make_atom(env, "ok");
    ATOM_OUT_OF_DATE = enif_make_atom(env, "out_of_date");
    ATOM_OUT_OF_MEMORY = enif_make_atom(env, "out_of_memory");
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
