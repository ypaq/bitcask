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
static ErlNifResourceType* bitcask_iterator_RESOURCE;
static ErlNifResourceType* bitcask_lock_RESOURCE;
static ErlNifResourceType* bitcask_file_RESOURCE;

typedef struct
{
    int fd;
} bitcask_file_handle;

typedef struct
{
    bitcask_keydir* keydir;
} bitcask_keydir_handle;

typedef struct
{
    int   fd;
    int   is_write_lock;
    char  filename[0];
} bitcask_lock_handle;

#define kh_put2(name, h, k, v) {                        \
        int itr_status;                                 \
        khiter_t itr = kh_put(name, h, k, &itr_status); \
        kh_val(h, itr) = v; }                           \


// Handle lock helper functions
#define LOCK(keydir)      { if (keydir->mutex) enif_mutex_lock(keydir->mutex); }
#define UNLOCK(keydir)    { if (keydir->mutex) enif_mutex_unlock(keydir->mutex); }

// Atoms (initialized in on_load)
static ERL_NIF_TERM ATOM_INVALID;
static ERL_NIF_TERM ATOM_ALLOCATION_ERROR;
static ERL_NIF_TERM ATOM_BITCASK_ENTRY;
static ERL_NIF_TERM ATOM_ERROR;
static ERL_NIF_TERM ATOM_FALSE;
static ERL_NIF_TERM ATOM_FSTAT_ERROR;
static ERL_NIF_TERM ATOM_FTRUNCATE_ERROR;
static ERL_NIF_TERM ATOM_LOCK_NOT_WRITABLE;
static ERL_NIF_TERM ATOM_MODIFIED;
static ERL_NIF_TERM ATOM_NOT_FOUND;
static ERL_NIF_TERM ATOM_NOT_READY;
static ERL_NIF_TERM ATOM_OK;
static ERL_NIF_TERM ATOM_OUT_OF_MEMORY;
static ERL_NIF_TERM ATOM_PREAD_ERROR;
static ERL_NIF_TERM ATOM_PWRITE_ERROR;
static ERL_NIF_TERM ATOM_READY;
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
ERL_NIF_TERM bitcask_nifs_get_keydir(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
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
ERL_NIF_TERM bitcask_nifs_keydir_add_file(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM bitcask_nifs_keydir_remove_file(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

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

ERL_NIF_TERM errno_atom(ErlNifEnv* env, int error);
ERL_NIF_TERM errno_error_tuple(ErlNifEnv* env, ERL_NIF_TERM key, int error);

static void lock_release(bitcask_lock_handle* handle);

static void bitcask_nifs_keydir_resource_cleanup(ErlNifEnv* env, void* arg);
static void bitcask_nifs_iterator_resource_cleanup(ErlNifEnv* env, void* arg);
static void bitcask_nifs_file_resource_cleanup(ErlNifEnv* env, void* arg);

static ErlNifFunc nif_funcs[] =
{
#ifdef PULSE
    {"set_pulse_pid", 1, set_pulse_pid},
#endif
    {"keydir_new", 0, bitcask_nifs_keydir_new0},
    {"keydir_new", 1, bitcask_nifs_keydir_new1},
    {"get_keydir", 1, bitcask_nifs_get_keydir},
    {"keydir_mark_ready", 1, bitcask_nifs_keydir_mark_ready},
    {"keydir_put_int", 8, bitcask_nifs_keydir_put_int},
    {"keydir_get_int", 3, bitcask_nifs_keydir_get_int},
    {"keydir_get_epoch", 1, bitcask_nifs_keydir_get_epoch},
    {"keydir_remove", 2, bitcask_nifs_keydir_remove},
    {"keydir_remove_int", 4, bitcask_nifs_keydir_remove},
    {"keydir_itr", 2, bitcask_nifs_keydir_itr},
    {"keydir_itr_next", 1, bitcask_nifs_keydir_itr_next},
    {"keydir_itr_release", 1, bitcask_nifs_keydir_itr_release},
    {"keydir_info", 1, bitcask_nifs_keydir_info},
    {"keydir_release", 1, bitcask_nifs_keydir_release},
    {"keydir_add_file", 2, bitcask_nifs_keydir_add_file},
    {"keydir_remove_file", 2, bitcask_nifs_keydir_remove_file},

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
    {"update_fstats", 7, bitcask_nifs_update_fstats}
};

static bitcask_keydir * create_keydir_helper(global_keydir_data * gkd,
                                             const char * name,
                                             const char * dir,
                                             int * created_out)
{
    bitcask_keydir * keydir;
    keydir_init_params_t keydir_init_params, *params_p;
    ErlNifSysInfo sys_info;

    if (dir)
    {
        enif_system_info(&sys_info, sizeof(ErlNifSysInfo));
        keydir_default_init_params(&keydir_init_params);
        keydir_init_params.basedir = dir;
        // If made a port, add number of async threads.
        // If we start using dirty schedulers, add those too.
        keydir_init_params.num_fstats = sys_info.scheduler_threads;

        params_p = &keydir_init_params;
    }
    else // Not creating, just lookup
    {
        params_p = NULL;
    }

    return keydir = keydir_acquire(gkd, name, params_p, created_out);
}

ERL_NIF_TERM create_keydir_handle(ErlNifEnv * env, bitcask_keydir * keydir)
{
    bitcask_keydir_handle * handle;
    handle = enif_alloc_resource_compat(env, bitcask_keydir_RESOURCE,
                                        sizeof(bitcask_keydir_handle));
    memset(handle, '\0', sizeof(bitcask_keydir_handle));
    handle->keydir = keydir;
    ERL_NIF_TERM result = enif_make_resource(env, handle);
    enif_release_resource_compat(env, handle);
    return result;
}

ERL_NIF_TERM bitcask_nifs_keydir_new0(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    global_keydir_data* gkd = (global_keydir_data*)enif_priv_data(env);
    int created;
    bitcask_keydir* keydir = create_keydir_helper(gkd, NULL, ".", &created);

    if (!keydir)
    {
        int error = errno;
        return enif_make_tuple2(env, ATOM_ERROR, errno_atom(env, error));
    }

    ERL_NIF_TERM keydir_handle = create_keydir_handle(env, keydir);
    return enif_make_tuple2(env, ATOM_OK, keydir_handle);
}

ERL_NIF_TERM bitcask_nifs_get_keydir(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    char name[4096];

    if (enif_get_string(env, argv[0], name, sizeof(name), ERL_NIF_LATIN1))
    {
        global_keydir_data* gkd = (global_keydir_data*)enif_priv_data(env);
        bitcask_keydir * keydir = create_keydir_helper(gkd, name, NULL, NULL);

        if (keydir)
        {
            if (!keydir->is_ready)
            {
                keydir_release(keydir);
                keydir = NULL;
                return enif_make_tuple2(env, ATOM_ERROR, ATOM_NOT_READY);
            }
            else
            {
                ERL_NIF_TERM keydir_handle = create_keydir_handle(env, keydir);
                return enif_make_tuple2(env, ATOM_OK, keydir_handle);
            }
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

ERL_NIF_TERM bitcask_nifs_keydir_new1(ErlNifEnv* env, int argc,
                                      const ERL_NIF_TERM argv[])
{
    char name[1024];

    if (enif_get_string(env, argv[0], name, sizeof(name), ERL_NIF_LATIN1) > 0)
    {
        // Get our private stash and check the global hash table for this entry
        global_keydir_data* gkd = (global_keydir_data*)enif_priv_data(env);
        int created;
        bitcask_keydir * keydir = create_keydir_helper(gkd, name, ".",
                                                       &created);

        if (keydir)
        {
            if (!created && !keydir->is_ready)
            {
                keydir_release(keydir);
                return enif_make_tuple2(env, ATOM_ERROR, ATOM_NOT_READY);
            }
            else
            {
                ERL_NIF_TERM result = create_keydir_handle(env, keydir);
                ERL_NIF_TERM is_ready_atom =
                    keydir->is_ready ? ATOM_READY : ATOM_NOT_READY;
                return enif_make_tuple2(env, is_ready_atom, result);
            }
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

ERL_NIF_TERM bitcask_nifs_keydir_mark_ready(ErlNifEnv* env,
                                            int argc,
                                            const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;

    if (enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE,
                          (void**)&handle))
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
ERL_NIF_TERM bitcask_nifs_update_fstats(ErlNifEnv* env, int argc,
                                        const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;
    uint32_t file_id, tstamp;
    int32_t live_increment, total_increment;
    int32_t live_bytes_increment, total_bytes_increment;

    if (argc == 7
            && enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE,
                (void**)&handle)
            && enif_get_uint(env, argv[1], &file_id)
            && enif_get_uint(env, argv[2], &tstamp)
            && enif_get_int(env, argv[3], &live_increment)
            && enif_get_int(env, argv[4], &total_increment)
            && enif_get_int(env, argv[5], &live_bytes_increment)
            && enif_get_int(env, argv[6], &total_bytes_increment))
    {
        bitcask_keydir * keydir = handle->keydir;
        unsigned fstats_idx = keydir->fstats_idx_fun() % keydir->num_fstats;
        fstats_handle_t * fstats_handle = keydir->fstats_array + fstats_idx;
        update_fstats(fstats_handle->fstats, fstats_handle->mutex,
                      file_id, tstamp,
                      live_increment, total_increment,
                      live_bytes_increment, total_bytes_increment);
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

ERL_NIF_TERM bitcask_nifs_keydir_put_int(ErlNifEnv* env,
                                         int argc,
                                         const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;
    ErlNifBinary key;
    keydir_entry_t entry;
    uint32_t old_file_id;
    uint64_t old_offset;
    KeydirPutCode ret_code;

    if (enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE,
                          (void**)&handle) &&
        enif_inspect_binary(env, argv[1], &key) &&
        enif_get_uint(env, argv[2], &(entry.file_id)) &&
        enif_get_uint(env, argv[3], &(entry.total_size)) &&
        enif_get_uint64_bin(env, argv[4], &(entry.offset)) &&
        enif_get_uint(env, argv[5], &(entry.timestamp)) &&
        enif_get_uint(env, argv[6], &(old_file_id)) &&
        enif_get_uint64_bin(env, argv[7], &(old_offset)))
    {
        bitcask_keydir* keydir = handle->keydir;
        entry.key = key.data;
        entry.key_size = key.size;

        DEBUG2("LINE %d put\r\n", __LINE__);

        DEBUG_BIN(dbgKey, key.data, key.size);
        DEBUG("+++ Put key = %s file_id=%d offset=%d total_sz=%d tstamp=%u old_file_id=%d\r\n",
                dbgKey,
              (int) entry.file_id, (int) entry.offset,
              (int)entry.total_sz, (unsigned) entry.tstamp, (int)old_file_id);
        DEBUG_KEYDIR(keydir);


        ret_code = keydir_put(keydir, &entry, old_file_id, old_offset);

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
    keydir_entry_t entry;
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

        if (ret_code == KEYDIR_GET_FOUND && !is_tombstone_entry(&entry))
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
            enif_get_uint(env, argv[2], (unsigned int*)&file_id)
            && enif_get_uint64_bin(env, argv[3], (uint64_t*)&offset);

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

ERL_NIF_TERM bitcask_nifs_keydir_itr(ErlNifEnv* env, int argc,
                                     const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;
    int use_snapshot;
    KeydirItrSnapshotFlag snapshot_flag;

    if (argc == 2
        && enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE,
                          (void**)&handle)
        && enif_get_int(env, argv[1], &use_snapshot))
    {
        bitcask_keydir * keydir = handle->keydir;
        ERL_NIF_TERM itr_ref;

        if (!keydir)
        {
            return enif_make_badarg(env);
        }

        bitcask_iterator_handle * itr_handle =
            enif_alloc_resource_compat(env,
                                       bitcask_iterator_RESOURCE,
                                       sizeof(bitcask_iterator_handle));

        snapshot_flag = use_snapshot ?
            KEYDIR_ITR_USE_SNAPSHOT : KEYDIR_ITR_NO_SNAPSHOT;
        itr_handle->itr = keydir_itr_create(keydir, snapshot_flag);
        if (!itr_handle->itr)
        {
            enif_release_resource_compat(env, itr_handle);
            return enif_make_tuple2(env, ATOM_ERROR, ATOM_ALLOCATION_ERROR);
        }

        itr_handle->mutex = enif_mutex_create(0);

        itr_ref = enif_make_resource(env, itr_handle);
        enif_release_resource_compat(env, itr_handle);
        return enif_make_tuple2(env, ATOM_OK, itr_ref);
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_keydir_itr_next(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_iterator_handle* itr_handle;

    if (enif_get_resource(env, argv[0], bitcask_iterator_RESOURCE,
                          (void**)&itr_handle))
    {
        keydir_entry_t entry;
        ErlNifBinary key_binary;
        KeydirItrCode ret;

        DEBUG("+++ itr next\r\n");
        enif_mutex_lock(itr_handle->mutex);

        if (!itr_handle->itr)
        {
            enif_mutex_unlock(itr_handle->mutex);
            return enif_make_tuple2(env, ATOM_ERROR, ATOM_INVALID);
        }

        ret = keydir_itr_next(itr_handle->itr, &entry);
        enif_mutex_unlock(itr_handle->mutex);

        switch(ret)
        {
            case KEYDIR_ITR_OK:
                if (!enif_alloc_binary(entry.key_size, &key_binary))
                {
                    free(entry.key);
                    return enif_make_tuple2(env, ATOM_ERROR,
                                            ATOM_ALLOCATION_ERROR);
                }

                // Copy the data from our key to the new allocated binary
                // TODO: Refactor to avoid temporary key buffer even if ugly
                memcpy(key_binary.data, entry.key, entry.key_size);
                free(entry.key);
                return enif_make_tuple6(env,
                                        ATOM_BITCASK_ENTRY,
                                        enif_make_binary(env, &key_binary),
                                        enif_make_uint(env, entry.file_id),
                                        enif_make_uint(env, entry.total_size),
                                        enif_make_uint64(env, entry.offset),
                                        enif_make_uint(env, entry.timestamp));
            case KEYDIR_ITR_OUT_OF_MEMORY:
                return enif_make_tuple2(env, ATOM_ERROR,
                                        ATOM_ALLOCATION_ERROR);
            case KEYDIR_ITR_END:
                // The iterator is at the end of the table
                return ATOM_NOT_FOUND;
            case KEYDIR_ITR_INVALID: default:
                return enif_make_tuple2(env, ATOM_ERROR,
                                        ATOM_INVALID);
        }
    }
    else
    {
        return enif_make_badarg(env);
    }
}

static void iterator_cleanup_internal(bitcask_iterator_handle * itr_handle)
{
    enif_mutex_lock(itr_handle->mutex);
    if (itr_handle->itr)
    {
        keydir_itr_release(itr_handle->itr);
        free(itr_handle->itr);
        itr_handle->itr = NULL;
    }
    enif_mutex_unlock(itr_handle->mutex);
}

ERL_NIF_TERM bitcask_nifs_keydir_itr_release(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    bitcask_iterator_handle * itr_handle;

    if (enif_get_resource(env, argv[0], bitcask_iterator_RESOURCE,
                          (void**)&itr_handle))
    {
        iterator_cleanup_internal(itr_handle);
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

        // Fold partial fstats into keydir fstats
        keydir_aggregate_fstats(keydir);

        // Dump fstats info into a list of [{file_id, live_keys, total_keys,
        //                                   live_bytes, total_bytes,
        //                                   oldest_tstamp, newest_tstamp,
        //                                   expiration_epoch}]
        LOCK(keydir);
        ERL_NIF_TERM fstats_list = enif_make_list(env, 0);
        khiter_t itr;
        bitcask_fstats_entry* curr_f;
        for (itr = kh_begin(keydir->fstats); itr != kh_end(keydir->fstats); ++itr)
        {
            if (kh_exist(keydir->fstats, itr))
            {
                curr_f = &kh_val(keydir->fstats, itr);
                ERL_NIF_TERM fstat =
                    enif_make_tuple8(env,
                                     enif_make_uint(env, curr_f->file_id),
                                     enif_make_ulong(env, curr_f->live_keys),
                                     enif_make_ulong(env, curr_f->total_keys),
                                     enif_make_ulong(env, curr_f->live_bytes),
                                     enif_make_ulong(env, curr_f->total_bytes),
                                     enif_make_uint(env, curr_f->oldest_tstamp),
                                     enif_make_uint(env, curr_f->newest_tstamp),
                                     enif_make_uint64(env, 0));
                fstats_list = enif_make_list_cell(env, fstat, fstats_list);
            }
        }

        ERL_NIF_TERM iter_info =
            enif_make_tuple4(env,
                             enif_make_int(env, 0),
                             enif_make_int(env, keydir->itr_array.count),
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

ERL_NIF_TERM bitcask_nifs_keydir_add_file(ErlNifEnv* env, int argc,
                                           const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;
    uint32_t file_id;

    if (enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE,
                          (void**)&handle)
        && enif_get_uint(env, argv[1], &file_id))
    {
        keydir_add_file(handle->keydir, file_id);
        return ATOM_OK;
    }
    else
    {
        return enif_make_badarg(env);
    }
}

ERL_NIF_TERM bitcask_nifs_keydir_remove_file(ErlNifEnv* env, int argc,
                                             const ERL_NIF_TERM argv[])
{
    bitcask_keydir_handle* handle;
    uint32_t file_id;

    if (enif_get_resource(env, argv[0], bitcask_keydir_RESOURCE,
                          (void**)&handle)
        && enif_get_uint(env, argv[1], &file_id))
    {
        keydir_remove_file(handle->keydir, file_id);
        return ATOM_OK;
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

static void bitcask_nifs_iterator_resource_cleanup(ErlNifEnv* env, void* arg)
{
    bitcask_iterator_handle * handle = (bitcask_iterator_handle*)arg;
    iterator_cleanup_internal(handle);
    enif_mutex_destroy(handle->mutex);
}

static void bitcask_nifs_keydir_resource_cleanup(ErlNifEnv* env, void* arg)
{
    bitcask_keydir_handle* handle = (bitcask_keydir_handle*)arg;

    if (handle->keydir)
    {
        keydir_release(handle->keydir);
        handle->keydir = NULL;
        return;
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
    bitcask_keydir_RESOURCE =
        enif_open_resource_type_compat(env, "bitcask_keydir_resource",
                                       &bitcask_nifs_keydir_resource_cleanup,
                                       ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
                                       0);

    bitcask_iterator_RESOURCE =
        enif_open_resource_type_compat(env, "bitcask_iterator_resource",
                                       &bitcask_nifs_iterator_resource_cleanup,
                                       ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
                                       0);

    bitcask_lock_RESOURCE =
        enif_open_resource_type_compat(env, "bitcask_lock_resource",
                                       &bitcask_nifs_lock_resource_cleanup,
                                       ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
                                       0);

    bitcask_file_RESOURCE =
        enif_open_resource_type_compat(env, "bitcask_file_resource",
                                       &bitcask_nifs_file_resource_cleanup,
                                       ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
                                       0);

    // Initialize shared keydir hashtable
    global_keydir_data* priv = malloc(sizeof(global_keydir_data));
    priv->global_biggest_file_id = kh_init(global_biggest_file_id);
    priv->keydirs = kh_init(global_keydirs);
    priv->mutex = enif_mutex_create("bitcask_global_handles_lock");
    *priv_data = priv;

    // Initialize atoms that we use throughout the NIF.
    ATOM_ALLOCATION_ERROR = enif_make_atom(env, "allocation_error");
    ATOM_BITCASK_ENTRY = enif_make_atom(env, "bitcask_entry");
    ATOM_ERROR = enif_make_atom(env, "error");
    ATOM_FALSE = enif_make_atom(env, "false");
    ATOM_FSTAT_ERROR = enif_make_atom(env, "fstat_error");
    ATOM_FTRUNCATE_ERROR = enif_make_atom(env, "ftruncate_error");
    ATOM_LOCK_NOT_WRITABLE = enif_make_atom(env, "lock_not_writable");
    ATOM_MODIFIED = enif_make_atom(env, "modified");
    ATOM_NOT_FOUND = enif_make_atom(env, "not_found");
    ATOM_NOT_READY = enif_make_atom(env, "not_ready");
    ATOM_OK = enif_make_atom(env, "ok");
    ATOM_OUT_OF_MEMORY = enif_make_atom(env, "out_of_memory");
    ATOM_PREAD_ERROR = enif_make_atom(env, "pread_error");
    ATOM_PWRITE_ERROR = enif_make_atom(env, "pwrite_error");
    ATOM_READY = enif_make_atom(env, "ready");
    ATOM_TRUE = enif_make_atom(env, "true");
    ATOM_UNDEFINED = enif_make_atom(env, "undefined");
    ATOM_EOF = enif_make_atom(env, "eof");
    ATOM_CREATE = enif_make_atom(env, "create");
    ATOM_READONLY = enif_make_atom(env, "readonly");
    ATOM_O_SYNC = enif_make_atom(env, "o_sync");
    ATOM_CUR = enif_make_atom(env, "cur");
    ATOM_BOF = enif_make_atom(env, "bof");
    ATOM_INVALID = enif_make_atom(env, "invalid");

#ifdef PULSE
    pulse_c_send_on_load(env);
#endif

    return 0;
}

ERL_NIF_INIT(bitcask_nifs, nif_funcs, &on_load, NULL, NULL, NULL);
