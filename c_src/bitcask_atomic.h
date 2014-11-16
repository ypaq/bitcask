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
#ifndef BITCASK_ATOMIC_H
#define BITCASK_ATOMIC_H

// Low level atomic instructions and memory barriers

#if defined(OS_SOLARIS) || defined(SOLARIS) || defined(sun)
 #define BITCASK_IS_SOLARIS 1
#else
 #undef BITCASK_IS_SOLARIS
#endif

#ifdef BITCASK_IS_SOLARIS
 #include <atomic.h>
#endif

static uint64_t bc_atomic_incr_64(volatile uint64_t * ptr)
{
#if BITCASK_IS_SOLARIS
    return atomic_inc_64_nv(ptr);
#else
    return __sync_add_and_fetch(ptr, 1);
#endif
}

static uint32_t bc_atomic_incr_32(volatile uint32_t * ptr)
{
#if BITCASK_IS_SOLARIS
    return atomic_inc_32_nv(ptr);
#else
    return __sync_add_and_fetch(ptr, 1);
#endif
}

static uint64_t bc_atomic_add_64(volatile uint64_t * ptr, int64_t val)
{
#if BITCASK_IS_SOLARIS
    return atomic_add_64_nv(ptr, val);
#else
    return __sync_add_and_fetch(ptr, val);
#endif
}

static uint32_t bc_atomic_add_32(volatile uint32_t * ptr, int32_t val)
{
#if BITCASK_IS_SOLARIS
    return atomic_add_32_nv(ptr, val);
#else
    return __sync_add_and_fetch(ptr, val);
#endif
}

static int bc_atomic_cas_32(volatile uint32_t * ptr,
                          uint32_t comp_val,
                          uint32_t exchange_val)
{
#if BITCASK_IS_SOLARIS
    return (comp_val==atomic_cas_32(ptr, comp_val, exchange_val));
#else
    return __sync_bool_compare_and_swap(ptr, comp_val, exchange_val);
#endif
}

static int bc_atomic_cas_64(volatile uint64_t * ptr,
                          uint64_t comp_val,
                          uint64_t exchange_val)
{
#if BITCASK_IS_SOLARIS
    return (comp_val==atomic_cas_ptr(ptr, comp_val, exchange_val));
#else
    return __sync_bool_compare_and_swap(ptr, comp_val, exchange_val);
#endif
}

static int bc_atomic_cas_ptr(volatile void ** ptr,
                           void* comp_val,
                           void* exchange_val)
{
#if BITCASK_IS_SOLARIS
    return (comp_val==atomic_cas_ptr(ptr, comp_val, exchange_val));
#else
    return __sync_bool_compare_and_swap(ptr, comp_val, exchange_val);
#endif
}

static void bc_full_barrier()
{
    __sync_synchronize();
}

#endif
