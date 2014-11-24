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


#ifdef BITCASK_DEBUG

#include <stddef.h>
#include <stdio.h>

int erts_snprintf(char *, size_t, const char *, ...); 
void format_bin(char * buf, size_t buf_size, const unsigned char * bin,
                size_t bin_size);
void print_keydir(bitcask_keydir* keydir);

#define BC_DEBUG(F, ...) fprintf(stderr, F, __VA_ARGS__)
#define MAX_DEBUG_STR 128
#define BC_DEBUG_STR(N, V) \
    char N[MAX_DEBUG_STR];\
    erts_snprintf(N, MAX_DEBUG_STR, "%s", V)

#define BC_DEBUG_BIN(N, V, S) \
    char N[MAX_DEBUG_STR];\
    format_bin(N, MAX_DEBUG_STR, (unsigned char*)V, (size_t)S)

#define BC_DEBUG2 BC_DEBUG

#if defined(BITCASK_DEBUG_KEYDIR)
#  define BC_DEBUG_KEYDIR(KD) print_keydir((KD))
#  define BC_DEBUG_ENTRY(E) print_entry((E))
#else
#  define BC_DEBUG_KEYDIR(X)
#  define BC_DEBUG_ENTRY(E)
#endif

#else // No debugging, all cheap stubs.

#define BC_DEBUG(X, ...) 
#define BC_DEBUG2(X, ...) 
#define BC_DEBUG_STR(A, B)
#define BC_DEBUG_BIN(N, V, S)
#define BC_DEBUG_KEYDIR(X)
#define BC_DEBUG_ENTRY(E)
#define BC_DEBUG_KEY(KS, K)

#endif
