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
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#include "bitcask_debug.h"
#include "bitcask_keydir.h"

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

void print_keydir(bitcask_keydir* keydir)
{
}

void dump_fstats(bitcask_keydir* keydir)
{
    bitcask_fstats_entry* curr_f;
    khiter_t itr;
    for (itr = kh_begin(keydir->fstats); itr != kh_end(keydir->fstats); ++itr)
    {
        if (kh_exist(keydir->fstats, itr))
        {
            curr_f = &kh_val(keydir->fstats, itr);
            BC_DEBUG("fstats %d live=(%d,%d) total=(%d,%d)\r\n",
                     (int) curr_f->file_id,
                     (int) curr_f->live_keys,
                     (int) curr_f->live_bytes,
                     (int) curr_f->total_keys,
                     (int) curr_f->total_bytes);
        }
    }
}
