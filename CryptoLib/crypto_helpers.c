// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/**
 * @file crypto_helpers.c
 * @author Andrey Grabov-Smetankin <ukbpyh@gmail.com>
 *
 * @section LICENSE
 *
 * Copyright 2022-2023 Andrey Grabov-Smetankin <ukbpyh@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include "pch.h"
#include "crypto_helpers.h"
#include "paddings.h"

#ifndef __STDC_LIB_EXT1__
errno_t memset_s(void* dest, rsize_t destsz, int ch, rsize_t count)
{
    if (dest && destsz >= count) {
        if (count & 7) {
            ++count;
            volatile uint8_t* p = (uint8_t*)dest - 1;
            while (--count)
                *++p = (uint8_t)ch;
        }
        else {
            count = (count >> 3) + 1;
            volatile uint64_t* p = (uint64_t*)dest - 1;
            while (--count)
                *++p = (uint64_t)ch;
        }
    }

    return 0;
}
#endif // __STDC_LIB_EXT1__

int CheckHashAndXofPrimaryArguments(const StateHandle state, const void* input, uint64_t inputSize, bool finalize, const void* output)
{
    if (!state)
        return ERROR_NULL_STATE_HANDLE;
    else if (finalize && !output)
        return ERROR_NULL_OUTPUT;
    else if (!input && inputSize)
        return ERROR_NULL_INPUT;
    else
        return NO_ERROR;
}
