/*
 * @file pch.c: source file corresponding to the pre-compiled header
 * @author Andrey Grabov-Smetankin <ukbpyh@gmail.com>
 *
 * @section LICENSE
 *
 * Copyright 2022 Andrey Grabov-Smetankin
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
 * @section DESCRIPTON
 *
 * This file represents public interface, enums and macros of CryptoLib
 */

#include "pch.h"

// When you are using pre-compiled headers, this source file is necessary for compilation to succeed.

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
