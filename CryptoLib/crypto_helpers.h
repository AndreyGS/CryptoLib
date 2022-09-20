/**
 * @file crypto_helpers.h
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
 */

#pragma once

#include "crypto.h"

#ifndef KERNEL
#include <stdalign.h>
#endif // !KERNEL

#define QWORDS_IN_XMM 2
#define XMM_NUMBER_WITHOUT_AVX 8
#define XMM_NUMBER_WITH_AVX 16

#define SHA_1_2_MAX_BLOCKS_NUMBER_IN_TAIL 2

#define EVAL(expr) { if ((status = (expr)) < 0) goto exit; }

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__STDC_LIB_EXT1__) && !defined(KERNEL)
    #define __STDC_WANT_LIB_EXT1__ 1
    #include <string.h>
#else
    errno_t memset_s(void* dest, rsize_t destsz, int ch, rsize_t count);
#endif

int CheckHashAndXofPrimaryArguments(const StateHandle state, const void* input, uint64_t inputSize, bool finalize, const void* output);

extern inline uint32_t Uint32BigEndianLeftRotateByOne(uint32_t word);
extern inline uint32_t Uint32BigEndianLeftRotate(uint32_t word, int rounds);
extern inline uint32_t Uint32BigEndianRightRotate(uint32_t word, int rounds);
extern inline uint64_t Uint64BigEndianRightRotate(uint64_t word, int rounds);

// All "le to be" funcs also working as "be to le", obviously
extern inline uint32_t Uint32LittleEndianToBigEndian(uint32_t input);
extern inline uint64_t Uint64LittleEndianToBigEndian(uint64_t input);
extern inline uint64_t Uint64LittleEndianToBigEndianBits(uint64_t input);

extern inline int AllocBuffer(void** buffer, size_t size);
extern inline int AlignedAllocBuffer(void** buffer, size_t size, size_t alignment);
extern inline void FreeBuffer(void* buffer);
extern inline void AlignedFreeBuffer(void* buffer);

#ifdef __cplusplus
}
#endif
