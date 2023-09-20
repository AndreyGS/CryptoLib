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

#if defined _MSC_VER
#define AllignedAlloc _aligned_malloc
#define AllignedFree _aligned_free
#else
#define AllignedAlloc aligned_alloc
#define AllignedFree free
#endif

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

inline uint32_t Uint32BigEndianLeftRotateByOne(uint32_t word) // big-endian style
{
    return word << 1 | (word & 0x80000000 ? 1 : 0); // on 10700K this is more than 10% faster than word << 1 | word >> 31
}

inline uint32_t Uint32BigEndianLeftRotate(uint32_t word, int rounds) // big-endian style, rounds max == 32
{
    return word << rounds | word >> (32 - rounds);
}

inline uint32_t Uint32BigEndianRightRotate(uint32_t word, int rounds)
{
    return word >> rounds | word << (32 - rounds);
}

inline uint64_t Uint64BigEndianRightRotate(uint64_t word, int rounds)
{
    return word >> rounds | word << (64 - rounds);
}

inline uint64_t Uint64LittleEndianToBigEndian(uint64_t input)
{
    return input >> 56 
         | input >> 40 & 0x000000000000ff00 
         | input >> 24 & 0x0000000000ff0000 
         | input >> 8  & 0x00000000ff000000
         | input << 8  & 0x000000ff00000000
         | input << 24 & 0x0000ff0000000000
         | input << 40 & 0x00ff000000000000
         | input << 56;
}

inline uint32_t Uint32LittleEndianToBigEndian(uint32_t input)
{
    return input >> 24
         | input >> 8 & 0x0000ff00
         | input << 8 & 0x00ff0000
         | input << 24;
}

// Example of input and output of Uint64LittleEndianToBigEndianBits:
//
// first two bytes:
// input:
// 1010 0110 1110 0010 (0xa6e2)
// output:
// 0110 0101 0100 0111 (0x6547)
inline uint64_t Uint64LittleEndianToBigEndianBits(uint64_t input)
{
    return (input & 0x8080808080808080) >> 7
        |  (input & 0x4040404040404040) >> 5
        |  (input & 0x2020202020202020) >> 3
        |  (input & 0x1010101010101010) >> 1
        |  (input & 0x0808080808080808) << 1
        |  (input & 0x0404040404040404) << 3
        |  (input & 0x0202020202020202) << 5
        |  (input & 0x0101010101010101) << 7;
}

inline int AllocBuffer(void** buffer, size_t size)
{
    assert(buffer);

#ifndef KERNEL
    *buffer = malloc(size);
#endif
    if (!*buffer)
        return ERROR_NO_MEMORY;
    else
        return NO_ERROR;
}

inline int AlignedAllocBuffer(void** buffer, size_t size, size_t alignment)
{
    assert(buffer);

#ifndef KERNEL
    *buffer = AllignedAlloc(size, alignment);
#endif
    if (!*buffer)
        return ERROR_NO_MEMORY;
    else
        return NO_ERROR;
}

inline void FreeBuffer(void* buffer)
{
#ifndef KERNEL
    free(buffer);
#endif
}

inline void AlignedFreeBuffer(void* buffer)
{
#ifndef KERNEL
    AllignedFree(buffer);
#endif
}

