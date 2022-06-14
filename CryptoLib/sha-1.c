// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/**
 * @file sha-1.c
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
#include "sha-1.h"
#include "paddings.h"
#include "crypto_internal.h"

const uint32_t H[5] = {
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
    0xc3d2e1f0
};

const uint32_t K1 = 0x5a827999;
const uint32_t K2 = 0x6ed9eba1;
const uint32_t K3 = 0x8f1bbcdc;
const uint32_t K4 = 0xca62c1d6;

void Sha1InitState(__out uint32_t* state)
{
    state[0] = H[0], state[1] = H[1], state[2] = H[2], state[3] = H[3], state[4] = H[4];
}

void Sha1ProcessBlock(const uint32_t* input, uint32_t* words, uint32_t* output)
{
    for (int i = 0; i < 16; ++i)
        words[i] = Uint32LittleEndianToBigEndian(*input++);

    for (int i = 16; i < 32; ++i)
        words[i] = Uint32BigEndianLeftRotateByOne(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]);

    for (int i = 32; i < 80; ++i)
        words[i] = Uint32BigEndianLeftRotate(words[i - 6] ^ words[i - 16] ^ words[i - 28] ^ words[i - 32], 2);

    uint32_t a = output[0],
             b = output[1],
             c = output[2],
             d = output[3],
             e = output[4],
             f = 0,
             k = 0,
             temp = 0;

    for (int i = 0; i < 80; ++i) {
        if (i < 20) {
            f = d ^ (b & (c ^ d));
            k = K1;
        }
        else if (i < 40) {
            f = b ^ c ^ d;
            k = K2;
        }
        else if (i < 60) {
            f = b & c | d & (b | c);
            k = K3;
        }
        else {
            f = b ^ c ^ d;
            k = K4;
        }

        temp = Uint32BigEndianLeftRotate(a, 5) + e + f + k + words[i],
        e = d,
        d = c,
        c = Uint32BigEndianLeftRotate(b, 30),
        b = a,
        a = temp;
    }
    
    output[0] += a;
    output[1] += b;
    output[2] += c;
    output[3] += d;
    output[4] += e;
}

void Sha1Get(__inout Sha1State* state, __in_opt const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt uint32_t* output)
{
    uint64_t blocksNum = (inputSize >> 6 /* inputSize / SHA1_BLOCK_SIZE */) + 1;
    uint32_t* mainState = state->state;

    while (--blocksNum) {
        Sha1ProcessBlock(input, state->words, mainState);
        (uint8_t*)input += SHA1_BLOCK_SIZE;
    }
    
    state->size += inputSize;

    if (finalize) {
        uint8_t* tailBlocks = (uint8_t*)state->tailBlocks;

        AddShaPaddingInternal(input, state->size, tailBlocks, &blocksNum);

        while (blocksNum--) {
            Sha1ProcessBlock((uint32_t*)tailBlocks, state->words, mainState);
            tailBlocks += SHA1_BLOCK_SIZE;
        }

        output[0] = Uint32LittleEndianToBigEndian(mainState[0]);
        output[1] = Uint32LittleEndianToBigEndian(mainState[1]);
        output[2] = Uint32LittleEndianToBigEndian(mainState[2]);
        output[3] = Uint32LittleEndianToBigEndian(mainState[3]);
        output[4] = Uint32LittleEndianToBigEndian(mainState[4]);
    }
}
