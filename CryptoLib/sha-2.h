/**
 * @file sha-2.h
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

#pragma once

#include "crypto_helpers.h"

typedef struct _Sha2_32State {
    uint32_t state[8];
    uint64_t size;
    uint32_t words[64];
    uint64_t tailBlocks[16];
} Sha2_32State;

typedef struct _Sha2_64State {
    uint64_t state[8];
    uint64_t sizeLow;
    uint64_t sizeHigh;
    uint64_t words[80];
    uint64_t tailBlocks[32];
} Sha2_64State;

void Sha2_32InitState(__in HashFunc func, __out uint32_t* state);
void Sha2_64InitState(__in HashFunc func, __out uint64_t* state);
void Sha2_32Get(__inout Sha2_32State* state, __in_opt const void* input, __in uint64_t inputSize, __in HashFunc func,  __in bool finalize, __out_opt uint32_t* output);
void Sha2_64Get(__inout Sha2_64State* state, __in_opt const void* input, __in uint64_t inputSize, __in HashFunc func,  __in bool finalize, __out_opt uint64_t* output);
