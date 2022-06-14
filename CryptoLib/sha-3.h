/**
 * @file sha-3.h
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

#include "crypto.h"

typedef enum _Sha3Func {
    Sha3Func_SHA3_224,
    Sha3Func_SHA3_256,
    Sha3Func_SHA3_384,
    Sha3Func_SHA3_512,
    Sha3Func_SHAKE128,
    Sha3Func_SHAKE256
} Sha3Func;

typedef struct _Sha3_224State {
    uint64_t state[25];
    uint64_t tailBlocks[18];
} Sha3_224State;

typedef struct _Sha3_256State {
    uint64_t state[25];
    uint64_t tailBlocks[17];
} Sha3_256State;

typedef struct _Sha3_384State {
    uint64_t state[25];
    uint64_t tailBlocks[13];
} Sha3_384State;

typedef struct _Sha3_512State {
    uint64_t state[25];
    uint64_t tailBlocks[9];
} Sha3_512State;

typedef struct _Shake128State {
    uint64_t state[25];
    uint64_t tailBlocks[42];
} Shake128State;

typedef struct _Shake256State {
    uint64_t state[25];
    uint64_t tailBlocks[34];
} Shake256State;

void Sha3GetHash(__inout void* state, __in_opt const void* input, __in uint64_t inputSize, __in HashFunc func, __in bool finalize, __out_opt uint64_t* output);
void Sha3GetXof(__inout void* state, __in_opt const void* input, __in uint64_t inputSize, __in Xof func, __in bool finalize, __out_opt uint64_t* output, __in uint64_t outputSize);

