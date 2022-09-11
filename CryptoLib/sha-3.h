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
 */

#pragma once

#include "crypto_helpers.h"

#define SHA3_QWORDS_IN_STATE        25

#define SHA3_224_QWORDS_IN_BLOCK    SHA3_224_BLOCK_SIZE / sizeof(uint64_t)
#define SHA3_256_QWORDS_IN_BLOCK    SHA3_256_BLOCK_SIZE / sizeof(uint64_t)
#define SHA3_384_QWORDS_IN_BLOCK    SHA3_384_BLOCK_SIZE / sizeof(uint64_t)
#define SHA3_512_QWORDS_IN_BLOCK    SHA3_512_BLOCK_SIZE / sizeof(uint64_t)

#define SHAKE128_QWORDS_IN_BLOCK    SHAKE128_BLOCK_SIZE / sizeof(uint64_t)
#define SHAKE256_QWORDS_IN_BLOCK    SHAKE256_BLOCK_SIZE / sizeof(uint64_t)

typedef enum _Sha3Func {
    Sha3Func_SHA3_224,
    Sha3Func_SHA3_256,
    Sha3Func_SHA3_384,
    Sha3Func_SHA3_512,
    Sha3Func_SHAKE128,
    Sha3Func_SHAKE256
} Sha3Func;

typedef struct _Sha3_224State {
    uint64_t state[SHA3_QWORDS_IN_STATE];
    uint64_t tailBlocks[SHA3_224_QWORDS_IN_BLOCK];
} Sha3_224State;

typedef struct _Sha3_256State {
    uint64_t state[SHA3_QWORDS_IN_STATE];
    uint64_t tailBlocks[SHA3_256_QWORDS_IN_BLOCK];
} Sha3_256State;

typedef struct _Sha3_384State {
    uint64_t state[SHA3_QWORDS_IN_STATE];
    uint64_t tailBlocks[SHA3_384_QWORDS_IN_BLOCK];
} Sha3_384State;

typedef struct _Sha3_512State {
    uint64_t state[SHA3_QWORDS_IN_STATE];
    uint64_t tailBlocks[SHA3_512_QWORDS_IN_BLOCK];
} Sha3_512State;

typedef struct _Shake128State {
    uint64_t state[SHA3_QWORDS_IN_STATE];
    uint64_t tailBlocks[SHAKE128_QWORDS_IN_BLOCK];
} Shake128State;

typedef struct _Shake256State {
    uint64_t state[SHA3_QWORDS_IN_STATE];
    uint64_t tailBlocks[SHAKE256_QWORDS_IN_BLOCK];
} Shake256State;

#define HASH_STATE_SHA3_224_SIZE         HASH_STATE_HEADER_SIZE + sizeof(Sha3_224State)
#define HASH_STATE_SHA3_256_SIZE         HASH_STATE_HEADER_SIZE + sizeof(Sha3_256State)
#define HASH_STATE_SHA3_384_SIZE         HASH_STATE_HEADER_SIZE + sizeof(Sha3_384State)
#define HASH_STATE_SHA3_512_SIZE         HASH_STATE_HEADER_SIZE + sizeof(Sha3_512State)

void Sha3GetHash(__inout void* state, __in_opt const void* input, __in size_t inputSize, __in HashFunc func, __in bool finalize, __out_opt uint64_t* output);
void Sha3GetXof(__inout void* state, __in_opt const void* input, __in size_t inputSize, __in Xof func, __in bool finalize, __out_opt uint64_t* output, __in size_t outputSize);

