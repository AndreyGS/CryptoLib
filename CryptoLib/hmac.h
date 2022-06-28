/**
 * @file hmac.h
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

#include "crypto_internal.h"
#include "sha-1.h"
#include "sha-2.h"
#include "sha-3.h"

typedef struct _Hmac_Sha1State {
    uint8_t hashFuncState[HASH_STATE_SHA1_SIZE];
    uint8_t iKeyPad[SHA1_BLOCK_SIZE];
    uint8_t oKeyPad[SHA1_BLOCK_SIZE];
    bool notFirst;
} Hmac_Sha1State;

typedef struct _Hmac_Sha2_32State {
    uint8_t hashFuncState[HASH_STATE_SHA2_32_SIZE];
    uint8_t iKeyPad[SHA2_32_BLOCK_SIZE];
    uint8_t oKeyPad[SHA2_32_BLOCK_SIZE];
    bool notFirst;
} Hmac_Sha2_32State;

typedef struct _Hmac_Sha2_64State {
    uint8_t hashFuncState[HASH_STATE_SHA2_64_SIZE];
    uint8_t iKeyPad[SHA2_64_BLOCK_SIZE];
    uint8_t oKeyPad[SHA2_64_BLOCK_SIZE];
    bool notFirst;
} Hmac_Sha2_64State;

typedef struct _Hmac_Sha3_224State {
    uint8_t hashFuncState[HASH_STATE_SHA3_224_SIZE];
    uint8_t iKeyPad[SHA3_224_BLOCK_SIZE];
    uint8_t oKeyPad[SHA3_224_BLOCK_SIZE];
    bool notFirst;
} Hmac_Sha3_224State;

typedef struct _Hmac_Sha3_256State {
    uint8_t hashFuncState[HASH_STATE_SHA3_256_SIZE];
    uint8_t iKeyPad[SHA3_256_BLOCK_SIZE];
    uint8_t oKeyPad[SHA3_256_BLOCK_SIZE];
    bool notFirst;
} Hmac_Sha3_256State;

typedef struct _Hmac_Sha3_384State {
    uint8_t hashFuncState[HASH_STATE_SHA3_384_SIZE];
    uint8_t iKeyPad[SHA3_384_BLOCK_SIZE];
    uint8_t oKeyPad[SHA3_384_BLOCK_SIZE];
    bool notFirst;
} Hmac_Sha3_384State;

typedef struct _Hmac_Sha3_512State {
    uint8_t hashFuncState[HASH_STATE_SHA3_512_SIZE];
    uint8_t iKeyPad[SHA3_512_BLOCK_SIZE];
    uint8_t oKeyPad[SHA3_512_BLOCK_SIZE];
    bool notFirst;
} Hmac_Sha3_512State;

void GetHmac(__inout HmacStateHandle state, __in const void* input, __in size_t inputSize, __in const void* key, __in size_t keySize, __in Prf func, __in bool finalize, __out_opt void* output);
