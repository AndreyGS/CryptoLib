/**
 * @file aes.h
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

#pragma once

#include "crypto_helpers.h"

#define AES128_ROUNDKEYS_NUMBER         11
#define AES192_ROUNDKEYS_NUMBER         13
#define AES256_ROUNDKEYS_NUMBER         15
#define AES_QWORDS_IN_ROUNDKEY          2

#define AES128_TOTAL_QWORDS_IN_ROUNDKEYS (AES128_ROUNDKEYS_NUMBER * AES_QWORDS_IN_ROUNDKEY)
#define AES192_TOTAL_QWORDS_IN_ROUNDKEYS (AES192_ROUNDKEYS_NUMBER * AES_QWORDS_IN_ROUNDKEY)
#define AES256_TOTAL_QWORDS_IN_ROUNDKEYS (AES256_ROUNDKEYS_NUMBER * AES_QWORDS_IN_ROUNDKEY)

#define AES_QWORDS_IN_IV                2

typedef struct _Aes128State {
    uint64_t roundKeys[AES128_TOTAL_QWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
} Aes128State;

typedef struct _Aes192State {
    uint64_t roundKeys[AES192_TOTAL_QWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
} Aes192State;

typedef struct _Aes256State {
    uint64_t roundKeys[AES256_TOTAL_QWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
} Aes256State;

typedef struct _Aes128NiState {
    uint64_t roundKeys[AES128_TOTAL_QWORDS_IN_ROUNDKEYS];
    uint64_t decryptionRoundKeys[AES128_TOTAL_QWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
} Aes128NiState;

typedef struct _Aes192NiState {
    uint64_t roundKeys[AES192_TOTAL_QWORDS_IN_ROUNDKEYS];
    uint64_t decryptionRoundKeys[AES192_TOTAL_QWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
} Aes192NiState;

typedef struct _Aes256NiState {
    uint64_t roundKeys[AES256_TOTAL_QWORDS_IN_ROUNDKEYS];
    uint64_t decryptionRoundKeys[AES256_TOTAL_QWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
} Aes256NiState;

typedef struct _Aes128AvxState {
    uint64_t roundKeys[AES128_TOTAL_QWORDS_IN_ROUNDKEYS];
    uint64_t decryptionRoundKeys[AES128_TOTAL_QWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
} Aes128AvxState;

typedef struct _Aes192AvxState {
    uint64_t roundKeys[AES192_TOTAL_QWORDS_IN_ROUNDKEYS];
    uint64_t decryptionRoundKeys[AES192_TOTAL_QWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
} Aes192AvxState;

typedef struct _Aes256AvxState {
    uint64_t roundKeys[AES256_TOTAL_QWORDS_IN_ROUNDKEYS];
    uint64_t decryptionRoundKeys[AES256_TOTAL_QWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
} Aes256AvxState;

void AesKeySchedule(__in BlockCipherType cipher, __in const uint64_t* key, __in HardwareFeatures hwFeatures, __out void* specificCipherState);

int AesEncrypt(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding, __in HardwareFeatures hwFeatures
    , __in const uint64_t* input, __in size_t inputSize, __in bool finalize, __out_opt uint64_t* output, __inout size_t* outputSize);

int AesDecrypt(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding, __in HardwareFeatures hwFeatures
    , __in const uint64_t* input, __in size_t inputSize, __in bool finalize, __out_opt uint64_t* output, __inout size_t* outputSize);
