/**
 * @file aes.h
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

#define AES128_ROUNDKEYS_NUMBER         11
#define AES192_ROUNDKEYS_NUMBER         13
#define AES256_ROUNDKEYS_NUMBER         15
#define AES_DWORDS_IN_ROUNDKEY          4

#define AES128_TOTAL_DWORDS_IN_ROUNDKEYS AES128_ROUNDKEYS_NUMBER * AES_DWORDS_IN_ROUNDKEY
#define AES192_TOTAL_DWORDS_IN_ROUNDKEYS AES192_ROUNDKEYS_NUMBER * AES_DWORDS_IN_ROUNDKEY
#define AES256_TOTAL_DWORDS_IN_ROUNDKEYS AES256_ROUNDKEYS_NUMBER * AES_DWORDS_IN_ROUNDKEY

#define AES_QWORDS_IN_IV                2

#define AESNI_XMM_REGS_IN_ALGO_USE      8
#define AES128AVX_XMM_REGS_IN_ALGO_USE  12
#define AES192AVX_XMM_REGS_IN_ALGO_USE  14
#define AES256AVX_XMM_REGS_IN_ALGO_USE  16

#define AESNI_TOTAL_QWORDS_IN_XMM_REGS_IN_ALOG_USE      AESNI_XMM_REGS_IN_ALGO_USE * QWORDS_IN_XMM
#define AES128AVX_TOTAL_QWORDS_IN_XMM_REGS_IN_ALGO_USE  AES128AVX_XMM_REGS_IN_ALGO_USE * QWORDS_IN_XMM
#define AES192AVX_TOTAL_QWORDS_IN_XMM_REGS_IN_ALGO_USE  AES192AVX_XMM_REGS_IN_ALGO_USE * QWORDS_IN_XMM
#define AES256AVX_TOTAL_QWORDS_IN_XMM_REGS_IN_ALGO_USE  AES256AVX_XMM_REGS_IN_ALGO_USE * QWORDS_IN_XMM

typedef struct _Aes128State {
    uint32_t roundKeys[AES128_TOTAL_DWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
} Aes128State;

typedef struct _Aes192State {
    uint32_t roundKeys[AES192_TOTAL_DWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
} Aes192State;

typedef struct _Aes256State {
    uint32_t roundKeys[AES256_TOTAL_DWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
} Aes256State;

typedef struct _Aes128NiState {
    uint32_t roundKeys[AES128_TOTAL_DWORDS_IN_ROUNDKEYS];
    uint32_t decryptionRoundKeys[AES128_TOTAL_DWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
    uint64_t xmmRegsBuffer[AESNI_TOTAL_QWORDS_IN_XMM_REGS_IN_ALOG_USE];
} Aes128NiState;

typedef struct _Aes192NiState {
    uint32_t roundKeys[AES192_TOTAL_DWORDS_IN_ROUNDKEYS];
    uint32_t decryptionRoundKeys[AES192_TOTAL_DWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
    uint64_t xmmRegsBuffer[AESNI_TOTAL_QWORDS_IN_XMM_REGS_IN_ALOG_USE];
} Aes192NiState;

typedef struct _Aes256NiState {
    uint32_t roundKeys[AES256_TOTAL_DWORDS_IN_ROUNDKEYS];
    uint32_t decryptionRoundKeys[AES256_TOTAL_DWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
    uint64_t xmmRegsBuffer[AESNI_TOTAL_QWORDS_IN_XMM_REGS_IN_ALOG_USE];
} Aes256NiState;

typedef struct _Aes128AvxState {
    uint32_t roundKeys[AES128_TOTAL_DWORDS_IN_ROUNDKEYS];
    uint32_t decryptionRoundKeys[AES128_TOTAL_DWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
    uint64_t xmmRegsBuffer[AES128AVX_TOTAL_QWORDS_IN_XMM_REGS_IN_ALGO_USE];
} Aes128AvxState;

typedef struct _Aes192AvxState {
    uint32_t roundKeys[AES192_TOTAL_DWORDS_IN_ROUNDKEYS];
    uint32_t decryptionRoundKeys[AES192_TOTAL_DWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
    uint64_t xmmRegsBuffer[AES192AVX_TOTAL_QWORDS_IN_XMM_REGS_IN_ALGO_USE];
} Aes192AvxState;

typedef struct _Aes256AvxState {
    uint32_t roundKeys[AES256_TOTAL_DWORDS_IN_ROUNDKEYS];
    uint32_t decryptionRoundKeys[AES256_TOTAL_DWORDS_IN_ROUNDKEYS];
    uint64_t iv[AES_QWORDS_IN_IV];
    uint64_t xmmRegsBuffer[AES256AVX_TOTAL_QWORDS_IN_XMM_REGS_IN_ALGO_USE];
} Aes256AvxState;

void AesKeySchedule(__in BlockCipherType cipher, __in const uint32_t* key, __in HardwareFeatures hwFeatures, __out void* specificCipherState);

int AesEncrypt(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding, __in HardwareFeatures hwFeatures
    , __in const uint64_t* input, __in size_t inputSize, __in bool finalize, __out_opt uint64_t* output, __inout size_t* outputSize);

int AesDecrypt(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding, __in HardwareFeatures hwFeatures
    , __in const uint64_t* input, __in size_t inputSize, __in bool finalize, __out_opt uint64_t* output, __inout size_t* outputSize);
