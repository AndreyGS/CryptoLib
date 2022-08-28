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

typedef struct _Aes128State {
    uint32_t roundsKeys[44];
    uint64_t iv[2];
} Aes128State;

typedef struct _Aes192State {
    uint32_t roundsKeys[52];
    uint64_t iv[2];
} Aes192State;

typedef struct _Aes256State {
    uint32_t roundsKeys[60];
    uint64_t iv[2];
} Aes256State;

typedef struct _Aes128StateXmm8 {
    void* xmmRegsBuffer[8];
    uint32_t roundsKeys[44];
    uint64_t iv[2];
} Aes128StateXmm8;

typedef struct _Aes192StateXmm8 {
    void* xmmRegsBuffer[8];
    uint32_t roundsKeys[52];
    uint64_t iv[2];
} Aes192StateXmm8;

typedef struct _Aes256StateXmm8 {
    void* xmmRegsBuffer[8];
    uint32_t roundsKeys[60];
    uint64_t iv[2];
} Aes256StateXmm8;

typedef struct _Aes128StateXmm16 {
    void* xmmRegsBuffer[16];
    uint32_t roundsKeys[44];
    uint64_t iv[2];
} Aes128StateXmm16;

typedef struct _Aes192StateXmm16 {
    void* xmmRegsBuffer[16];
    uint32_t roundsKeys[52];
    uint64_t iv[2];
} Aes192StateXmm16;

typedef struct _Aes256StateXmm16 {
    void* xmmRegsBuffer[16];
    uint32_t roundsKeys[60];
    uint64_t iv[2];
} Aes256StateXmm16;

void AesKeySchedule(__in BlockCipherType cipher, __in const uint32_t* key, __out uint32_t* roundsKeys);

int AesEncrypt(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding, __in const uint64_t* input, __in size_t inputSize
    , __in bool finalize, __out_opt uint64_t* output, __inout size_t* outputSize);

int AesDecrypt(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding, __in const uint64_t* input, __in size_t inputSize
    , __in bool finalize, __out_opt uint64_t* output, __inout size_t* outputSize);
