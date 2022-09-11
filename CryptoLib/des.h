/**
 * @file des.h
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

#define DES_ROUND_KEYS_NUMBER       16
#define TDES_ROUND_KEYS_NUMBER      48

#define DES_ROUND_KEYS_NUMBER_X2    32

typedef struct _DesState {
    uint64_t roundKeys[DES_ROUND_KEYS_NUMBER];
    uint64_t iv;
} DesState;

typedef struct _TdesState {
    uint64_t roundKeys[TDES_ROUND_KEYS_NUMBER];
    uint64_t iv;
} TdesState;


extern inline void DesKeySchedule(__in BlockCipherType cipher, __in const uint64_t* key, __out uint64_t* roundKeys);

int DesEncrypt(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding, __in const uint64_t* input, __in size_t inputSize
    , __in bool finalize, __out_opt uint64_t* output, __inout size_t* outputSize);
int DesDecrypt(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding, __in const uint64_t* input, __in size_t inputSize
    , __in bool finalize, __out_opt uint64_t* output, __inout size_t* outputSize);
