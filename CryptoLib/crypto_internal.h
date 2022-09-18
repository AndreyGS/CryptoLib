/**
 * @file crypto_internal.h
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
#include "sha-1.h"
#include "sha-2.h"
#include "sha-3.h"

#ifndef ANYSIZE_ARRAY
#define ANYSIZE_ARRAY 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _BlockCipherState {
    BlockCipherType cipher;
    CryptoMode enMode;
    BlockCipherOpMode opMode;
    PaddingType padding;
    HardwareFeatures hwFeatures;
    void* state;
} BlockCipherState;

typedef struct _BlockCiphersSizes {
    BlockCipherType cipher;
    uint16_t stateSize;
} BlockCiphersSizes;

#define BITS_PER_BYTE                   8

typedef struct _HashState {
    HashFunc func;
    uint64_t state[ANYSIZE_ARRAY];
} HashState;

#define HASH_STATE_HEADER_SIZE           sizeof(HashState) - sizeof(uint64_t)

typedef struct _HashFuncsSizes {
    HashFunc func;
    uint16_t blockSize;
    uint16_t didgestSize;
    uint16_t stateSize;
    uint16_t stateAndHeaderSize;
} HashFuncsSizes;

extern const HashFuncsSizes g_hashFuncsSizesMapping[11];

typedef struct _XofState {
    Xof func;
    uint64_t state[ANYSIZE_ARRAY];
} XofState;

typedef struct _XofSizes {
    Xof func;
    uint16_t blockSize;
    uint16_t stateSize;
    uint16_t stateAndHeaderSize;
} XofSizes;

extern const XofSizes g_XofSizesMapping[2];

typedef StateHandle HmacStateHandle;

typedef struct _PrfState {
    Prf func;
    uint64_t state[ANYSIZE_ARRAY];
} PrfState;

typedef struct _PrfSizes {
    Prf prf;
    HashFunc hashFunc;
    uint16_t stateSize;
    uint16_t stateAndHeaderSize;
} PrfSizes;

extern const PrfSizes g_PrfSizesMapping[11];

int
AddPaddingInternal(__in const void* input, __in size_t inputSize, __in PaddingType padding, __in size_t blockSize, __out_opt void* output, __inout size_t* outputSize, __in bool fillLastBlock);

int
PullPaddingSizeInternal(__in PaddingType padding, __in const uint8_t* input, __in size_t blockSize, __out size_t* paddingSize);

int
CutPaddingInternal(__in PaddingType padding, __in size_t blockSize, __in uint8_t* paddedInput, __inout size_t* inputSize);

// Block Ciphers Functions
int
InitBlockCiperStateInternal(__inout BlockCipherState** state, __in BlockCipherType cipher, __in CryptoMode cryptoMode, __in BlockCipherOpMode opMode
    , __in PaddingType padding, __inout_opt HardwareFeatures* hwFeatures, __in const void* key, __in_opt const void* iv);

extern inline void
GetActiveHardwareFeaturesInternal(__in BlockCipherState* state, __out HardwareFeatures* hwFeatures);

extern inline void 
ReInitBlockCipherCryptoModeInternal(__inout BlockCipherState* state, __in CryptoMode cryptoMode);

extern inline void 
ReInitBlockCipherOpModeInternal(__inout BlockCipherState* state, __in BlockCipherOpMode opMode);

extern inline void 
ReInitBlockCipherPaddingTypeInternal(__inout BlockCipherState* state, __in PaddingType padding);

void 
ReInitBlockCipherIvInternal(__in BlockCipherType cipher, __in HardwareFeatures hwFeatures, __in const uint64_t* iv, __inout void* specificCipherState);

int 
ProcessingByBlockCipherInternal(__inout BlockCipherState* state, __in const void* input, __in size_t inputSize, __in bool finalize, __out_opt void* output, __inout size_t* outputSize);

int
FillLastDecryptedBlockInternal(__in PaddingType padding, __in size_t blockSize, __in const void* lastOutputBlock, __in size_t inputSize, __out void* output, __inout size_t* outputSize);

void 
FreeBlockCipherStateInternal(__inout BlockCipherState* state);

// Hash Functions
int 
InitHashStateInternal(__inout HashState** state, __in HashFunc func);

void 
ResetHashStateInternal(__inout HashState* state);

void 
GetHashInternal(__inout HashState* state, __in const void* input, __in size_t inputSize, __in bool finalize, __out_opt void* output);

extern inline void 
FreeHashStateInternal(__inout HashState* state);

// XOF functions
int
InitXofStateInternal(__inout XofState** state, __in Xof func);

extern inline void
ResetXofStateInternal(__inout XofState* state);

void 
GetXofInternal(__inout XofState* state, __in const void* input, __in size_t inputSize, __in bool finalize, __out_opt void* output, __in size_t outputSize);

extern inline void 
FreeXofStateInternal(__inout XofState* state);

// Prf functions
int 
InitPrfStateInternal(__inout PrfState** state, __in Prf func);

extern inline void 
ResetPrfStateInternal(__inout PrfState* state);

void 
GetPrfInternal(__inout PrfState* state, __in_opt const void* input, __in size_t inputSize, __in_opt const void* key, __in size_t keySize, __in bool finalize, __out_opt void* output, __in_opt size_t outputSize);

extern inline void 
FreePrfStateInternal(__inout PrfState* state);

#ifdef __cplusplus
}
#endif