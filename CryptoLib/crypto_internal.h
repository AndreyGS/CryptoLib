/*
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
 * @section DESCRIPTON
 *
 * This file represents public interface, enums and macros of CryptoLib
 */

#pragma once

#include "crypto_helpers.h"
#include "des.h"
#include "sha-1.h"
#include "sha-2.h"
#include "sha-3.h"

#ifndef ANYSIZE_ARRAY
#define ANYSIZE_ARRAY 1
#endif

typedef struct _BlockCipherState {
    BlockCipherType cipher;
    CryptoMode enMode;
    BlockCipherOpMode opMode;
    PaddingType padding;
    uint64_t state[ANYSIZE_ARRAY];
} BlockCipherState;

typedef struct _BlockCiphersSizes {
    BlockCipherType cipher;
    uint16_t keySize;
    uint16_t roundsKeysSize;
    uint16_t stateSize;
    uint16_t stateAndHeaderSize;
} BlockCiphersSizes;

static const BlockCiphersSizes g_blockCiphersSizes[] = {
    { DES_cipher_type,   DES_KEY_SIZE,  DES_ROUNDS_KEYS_SIZE, sizeof(DesState),  BLOCK_CIPHER_STATE_DES_SIZE  },
    { TDES_cipher_type, TDES_KEY_SIZE, TDES_ROUNDS_KEYS_SIZE, sizeof(TdesState), BLOCK_CIPHER_STATE_TDES_SIZE }
};

#define BITS_PER_BYTE                   8
#define DES_BLOCK_SIZE                  8
#define MAX_PKCSN7_BLOCK_SIZE           255

typedef struct _HashState {
    HashFunc func;
    uint64_t state[ANYSIZE_ARRAY];
} HashState;

#define HASH_STATE_HEADER_SIZE           sizeof(HashState) - sizeof(uint64_t)

#define HASH_STATE_SHA1_SIZE             HASH_STATE_HEADER_SIZE + sizeof(Sha1State)
#define HASH_STATE_SHA2_32_SIZE          HASH_STATE_HEADER_SIZE + sizeof(Sha2_32State)
#define HASH_STATE_SHA2_64_SIZE          HASH_STATE_HEADER_SIZE + sizeof(Sha2_64State)
#define HASH_STATE_SHA3_224_SIZE         HASH_STATE_HEADER_SIZE + sizeof(Sha3_224State)
#define HASH_STATE_SHA3_256_SIZE         HASH_STATE_HEADER_SIZE + sizeof(Sha3_256State)
#define HASH_STATE_SHA3_384_SIZE         HASH_STATE_HEADER_SIZE + sizeof(Sha3_384State)
#define HASH_STATE_SHA3_512_SIZE         HASH_STATE_HEADER_SIZE + sizeof(Sha3_512State)

typedef struct _HashFuncsSizes {
    HashFunc func;
    uint16_t blockSize;
    uint16_t didgestSize;
    uint16_t stateSize;
    uint16_t stateAndHeaderSize;
} HashFuncsSizes;

// The order of mappings must be equal to the order of HashFunc consts
static const HashFuncsSizes g_hashFuncsSizesMapping[] =
{
    { SHA1,         SHA1_BLOCK_SIZE,     SHA1_DIGEST_SIZE,          sizeof(Sha1State),      HASH_STATE_SHA1_SIZE },
    { SHA_224,      SHA2_32_BLOCK_SIZE,  SHA_224_DIGEST_SIZE,       sizeof(Sha2_32State),   HASH_STATE_SHA2_32_SIZE },
    { SHA_256,      SHA2_32_BLOCK_SIZE,  SHA_256_DIGEST_SIZE,       sizeof(Sha2_32State),   HASH_STATE_SHA2_32_SIZE },
    { SHA_384,      SHA2_64_BLOCK_SIZE,  SHA_384_DIGEST_SIZE,       sizeof(Sha2_64State),   HASH_STATE_SHA2_64_SIZE },
    { SHA_512_224,  SHA2_64_BLOCK_SIZE,  SHA_512_224_DIGEST_SIZE,   sizeof(Sha2_64State),   HASH_STATE_SHA2_64_SIZE },
    { SHA_512_256,  SHA2_64_BLOCK_SIZE,  SHA_512_256_DIGEST_SIZE,   sizeof(Sha2_64State),   HASH_STATE_SHA2_64_SIZE },
    { SHA_512,      SHA2_64_BLOCK_SIZE,  SHA_512_DIGEST_SIZE,       sizeof(Sha2_64State),   HASH_STATE_SHA2_64_SIZE },
    { SHA3_224,     SHA3_224_BLOCK_SIZE, SHA3_224_DIGEST_SIZE,      sizeof(Sha3_224State),  HASH_STATE_SHA3_224_SIZE },
    { SHA3_256,     SHA3_256_BLOCK_SIZE, SHA3_256_DIGEST_SIZE,      sizeof(Sha3_256State),  HASH_STATE_SHA3_256_SIZE },
    { SHA3_384,     SHA3_384_BLOCK_SIZE, SHA3_384_DIGEST_SIZE,      sizeof(Sha3_384State),  HASH_STATE_SHA3_384_SIZE },
    { SHA3_512,     SHA3_512_BLOCK_SIZE, SHA3_512_DIGEST_SIZE,      sizeof(Sha3_512State),  HASH_STATE_SHA3_512_SIZE }
};

typedef struct _XofState {
    Xof func;
    uint64_t state[ANYSIZE_ARRAY];
} XofState;

#define XOF_STATE_HEADER_SIZE       sizeof(XofState) - sizeof(uint64_t)

#define XOF_STATE_SHAKE128_SIZE          XOF_STATE_HEADER_SIZE + sizeof(Shake128State)
#define XOF_STATE_SHAKE256_SIZE          XOF_STATE_HEADER_SIZE + sizeof(Shake256State)

typedef struct _XofSizes {
    Xof func;
    uint16_t blockSize;
    uint16_t stateSize;
    uint16_t stateAndHeaderSize;
} XofSizes;

static const XofSizes g_XofSizesMapping[] =
{
    { SHAKE128, SHAKE128_BLOCK_SIZE, sizeof(Shake128State), XOF_STATE_SHAKE128_SIZE },
    { SHAKE256, SHAKE256_BLOCK_SIZE, sizeof(Shake256State), XOF_STATE_SHAKE256_SIZE }
};

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

typedef StateHandle HmacStateHandle;

typedef struct _PrfState {
    Prf func;
    uint64_t state[ANYSIZE_ARRAY];
} PrfState;

#define PRF_STATE_HEADER_SIZE                sizeof(PrfState) - sizeof(uint64_t)

#define PRF_STATE_HMAC_SHA1_SIZE             PRF_STATE_HEADER_SIZE + sizeof(Hmac_Sha1State)
#define PRF_STATE_HMAC_SHA2_32_SIZE          PRF_STATE_HEADER_SIZE + sizeof(Hmac_Sha2_32State)
#define PRF_STATE_HMAC_SHA2_64_SIZE          PRF_STATE_HEADER_SIZE + sizeof(Hmac_Sha2_64State)
#define PRF_STATE_HMAC_SHA3_224_SIZE         PRF_STATE_HEADER_SIZE + sizeof(Hmac_Sha3_224State)
#define PRF_STATE_HMAC_SHA3_256_SIZE         PRF_STATE_HEADER_SIZE + sizeof(Hmac_Sha3_256State)
#define PRF_STATE_HMAC_SHA3_384_SIZE         PRF_STATE_HEADER_SIZE + sizeof(Hmac_Sha3_384State)
#define PRF_STATE_HMAC_SHA3_512_SIZE         PRF_STATE_HEADER_SIZE + sizeof(Hmac_Sha3_512State)

typedef struct _PrfSizes {
    Prf prf;
    HashFunc hashFunc;
    uint16_t stateSize;
    uint16_t stateAndHeaderSize;
} PrfSizes;

static const PrfSizes g_PrfSizesMapping[] = {
    { HMAC_SHA1,        SHA1,        sizeof(Hmac_Sha1State),        PRF_STATE_HMAC_SHA1_SIZE     },
    { HMAC_SHA_224,     SHA_224,     sizeof(Hmac_Sha2_32State),     PRF_STATE_HMAC_SHA2_32_SIZE  },
    { HMAC_SHA_256,     SHA_256,     sizeof(Hmac_Sha2_32State),     PRF_STATE_HMAC_SHA2_32_SIZE  },
    { HMAC_SHA_384,     SHA_384,     sizeof(Hmac_Sha2_64State),     PRF_STATE_HMAC_SHA2_64_SIZE  },
    { HMAC_SHA_512_224, SHA_512_224, sizeof(Hmac_Sha2_64State),     PRF_STATE_HMAC_SHA2_64_SIZE  },
    { HMAC_SHA_512_256, SHA_512_256, sizeof(Hmac_Sha2_64State),     PRF_STATE_HMAC_SHA2_64_SIZE  },
    { HMAC_SHA_512,     SHA_512,     sizeof(Hmac_Sha2_64State),     PRF_STATE_HMAC_SHA2_64_SIZE  },
    { HMAC_SHA3_224,    SHA3_224,    sizeof(Hmac_Sha3_224State),    PRF_STATE_HMAC_SHA3_224_SIZE },
    { HMAC_SHA3_256,    SHA3_256,    sizeof(Hmac_Sha3_256State),    PRF_STATE_HMAC_SHA3_256_SIZE },
    { HMAC_SHA3_384,    SHA3_384,    sizeof(Hmac_Sha3_384State),    PRF_STATE_HMAC_SHA3_384_SIZE },
    { HMAC_SHA3_512,    SHA3_512,    sizeof(Hmac_Sha3_512State),    PRF_STATE_HMAC_SHA3_512_SIZE }
};

// Block Ciphers Functions
int
InitBlockCiperStateInternal(__inout BlockCipherState** state, __in BlockCipherType cipher, __in CryptoMode cryptoMode, __in BlockCipherOpMode opMode, __in PaddingType padding, __in const void* key, __in_opt void* iv);

extern inline void 
GetBlockCipherRoundsKeysInternal(__in BlockCipherType cipher, __in const void* key, __out void* roundsKeys);

extern inline void 
ReInitBlockCipherCryptoModeInternal(__inout BlockCipherState* handle, __in CryptoMode cryptoMode);

extern inline void 
ReInitBlockCipherOpModeInternal(__inout BlockCipherState* handle, __in BlockCipherOpMode opMode);

extern inline void 
ReInitBlockCipherPaddingTypeInternal(__inout BlockCipherState* handle, __in PaddingType padding);

void 
ReInitBlockCipherIvInternal(__inout BlockCipherState* handle, __in const void* iv);

int 
ProcessingByBlockCipherInternal(__inout BlockCipherState* handle, __in const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output, __inout uint64_t* outputSize);

extern inline void 
FreeBlockCipherStateInternal(__inout BlockCipherState* state);

// Hash Functions
int 
InitHashStateInternal(__inout HashState** state, __in HashFunc func);

void 
ResetHashStateInternal(__inout HashState* state);

void 
GetHashInternal(__inout HashState* state, __in const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output);

extern inline void 
FreeHashStateInternal(__inout HashState* state);

// XOF functions
int
InitXofStateInternal(__inout XofState** state, __in Xof func);

extern inline void
ResetXofStateInternal(__inout XofState* state);

void 
GetXofInternal(__inout XofState* state, __in const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output, __in uint64_t outputSize);

extern inline void 
FreeXofStateInternal(__inout XofState* state);

// Prf functions
int 
InitPrfStateInternal(__inout PrfState** state, __in Prf func);

extern inline void 
ResetPrfStateInternal(__inout PrfState* state);

void 
GetPrfInternal(__inout PrfState* state, __in_opt const void* input, __in uint64_t inputSize, __in_opt const void* key, __in uint64_t keySize, __in bool finalize, __out_opt void* output, __in_opt uint64_t outputSize);

extern inline void 
FreePrfStateInternal(__inout PrfState* state);
