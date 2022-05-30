// crypto_internal.h
//

#pragma once

#include "crypto_helpers.h"
#include "sha-1.h"
#include "sha-2.h"
#include "sha-3.h"

#ifndef ANYSIZE_ARRAY
#define ANYSIZE_ARRAY 1
#endif

#define DES_ROUNDS_KEYS_SIZE            128
#define TDES_ROUNDS_KEYS_SIZE           384

#define BITS_PER_BYTE                   8
#define DES_BLOCK_SIZE                  8
#define MAX_PKCSN7_BLOCK_SIZE           255

typedef struct _DesState {
    uint64_t roundsKeys[16];
    uint64_t iv;
} DesState;

typedef struct _TdesState {
    uint64_t roundsKeys[48];
    uint64_t iv;
} TdesState;

typedef struct _BlockCipherState {
    BlockCipherType cipher;
    CryptoMode enMode;
    BlockCipherOpMode opMode;
    PaddingType padding;
    uint64_t state[ANYSIZE_ARRAY];
} BlockCipherState;

#define BLOCK_CIPHER_STATE_HEADER_SIZE  sizeof(BlockCipherState) - sizeof(uint64_t)

#define BLOCK_CIPHER_STATE_DES_SIZE     BLOCK_CIPHER_STATE_HEADER_SIZE + sizeof(DesState)
#define BLOCK_CIPHER_STATE_TDES_SIZE    BLOCK_CIPHER_STATE_HEADER_SIZE + sizeof(TdesState)

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

typedef struct _Shake128State {
    uint64_t state[25];         // state field must be the first in the current structure
    uint64_t tailBlocks[42];
} Shake128State;

typedef struct _Shake256State {
    uint64_t state[25];         // state field must be the first in the current structure
    uint64_t tailBlocks[34];
} Shake256State;

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

int EncryptByBlockCipherInternal(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* roundsKeys, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __inout_opt const void* iv);
int DecryptByBlockCipherInternal(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* roundsKeys, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __inout_opt const void* iv);

void GetBlockCipherRoundsKeysInternal(__out void* roundsKeys, __in const void* key, __in BlockCipherType cipherType);

extern inline void ReInitBlockCiperCryptoModeInternal(__inout BlockCipherHandle handle, __in CryptoMode cryptoMode);
extern inline void ReInitBlockCiperOpModeInternal(__inout BlockCipherHandle handle, __in BlockCipherOpMode opMode);
extern inline void ReInitBlockCiperPaddingTypeInternal(__inout BlockCipherHandle handle, __in PaddingType padding);
void ReInitBlockCiperIvInternal(__inout BlockCipherHandle handle, __in void* iv);

int InitHashStateInternal(__inout HashHandle* handle, __in HashFunc func);
void ResetHashStateInternal(__inout HashHandle handle);
void GetHashInternal(__inout HashState* state, __out_opt void* output, __in const void* input, __in uint64_t inputSize, __in bool finalize);
void FreeHashStateInternal(__inout HashHandle handle);

int InitXofStateInternal(__inout XofHandle* handle, __in Xof func);
inline void ResetXofStateInternal(__inout XofHandle handle);
void GetXofInternal(__inout XofState* state, __out_opt void* output, __in uint64_t outputSize, __in const void* input, __in uint64_t inputSize, __in bool finalize);
void FreeXofStateInternal(__inout XofHandle handle);

int InitPrfStateInternal(__inout PrfHandle* handle, __in Prf func);
inline void ResetPrfStateInternal(__inout PrfHandle handle);
void GetPrfInternal(__inout PrfState* state, __out_opt void* output, __in uint64_t outputSize, __in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __in bool finalize);
void FreePrfStateInternal(__inout PrfHandle handle);
