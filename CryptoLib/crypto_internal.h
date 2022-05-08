// crypto_internal.h
//

#pragma once

#include "crypto_helpers.h"

typedef struct _BlockCipherKeysSizes {
    BlockCipherType cipherType;
    uint16_t keySize;
    uint16_t roundsKeysSize;
} BlockCipherKeysSizes;

static const BlockCipherKeysSizes g_blockCipherKeysSizes[] = {
    { DES_cipher_type,   DES_KEY_SIZE,  DES_ROUNDS_KEYS_SIZE },
    { TDES_cipher_type, TDES_KEY_SIZE, TDES_ROUNDS_KEYS_SIZE }
};

#define BITS_PER_BYTE                   8
#define DES_BLOCK_SIZE                  8
#define MAX_PKCSN7_BLOCK_SIZE           255
#define SHA1_BLOCK_SIZE                 64
#define SHA2_BLOCK_SIZE                 128

#define SHA1_STATE_SIZE                 20
#define SHA2_32_STATE_SIZE              32
#define SHA2_64_STATE_SIZE              64
#define SHA3_STATE_SIZE                 200

#define SHA1_FULL_STATE_SIZE            (sizeof(HashFunc) + SHA1_STATE_SIZE + sizeof(uint64_t))
#define SHA2_32_FULL_STATE_SIZE         (sizeof(HashFunc) + SHA2_32_STATE_SIZE + sizeof(uint64_t))
#define SHA2_64_FULL_STATE_SIZE         (sizeof(HashFunc) + SHA2_64_STATE_SIZE + (sizeof(uint64_t) << 1))
#define SHA3_FULL_STATE_SIZE            (sizeof(HashFunc) + SHA3_STATE_SIZE + sizeof(uint64_t))

// The order of mappings must be equal to the order of HashFunc consts
static const HashFuncsSizes g_hashFuncsSizesMapping[] =
{
    { SHA1,          64, SHA1_DIGEST_SIZE,          SHA1_STATE_SIZE,       SHA1_FULL_STATE_SIZE    },
    { SHA_224,       64, SHA_224_DIGEST_SIZE,       SHA2_32_STATE_SIZE,    SHA2_32_FULL_STATE_SIZE },
    { SHA_256,       64, SHA_256_DIGEST_SIZE,       SHA2_32_STATE_SIZE,    SHA2_32_FULL_STATE_SIZE },
    { SHA_384,      128, SHA_384_DIGEST_SIZE,       SHA2_64_STATE_SIZE,    SHA2_64_FULL_STATE_SIZE },
    { SHA_512_224,  128, SHA_512_224_DIGEST_SIZE,   SHA2_64_STATE_SIZE,    SHA2_64_FULL_STATE_SIZE },
    { SHA_512_256,  128, SHA_512_256_DIGEST_SIZE,   SHA2_64_STATE_SIZE,    SHA2_64_FULL_STATE_SIZE },
    { SHA_512,      128, SHA_512_DIGEST_SIZE,       SHA2_64_STATE_SIZE,    SHA2_64_FULL_STATE_SIZE },
    { SHA3_224,     144, SHA3_224_DIGEST_SIZE,      SHA3_STATE_SIZE,       SHA3_FULL_STATE_SIZE    },
    { SHA3_256,     136, SHA3_256_DIGEST_SIZE,      SHA3_STATE_SIZE,       SHA3_FULL_STATE_SIZE    },
    { SHA3_384,     104, SHA3_384_DIGEST_SIZE,      SHA3_STATE_SIZE,       SHA3_FULL_STATE_SIZE    },
    { SHA3_512,      72, SHA3_512_DIGEST_SIZE,      SHA3_STATE_SIZE,       SHA3_FULL_STATE_SIZE    }
};

typedef struct _XofSizes {
    Xof func;
    uint16_t blockSize;
    uint16_t fullStateSize;
} XofSizes;

static const XofSizes g_XofSizesMapping[] =
{
    { SHAKE128, 168, SHA3_FULL_STATE_SIZE },
    { SHAKE256, 136, SHA3_FULL_STATE_SIZE }
};


typedef struct _PrfSizes {
    Prf prf;
    HashFunc hashFunc;
    uint16_t stateSize;
    uint16_t fullStateSize;
} PrfSizes;

#define  HMAC_SHA1_STATE_SIZE               SHA1_FULL_STATE_SIZE + sizeof(Prf)
#define  HMAC_SHA_224_STATE_SIZE            SHA2_32_FULL_STATE_SIZE + sizeof(Prf)
#define  HMAC_SHA_256_STATE_SIZE            SHA2_32_FULL_STATE_SIZE + sizeof(Prf)
#define  HMAC_SHA_384_STATE_SIZE            SHA2_64_FULL_STATE_SIZE + sizeof(Prf)
#define  HMAC_SHA_512_224_STATE_SIZE        SHA2_64_FULL_STATE_SIZE + sizeof(Prf)
#define  HMAC_SHA_512_256_STATE_SIZE        SHA2_64_FULL_STATE_SIZE + sizeof(Prf)
#define  HMAC_SHA_512_STATE_SIZE            SHA2_64_FULL_STATE_SIZE + sizeof(Prf)
#define  HMAC_SHA3_224_STATE_SIZE           SHA3_FULL_STATE_SIZE + sizeof(Prf)
#define  HMAC_SHA3_256_STATE_SIZE           SHA3_FULL_STATE_SIZE + sizeof(Prf)
#define  HMAC_SHA3_384_STATE_SIZE           SHA3_FULL_STATE_SIZE + sizeof(Prf)
#define  HMAC_SHA3_512_STATE_SIZE           SHA3_FULL_STATE_SIZE + sizeof(Prf)

#define  HMAC_SHA1_FULL_STATE_SIZE          (SHA1_FULL_STATE_SIZE + 128)
#define  HMAC_SHA_224_FULL_STATE_SIZE       (SHA2_32_FULL_STATE_SIZE + 128)
#define  HMAC_SHA_256_FULL_STATE_SIZE       (SHA2_32_FULL_STATE_SIZE + 128)
#define  HMAC_SHA_384_FULL_STATE_SIZE       (SHA2_64_FULL_STATE_SIZE + 256)
#define  HMAC_SHA_512_224_FULL_STATE_SIZE   (SHA2_64_FULL_STATE_SIZE + 256)
#define  HMAC_SHA_512_256_FULL_STATE_SIZE   (SHA2_64_FULL_STATE_SIZE + 256)
#define  HMAC_SHA_512_FULL_STATE_SIZE       (SHA2_64_FULL_STATE_SIZE + 256)
#define  HMAC_SHA3_224_FULL_STATE_SIZE      (SHA3_FULL_STATE_SIZE + 288)
#define  HMAC_SHA3_256_FULL_STATE_SIZE      (SHA3_FULL_STATE_SIZE + 272)
#define  HMAC_SHA3_384_FULL_STATE_SIZE      (SHA3_FULL_STATE_SIZE + 208)
#define  HMAC_SHA3_512_FULL_STATE_SIZE      (SHA3_FULL_STATE_SIZE + 144)

static const PrfSizes g_PrfSizesMapping[] = {
    { HMAC_SHA1,        SHA1,        HMAC_SHA1_STATE_SIZE, HMAC_SHA1_FULL_STATE_SIZE},
    { HMAC_SHA_224,     SHA_224,     HMAC_SHA_224_STATE_SIZE, HMAC_SHA_224_FULL_STATE_SIZE},
    { HMAC_SHA_256,     SHA_256,     HMAC_SHA_256_STATE_SIZE, HMAC_SHA_256_FULL_STATE_SIZE},
    { HMAC_SHA_384,     SHA_384,     HMAC_SHA_384_STATE_SIZE, HMAC_SHA_384_FULL_STATE_SIZE},
    { HMAC_SHA_512_224, SHA_512_224, HMAC_SHA_512_224_STATE_SIZE, HMAC_SHA_512_224_FULL_STATE_SIZE},
    { HMAC_SHA_512_256, SHA_512_256, HMAC_SHA_512_256_STATE_SIZE, HMAC_SHA_512_256_FULL_STATE_SIZE},
    { HMAC_SHA_512,     SHA_512,     HMAC_SHA_512_STATE_SIZE, HMAC_SHA_512_FULL_STATE_SIZE},
    { HMAC_SHA3_224,    SHA3_224,    HMAC_SHA3_224_STATE_SIZE, HMAC_SHA3_224_FULL_STATE_SIZE},
    { HMAC_SHA3_256,    SHA3_256,    HMAC_SHA3_256_STATE_SIZE, HMAC_SHA3_256_FULL_STATE_SIZE},
    { HMAC_SHA3_384,    SHA3_384,    HMAC_SHA3_384_STATE_SIZE, HMAC_SHA3_384_FULL_STATE_SIZE},
    { HMAC_SHA3_512,    SHA3_512,    HMAC_SHA3_512_STATE_SIZE, HMAC_SHA3_512_FULL_STATE_SIZE}
};

/*
    State structs

    Hash States (HashFuncState<T>)
    (T == SHA1)                         { HashFunc func, uint32_t[5] state,  uint64_t size };
    (T == SHA_224  || T == SHA_256)     { HashFunc func, uint32_t[8] state,  uint64_t size };
    (T >= SHA_384  && T <= SHA_512)     { HashFunc func, uint64_t[8] state,  uint64_t sizeLow, uint64_t sizeHigh };
    (T >= SHA3_224 && T <= SHA3_512)    { HashFunc func, uint64_t[25] state };

    Xof States (XofFuncState<T>)
    (T == SHAKE128 || T == SHAKE256)    { Xof func, uint64_t[25] state, bool stateWasAllocatedByLib };

    HMAC States
    HMAC {
        Prf func,
        bool isStart,
        uint8_t hashFuncState[g_hashFuncsSizesMapping[g_PrfSizesMapping[func].hashFunc].fullStateSize],
        uint8_t iKeyPad[g_hashFuncsSizesMapping[g_PrfSizesMapping[func].hashFunc].blockSize],
        uint8_t oKeyPad[g_hashFuncsSizesMapping[g_PrfSizesMapping[func].hashFunc].blockSize]
    };
*/

int EncryptByBlockCipherInternal(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* roundsKeys, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __in_opt const void* iv);
int DecryptByBlockCipherInternal(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* roundsKeys, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __in_opt const void* iv);

int GetBlockCipherRoundsKeysInternal(__in const void* key, __in BlockCipherType cipherType, __out void* output);

void GetHashInternal(__in const void* input, __in uint64_t inputSize, __out void* output, __in bool finalize, __inout HashState state);
void GetXofInternal(__in const void* input, __in uint64_t inputSize, __out void* output, __in uint64_t outputSize, __in bool finalize, __inout XofState state);
void GetPrfInternal(__in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __out void* output, __in bool finalize, __inout PrfState state);