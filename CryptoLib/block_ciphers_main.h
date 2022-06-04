#pragma once

#include "crypto_helpers.h"

typedef struct _DesState {
    uint64_t roundsKeys[16];
    uint64_t iv;
    uint64_t outputBuffer;      // Using only in CFB, OFB and CTR operation modes
} DesState;

typedef struct _TdesState {
    uint64_t roundsKeys[48];
    uint64_t iv;
    uint64_t outputBuffer;      // Using only in CFB, OFB and CTR operation modes
} TdesState;

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

#define DES_ROUNDS_KEYS_SIZE            128
#define TDES_ROUNDS_KEYS_SIZE           384

#define BLOCK_CIPHER_STATE_HEADER_SIZE  sizeof(BlockCipherState) - sizeof(uint64_t)

#define BLOCK_CIPHER_STATE_DES_SIZE     BLOCK_CIPHER_STATE_HEADER_SIZE + sizeof(DesState)
#define BLOCK_CIPHER_STATE_TDES_SIZE    BLOCK_CIPHER_STATE_HEADER_SIZE + sizeof(TdesState)

static const BlockCiphersSizes g_blockCiphersSizes[] = {
    { DES_cipher_type,   DES_KEY_SIZE,  DES_ROUNDS_KEYS_SIZE, sizeof(DesState),  BLOCK_CIPHER_STATE_DES_SIZE  },
    { TDES_cipher_type, TDES_KEY_SIZE, TDES_ROUNDS_KEYS_SIZE, sizeof(TdesState), BLOCK_CIPHER_STATE_TDES_SIZE }
};

int EncryptByBlockCipher(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding
    , __in const uint8_t* input, __in uint64_t inputSize, __in bool finalize, __out_opt uint8_t* output, __inout uint64_t* outputSize);
int DecryptByBlockCipher(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding
    , __in const uint8_t* input, __in uint64_t inputSize, __in bool finalize, __out_opt uint8_t* output, __inout uint64_t* outputSize);
