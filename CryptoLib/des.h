// des.h
//

#pragma once

#include "crypto_helpers.h"

typedef struct _DesState {
    uint64_t roundsKeys[16];
    uint64_t iv;
} DesState;

typedef struct _TdesState {
    uint64_t roundsKeys[48];
    uint64_t iv;
} TdesState;

#define DES_ROUNDS_KEYS_SIZE            128
#define TDES_ROUNDS_KEYS_SIZE           384

#define BLOCK_CIPHER_STATE_HEADER_SIZE  sizeof(BlockCipherState) - sizeof(uint64_t)

#define BLOCK_CIPHER_STATE_DES_SIZE     BLOCK_CIPHER_STATE_HEADER_SIZE + sizeof(DesState)
#define BLOCK_CIPHER_STATE_TDES_SIZE    BLOCK_CIPHER_STATE_HEADER_SIZE + sizeof(TdesState)

extern inline void DesGetRoundsKeys(__in BlockCipherType cipher, __in const uint64_t* key, __out uint64_t* roundsKeys);

int DesEncrypt(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding, __in const void* input, __in uint64_t inputSize
    , __in bool finalize, __out_opt void* output, __inout uint64_t* outputSize);
int DesDecrypt(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding, __in const void* input, __in uint64_t inputSize
    , __in bool finalize, __out_opt void* output, __inout uint64_t* outputSize);

