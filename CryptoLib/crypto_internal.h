// crypto_internal.h
//

#pragma once

#include "crypto_helpers.h"

int EncryptByBlockCipherInternal(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* roundsKeys, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __in_opt const void* iv);
int DecryptByBlockCipherInternal(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* roundsKeys, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __in_opt const void* iv);

int GetBlockCipherRoundsKeysInternal(__in const void* key, __in BlockCipherType cipherType, __out void* output);

void GetHashInternal(__in const void* input, __in uint64_t inputSize, __in HashFunc func, __out void* output, __in StageType stageType, __inout_opt void* state);
void GetXofInternal(__in const void* input, __in uint64_t inputSize, __in Xof func, __out void* output, __in StageType stageType, __in uint64_t outputSize, __inout_opt void* state);
