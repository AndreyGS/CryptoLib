// des.h
//

#pragma once

#include "crypto_helpers.h"

void SingleDesGetRoundsKeys(__in uint64_t extendedKey, __out uint64_t* roundsKeys);

int SingleDesEncrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t* roundsKeys, __out void* output, __inout uint64_t* outputSize,
    __in BlockCipherOpMode mode, __in_opt const void* iv);
int SingleDesDecrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t* roundsKeys, __out void* output, __inout uint64_t* outputSize,
    __in BlockCipherOpMode mode, __in_opt const void* iv);

void TripleDesGetRoundsKeys(__in const uint64_t* extendedKeys, __out uint64_t* roundsKeys);

int TripleDesEncrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t* roundsKeys, __out void* output, __inout uint64_t* outputSize,
    __in BlockCipherOpMode mode, __in_opt const void* iv);
int TripleDesDecrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t* roundsKeys, __out void* output, __inout uint64_t* outputSize,
    __in BlockCipherOpMode mode, __in_opt const void* iv);