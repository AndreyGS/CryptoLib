// des.h
//

#pragma once

#include "crypto_helpers.h"

void SingleDesGetRoundsKeys(__in uint64_t extendedKey, __out uint64_t* roundsKeys);

uint64_t DesEncryptBlock(uint64_t input, const uint64_t* roundsKeys);
uint64_t DesDecryptBlock(uint64_t input, const uint64_t* roundsKeys);

int SingleDesEncrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const uint64_t* roundsKeys, __out void* output, __inout uint64_t* outputSize,
    __in BlockCipherOpMode mode, __inout_opt uint64_t* iv);
int SingleDesDecrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const uint64_t* roundsKeys, __out void* output, __inout uint64_t* outputSize,
    __in BlockCipherOpMode mode, __inout_opt uint64_t* iv);

void TripleDesGetRoundsKeys(__in const uint64_t* extendedKeys, __out uint64_t* roundsKeys);

int TripleDesEncrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const uint64_t* roundsKeys, __out void* output, __inout uint64_t* outputSize,
    __in BlockCipherOpMode mode, __inout_opt uint64_t* iv);
int TripleDesDecrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const uint64_t* roundsKeys, __out void* output, __inout uint64_t* outputSize,
    __in BlockCipherOpMode mode, __inout_opt uint64_t* iv);