// des.h
//

#pragma once

#include "crypto_helpers.h"

void SingleDesGetRoundsKeys(__in uint64_t extendedKey, __out uint64_t* roundsKeys);

void DesEncryptBlock(__in const uint64_t* roundsKeys, __in const uint64_t* input, __out uint64_t* output);
void DesDecryptBlock(__in const uint64_t* roundsKeys, __in const uint64_t* input, __out uint64_t* output);

void TdesEncryptBlock(__in const uint64_t* roundsKeys, __in const uint64_t* input, __out uint64_t* output);
void TdesDecryptBlock(__in const uint64_t* roundsKeys, __in const uint64_t* input, __out uint64_t* output);

int SingleDesEncrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const uint64_t* roundsKeys, __out void* output, __inout uint64_t* outputSize,
    __in BlockCipherOpMode mode, __inout_opt uint64_t* iv);
int SingleDesDecrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const uint64_t* roundsKeys, __out void* output, __inout uint64_t* outputSize,
    __in BlockCipherOpMode mode, __inout_opt uint64_t* iv);

void TripleDesGetRoundsKeys(__in const uint64_t* extendedKeys, __out uint64_t* roundsKeys);

int TripleDesEncrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const uint64_t* roundsKeys, __out void* output, __inout uint64_t* outputSize,
    __in BlockCipherOpMode mode, __inout_opt uint64_t* iv);
int TripleDesDecrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const uint64_t* roundsKeys, __out void* output, __inout uint64_t* outputSize,
    __in BlockCipherOpMode mode, __inout_opt uint64_t* iv);