#pragma once

#include "crypto_internal.h"

DesEncrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t* key, __out void* output, __inout uint64_t* outputSize,
    __in BlockCipherOpMode mode, __in const void* iv);
DesDecrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t* key, __out void* output, __inout uint64_t* outputSize,
    __in BlockCipherOpMode mode, __in const void* iv);
