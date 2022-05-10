// sha-3.h
//

#pragma once

#include "crypto_helpers.h"

typedef enum _Sha3Func {
    Sha3Func_SHA3_224,
    Sha3Func_SHA3_256,
    Sha3Func_SHA3_384,
    Sha3Func_SHA3_512,
    Sha3Func_SHAKE128,
    Sha3Func_SHAKE256
} Sha3Func;

void Sha3GetHash(__in const void* input, __in uint64_t inputSize, __in HashFunc func, __out uint64_t* output, __in bool finalize, __inout void* state);
void Sha3GetXof(__in const void* input, __in uint64_t inputSize, __in Xof func, __out uint64_t* output, __in uint64_t outputSize, __in bool finalize, __inout void* state);

