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

int Sha3GetHash(__in const VoidAndSizeNode* inputList, __in uint64_t inputListSize, __in HashFunc func, __out uint64_t* output);
int Sha3GetXof(__in const VoidAndSizeNode* inputList, __in uint64_t inputListSize, __in HashFunc func, __out uint64_t* output, __in uint64_t outputSize);

