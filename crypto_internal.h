// crypto_internal.h
//

#pragma once

#include "crypto_helpers.h"

int GetHashMultipleInternal(__in const HashInputNode* inputList, __in uint64_t inputListSize, __in HashFunc func, __out void* output);
int GetPrfInternal(__in void* input, __in uint64_t inputSize, __in void* key, __in uint64_t keySize, __in PRF func, __out void* output, __out_opt uint16_t* outputSize);
