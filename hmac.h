// hmac.h
//

#pragma once

#include "crypto_internal.h"

int GetHmac(__in void* input, __in uint64_t inputSize, __in void* key, __in uint64_t keySize, __in HashFunc func, __out void* output, __out_opt uint16_t* outputSize);
int GetHmacPrf(__in void* input, __in uint64_t inputSize, __in void* key, __in uint64_t keySize, __in PRF func, __out void* output, __out_opt uint16_t* outputSize);
