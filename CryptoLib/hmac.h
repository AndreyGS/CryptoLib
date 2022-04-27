// hmac.h
//

#pragma once

#include "crypto_internal.h"

int GetHmac(__in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __in HashFunc func, __out void* output);
int GetHmacPrf(__in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __in PRF func, __out void* output);
