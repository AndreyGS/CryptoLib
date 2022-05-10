// hmac.h
//

#pragma once

#include "crypto_internal.h"

void GetHmac(__in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __in Prf func, __out void* output, __in bool finalize, __inout StateHandle state);
