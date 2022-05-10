// sha-2.h
//

#pragma once

#include "crypto_helpers.h"
#include "crypto_internal.h"

void Sha2_32Get(__in const void* input, __in uint64_t inputSize, __in HashFunc func, __out uint32_t* output, __in bool lastPart, __inout Sha2_32State* state);
void Sha2_64Get(__in const void* input, __in uint64_t inputSize, __in HashFunc func, __out uint64_t* output, __in bool lastPart, __inout Sha2_64State* state);
