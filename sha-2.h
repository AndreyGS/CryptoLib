#pragma once

#include "crypto_internal.h"

void Sha2_32Get(__in const uint32_t* input, __in uint64_t inputSize, __in HashFunc func, __out uint32_t* output);
void Sha2_64Get(__in const uint64_t* input, __in uint64_t inputSizeLowPart, __in uint64_t inputSizeHighPart, __in HashFunc func, __out uint64_t* output);
