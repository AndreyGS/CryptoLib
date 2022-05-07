// sha-2.h
//

#pragma once

#include "crypto_helpers.h"

void Sha2_32Get(__in const void* input, __in uint64_t inputSize, __in HashFunc func, __out uint64_t* output, __in StageType stageType, __inout_opt void* state);
void Sha2_64Get(__in const void* input, __in uint64_t inputSize, __in HashFunc func, __out uint32_t* output, __in StageType stageType, __inout_opt void* state);
