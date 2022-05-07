// sha-1.h
//

#pragma once

#include "crypto_helpers.h"

void Sha1Get(__in const void* input, __in uint64_t inputSize, __in HashFunc func, __out uint32_t* output, __in StageType stageType, __inout_opt void* state);
