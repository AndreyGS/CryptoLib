// sha-1.h
//

#pragma once

#include "crypto_helpers.h"
#include "crypto_internal.h"

void Sha1Get(__in const void* input, __in uint64_t inputSize, __out uint32_t* output, __in bool finalize, __inout Sha1State* state);
