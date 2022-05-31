// sha-1.h
//

#pragma once

#include "crypto.h"

typedef struct _Sha1State {
    uint32_t state[5];
    uint64_t size;
    uint32_t words[80];
    uint64_t tailBlocks[16];
} Sha1State;

void Sha1InitState(__out uint32_t* state);
void Sha1Get(__inout Sha1State* state, __in const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt uint32_t* output);
