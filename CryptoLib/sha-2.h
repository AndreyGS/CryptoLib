// sha-2.h
//

#pragma once

#include "crypto_helpers.h"

typedef struct _Sha2_32State {
    uint32_t state[8];
    uint64_t size;
    uint32_t words[64];
    uint64_t tailBlocks[16];
} Sha2_32State;

typedef struct _Sha2_64State {
    uint64_t state[8];
    uint64_t sizeLow;
    uint64_t sizeHigh;
    uint64_t words[80];
    uint64_t tailBlocks[32];
} Sha2_64State;

void Sha2_32InitState(__in HashFunc func, __out uint32_t* state);
void Sha2_64InitState(__in HashFunc func, __out uint64_t* state);
void Sha2_32Get(__inout Sha2_32State* state, __in_opt const void* input, __in uint64_t inputSize, __in HashFunc func,  __in bool finalize, __out_opt uint32_t* output);
void Sha2_64Get(__inout Sha2_64State* state, __in_opt const void* input, __in uint64_t inputSize, __in HashFunc func,  __in bool finalize, __out_opt uint64_t* output);
