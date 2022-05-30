// sha-3.h
//

#pragma once

#include "crypto.h"

typedef enum _Sha3Func {
    Sha3Func_SHA3_224,
    Sha3Func_SHA3_256,
    Sha3Func_SHA3_384,
    Sha3Func_SHA3_512,
    Sha3Func_SHAKE128,
    Sha3Func_SHAKE256
} Sha3Func;

typedef struct _Sha3_224State {
    uint64_t state[25];
    uint64_t tailBlocks[18];
} Sha3_224State;

typedef struct _Sha3_256State {
    uint64_t state[25];
    uint64_t tailBlocks[17];
} Sha3_256State;

typedef struct _Sha3_384State {
    uint64_t state[25];
    uint64_t tailBlocks[13];
} Sha3_384State;

typedef struct _Sha3_512State {
    uint64_t state[25];
    uint64_t tailBlocks[9];
} Sha3_512State;

void Sha3GetHash(__inout void* state, __out_opt uint64_t* output, __in const void* input, __in uint64_t inputSize, __in HashFunc func, __in bool finalize);
void Sha3GetXof(__inout void* state, __out_opt uint64_t* output, __in uint64_t outputSize, __in const void* input, __in uint64_t inputSize, __in Xof func, __in bool finalize);

