#pragma once

#include "crypto.h"

inline int CheckInputOutput(__in const void* input, __in uint64_t inputSize, __in void* output, __in uint64_t* outputSize);
inline int GetPaddingInternal(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize);
