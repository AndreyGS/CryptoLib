#pragma once

#include "crypto.h"

inline int CheckOutput(__in const void* output, __in const uint64_t* outputSize);
extern inline int CheckInputOutput(__in const void* input, __in uint64_t inputSize, __in const void* output, __in const uint64_t* outputSize);

inline int AddPaddingInternal(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize);
inline int CutPaddingInternal(__in PaddingType padding, __in uint64_t blockSize, __out void* paddedOutput, __inout uint64_t* outputSize);
