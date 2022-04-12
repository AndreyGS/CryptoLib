#pragma once

#include "crypto.h"

int AddPaddingInternal(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock);
int PullPaddingSizeInternal(__in PaddingType padding, __in void* input, __in uint64_t blockSize, __out uint64_t* paddingSize);
int CutPaddingInternal(__in PaddingType padding, __in uint64_t blockSize, __out void* paddedOutput, __inout uint64_t* outputSize);
int AddShaPaddingInternal(__in const void* input, __in uint64_t inputSize, __out void* output, __out uint64_t* outputSize);
int AddSha2_64PaddingInternal(__in const void* input, __in uint64_t inputSizeLowPart, __in uint64_t inputSizeHighPart, __out void* output, __out uint64_t* outputBlocksNum);
