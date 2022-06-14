/*
 * @file paddings.h
 * @author Andrey Grabov-Smetankin <ukbpyh@gmail.com>
 *
 * @section LICENSE
 *
 * Copyright 2022 Andrey Grabov-Smetankin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * @section DESCRIPTON
 *
 * This file represents public interface, enums and macros of CryptoLib
 */

#pragma once

#include "sha-3.h"

int CheckPaddingInputOutput(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __in void* output, __in uint64_t* outputSize);
int CheckPaddingOutput(__in uint64_t blockSize, __in const void* paddedOutput, __in uint64_t* outputSize);

int AddPaddingInternal(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in size_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock);
int PullPaddingSizeInternal(__in PaddingType padding, __in const void* input, __in uint64_t blockSize, __out uint64_t* paddingSize);
int CutPaddingInternal(__in PaddingType padding, __in uint64_t blockSize, __out void* paddedOutput, __inout uint64_t* outputSize);

void AddShaPaddingInternal(__in const void* input, __in uint64_t inputSize, __out void* output, __out uint64_t* outputSize);
void AddSha2_64PaddingInternal(__in const void* input, __in uint64_t inputSizeLowPart, __in uint64_t inputSizeHighPart, __out void* output, __out uint64_t* outputBlocksNum);
void AddSha3PaddingInternal(__in const void* input, __in uint64_t inputSize, __in Sha3Func func, __out void* output);
