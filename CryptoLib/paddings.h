/**
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
 */

#pragma once

#include "sha-3.h"

int AddZeroPadding(__in const uint8_t* input, __in size_t inputSize, __in size_t blockSize, __out uint8_t* output, __inout size_t* outputSize, __in bool fillLastBlock);
int AddPKCSN7Padding(__in const uint8_t* input, __in size_t inputSize, __in uint8_t blockSize, __out uint8_t* output, __inout size_t* outputSize, __in bool fillLastBlock);
int AddISO7816Padding(__in const uint8_t* input, __in size_t inputSize, __in size_t blockSize, __out uint8_t* output, __inout size_t* outputSize, __in bool fillLastBlock);

int PullPaddingSizeInternal(__in PaddingType padding, __in const uint8_t* input, __in size_t blockSize, __out size_t* paddingSize);
int CutPaddingInternal(__in PaddingType padding, __in size_t blockSize, __out uint8_t* paddedOutput, __inout size_t* outputSize);

void AddShaPadding(__in const uint8_t* input, __in uint64_t inputSize, __out uint8_t* output, __out uint64_t* outputBlocksNum);
void AddSha2_64Padding(__in const uint8_t* input, __in uint64_t inputSizeLowPart, __in uint64_t inputSizeHighPart, __out uint8_t* output, __out uint64_t* outputBlocksNum);
void AddSha3Padding(__in const uint8_t* input, __in size_t inputSize, __in Sha3Func func, __out uint8_t* output);
