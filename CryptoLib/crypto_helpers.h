/*
 * @file crypto_helpers.h
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

#include "crypto.h"

#define EVAL(expr) { status = expr; if (status < 0) goto exit; }

int CheckInput(__in const void* input, __in uint64_t inputSize);
int CheckOutput(__in const void* output, __in const uint64_t* outputSize);
int CheckInputOutput(__in const void* input, __in uint64_t inputSize, __in const void* output, __in const uint64_t* outputSize);
int CheckBlockCipherPrimaryArguments(const void* input, uint64_t inputSize, PaddingType padding, const uint64_t* key, BlockCipherType cipherType, const void* output, const uint64_t* outputSize, BlockCipherOpMode mode, const void* iv);
int CheckHashAndXofPrimaryArguments(const StateHandle state, const void* input, uint64_t inputSize, bool finalize, const void* output);

extern inline uint32_t Uint32BigEndianLeftRotateByOne(uint32_t word);
extern inline uint32_t Uint32BigEndianLeftRotate(uint32_t word, int rounds);
extern inline uint32_t Uint32BigEndianRightRotate(uint32_t word, int rounds);
extern inline uint64_t Uint64BigEndianRightRotate(uint64_t word, int rounds);

// All "le to be" funcs also working as "be to le", obviously
extern inline uint32_t Uint32LittleEndianToBigEndian(uint32_t input);
extern inline uint64_t Uint64LittleEndianToBigEndian(uint64_t input);
extern inline uint64_t Uint64LittleEndianToBigEndianBits(uint64_t input);

extern inline int AllocBuffer(size_t size, void**);
extern inline void FreeBuffer(void* buffer);

int FillLastDecryptedBlockInternal(__in PaddingType padding, __in uint64_t blockSize, __in const void* lastOutputBlock, __in uint64_t inputSize, __out void* output, __inout uint64_t* outputSize);
