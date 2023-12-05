// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/**
 * @file paddings.c
 * @author Andrey Grabov-Smetankin <ukbpyh@gmail.com>
 *
 * @section LICENSE
 *
 * Copyright 2022-2023 Andrey Grabov-Smetankin <ukbpyh@gmail.com>
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

#include "pch.h"
#include "paddings.h"
#include "crypto_internal.h"

#define SHA_START_LENGTH_OFFSET 56
#define SHA2_START_LENGTH_OFFSET 112

static int CheckPaddingOutput(__in size_t blockSize, __in const void* paddedOutput, __in size_t* outputSize)
{
    if (!paddedOutput && outputSize && *outputSize)
        return ERROR_NULL_OUTPUT;
    else if (!outputSize)
        return ERROR_NULL_OUTPUT_SIZE;
    else if (!blockSize)
        return ERROR_TOO_SMALL_BLOCK_SIZE;
    else
        return NO_ERROR;
}

int PullPaddingSize(__in PaddingType padding, __in void* input, __in size_t blockSize, __out size_t* paddingSize)
{
    int status = NO_ERROR;
    if (status = CheckPaddingOutput(blockSize, input, paddingSize)) {
        if (status == ERROR_NULL_OUTPUT)
            status = ERROR_NULL_INPUT;
        return status;
    }

    return PullPaddingSizeInternal(padding, input, blockSize, paddingSize);
}

int CutPadding(__in PaddingType padding, __in size_t blockSize, __out void* output, __inout size_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckPaddingOutput(blockSize, output, outputSize))
        return status;

    return CutPaddingInternal(padding, blockSize, output, outputSize);
}

static inline bool IsWholeBlockMultiplier(size_t inputSize, size_t blockSize)
{
    return inputSize < blockSize ? false : !(inputSize % blockSize);
}

static void FillBlockStartByInput(__in const uint8_t* input, __in size_t inputSize, __in size_t blockSize, __out uint8_t* output, __in size_t paddingSize)
{
    size_t length = blockSize - paddingSize;
    size_t offset = inputSize - length;

    memcpy(output + offset, input + offset, length);
}

static size_t GetRequiringOutputSize(__in size_t inputSize, __in size_t blockSize)
{
    return inputSize + blockSize - (IsWholeBlockMultiplier(inputSize, blockSize) ? 0 : inputSize % blockSize);
}

static int GetPaddingSize(__in size_t inputSize, __in size_t blockSize, __inout size_t* outputSize, __inout size_t* paddingSize)
{
    size_t requiringSize = GetRequiringOutputSize(inputSize, blockSize);

    if (*outputSize < requiringSize) {
        *outputSize = requiringSize;
        return ERROR_TOO_SMALL_OUTPUT_SIZE;
    }
    else {
        *outputSize = requiringSize;
        *paddingSize = requiringSize - inputSize;
        return NO_ERROR;
    }
}

/*
    Zero padding functions
*/

int AddZeroPadding(__in const uint8_t* input, __in size_t inputSize, __in size_t blockSize, __out_opt uint8_t* output, __inout size_t* outputSize, __in bool fillLastBlock)
{
    int status = NO_ERROR;
    size_t paddingSize = 0;

    if (status = GetPaddingSize(inputSize, blockSize, outputSize, &paddingSize))
        return status;

    if (fillLastBlock)
        FillBlockStartByInput(input, inputSize, blockSize, output, paddingSize);

    memset(output + inputSize, 0, paddingSize);

    return NO_ERROR;
}

int PullZeroPaddingSize(__in const uint8_t* input, __in size_t blockSize, __out size_t* paddingSize)
{
    input += blockSize;
    while (!*--input && blockSize--)
        ++*paddingSize;

    if (*paddingSize == 0)
        return ERROR_PADDING_CORRUPTED;
    else
        return NO_ERROR;
}

int CutZeroPadding(__in size_t blockSize, __in const uint8_t* input, __inout size_t* inputSize)
{
    int status = NO_ERROR;
    size_t paddingSize = 0;
    if (status = PullZeroPaddingSize(input, blockSize, &paddingSize))
        return status;
    else
        return *inputSize -= paddingSize, NO_ERROR;
}

/*
    PKCS#7 padding functions
*/

int AddPKCSN7Padding(__in const uint8_t* input, __in size_t inputSize, __in uint8_t blockSize, __out_opt uint8_t* output, __inout size_t* outputSize, __in bool fillLastBlock)
{
    int status = NO_ERROR;
    size_t paddingSize = 0;

    if (status = GetPaddingSize(inputSize, blockSize, outputSize, &paddingSize))
        return status;

    if (fillLastBlock)
        FillBlockStartByInput(input, inputSize, blockSize, output, paddingSize);

    memset(output + inputSize, (int)paddingSize, paddingSize);

    return NO_ERROR;
}

int PullPKCSN7PaddingSize(__in const uint8_t* input, __in size_t blockSize, __out uint8_t* paddingSize)
{
    *paddingSize = *(input + blockSize - 1);
    if (*paddingSize == 0)
        return ERROR_PADDING_CORRUPTED;
    else
        return NO_ERROR;
}

int CutPKCSN7Padding(__in size_t blockSize, __in const uint8_t* input, __inout size_t* inputSize)
{
    int status = NO_ERROR;
    uint8_t paddingSize = 0;
    if (status = PullPKCSN7PaddingSize(input, blockSize, &paddingSize))
        return status;
    else
        return *inputSize -= paddingSize, NO_ERROR;
}

/*
    ISO/IEC 7816-4:2005 padding functions
*/

int AddISO7816Padding(__in const uint8_t* input, __in size_t inputSize, __in size_t blockSize, __out_opt uint8_t* output, __inout size_t* outputSize, __in bool fillLastBlock)
{
    int status = NO_ERROR;
    size_t paddingSize = 0;

    if (status = GetPaddingSize(inputSize, blockSize, outputSize, &paddingSize))
        return status;

    if (fillLastBlock)
        FillBlockStartByInput(input, inputSize, blockSize, output, paddingSize);

    output[inputSize] = 0x80;

    memset(output + inputSize + 1, 0, paddingSize - 1);

    return NO_ERROR;
}

int PullISO7816PaddingSize(__in const uint8_t* input, __in size_t blockSize, __out size_t* paddingSize)
{
    input += blockSize;

    while (blockSize-- && !*--input)
        ++*paddingSize;

    if (*input != 0x80)
        return ERROR_PADDING_CORRUPTED;
    else
        return ++*paddingSize, NO_ERROR;
}

int CutISO7816Padding(__in size_t blockSize, __in const uint8_t* input, __inout size_t* inputSize)
{
    int status = NO_ERROR;
    size_t paddingSize = 0;
    if (status = PullISO7816PaddingSize(input, blockSize, &paddingSize))
        return status;
    else
        return *inputSize -= paddingSize, NO_ERROR;
}

/*
    SHA paddings
*/

// output must be zeroed before its passed here
void AddShaPadding(__in const uint8_t* input, __in uint64_t inputSize, __out uint8_t* output, __out uint64_t* outputBlocksNum)
{   
    size_t lastBlockSize = inputSize % SHA1_BLOCK_SIZE;
    uint64_t messageBitsSize = inputSize << 3; // inputSizeLowPart * BITS_PER_BYTE;

    if (lastBlockSize >= SHA_START_LENGTH_OFFSET) {
        size_t paddingFillSize = SHA1_BLOCK_SIZE;
        AddPaddingInternal(input, lastBlockSize, ISO_7816_padding, SHA1_BLOCK_SIZE, output, &paddingFillSize, true);
        ((uint64_t*)output)[15] = ReverseEndiannessUint64(messageBitsSize);                                               // 15 == ((SHA1_BLOCK_SIZE * 2) / sizeof(uint64_t)) - 1
        *outputBlocksNum = 2;
    }
    else {
        size_t paddingFillSize = SHA_START_LENGTH_OFFSET;
        AddPaddingInternal(input, lastBlockSize, ISO_7816_padding, SHA_START_LENGTH_OFFSET, output, &paddingFillSize, true);
        ((uint64_t*)output)[7] = ReverseEndiannessUint64(messageBitsSize);                                                // 7 == (SHA1_BLOCK_SIZE / sizeof(uint64_t)) - 1
        *outputBlocksNum = 1;
    }
}

void AddSha2_64Padding(__in const uint8_t* input, __in uint64_t inputSizeLowPart, __in uint64_t inputSizeHighPart, __out uint8_t* output, __out uint64_t* outputBlocksNum)
{
    size_t lastBlockSize = inputSizeLowPart % SHA2_64_BLOCK_SIZE;
    uint64_t messageBitsSizeLow = inputSizeLowPart << 3; // inputSizeLowPart * BITS_PER_BYTE;
    uint64_t messageBitsSizeHigh = (inputSizeHighPart << 3) | (inputSizeLowPart & 0xe000000000000000) >> 61;

    if (lastBlockSize >= SHA2_START_LENGTH_OFFSET) {
        size_t paddingFillSize = SHA2_64_BLOCK_SIZE;
        AddPaddingInternal(input, lastBlockSize, ISO_7816_padding, SHA2_64_BLOCK_SIZE, output, &paddingFillSize, true);
        ((uint64_t*)output)[30] = ReverseEndiannessUint64(messageBitsSizeHigh);                                           // 30 == ((SHA2_BLOCK_SIZE * 2) / sizeof(uint64_t)) - 2
        ((uint64_t*)output)[31] = ReverseEndiannessUint64(messageBitsSizeLow);
        *outputBlocksNum = 2;
    }
    else {
        size_t paddingFillSize = SHA2_START_LENGTH_OFFSET;
        AddPaddingInternal(input, lastBlockSize, ISO_7816_padding, SHA2_START_LENGTH_OFFSET, output, &paddingFillSize, true);
        ((uint64_t*)output)[14] = ReverseEndiannessUint64(messageBitsSizeHigh);                                           // 14 == (SHA2_BLOCK_SIZE / sizeof(uint64_t)) - 2
        ((uint64_t*)output)[15] = ReverseEndiannessUint64(messageBitsSizeLow);
        *outputBlocksNum = 1;
    }
}

void AddSha3Padding(__in const uint8_t* input, __in size_t inputSize, __in Sha3Func func, __out uint8_t* output)
{
    uint16_t blockSize = func == Sha3Func_SHAKE128 || func == Sha3Func_SHAKE256
                       ? g_XofSizesMapping[func == Sha3Func_SHAKE128 ? SHAKE128 : SHAKE256].blockSize
                       : g_hashFuncsSizesMapping[func + SHA3_224].blockSize;
    uint16_t lastBlockSize = inputSize % blockSize;
    uint16_t paddingSize = blockSize - lastBlockSize;

    FillBlockStartByInput(input, lastBlockSize, blockSize, output, paddingSize);

    // Here we're not filling zeros cause it's an internal function and we get already zeroed array as input
    // Sha1 and Sha2 padding functions has the same situation, but there we are using standart function AddPaddingInternal,
    // which is not very nice fits Sha3 padding scheme

    output[lastBlockSize]  = func == Sha3Func_SHAKE128 || func == Sha3Func_SHAKE256
                                   ? 0x1f
                                   : 0x06;
    output[blockSize - 1] |= 0x80;
}
