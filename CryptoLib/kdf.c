// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/**
 * @file kdf.c
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

#include "pch.h"
#include "kdf.h"
#include "hmac.h"

int GetPbkdf2(__in_opt const void* salt, __in size_t saltSize, __in_opt const void* password, __in size_t passwordSize, __in Prf func, __in uint64_t iterationsNum, __out void* output, __in size_t outputSize)
{
    int status = NO_ERROR;
    if (!salt && saltSize)
        return ERROR_NULL_INPUT;
    else if (!password && passwordSize)
        return ERROR_NULL_KEY;
    else if (func < HMAC_SHA1 || func > HMAC_SHA3_512)
        return ERROR_UNSUPPORTED_PRF_FUNC;
    else if (!iterationsNum)
        return ERROR_TOO_SMALL_ITERATIONS_NUMBER;
    else if (!output)
        return ERROR_NULL_OUTPUT;
    else if (!outputSize)
        return ERROR_TOO_SMALL_OUTPUT_SIZE;
    else {
        uint8_t* saltBuffer = NULL;
        EVAL(AllocBuffer(&saltBuffer, (size_t)saltSize + 4));

        memcpy(saltBuffer, salt, (size_t)saltSize);
        status = GetPbkdf2Internal(saltBuffer, saltSize, password, passwordSize, func, iterationsNum, output, outputSize);
        FreeBuffer(saltBuffer);
    }

exit:
    return status;
}

int GetPbkdf2Internal(__in_opt const void* salt, __in size_t saltSize, __in_opt const void* password, __in size_t passwordSize, __in Prf func, __in uint64_t iterationsNum, __out void* output, __in size_t outputSize)
{
    assert((salt || !saltSize) && (password || !passwordSize) && output && outputSize);

    int status = NO_ERROR;

    uint16_t didgestSize = g_hashFuncsSizesMapping[func].didgestSize;

    uint8_t* buffer1 = NULL;
    uint8_t* buffer2 = NULL;
    PrfState* state = NULL;
    EVAL(AllocBuffer(&buffer1, didgestSize));
    EVAL(AllocBuffer(&buffer2, didgestSize));
    EVAL(InitPrfState(&state, func));

    uint8_t* reserveBuffer2 = buffer2;

    if (outputSize > 0xffffffff * (uint64_t)didgestSize)
        EVAL(ERROR_NULL_OUTPUT_SIZE);

    uint32_t blocksNum = (uint32_t)((outputSize + (didgestSize - 1)) / didgestSize);
    uint32_t blocksCounter = 0;
    size_t saltFullSize = saltSize + 4;

    while (blocksNum--) {
        *(uint32_t*)((uint8_t*)salt + saltSize) = Uint32LittleEndianToBigEndian(++blocksCounter);
        GetPrfInternal(state, salt, saltFullSize, password, passwordSize, true, buffer1, 0);

        if (blocksNum) {
            buffer2 = output;
            (uint8_t*)output += didgestSize;
        }
        else
            buffer2 = reserveBuffer2;

        memcpy(buffer2, buffer1, didgestSize);

        uint64_t blockIterationsNum = iterationsNum;
        while (--blockIterationsNum) {
            GetPrfInternal(state, buffer1, didgestSize, password, passwordSize, true, buffer1, 0);
            for (uint16_t i = 0; i < didgestSize; ++i)
                buffer2[i] ^= buffer1[i];
        }

        // Last block, it can be not whole didgest size
        if (!blocksNum)
            memcpy(output, buffer2, outputSize % didgestSize ? outputSize % didgestSize : didgestSize);
    }

exit:
    FreePrfState(state);
    FreeBuffer(buffer2);
    FreeBuffer(buffer1);
    
    return status;
}
