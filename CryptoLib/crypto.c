// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/**
 * @file crypto.c: here placed all aggregating functins
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

#include "crypto_internal.h"
#include "des.h"
#include "paddings.h"
#include "kdf.h"

int AddPadding(__in const void* input, __in size_t inputSize, __in PaddingType padding, __in size_t blockSize, __out void* output, __inout size_t* outputSize, __in bool fillLastBlock)
{
    if (!input)
        return ERROR_NULL_INPUT;
    else if (!inputSize)
        return ERROR_TOO_SMALL_INPUT_SIZE;
    else if (!output && outputSize && *outputSize)
        return ERROR_NULL_OUTPUT;
    else if (!outputSize)
        return ERROR_NULL_OUTPUT_SIZE;
    else if (!blockSize)
        return ERROR_TOO_SMALL_BLOCK_SIZE;
    else    
        return AddPaddingInternal(input, inputSize, padding, blockSize, output, outputSize, fillLastBlock);
}

int InitBlockCipherState(__inout BlockCipherHandle* handle, __in BlockCipherType cipher, __in CryptoMode cryptoMode, __in BlockCipherOpMode opMode
    , __in PaddingType padding, __inout_opt HardwareFeatures* hwFeatures, __in const void* key, __in_opt const void* iv)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;
    else if ((unsigned)cipher >= BlockCipherType_max)
        return ERROR_UNSUPPORTED_CIPHER_FUNC;
    else if ((unsigned)cryptoMode >= CryptoMode_max)
        return ERROR_UNSUPPROTED_ENCRYPTION_MODE;
    else if ((unsigned)opMode >= BlockCipherOpMode_max)
        return ERROR_UNSUPPROTED_OPERATION_MODE;
    else if ((unsigned)padding >= PaddingType_max)
        return ERROR_UNSUPPORTED_PADDING_TYPE;
    else if (!key)
        return ERROR_NULL_KEY;
    else if (!iv && opMode != ECB_mode)
        return ERROR_NULL_INIT_VECTOR;
    else
        return InitBlockCiperStateInternal((BlockCipherState**)handle, cipher, cryptoMode, opMode, padding, hwFeatures, key, iv);
}

int GetActiveHardwareFeatures(__in BlockCipherHandle handle, __out HardwareFeatures* hwFeatures)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;
    else if (!hwFeatures)
        return ERROR_NULL_HW_FEATURES;

    GetActiveHardwareFeaturesInternal(handle, hwFeatures);

    return NO_ERROR;
}

int ReInitBlockCipherCryptoMode(__inout BlockCipherHandle handle, __in CryptoMode cryptoMode)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;
    else if ((unsigned)cryptoMode >= CryptoMode_max)
        return ERROR_UNSUPPROTED_ENCRYPTION_MODE;
    
    ReInitBlockCipherCryptoModeInternal(handle, cryptoMode);

    return NO_ERROR;
}

int ReInitBlockCipherOpMode(__inout BlockCipherHandle handle, __in BlockCipherOpMode opMode)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;
    else if ((unsigned)opMode >= BlockCipherOpMode_max)
        return ERROR_UNSUPPROTED_OPERATION_MODE;

    ReInitBlockCipherOpModeInternal(handle, opMode);

    return NO_ERROR;
}

int ReInitBlockCipherPaddingType(__inout BlockCipherHandle handle, __in PaddingType padding)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;
    else if ((unsigned)padding >= PaddingType_max)
        return ERROR_UNSUPPORTED_PADDING_TYPE;

    ReInitBlockCipherPaddingTypeInternal(handle, padding);

    return NO_ERROR;
}

int ReInitBlockCipherIv(__inout BlockCipherHandle handle, __in const void* iv)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;
    else if (!iv)
        return ERROR_NULL_INIT_VECTOR;

    ReInitBlockCipherIvInternal(((BlockCipherState*)handle)->cipher, ((BlockCipherState*)handle)->hwFeatures, iv, ((BlockCipherState*)handle)->state);

    return NO_ERROR;
}

int ProcessingByBlockCipher(__inout BlockCipherHandle handle, __in const void* input, __in size_t inputSize, __in bool finalize, __out_opt void* output, __inout size_t* outputSize)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;
    else if (!input)
        return ERROR_NULL_INPUT;
    else if (!inputSize)
        return ERROR_TOO_SMALL_INPUT_SIZE;
    else if (!output && outputSize && *outputSize)
        return ERROR_NULL_OUTPUT;
    else if (!outputSize)
        return ERROR_NULL_OUTPUT_SIZE;
    else if (!finalize && inputSize > *outputSize) {
        *outputSize = inputSize;
        return ERROR_TOO_SMALL_OUTPUT_SIZE;
    }

    return ProcessingByBlockCipherInternal(handle, input, inputSize, finalize, output, outputSize);
}

int FreeBlockCipherState(__inout BlockCipherHandle handle)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;

    FreeBlockCipherStateInternal(handle);

    return NO_ERROR;
}

int InitHashState(__inout HashHandle* handle, __in HashFunc func, __inout_opt HardwareFeatures* hwFeatures)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;
    else if ((unsigned)func >= HashFunc_max)
        return ERROR_UNSUPPORTED_HASHING_FUNC;
    else
        return InitHashStateInternal((HashState**)handle, func);
}

int ResetHashState(__inout HashHandle handle)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;

    ResetHashStateInternal(handle);

    return NO_ERROR;
}

int GetHash(__inout HashHandle handle, __in_opt const void* input, __in size_t inputSize, __in bool finalize, __out_opt void* output)
{
    int status = NO_ERROR;
    if ((status = CheckHashAndXofPrimaryArguments(handle, input, inputSize, finalize, output)))
        return status;
    else if (!finalize && (inputSize % g_hashFuncsSizesMapping[*(HashFunc*)handle].blockSize))
        return ERROR_WRONG_INPUT_SIZE;

    GetHashInternal(handle, input, inputSize, finalize, output);
    return NO_ERROR;
}

int FreeHashState(__inout HashHandle handle)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;

    FreeHashStateInternal(handle);

    return NO_ERROR;
}

int InitXofState(__inout XofHandle* handle, __in Xof func, __inout_opt HardwareFeatures* hwFeatures)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;
    else if ((unsigned)func >= Xof_max)
        return ERROR_UNSUPPORTED_XOF;
    else
        return InitXofStateInternal((XofState**)handle, func);
}

int ResetXofState(__inout XofHandle handle)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;

    ResetXofStateInternal(handle);

    return NO_ERROR;
}

int GetXof(__inout XofHandle handle, __in_opt const void* input, __in size_t inputSize, __in bool finalize, __out_opt void* output, __in size_t outputSize)
{
    int status = NO_ERROR;
    if ((status = CheckHashAndXofPrimaryArguments(handle, input, inputSize, finalize, output)))
        return status;
    else if (finalize && !outputSize)
        return ERROR_NULL_OUTPUT_SIZE;
    else if (!finalize && (inputSize % g_XofSizesMapping[*(Xof*)handle].blockSize))
        return ERROR_WRONG_INPUT_SIZE;

    GetXofInternal(handle, input, inputSize, finalize, output, outputSize);
    return NO_ERROR;
}

int FreeXofState(__inout XofHandle handle)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;

    FreeXofStateInternal(handle);

    return NO_ERROR;
}

int InitPrfState(__inout PrfHandle* handle, __in Prf func, __inout_opt HardwareFeatures* hwFeatures)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;
    else if ((unsigned)func >= Prf_max)
        return ERROR_UNSUPPORTED_PRF_FUNC;
    else
        return InitPrfStateInternal((PrfState**)handle, func);
}

int ResetPrfState(__inout PrfHandle handle)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;

    ResetPrfStateInternal(handle);

    return NO_ERROR;
}

int FreePrfState(__inout PrfHandle handle)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;

    FreePrfStateInternal(handle);

    return NO_ERROR;
}

int GetPrf(__inout PrfHandle handle, __in_opt const void* input, __in size_t inputSize, __in_opt const void* key, __in size_t keySize, __in bool finalize, __out_opt void* output, __in_opt size_t outputSize)
{
    if (!handle)
        return ERROR_NULL_STATE_HANDLE;
    else if (!input && inputSize)
        return ERROR_NULL_INPUT;
    else if (!key && keySize)
        return ERROR_NULL_KEY;
    else if (finalize && !output)
        return ERROR_NULL_OUTPUT;
    else if (!finalize && *(Prf*)handle >= HMAC_SHA1 && *(Prf*)handle <= HMAC_SHA3_512 && inputSize % g_hashFuncsSizesMapping[g_PrfSizesMapping[*(Prf*)handle].hashFunc].blockSize)
        return ERROR_WRONG_INPUT_SIZE;
    
    GetPrfInternal(handle, input, inputSize, key, keySize, finalize, output, outputSize);

    return NO_ERROR;
}

int GetPbkdf2(__in_opt const void* salt, __in size_t saltSize, __in_opt const void* password, __in size_t passwordSize, __in Prf func
    , __in uint64_t iterationsNum, __inout_opt HardwareFeatures* hwFeatures, __out void* output, __in size_t outputSize)
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
        void* saltBuffer = NULL;
        EVAL(AllocBuffer(&saltBuffer, (size_t)saltSize + 4));

        memcpy(saltBuffer, salt, (size_t)saltSize);
        status = GetPbkdf2Internal(saltBuffer, saltSize, password, passwordSize, func, iterationsNum, output, outputSize);
        FreeBuffer(saltBuffer);
    }

exit:
    return status;
}
