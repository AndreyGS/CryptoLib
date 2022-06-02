// crypto.c
//
// Here placed all aggregating functins

#include "pch.h"

#include "crypto_internal.h"
#include "des.h"
#include "paddings.h"
/*
int EncryptByBlockCipher(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* key, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __inout_opt void* iv)
{
    int status = NO_ERROR;
    if (status = CheckBlockCipherPrimaryArguments(input, inputSize, padding, key, cipherType, output, outputSize, mode, iv))
        return status;

    void* roundsKeys = NULL;
    
    if (*outputSize) {
        EVAL(AllocBuffer(g_blockCiphersSizes[cipherType].roundsKeysSize, &roundsKeys));
        GetBlockCipherRoundsKeysInternal(cipherType, key, roundsKeys);
    }

    status = EncryptByBlockCipherInternal(input, inputSize, padding, roundsKeys, cipherType, output, outputSize, mode, iv);

exit:
    if (roundsKeys) {
        memset_s(roundsKeys, g_blockCiphersSizes[cipherType].roundsKeysSize, '\xcc', 128);
        FreeBuffer(roundsKeys);
    }

    return status;
}*/

int EncryptByBlockCipherEx(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* roundsKeys, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __inout_opt void* iv)
{
    int status = NO_ERROR;
    if (status = CheckBlockCipherPrimaryArguments(input, inputSize, padding, roundsKeys, cipherType, output, outputSize, mode, iv))
        return status;

    status = EncryptByBlockCipherInternal(input, inputSize, padding, roundsKeys, cipherType, output, outputSize, mode, iv);

    return status;
}

int EncryptByBlockCipherInternal(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* roundsKeys, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __inout_opt void* iv)
{
    switch (cipherType) {
    case DES_cipher_type:
        return SingleDesEncrypt(input, inputSize, padding, roundsKeys, output, outputSize, mode, iv);
    case TDES_cipher_type:
        return TripleDesEncrypt(input, inputSize, padding, roundsKeys, output, outputSize, mode, iv);
    default:
        return ERROR_UNSUPPORTED_CIPHER_FUNC;
    }
}
/*
int DecryptByBlockCipher(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* key, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __inout_opt void* iv)
{
    int status = NO_ERROR;
    if (status = CheckBlockCipherPrimaryArguments(input, inputSize, padding, key, cipherType, output, outputSize, mode, iv))
        return status;

    void* roundsKeys = NULL;
    EVAL(AllocBuffer(g_blockCiphersSizes[cipherType].roundsKeysSize, &roundsKeys));

    GetBlockCipherRoundsKeysInternal(cipherType, key, roundsKeys);

    status = DecryptByBlockCipherInternal(input, inputSize, padding, roundsKeys, cipherType, output, outputSize, mode, iv);

exit:
    if (roundsKeys) {
        memset_s(roundsKeys, g_blockCiphersSizes[cipherType].roundsKeysSize, 0, 128);
        FreeBuffer(roundsKeys);
    }

    return status;
}*/

int DecryptByBlockCipherEx(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* roundsKeys, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __inout_opt void* iv)
{
    int status = NO_ERROR;
    if (status = CheckBlockCipherPrimaryArguments(input, inputSize, padding, roundsKeys, cipherType, output, outputSize, mode, iv))
        return status;

    status = DecryptByBlockCipherInternal(input, inputSize, padding, roundsKeys, cipherType, output, outputSize, mode, iv);

    return status;
}

int DecryptByBlockCipherInternal(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* roundsKeys, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __inout_opt void* iv)
{
    switch (cipherType) {
    case DES_cipher_type:
        return SingleDesDecrypt(input, inputSize, padding, roundsKeys, output, outputSize, mode, iv);
    case TDES_cipher_type:
        return TripleDesDecrypt(input, inputSize, padding, roundsKeys, output, outputSize, mode, iv);
    default:
        return ERROR_UNSUPPORTED_CIPHER_FUNC;
    }
}

int GetBlockCipherRoundsKeys(__in const void* key, __in BlockCipherType cipherType, __out void* output)
{
    int status = NO_ERROR;
    if (!key)
        return ERROR_WRONG_KEY;
    else if (cipherType >= sizeof(g_blockCiphersSizes) / sizeof(BlockCipherType))
        return ERROR_UNSUPPORTED_CIPHER_FUNC;
    else if (!output)
        return ERROR_WRONG_OUTPUT;
                
    GetBlockCipherRoundsKeysInternal(cipherType, key, output);

    return NO_ERROR;
}

int AddPadding(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock)
{
    int status = NO_ERROR;
    if (status = CheckPaddingInputOutput(input, inputSize, blockSize, output, outputSize))
        return status;
    
    return AddPaddingInternal(input, inputSize, padding, blockSize, output, outputSize, fillAllBlock);
}

int InitBlockCiperState(__inout BlockCipherHandle* handle, __in BlockCipherType cipher, __in CryptoMode cryptoMode, __in BlockCipherOpMode opMode, __in PaddingType padding, __in const void* key, __in_opt void* iv)
{
    if (!*handle)
        return ERROR_WRONG_STATE_HANDLE;
    else if ((unsigned)cipher >= BlockCipherType_max)
        return ERROR_UNSUPPORTED_CIPHER_FUNC;
    else if ((unsigned)opMode >= BlockCipherOpMode_max)
        return ERROR_UNSUPPROTED_OPERATION_MODE;
    else if ((unsigned)cryptoMode >= CryptoMode_mode_max)
        return ERROR_UNSUPPROTED_ENCRYPTION_MODE;
    else if ((unsigned)padding >= PaddingType_max)
        return ERROR_UNSUPPORTED_PADDING_TYPE;
    else if (!key)
        return ERROR_WRONG_KEY;
    else if (!iv && opMode != ECB_mode)
        return ERROR_WRONG_INIT_VECTOR;
    else
        return InitBlockCiperStateInternal(handle, cipher, cryptoMode, opMode, padding, key, iv);
}

int ReInitBlockCiperCryptoMode(__inout BlockCipherHandle handle, __in CryptoMode cryptoMode)
{
    if (!handle)
        return ERROR_WRONG_STATE_HANDLE;
    else if ((unsigned)cryptoMode >= CryptoMode_mode_max)
        return ERROR_UNSUPPROTED_ENCRYPTION_MODE;
    
    ReInitBlockCiperCryptoModeInternal(handle, cryptoMode);

    return NO_ERROR;
}

int ReInitBlockCiperOpMode(__inout BlockCipherHandle handle, __in BlockCipherOpMode opMode)
{
    if (!handle)
        return ERROR_WRONG_STATE_HANDLE;
    else if ((unsigned)opMode >= BlockCipherOpMode_max)
        return ERROR_UNSUPPROTED_ENCRYPTION_MODE;

    ReInitBlockCiperOpModeInternal(handle, opMode);

    return NO_ERROR;
}

int ReInitBlockCiperPaddingType(__inout BlockCipherHandle handle, __in PaddingType padding)
{
    if (!handle)
        return ERROR_WRONG_STATE_HANDLE;
    else if ((unsigned)padding >= PaddingType_max)
        return ERROR_UNSUPPROTED_ENCRYPTION_MODE;

    ReInitBlockCiperPaddingTypeInternal(handle, padding);

    return NO_ERROR;
}

int ReInitBlockCiperIv(__inout BlockCipherHandle handle, __in void* iv)
{
    if (!handle)
        return ERROR_WRONG_STATE_HANDLE;
    else if (!iv)
        return ERROR_WRONG_INIT_VECTOR;

    ReInitBlockCiperIvInternal(handle, iv);

    return NO_ERROR;
}

int ProcessingByBlockCipher(__inout BlockCipherHandle handle, __in const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output, __inout uint64_t* outputSize)
{
    if (!handle)
        return ERROR_WRONG_STATE_HANDLE;
    else if (!input)
        return ERROR_WRONG_INPUT;
    else if (!inputSize)
        return ERROR_WRONG_INPUT_SIZE;
    else if (!output && outputSize && *outputSize)
        return ERROR_WRONG_OUTPUT;
    else if (!outputSize)
        return ERROR_WRONG_OUTPUT_SIZE;

    return ProcessingByBlockCipherInternal(handle, input, inputSize, finalize, output, outputSize);
}

int InitHashState(__inout HashHandle* handle, __in HashFunc func)
{
    if (!handle)
        return ERROR_WRONG_STATE_HANDLE;
    else if ((unsigned)func >= HashFunc_max)
        return ERROR_UNSUPPORTED_HASHING_FUNC;
    else
        return InitHashStateInternal(handle, func);
}

int ResetHashState(__inout HashHandle handle)
{
    if (!handle || (unsigned)*(HashFunc*)handle >= HashFunc_max)
        return ERROR_WRONG_STATE_HANDLE;

    ResetHashStateInternal(handle);

    return NO_ERROR;
}

int GetHash(__inout HashHandle handle, __in const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output)
{
    int status = NO_ERROR;
    if (status = CheckHashAndXofPrimaryArguments(handle, input, inputSize, finalize, output))
        return status;

    if (!finalize && (inputSize % g_hashFuncsSizesMapping[*(HashFunc*)handle].blockSize))
        return ERROR_WRONG_INPUT_SIZE;

    GetHashInternal(handle, input, inputSize, finalize, output);
    return NO_ERROR;
}

int FreeHashState(__inout HashHandle handle)
{
    if (!handle || (unsigned)*(HashFunc*)handle >= HashFunc_max)
        return ERROR_WRONG_STATE_HANDLE;

    FreeHashStateInternal(handle);

    return NO_ERROR;
}

int InitXofState(__inout XofHandle* handle, __in Xof func)
{
    if (!handle)
        return ERROR_WRONG_STATE_HANDLE;
    else if ((unsigned)func >= Xof_max)
        return ERROR_UNSUPPORTED_XOF;
    else
        return InitXofStateInternal(handle, func);
}

int ResetXofState(__inout XofHandle handle)
{
    if (!handle || (unsigned)*(HashFunc*)handle >= HashFunc_max)
        return ERROR_WRONG_STATE_HANDLE;

    ResetXofStateInternal(handle);

    return NO_ERROR;
}

int GetXof(__inout XofHandle handle, __in const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output, __in uint64_t outputSize)
{
    int status = NO_ERROR;
    if (status = CheckHashAndXofPrimaryArguments(handle, input, inputSize, finalize, output))
        return status;
    else if (!outputSize)
        return ERROR_WRONG_OUTPUT_SIZE;

    if (!finalize && (inputSize % g_XofSizesMapping[*(Xof*)handle].blockSize))
        return ERROR_WRONG_INPUT_SIZE;

    GetXofInternal(handle, input, inputSize, finalize, output, outputSize);
    return NO_ERROR;
}

int FreeXofState(__inout XofHandle handle)
{
    if (!handle || (unsigned)*(HashFunc*)handle >= HashFunc_max)
        return ERROR_WRONG_STATE_HANDLE;

    FreeXofStateInternal(handle);

    return NO_ERROR;
}

int InitPrfState(__inout PrfHandle* handle, __in Prf func)
{
    if (!handle)
        return ERROR_WRONG_STATE_HANDLE;
    else if ((unsigned)func >= Prf_max)
        return ERROR_UNSUPPORTED_HASHING_FUNC;
    else
        return InitPrfStateInternal(handle, func);
}

int ResetPrfState(__inout PrfHandle handle)
{
    if (!handle || (unsigned)*(HashFunc*)handle >= HashFunc_max)
        return ERROR_WRONG_STATE_HANDLE;

    ResetPrfStateInternal(handle);

    return NO_ERROR;
}

int FreePrfState(__inout PrfHandle handle)
{
    if (!handle || (unsigned)*(HashFunc*)handle >= HashFunc_max)
        return ERROR_WRONG_STATE_HANDLE;

    FreePrfStateInternal(handle);

    return NO_ERROR;
}

int GetPrf(__inout PrfHandle handle, __in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __in bool finalize, __out_opt void* output, __in_opt uint64_t outputSize)
{
    int status = NO_ERROR;
    if (!handle)
        return ERROR_WRONG_STATE_HANDLE;
    else if (finalize && !output)
        return ERROR_WRONG_OUTPUT;
    else if (!input && inputSize)
        return ERROR_WRONG_INPUT;
    else if (!key && keySize)
        return ERROR_WRONG_KEY;

    if (!finalize && (inputSize % g_hashFuncsSizesMapping[g_PrfSizesMapping[*(Prf*)handle].hashFunc].blockSize))
        return ERROR_WRONG_INPUT_SIZE;
    
    GetPrfInternal(handle, input, inputSize, key, keySize, finalize, output, outputSize);

    return NO_ERROR;
}
