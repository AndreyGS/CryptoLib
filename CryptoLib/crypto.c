// crypto.c
//
// Here placed all aggregating functins

#include "pch.h"

#include "crypto_internal.h"
#include "des.h"
#include "paddings.h"

int EncryptByBlockCipher(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* key, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __inout_opt void* iv)
{
    int status = NO_ERROR;
    if (status = CheckBlockCipherPrimaryArguments(input, inputSize, padding, key, cipherType, output, outputSize, mode, iv))
        return status;

    void* roundsKeys = NULL;
    
    if (*outputSize) {
        EVAL(AllocBuffer(g_blockCiphersSizes[cipherType].roundsKeysSize, &roundsKeys));
        GetBlockCipherRoundsKeysInternal(key, cipherType, roundsKeys);
    }

    status = EncryptByBlockCipherInternal(input, inputSize, padding, roundsKeys, cipherType, output, outputSize, mode, iv);

exit:
    if (roundsKeys) {
        memset_s(roundsKeys, g_blockCiphersSizes[cipherType].roundsKeysSize, '\xcc', 128);
        FreeBuffer(roundsKeys);
    }

    return status;
}

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

int DecryptByBlockCipher(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* key, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __inout_opt void* iv)
{
    int status = NO_ERROR;
    if (status = CheckBlockCipherPrimaryArguments(input, inputSize, padding, key, cipherType, output, outputSize, mode, iv))
        return status;

    void* roundsKeys = NULL;
    EVAL(AllocBuffer(g_blockCiphersSizes[cipherType].roundsKeysSize, &roundsKeys));

    GetBlockCipherRoundsKeysInternal(key, cipherType, roundsKeys);

    status = DecryptByBlockCipherInternal(input, inputSize, padding, roundsKeys, cipherType, output, outputSize, mode, iv);

exit:
    if (roundsKeys) {
        memset_s(roundsKeys, g_blockCiphersSizes[cipherType].roundsKeysSize, 0, 128);
        FreeBuffer(roundsKeys);
    }

    return status;
}

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
    else
        return GetBlockCipherRoundsKeysInternal(key, cipherType, output);
}

int GetBlockCipherRoundsKeysInternal(__in const void* key, __in BlockCipherType cipherType, __out void* output)
{
    int status = NO_ERROR;

    switch (cipherType) {
    case DES_cipher_type:
        SingleDesGetRoundsKeys(*(uint64_t*)key, output);
        break;
    case TDES_cipher_type:
        TripleDesGetRoundsKeys(key, output);
        break;
    default:
        status = ERROR_UNSUPPORTED_CIPHER_FUNC;
        break;
    }

    return status;
}

int AddPadding(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock)
{
    int status = NO_ERROR;
    if (status = CheckPaddingInputOutput(input, inputSize, blockSize, output, outputSize))
        return status;
    
    return AddPaddingInternal(input, inputSize, padding, blockSize, output, outputSize, fillAllBlock);
}
/*
int InitBlockCiperState(__inout BlockCipherHandle* handle, __in BlockCipherType cipher, __in CryptoMode cryptoMode, __in BlockCipherOpMode opMode, __in PaddingType padding, __in const void* key, __in_opt void* iv)
{
    int status = NO_ERROR;
    if (!*handle)
        return ERROR_WRONG_STATE_HANDLE;
    else if ((unsigned)cipher >= BlockCipherType_max)
        return ERROR_UNSUPPORTED_CIPHER_FUNC;
    else if ((unsigned)opMode >= BlockCipherOpMode_max)
        return ERROR_UNSUPPROTED_OPERATION_MODE;
    else if ((unsigned)cryptoMode >= Decryption_mode_max)
        return ERROR_UNSUPPROTED_ENCRYPTION_MODE;
    else if ((unsigned)padding >= PaddingType_max)
        return ERROR_UNSUPPORTED_PADDING_TYPE;
    else if (!key)
        return ERROR_WRONG_KEY;
    else if (!iv && opMode != ECB_mode)
        return ERROR_WRONG_INIT_VECTOR;
    
    EVAL(AllocBuffer(g_blockCiphersSizes[cipher].stateAndHeaderSize, handle));

    ((BlockCipherState*)(*handle))->cipher = cipher;
    ((BlockCipherState*)(*handle))->enMode = cryptoMode;
    ((BlockCipherState*)(*handle))->opMode = opMode;
    ((BlockCipherState*)(*handle))->padding = padding;

    ResetHashState(*handle);

exit:
    return status;
}

int ReInitBlockCiperCryptoMode(__inout BlockCipherHandle handle, __in CryptoMode cryptoMode)
{

}

int ReInitBlockCiperOpMode(__inout BlockCipherHandle handle, __in BlockCipherOpMode opMode)
{

}

int ReInitBlockCiperPaddingType(__inout BlockCipherHandle handle, __in PaddingType padding)
{

}

int ReInitBlockCiperIv(__inout BlockCipherHandle handle, __in void* iv)
{

}*/

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

int GetHash(__inout HashHandle handle, __out_opt void* output, __in const void* input, __in uint64_t inputSize, __in bool finalize)
{
    int status = NO_ERROR;
    if (status = CheckHashAndXofPrimaryArguments(handle, output, input, inputSize, finalize))
        return status;

    HashFunc func = *(HashFunc*)handle;
    if (func >= HashFunc_max)
        return ERROR_WRONG_STATE_HANDLE;
    else if (!finalize && (inputSize % g_hashFuncsSizesMapping[func].blockSize))
        return ERROR_WRONG_INPUT_SIZE;

    GetHashInternal(handle, output, input, inputSize, finalize);
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

int GetXof(__inout XofHandle handle, __out_opt void* output, __in uint64_t outputSize, __in const void* input, __in uint64_t inputSize, __in bool finalize)
{
    int status = NO_ERROR;
    if (status = CheckHashAndXofPrimaryArguments(handle, output, input, inputSize, finalize))
        return status;
    else if (!outputSize)
        return ERROR_WRONG_OUTPUT_SIZE;

    HashFunc func = *(HashFunc*)handle;
    if (func >= Xof_max)
        return ERROR_WRONG_STATE_HANDLE;
    else if (!finalize && (inputSize % g_XofSizesMapping[*(Xof*)handle].blockSize))
        return ERROR_WRONG_INPUT_SIZE;

    GetXofInternal(handle, output, outputSize, input, inputSize, finalize);
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

int GetPrf(__inout PrfHandle handle, __out_opt void* output, __in_opt uint64_t outputSize, __in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __in bool finalize)
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

    Prf func = *(Prf*)handle;

    if ((unsigned)func >= Prf_max)
        return ERROR_WRONG_STATE_HANDLE;
    else if (!finalize && (inputSize % g_hashFuncsSizesMapping[g_PrfSizesMapping[func].hashFunc].blockSize))
        return ERROR_WRONG_INPUT_SIZE;
    
    GetPrfInternal(handle, output, outputSize, input, inputSize, key, keySize, finalize);
    return NO_ERROR;
}
