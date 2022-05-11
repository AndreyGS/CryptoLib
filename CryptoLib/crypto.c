// crypto.c
//
// Here placed all aggregating functins

#include "pch.h"
#include "des.h"
#include "paddings.h"
#include "sha-1.h"
#include "sha-2.h"
#include "sha-3.h"
#include "hmac.h"

int EncryptByBlockCipher(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* key, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __inout_opt void* iv)
{
    int status = NO_ERROR;
    if (status = CheckBlockCipherPrimaryArguments(input, inputSize, padding, key, cipherType, output, outputSize, mode, iv))
        return status;

    void* roundsKeys = NULL;
    
    if (*outputSize) {
        EVAL(AllocBuffer(g_blockCipherKeysSizes[cipherType].roundsKeysSize, &roundsKeys));
        GetBlockCipherRoundsKeysInternal(key, cipherType, roundsKeys);
    }

    status = EncryptByBlockCipherInternal(input, inputSize, padding, roundsKeys, cipherType, output, outputSize, mode, iv);

exit:
    if (roundsKeys) {
        memset_s(roundsKeys, g_blockCipherKeysSizes[cipherType].roundsKeysSize, '\xcc', 128);
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
        return ERROR_CIPHER_FUNC_NOT_SUPPORTED;
    }
}

int DecryptByBlockCipher(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* key, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __inout_opt void* iv)
{
    int status = NO_ERROR;
    if (status = CheckBlockCipherPrimaryArguments(input, inputSize, padding, key, cipherType, output, outputSize, mode, iv))
        return status;

    void* roundsKeys = NULL;
    EVAL(AllocBuffer(g_blockCipherKeysSizes[cipherType].roundsKeysSize, &roundsKeys));

    GetBlockCipherRoundsKeysInternal(key, cipherType, roundsKeys);

    status = DecryptByBlockCipherInternal(input, inputSize, padding, roundsKeys, cipherType, output, outputSize, mode, iv);

exit:
    if (roundsKeys) {
        memset_s(roundsKeys, g_blockCipherKeysSizes[cipherType].roundsKeysSize, 0, 128);
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
        return ERROR_CIPHER_FUNC_NOT_SUPPORTED;
    }
}

int GetBlockCipherRoundsKeys(__in const void* key, __in BlockCipherType cipherType, __out void* output)
{
    int status = NO_ERROR;
    if (!key)
        return ERROR_WRONG_KEY;
    else if (cipherType >= sizeof(g_blockCipherKeysSizes) / sizeof(BlockCipherType))
        return ERROR_CIPHER_FUNC_NOT_SUPPORTED;
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
        status = ERROR_CIPHER_FUNC_NOT_SUPPORTED;
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

int InitHashState(__in HashFunc func, __inout StateHandle* state)
{
    int status = NO_ERROR;
    if ((unsigned)func >= HashFunc_max)
        return ERROR_HASHING_FUNC_NOT_SUPPORTED;
    else if (!state)
        return ERROR_WRONG_STATE_HANDLE;

    EVAL(AllocBuffer(g_hashFuncsSizesMapping[func].stateAndHeaderSize, state));
    *(HashFunc*)(*state) = func;
    ResetHashState(*state);

exit:
    return status;
}

int ResetHashState(__inout StateHandle state)
{
    if (state) {
        HashFunc func = *(HashFunc*)state;

        if ((unsigned)func >= HashFunc_max)
            return ERROR_WRONG_STATE_HANDLE;
        
        memset(((HashState*)state)->state, 0, g_hashFuncsSizesMapping[func].stateSize);

        return NO_ERROR;
    }
    else
        return ERROR_WRONG_STATE_HANDLE;
}

int FreeHashState(__inout StateHandle state)
{
    if (state) {
        HashFunc func = *(HashFunc*)state;

        if ((unsigned)func >= HashFunc_max)
            return ERROR_WRONG_STATE_HANDLE;

        memset_s(state, g_hashFuncsSizesMapping[func].stateAndHeaderSize, 0, g_hashFuncsSizesMapping[func].stateAndHeaderSize);

        FreeBuffer(state);

        return NO_ERROR;
    }
    else
        return ERROR_WRONG_STATE_HANDLE;
}

int GetHash(__in const void* input, __in uint64_t inputSize, __out void* output, __in bool finalize, __inout StateHandle state)
{
    int status = NO_ERROR;
    if (status = CheckHashAndXofPrimaryArguments(input, inputSize, output, state))
        return status;

    HashFunc func = *(HashFunc*)state;
    if (func >= HashFunc_max)
        return ERROR_WRONG_STATE_HANDLE;
    else if (!finalize && (inputSize % g_hashFuncsSizesMapping[func].blockSize))
        return ERROR_WRONG_INPUT_SIZE;

    GetHashInternal(input, inputSize, output, finalize, state);
    return NO_ERROR;
}

void GetHashInternal(__in const void* input, __in uint64_t inputSize, __out void* output, __in bool finalize, __inout HashState* state)
{
    HashFunc func = state->func;

    switch (func) {
    case SHA1:
        Sha1Get(input, inputSize, output, finalize, (Sha1State*)state->state);
        break;
    case SHA_224:
    case SHA_256:
        Sha2_32Get(input, inputSize, func, output, finalize, (Sha2_32State*)state->state);
        break;
    case SHA_384:
    case SHA_512_224:
    case SHA_512_256:
    case SHA_512:
        Sha2_64Get(input, inputSize, func, output, finalize, (Sha2_64State*)state->state);
        break;
    case SHA3_224:
    case SHA3_256:
    case SHA3_384:
    case SHA3_512:
        Sha3GetHash(input, inputSize, func, output, finalize, state->state);
        break;
    default:
        break;
    }

    if (finalize)
        ResetHashState(state);
}

int InitXofState(__in Xof func, __inout StateHandle* state)
{
    int status = NO_ERROR;
    if ((unsigned)func >= Xof_max)
        return ERROR_XOF_NOT_SUPPORTED;
    else if (!state)
        return ERROR_WRONG_STATE_HANDLE;

    EVAL(AllocBuffer(g_XofSizesMapping[func].stateAndHeaderSize, state));
    *(Xof*)(*state) = func;
    ResetHashState(*state);

exit:
    return status;
}

int ResetXofState(__inout StateHandle state)
{
    if (state) {
        Xof func = *(Xof*)state;

        if ((unsigned)func >= Xof_max)
            return ERROR_WRONG_STATE_HANDLE;

        memset(((XofState*)state)->state, 0, g_XofSizesMapping[func].stateSize);

        return NO_ERROR;
    }
    else
        return ERROR_WRONG_STATE_HANDLE;
}

int FreeXofState(__inout StateHandle state)
{
    if (state) {
        Xof func = *(Xof*)state;

        if ((unsigned)func >= Xof_max)
            return ERROR_WRONG_STATE_HANDLE;

        memset_s(state, g_XofSizesMapping[func].stateAndHeaderSize, 0, g_XofSizesMapping[func].stateAndHeaderSize);

        FreeBuffer(state);

        return NO_ERROR;
    }
    else
        return ERROR_WRONG_STATE_HANDLE;
}

int GetXof(__in const void* input, __in uint64_t inputSize, __out void* output, __in uint64_t outputSize, __in bool finalize, __inout StateHandle state)
{
    int status = NO_ERROR;
    if (status = CheckHashAndXofPrimaryArguments(input, inputSize, output, state))
        return status;
    else if (!outputSize)
        return ERROR_WRONG_OUTPUT_SIZE;

    HashFunc func = *(HashFunc*)state;
    if (func >= Xof_max)
        return ERROR_WRONG_STATE_HANDLE;
    else if (!finalize && (inputSize % g_XofSizesMapping[*(Xof*)state].blockSize))
        return ERROR_WRONG_INPUT_SIZE;
    
    GetXofInternal(input, inputSize, output, outputSize, finalize, state);
    return NO_ERROR;
}

void GetXofInternal(__in const void* input, __in uint64_t inputSize, __out void* output, __in uint64_t outputSize, __in bool finalize, __inout XofState* state)
{
    Xof func = state->func;

    switch (func) {
    case SHAKE128:
    case SHAKE256:
        Sha3GetXof(input, inputSize, func, output, outputSize, finalize, state->state);
        break;
    default:
        break;
    }

    if (finalize)
        ResetXofState(state);
}

int InitPrfState(__in Prf func, __inout StateHandle* state)
{
    int status = NO_ERROR;
    if ((unsigned)func >= Prf_max)
        return ERROR_HASHING_FUNC_NOT_SUPPORTED;
    else if (!state)
        return ERROR_WRONG_STATE_HANDLE;

    EVAL(AllocBuffer(g_PrfSizesMapping[func].stateAndHeaderSize, state));
    *(Prf*)(*state) = func;
    ResetHashState(*state);

exit:
    return status;
}

int ResetPrfState(__inout StateHandle state)
{
    if (state) {
        Prf func = *(Prf*)state;

        if ((unsigned)func >= Prf_max)
            return ERROR_WRONG_STATE_HANDLE;

        memset(((PrfState*)state)->state, 0, g_PrfSizesMapping[func].stateSize);

        return NO_ERROR;
    }
    else
        return ERROR_WRONG_STATE_HANDLE;
}

int FreePrfState(__inout StateHandle state)
{
    if (state) {
        Prf func = *(Prf*)state;

        if ((unsigned)func >= Prf_max)
            return ERROR_WRONG_STATE_HANDLE;

        memset_s(state, g_PrfSizesMapping[func].stateAndHeaderSize, 0, g_PrfSizesMapping[func].stateAndHeaderSize);

        FreeBuffer(state);

        return NO_ERROR;
    }
    else
        return ERROR_WRONG_STATE_HANDLE;
}

int GetPrf(__in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __out void* output, __in_opt uint64_t outputSize, __in bool finalize, __inout StateHandle state)
{
    int status = NO_ERROR;
    if (!input && inputSize)
        return ERROR_WRONG_INPUT;
    else if (!key && keySize)
        return ERROR_WRONG_KEY;
    else if (!output)
        return ERROR_WRONG_OUTPUT;

    Prf func = *(Prf*)state;

    if ((unsigned)func >= Prf_max)
        return ERROR_WRONG_STATE_HANDLE;
    else if (!finalize && (inputSize % g_hashFuncsSizesMapping[g_PrfSizesMapping[func].hashFunc].blockSize))
        return ERROR_WRONG_INPUT_SIZE;
    
    GetPrfInternal(input, inputSize, key, keySize, output, finalize, state);
    return NO_ERROR;
}

void GetPrfInternal(__in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __out void* output, __in bool finalize, __inout PrfState* state)
{
    Prf func = state->func;

    switch (func) {
    case HMAC_SHA1:
    case HMAC_SHA_224:
    case HMAC_SHA_256:
    case HMAC_SHA_384:
    case HMAC_SHA_512_224:
    case HMAC_SHA_512_256:
    case HMAC_SHA_512:
    case HMAC_SHA3_224:
    case HMAC_SHA3_256:
    case HMAC_SHA3_384:
    case HMAC_SHA3_512: {
        GetHmac(input, inputSize, key, keySize, func, output, finalize, state->state);
        break;
    }
    default:
        break;
    }

    if (finalize)
        ResetPrfState(state);
}
