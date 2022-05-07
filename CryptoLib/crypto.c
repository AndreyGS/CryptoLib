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
        roundsKeys = AllocBuffer(g_blockCipherKeysSizes[cipherType].roundsKeysSize);
        if (!roundsKeys)
            return ERROR_NO_MEMORY;
        else
            GetBlockCipherRoundsKeysInternal(key, cipherType, roundsKeys);
    }

    status = EncryptByBlockCipherInternal(input, inputSize, padding, roundsKeys, cipherType, output, outputSize, mode, iv);

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

    void* roundsKeys = AllocBuffer(g_blockCipherKeysSizes[cipherType].roundsKeysSize);
    if (!roundsKeys)
        return ERROR_NO_MEMORY;
    else
        GetBlockCipherRoundsKeysInternal(key, cipherType, roundsKeys);

    status = DecryptByBlockCipherInternal(input, inputSize, padding, roundsKeys, cipherType, output, outputSize, mode, iv);

    memset_s(roundsKeys, g_blockCipherKeysSizes[cipherType].roundsKeysSize, '\xcc', 128);
    FreeBuffer(roundsKeys);

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

int GetHash(__in const void* input, __in uint64_t inputSize, __in HashFunc func, __out void* output, __in StageType stageType, __inout_opt void* state)
{
    int status = NO_ERROR;
    if (func >= HashFunc_max)
        return ERROR_HASHING_FUNC_NOT_SUPPORTED;
    else if (status = CheckHashAndXofPrimaryArguments(input, inputSize, func, output, stageType, state))
        return status;

    GetHashInternal(input, inputSize, func, output, stageType, state);
    return NO_ERROR;
}

void GetHashInternal(__in const void* input, __in uint64_t inputSize, __in HashFunc func, __out void* output, __in StageType stageType, __inout_opt void* state)
{
    switch (func) {
    case SHA1:
        Sha1Get(input, inputSize, output, stageType, state);
        break;
    case SHA_224:
    case SHA_256:
        Sha2_32Get(input, inputSize, func, output, stageType, state);
        break;
    case SHA_384:
    case SHA_512_224:
    case SHA_512_256:
    case SHA_512:
        Sha2_64Get(input, inputSize, func, output, stageType, state);
        break;
    case SHA3_224:
    case SHA3_256:
    case SHA3_384:
    case SHA3_512:
        Sha3GetHash(input, inputSize, func, output, stageType, state);
        break;
    default:
        break;
    }
}

int GetXof(__in const void* input, __in uint64_t inputSize, __in Xof func, __out void* output, __in StageType stageType, __in uint64_t outputSize, __inout_opt void* state)
{
    int status = NO_ERROR;
    if (func >= Xof_max)
        return ERROR_XOF_NOT_SUPPORTED;
    else if (status = CheckHashAndXofPrimaryArguments(input, inputSize, func, output, stageType, state))
        return status;

    GetXofInternal(input, inputSize, func, output, stageType, outputSize, state);
    return NO_ERROR;
}

void GetXofInternal(__in const void* input, __in uint64_t inputSize, __in Xof func, __out void* output, __in StageType stageType, __in uint64_t outputSize, __inout_opt void* state)
{
    switch (func) {
    case SHAKE128:
    case SHAKE256:
        Sha3GetXof(input, inputSize, func, output, stageType, outputSize, state);
        break;
    default:
        break;
    }
}

int GetPrf(__in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __in PRF func, __out void* output, __in_opt uint64_t outputSize)
{
    int status = NO_ERROR;
    if (!input && inputSize)
        return ERROR_WRONG_INPUT;
    else if (!key && keySize)
        return ERROR_WRONG_KEY;
    else if (!output)
        return ERROR_WRONG_OUTPUT;

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
    case HMAC_SHA3_512:
        return GetHmacPrf(input, inputSize, key, keySize, func, output);
    default:
        return ERROR_PRF_FUNC_NOT_SUPPORTED;
    }
}
