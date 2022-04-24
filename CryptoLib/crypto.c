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

int GetHashMultipleInternal(__in const VoidAndSizeNode* inputList, __in uint64_t inputListSize, __in HashFunc func, __out void* output);
int GetXofMultipleInternal(__in const VoidAndSizeNode* inputList, __in uint64_t inputListSize, __in Xof func, __out void* output, __in uint64_t outputSize);

int EncryptByBlockCipher(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __in_opt const void* iv)
{
    int status = NO_ERROR;
    if (status = CheckBlockCipherPrimaryArguments(input, inputSize, key, output, outputSize, mode, iv))
        return status;

    switch (cipherType) {
    case DES_cipher_type:
        return DesEncrypt(input, inputSize, padding, key, output, outputSize, mode, iv);
    default:
        return ERROR_CIPHER_FUNC_NOT_SUPPORTED;
    }
}

int DecryptByBlockCipher(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __in_opt const void* iv)
{
    int status = NO_ERROR;
    if (status = CheckBlockCipherPrimaryArguments(input, inputSize, key, output, outputSize, mode, iv))
        return status;

    switch (cipherType) {
    case DES_cipher_type:
        return DesDecrypt(input, inputSize, padding, key, output, outputSize, mode, iv);
    default:
        return ERROR_CIPHER_FUNC_NOT_SUPPORTED;
    }
}

int AddPadding(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock)
{
    int status = NO_ERROR;
    if (status = CheckPaddingInputOutput(input, inputSize, blockSize, output, outputSize))
        return status;
    
    return AddPaddingInternal(input, inputSize, padding, blockSize, output, outputSize, fillAllBlock);
}

int GetHash(__in const void* input, __in uint64_t inputSize, __in HashFunc func, __out void* output)
{
    return GetHashEx(input, inputSize, 0, func, output);
}

int GetHashEx(__in const void* input, __in uint64_t inputSizeLowPart, __in uint64_t inputSizeHighPart, __in HashFunc func, __out void* output)
{
    const VoidAndSizeNode inputList = { (void*)input, inputSizeLowPart, inputSizeHighPart };
    return GetHashMultiple(&inputList, 1, func, output);
}

int GetHashMultiple(__in const VoidAndSizeNode* inputList, __in uint64_t inputListSize, __in HashFunc func, __out void* output)
{
    int status = NO_ERROR;
    if (status = CheckInput(inputList, inputListSize))
        return status;
    else
        for (uint64_t i = 0; i < inputListSize; ++i)
            if (status = CheckInput(inputList[i].input, inputList[i].inputSizeLowPart ? inputList[i].inputSizeLowPart : inputList[i].inputSizeHighPart))
                return status;

    if (!output)
        return ERROR_WRONG_OUTPUT;
    else
        return GetHashMultipleInternal(inputList, inputListSize, func, output);
}

int GetHashMultipleInternal(__in const VoidAndSizeNode* inputList, __in uint64_t inputListSize, __in HashFunc func, __out void* output)
{
    switch (func) {
    case SHA1:
        Sha1Get(inputList, inputListSize, output);
        break;
    case SHA_224:
    case SHA_256:
        Sha2_32Get(inputList, inputListSize, func, output);
        break;
    case SHA_384:
    case SHA_512_224:
    case SHA_512_256:
    case SHA_512:
        Sha2_64Get(inputList, inputListSize, func, output);
        break;
    case SHA3_224:
    case SHA3_256:
    case SHA3_384:
    case SHA3_512:
        Sha3GetHash(inputList, inputListSize, func, output);
        break;
    default:
        return ERROR_HASHING_FUNC_NOT_SUPPORTED;
    }

    return NO_ERROR;
}

int GetXof(__in const void* input, __in uint64_t inputSize, __in Xof func, __out void* output, __in uint64_t outputSize)
{
    const VoidAndSizeNode inputList = { (void*)input, inputSize, 0 };
    return GetXofMultiple(&inputList, 1, func, output, outputSize);
}

int GetXofMultiple(__in const VoidAndSizeNode* inputList, __in uint64_t inputListSize, __in Xof func, __out void* output, __in uint64_t outputSize)
{
    int status = NO_ERROR;
    if (status = CheckInputOutput(inputList, inputListSize, output, &outputSize))
        return status;
    else
        for (uint64_t i = 0; i < inputListSize; ++i)
            if (status = CheckInput(inputList[i].input, inputList[i].inputSizeLowPart ? inputList[i].inputSizeLowPart : inputList[i].inputSizeHighPart))
                return status;

   return GetXofMultipleInternal(inputList, inputListSize, func, output, outputSize);
}

int GetXofMultipleInternal(__in const VoidAndSizeNode* inputList, __in uint64_t inputListSize, __in Xof func, __out void* output, __in uint64_t outputSize)
{
    Sha3GetXof(inputList, inputListSize, func, output, outputSize);
    return NO_ERROR;
}

int GetPrf(__in void* input, __in uint64_t inputSize, __in void* key, __in uint64_t keySize, __in PRF func, __out void* output, __in_opt uint16_t outputSize)
{
    int status = NO_ERROR;
    if (status = CheckInput(input, inputSize))
        return status;
    else if (status = CheckInput(key, keySize))
        return status;
    else if (!output)
        return ERROR_WRONG_OUTPUT;

    switch (func) {
    case HMAC_Sha1:
    case HMAC_SHA_224:
    case HMAC_SHA_256:
    case HMAC_SHA_384:
    case HMAC_SHA_512_224:
    case HMAC_SHA_512_256:
    case HMAC_SHA_512:
        return GetHmacPrf(input, inputSize, key, keySize, func, output);
    default:
        return ERROR_HASHING_FUNC_NOT_SUPPORTED;
    }
}
