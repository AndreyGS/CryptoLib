#include "pch.h"
#include "crypto_internal.h"
#include "des.h"
#include "paddings.h"
#include "sha-1.h"
#include "sha-2.h"

int EncryptByBlockCipher(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __in const void* iv)
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

int DecryptFromBlockCipher(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __in const void* iv)
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
    int status = NO_ERROR;
    if (status = CheckInput(input, inputSizeLowPart ? inputSizeLowPart : inputSizeHighPart))
        return status;
    else if (!output)
        return ERROR_WRONG_OUTPUT;

    switch (func) {
    case SHA1:
        Sha1Get(input, inputSizeLowPart, output);
        break;
    case SHA_224:
    case SHA_256:
        Sha2_32Get(input, inputSizeLowPart, func, output);
        break;
    case SHA_384:
    case SHA_512_224:
    case SHA_512_256:
    case SHA_512:
        Sha2_64Get(input, inputSizeLowPart, inputSizeHighPart, func, output);
        break;
    default:
        return ERROR_HASHING_FUNC_NOT_SUPPORTED;
    }

    return NO_ERROR;
}
