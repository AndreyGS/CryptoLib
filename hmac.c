// hmac.c
//

#include "pch.h"
#include "crypto_internal.h"
#include "hmac.h"

int GetHmac(__in void* input, __in uint64_t inputSize, __in void* key, __in uint64_t keySize, __in HashFunc func, __out void* output, __out_opt uint16_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckInput(input, inputSize))
        return status;
    else if (status = CheckInput(key, keySize))
        return status;
    else if (!output)
        return ERROR_WRONG_OUTPUT;
    else
        return GetHmacInternal(input, inputSize, key, keySize, func, output, outputSize);
}

int GetHmacInternal(__in void* input, __in uint64_t inputSize, __in void* key, __in uint64_t keySize, __in HashFunc func, __out void* output, __out_opt uint16_t* outputSize)
{
    uint64_t iKeyPad[18] = { 0 };
    uint16_t blockSize = g_hashFuncsSizesMappings[func].blockSize;

    if (keySize > blockSize) {
        const HashInputNode inputNode = { key, keySize, 0 };
        GetHashMultipleInternal(&inputNode, 1, func, iKeyPad);
    }
    else
        memcpy(iKeyPad, key, (size_t)keySize);

    uint64_t oKeyPad[18] = { 0 };
    memcpy(oKeyPad, iKeyPad, blockSize);

    uint8_t* p = (uint8_t*)iKeyPad;
    for (uint8_t i = 0; i < blockSize; ++i)
        *p++ ^= '\x36';

    p = (uint8_t*)oKeyPad;
    for (uint8_t i = 0; i < blockSize; ++i)
        *p++ ^= '\x5c';

    uint16_t didgestSize = g_hashFuncsSizesMappings[func].outputSize;

    HashInputNode inputNodes[2] = { { iKeyPad, blockSize, 0 }, { input, inputSize, 0 } };

    GetHashMultipleInternal(inputNodes, 2, func, iKeyPad);

    inputNodes[0].input = oKeyPad, inputNodes[1].input = iKeyPad, inputNodes[1].inputSizeLowPart = didgestSize;

    GetHashMultipleInternal(inputNodes, 2, func, output);

    if (outputSize)
        *outputSize = didgestSize;

    return NO_ERROR;
}

int GetHmacPrf(__in void* input, __in uint64_t inputSize, __in void* key, __in uint64_t keySize, __in PRF func, __out void* output, __out_opt uint16_t* outputSize)
{
    switch (func) {
    case HMAC_Sha1:
        return GetHmac(input, inputSize, key, keySize, SHA1, output, outputSize);
    case HMAC_SHA_224:
        return GetHmac(input, inputSize, key, keySize, SHA_224, output, outputSize);
    case HMAC_SHA_256:
        return GetHmac(input, inputSize, key, keySize, SHA_256, output, outputSize);
    case HMAC_SHA_384:
        return GetHmac(input, inputSize, key, keySize, SHA_384, output, outputSize);
    case HMAC_SHA_512_224:
        return GetHmac(input, inputSize, key, keySize, SHA_512_224, output, outputSize);
    case HMAC_SHA_512_256:
        return GetHmac(input, inputSize, key, keySize, SHA_512_256, output, outputSize);
    case HMAC_SHA_512:
        return GetHmac(input, inputSize, key, keySize, SHA_512, output, outputSize);
    default:
        return ERROR_HASHING_FUNC_NOT_SUPPORTED;
    }
}

int GetHmacPrfInternal(__in void* input, __in uint64_t inputSize, __in void* key, __in uint64_t keySize, __in PRF func, __out void* output, __out_opt uint16_t* outputSize)
{
    switch (func) {
    case HMAC_Sha1:
        return GetHmacInternal(input, inputSize, key, keySize, SHA1, output, outputSize);
    case HMAC_SHA_224:
        return GetHmacInternal(input, inputSize, key, keySize, SHA_224, output, outputSize);
    case HMAC_SHA_256:
        return GetHmacInternal(input, inputSize, key, keySize, SHA_256, output, outputSize);
    case HMAC_SHA_384:
        return GetHmacInternal(input, inputSize, key, keySize, SHA_384, output, outputSize);
    case HMAC_SHA_512_224:
        return GetHmacInternal(input, inputSize, key, keySize, SHA_512_224, output, outputSize);
    case HMAC_SHA_512_256:
        return GetHmacInternal(input, inputSize, key, keySize, SHA_512_256, output, outputSize);
    case HMAC_SHA_512:
        return GetHmacInternal(input, inputSize, key, keySize, SHA_512, output, outputSize);
    default:
        return ERROR_HASHING_FUNC_NOT_SUPPORTED;
    }
}
