// hmac.c
//

#include "pch.h"
#include "hmac.h"

int GetHmac(__in void* input, __in uint64_t inputSize, __in void* key, __in uint64_t keySize, __in HashFunc func, __out void* output)
{
    int status = NO_ERROR;

    uint16_t blockSize = g_hashFuncsSizesMappings[func].blockSize;
    uint16_t didgestSize = g_hashFuncsSizesMappings[func].outputSize;

    uint8_t* iKeyPad = AllocBuffer(blockSize);
    uint8_t* oKeyPad = AllocBuffer(blockSize);
    if (!iKeyPad || !oKeyPad) {
        status = ERROR_NO_MEMORY;
        goto exit;
    }

    if (keySize > blockSize) {
        const VoidAndSizeNode inputNode = { key, keySize, 0 };
        GetHashMultipleInternal(&inputNode, 1, func, iKeyPad);
        keySize = didgestSize;
    }
    else
        memcpy(iKeyPad, key, (size_t)keySize);

    memset(iKeyPad + keySize, 0, blockSize - (uint16_t)keySize);
    memcpy(oKeyPad, iKeyPad, blockSize);

    uint8_t* p = (uint8_t*)iKeyPad;
    for (uint8_t i = 0; i < blockSize; ++i)
        *p++ ^= '\x36';

    p = (uint8_t*)oKeyPad;
    for (uint8_t i = 0; i < blockSize; ++i)
        *p++ ^= '\x5c';

    VoidAndSizeNode inputNodes[2] = 
    { 
        { iKeyPad, blockSize, 0 }, 
        { input,   inputSize, 0 } 
    };

    GetHashMultipleInternal(inputNodes, 2, func, iKeyPad);

    inputNodes[0].input = oKeyPad,
    inputNodes[1].input = iKeyPad, inputNodes[1].inputSizeLowPart = didgestSize;

    GetHashMultipleInternal(inputNodes, 2, func, output);

exit:
    FreeBuffer(iKeyPad);
    FreeBuffer(oKeyPad);

    return status;
}

int GetHmacPrf(__in void* input, __in uint64_t inputSize, __in void* key, __in uint64_t keySize, __in PRF func, __out void* output)
{
    switch (func) {
    case HMAC_Sha1:
        return GetHmac(input, inputSize, key, keySize, SHA1, output);
    case HMAC_SHA_224:
        return GetHmac(input, inputSize, key, keySize, SHA_224, output);
    case HMAC_SHA_256:
        return GetHmac(input, inputSize, key, keySize, SHA_256, output);
    case HMAC_SHA_384:
        return GetHmac(input, inputSize, key, keySize, SHA_384, output);
    case HMAC_SHA_512_224:
        return GetHmac(input, inputSize, key, keySize, SHA_512_224, output);
    case HMAC_SHA_512_256:
        return GetHmac(input, inputSize, key, keySize, SHA_512_256, output);
    case HMAC_SHA_512:
        return GetHmac(input, inputSize, key, keySize, SHA_512, output);
    default:
        return ERROR_HASHING_FUNC_NOT_SUPPORTED;
    }
}
