// hmac.c
//

#include "pch.h"
#include "hmac.h"

int GetHmac(__in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __in HashFunc func, __out void* output)
{
    int status = NO_ERROR;

    uint16_t blockSize = g_hashFuncsSizesMapping[func].blockSize;
    uint16_t didgestSize = g_hashFuncsSizesMapping[func].outputSize;

    uint8_t* iKeyPad = AllocBuffer(blockSize);
    uint8_t* oKeyPad = AllocBuffer(blockSize);
    if (!iKeyPad || !oKeyPad)
        EVAL(ERROR_NO_MEMORY);

    if (keySize > blockSize) {
        GetHashInternal(key, keySize, NULL, NULL, func, true, iKeyPad);
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
        { (void*)input,   inputSize, 0 }
    };

    uint64_t prevInputSizeLowPart = 0, prevInputSizeHighPart = 0;

    GetHashInternal(iKeyPad, blockSize, &prevInputSizeLowPart, &prevInputSizeHighPart, func, false, iKeyPad);

    GetHashMultipleInternal(inputNodes, 2, func, iKeyPad);

    inputNodes[0].input = oKeyPad,
    inputNodes[1].input = iKeyPad, inputNodes[1].inputSizeLowPart = didgestSize;

    GetHashMultipleInternal(inputNodes, 2, func, output);

exit:
    FreeBuffer(iKeyPad);
    FreeBuffer(oKeyPad);

    return status;
}

int GetHmacPrf(__in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __in PRF func, __out void* output)
{
    return GetHmac(input, inputSize, key, keySize, g_PrfHashPairMapping[func].hashFunc, output);
}
