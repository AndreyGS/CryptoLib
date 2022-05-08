// hmac.c
//

#include "pch.h"
#include "hmac.h"

void GetHmac(__in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __in HashFunc func, __out void* output, __in bool isStart,__in bool finalize, __inout HashState state)
{
    int status = NO_ERROR;
    
    uint16_t blockSize = g_hashFuncsSizesMapping[func].blockSize;
    uint16_t didgestSize = g_hashFuncsSizesMapping[func].outputSize;
    uint8_t* iKeyPad = (uint8_t*)state + g_hashFuncsSizesMapping[func].fullStateSize;
    uint8_t* oKeyPad = iKeyPad + blockSize;

    if (isStart) {
        if (keySize > blockSize) {
            GetHashInternal(key, keySize, iKeyPad, true, state);
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

        GetHashInternal(iKeyPad, blockSize, output, false, state);
    }
    
    GetHashInternal(input, inputSize, iKeyPad, finalize, state);

    if (finalize) {
        GetHashInternal(oKeyPad, blockSize, output, false, state);
        GetHashInternal(iKeyPad, didgestSize, output, true, state);
    }
}
