#include "pch.h"

#include "crypto_internal.h"

int HmacGet(__in void* input, __in uint64_t inputSize, __in void* key, __in uint64_t keySize, __in HashFunc func, __out void* output, __out uint64_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckInputOutput(input, inputSize, output, outputSize))
        return status;
    else if (status = CheckInput(key, keySize))
        return status;
    return 0; /*
    if (keySize > g_hashFuncsSizesMappings[func].blockSize) {
        if (func == SHA1)
            Sha1GetInternal(key, keySize)

    }*/

}
