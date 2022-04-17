// kdf.c
//

#include "pch.h"
#include "crypto_internal.h"
#include "hmac.h"

int CheckPbkdf2Arguments(__in void* salt, __in uint64_t saltSize, __in void* key, __in uint64_t keySize, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize)
{
    int status = NO_ERROR;
    if (status = CheckInputOutput(salt, saltSize, output, &outputSize))
        return status;
    else if (status = CheckInput(key, keySize))
        return status;
    else if (!iterationsNum)
        return ERROR_WRONG_ITERATIONS_NUMBER;
    else
        return NO_ERROR;
}

int GetPbkdf2(__in void* salt, __in uint64_t saltSize, __in void* key, __in uint64_t keySize, __in PRF func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize)
{
    int status = NO_ERROR;
    if (status = CheckPbkdf2Arguments(salt, saltSize, key, keySize, iterationsNum, output, outputSize))
        return status;
    else if (saltSize > 64)
        return ERROR_WRONG_INPUT_SIZE;
    else {
        uint8_t saltBuffer[68] = { 0 };
        memcpy(saltBuffer, salt, saltSize);
        return GetPbkdf2Internal(saltBuffer, saltSize, key, keySize, func, iterationsNum, output, outputSize);
    }
}

int GetPbkdf2Ex(__in void* salt, __in uint64_t saltSize, __in void* key, __in uint64_t keySize, __in PRF func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize)
{
    int status = NO_ERROR;
    if (status = CheckPbkdf2Arguments(salt, saltSize, key, keySize, iterationsNum, output, outputSize))
        return status;
    else
        return GetPbkdf2Internal(salt, saltSize, key, keySize, func, iterationsNum, output, outputSize);
}

int GetPbkdf2Internal(__in void* salt, __in uint64_t saltSize, __in void* key, __in uint64_t keySize, __in PRF func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize)
{
    uint16_t didgestSize = g_hashFuncsSizesMappings[func].outputSize;
    if (outputSize > 0xffffffff * (uint64_t)didgestSize)
        return ERROR_WRONG_OUTPUT_SIZE;

    uint32_t blocksNum = outputSize + (didgestSize - 1) / didgestSize;
    
    while (blocksNum--) {

    }

    GetPrfInternal(salt, saltSize, key, keySize, func, output, NULL);

    return NO_ERROR;
}