// kdf.c
//

#include "pch.h"
#include "kdf.h"
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
    else if (saltSize > 512)
        return ERROR_WRONG_INPUT_SIZE;
    else {
        uint8_t* saltBuffer = AllocBuffer((size_t)saltSize + 4);
        if (!saltBuffer)
            return ERROR_NO_MEMORY;
        memcpy(saltBuffer, salt, (size_t)saltSize);
        status = GetPbkdf2Internal(saltBuffer, saltSize, key, keySize, func, iterationsNum, output, outputSize);
        FreeBuffer(saltBuffer);
        return status;
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
    int status = NO_ERROR;

    uint16_t didgestSize = g_hashFuncsSizesMappings[func].outputSize;
    uint8_t* buffer1 = AllocBuffer(didgestSize);
    uint8_t* buffer2 = AllocBuffer(didgestSize);
    uint8_t* reserveBuffer2 = buffer2;

    if (outputSize > 0xffffffff * (uint64_t)didgestSize)
        EVAL(ERROR_WRONG_OUTPUT_SIZE);

    if (!buffer1 || !buffer2)
        EVAL(ERROR_NO_MEMORY);

    uint32_t blocksNum = (uint32_t)((outputSize + (didgestSize - 1)) / didgestSize);
    uint32_t blocksCounter = 0;
    uint64_t saltFullSize = saltSize + 4;
    
    while (blocksNum--) {
        *(uint32_t*)((uint8_t*)salt + saltSize) = Uint32LittleEndianToBigEndian(++blocksCounter);
        EVAL(GetPrf(salt, saltFullSize, key, keySize, func, buffer1, didgestSize));

        if (blocksNum) {
            buffer2 = output;
            (uint8_t*)output += didgestSize;
        }
        else
            buffer2 = reserveBuffer2;

        memcpy(buffer2, buffer1, didgestSize);

        uint64_t blockIterationsNum = iterationsNum;
        while (--blockIterationsNum) {
            EVAL(GetPrf(buffer1, didgestSize, key, keySize, func, buffer1, didgestSize));
            for (uint16_t i = 0; i < didgestSize; ++i)
                buffer2[i] ^= buffer1[i];
        }

        // Last block, it can be not whole didgest size
        if (!blocksNum)
            memcpy(output, buffer2, outputSize % didgestSize ? outputSize % didgestSize : didgestSize);
    }

exit:
    FreeBuffer(buffer2);
    FreeBuffer(buffer1);
    
    return status;
}
