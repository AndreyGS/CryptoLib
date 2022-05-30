// kdf.c
//

#include "pch.h"
#include "kdf.h"
#include "hmac.h"

int CheckPbkdf2Arguments(__in const void* salt, __in uint64_t saltSize, __in const void* key, __in uint64_t keySize, __in Prf func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize)
{
    int status = NO_ERROR;
    if (!salt && saltSize)
        return ERROR_WRONG_INPUT;
    else if (!key && keySize)
        return ERROR_WRONG_KEY;
    else if (!output)
        return ERROR_WRONG_OUTPUT;
    else if ((unsigned)func >= Prf_max)
        return ERROR_UNSUPPORTED_PRF_FUNC;
    else if (!iterationsNum)
        return ERROR_WRONG_ITERATIONS_NUMBER;
    else
        return NO_ERROR;
}

int GetPbkdf2(__in const void* salt, __in uint64_t saltSize, __in const void* key, __in uint64_t keySize, __in Prf func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize)
{
    int status = NO_ERROR;
    if (status = CheckPbkdf2Arguments(salt, saltSize, key, keySize, func, iterationsNum, output, outputSize))
        return status;
    else if (saltSize > 512)
        return ERROR_WRONG_INPUT_SIZE;
    else {
        uint8_t* saltBuffer = NULL;
        EVAL(AllocBuffer((size_t)saltSize + 4, &saltBuffer));

        memcpy(saltBuffer, salt, (size_t)saltSize);
        status = GetPbkdf2Internal(saltBuffer, saltSize, key, keySize, func, iterationsNum, output, outputSize);
        FreeBuffer(saltBuffer);
    }

exit:
    return status;
}

int GetPbkdf2Ex(__in const void* salt, __in uint64_t saltSize, __in const void* key, __in uint64_t keySize, __in Prf func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize)
{
    int status = NO_ERROR;
    if (status = CheckPbkdf2Arguments(salt, saltSize, key, keySize, func, iterationsNum, output, outputSize))
        return status;
    else
        return GetPbkdf2Internal(salt, saltSize, key, keySize, func, iterationsNum, output, outputSize);
}

int GetPbkdf2Internal(__in const void* salt, __in uint64_t saltSize, __in const void* key, __in uint64_t keySize, __in Prf func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize)
{
    int status = NO_ERROR;

    uint16_t didgestSize = g_hashFuncsSizesMapping[func].didgestSize;

    uint8_t* buffer1 = NULL;
    uint8_t* buffer2 = NULL;
    PrfState* state = NULL;
    EVAL(AllocBuffer(didgestSize, &buffer1));
    EVAL(AllocBuffer(didgestSize, &buffer2));
    EVAL(InitPrfState(&state, func));

    uint8_t* reserveBuffer2 = buffer2;

    if (outputSize > 0xffffffff * (uint64_t)didgestSize)
        EVAL(ERROR_WRONG_OUTPUT_SIZE);

    uint32_t blocksNum = (uint32_t)((outputSize + (didgestSize - 1)) / didgestSize);
    uint32_t blocksCounter = 0;
    uint64_t saltFullSize = saltSize + 4;

    while (blocksNum--) {
        *(uint32_t*)((uint8_t*)salt + saltSize) = Uint32LittleEndianToBigEndian(++blocksCounter);
        GetPrfInternal(state, buffer1, 0, salt, saltFullSize, key, keySize, true);

        if (blocksNum) {
            buffer2 = output;
            (uint8_t*)output += didgestSize;
        }
        else
            buffer2 = reserveBuffer2;

        memcpy(buffer2, buffer1, didgestSize);

        uint64_t blockIterationsNum = iterationsNum;
        while (--blockIterationsNum) {
            GetPrfInternal(state, buffer1, 0, buffer1, didgestSize, key, keySize, true);
            for (uint16_t i = 0; i < didgestSize; ++i)
                buffer2[i] ^= buffer1[i];
        }

        // Last block, it can be not whole didgest size
        if (!blocksNum)
            memcpy(output, buffer2, outputSize % didgestSize ? outputSize % didgestSize : didgestSize);
    }

exit:
    FreePrfState(state);
    FreeBuffer(buffer2);
    FreeBuffer(buffer1);
    
    return status;
}
