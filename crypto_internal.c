#include "pch.h"
#include "crypto_internal.h"

int CheckInput(__in const void* input, __in uint64_t inputSize)
{
    if (!input)
        return ERROR_WRONG_INPUT;
    else if (!inputSize)
        return ERROR_WRONG_INPUT_SIZE;
    else
        return NO_ERROR;
}

int CheckOutput(__in const void* output, __in const uint64_t* outputSize)
{
    if (!output || !outputSize)
        return ERROR_WRONG_OUTPUT;
    else
        return NO_ERROR;
}

int CheckInputOutput(__in const void* input, __in uint64_t inputSize, __in const void* output, __in const uint64_t* outputSize)
{
    return CheckInput(input, inputSize) || CheckOutput(output, outputSize);
}


int CheckBlockCipherPrimaryArguments(const void* input, uint64_t inputSize, uint64_t* roundsKeys, void* output, uint64_t* outputSize, BlockCipherOpMode mode, const void* iv)
{
    int status = NO_ERROR;
    if (status = CheckInputOutput(input, inputSize, output, outputSize))
        return status;
    else if (!roundsKeys)
        return ERROR_WRONG_KEYS;
    else if (mode != ECB_mode && !iv)
        return ERROR_WRONG_INIT_VECTOR;
    else
        return NO_ERROR;
}

inline uint32_t Uint32BigEndianLeftRotateByOne(uint32_t word) // big-endian style
{
    return word << 1 | (word & 0x80000000 ? 1 : 0); // on 10700K this is more than 10% faster than word << 1 | word >> 31
}

inline uint32_t Uint32BigEndianLeftRotate(uint32_t word, int rounds) // big-endian style, rounds max == 32
{
    return word << rounds | word >> (32 - rounds);
}

inline uint32_t Uint32BigEndianRightRotate(uint32_t word, int rounds)
{
    return word >> rounds | word << (32 - rounds);
}

inline uint64_t Uint64BigEndianRightRotate(uint64_t word, int rounds)
{
    return word >> rounds | word << (64 - rounds);
}

inline uint64_t Uint64LittleEndianToBigEndian(uint64_t input)
{
    return input >> 56 
         | input >> 40 & 0x000000000000ff00 
         | input >> 24 & 0x0000000000ff0000 
         | input >> 8  & 0x00000000ff000000
         | input << 8  & 0x000000ff00000000
         | input << 24 & 0x0000ff0000000000
         | input << 40 & 0x00ff000000000000
         | input << 56;
}

inline uint32_t Uint32LittleEndianToBigEndian(uint32_t input)
{
    return input >> 24
         | input >> 8 & 0x0000ff00
         | input << 8 & 0x00ff0000
         | input << 24;
}
