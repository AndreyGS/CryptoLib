// crypto_helpers.c
//

#include "pch.h"
#include "crypto_helpers.h"

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
    int status = NO_ERROR;
    return !(status = CheckInput(input, inputSize)) ? CheckOutput(output, outputSize) : status;
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

// Example of input and output of Uint64LittleEndianToBigEndianBits:
//
// first two bytes:
// input:
// 1010 0110 1110 0010 (0xa6e2)
// output:
// 0110 0101 0100 0111 (0x6547)
inline uint64_t Uint64LittleEndianToBigEndianBits(uint64_t input)
{
    return (input & 0x8080808080808080) >> 7
        |  (input & 0x4040404040404040) >> 5
        |  (input & 0x2020202020202020) >> 3
        |  (input & 0x1010101010101010) >> 1
        |  (input & 0x0808080808080808) << 1
        |  (input & 0x0404040404040404) << 3
        |  (input & 0x0202020202020202) << 5
        |  (input & 0x0101010101010101) << 7;
}

inline void* AllocBuffer(size_t size)
{
    void* buffer = NULL;
#ifndef KERNEL
    buffer = malloc(size);
#endif
    return buffer;
}

inline void FreeBuffer(void* buffer)
{
#ifndef KERNEL
    if (buffer)
        free(buffer);
#endif
}
