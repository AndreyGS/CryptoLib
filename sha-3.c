#include "pch.h"

#include "crypto_internal.h"

inline uint16_t GetSha3Capacity(HashFunc func)
{
    switch (func) {
    case SHA3_224:
        return 56;
    case SHA3_256:
        return 64;
    case SHA3_384:
        return 96;
    case SHA3_512:
        return 128;
    case SHAKE128:
        return 32;
    case SHAKE256:
        return 64;
    default:
        return 0;
    }
}

void Keccak_p(__inout uint64_t* output)
{

}

inline void Sha3StateXor(__in const uint64_t* input, __inout uint64_t** state)
{
    for (int i = 0; i < 5; ++i)
        for (int j = 0; j < 5; ++i)
            state[j][i] ^= Uint64LittleEndianToBigEndianBits(*input++);
}

void Sha3Get(__in const HashInputNode* inputList, __in uint64_t inputListSize, __in HashFunc func, __out uint64_t* output)
{
    HashInputNode inputNode = *inputList++;
    uint16_t capacity = GetSha3Capacity(func);
    uint64_t state[5][5] = { {0}, {0}, {0}, {0}, {0} };

    while (inputListSize--) {
        uint64_t blocksNum = inputNode.inputSizeLowPart / g_hashFuncsSizesMappings[func].blockSize;

        while (--blocksNum) {
            Sha3StateXor(inputNode.input, (uint64_t**)state);
            Keccak_p(output);
        }
    }
}
