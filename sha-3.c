#include "pch.h"

#include "crypto_internal.h"

const uint64_t RC[] =
{
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,      
};

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

void Keccak_p(__inout uint64_t* state)
{
    uint64_t buffer[5];
    
    for (int r = 0; r < 24; ++r) {
        // Theta
        buffer[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20],
        buffer[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21],
        buffer[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22],
        buffer[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23],
        buffer[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        for (int i = 0; i < 5; ++i) {
            uint64_t temp = buffer[(i + 1) % 5];
            temp = buffer[(i + 4) % 5] ^ (temp << 1 | temp >> 63);
            for (int j = 0; j < 5; ++j)
                state[i + j*5] ^= temp;
        }

        // Rho and Pi
        int i = 1, j = 0;
        int it1 = 0, it2 = 0;
        *buffer = state[1];
        for (int t = 0; t < 24; ++t) {
            it1 = j;
            j = (2 * i + 3 * j) % 5;
            i = it1;
            it1 = i + j * 5;
            buffer[1] = state[it1];
            it2 = ((t + 1) * (t + 2) >> 1) & 0x3f;
            state[it1] = *buffer << it2 | *buffer >> (64 - it2);
            *buffer = buffer[1];
        }

        // Chi
        for (int j = 0; j < 5; ++j) {
            buffer[0] = state[j * 5],
            buffer[1] = state[1 + j * 5],
            buffer[2] = state[2 + j * 5],
            buffer[3] = state[3 + j * 5],
            buffer[4] = state[4 + j * 5];

            for (int i = 0; i < 5; ++i)
                state[i + j * 5] = ~buffer[(i + 1) % 5] & buffer[(i + 2) % 5] ^ buffer[i];
        }

        // Iota
        *state ^= RC[r];
    }
}

inline void Sha3StateXor(__in const uint64_t* input, __in HashFunc func, __inout uint64_t* state)
{
    uint64_t x = 1;
    switch (func) {
    case SHAKE128:
        state[20] ^= Uint64LittleEndianToBigEndianBits(input[20]);
        state[19] ^= Uint64LittleEndianToBigEndianBits(input[19]);
        state[18] ^= Uint64LittleEndianToBigEndianBits(input[18]);
    case SHA3_224:
        state[17] ^= Uint64LittleEndianToBigEndianBits(input[17]);
    case SHAKE256:
    case SHA3_256:
        state[16] ^= Uint64LittleEndianToBigEndianBits(input[16]);
        state[15] ^= Uint64LittleEndianToBigEndianBits(input[15]);
        state[14] ^= Uint64LittleEndianToBigEndianBits(input[14]);
        state[13] ^= Uint64LittleEndianToBigEndianBits(input[13]);
    case SHA3_384:
        state[12] ^= Uint64LittleEndianToBigEndianBits(input[12]);
        state[11] ^= Uint64LittleEndianToBigEndianBits(input[11]);
        state[10] ^= Uint64LittleEndianToBigEndianBits(input[10]);
        state[9] ^= Uint64LittleEndianToBigEndianBits(input[9]);
    case SHA3_512: 
        state[8] ^= Uint64LittleEndianToBigEndianBits(input[8]);
        state[7] ^= Uint64LittleEndianToBigEndianBits(input[7]);
        state[6] ^= Uint64LittleEndianToBigEndianBits(input[6]);
        state[5] ^= Uint64LittleEndianToBigEndianBits(input[5]);
        state[4] ^= Uint64LittleEndianToBigEndianBits(input[4]);
        state[3] ^= Uint64LittleEndianToBigEndianBits(input[3]);
        state[2] ^= Uint64LittleEndianToBigEndianBits(input[2]);
        state[1] ^= Uint64LittleEndianToBigEndianBits(input[1]);
        state[0] ^= Uint64LittleEndianToBigEndianBits(*input);
    default:
        break;
    }  
}

void Sha3Get(__in const HashInputNode* inputList, __in uint64_t inputListSize, __in HashFunc func, __out uint64_t* output, __in_opt uint16_t outputSize)
{
    uint16_t blockSize = g_hashFuncsSizesMappings[func].blockSize;
    uint16_t capacity = GetSha3Capacity(func);
    uint64_t state[5][5] = { {0}, {0}, {0}, {0}, {0} };

    HashInputNode inputNode = *inputList++;

    while (inputListSize--) {
        uint64_t blocksNum = inputNode.inputSizeLowPart / blockSize;

        while (--blocksNum) {
            Sha3StateXor(inputNode.input, func, (uint64_t*)state);
            (uint8_t*)inputNode.input += blockSize;
            Keccak_p((uint64_t*)state);
        }

        if (inputListSize)
            inputNode = *inputList++;
    }
}
