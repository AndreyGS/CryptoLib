#include "pch.h"

#include "sha-3.h"
#include "crypto_internal.h"
#include "paddings.h"

void Sha3Get(__in const void* input, __in uint64_t inputSize, __in Sha3Func func, __in bool lastPart, __out uint64_t* output, __in uint64_t outputSize);

const uint64_t RC[] =
{
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,      
};

inline uint16_t GetSha3Capacity(Sha3Func func)
{
    switch (func) {
    case Sha3Func_SHA3_224:
        return 56;
    case Sha3Func_SHA3_256:
        return 64;
    case Sha3Func_SHA3_384:
        return 96;
    case Sha3Func_SHA3_512:
        return 128;
    case Sha3Func_SHAKE128:
        return 32;
    case Sha3Func_SHAKE256:
        return 64;
    default:
        return 0;
    }
}

void Keccak_p_Rnds(__inout uint64_t* state)
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

inline void Sha3StateXor(__in const uint64_t* input, __in Sha3Func func, __inout uint64_t* state)
{
    uint64_t x = 1;
    switch (func) {
    case Sha3Func_SHAKE128:
        state[20] ^= (input[20]);
        state[19] ^= (input[19]);
        state[18] ^= (input[18]);
    case Sha3Func_SHA3_224:
        state[17] ^= (input[17]);
    case Sha3Func_SHAKE256:
    case Sha3Func_SHA3_256:
        state[16] ^= (input[16]);
        state[15] ^= (input[15]);
        state[14] ^= (input[14]);
        state[13] ^= (input[13]);
    case Sha3Func_SHA3_384:
        state[12] ^= (input[12]);
        state[11] ^= (input[11]);
        state[10] ^= (input[10]);
        state[9] ^= (input[9]);
    case Sha3Func_SHA3_512:
        state[8] ^= (input[8]);
        state[7] ^= (input[7]);
        state[6] ^= (input[6]);
        state[5] ^= (input[5]);
        state[4] ^= (input[4]);
        state[3] ^= (input[3]);
        state[2] ^= (input[2]);
        state[1] ^= (input[1]);
        state[0] ^= (*input);
    default:
        break;
    }  
}

void Sha3GetHash(__in const void* input, __in uint64_t inputSize, __in HashFunc func, __out uint64_t* output, __in StageType stageType, __inout_opt void* state)
{
    Sha3Get(input, inputSize, func - SHA3_224, output, stageType, 0, state);
}

void Sha3GetXof(__in const void* input, __in uint64_t inputSize, __in Xof func, __out uint64_t* output, __in StageType stageType, __in uint64_t outputSize, __inout_opt void* state)
{
    Sha3Get(input, inputSize, func + Sha3Func_SHA3_512 + 1, output, stageType, outputSize, state);
}

void Sha3Get(__in const void* input, __in uint64_t inputSize, __in Sha3Func func, __out uint64_t* output, __in StageType stageType, __in uint64_t outputSize, __inout_opt void* state)
{
    int status = NO_ERROR;
    uint16_t blockSize = func == Sha3Func_SHAKE128 || func == Sha3Func_SHAKE256
                       ? g_XofSizesMapping[func - Sha3Func_SHAKE128].blockSize
                       : g_hashFuncsSizesMapping[func + SHA3_224].blockSize;
    uint64_t stackBuffer[5][5] = { {0}, {0}, {0}, {0}, {0} };
    uint32_t* buffer = NULL;

    if (state != Single_stage)
        buffer = state;
    else
        buffer = stackBuffer;

    if (state == First_stage)
        memset(buffer, 0, SHA3_FULL_STATE_SIZE);

    uint64_t blocksNum = inputSize / blockSize + (stageType == Single_stage || stageType == Final_stage ? 1 : 2);

    while (--blocksNum) {
        Sha3StateXor(input, func, (uint64_t*)buffer);
        (uint8_t*)input += blockSize;
        Keccak_p_Rnds((uint64_t*)buffer);
    }

    bool lastPart = state == Single_stage || state == Final_stage;

    if (lastPart) {
        uint64_t tailBlocks[42] = { 0 };
        uint8_t tailBlocksNum = 0;
        AddSha3PaddingInternal(input, inputSize, func, tailBlocks, &tailBlocksNum);

        uint8_t* p = (uint8_t*)tailBlocks;
        while (tailBlocksNum--) {
            Sha3StateXor((uint64_t*)p, func, (uint64_t*)buffer);
            p += SHA2_BLOCK_SIZE;
            Keccak_p_Rnds((uint64_t*)buffer);
        }
    }

    if (lastPart && (func == Sha3Func_SHAKE128 || func == Sha3Func_SHAKE256)) {
        uint16_t digestBlockSize = g_XofSizesMapping[func - Sha3Func_SHAKE128].blockSize;

        while (digestBlockSize < outputSize) {
            switch (func) {
            case Sha3Func_SHAKE128:
                output[20] = buffer[20];
                output[19] = buffer[19];
                output[18] = buffer[18];
                output[17] = buffer[17];
            case Sha3Func_SHAKE256:
                output[16] = buffer[16];
                output[15] = buffer[15];
                output[14] = buffer[14];
                output[13] = buffer[13];
                output[12] = buffer[12];
                output[11] = buffer[11];
                output[10] = buffer[10];
                output[9] = buffer[9];
                output[8] = buffer[8];
                output[7] = buffer[7];
                output[6] = buffer[6];
                output[5] = buffer[5];
                output[4] = buffer[4];
                output[3] = buffer[3];
                output[2] = buffer[2];
                output[1] = buffer[1];
                output[0] = buffer[0];
                break;
            }

            output += func == Sha3Func_SHAKE128 ? 21 : 17;
            
            Keccak_p_Rnds((uint64_t*)state);

            outputSize -= digestBlockSize;
        }

        uint8_t* p = (uint8_t*)state;

        while (outputSize--)
            *((uint8_t*)output)++ = *p++;

    }
    else if (!lastPart || (func != Sha3Func_SHAKE128 && func != Sha3Func_SHAKE256)) {
        switch (func) {
        case Sha3Func_SHA3_512:
            output[7] = buffer[7];
            output[6] = buffer[6];
        case Sha3Func_SHA3_384:
            output[5] = buffer[5];
            output[4] = buffer[4];
        default:
            if (func == Sha3Func_SHA3_224)
                (uint32_t)output[3] = *((uint32_t*)&buffer[3]);
            else
                output[3] = buffer[3];

            output[2] = buffer[2];
            output[1] = buffer[1];
            output[0] = buffer[0];
            break;
        }
    }
}
