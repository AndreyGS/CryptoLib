#include "pch.h"

#include "crypto_internal.h"

const uint32_t H[5] = {
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
    0xc3d2e1f0
};

const uint32_t K1 = 0x5a827999;
const uint32_t K2 = 0x6ed9eba1;
const uint32_t K3 = 0x8f1bbcdc;
const uint32_t K4 = 0xca62c1d6;

void Sha1ProcessBlock(const uint32_t* input, uint32_t* output)
{
    uint32_t words[80];

    for (int i = 0; i < 16; ++i)
        words[i] = Uint32LittleEndianToBigEndian(*input++);

    for (int i = 16; i < 32; ++i)
        words[i] = Uint32BigEndianLeftRotateByOne(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]);

    for (int i = 32; i < 80; ++i)
        words[i] = Uint32BigEndianLeftRotate(words[i - 6] ^ words[i - 16] ^ words[i - 28] ^ words[i - 32], 2);

    uint32_t a = output[0],
             b = output[1],
             c = output[2],
             d = output[3],
             e = output[4],
             f = 0,
             k = 0,
             temp = 0;

    for (int i = 0; i < 80; ++i) {
        if (i < 20) {
            f = d ^ (b & (c ^ d));
            k = K1;
        }
        else if (i < 40) {
            f = b ^ c ^ d;
            k = K2;
        }
        else if (i < 60) {
            f = b & c | d & (b | c);
            k = K3;
        }
        else {
            f = b ^ c ^ d;
            k = K4;
        }

        temp = Uint32BigEndianLeftRotate(a, 5) + e + f + k + words[i],
        e = d,
        d = c,
        c = Uint32BigEndianLeftRotate(b, 30),
        b = a,
        a = temp;
    }
    
    output[0] += a;
    output[1] += b;
    output[2] += c;
    output[3] += d;
    output[4] += e;
}

int Sha1Get(__in const void* input, __in uint64_t inputSize, __out void* output)
{
    int status = NO_ERROR;
    if (status = CheckInput(input, inputSize))
        return status;
    else if (!output)
        return ERROR_WRONG_OUTPUT;

    uint64_t blocksNum = (inputSize >> 6) + 1; // inputSize / SHA_BLOCK_SIZE + 1
    

    ((uint32_t*)output)[0] = H[0];
    ((uint32_t*)output)[1] = H[1];
    ((uint32_t*)output)[2] = H[2];
    ((uint32_t*)output)[3] = H[3];
    ((uint32_t*)output)[4] = H[4];

    while (--blocksNum) {
        Sha1ProcessBlock(input, output);
        (uint8_t*)input += SHA_BLOCK_SIZE;
    }

    uint64_t tailBlocks[16] = { 0 };
    AddShaPaddingInternal(input, inputSize, tailBlocks, &blocksNum);

    uint8_t* p = (uint8_t*)tailBlocks;

    while (blocksNum--) {
        Sha1ProcessBlock((uint32_t*)p, output);
        p += SHA_BLOCK_SIZE;
    }

    ((uint32_t*)output)[0] = Uint32LittleEndianToBigEndian(((uint32_t*)output)[0]);
    ((uint32_t*)output)[1] = Uint32LittleEndianToBigEndian(((uint32_t*)output)[1]);
    ((uint32_t*)output)[2] = Uint32LittleEndianToBigEndian(((uint32_t*)output)[2]);
    ((uint32_t*)output)[3] = Uint32LittleEndianToBigEndian(((uint32_t*)output)[3]);
    ((uint32_t*)output)[4] = Uint32LittleEndianToBigEndian(((uint32_t*)output)[4]);

    return NO_ERROR;
}
