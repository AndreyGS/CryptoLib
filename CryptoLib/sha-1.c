// sha-1.c
//

#include "pch.h"
#include "sha-1.h"
#include "paddings.h"
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

void Sha1Get(__in const void* input, __in uint64_t inputSize, __out uint32_t* output, __in bool finalize, __inout void* state)
{
    int status = NO_ERROR;
   
    uint64_t blocksNum = (inputSize >> 6 /* inputSize / SHA1_BLOCK_SIZE */) + 1;

    while (--blocksNum) {
        Sha1ProcessBlock(input, state);
        (uint8_t*)input += SHA1_BLOCK_SIZE;
    }
    
    uint64_t* totalSize = (uint64_t*)((uint8_t*)state + SHA1_STATE_SIZE);
    *totalSize += inputSize;

    if (finalize) {
        uint64_t tailBlocks[16] = { 0 };
        AddShaPaddingInternal(input, *totalSize, tailBlocks, &blocksNum);

        uint8_t* p = (uint8_t*)tailBlocks;

        while (blocksNum--) {
            Sha1ProcessBlock((uint32_t*)p, state);
            p += SHA1_BLOCK_SIZE;
        }

        output[0] = Uint32LittleEndianToBigEndian(((uint32_t*)state)[0]);
        output[1] = Uint32LittleEndianToBigEndian(((uint32_t*)state)[1]);
        output[2] = Uint32LittleEndianToBigEndian(((uint32_t*)state)[2]);
        output[3] = Uint32LittleEndianToBigEndian(((uint32_t*)state)[3]);
        output[4] = Uint32LittleEndianToBigEndian(((uint32_t*)state)[4]);
    }
}
