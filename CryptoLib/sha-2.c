/**
 * @file sha-2.c
 * @author Andrey Grabov-Smetankin <ukbpyh@gmail.com>
 *
 * @section LICENSE
 *
 * Copyright 2022 Andrey Grabov-Smetankin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * 
 */
 // This is an independent project of an individual developer. Dear PVS-Studio, please check it.
 // PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include "pch.h"
#include "sha-2.h"
#include "paddings.h"


const uint32_t H_224[8] = {
    0xc1059ed8,
    0x367cd507,
    0x3070dd17,
    0xf70e5939,
    0xffc00b31,
    0x68581511,
    0x64f98fa7,
    0xbefa4fa4
};

const uint32_t H_256[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

const uint64_t H_384[8] = {
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4
};

const uint64_t H_512_224[8] = {
    0x8c3d37c819544da2,
    0x73e1996689dcd4d6,
    0x1dfab7ae32ff9c82,
    0x679dd514582f9fcf,
    0x0f6d2b697bd44da8,
    0x77e36f7304c48942,
    0x3f9d85a86a1d36c8,
    0x1112e6ad91d692a1
};

const uint64_t H_512_256[8] = {
    0x22312194fc2bf72c,
    0x9f555fa3c84c64c2,
    0x2393b86b6f53b151,
    0x963877195940eabd,
    0x96283ee2a88Effe3,
    0xbe5e1e2553863992,
    0x2b0199fc2c85b8aa,
    0x0eb72ddc81c52ca2
};

const uint64_t H_512[8] = {
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179
};

const uint32_t K_32[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

const uint64_t K_64[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

void Sha2_32InitState(__in HashFunc func, __out uint32_t* state)
{
    const uint32_t* pH = NULL;

    if (func == SHA_224)
        pH = H_224;
    else
        pH = H_256;

    state[0] = pH[0], state[1] = pH[1], state[2] = pH[2], state[3] = pH[3],
    state[4] = pH[4], state[5] = pH[5], state[6] = pH[6], state[7] = pH[7];
}

void Sha2_64InitState(__in HashFunc func, __out uint64_t* state)
{
    const uint64_t* pH = NULL;

    switch (func) {
    case SHA_384:
        pH = H_384;
        break;
    case SHA_512_224:
        pH = H_512_224;
        break;
    case SHA_512_256:
        pH = H_512_256;
        break;
    case SHA_512:
        pH = H_512;
        break;
    }

    state[0] = pH[0], state[1] = pH[1], state[2] = pH[2], state[3] = pH[3], //-V522
    state[4] = pH[4], state[5] = pH[5], state[6] = pH[6], state[7] = pH[7];
}

void Sha2_32ProcessBlock(const uint32_t* input, uint32_t* words, uint32_t* output)
{
    for (int i = 0; i < 16; ++i)
        words[i] = Uint32LittleEndianToBigEndian(*input++);

    for (int i = 16; i < 64; ++i)
        words[i] = 
              (Uint32BigEndianRightRotate(words[i - 15],  7) ^ Uint32BigEndianRightRotate(words[i - 15], 18) ^ (words[i - 15] >>  3))
            + (Uint32BigEndianRightRotate(words[i -  2], 17) ^ Uint32BigEndianRightRotate(words[i -  2], 19) ^ (words[i -  2] >> 10))
            + words[i - 16] + words[i - 7];

    uint32_t a = output[0],
             b = output[1],
             c = output[2],
             d = output[3],
             e = output[4],
             f = output[5],
             g = output[6],
             h = output[7],
             temp1 = 0, temp2 = 0;

    for (int i = 0; i < 64; ++i) {
        temp1 =
              (Uint32BigEndianRightRotate(e, 6) ^ Uint32BigEndianRightRotate(e, 11) ^ Uint32BigEndianRightRotate(e, 25))
            + (e & f ^ ~e & g)
            + h + K_32[i] + words[i];

        temp2 =
              (Uint32BigEndianRightRotate(a, 2) ^ Uint32BigEndianRightRotate(a, 13) ^ Uint32BigEndianRightRotate(a, 22))
            + (a & b ^ a & c ^ b & c);

        h = g,
        g = f,
        f = e,
        e = d + temp1,
        d = c,
        c = b,
        b = a,
        a = temp1 + temp2;
    }

    output[0] += a;
    output[1] += b;
    output[2] += c;
    output[3] += d;
    output[4] += e;
    output[5] += f;
    output[6] += g;
    output[7] += h;
}

void Sha2_32Get(__inout Sha2_32State* state, __in_opt const void* input, __in uint64_t inputSize, __in HashFunc func, __in bool finalize, __out_opt uint32_t* output)
{
    uint64_t blocksNum = (inputSize >> 6) + 1; // inputSize / SHA1_BLOCK_SIZE + 1
    uint32_t* mainState = state->state;
    uint32_t* wordsBuffer = state->words;

    while (--blocksNum) {
        Sha2_32ProcessBlock(input, wordsBuffer, mainState);
        (uint8_t*)input += SHA2_32_BLOCK_SIZE;
    }
    
    state->size += inputSize;

    if (finalize) {
        uint8_t* tailBlocks = (uint8_t*)state->tailBlocks;
        AddShaPaddingInternal(input, state->size, tailBlocks, &blocksNum);

        while (blocksNum--) {
            Sha2_32ProcessBlock((uint32_t*)tailBlocks, wordsBuffer, mainState);
            tailBlocks += SHA2_32_BLOCK_SIZE;
        }

        output[0] = Uint32LittleEndianToBigEndian(mainState[0]);
        output[1] = Uint32LittleEndianToBigEndian(mainState[1]);
        output[2] = Uint32LittleEndianToBigEndian(mainState[2]);
        output[3] = Uint32LittleEndianToBigEndian(mainState[3]);
        output[4] = Uint32LittleEndianToBigEndian(mainState[4]);
        output[5] = Uint32LittleEndianToBigEndian(mainState[5]);
        output[6] = Uint32LittleEndianToBigEndian(mainState[6]);

        if (func == SHA_256)
            output[7] = Uint32LittleEndianToBigEndian(mainState[7]);
    }
}

void Sha2_64ProcessBlock(const uint64_t* input, uint64_t* words, uint64_t* output)
{
    for (int i = 0; i < 16; ++i)
        words[i] = Uint64LittleEndianToBigEndian(*input++);

    for (int i = 16; i < 80; ++i)
        words[i] =
              (Uint64BigEndianRightRotate(words[i - 15],  1) ^ Uint64BigEndianRightRotate(words[i - 15],  8) ^ (words[i - 15] >> 7))
            + (Uint64BigEndianRightRotate(words[i -  2], 19) ^ Uint64BigEndianRightRotate(words[i -  2], 61) ^ (words[i -  2] >> 6))
            + words[i - 16] + words[i - 7];

    uint64_t a = output[0],
             b = output[1],
             c = output[2],
             d = output[3],
             e = output[4],
             f = output[5],
             g = output[6],
             h = output[7],
             temp1 = 0, temp2 = 0;

    for (int i = 0; i < 80; ++i) {
        temp1 =
              (Uint64BigEndianRightRotate(e, 14) ^ Uint64BigEndianRightRotate(e, 18) ^ Uint64BigEndianRightRotate(e, 41))
            + (e & f ^ ~e & g)
            + h + K_64[i] + words[i];

        temp2 =
              (Uint64BigEndianRightRotate(a, 28) ^ Uint64BigEndianRightRotate(a, 34) ^ Uint64BigEndianRightRotate(a, 39))
            + (a & b ^ a & c ^ b & c);

        h = g,
        g = f,
        f = e,
        e = d + temp1,
        d = c,
        c = b,
        b = a,
        a = temp1 + temp2;
    }

    output[0] += a;
    output[1] += b;
    output[2] += c;
    output[3] += d;
    output[4] += e;
    output[5] += f;
    output[6] += g;
    output[7] += h;
}

void Sha2_64Get(__inout Sha2_64State* state, __in_opt const void* input, __in uint64_t inputSize, __in HashFunc func, __in bool finalize, __out_opt uint64_t* output)
{
    uint64_t blocksNum = (inputSize >> 7) + 1;
    uint64_t* mainState = state->state;
    uint64_t* wordsBuffer = state->words;

    while (--blocksNum) {
        Sha2_64ProcessBlock(input, wordsBuffer, mainState);
        (uint8_t*)input += SHA2_64_BLOCK_SIZE;
    }

    state->sizeHigh += (inputSize + state->sizeLow < inputSize ? 1 : 0);
    state->sizeLow += inputSize;

    if (finalize) {
        uint8_t* tailBlocks = (uint8_t*)state->tailBlocks;
        AddSha2_64PaddingInternal(input, state->sizeLow, state->sizeHigh, tailBlocks, &blocksNum);

        while (blocksNum--) {
            Sha2_64ProcessBlock((uint64_t*)tailBlocks, wordsBuffer, mainState);
            tailBlocks += SHA2_64_BLOCK_SIZE;
        }

        switch (func) {
        case SHA_512:
            output[7] = Uint64LittleEndianToBigEndian(mainState[7]);
            output[6] = Uint64LittleEndianToBigEndian(mainState[6]);
        case SHA_384:
            output[5] = Uint64LittleEndianToBigEndian(mainState[5]);
            output[4] = Uint64LittleEndianToBigEndian(mainState[4]);
        default:
            if (func == SHA_512_224)
                (uint32_t)output[3] = Uint32LittleEndianToBigEndian(*(((uint32_t*)&mainState[3]) + 1));
            else
                output[3] = Uint64LittleEndianToBigEndian(mainState[3]);

            output[2] = Uint64LittleEndianToBigEndian(mainState[2]);
            output[1] = Uint64LittleEndianToBigEndian(mainState[1]);
            output[0] = Uint64LittleEndianToBigEndian(mainState[0]);
            break;
        }
    }
}
