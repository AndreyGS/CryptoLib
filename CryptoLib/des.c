// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/**
 * @file des.c
 * @author Andrey Grabov-Smetankin <ukbpyh@gmail.com>
 *
 * @section LICENSE
 *
 * Copyright 2022-2023 Andrey Grabov-Smetankin <ukbpyh@gmail.com>
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

#include "pch.h"
#include "des.h"
#include "paddings.h"
#include "crypto_internal.h"

typedef uint64_t(*DesEncDecFunction)(const uint64_t* roundKeys, const uint64_t input);

typedef struct _CDBlocks {
    uint32_t cBlock;
    uint32_t dBlock;
} CDBlocks;


// Round Keys Generation Block

static inline uint64_t DesGetExtendedKeyPermutation(uint64_t extendedKey)
{
    /*
        57	49	41	33	25	17	9	1	58	50	42	34	26	18	C0
        10	2	59	51	43	35	27	19	11	3	60	52	44	36	
        63	55	47	39	31	23	15	7	62	54	46	38	30	22	D0
        14	6	61	53	45	37	29	21	13	5	28	20	12	4	
    */

    return
        // C0
        // bits 0-7
          (extendedKey & 0x8000000000000000 /* 2^63 */) >> 56
        | (extendedKey & 0x0080000000000000 /* 2^55 */) >> 49
        | (extendedKey & 0x0000800000000000 /* 2^47 */) >> 42
        | (extendedKey & 0x0000008000000000 /* 2^39 */) >> 35
        | (extendedKey & 0x0000000080000000 /* 2^31 */) >> 28
        | (extendedKey & 0x0000000000800000 /* 2^23 */) >> 21
        | (extendedKey & 0x0000000000008000 /* 2^15 */) >> 14
        | (extendedKey & 0x0000000000000080 /* 2^ 7 */) >>  7

        // bits 8-15
        | (extendedKey & 0x4000000000000000 /* 2^62 */) >> 47
        | (extendedKey & 0x0040000000000000 /* 2^54 */) >> 40
        | (extendedKey & 0x0000400000000000 /* 2^46 */) >> 33
        | (extendedKey & 0x0000004000000000 /* 2^38 */) >> 26
        | (extendedKey & 0x0000000040000000 /* 2^30 */) >> 19
        | (extendedKey & 0x0000000000400000 /* 2^22 */) >> 12
        | (extendedKey & 0x0000000000004000 /* 2^14 */) >>  5
        | (extendedKey & 0x0000000000000040 /* 2^ 6 */) <<  2

        // bits 16-23
        | (extendedKey & 0x2000000000000000 /* 2^61 */) >> 38
        | (extendedKey & 0x0020000000000000 /* 2^53 */) >> 31
        | (extendedKey & 0x0000200000000000 /* 2^45 */) >> 24
        | (extendedKey & 0x0000002000000000 /* 2^37 */) >> 17
        | (extendedKey & 0x0000000020000000 /* 2^29 */) >> 10
        | (extendedKey & 0x0000000000200000 /* 2^21 */) >>  3
        | (extendedKey & 0x0000000000002000 /* 2^13 */) <<  4
        | (extendedKey & 0x0000000000000020 /* 2^ 5 */) << 11

        // bits 24-27
        | (extendedKey & 0x1000000000000000 /* 2^60 */) >> 29
        | (extendedKey & 0x0010000000000000 /* 2^52 */) >> 22
        | (extendedKey & 0x0000100000000000 /* 2^44 */) >> 15
        | (extendedKey & 0x0000001000000000 /* 2^36 */) >>  8

        // D0
        | (extendedKey & 0x0200000000000000 /* 2^57 */) >> 30 
        | (extendedKey & 0x0402000000000000 /* 2^58 | 2^49 */) >> 23
        | (extendedKey & 0x0804020000000000 /* 2^59 | 2^50 | 2^41 */) >> 16
        | (extendedKey & 0x0008040200000000 /* 2^51 | 2^42 | 2^33 */) >>  9

        | (extendedKey & 0x0000000002000000 /* 2^25 */) << 14
        | (extendedKey & 0x0000000004020000 /* 2^26 | 2^17 */) << 21
        | (extendedKey & 0x0000000008040200 /* 2^27 | 2^18 | 2^ 9 */) << 28
        | (extendedKey & 0x0000000000080402 /* 2^19 | 2^10 | 2^ 1 */) << 35

        | (extendedKey & 0x0000080400000000 /* 2^43 | 2^34 */) >>  2
        | (extendedKey & 0x0000000000000804 /* 2^11 | 2^ 2 */) << 42
        | (extendedKey & 0x0000000800000000 /* 2^35 */) <<  5
        | (extendedKey & 0x0000000000000008 /* 2^ 3 */) << 49

        | (extendedKey & 0x0000000010000000 /* 2^28 */) << 23
        | (extendedKey & 0x0000000000100000 /* 2^20 */) << 30
        | (extendedKey & 0x0000000000001000 /* 2^12 */) << 37
        | (extendedKey & 0x0000000000000010 /* 2^ 4 */) << 44;
}

static inline CDBlocks DesGetZeroCDBlocks(uint64_t permKey)
{
    CDBlocks initialBlock = { (uint32_t)(permKey & 0x00000000f0ffffff), (uint32_t)(((permKey & 0x000f0f0f0f000000) >> 20) | ((permKey & 0x00f0f0f000000000) >> 36)) };
    return initialBlock;
}

static inline uint32_t DesRotateByOne(uint32_t number)
{
    return (number & 0x707f7f7f) << 1 | (number & 0x00000080) << 21 | (number & 0x80808000) >> 15;
}

static inline CDBlocks DesGetRoundCDBlocksOne(CDBlocks cdBlocks)
{
    CDBlocks rotatedBlock = { DesRotateByOne(cdBlocks.cBlock), DesRotateByOne(cdBlocks.dBlock) };
    return rotatedBlock;
}

static inline uint32_t DesRotateByTwo(uint32_t number)
{
    return (number & 0x303f3f3f) << 2 | (number & 0x000000c0) << 22 | (number & 0xc0c0c000) >> 14;
}

static inline CDBlocks DesGetRoundCDBlocksTwo(CDBlocks cdBlocks)
{
    CDBlocks rotatedBlock = { DesRotateByTwo(cdBlocks.cBlock), DesRotateByTwo(cdBlocks.dBlock) };
    return rotatedBlock;
}

static inline uint64_t DesGetRoundKey(CDBlocks cdBlocks)
{
    /*
        14	17	11	24	1	5	3	28	15	6	21	10	23	19	12	4
        26	8	16	7	27	20	13	2	41	52	31	37	47	55	30	40
        51	45	33	48	44	49	39	56	34	53	46	42	50	36	29	32
    */

    return
        // bits 0-3
          (cdBlocks.cBlock & 0x0000000000001400 /* 2^12 | 2^10 */) >>  3
        | (cdBlocks.cBlock & 0x0000000000800000 /* 2^23 */) >> 17
        | (cdBlocks.cBlock & 0x0000000000002000 /* 2^13 */) >>  8
        | (cdBlocks.cBlock & 0x0000000000010000 /* 2^16 */) >> 12

        | (cdBlocks.cBlock & 0x00000000000000a0 /* 2^ 7 | 2^ 5 */) >>  4
        | (cdBlocks.cBlock & 0x0000000000000008 /* 2^ 3 */) >>  1
        | (cdBlocks.cBlock & 0x0000000010000000 /* 2^28 */) >> 28
        | (cdBlocks.cBlock & 0x0000000000000a00 /* 2^11 | 2^ 9 */) <<  6
        
        | (cdBlocks.cBlock & 0x0000000000000004 /* 2^ 2 */) << 12
        | (cdBlocks.cBlock & 0x00000000000a0000 /* 2^19 | 2^17 */) >>  6
        | (cdBlocks.cBlock & 0x0000000000104000 /* 2^20 | 2^14 */) >>  2
        | (cdBlocks.cBlock & 0x0000000000200000 /* 2^21 */) >> 11

        | (cdBlocks.cBlock & 0x0000000000000010 /* 2^ 4 */) <<  4
        | (cdBlocks.cBlock & 0x0000000040000000 /* 2^30 */) >>  7
        | (cdBlocks.cBlock & 0x0000000000000001 /* 2^ 0 */) << 22
        | (cdBlocks.cBlock & 0x0000000000000100 /* 2^ 8 */) << 13
        
        | (cdBlocks.cBlock & 0x0000000000000002 /* 2^ 1 */) << 19
        | (cdBlocks.cBlock & 0x0000000020000000 /* 2^29 */) >> 10
        | (cdBlocks.cBlock & 0x0000000000000040 /* 2^ 6 */) << 10


        | (cdBlocks.dBlock & 0x0000000000010000 /* 2^16 */) << 14
        | (cdBlocks.dBlock & 0x0000000000000020 /* 2^ 5 */) << 24
        | (cdBlocks.dBlock & 0x0000000000008000 /* 2^15 */) << 13
        | (cdBlocks.dBlock & 0x0000000000200000 /* 2^21 */) <<  6
        
        | (cdBlocks.dBlock & 0x0000000020000000 /* 2^29 */) >>  3
        | (cdBlocks.dBlock & 0x0000000000000040 /* 2^ 6 */) << 19
        | (cdBlocks.dBlock & 0x0000000000001000 /* 2^12 */) << 12

        | ((uint64_t)cdBlocks.dBlock & 0x0000000000020000 /* 2^17 */) << 22
        | ((uint64_t)cdBlocks.dBlock & 0x0000000080880000 /* 2^31 | 2^23 | 2^19 */) << 15
        | ((uint64_t)cdBlocks.dBlock & 0x0000000000000488 /* 2^10 | 2^ 7 | 2^ 3 */) << 34
        | ((uint64_t)cdBlocks.dBlock & 0x0000000000100000 /* 2^20 */) << 16

        | ((uint64_t)cdBlocks.dBlock & 0x0000000000000100 /* 2^ 8 */) << 27
        | ((uint64_t)cdBlocks.dBlock & 0x0000000000002800 /* 2^13 | 2^11 */) << 20
        | ((uint64_t)cdBlocks.dBlock & 0x0000000010000000 /* 2^28 */) <<  4
        | ((uint64_t)cdBlocks.dBlock & 0x0000000000000004 /* 2^ 2 */) << 45

        | ((uint64_t)cdBlocks.dBlock & 0x0000000000400000 /* 2^22 */) << 23
        | ((uint64_t)cdBlocks.dBlock & 0x0000000000040000 /* 2^18 */) << 25
        | ((uint64_t)cdBlocks.dBlock & 0x0000000000000001 /* 2^ 0 */) << 42
        | ((uint64_t)cdBlocks.dBlock & 0x0000000000000010 /* 2^ 4 */) << 36;
}

static void SingleDesKeySchedule(__in uint64_t extendedKey, __out uint64_t* roundKeys)
{
    assert(roundKeys);

    CDBlocks cdBlocks = DesGetZeroCDBlocks(DesGetExtendedKeyPermutation(extendedKey));
    roundKeys[0] = DesGetRoundKey(cdBlocks = DesGetRoundCDBlocksOne(cdBlocks));
    roundKeys[1] = DesGetRoundKey(cdBlocks = DesGetRoundCDBlocksOne(cdBlocks));
    roundKeys[2] = DesGetRoundKey(cdBlocks = DesGetRoundCDBlocksTwo(cdBlocks));
    roundKeys[3] = DesGetRoundKey(cdBlocks = DesGetRoundCDBlocksTwo(cdBlocks));
    roundKeys[4] = DesGetRoundKey(cdBlocks = DesGetRoundCDBlocksTwo(cdBlocks));
    roundKeys[5] = DesGetRoundKey(cdBlocks = DesGetRoundCDBlocksTwo(cdBlocks));
    roundKeys[6] = DesGetRoundKey(cdBlocks = DesGetRoundCDBlocksTwo(cdBlocks));
    roundKeys[7] = DesGetRoundKey(cdBlocks = DesGetRoundCDBlocksTwo(cdBlocks));
    roundKeys[8] = DesGetRoundKey(cdBlocks = DesGetRoundCDBlocksOne(cdBlocks));
    roundKeys[9] = DesGetRoundKey(cdBlocks = DesGetRoundCDBlocksTwo(cdBlocks));
    roundKeys[10] = DesGetRoundKey(cdBlocks = DesGetRoundCDBlocksTwo(cdBlocks));
    roundKeys[11] = DesGetRoundKey(cdBlocks = DesGetRoundCDBlocksTwo(cdBlocks));
    roundKeys[12] = DesGetRoundKey(cdBlocks = DesGetRoundCDBlocksTwo(cdBlocks));
    roundKeys[13] = DesGetRoundKey(cdBlocks = DesGetRoundCDBlocksTwo(cdBlocks));
    roundKeys[14] = DesGetRoundKey(cdBlocks = DesGetRoundCDBlocksTwo(cdBlocks));
    roundKeys[15] = DesGetRoundKey(DesGetRoundCDBlocksOne(cdBlocks));
}

static void TripleDesKeySchedule(__in const uint64_t* extendedKeys, __out uint64_t* roundKeys)
{
    assert(roundKeys);

    SingleDesKeySchedule(*extendedKeys++, roundKeys);
    SingleDesKeySchedule(*extendedKeys++, roundKeys + DES_ROUND_KEYS_NUMBER);
    SingleDesKeySchedule(*extendedKeys, roundKeys + DES_ROUND_KEYS_NUMBER_X2);
}

void DesKeySchedule(__in BlockCipherType cipher, __in const uint64_t* key, __out uint64_t* roundKeys)
{
    assert(key && roundKeys);

    switch (cipher) {
    case DES_cipher_type:
        SingleDesKeySchedule(*key, roundKeys);
        break;
    case TDES_cipher_type:
        TripleDesKeySchedule(key, roundKeys);
        break;
    default:
        break;
    }
}

// Feistel block

static inline uint64_t DesFeistelExtention(uint32_t r)
{
    /*
        32	1	2	3	4	5
        4	5	6	7	8	9
        8	9	10	11	12	13
        12	13	14	15	16	17
        16	17	18	19	20	21
        20	21	22	23	24	25
        24	25	26	27	28	29
        28	29	30	31	32	1
    */

    return
          ((uint64_t)r & 0x0000000000000080) << 33 | ((uint64_t)r & 0x000000001f000000) << 17
        | ((uint64_t)r & 0x0000000018010000) << 19 | ((uint64_t)r & 0x00000000e0000000) <<  3
        | ((uint64_t)r & 0x0000000080180000) <<  5 | ((uint64_t)r & 0x0000000000070000) << 21
        | ((uint64_t)r & 0x0000000000f80000) <<  7 | ((uint64_t)r & 0x0000000000000100) << 23
        | ((uint64_t)r & 0x0000000000800000) >>  7 | ((uint64_t)r & 0x0000000000001f00) <<  9
        | ((uint64_t)r & 0x0000000000001801) << 11 | ((uint64_t)r & 0x000000000000e000) >>  5
        | ((uint64_t)r & 0x0000000000008018) >>  3 | ((uint64_t)r & 0x0000000000000007) << 13
        | ((uint64_t)r & 0x00000000000000f8) >>  1 | ((uint64_t)r & 0x0000000001000000) >> 17;
}

const uint8_t DES_S_TRANSFORM_OPTIMIZED[8][64] =
{
    {
        14,  0,  4, 15, 13,  7,  1,  4,  2, 14, 15,  2, 11, 13,  8,  1,
         3, 10, 10,  6,  6, 12, 12, 11,  5,  9,  9,  5,  0,  3,  7,  8,
         4, 15,  1, 12, 14,  8,  8,  2, 13,  4,  6,  9,  2,  1, 11,  7,
        15,  5, 12, 11,  9,  3,  7, 14,  3, 10, 10,  0,  5,  6,  0 , 13
    },

    {
        15,  3,  1, 13,  8,  4, 14,  7,  6, 15, 11,  2,  3,  8,  4, 14,
         9, 12,  7,  0,  2,  1, 13, 10, 12,  6,  0,  9,  5, 11, 10,  5,
         0, 13, 14,  8,  7, 10, 11,  1, 10,  3,  4, 15, 13,  4,  1,  2,
         5, 11,  8,  6, 12,  7,  6, 12,  9,  0,  3,  5,  2, 14, 15,  9
    },

    {
        10, 13,  0,  7,  9,  0, 14,  9,  6,  3,  3,  4, 15,  6,  5, 10,
         1,  2, 13,  8, 12,  5,  7, 14, 11, 12,  4, 11,  2, 15,  8,  1,
        13,  1,  6, 10,  4, 13,  9,  0,  8,  6, 15,  9,  3,  8,  0,  7,
        11,  4,  1, 15,  2, 14, 12,  3,  5, 11, 10,  5, 14,  2,  7, 12
    },

    {
         7, 13, 13,  8, 14, 11,  3,  5,  0,  6,  6, 15,  9,  0, 10,  3,
         1,  4,  2,  7,  8,  2,  5, 12, 11,  1, 12, 10,  4, 14, 15,  9,
        10,  3,  6, 15,  9,  0,  0,  6, 12, 10, 11,  1,  7, 13, 13,  8,
        15,  9,  1,  4,  3,  5, 14, 11,  5, 12,  2,  7,  8,  2,  4, 14
    },

    {
         2, 14, 12, 11,  4,  2,  1, 12,  7,  4, 10,  7, 11, 13,  6,  1,
         8,  5,  5,  0,  3, 15, 15, 10, 13,  3,  0,  9, 14,  8,  9,  6,
         4, 11,  2,  8,  1, 12, 11,  7, 10,  1, 13, 14,  7,  2,  8, 13,
        15,  6,  9, 15, 12,  0,  5,  9,  6, 10,  3,  4,  0,  5, 14,  3
    },

    {
        12, 10,  1, 15, 10,  4, 15,  2,  9,  7,  2, 12,  6,  9,  8,  5,
         0,  6, 13,  1,  3, 13,  4, 14, 14,  0,  7, 11,  5,  3, 11,  8,
         9,  4, 14,  3, 15,  2,  5, 12,  2,  9,  8,  5, 12, 15,  3, 10,
         7, 11,  0, 14,  4,  1, 10,  7,  1,  6, 13,  0, 11,  8,  6, 13
    },

    {
         4, 13, 11,  0,  2, 11, 14,  7, 15,  4,  0,  9,  8,  1, 13, 10,
         3, 14, 12,  3,  9,  5,  7, 12,  5,  2, 10, 15,  6,  8,  1,  6,
         1,  6,  4, 11, 11, 13, 13,  8, 12,  1,  3,  4,  7, 10, 14,  7,
        10,  9, 15,  5,  6,  0,  8, 15,  0, 14,  5,  2,  9,  3,  2, 12
    },

    {
        13,  1,  2, 15,  8, 13,  4,  8,  6, 10, 15,  3, 11,  7,  1,  4,
        10, 12,  9,  5,  3,  6, 14, 11,  5,  0,  0, 14, 12,  9,  7,  2,
         7,  2, 11,  1,  4, 14,  1,  7,  9,  4, 12, 10, 14,  8,  2, 13,
         0, 15,  6, 12, 10,  9, 13,  0, 15,  3,  3,  5,  5,  6,  8, 11
    }
};

static inline uint32_t DesSTransform(uint64_t allB)
{
    return
          (DES_S_TRANSFORM_OPTIMIZED[0][(allB & 0x00000000000000fc) >>  2                                    ] <<  4)
        |  DES_S_TRANSFORM_OPTIMIZED[1][(allB & 0x0000000000000003) <<  4 | (allB & 0x000000000000f000) >> 12]
        | (DES_S_TRANSFORM_OPTIMIZED[2][(allB & 0x0000000000000f00) >>  6 | (allB & 0x0000000000c00000) >> 22] << 12)
        | (DES_S_TRANSFORM_OPTIMIZED[3][(allB & 0x00000000003f0000) >> 16                                    ] <<  8)

        | (DES_S_TRANSFORM_OPTIMIZED[4][(allB & 0x00000000fc000000) >> 26                                    ] << 20)
        | (DES_S_TRANSFORM_OPTIMIZED[5][(allB & 0x0000000003000000) >> 20 | (allB & 0x000000f000000000) >> 36] << 16)
        | (DES_S_TRANSFORM_OPTIMIZED[6][(allB & 0x0000000f00000000) >> 30 | (allB & 0x0000c00000000000) >> 46] << 28)
        | (DES_S_TRANSFORM_OPTIMIZED[7][(allB & 0x00003f0000000000) >> 40                                    ] << 24);
}

static inline uint32_t DesFeistelPermutation(uint32_t transformed) // correct
{
    /*
        16	7	20	21	29	12	28	17
        1	15	23	26	5	18	31	10
        2	8	24	14	32	27	3	9
        19	13	30	6	22	11	4	25
    */

    return
          (transformed & 0x0000000000000100 /* 2^ 8 */) >>  1
        | (transformed & 0x0000000000010202 /* 2^16 | 2^ 9 | 2^ 1 */) <<  5
        | (transformed & 0x0000000000180000 /* 2^20 | 2^19 */) >> 15
        | (transformed & 0x0000000008000000 /* 2^27 */) >> 24
        
        | (transformed & 0x0000000000001000 /* 2^12 */) >> 10
        | (transformed & 0x0000000010000000 /* 2^28 */) >> 27
        | (transformed & 0x0000000000800000 /* 2^23 */) >> 23
        | (transformed & 0x0000000000000088 /* 2^ 7 | 2^ 3 */) <<  8

        | (transformed & 0x0000000000020000 /* 2^17 */) >>  4
        | (transformed & 0x0000000040000000 /* 2^30 */) >> 18
        | (transformed & 0x0000000000400000 /* 2^22 */) >> 12
        | (transformed & 0x0000000002000000 /* 2^25 */) >> 16
        
        | (transformed & 0x0000000000004000 /* 2^14 */) >>  6
        | (transformed & 0x0000000000000040 /* 2^ 6 */) << 17
        | (transformed & 0x0000000000000001 /* 2^ 0 */) << 22
        | (transformed & 0x0000000000200400 /* 2^21 | 2^10 */) << 10

        | (transformed & 0x0000000001000000 /* 2^24 */) >>  5
        | (transformed & 0x0000000020000000 /* 2^29 */) >> 11
        | (transformed & 0x0000000000000020 /* 2^ 5 */) << 12
        | (transformed & 0x0000000000008000 /* 2^15 */) <<  1

        | (transformed & 0x0000000000000800 /* 2^11 */) << 19
        | (transformed & 0x0000000004000000 /* 2^26 */) <<  3
        | (transformed & 0x0000000000000004 /* 2^ 2 */) << 26
        | (transformed & 0x0000000000040000 /* 2^18 */) <<  9
        
        | (transformed & 0x0000000000002000 /* 2^13 */) << 13
        | (transformed & 0x0000000000000010 /* 2^ 4 */) << 21
        | (transformed & 0x0000000080000000 /* 2^31 */) >>  7;
}

static inline uint32_t DesFeistelFunc(uint32_t r, uint64_t roundKey)
{
    return DesFeistelPermutation(DesSTransform(DesFeistelExtention(r) ^ roundKey));
}

// Additional Permutations

static inline uint64_t DesInitialPermutation(uint64_t input)
{
    /*
        58	50	42	34	26	18	10	2	60	52	44	36	28	20	12	4
        62	54	46	38	30	22	14	6	64	56	48	40	32	24	16	8
        57	49	41	33	25	17	9	1	59	51	43	35	27	19	11	3
        61	53	45	37	29	21	13	5	63	55	47	39	31	23	15	7
    */

    return
          (input & 0x4000000000000000 /* 2^62 */) >> 55
        | (input & 0x0040000000000000 /* 2^54 */) >> 48
        | (input & 0x0000400000000000 /* 2^46 */) >> 41
        | (input & 0x0000004000000000 /* 2^38 */) >> 34
        | (input & 0x0000000040000000 /* 2^30 */) >> 27
        | (input & 0x0000000000400000 /* 2^22 */) >> 20
        | (input & 0x0000000000004000 /* 2^14 */) >> 13
        | (input & 0x0000000000000040 /* 2^ 6 */) >>  6

        | (input & 0x1000000000000000 /* 2^60 */) >> 45
        | (input & 0x0010000000000000 /* 2^52 */) >> 38
        | (input & 0x0000100000000000 /* 2^44 */) >> 31
        | (input & 0x8000001000000000 /* 2^63 | 2^36 */) >> 24
        | (input & 0x0080000010000000 /* 2^55 | 2^28 */) >> 17
        | (input & 0x0000800000100000 /* 2^47 | 2^20 */) >> 10
        | (input & 0x0000008000001000 /* 2^39 | 2^12 */) >>  3
        | (input & 0x0000000000000010 /* 2^ 4 */) <<  4

        | (input & 0x0400000000000000 /* 2^58 */) >> 35
        | (input & 0x0004000000000000 /* 2^50 */) >> 28
        | (input & 0x0000040000000000 /* 2^42 */) >> 21
        | (input & 0x2000000400000000 /* 2^61 | 2^34 */) >> 14
        | (input & 0x0020000004000000 /* 2^53 | 2^26 */) >>  7
        | (input & 0x0000200000040000 /* 2^45 | 2^18 */)      
        | (input & 0x0000002000000400 /* 2^37 | 2^10 */) <<  7
        | (input & 0x0000000020000004 /* 2^29 | 2^ 2 */) << 14

        | (input & 0x0100000000000000 /* 2^56 */) >> 25
        | (input & 0x0001000000000000 /* 2^48 */) >> 18
        | (input & 0x0000010000000000 /* 2^40 */) >> 11
        | (input & 0x0800000100000000 /* 2^59 | 2^32 */) >>  4
        | (input & 0x0008000001000000 /* 2^51 | 2^24 */) <<  3
        | (input & 0x0000080000010000 /* 2^43 | 2^16 */) << 10
        | (input & 0x0000000800000100 /* 2^35 | 2^ 8 */) << 17
        | (input & 0x0000000008000001 /* 2^27 | 2^ 0 */) << 24

        | (input & 0x0000000080000000 /* 2^31 */) <<  4
        | (input & 0x0000000000800000 /* 2^23 */) << 11
        | (input & 0x0000000000008000 /* 2^15 */) << 18
        | (input & 0x0000000000000080 /* 2^7  */) << 25

        | (input & 0x0000000000200000 /* 2^21 */) << 21
        | (input & 0x0000000000002000 /* 2^13 */) << 28
        | (input & 0x0000000000000020 /* 2^5  */) << 35

        | (input & 0x0000000000080000 /* 2^19 */) << 31
        | (input & 0x0000000000000800 /* 2^11 */) << 38
        | (input & 0x0000000000000008 /* 2^3  */) << 45

        | (input & 0x0200000000000000 /* 2^57 */) <<  6
        | (input & 0x0002000000000000 /* 2^49 */) << 13
        | (input & 0x0000020000000000 /* 2^41 */) << 20
        | (input & 0x0000000200000000 /* 2^33 */) << 27
        | (input & 0x0000000002000000 /* 2^25 */) << 34
        | (input & 0x0000000000020000 /* 2^17 */) << 41
        | (input & 0x0000000000000200 /* 2^9  */) << 48
        | (input & 0x0000000000000002 /* 2^1  */) << 55;
}

static inline uint64_t DesFinalPermutation(uint64_t encryptedBlock)
{
    /*
        40	8	48	16	56	24	64	32	39	7	47	15	55	23	63	31
        38	6	46	14	54	22	62	30	37	5	45	13	53	21	61	29
        36	4	44	12	52	20	60	28	35	3	43	11	51	19	59	27
        34	2	42	10	50	18	58	26	33	1	41	9	49	17	57	25
    */

    return
          (encryptedBlock & 0x0000000100000000 /* 2^32 */) >> 25
        | (encryptedBlock & 0x0000000000000001 /* 2^ 0 */) <<  6
        | (encryptedBlock & 0x0000010000000000 /* 2^40 */) >> 35
        | (encryptedBlock & 0x0000000800000100 /* 2^35 | 2^ 8 */) >>  4
        | (encryptedBlock & 0x0001000000000000 /* 2^48 */) >> 45
        | (encryptedBlock & 0x0000080000010000 /* 2^43 | 2^16 */) >> 14
        | (encryptedBlock & 0x0100000000000000 /* 2^56 */) >> 55
        | (encryptedBlock & 0x0008000001000000 /* 2^51 | 2^24 */) >> 24

        | (encryptedBlock & 0x0000000200000000 /* 2^33 */) >> 18
        | (encryptedBlock & 0x0000000000000002 /* 2^ 1 */) << 13
        | (encryptedBlock & 0x0000020000000000 /* 2^41 */) >> 28
        | (encryptedBlock & 0x0000001000000200 /* 2^36 | 2^ 9 */) <<  3

        | (encryptedBlock & 0x0002000000000000 /* 2^49 */) >> 38
        | (encryptedBlock & 0x0000100000020000 /* 2^44 | 2^17 */) >>  7
        | (encryptedBlock & 0x0200000000000000 /* 2^57 */) >> 48
        | (encryptedBlock & 0x0010000002000000 /* 2^52 | 2^25 */) >> 17

        | (encryptedBlock & 0x0000000400000000 /* 2^34 */) >> 11
        | (encryptedBlock & 0x0000000000000004 /* 2^ 2 */) << 20
        | (encryptedBlock & 0x0000040000000000 /* 2^42 */) >> 21
        | (encryptedBlock & 0x0000002000000400 /* 2^37 | 2^10 */) << 10
        | (encryptedBlock & 0x0004000000000000 /* 2^50 */) >> 31
        | (encryptedBlock & 0x0000200000040000 /* 2^45 | 2^18 */)      
        | (encryptedBlock & 0x0400000000000000 /* 2^58 */) >> 41
        | (encryptedBlock & 0x0020000004000000 /* 2^53 | 2^26 */) >> 10

        | (encryptedBlock & 0x0000000000000008 /* 2^ 3 */) << 27
        | (encryptedBlock & 0x0000004000000800 /* 2^38 | 2^11 */) << 17
        | (encryptedBlock & 0x0000400000080000 /* 2^46 | 2^19 */) <<  7
        | (encryptedBlock & 0x0800000000000000 /* 2^59 */) >> 34
        | (encryptedBlock & 0x0040000008000000 /* 2^54 | 2^27 */) >>  3

        | (encryptedBlock & 0x0000000000000010 /* 2^ 4 */) << 34
        | (encryptedBlock & 0x0000008000001000 /* 2^39 | 2^12 */) << 24
        | (encryptedBlock & 0x0000800000100000 /* 2^47 | 2^20 */) << 14
        | (encryptedBlock & 0x1000000000000000 /* 2^60 */) >> 27
        | (encryptedBlock & 0x0080000010000000 /* 2^55 | 2^28 */) <<  4

        | (encryptedBlock & 0x0000000000000020 /* 2^ 5 */) << 41
        | (encryptedBlock & 0x0000000000002000 /* 2^13 */) << 31
        | (encryptedBlock & 0x0020000000000000 /* 2^53 */) >> 10
        | (encryptedBlock & 0x0000000000200000 /* 2^21 */) << 21
        | (encryptedBlock & 0x2000000000000000 /* 2^61 */) >> 20
        | (encryptedBlock & 0x0000000020000000 /* 2^29 */) << 11

        | (encryptedBlock & 0x0000000000000040 /* 2^ 6 */) << 48
        | (encryptedBlock & 0x0000000000004000 /* 2^14 */) << 38
        | (encryptedBlock & 0x0000000000400000 /* 2^22 */) << 28
        | (encryptedBlock & 0x4000000000000000 /* 2^62 */) >> 13
        | (encryptedBlock & 0x0000000040000000 /* 2^30 */) << 18

        | (encryptedBlock & 0x0000000000000080 /* 2^ 7 */) << 55
        | (encryptedBlock & 0x0000000000008000 /* 2^15 */) << 45
        | (encryptedBlock & 0x0000000000800000 /* 2^23 */) << 35
        | (encryptedBlock & 0x8000000000000000 /* 2^63 */) >>  6
        | (encryptedBlock & 0x0000000080000000 /* 2^31 */) << 25;
}

// Main algo block

static uint64_t DesEncryptBlock(const uint64_t* roundKeys, const uint64_t input)
{
    assert(roundKeys);

    uint64_t permInput = DesInitialPermutation(input);

    for (int i = 0; i < DES_ROUND_KEYS_NUMBER; ++i)
        permInput = (permInput >> 32) | ((DesFeistelFunc(permInput >> 32, roundKeys[i]) ^ permInput) << 32);

    permInput = permInput >> 32 | permInput << 32;

    return DesFinalPermutation(permInput);
}

static uint64_t DesDecryptBlock(const uint64_t* roundKeys, const uint64_t input)
{
    assert(roundKeys);

    uint64_t permInput = DesInitialPermutation(input);

    permInput = permInput >> 32 | permInput << 32;

    for (int i = DES_ROUND_KEYS_NUMBER - 1; i >= 0; --i)
        permInput = (permInput << 32) | (DesFeistelFunc((uint32_t)permInput, roundKeys[i]) ^ (permInput >> 32));

    return DesFinalPermutation(permInput);
}

static uint64_t TdesEncryptBlock(const uint64_t* roundKeys, const uint64_t input)
{
    assert(roundKeys);

    return DesEncryptBlock(roundKeys + DES_ROUND_KEYS_NUMBER_X2, DesDecryptBlock(roundKeys + DES_ROUND_KEYS_NUMBER, DesEncryptBlock(roundKeys, input)));
}

static uint64_t TdesDecryptBlock(const uint64_t* roundKeys, const uint64_t input)
{
    assert(roundKeys);

    return DesDecryptBlock(roundKeys, DesEncryptBlock(roundKeys + DES_ROUND_KEYS_NUMBER, DesDecryptBlock(roundKeys + DES_ROUND_KEYS_NUMBER_X2, input)));
}

int DesEncrypt(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding, __in const uint64_t* input, __in size_t inputSize
    , __in bool finalize, __out_opt uint64_t* output, __inout size_t* outputSize)
{
    assert(input && outputSize);

    int status = NO_ERROR;

    if (!finalize) {
        if (inputSize & 7)
            return ERROR_WRONG_INPUT_SIZE;
        else
            *outputSize = inputSize;
    }
    else if ((status = AddPaddingInternal(input, inputSize, padding, DES_BLOCK_SIZE, output, outputSize, true)))
        return status;

    assert((*outputSize & 7) == 0);

    DesEncDecFunction func = NULL;
    uint64_t* roundKeys = NULL;
    uint64_t iv = 0;

    if (cipher == DES_cipher_type) {
        func = DesEncryptBlock;
        roundKeys = ((DesState*)state)->roundKeys;
        iv = ((DesState*)state)->iv;
    }
    else {
        func = TdesEncryptBlock;
        roundKeys = ((TdesState*)state)->roundKeys;
        iv = ((TdesState*)state)->iv;
    }

    uint64_t blocksNumber = *outputSize >> 3; // (outputSize / DES_BLOCK_SIZE) outputSize must be divisible by DES_BLOCK_SIZE without remainder

    switch (opMode) {
    case ECB_mode: {
        while (--blocksNumber)
            *output++ = func(roundKeys, *input++);

        *output = func(roundKeys, finalize ? *output : *input);

        break;
    }

    case CBC_mode: {
        while (--blocksNumber) {
            *output = func(roundKeys, iv ^ *input++);
            iv = *output++;
        }

        *output = func(roundKeys, iv ^ (finalize ? *output : *input));
        iv = *output;

        break;
    }

    case CFB_mode: {
        while (--blocksNumber) {
            *output = func(roundKeys, iv) ^ *input++;
            iv = *output++;
        }

        *output = func(roundKeys, iv) ^ (finalize ? *output : *input);
        iv = *output;

        break;
    }

    case OFB_mode: {
        while (--blocksNumber)
            *output++ = (iv = func(roundKeys, iv)) ^ *input++;

        *output = (iv = func(roundKeys, iv)) ^ (finalize ? *output : *input);

        break;
    }

    case CTR_mode: {
        while (--blocksNumber) {
            *output++ = func(roundKeys, iv) ^ *input++;
            iv = ReverseEndiannessUint64(ReverseEndiannessUint64(iv) + 1); // I'm not sure that approach with Big Endian counter is necessary
                                                                                       // but the other working examplse of des with ctr with which I can compare the result
                                                                                       // has that (based on my calculations).
        }

        *output = func(roundKeys, iv) ^ (finalize ? *output : *input);
        iv = ReverseEndiannessUint64(ReverseEndiannessUint64(iv) + 1);

        break;
    }

    default:
        break;

    }

    if (cipher == DES_cipher_type)
        ((DesState*)state)->iv = iv;
    else
        ((TdesState*)state)->iv = iv;

    return NO_ERROR;
}

int DesDecrypt(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding, __in const uint64_t* input, __in size_t inputSize
    , __in bool finalize, __out_opt uint64_t* output, __inout size_t* outputSize)
{
    assert(input && outputSize);

    int status = NO_ERROR;

    if (inputSize & 7) // (7 == DES_BLOCK_SIZE - 1)
        return ERROR_WRONG_INPUT_SIZE;

    DesEncDecFunction func = NULL;
    uint64_t* roundKeys = NULL;
    uint64_t iv = 0;

    if (cipher == DES_cipher_type) {
        if (opMode == ECB_mode || opMode == CBC_mode)
            func = DesDecryptBlock;
        else
            func = DesEncryptBlock;

        roundKeys = ((DesState*)state)->roundKeys;
        iv = ((DesState*)state)->iv;
    }
    else {
        if (opMode == ECB_mode || opMode == CBC_mode)
            func = TdesDecryptBlock;
        else
            func = TdesEncryptBlock;

        roundKeys = ((TdesState*)state)->roundKeys;
        iv = ((TdesState*)state)->iv;
    }

    uint64_t blocksNumber = inputSize >> 3; // (inputSize / DES_BLOCK_SIZE) inputSize must be divisible by DES_BLOCK_SIZE without remainder
    const uint64_t* lastInputBlock = input + blocksNumber - 1;
    uint64_t lastOutputBlock = 0;
    uint64_t lastIvBlock = 0;

    bool multiBlock = inputSize > DES_BLOCK_SIZE;

    switch (opMode) {
    case ECB_mode:
    case CBC_mode: {
        lastOutputBlock = func(roundKeys , *lastInputBlock);

        if (opMode == CBC_mode) {
            if (multiBlock) {
                lastOutputBlock ^= *(lastInputBlock - 1);
                lastIvBlock = *lastInputBlock;
            }
            else {
                lastOutputBlock ^= iv;
                lastIvBlock = *input;
            }
        }
        break;
    }

    case CFB_mode: {
        if (multiBlock) {
            lastOutputBlock = func(roundKeys, *(lastInputBlock - 1)) ^ *lastInputBlock;
            lastIvBlock = *lastInputBlock;
        }
        else {
            lastOutputBlock = func(roundKeys, iv) ^ *lastInputBlock;
            lastIvBlock = *input;
        }
        break;
    }

    case OFB_mode: {
        // All input processing when OFB_mode must be calculated here
        if (*outputSize >= inputSize) {
            while (blocksNumber--)
                *output++ = (iv = func(roundKeys, iv)) ^ *input++;
            lastOutputBlock = *--output;

            lastIvBlock = iv;
        }
        else {
            *outputSize = inputSize;
            return ERROR_TOO_SMALL_OUTPUT_SIZE;
        }

        break;
    }

    case CTR_mode: {
        lastOutputBlock = func(roundKeys, ReverseEndiannessUint64(ReverseEndiannessUint64(iv) + blocksNumber - 1)) ^ *lastInputBlock;
        lastIvBlock = ReverseEndiannessUint64(ReverseEndiannessUint64(iv) + blocksNumber);

        break;
    }

    default:
        break;

    }

    if (!finalize) {
        if (opMode != OFB_mode)
            *(output + blocksNumber - 1) = lastOutputBlock;

        *outputSize = inputSize;
    } 
    else if ((status = FillLastDecryptedBlockInternal(padding, DES_BLOCK_SIZE, &lastOutputBlock, inputSize, output, outputSize)))
        return status;

    switch (opMode) {
    case ECB_mode: {
        while (--blocksNumber)
            *output++ = func(roundKeys , *input++);

        break;
    }

    case CBC_mode: {
        uint64_t ivBlockNext = 0;

        while (--blocksNumber) {
            ivBlockNext = *input++;
            *output++ = func(roundKeys, ivBlockNext) ^ iv;
            iv = ivBlockNext;
        }

        break;
    }

    case CFB_mode: {
        uint64_t ivBlockNext = 0;

        while (--blocksNumber) {
            ivBlockNext = *input++;
            *output++ = func(roundKeys, iv) ^ ivBlockNext;
            iv = ivBlockNext;
        }

        break;
    }
    
    case OFB_mode:
        break;

    case CTR_mode: {
        while (--blocksNumber) {
            *output++ = func(roundKeys, iv) ^ *input++;
            iv = ReverseEndiannessUint64(ReverseEndiannessUint64(iv) + 1);
        }

        break;
    }

    default:
        break;

    }

    if (cipher == DES_cipher_type)
        ((DesState*)state)->iv = lastIvBlock;
    else
        ((TdesState*)state)->iv = lastIvBlock;

    return NO_ERROR;
}
