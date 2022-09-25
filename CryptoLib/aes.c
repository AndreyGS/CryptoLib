// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/**
 * @file aes.c
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

#include "pch.h"
#include "aes.h"
#include "paddings.h"
#include "crypto_internal.h"
#include "aes_ni.h"

#define AES_DWORDS_IN_ROUNDKEY          4
#define AES128_TOTAL_DWORDS_IN_ROUNDKEYS (AES128_ROUNDKEYS_NUMBER * AES_DWORDS_IN_ROUNDKEY)
#define AES192_TOTAL_DWORDS_IN_ROUNDKEYS (AES192_ROUNDKEYS_NUMBER * AES_DWORDS_IN_ROUNDKEY)
#define AES256_TOTAL_DWORDS_IN_ROUNDKEYS (AES256_ROUNDKEYS_NUMBER * AES_DWORDS_IN_ROUNDKEY)

typedef void (*AesProcessingBlockFunction)(__in_opt const uint64_t* roundKeys, __in const uint64_t* input, __out uint64_t* output);

const uint8_t AES_S_BOX[256] = 
{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t AES_S_BOX_INV[256] =
{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

const uint32_t R_CONSTANTS[10] =
{
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static void AesKeyScheduleSoftware(__in BlockCipherType cipher, __in const uint32_t* key, __out uint32_t* roundKeys)
{
    assert(key && roundKeys);
    
    int dwordsTotal = 0;
    int dwordsInKey = 0;
    int i = -1;
    uint32_t t = 0;
    
    switch (cipher) {
    case AES128_cipher_type:
        dwordsTotal = AES128_TOTAL_DWORDS_IN_ROUNDKEYS;
        dwordsInKey = 4;
        break;
    case AES192_cipher_type:
        dwordsTotal = AES192_TOTAL_DWORDS_IN_ROUNDKEYS;
        dwordsInKey = 6;
        break;
    case AES256_cipher_type:
        dwordsTotal = AES256_TOTAL_DWORDS_IN_ROUNDKEYS;
        dwordsInKey = 8;
        break;
    }

    while (++i < dwordsInKey)
        roundKeys[i] = key[i];
    
    --i;

    while (i < dwordsTotal) {
        t = roundKeys[i++];
        if (i % dwordsInKey == 0) {
            t = Uint32BigEndianRightRotate(t, 8);
            t = (AES_S_BOX[((uint8_t*)&t)[0]] | (AES_S_BOX[((uint8_t*)&t)[1]] << 8) | (AES_S_BOX[((uint8_t*)&t)[2]] << 16) | (AES_S_BOX[((uint8_t*)&t)[3]] << 24)) ^ R_CONSTANTS[(i / dwordsInKey) - 1];
        }
        else if (dwordsInKey == 8 && (i & 3) == 0)
            t = (AES_S_BOX[((uint8_t*)&t)[0]] | (AES_S_BOX[((uint8_t*)&t)[1]] << 8) | (AES_S_BOX[((uint8_t*)&t)[2]] << 16) | (AES_S_BOX[((uint8_t*)&t)[3]] << 24));

        roundKeys[i] = roundKeys[i - dwordsInKey] ^ t;
    }
}

void AesKeySchedule(__in BlockCipherType cipher, __in const uint64_t* key, __in HardwareFeatures hwFeatures, __out void* specificCipherState)
{
    if (hwFeatures.avx) {
        if (cipher == AES128_cipher_type)
            Aes128AvxKeySchedule(key, specificCipherState, ((Aes128AvxState*)specificCipherState)->decryptionRoundKeys);
        else if (cipher == AES192_cipher_type)
            Aes192AvxKeySchedule(key, specificCipherState, ((Aes192AvxState*)specificCipherState)->decryptionRoundKeys);
        else
            Aes256AvxKeySchedule(key, specificCipherState, ((Aes256AvxState*)specificCipherState)->decryptionRoundKeys);
    }
    else if (hwFeatures.aesni) {
        if (cipher == AES128_cipher_type)
            Aes128NiKeySchedule(key, specificCipherState, ((Aes128NiState*)specificCipherState)->decryptionRoundKeys);
        else if (cipher == AES192_cipher_type)
            Aes192NiKeySchedule(key, specificCipherState, ((Aes192NiState*)specificCipherState)->decryptionRoundKeys);
        else
            Aes256NiKeySchedule(key, specificCipherState, ((Aes256NiState*)specificCipherState)->decryptionRoundKeys);
    }
    else
        AesKeyScheduleSoftware(cipher, (uint32_t*)key, specificCipherState);
}

static inline void AesSubBytes(__inout uint8_t* input)
{
    assert(input);

    input[0] =  AES_S_BOX[input[0]],  input[1] =  AES_S_BOX[input[1]],  input[2] =  AES_S_BOX[input[2]],  input[3] =  AES_S_BOX[input[3]],
    input[4] =  AES_S_BOX[input[4]],  input[5] =  AES_S_BOX[input[5]],  input[6] =  AES_S_BOX[input[6]],  input[7] =  AES_S_BOX[input[7]],
    input[8] =  AES_S_BOX[input[8]],  input[9] =  AES_S_BOX[input[9]],  input[10] = AES_S_BOX[input[10]], input[11] = AES_S_BOX[input[11]],
    input[12] = AES_S_BOX[input[12]], input[13] = AES_S_BOX[input[13]], input[14] = AES_S_BOX[input[14]], input[15] = AES_S_BOX[input[15]];
}

static inline void AesSubBytesInv(__inout uint8_t* input)
{
    assert(input);

    input[0] =  AES_S_BOX_INV[input[0]],  input[1] =  AES_S_BOX_INV[input[1]],  input[2] =  AES_S_BOX_INV[input[2]],  input[3] =  AES_S_BOX_INV[input[3]],
    input[4] =  AES_S_BOX_INV[input[4]],  input[5] =  AES_S_BOX_INV[input[5]],  input[6] =  AES_S_BOX_INV[input[6]],  input[7] =  AES_S_BOX_INV[input[7]],
    input[8] =  AES_S_BOX_INV[input[8]],  input[9] =  AES_S_BOX_INV[input[9]],  input[10] = AES_S_BOX_INV[input[10]], input[11] = AES_S_BOX_INV[input[11]],
    input[12] = AES_S_BOX_INV[input[12]], input[13] = AES_S_BOX_INV[input[13]], input[14] = AES_S_BOX_INV[input[14]], input[15] = AES_S_BOX_INV[input[15]];
}

static inline void AesShiftRows(__inout uint8_t* input)
{
    assert(input);

    uint8_t temp = input[1];

    input[1] = input[5], input[5] = input[9], input[9] = input[13], input[13] = temp,
    temp = input[2], input[2] = input[10], input[10] = temp, temp = input[6], input[6] = input[14], input[14] = temp,
    temp = input[3], input[3] = input[15], input[15] = input[11], input[11] = input[7], input[7] = temp;
}

static inline void AesShiftRowsInv(__inout uint8_t* input)
{
    assert(input);

    uint8_t temp = input[1];

    input[1] = input[13], input[13] = input[9], input[9] = input[5], input[5] = temp,
    temp = input[2], input[2] = input[10], input[10] = temp, temp = input[6], input[6] = input[14], input[14] = temp,
    temp = input[3], input[3] = input[7], input[7] = input[11], input[11] = input[15], input[15] = temp;
}


const uint8_t AES_MC_PRECALCULETED_CONSTS_X2[256] =
{
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
    0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
    0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
    0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
    0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
    0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
    0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
    0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
    0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
    0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
    0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
    0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
    0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
    0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
    0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
    0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5
};

const uint8_t AES_MC_PRECALCULETED_CONSTS_X3[256] =
{
    0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11,
    0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39, 0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21,
    0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71,
    0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d, 0x44, 0x47, 0x42, 0x41,
    0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9, 0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1,
    0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
    0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd, 0xb4, 0xb7, 0xb2, 0xb1,
    0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99, 0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81,
    0x9b, 0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a,
    0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6, 0xbf, 0xbc, 0xb9, 0xba,
    0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2, 0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea,
    0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda,
    0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4f, 0x4c, 0x49, 0x4a,
    0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a,
    0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a,
    0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1f, 0x1c, 0x19, 0x1a
};

static inline void AesMixColumns(__inout uint8_t* input)
{
    assert(input);

    uint8_t output[4] = { 0 };

    for (int i = 0; i < 4; ++i) {
        output[0] = AES_MC_PRECALCULETED_CONSTS_X2[input[0]] ^ AES_MC_PRECALCULETED_CONSTS_X3[input[1]] ^ input[2] ^ input[3];
        output[1] = input[0] ^ AES_MC_PRECALCULETED_CONSTS_X2[input[1]] ^ AES_MC_PRECALCULETED_CONSTS_X3[input[2]] ^ input[3];
        output[2] = input[0] ^ input[1] ^ AES_MC_PRECALCULETED_CONSTS_X2[input[2]] ^ AES_MC_PRECALCULETED_CONSTS_X3[input[3]];
        output[3] = AES_MC_PRECALCULETED_CONSTS_X3[input[0]] ^ input[1] ^ input[2] ^ AES_MC_PRECALCULETED_CONSTS_X2[input[3]];

        *((uint32_t*)input)++ = *(uint32_t*)output;
    }
}

const uint8_t AES_MC_PRECALCULETED_CONSTS_X9[256] =
{
    0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f, 0x48, 0x41, 0x5a, 0x53, 0x6c, 0x65, 0x7e, 0x77,
    0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf, 0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5, 0xee, 0xe7,
    0x3b, 0x32, 0x29, 0x20, 0x1f, 0x16, 0x0d, 0x04, 0x73, 0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c,
    0xab, 0xa2, 0xb9, 0xb0, 0x8f, 0x86, 0x9d, 0x94, 0xe3, 0xea, 0xf1, 0xf8, 0xc7, 0xce, 0xd5, 0xdc,
    0x76, 0x7f, 0x64, 0x6d, 0x52, 0x5b, 0x40, 0x49, 0x3e, 0x37, 0x2c, 0x25, 0x1a, 0x13, 0x08, 0x01,
    0xe6, 0xef, 0xf4, 0xfd, 0xc2, 0xcb, 0xd0, 0xd9, 0xae, 0xa7, 0xbc, 0xb5, 0x8a, 0x83, 0x98, 0x91,
    0x4d, 0x44, 0x5f, 0x56, 0x69, 0x60, 0x7b, 0x72, 0x05, 0x0c, 0x17, 0x1e, 0x21, 0x28, 0x33, 0x3a,
    0xdd, 0xd4, 0xcf, 0xc6, 0xf9, 0xf0, 0xeb, 0xe2, 0x95, 0x9c, 0x87, 0x8e, 0xb1, 0xb8, 0xa3, 0xaa,
    0xec, 0xe5, 0xfe, 0xf7, 0xc8, 0xc1, 0xda, 0xd3, 0xa4, 0xad, 0xb6, 0xbf, 0x80, 0x89, 0x92, 0x9b,
    0x7c, 0x75, 0x6e, 0x67, 0x58, 0x51, 0x4a, 0x43, 0x34, 0x3d, 0x26, 0x2f, 0x10, 0x19, 0x02, 0x0b,
    0xd7, 0xde, 0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8, 0x9f, 0x96, 0x8d, 0x84, 0xbb, 0xb2, 0xa9, 0xa0,
    0x47, 0x4e, 0x55, 0x5c, 0x63, 0x6a, 0x71, 0x78, 0x0f, 0x06, 0x1d, 0x14, 0x2b, 0x22, 0x39, 0x30,
    0x9a, 0x93, 0x88, 0x81, 0xbe, 0xb7, 0xac, 0xa5, 0xd2, 0xdb, 0xc0, 0xc9, 0xf6, 0xff, 0xe4, 0xed,
    0x0a, 0x03, 0x18, 0x11, 0x2e, 0x27, 0x3c, 0x35, 0x42, 0x4b, 0x50, 0x59, 0x66, 0x6f, 0x74, 0x7d,
    0xa1, 0xa8, 0xb3, 0xba, 0x85, 0x8c, 0x97, 0x9e, 0xe9, 0xe0, 0xfb, 0xf2, 0xcd, 0xc4, 0xdf, 0xd6,
    0x31, 0x38, 0x23, 0x2a, 0x15, 0x1c, 0x07, 0x0e, 0x79, 0x70, 0x6b, 0x62, 0x5d, 0x54, 0x4f, 0x46
};

const uint8_t AES_MC_PRECALCULETED_CONSTS_X11[256] =
{
    0x00, 0x0b, 0x16, 0x1d, 0x2c, 0x27, 0x3a, 0x31, 0x58, 0x53, 0x4e, 0x45, 0x74, 0x7f, 0x62, 0x69,
    0xb0, 0xbb, 0xa6, 0xad, 0x9c, 0x97, 0x8a, 0x81, 0xe8, 0xe3, 0xfe, 0xf5, 0xc4, 0xcf, 0xd2, 0xd9,
    0x7b, 0x70, 0x6d, 0x66, 0x57, 0x5c, 0x41, 0x4a, 0x23, 0x28, 0x35, 0x3e, 0x0f, 0x04, 0x19, 0x12,
    0xcb, 0xc0, 0xdd, 0xd6, 0xe7, 0xec, 0xf1, 0xfa, 0x93, 0x98, 0x85, 0x8e, 0xbf, 0xb4, 0xa9, 0xa2,
    0xf6, 0xfd, 0xe0, 0xeb, 0xda, 0xd1, 0xcc, 0xc7, 0xae, 0xa5, 0xb8, 0xb3, 0x82, 0x89, 0x94, 0x9f,
    0x46, 0x4d, 0x50, 0x5b, 0x6a, 0x61, 0x7c, 0x77, 0x1e, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2f,
    0x8d, 0x86, 0x9b, 0x90, 0xa1, 0xaa, 0xb7, 0xbc, 0xd5, 0xde, 0xc3, 0xc8, 0xf9, 0xf2, 0xef, 0xe4,
    0x3d, 0x36, 0x2b, 0x20, 0x11, 0x1a, 0x07, 0x0c, 0x65, 0x6e, 0x73, 0x78, 0x49, 0x42, 0x5f, 0x54,
    0xf7, 0xfc, 0xe1, 0xea, 0xdb, 0xd0, 0xcd, 0xc6, 0xaf, 0xa4, 0xb9, 0xb2, 0x83, 0x88, 0x95, 0x9e,
    0x47, 0x4c, 0x51, 0x5a, 0x6b, 0x60, 0x7d, 0x76, 0x1f, 0x14, 0x09, 0x02, 0x33, 0x38, 0x25, 0x2e,
    0x8c, 0x87, 0x9a, 0x91, 0xa0, 0xab, 0xb6, 0xbd, 0xd4, 0xdf, 0xc2, 0xc9, 0xf8, 0xf3, 0xee, 0xe5,
    0x3c, 0x37, 0x2a, 0x21, 0x10, 0x1b, 0x06, 0x0d, 0x64, 0x6f, 0x72, 0x79, 0x48, 0x43, 0x5e, 0x55,
    0x01, 0x0a, 0x17, 0x1c, 0x2d, 0x26, 0x3b, 0x30, 0x59, 0x52, 0x4f, 0x44, 0x75, 0x7e, 0x63, 0x68,
    0xb1, 0xba, 0xa7, 0xac, 0x9d, 0x96, 0x8b, 0x80, 0xe9, 0xe2, 0xff, 0xf4, 0xc5, 0xce, 0xd3, 0xd8,
    0x7a, 0x71, 0x6c, 0x67, 0x56, 0x5d, 0x40, 0x4b, 0x22, 0x29, 0x34, 0x3f, 0x0e, 0x05, 0x18, 0x13,
    0xca, 0xc1, 0xdc, 0xd7, 0xe6, 0xed, 0xf0, 0xfb, 0x92, 0x99, 0x84, 0x8f, 0xbe, 0xb5, 0xa8, 0xa3
};

const uint8_t AES_MC_PRECALCULETED_CONSTS_X13[256] =
{
    0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e, 0x23, 0x68, 0x65, 0x72, 0x7f, 0x5c, 0x51, 0x46, 0x4b,
    0xd0, 0xdd, 0xca, 0xc7, 0xe4, 0xe9, 0xfe, 0xf3, 0xb8, 0xb5, 0xa2, 0xaf, 0x8c, 0x81, 0x96, 0x9b,
    0xbb, 0xb6, 0xa1, 0xac, 0x8f, 0x82, 0x95, 0x98, 0xd3, 0xde, 0xc9, 0xc4, 0xe7, 0xea, 0xfd, 0xf0,
    0x6b, 0x66, 0x71, 0x7c, 0x5f, 0x52, 0x45, 0x48, 0x03, 0x0e, 0x19, 0x14, 0x37, 0x3a, 0x2d, 0x20,
    0x6d, 0x60, 0x77, 0x7a, 0x59, 0x54, 0x43, 0x4e, 0x05, 0x08, 0x1f, 0x12, 0x31, 0x3c, 0x2b, 0x26,
    0xbd, 0xb0, 0xa7, 0xaa, 0x89, 0x84, 0x93, 0x9e, 0xd5, 0xd8, 0xcf, 0xc2, 0xe1, 0xec, 0xfb, 0xf6,
    0xd6, 0xdb, 0xcc, 0xc1, 0xe2, 0xef, 0xf8, 0xf5, 0xbe, 0xb3, 0xa4, 0xa9, 0x8a, 0x87, 0x90, 0x9d,
    0x06, 0x0b, 0x1c, 0x11, 0x32, 0x3f, 0x28, 0x25, 0x6e, 0x63, 0x74, 0x79, 0x5a, 0x57, 0x40, 0x4d,
    0xda, 0xd7, 0xc0, 0xcd, 0xee, 0xe3, 0xf4, 0xf9, 0xb2, 0xbf, 0xa8, 0xa5, 0x86, 0x8b, 0x9c, 0x91,
    0x0a, 0x07, 0x10, 0x1d, 0x3e, 0x33, 0x24, 0x29, 0x62, 0x6f, 0x78, 0x75, 0x56, 0x5b, 0x4c, 0x41,
    0x61, 0x6c, 0x7b, 0x76, 0x55, 0x58, 0x4f, 0x42, 0x09, 0x04, 0x13, 0x1e, 0x3d, 0x30, 0x27, 0x2a,
    0xb1, 0xbc, 0xab, 0xa6, 0x85, 0x88, 0x9f, 0x92, 0xd9, 0xd4, 0xc3, 0xce, 0xed, 0xe0, 0xf7, 0xfa,
    0xb7, 0xba, 0xad, 0xa0, 0x83, 0x8e, 0x99, 0x94, 0xdf, 0xd2, 0xc5, 0xc8, 0xeb, 0xe6, 0xf1, 0xfc,
    0x67, 0x6a, 0x7d, 0x70, 0x53, 0x5e, 0x49, 0x44, 0x0f, 0x02, 0x15, 0x18, 0x3b, 0x36, 0x21, 0x2c,
    0x0c, 0x01, 0x16, 0x1b, 0x38, 0x35, 0x22, 0x2f, 0x64, 0x69, 0x7e, 0x73, 0x50, 0x5d, 0x4a, 0x47,
    0xdc, 0xd1, 0xc6, 0xcb, 0xe8, 0xe5, 0xf2, 0xff, 0xb4, 0xb9, 0xae, 0xa3, 0x80, 0x8d, 0x9a, 0x97
};

const uint8_t AES_MC_PRECALCULETED_CONSTS_X14[256] =
{
    0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24, 0x2a, 0x70, 0x7e, 0x6c, 0x62, 0x48, 0x46, 0x54, 0x5a,
    0xe0, 0xee, 0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca, 0x90, 0x9e, 0x8c, 0x82, 0xa8, 0xa6, 0xb4, 0xba,
    0xdb, 0xd5, 0xc7, 0xc9, 0xe3, 0xed, 0xff, 0xf1, 0xab, 0xa5, 0xb7, 0xb9, 0x93, 0x9d, 0x8f, 0x81,
    0x3b, 0x35, 0x27, 0x29, 0x03, 0x0d, 0x1f, 0x11, 0x4b, 0x45, 0x57, 0x59, 0x73, 0x7d, 0x6f, 0x61,
    0xad, 0xa3, 0xb1, 0xbf, 0x95, 0x9b, 0x89, 0x87, 0xdd, 0xd3, 0xc1, 0xcf, 0xe5, 0xeb, 0xf9, 0xf7,
    0x4d, 0x43, 0x51, 0x5f, 0x75, 0x7b, 0x69, 0x67, 0x3d, 0x33, 0x21, 0x2f, 0x05, 0x0b, 0x19, 0x17,
    0x76, 0x78, 0x6a, 0x64, 0x4e, 0x40, 0x52, 0x5c, 0x06, 0x08, 0x1a, 0x14, 0x3e, 0x30, 0x22, 0x2c,
    0x96, 0x98, 0x8a, 0x84, 0xae, 0xa0, 0xb2, 0xbc, 0xe6, 0xe8, 0xfa, 0xf4, 0xde, 0xd0, 0xc2, 0xcc,
    0x41, 0x4f, 0x5d, 0x53, 0x79, 0x77, 0x65, 0x6b, 0x31, 0x3f, 0x2d, 0x23, 0x09, 0x07, 0x15, 0x1b,
    0xa1, 0xaf, 0xbd, 0xb3, 0x99, 0x97, 0x85, 0x8b, 0xd1, 0xdf, 0xcd, 0xc3, 0xe9, 0xe7, 0xf5, 0xfb,
    0x9a, 0x94, 0x86, 0x88, 0xa2, 0xac, 0xbe, 0xb0, 0xea, 0xe4, 0xf6, 0xf8, 0xd2, 0xdc, 0xce, 0xc0,
    0x7a, 0x74, 0x66, 0x68, 0x42, 0x4c, 0x5e, 0x50, 0x0a, 0x04, 0x16, 0x18, 0x32, 0x3c, 0x2e, 0x20,
    0xec, 0xe2, 0xf0, 0xfe, 0xd4, 0xda, 0xc8, 0xc6, 0x9c, 0x92, 0x80, 0x8e, 0xa4, 0xaa, 0xb8, 0xb6,
    0x0c, 0x02, 0x10, 0x1e, 0x34, 0x3a, 0x28, 0x26, 0x7c, 0x72, 0x60, 0x6e, 0x44, 0x4a, 0x58, 0x56,
    0x37, 0x39, 0x2b, 0x25, 0x0f, 0x01, 0x13, 0x1d, 0x47, 0x49, 0x5b, 0x55, 0x7f, 0x71, 0x63, 0x6d,
    0xd7, 0xd9, 0xcb, 0xc5, 0xef, 0xe1, 0xf3, 0xfd, 0xa7, 0xa9, 0xbb, 0xb5, 0x9f, 0x91, 0x83, 0x8d
};


static inline void AesMixColumnsInv(__inout uint8_t* input)
{
    assert(input);

    uint8_t output[4] = { 0 };

    for (int i = 0; i < 4; ++i) {
        output[0] = AES_MC_PRECALCULETED_CONSTS_X14[input[0]] ^ AES_MC_PRECALCULETED_CONSTS_X11[input[1]] ^ AES_MC_PRECALCULETED_CONSTS_X13[input[2]] ^ AES_MC_PRECALCULETED_CONSTS_X9[input[3]];
        output[1] = AES_MC_PRECALCULETED_CONSTS_X9[input[0]] ^ AES_MC_PRECALCULETED_CONSTS_X14[input[1]] ^ AES_MC_PRECALCULETED_CONSTS_X11[input[2]] ^ AES_MC_PRECALCULETED_CONSTS_X13[input[3]];
        output[2] = AES_MC_PRECALCULETED_CONSTS_X13[input[0]] ^ AES_MC_PRECALCULETED_CONSTS_X9[input[1]] ^ AES_MC_PRECALCULETED_CONSTS_X14[input[2]] ^ AES_MC_PRECALCULETED_CONSTS_X11[input[3]];
        output[3] = AES_MC_PRECALCULETED_CONSTS_X11[input[0]] ^ AES_MC_PRECALCULETED_CONSTS_X13[input[1]] ^ AES_MC_PRECALCULETED_CONSTS_X9[input[2]] ^ AES_MC_PRECALCULETED_CONSTS_X14[input[3]];

        *((uint32_t*)input)++ = *(uint32_t*)output;
    }
}

// After compiler optimization call of AesEncryptBlock from AesEncryptBlock128, AesEncryptBlock192 etc. will be inlined 
static void AesEncryptBlock(__in const uint64_t* roundKeys, __in uint8_t roundsNum, __in const uint64_t* input, __out uint64_t* output)
{
    assert(roundKeys && input && output);

    output[0] = input[0] ^ roundKeys[0];
    output[1] = input[1] ^ roundKeys[1];

    roundKeys += 2;

    for (int i = 1; i < roundsNum; ++i) {
        AesSubBytes((uint8_t*)output);
        AesShiftRows((uint8_t*)output);
        AesMixColumns((uint8_t*)output);

        output[0] ^= roundKeys[0];
        output[1] ^= roundKeys[1];

        roundKeys += 2;
    }

    AesSubBytes((uint8_t*)output);
    AesShiftRows((uint8_t*)output);

    output[0] ^= roundKeys[0];
    output[1] ^= roundKeys[1];
}

static void Aes128EncryptBlock(__in const uint64_t* roundKeys, __in const uint64_t* input, __out uint64_t* output)
{
    AesEncryptBlock(roundKeys, 10, input, output);
}

static void Aes192EncryptBlock(__in const uint64_t* roundKeys, __in const uint64_t* input, __out uint64_t* output)
{
    AesEncryptBlock(roundKeys, 12, input, output);
}

static void Aes256EncryptBlock(__in const uint64_t* roundKeys, __in const uint64_t* input, __out uint64_t* output)
{
    AesEncryptBlock(roundKeys, 14, input, output);
}


// roundsNum variable is expecting real rounds num minus one (for exclusion of one additional substraction)
static void AesDecryptBlock(__in const uint64_t* roundKeys, __in uint8_t roundsNum, __in const uint64_t* input, __out uint64_t* output)
{
    assert(roundKeys && input && output);

    roundKeys += roundsNum << 1;

    output[0] = input[0] ^ roundKeys[0];
    output[1] = input[1] ^ roundKeys[1];

    roundKeys -= 2;

    for (int i = 1; i < roundsNum; ++i) {
        AesShiftRowsInv((uint8_t*)output);
        AesSubBytesInv((uint8_t*)output);

        output[0] ^= roundKeys[0];
        output[1] ^= roundKeys[1];
        roundKeys -= 2;

        AesMixColumnsInv((uint8_t*)output);
    }

    AesShiftRowsInv((uint8_t*)output);
    AesSubBytesInv((uint8_t*)output);

    output[0] ^= roundKeys[0];
    output[1] ^= roundKeys[1];
}

static void Aes128DecryptBlock(__in const uint64_t* roundKeys, __in const uint64_t* input, __out uint64_t* output)
{
    AesDecryptBlock(roundKeys, 10, input, output);
}

static void Aes192DecryptBlock(__in const uint64_t* roundKeys, __in const uint64_t* input, __out uint64_t* output)
{
    AesDecryptBlock(roundKeys, 12, input, output);
}

static void Aes256DecryptBlock(__in const uint64_t* roundKeys, __in const uint64_t* input, __out uint64_t* output)
{
    AesDecryptBlock(roundKeys, 14, input, output);
}

int AesEncrypt(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding, __in HardwareFeatures hwFeatures
    , __in const uint64_t* input, __in size_t inputSize, __in bool finalize, __out_opt uint64_t* output, __inout size_t* outputSize)
{
    assert(input && outputSize);

    int status = NO_ERROR;

    if (!finalize) {
        if (inputSize & 15)
            return ERROR_WRONG_INPUT_SIZE;
        else
            *outputSize = inputSize;
    }
    else if (status = AddPaddingInternal(input, inputSize, padding, AES_BLOCK_SIZE, output, outputSize, true))
        return status;

    assert((*outputSize & 15) == 0);

    AesProcessingBlockFunction func = NULL;
    uint64_t* roundKeys = state;
    uint64_t* iv = NULL;
    
    if (cipher == AES128_cipher_type) {
        if (hwFeatures.avx) {
            func = Aes128AvxEncryptBlock;
            iv = ((Aes128AvxState*)state)->iv;
        }
        else if (hwFeatures.aesni) {
            func = Aes128NiEncryptBlock;
            iv = ((Aes128NiState*)state)->iv;
        }
        else {
            func = Aes128EncryptBlock;
            iv = ((Aes128State*)state)->iv;
        }
    }
    else if (cipher == AES192_cipher_type) {
        if (hwFeatures.avx) {
            func = Aes192AvxEncryptBlock;
            iv = ((Aes192AvxState*)state)->iv;
        }
        else if (hwFeatures.aesni) {
            func = Aes192NiEncryptBlock;
            iv = ((Aes192NiState*)state)->iv;
        }
        else {
            func = Aes192EncryptBlock;
            iv = ((Aes192State*)state)->iv;
        }
    }
    else {
        if (hwFeatures.avx) {
            func = Aes256AvxEncryptBlock;
            iv = ((Aes256AvxState*)state)->iv;
        }
        else if (hwFeatures.aesni) {
            func = Aes256NiEncryptBlock;
            iv = ((Aes256NiState*)state)->iv;
        }
        else {
            func = Aes256EncryptBlock;
            iv = ((Aes256State*)state)->iv;
        }
    }

    assert(func && iv);

    uint64_t blocksNumber = *outputSize >> 4; // (outputSize / AES_BLOCK_SIZE) outputSize must be divisible by AES_BLOCK_SIZE without remainder

    switch (opMode) {
    case ECB_mode: {
        while (--blocksNumber) {
            func(roundKeys, input, output);
            input += 2;
            output += 2;
        }

        func(roundKeys, finalize ? output : input, output);

        break;
    }

    case CBC_mode: {
        --input; // for speeding

        while (--blocksNumber) {
            iv[0] ^= *++input, iv[1] ^= *++input;
            func(roundKeys, iv, output);
            iv[0] = *output++, iv[1] = *output++;
        }

        if (finalize)
            iv[0] ^= output[0], iv[1] ^= output[1];
        else
            iv[0] ^= *++input, iv[1] ^= *++input;

        func(roundKeys, iv, output);

        if (!finalize)
            iv[0] = *output++, iv[1] = *output++;

        break;
    }

    case CFB_mode: {
        --input; // for speeding

        // inputCopy needed to apply "in place" encryption
        uint64_t inputCopy[2] = { 0 };

        while (--blocksNumber) {
            inputCopy[0] = *++input,
            inputCopy[1] = *++input;
            func(roundKeys, iv, output);
            iv[0] = *output++ ^= inputCopy[0],
            iv[1] = *output++ ^= inputCopy[1];
        }

        if (finalize) {
            inputCopy[0] = output[0],
            inputCopy[1] = output[1];
        }
        else {
            inputCopy[0] = *++input,
            inputCopy[1] = *++input;
        }

        func(roundKeys, iv, output);
        output[0] ^= inputCopy[0],
        output[1] ^= inputCopy[1];

        if (!finalize) {
            iv[0] = output[0],
            iv[1] = output[1];
        }

        break;
    }

    case OFB_mode: {
        --input;    // for speeding
        --output;   //
        
        while (--blocksNumber) {
            func(roundKeys, iv, iv);
            *++output = iv[0] ^ *++input,
            *++output = iv[1] ^ *++input;
        }

        func(roundKeys, iv, iv);

        if (finalize) {
            *++output ^= iv[0],
            *++output ^= iv[1];
        }
        else {
            *++output = iv[0] ^ *++input,
            *++output = iv[1] ^ *++input;
        }

        break;
    }

    case CTR_mode: {
        --input;    // for speeding

        // inputCopy needed to apply "in place" encryption
        uint64_t inputCopy[2] = { 0 };

        while (--blocksNumber) {
            inputCopy[0] = *++input,
            inputCopy[1] = *++input;
            func(roundKeys, iv, output);
            *output++ ^= inputCopy[0], * output++ ^= inputCopy[1];

            iv[1] = Uint64LittleEndianToBigEndian(Uint64LittleEndianToBigEndian(iv[1]) + 1);    // I'm not sure that approach with Big Endian counter is necessary
                                                                                                // but the other working examplse of AES with ctr with which I can compare the result
                                                                                                // has such (based on my calculations).
        }

        if (finalize) {
            inputCopy[0] = output[0],
            inputCopy[1] = output[1];
        }
        else {
            inputCopy[0] = *++input,
            inputCopy[1] = *++input;
        }

        func(roundKeys, iv, output);
        output[0] ^= inputCopy[0], output[1] ^= inputCopy[1];

        if (!finalize)
            iv[1] = Uint64LittleEndianToBigEndian(Uint64LittleEndianToBigEndian(iv[1]) + 1);

        break;
    }

    }

    return NO_ERROR;
}

int AesDecrypt(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding, __in HardwareFeatures hwFeatures
    , __in const uint64_t* input, __in size_t inputSize, __in bool finalize, __out_opt uint64_t* output, __inout size_t* outputSize)
{
    assert(input && outputSize);

    int status = NO_ERROR;

    if (inputSize & 15)
        return ERROR_WRONG_INPUT_SIZE;

    AesProcessingBlockFunction func = NULL;
    uint64_t* roundKeys = NULL;
    uint64_t* iv = NULL;
    bool isDecryptionFunc = opMode == ECB_mode || opMode == CBC_mode;

    if (cipher == AES128_cipher_type) {
        if (hwFeatures.avx) {
            func = isDecryptionFunc ? Aes128AvxDecryptBlock : Aes128AvxEncryptBlock;
            roundKeys = isDecryptionFunc ? ((Aes128AvxState*)state)->decryptionRoundKeys : state;
            iv = ((Aes128AvxState*)state)->iv;
        }
        else if (hwFeatures.aesni) {
            func = isDecryptionFunc ? Aes128NiDecryptBlock : Aes128NiEncryptBlock;
            roundKeys = isDecryptionFunc ? ((Aes128NiState*)state)->decryptionRoundKeys : state;
            iv = ((Aes128NiState*)state)->iv;
        }
        else {
            func = isDecryptionFunc ? Aes128DecryptBlock : Aes128EncryptBlock;
            roundKeys = (uint64_t*)((Aes128State*)state)->roundKeys;
            iv = ((Aes128State*)state)->iv;
        }
    }
    else if (cipher == AES192_cipher_type) {
        if (hwFeatures.avx) {
            func = isDecryptionFunc ? Aes192AvxDecryptBlock : Aes192AvxEncryptBlock;
            roundKeys = isDecryptionFunc ? ((Aes192AvxState*)state)->decryptionRoundKeys : state;
            iv = ((Aes192AvxState*)state)->iv;
        }
        else if (hwFeatures.aesni) {
            func = isDecryptionFunc ? Aes192NiDecryptBlock : Aes192NiEncryptBlock;
            roundKeys = isDecryptionFunc ? ((Aes192NiState*)state)->decryptionRoundKeys : state;
            iv = ((Aes192NiState*)state)->iv;
        }
        else {
            func = isDecryptionFunc ? Aes192DecryptBlock : Aes192EncryptBlock;
            roundKeys = (uint64_t*)((Aes192State*)state)->roundKeys;
            iv = ((Aes192State*)state)->iv;
        }
    }
    else {
        if (hwFeatures.avx) {
            func = isDecryptionFunc ? Aes256AvxDecryptBlock : Aes256AvxEncryptBlock;
            roundKeys = isDecryptionFunc ? ((Aes256AvxState*)state)->decryptionRoundKeys : state;
            iv = ((Aes256AvxState*)state)->iv;
        }
        else if (hwFeatures.aesni) {
            func = isDecryptionFunc ? Aes256NiDecryptBlock : Aes256NiEncryptBlock;
            roundKeys = isDecryptionFunc ? ((Aes256NiState*)state)->decryptionRoundKeys : state;
            iv = ((Aes256NiState*)state)->iv;
        }
        else {
            func = isDecryptionFunc ? Aes256DecryptBlock : Aes256EncryptBlock;
            roundKeys = (uint64_t*)((Aes256State*)state)->roundKeys;
            iv = ((Aes256State*)state)->iv;
        }
    }

    assert(func && roundKeys && iv);

    uint64_t blocksNumber = inputSize >> 4; // (inputSize / AES_BLOCK_SIZE) inputSize must be divisible by AES_BLOCK_SIZE without remainder
    const uint64_t* lastInputBlock = input + ((blocksNumber - 1) << 1);
    uint64_t lastOutputBlock[2] = { 0 };
    uint64_t lastIvBlock[2] = { 0 };

    bool multiBlock = inputSize > AES_BLOCK_SIZE;

    switch (opMode) {
    case ECB_mode:
    case CBC_mode: {
        func(roundKeys, lastInputBlock, lastOutputBlock);

        if (opMode == CBC_mode) {
            if (multiBlock) {
                lastOutputBlock[0] ^= *(lastInputBlock - 2),
                lastOutputBlock[1] ^= *(lastInputBlock - 1),
                lastIvBlock[0] = lastInputBlock[0],
                lastIvBlock[1] = lastInputBlock[1];
            }
            else {
                lastOutputBlock[0] ^= iv[0],
                lastOutputBlock[1] ^= iv[1],
                lastIvBlock[0] = input[0],
                lastIvBlock[1] = input[1];
            }
        }
        break;
    }

    case CFB_mode: {
        if (multiBlock) {
            func(roundKeys, lastInputBlock - 2, lastOutputBlock);
            lastOutputBlock[0] ^= lastInputBlock[0],
            lastOutputBlock[1] ^= lastInputBlock[1],
            lastIvBlock[0] = lastInputBlock[0],
            lastIvBlock[1] = lastInputBlock[1];
        }
        else {
            func(roundKeys, iv, lastOutputBlock);
            lastOutputBlock[0] ^= input[0],
            lastOutputBlock[1] ^= input[1],
            lastIvBlock[0] = input[0],
            lastIvBlock[1] = input[1];
        }
        break;
    }

    case OFB_mode: {
        // All input processing when OFB_mode must be calculated here
        if (*outputSize >= inputSize) {
            --input;
            --output;

            while (blocksNumber--) {
                func(roundKeys, iv, iv);
                *++output = iv[0] ^ *++input,
                *++output = iv[1] ^ *++input;
            }

            --output;

            lastOutputBlock[0] ^= output[0],
            lastOutputBlock[1] ^= output[1],
            lastIvBlock[0] = iv[0],
            lastIvBlock[1] = iv[1];
        }
        else {
            *outputSize = inputSize;
            return ERROR_TOO_SMALL_OUTPUT_SIZE;
        }

        break;
    }

    case CTR_mode: {
        lastIvBlock[0] = iv[0];
        lastIvBlock[1] = Uint64LittleEndianToBigEndian(Uint64LittleEndianToBigEndian(iv[1]) + blocksNumber - 1);
        func(roundKeys, lastIvBlock, lastOutputBlock);
        lastOutputBlock[0] ^= lastInputBlock[0],
        lastOutputBlock[1] ^= lastInputBlock[1],
        lastIvBlock[1] = Uint64LittleEndianToBigEndian(Uint64LittleEndianToBigEndian(iv[1]) + blocksNumber);

        break;
    }

    }

    if (!finalize) {
        if (opMode != OFB_mode) {
            *(output + ((blocksNumber - 1) << 1)) = lastOutputBlock[0],
            *(output + (blocksNumber << 1) - 1) = lastOutputBlock[1];
        }

        *outputSize = inputSize;
    }
    else if (status = FillLastDecryptedBlockInternal(padding, AES_BLOCK_SIZE, &lastOutputBlock, inputSize, output, outputSize))
        return status;

    assert(*outputSize);

    switch (opMode) {
    case ECB_mode: {
        while (--blocksNumber) {
            func(roundKeys, input, output);
            input += 2,
            output += 2;
        }

        break;
    }

    case CBC_mode: {
        uint64_t ivBlockNext[2] = { 0 };

        --input,
        output;

        while (--blocksNumber) {
            ivBlockNext[0] = *++input,
            ivBlockNext[1] = *++input;
            func(roundKeys, ivBlockNext, output);
            *output++ ^= iv[0],
            *output++ ^= iv[1];
            iv[0] = ivBlockNext[0],
            iv[1] = ivBlockNext[1];
        }

        break;
    }

    case CFB_mode: {
        uint64_t ivBlockNext[2] = { 0 };

        --input,
        output;

        while (--blocksNumber) {
            ivBlockNext[0] = *++input,
            ivBlockNext[1] = *++input;
            func(roundKeys, iv, output);
            *output++ ^= ivBlockNext[0],
            *output++ ^= ivBlockNext[1];
            iv[0] = ivBlockNext[0],
            iv[1] = ivBlockNext[1];
        }

        break;
    }

    case OFB_mode:
        break;

    case CTR_mode: {
        --input;
        
        // inputCopy needed to apply "in place" encryption
        uint64_t inputCopy[2] = { 0 };

        while (--blocksNumber) {
            inputCopy[0] = *++input,
            inputCopy[1] = *++input;
            func(roundKeys, iv, output);
            *output++ ^= inputCopy[0],
            *output++ ^= inputCopy[1];
            iv[1] = Uint64LittleEndianToBigEndian(Uint64LittleEndianToBigEndian(iv[1]) + 1);
        }

        break;
    }

    }

    iv[0] = lastIvBlock[0];
    iv[1] = lastIvBlock[1];

    if (hwFeatures.aesni)
        SecureClearRegistersUsedInAes();

    return NO_ERROR;
}
