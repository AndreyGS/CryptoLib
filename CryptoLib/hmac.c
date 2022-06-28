/**
 * @file hmac.c
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
#include "hmac.h"

void GetHmac(__inout HmacStateHandle state, __in_opt const void* input, __in size_t inputSize, __in_opt const void* key, __in size_t keySize, __in Prf func, __in bool finalize, __out_opt void* output)
{
    assert(state && (input || !inputSize) && (key || !keySize) && (!finalize || output));

    int status = NO_ERROR;

    uint16_t blockSize = 0;
    uint16_t didgestSize = 0;
    
    HashHandle hashState = ((Hmac_Sha1State*)(state))->hashFuncState;
    uint8_t* iKeyPad = NULL;
    uint8_t* oKeyPad = NULL;
    bool isStart = false;

    // First we need to init pointers and if it is a first call (isStart) then we should also init hash state
    switch (func) {
    case HMAC_SHA1:
        blockSize = SHA1_BLOCK_SIZE;
        didgestSize = SHA1_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha1State*)(state))->iKeyPad;
        oKeyPad = ((Hmac_Sha1State*)(state))->oKeyPad;
        isStart = !((Hmac_Sha1State*)(state))->notFirst;

        if (isStart) {
            ((HashState*)hashState)->func = SHA1;
            ((Hmac_Sha1State*)(state))->notFirst = true;
        }

        break;

    case HMAC_SHA_224:
    case HMAC_SHA_256:
        blockSize = SHA2_32_BLOCK_SIZE;
        didgestSize = func == HMAC_SHA_224 ? SHA_224_DIGEST_SIZE : SHA_256_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha2_32State*)(state))->iKeyPad;
        oKeyPad = ((Hmac_Sha2_32State*)(state))->oKeyPad;
        isStart = !((Hmac_Sha2_32State*)(state))->notFirst;

        if (isStart) {
            ((HashState*)hashState)->func = func == HMAC_SHA_224 ? SHA_224 : SHA_256;
            ((Hmac_Sha2_32State*)(state))->notFirst = true;
        }

        break;

    case HMAC_SHA_384:
    case HMAC_SHA_512_224:
    case HMAC_SHA_512_256:
    case HMAC_SHA_512:
        blockSize = SHA2_64_BLOCK_SIZE;
        didgestSize = func == HMAC_SHA_384 ? SHA_384_DIGEST_SIZE : func == HMAC_SHA_512_224 ? SHA_512_224_DIGEST_SIZE : func == HMAC_SHA_512_256 ? SHA_512_256_DIGEST_SIZE : SHA_512_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha2_64State*)(state))->iKeyPad;
        oKeyPad = ((Hmac_Sha2_64State*)(state))->oKeyPad;
        isStart = !((Hmac_Sha2_64State*)(state))->notFirst;

        if (isStart) {
            switch (func) {
            case HMAC_SHA_384:
                ((HashState*)hashState)->func = SHA_384;
                break;
            case HMAC_SHA_512_224:
                ((HashState*)hashState)->func = SHA_512_224;
                break;
            case HMAC_SHA_512_256:
                ((HashState*)hashState)->func = SHA_512_256;
                break;
            case HMAC_SHA_512:
                ((HashState*)hashState)->func = SHA_512;
                break;
            }

            ((Hmac_Sha2_64State*)(state))->notFirst = true;
        }

        break;

    case HMAC_SHA3_224:
        blockSize = SHA3_224_BLOCK_SIZE;
        didgestSize = SHA3_224_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha3_224State*)(state))->iKeyPad;
        oKeyPad = ((Hmac_Sha3_224State*)(state))->oKeyPad;
        isStart = !((Hmac_Sha3_224State*)(state))->notFirst;

        if (isStart) {
            ((HashState*)hashState)->func = SHA3_224;
            ((Hmac_Sha3_224State*)(state))->notFirst = true;
        }

        break;

    case HMAC_SHA3_256:
        blockSize = SHA3_256_BLOCK_SIZE;
        didgestSize = SHA3_256_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha3_256State*)(state))->iKeyPad;
        oKeyPad = ((Hmac_Sha3_256State*)(state))->oKeyPad;
        isStart = !((Hmac_Sha3_256State*)(state))->notFirst;

        if (isStart) {
            ((HashState*)hashState)->func = SHA3_256;
            ((Hmac_Sha3_256State*)(state))->notFirst = true;
        }

        break;

    case HMAC_SHA3_384:
        blockSize = SHA3_384_BLOCK_SIZE;
        didgestSize = SHA3_384_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha3_384State*)(state))->iKeyPad;
        oKeyPad = ((Hmac_Sha3_384State*)(state))->oKeyPad;
        isStart = !((Hmac_Sha3_384State*)(state))->notFirst;

        if (isStart) {
            ((HashState*)hashState)->func = SHA3_384;
            ((Hmac_Sha3_384State*)(state))->notFirst = true;
        }

        break;

    case HMAC_SHA3_512:
        blockSize = SHA3_512_BLOCK_SIZE;
        didgestSize = SHA3_512_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha3_512State*)(state))->iKeyPad;
        oKeyPad = ((Hmac_Sha3_512State*)(state))->oKeyPad;
        isStart = !((Hmac_Sha3_512State*)(state))->notFirst;

        if (isStart) {
            ((HashState*)hashState)->func = SHA3_512;
            ((Hmac_Sha3_512State*)(state))->notFirst = true;
        }

        break;
    }

    if (isStart) {
        ResetHashStateInternal(hashState);

        if (keySize > blockSize) {
            GetHashInternal(hashState, key, keySize, true, iKeyPad);
            keySize = didgestSize;
        }
        else
            memcpy(iKeyPad, key, (size_t)keySize);

        memset(iKeyPad + keySize, 0, blockSize - (uint16_t)keySize);
        memcpy(oKeyPad, iKeyPad, blockSize);

        uint8_t* p = (uint8_t*)iKeyPad;
        for (uint8_t i = 0; i < blockSize; ++i)
            *p++ ^= '\x36';

        p = (uint8_t*)oKeyPad;
        for (uint8_t i = 0; i < blockSize; ++i)
            *p++ ^= '\x5c';

        GetHashInternal(hashState, iKeyPad, blockSize, false, iKeyPad);
    }
    
    GetHashInternal(hashState, input, inputSize, finalize, iKeyPad);

    if (finalize) {
        GetHashInternal(hashState, oKeyPad, blockSize, false, NULL);
        GetHashInternal(hashState, iKeyPad, didgestSize, true, output);
    }
}
