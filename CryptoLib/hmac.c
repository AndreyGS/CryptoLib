// hmac.c
//

#include "pch.h"
#include "hmac.h"

void GetHmac(__in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __in Prf func, __out void* output,__in bool finalize, __inout StateHandle state)
{
    int status = NO_ERROR;

    uint16_t blockSize = 0;
    uint16_t didgestSize = 0;
    
    StateHandle hashState = state;
    uint8_t* iKeyPad = NULL;
    uint8_t* oKeyPad = NULL;
    bool isStart = false;

    switch (func) {
    case HMAC_SHA1:
        blockSize = SHA1_BLOCK_SIZE;
        didgestSize = SHA1_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha1State*)((PrfState*)state)->state)->iKeyPad;
        iKeyPad = ((Hmac_Sha1State*)((PrfState*)state)->state)->oKeyPad;
        isStart = !((Hmac_Sha1State*)((PrfState*)state)->state)->notFirst;

        if (isStart)
            ((Hmac_Sha1State*)((PrfState*)state)->state)->notFirst = true;

        break;

    case HMAC_SHA_224:
    case HMAC_SHA_256:
        blockSize = SHA2_32_BLOCK_SIZE;
        didgestSize = func == HMAC_SHA_224 ? SHA_224_DIGEST_SIZE : SHA_256_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha2_32State*)((PrfState*)state)->state)->iKeyPad;
        iKeyPad = ((Hmac_Sha2_32State*)((PrfState*)state)->state)->oKeyPad;
        isStart = !((Hmac_Sha2_32State*)((PrfState*)state)->state)->notFirst;

        if (isStart)
            ((Hmac_Sha2_32State*)((PrfState*)state)->state)->notFirst = true;

        break;

    case HMAC_SHA_384:
    case HMAC_SHA_512_224:
    case HMAC_SHA_512_256:
    case HMAC_SHA_512:
        blockSize = SHA2_64_BLOCK_SIZE;
        didgestSize = func == HMAC_SHA_384 ? SHA_256_DIGEST_SIZE : func == HMAC_SHA_512_224 ? SHA_512_224_DIGEST_SIZE : func == HMAC_SHA_512_256 ? SHA_512_256_DIGEST_SIZE : SHA_512_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha2_64State*)((PrfState*)state)->state)->iKeyPad;
        iKeyPad = ((Hmac_Sha2_64State*)((PrfState*)state)->state)->oKeyPad;
        isStart = !((Hmac_Sha2_64State*)((PrfState*)state)->state)->notFirst;

        if (isStart)
            ((Hmac_Sha2_64State*)((PrfState*)state)->state)->notFirst = true;

        break;

    case HMAC_SHA3_224:
        blockSize = SHA3_224_BLOCK_SIZE;
        didgestSize = SHA3_224_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha3_224State*)((PrfState*)state)->state)->iKeyPad;
        iKeyPad = ((Hmac_Sha3_224State*)((PrfState*)state)->state)->oKeyPad;
        isStart = !((Hmac_Sha3_224State*)((PrfState*)state)->state)->notFirst;

        if (isStart)
            ((Hmac_Sha3_224State*)((PrfState*)state)->state)->notFirst = true;

        break;

    case HMAC_SHA3_256:
        blockSize = SHA3_256_BLOCK_SIZE;
        didgestSize = SHA3_256_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha3_256State*)((PrfState*)state)->state)->iKeyPad;
        iKeyPad = ((Hmac_Sha3_256State*)((PrfState*)state)->state)->oKeyPad;
        isStart = !((Hmac_Sha3_256State*)((PrfState*)state)->state)->notFirst;

        if (isStart)
            ((Hmac_Sha3_256State*)((PrfState*)state)->state)->notFirst = true;

        break;

    case HMAC_SHA3_384:
        blockSize = SHA3_384_BLOCK_SIZE;
        didgestSize = SHA3_384_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha3_384State*)((PrfState*)state)->state)->iKeyPad;
        iKeyPad = ((Hmac_Sha3_384State*)((PrfState*)state)->state)->oKeyPad;
        isStart = !((Hmac_Sha3_384State*)((PrfState*)state)->state)->notFirst;

        if (isStart)
            ((Hmac_Sha3_384State*)((PrfState*)state)->state)->notFirst = true;

        break;

    case HMAC_SHA3_512:
        blockSize = SHA3_512_BLOCK_SIZE;
        didgestSize = SHA3_512_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha3_512State*)((PrfState*)state)->state)->iKeyPad;
        iKeyPad = ((Hmac_Sha3_512State*)((PrfState*)state)->state)->oKeyPad;
        isStart = !((Hmac_Sha3_512State*)((PrfState*)state)->state)->notFirst;

        if (isStart)
            ((Hmac_Sha3_512State*)((PrfState*)state)->state)->notFirst = true;

        break;
    }

    if (isStart) {
        if (keySize > blockSize) {
            GetHashInternal(key, keySize, iKeyPad, true, hashState);
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

        GetHashInternal(iKeyPad, blockSize, output, false, hashState);
    }
    
    GetHashInternal(input, inputSize, iKeyPad, finalize, hashState);

    if (finalize) {
        GetHashInternal(oKeyPad, blockSize, output, false, hashState);
        GetHashInternal(iKeyPad, didgestSize, output, true, hashState);
    }
}
