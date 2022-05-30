// hmac.c
//

#include "pch.h"
#include "hmac.h"

void GetHmac(__inout HmacStateHandle state, __out void* output, __in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __in Prf func, __in bool finalize)
{
    int status = NO_ERROR;

    uint16_t blockSize = 0;
    uint16_t didgestSize = 0;
    
    HashHandle hashState = ((Hmac_Sha1State*)(state))->hashFuncState;
    uint8_t* iKeyPad = NULL;
    uint8_t* oKeyPad = NULL;
    bool isStart = false;

    switch (func) {
    case HMAC_SHA1:
        blockSize = SHA1_BLOCK_SIZE;
        didgestSize = SHA1_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha1State*)(state))->iKeyPad;
        iKeyPad = ((Hmac_Sha1State*)(state))->oKeyPad;
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
        iKeyPad = ((Hmac_Sha2_32State*)(state))->oKeyPad;
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
        didgestSize = func == HMAC_SHA_384 ? SHA_256_DIGEST_SIZE : func == HMAC_SHA_512_224 ? SHA_512_224_DIGEST_SIZE : func == HMAC_SHA_512_256 ? SHA_512_256_DIGEST_SIZE : SHA_512_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha2_64State*)(state))->iKeyPad;
        iKeyPad = ((Hmac_Sha2_64State*)(state))->oKeyPad;
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
        iKeyPad = ((Hmac_Sha3_224State*)(state))->oKeyPad;
        isStart = !((Hmac_Sha3_224State*)(state))->notFirst;

        if (isStart)
            ((Hmac_Sha3_224State*)(state))->notFirst = true;

        break;

    case HMAC_SHA3_256:
        blockSize = SHA3_256_BLOCK_SIZE;
        didgestSize = SHA3_256_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha3_256State*)(state))->iKeyPad;
        iKeyPad = ((Hmac_Sha3_256State*)(state))->oKeyPad;
        isStart = !((Hmac_Sha3_256State*)(state))->notFirst;

        if (isStart)
            ((Hmac_Sha3_256State*)(state))->notFirst = true;

        break;

    case HMAC_SHA3_384:
        blockSize = SHA3_384_BLOCK_SIZE;
        didgestSize = SHA3_384_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha3_384State*)(state))->iKeyPad;
        iKeyPad = ((Hmac_Sha3_384State*)(state))->oKeyPad;
        isStart = !((Hmac_Sha3_384State*)(state))->notFirst;

        if (isStart)
            ((Hmac_Sha3_384State*)(state))->notFirst = true;

        break;

    case HMAC_SHA3_512:
        blockSize = SHA3_512_BLOCK_SIZE;
        didgestSize = SHA3_512_DIGEST_SIZE;
        iKeyPad = ((Hmac_Sha3_512State*)(state))->iKeyPad;
        iKeyPad = ((Hmac_Sha3_512State*)(state))->oKeyPad;
        isStart = !((Hmac_Sha3_512State*)(state))->notFirst;

        if (isStart)
            ((Hmac_Sha3_512State*)(state))->notFirst = true;

        break;
    }

    if (isStart) {
        if (keySize > blockSize) {
            GetHashInternal(hashState, iKeyPad, key, keySize, true);
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

        GetHashInternal(hashState, output, iKeyPad, blockSize, false);
    }
    
    GetHashInternal(hashState, iKeyPad, input, inputSize, finalize);

    if (finalize) {
        GetHashInternal(hashState, output, oKeyPad, blockSize, false);
        GetHashInternal(hashState, output, iKeyPad, didgestSize, true);
    }
}
