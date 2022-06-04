#include "pch.h"

#include "block_ciphers_main.h"
#include "des.h"
#include "paddings.h"

typedef void (*BlockCipherProcessingFunction)(const void*, const void*, void*);

int EncryptByBlockCipher(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding, __in const uint8_t* input, __in uint64_t inputSize
    , __in bool finalize, __out_opt uint8_t* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;

    BlockCipherProcessingFunction func = NULL;
    void* keys = NULL;
    uint64_t* iv = NULL;
    uint8_t ivArrayLen = 0;
    uint64_t* outputBuffer = NULL;
    uint16_t blockSize = 0;

    switch (cipher) {
    case DES_cipher_type:
        func = DesEncryptBlock;
        keys = ((DesState*)state)->roundsKeys;
        iv = &((DesState*)state)->iv;
        ivArrayLen = sizeof(((DesState*)0)->iv) / sizeof(uint64_t);
        outputBuffer = &((DesState*)state)->outputBuffer;
        blockSize = DES_BLOCK_SIZE;
        break;
    case TDES_cipher_type:
        func = TdesEncryptBlock;
        keys = ((TdesState*)state)->roundsKeys;
        iv = &((TdesState*)state)->iv;
        ivArrayLen = sizeof(((TdesState*)0)->iv) / sizeof(uint64_t);
        outputBuffer = &((TdesState*)state)->outputBuffer;
        blockSize = DES_BLOCK_SIZE;
        break;
    } 

    if (!finalize) {
        if (inputSize % blockSize)
            return ERROR_WRONG_INPUT_SIZE;
    }
    // When finalize flag is set we adding padding. See AddPaddingInternal description for understanding what it does exactly
    else if (status = AddPaddingInternal(input, inputSize, padding, blockSize, output, outputSize, true))
        return status;

    uint64_t blocksNumber = *outputSize / blockSize; // outputSize must be divisible for now by blockSize without remainder

    switch (opMode) {
    case ECB_mode: {
        while (--blocksNumber) {
            func(keys, input, output);
            input += blockSize;
            output += blockSize;
        }

        func(keys, input, output);

        break;
    }

    case CBC_mode: {
        while (--blocksNumber) {
            memcpy(output, input, blockSize);

            input += blockSize;

            for (int i = 0; i < ivArrayLen; ++i)
                ((uint64_t*)output)[i] ^= iv[i];

            func(keys, output, output);

            for (int i = 0; i < ivArrayLen; ++i)
                iv[i] = ((uint64_t*)output)[i];

            output += blockSize;
        }

        for (int i = 0; i < ivArrayLen; ++i)
            ((uint64_t*)output)[i] ^= iv[i];

        func(keys, output, output);

        for (int i = 0; i < ivArrayLen; ++i)
            iv[i] = ((uint64_t*)output)[i];

        break;
    }

    case CFB_mode: {
        while (--blocksNumber) {
            func(keys, iv, output);
            for (int i = 0; i < ivArrayLen; ++i)
                ((uint64_t*)output)[i] ^= ((uint64_t*)input)[i];

            input += blockSize;

            for (int i = 0; i < ivArrayLen; ++i)
                iv[i] = ((uint64_t*)output)[i];

            output += blockSize;
        }

        func(keys, iv, outputBuffer);

        for (int i = 0; i < ivArrayLen; ++i)
            ((uint64_t*)output)[i] ^= ((uint64_t*)outputBuffer)[i];

        for (int i = 0; i < ivArrayLen; ++i)
            iv[i] = ((uint64_t*)output)[i];

        break;
    }

    case OFB_mode: {
        while (--blocksNumber) {
            func(keys, iv, iv);
            
            for (int i = 0; i < ivArrayLen; ++i)
                ((uint64_t*)output)[i] = iv[i] ^ ((uint64_t*)input)[i];

            input += blockSize;
            output += blockSize;
        }

        func(keys, iv, iv);

        for (int i = 0; i < ivArrayLen; ++i)
            ((uint64_t*)output)[i] ^= iv[i];

        break;
    }

    case CTR_mode: {
        while (--blocksNumber) {
            func(keys, iv, output);

            for (int i = 0; i < ivArrayLen; ++i)
                ((uint64_t*)output)[i] ^= ((uint64_t*)input)[i];

            ivBlock = Uint64LittleEndianToBigEndian(Uint64LittleEndianToBigEndian(ivBlock) + 1); // I'm not sure that approach with Big Endian counter is necessary
                                                                                                 // but the other working example of des with ctr with which I can compare the result
                                                                                                 // has that (based on my calculations).
        }

        *(uint64_t*)output = DesEncryptBlock(ivBlock, roundsKeys) ^ *(uint64_t*)output;
        ivBlock = Uint64LittleEndianToBigEndian(Uint64LittleEndianToBigEndian(ivBlock) + 1);

        break;
    }

    }

    if (iv)
        *iv = ivBlock;

    return NO_ERROR;
}

int DecryptByBlockCipher(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding
    , __in const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output, __inout uint64_t* outputSize)
{

}