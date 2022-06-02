#include "pch.h"

#include "block_ciphers_main.h"
#include "des.h"
#include "paddings.h"

typedef void* (*BlockCipherProcessingFunction)(const void*, void*);

int EncryptByBlockCipher(__inout StateHandle state, __in BlockCipherType cipher, __in BlockCipherOpMode opMode, __in PaddingType padding, __in const void* input, __in uint64_t inputSize
    , __in bool finalize, __out_opt void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;

    BlockCipherProcessingFunction func = NULL;
    void* ivBlock = NULL;
    void* keys = NULL;
    uint16_t blockSize = 0;

    switch (cipher) {
    case DES_cipher_type:
        func = DesEncryptBlock;
        keys = ((DesState*)state)->roundsKeys;
        ivBlock = ((DesState*)state)->iv;
        blockSize = DES_BLOCK_SIZE;
        break;
    case TDES_cipher_type:
        func = TdesEncryptBlock;
        keys = ((TdesState*)state)->roundsKeys;
        ivBlock = ((TdesState*)state)->iv;
        blockSize = DES_BLOCK_SIZE;
        break;
    } 

    if (!finalize) {
        if (inputSize % blockSize)
            return ERROR_WRONG_INPUT_SIZE;
    }
    else if (status = AddPaddingInternal(input, inputSize, padding, blockSize, output, outputSize, true))
        return status;

    uint64_t blocksNumber = *outputSize / blockSize; // (outputSize / DES_BLOCK_SIZE) outputSize must be divisible for now by blockSize without remainder

    switch (opMode) {
    case ECB_mode: {
        while (--blocksNumber)
            *((uint64_t*)output)++ = DesEncryptBlock(*((uint64_t*)input)++, roundsKeys);

        *(uint64_t*)output = DesEncryptBlock(*(uint64_t*)output, roundsKeys);

        break;
    }

    case CBC_mode: {
        while (--blocksNumber) {
            *(uint64_t*)output = DesEncryptBlock(ivBlock ^ *((uint64_t*)input)++, roundsKeys);
            ivBlock = *((uint64_t*)output)++;
        }

        *(uint64_t*)output = DesEncryptBlock(ivBlock ^ *(uint64_t*)output, roundsKeys);
        ivBlock = *(uint64_t*)output;

        break;
    }

    case CFB_mode: {
        while (--blocksNumber) {
            *(uint64_t*)output = DesEncryptBlock(ivBlock, roundsKeys) ^ *((uint64_t*)input)++;
            ivBlock = *((uint64_t*)output)++;
        }

        *(uint64_t*)output ^= DesEncryptBlock(ivBlock, roundsKeys);
        ivBlock = *(uint64_t*)output;

        break;
    }

    case OFB_mode: {
        while (--blocksNumber)
            *((uint64_t*)output)++ = (ivBlock = DesEncryptBlock(ivBlock, roundsKeys)) ^ *((uint64_t*)input)++;

        *(uint64_t*)output ^= (ivBlock = DesEncryptBlock(ivBlock, roundsKeys));

        break;
    }

    case CTR_mode: {
        while (--blocksNumber) {
            *((uint64_t*)output)++ = DesEncryptBlock(ivBlock, roundsKeys) ^ *((uint64_t*)input)++;
            ivBlock = Uint64LittleEndianToBigEndian(Uint64LittleEndianToBigEndian(ivBlock) + 1); // I'm not sure that approach with Big Endian counter is necessary
                                                                                                 // but the other working examplse of des with ctr with which I can compare the result
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