// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/**
 * @file crypto_internal.c
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

#include "crypto_internal.h"
#include "des.h"
#include "aes.h"
#include "paddings.h"
#include "hmac.h"

// The order of mappings must be equal to the order of HashFunc consts
const HashFuncsSizes g_hashFuncsSizesMapping[11] =
{
    { SHA1,         SHA1_BLOCK_SIZE,     SHA1_DIGEST_SIZE,          sizeof(Sha1State),      HASH_STATE_SHA1_SIZE },
    { SHA_224,      SHA2_32_BLOCK_SIZE,  SHA_224_DIGEST_SIZE,       sizeof(Sha2_32State),   HASH_STATE_SHA2_32_SIZE },
    { SHA_256,      SHA2_32_BLOCK_SIZE,  SHA_256_DIGEST_SIZE,       sizeof(Sha2_32State),   HASH_STATE_SHA2_32_SIZE },
    { SHA_384,      SHA2_64_BLOCK_SIZE,  SHA_384_DIGEST_SIZE,       sizeof(Sha2_64State),   HASH_STATE_SHA2_64_SIZE },
    { SHA_512_224,  SHA2_64_BLOCK_SIZE,  SHA_512_224_DIGEST_SIZE,   sizeof(Sha2_64State),   HASH_STATE_SHA2_64_SIZE },
    { SHA_512_256,  SHA2_64_BLOCK_SIZE,  SHA_512_256_DIGEST_SIZE,   sizeof(Sha2_64State),   HASH_STATE_SHA2_64_SIZE },
    { SHA_512,      SHA2_64_BLOCK_SIZE,  SHA_512_DIGEST_SIZE,       sizeof(Sha2_64State),   HASH_STATE_SHA2_64_SIZE },
    { SHA3_224,     SHA3_224_BLOCK_SIZE, SHA3_224_DIGEST_SIZE,      sizeof(Sha3_224State),  HASH_STATE_SHA3_224_SIZE },
    { SHA3_256,     SHA3_256_BLOCK_SIZE, SHA3_256_DIGEST_SIZE,      sizeof(Sha3_256State),  HASH_STATE_SHA3_256_SIZE },
    { SHA3_384,     SHA3_384_BLOCK_SIZE, SHA3_384_DIGEST_SIZE,      sizeof(Sha3_384State),  HASH_STATE_SHA3_384_SIZE },
    { SHA3_512,     SHA3_512_BLOCK_SIZE, SHA3_512_DIGEST_SIZE,      sizeof(Sha3_512State),  HASH_STATE_SHA3_512_SIZE }
};

#define XOF_STATE_HEADER_SIZE           sizeof(XofState) - sizeof(uint64_t)

#define XOF_STATE_SHAKE128_SIZE         XOF_STATE_HEADER_SIZE + sizeof(Shake128State)
#define XOF_STATE_SHAKE256_SIZE         XOF_STATE_HEADER_SIZE + sizeof(Shake256State)

const XofSizes g_XofSizesMapping[2] =
{
    { SHAKE128, SHAKE128_BLOCK_SIZE, sizeof(Shake128State), XOF_STATE_SHAKE128_SIZE },
    { SHAKE256, SHAKE256_BLOCK_SIZE, sizeof(Shake256State), XOF_STATE_SHAKE256_SIZE }
};

#define PRF_STATE_HEADER_SIZE                sizeof(PrfState) - sizeof(uint64_t)

#define PRF_STATE_HMAC_SHA1_SIZE             PRF_STATE_HEADER_SIZE + sizeof(Hmac_Sha1State)
#define PRF_STATE_HMAC_SHA2_32_SIZE          PRF_STATE_HEADER_SIZE + sizeof(Hmac_Sha2_32State)
#define PRF_STATE_HMAC_SHA2_64_SIZE          PRF_STATE_HEADER_SIZE + sizeof(Hmac_Sha2_64State)
#define PRF_STATE_HMAC_SHA3_224_SIZE         PRF_STATE_HEADER_SIZE + sizeof(Hmac_Sha3_224State)
#define PRF_STATE_HMAC_SHA3_256_SIZE         PRF_STATE_HEADER_SIZE + sizeof(Hmac_Sha3_256State)
#define PRF_STATE_HMAC_SHA3_384_SIZE         PRF_STATE_HEADER_SIZE + sizeof(Hmac_Sha3_384State)
#define PRF_STATE_HMAC_SHA3_512_SIZE         PRF_STATE_HEADER_SIZE + sizeof(Hmac_Sha3_512State)

const PrfSizes g_PrfSizesMapping[11] = {
    { HMAC_SHA1,        SHA1,        sizeof(Hmac_Sha1State),        PRF_STATE_HMAC_SHA1_SIZE     },
    { HMAC_SHA_224,     SHA_224,     sizeof(Hmac_Sha2_32State),     PRF_STATE_HMAC_SHA2_32_SIZE  },
    { HMAC_SHA_256,     SHA_256,     sizeof(Hmac_Sha2_32State),     PRF_STATE_HMAC_SHA2_32_SIZE  },
    { HMAC_SHA_384,     SHA_384,     sizeof(Hmac_Sha2_64State),     PRF_STATE_HMAC_SHA2_64_SIZE  },
    { HMAC_SHA_512_224, SHA_512_224, sizeof(Hmac_Sha2_64State),     PRF_STATE_HMAC_SHA2_64_SIZE  },
    { HMAC_SHA_512_256, SHA_512_256, sizeof(Hmac_Sha2_64State),     PRF_STATE_HMAC_SHA2_64_SIZE  },
    { HMAC_SHA_512,     SHA_512,     sizeof(Hmac_Sha2_64State),     PRF_STATE_HMAC_SHA2_64_SIZE  },
    { HMAC_SHA3_224,    SHA3_224,    sizeof(Hmac_Sha3_224State),    PRF_STATE_HMAC_SHA3_224_SIZE },
    { HMAC_SHA3_256,    SHA3_256,    sizeof(Hmac_Sha3_256State),    PRF_STATE_HMAC_SHA3_256_SIZE },
    { HMAC_SHA3_384,    SHA3_384,    sizeof(Hmac_Sha3_384State),    PRF_STATE_HMAC_SHA3_384_SIZE },
    { HMAC_SHA3_512,    SHA3_512,    sizeof(Hmac_Sha3_512State),    PRF_STATE_HMAC_SHA3_512_SIZE }
};

// AddPaddingInternal function adds padding and fills last block by padding directly to output with respective offset 
// and when fillLastBlock is set and (inputSize % blockSize != 0) it also copying the begining of the last input block to output with respective offset
int AddPaddingInternal(__in const void* input, __in size_t inputSize, __in PaddingType padding, __in size_t blockSize, __out void* output, __inout size_t* outputSize, __in bool fillLastBlock)
{
    assert((input || !inputSize) && output && outputSize);

    int status = NO_ERROR;

    switch (padding) {
    case No_padding:
        // here we don't using '&' operator to theoretically accept blockSize that is not power of two
        if (inputSize % blockSize)
            status = ERROR_INAPPLICABLE_PADDING_TYPE;
        else {
            *outputSize = inputSize;

            if (fillLastBlock) {
                size_t offset = inputSize - blockSize;
                memcpy((uint8_t*)output + offset, (uint8_t*)input + offset, blockSize);
            }
        }
        break;

    case Zero_padding:
        status = AddZeroPadding(input, inputSize, blockSize, output, outputSize, fillLastBlock);
        break;

    case PKCSN7_padding:
        if (blockSize > MAX_PKCSN7_BLOCK_SIZE)
            status = ERROR_TOO_BIG_BLOCK_SIZE;
        else
            status = AddPKCSN7Padding(input, inputSize, (uint8_t)blockSize, output, outputSize, fillLastBlock);
        break;

    case ISO_7816_padding:
        status = AddISO7816Padding(input, inputSize, blockSize, output, outputSize, fillLastBlock);
        break;

    default:
        break;
    }

    return status;
}

int PullPaddingSizeInternal(__in PaddingType padding, __in const uint8_t* input, __in size_t blockSize, __out size_t* paddingSize)
{
    int status = NO_ERROR;

    switch (padding) {
    case No_padding:
        *paddingSize = 0;
        break;

    case Zero_padding:
        status = PullZeroPaddingSize(input, blockSize, paddingSize);
        break;

    case PKCSN7_padding:
        status = PullPKCSN7PaddingSize(input, blockSize, (uint8_t*)paddingSize);
        break;

    case ISO_7816_padding:
        status = PullISO7816PaddingSize(input, blockSize, paddingSize);
        break;

    default:
        break;
    }

    return status;
}

int CutPaddingInternal(__in PaddingType padding, __in size_t blockSize, __out uint8_t* paddedOutput, __inout size_t* outputSize)
{
    int status = NO_ERROR;

    switch (padding) {
    case No_padding:
        if (*outputSize % blockSize)
            status = ERROR_INAPPLICABLE_PADDING_TYPE;
        break;

    case Zero_padding:
        CutZeroPadding(blockSize, paddedOutput, outputSize);
        break;

    case PKCSN7_padding:
        CutPKCSN7Padding(blockSize, paddedOutput, outputSize);
        break;

    case ISO_7816_padding:
        CutISO7816Padding(blockSize, paddedOutput, outputSize);
        break;

    default:
        break;
    }

    return status;
}

inline size_t GetSpecificBlockCipherStateSize(__in BlockCipherType cipher)
{
    switch (cipher) {
    case DES_cipher_type:
        return sizeof(DesState);
    case TDES_cipher_type:
        return sizeof(TdesState);
    case AES128_cipher_type:
        return sizeof(Aes128State);
    case AES192_cipher_type:
        return sizeof(Aes192State);
    case AES256_cipher_type:
        return sizeof(Aes256State);
    default:
        return 0;
    }
}

int InitBlockCiperStateInternal(__inout BlockCipherState** state, __in BlockCipherType cipher, __in CryptoMode cryptoMode, __in BlockCipherOpMode opMode, __in PaddingType padding, __in const void* key, __in_opt const void* iv)
{
    assert(state && key && (opMode == ECB_mode || iv));

    int status = NO_ERROR;

    EVAL(AllocBuffer(state, sizeof(BlockCipherState)));
    (*state)->cipher = cipher;

    size_t specificStateSize = GetSpecificBlockCipherStateSize(cipher);

    switch (cipher) {
    case DES_cipher_type:
    case TDES_cipher_type:
        EVAL(AllocBuffer(&(*state)->state, specificStateSize));
        break;
    case AES128_cipher_type:
    case AES192_cipher_type:
    case AES256_cipher_type:
        EVAL(AlignedAllocBuffer(&(*state)->state, specificStateSize, 16));
        break;
    }

    BlockCipherKeySchedule(cipher, key, (*state)->state);

    ReInitBlockCipherCryptoModeInternal(*state, cryptoMode);
    ReInitBlockCipherOpModeInternal(*state, opMode);
    ReInitBlockCipherPaddingTypeInternal(*state, padding);

    if (iv)
        ReInitBlockCipherIvInternal(cipher, iv, (*state)->state);

exit:
    return status;
}

void BlockCipherKeySchedule(__in BlockCipherType cipher, __in const void* key, __inout void* specificCipherState)
{
    assert(key && specificCipherState);

    switch (cipher) {
    case DES_cipher_type:
    case TDES_cipher_type:
        DesKeySchedule(cipher, key, specificCipherState);
        break;
    case AES128_cipher_type:
    case AES192_cipher_type:
    case AES256_cipher_type:
        AesKeySchedule(cipher, key, specificCipherState);
    }
}

inline void ReInitBlockCipherCryptoModeInternal(__inout BlockCipherState* state, __in CryptoMode cryptoMode)
{
    assert(state);

    state->enMode = cryptoMode;
}

inline void ReInitBlockCipherOpModeInternal(__inout BlockCipherState* state, __in BlockCipherOpMode opMode)
{
    assert(state);

    state->opMode = opMode;
}

inline void ReInitBlockCipherPaddingTypeInternal(__inout BlockCipherState* state, __in PaddingType padding)
{
    assert(state);

    state->padding = padding;
}

void ReInitBlockCipherIvInternal(__in BlockCipherType cipher, __in const void* iv, __inout void* specificCipherState)
{
    assert(specificCipherState);

    switch (cipher) {
    case DES_cipher_type:
        ((DesState*)specificCipherState)->iv = *(uint64_t*)iv;
        break;
    case TDES_cipher_type:
        ((TdesState*)specificCipherState)->iv = *(uint64_t*)iv;
        break;
    case AES128_cipher_type:
        ((Aes128State*)specificCipherState)->iv[0] = ((uint64_t*)iv)[0];
        ((Aes128State*)specificCipherState)->iv[1] = ((uint64_t*)iv)[1];
        break;
    case AES192_cipher_type:
        ((Aes192State*)specificCipherState)->iv[0] = ((uint64_t*)iv)[0];
        ((Aes192State*)specificCipherState)->iv[1] = ((uint64_t*)iv)[1];
        break;
    case AES256_cipher_type:
        ((Aes256State*)specificCipherState)->iv[0] = ((uint64_t*)iv)[0];
        ((Aes256State*)specificCipherState)->iv[1] = ((uint64_t*)iv)[1];
        break;
    }
}

int ProcessingByBlockCipherInternal(__inout BlockCipherState* state, __in const void* input, __in size_t inputSize, __in bool finalize, __out_opt void* output, __inout size_t* outputSize)
{
    assert(state && input && outputSize && (!finalize || output));

    switch (state->cipher) {
    case DES_cipher_type:
    case TDES_cipher_type:
        if (state->enMode == Encryption_mode)
            return DesEncrypt(state->state, state->cipher, state->opMode, state->padding, input, inputSize, finalize, output, outputSize);
        else
            return DesDecrypt(state->state, state->cipher, state->opMode, state->padding, input, inputSize, finalize, output, outputSize);
    case AES128_cipher_type:
    case AES192_cipher_type:
    case AES256_cipher_type:
        if (state->enMode == Encryption_mode)
            return AesEncrypt(state->state, state->cipher, state->opMode, state->padding, input, inputSize, finalize, output, outputSize);
        else
            return AesDecrypt(state->state, state->cipher, state->opMode, state->padding, input, inputSize, finalize, output, outputSize);
    default:
        return NO_ERROR;
    }
}

int FillLastDecryptedBlockInternal(__in PaddingType padding, __in size_t blockSize, __in const void* lastOutputBlock, __in size_t inputSize, __out void* output, __inout size_t* outputSize)
{
    int status = NO_ERROR;
    size_t paddingSize = 0;

    if (status = PullPaddingSizeInternal(padding, lastOutputBlock, blockSize, &paddingSize))
        return status;
    else if (paddingSize > blockSize)
        return ERROR_PADDING_CORRUPTED;

    size_t requiringSize = inputSize - paddingSize;

    if (requiringSize > *outputSize) {
        *outputSize = requiringSize;
        return ERROR_TOO_SMALL_OUTPUT_SIZE;
    }

    *outputSize = requiringSize;

    // parenthesis over inputSize - blockSize is a little integer overflow protection
    memcpy((uint8_t*)output + (inputSize - blockSize), lastOutputBlock, blockSize - paddingSize);

    return NO_ERROR;
}

void FreeBlockCipherStateInternal(__inout BlockCipherState* state)
{
    assert(state && state->state);

    size_t specificStateSize = GetSpecificBlockCipherStateSize(state->cipher);

    memset_s(state->state, specificStateSize, 0, specificStateSize);

    switch (state->cipher) {
    case DES_cipher_type:
    case TDES_cipher_type:
        FreeBuffer(state->state);
        break;
    case AES128_cipher_type:
    case AES192_cipher_type:
    case AES256_cipher_type:
        AlignedFreeBuffer(state->state);
        break;
    }

    memset_s(state, sizeof(BlockCipherState), 0, sizeof(BlockCipherState));
    FreeBuffer(state);
}

int InitHashStateInternal(__inout HashState** state, __in HashFunc func)
{
    assert(state);

    int status = NO_ERROR;

    EVAL(AllocBuffer(state, g_hashFuncsSizesMapping[func].stateAndHeaderSize));
    (*state)->func = func;
    ResetHashStateInternal(*state);

exit:
    return status;
}

void ResetHashStateInternal(__inout HashState* state)
{
    assert(state);

    uint8_t* startZeroing = (uint8_t*)state->state;
    uint16_t sizeZeroing = g_hashFuncsSizesMapping[state->func].stateSize;

    switch (state->func) {
    case SHA1:
        Sha1InitState((uint32_t*)state->state);
        startZeroing += sizeof(((Sha1State*)0)->state);
        sizeZeroing -= sizeof(((Sha1State*)0)->state);
        break;
    case SHA_224:
    case SHA_256:
        Sha2_32InitState(state->func, (uint32_t*)state->state);
        startZeroing += sizeof(((Sha2_32State*)0)->state);
        sizeZeroing -= sizeof(((Sha2_32State*)0)->state);
        break;
    case SHA_384:
    case SHA_512_224:
    case SHA_512_256:
    case SHA_512:
        Sha2_64InitState(state->func, state->state);
        startZeroing += sizeof(((Sha2_64State*)0)->state);
        sizeZeroing -= sizeof(((Sha2_64State*)0)->state);
        break;
    }

    memset(startZeroing, 0, sizeZeroing);
}

void GetHashInternal(__inout HashState* state, __in_opt const void* input, __in size_t inputSize, __in bool finalize, __out_opt void* output)
{
    assert(state && (!finalize || output) && (input || !inputSize));

    switch (state->func) {
    case SHA1:
        Sha1Get((Sha1State*)state->state, input, inputSize, finalize, output);
        break;
    case SHA_224:
    case SHA_256:
        Sha2_32Get((Sha2_32State*)state->state, input, inputSize, state->func, finalize, output);
        break;
    case SHA_384:
    case SHA_512_224:
    case SHA_512_256:
    case SHA_512:
        Sha2_64Get((Sha2_64State*)state->state, input, inputSize, state->func, finalize, output);
        break;
    case SHA3_224:
    case SHA3_256:
    case SHA3_384:
    case SHA3_512:
        Sha3GetHash(state->state, input, inputSize, state->func, finalize, output);
        break;
    }

    if (finalize)
        ResetHashStateInternal(state);
}

inline void FreeHashStateInternal(__inout HashState* state)
{
    assert(state);

    memset_s(state, g_hashFuncsSizesMapping[state->func].stateAndHeaderSize, 0, g_hashFuncsSizesMapping[state->func].stateAndHeaderSize);

    FreeBuffer(state);
}

int InitXofStateInternal(__inout XofState** state, __in Xof func)
{
    assert(state);

    int status = NO_ERROR;

    EVAL(AllocBuffer(state, g_XofSizesMapping[func].stateAndHeaderSize));
    (*state)->func = func;
    ResetXofStateInternal(*state);

exit:
    return status;
}

inline void ResetXofStateInternal(__inout XofState* state)
{
    assert(state);

    memset(state->state, 0, g_XofSizesMapping[state->func].stateSize);
}

void GetXofInternal(__inout XofState* state, __in const void* input, __in size_t inputSize, __in bool finalize, __out_opt void* output, __in size_t outputSize)
{
    assert(state && (!finalize || output) && outputSize && (input || !inputSize));

    Xof func = state->func;

    switch (func) {
    case SHAKE128:
    case SHAKE256:
        Sha3GetXof(state->state, input, inputSize, func, finalize, output, outputSize);
        break;
    }

    if (finalize)
        ResetXofStateInternal(state);
}

inline void FreeXofStateInternal(__inout XofState* state)
{
    assert(state);

    memset_s(state, g_XofSizesMapping[state->func].stateAndHeaderSize, 0, g_XofSizesMapping[state->func].stateAndHeaderSize);

    FreeBuffer(state);
}

int InitPrfStateInternal(__inout PrfState** state, __in Prf func)
{
    assert(state);

    int status = NO_ERROR;

    EVAL(AllocBuffer(state, g_PrfSizesMapping[func].stateAndHeaderSize));
    (*state)->func = func;
    ResetPrfStateInternal(*state);

exit:
    return status;
}

inline void ResetPrfStateInternal(__inout PrfState* state)
{
    assert(state);

    memset(state->state, 0, g_PrfSizesMapping[state->func].stateSize);
}

void GetPrfInternal(__inout PrfState* state, __in_opt const void* input, __in size_t inputSize, __in_opt const void* key, __in size_t keySize, __in bool finalize, __out_opt void* output, __in_opt size_t outputSize)
{
    assert(state && (!finalize || output) && (input || !inputSize) && (key || !keySize));

    Prf func = state->func;

    switch (func) {
    case HMAC_SHA1:
    case HMAC_SHA_224:
    case HMAC_SHA_256:
    case HMAC_SHA_384:
    case HMAC_SHA_512_224:
    case HMAC_SHA_512_256:
    case HMAC_SHA_512:
    case HMAC_SHA3_224:
    case HMAC_SHA3_256:
    case HMAC_SHA3_384:
    case HMAC_SHA3_512: {
        GetHmac(state->state, input, inputSize, key, keySize, func, finalize, output);
        break;
    }
    }

    if (finalize)
        ResetPrfStateInternal(state);
}

inline void FreePrfStateInternal(__inout PrfState* state)
{
    assert(state);

    memset_s(state, g_PrfSizesMapping[state->func].stateAndHeaderSize, 0, g_PrfSizesMapping[state->func].stateAndHeaderSize);

    FreeBuffer(state);
}
