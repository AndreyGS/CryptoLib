/*
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
 * @section DESCRIPTON
 *
 * This file represents public interface, enums and macros of CryptoLib
 */

#include "pch.h"

#include "crypto_internal.h"
#include "paddings.h"
#include "hmac.h"

int InitBlockCiperStateInternal(__inout BlockCipherState** state, __in BlockCipherType cipher, __in CryptoMode cryptoMode, __in BlockCipherOpMode opMode, __in PaddingType padding, __in const void* key, __in_opt void* iv)
{
    int status = NO_ERROR;
    void* roundsKeys = NULL;

    EVAL(AllocBuffer(g_blockCiphersSizes[cipher].stateAndHeaderSize, state));

    (*state)->cipher = cipher;

    switch (cipher) {
    case DES_cipher_type:
        roundsKeys = ((DesState*)&((*state)->state))->roundsKeys;
        break;
    case TDES_cipher_type:
        roundsKeys = ((TdesState*)&((*state)->state))->roundsKeys;
        break;
    }

    GetBlockCipherRoundsKeysInternal(cipher, key, roundsKeys);

    ReInitBlockCipherCryptoModeInternal(*state, cryptoMode);
    ReInitBlockCipherOpModeInternal(*state, opMode);
    ReInitBlockCipherPaddingTypeInternal(*state, padding);

    if (iv)
        ReInitBlockCipherIvInternal(*state, iv);

exit:
    return status;
}

void GetBlockCipherRoundsKeysInternal(__in BlockCipherType cipher, __in const void* key, __out void* roundsKeys)
{
    switch (cipher) {
    case DES_cipher_type:
    case TDES_cipher_type:
        DesGetRoundsKeys(cipher, key, roundsKeys);
        break;
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

void ReInitBlockCipherIvInternal(__inout BlockCipherState* state, __in const void* iv)
{
    assert(state);

    switch (state->cipher) {
    case DES_cipher_type:
        ((DesState*)&(state->state))->iv = *(uint64_t*)iv;
        break;
    case TDES_cipher_type:
        ((TdesState*)&(state->state))->iv = *(uint64_t*)iv;
        break;
    }
}

int ProcessingByBlockCipherInternal(__inout BlockCipherState* state, __in const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output, __inout uint64_t* outputSize)
{
    assert(state && input && outputSize && (!finalize || output));

    switch (state->cipher) {
    case DES_cipher_type:
    case TDES_cipher_type:
        if (state->enMode == Encryption_mode)
            return DesEncrypt(state->state, state->cipher, state->opMode, state->padding, input, inputSize, finalize, output, outputSize);
        else
            return DesDecrypt(state->state, state->cipher, state->opMode, state->padding, input, inputSize, finalize, output, outputSize);
    default:
        return NO_ERROR;
    }
}

inline void FreeBlockCipherStateInternal(__inout BlockCipherState* state)
{
    assert(state);

    memset_s(state, g_blockCiphersSizes[state->cipher].stateAndHeaderSize, 0, g_blockCiphersSizes[state->cipher].stateAndHeaderSize);

    FreeBuffer(state);
}

int InitHashStateInternal(__inout HashState** state, __in HashFunc func)
{
    assert(state);

    int status = NO_ERROR;

    EVAL(AllocBuffer(g_hashFuncsSizesMapping[func].stateAndHeaderSize, state));
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

void GetHashInternal(__inout HashState* state, __in_opt const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output)
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

    EVAL(AllocBuffer(g_XofSizesMapping[func].stateAndHeaderSize, state));
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

void GetXofInternal(__inout XofState* state, __in const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output, __in uint64_t outputSize)
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

    EVAL(AllocBuffer(g_PrfSizesMapping[func].stateAndHeaderSize, state));
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

void GetPrfInternal(__inout PrfState* state, __in_opt const void* input, __in uint64_t inputSize, __in_opt const void* key, __in uint64_t keySize, __in bool finalize, __out_opt void* output, __in_opt uint64_t outputSize)
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
