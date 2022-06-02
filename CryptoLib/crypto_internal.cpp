#include "pch.h"

#include "crypto_internal.h"
#include "block_ciphers_main.h"
#include "paddings.h"
#include "des.h"
#include "sha-1.h"
#include "sha-2.h"
#include "sha-3.h"
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

    ReInitBlockCiperCryptoModeInternal(*state, cryptoMode);
    ReInitBlockCiperOpModeInternal(*state, opMode);
    ReInitBlockCiperPaddingTypeInternal(*state, padding);

    if (iv)
        ReInitBlockCiperIvInternal(*state, iv);

exit:
    return status
}

void GetBlockCipherRoundsKeysInternal(__in BlockCipherType cipherType, __in const void* key, __out void* roundsKeys)
{
    switch (cipherType) {
    case DES_cipher_type:
        SingleDesGetRoundsKeys(*(uint64_t*)key, roundsKeys);
        break;
    case TDES_cipher_type:
        TripleDesGetRoundsKeys(key, roundsKeys);
        break;
    }
}

inline void ReInitBlockCiperCryptoModeInternal(__inout BlockCipherState* state, __in CryptoMode cryptoMode)
{
    assert(state);

    state->enMode = cryptoMode;
}

inline void ReInitBlockCiperOpModeInternal(__inout BlockCipherState* state, __in BlockCipherOpMode opMode)
{
    assert(state);

    state->opMode = opMode;
}

inline void ReInitBlockCiperPaddingTypeInternal(__inout BlockCipherState* state, __in PaddingType padding)
{
    assert(state);

    state->padding = padding;
}

void ReInitBlockCiperIvInternal(__inout BlockCipherState* state, __in void* iv)
{
    assert(state);

    switch (state->cipher) {
    case DES_cipher_type:
        ((DesState*)&(state->state))->iv = *(uint64_t*)iv;
        break;
    case TDES_cipher_type:
        ((TdesState*)&(state->state)))->iv = *(uint64_t*)iv;
        break;
    }
}

int ProcessingByBlockCipherInternal(__inout BlockCipherState* state, __in const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output, __inout uint64_t* outputSize)
{
    switch (state->enMode) {
    case Encryption_mode:
        return EncryptByBlockCipher(state->state, state->cipher, state->opMode, state->padding, finalize, output, outputSize);
    case Decryption_mode:
        return DecryptByBlockCipher(state->state, state->cipher, state->opMode, state->padding, finalize, output, outputSize);
    default:
        return ERROR_WRONG_STATE_HANDLE;
    }
}

int InitHashStateInternal(__inout HashHandle* handle, __in HashFunc func)
{
    assert(handle);

    int status = NO_ERROR;

    EVAL(AllocBuffer(g_hashFuncsSizesMapping[func].stateAndHeaderSize, handle));
    *(HashFunc*)(*handle) = func;
    ResetHashStateInternal(*handle);

exit:
    return status;
}

void ResetHashStateInternal(__inout HashHandle handle)
{
    assert(handle);

    HashFunc func = *(HashFunc*)handle;

    uint8_t* startZeroing = (uint8_t*)((HashState*)handle)->state;
    uint16_t sizeZeroing = g_hashFuncsSizesMapping[func].stateSize;

    switch (func) {
    case SHA1:
        Sha1InitState((uint32_t*)((HashState*)handle)->state);
        startZeroing += sizeof(((Sha1State*)0)->state);
        sizeZeroing -= sizeof(((Sha1State*)0)->state);
        break;
    case SHA_224:
    case SHA_256:
        Sha2_32InitState(func, (uint32_t*)((HashState*)handle)->state);
        startZeroing += sizeof(((Sha2_32State*)0)->state);
        sizeZeroing -= sizeof(((Sha2_32State*)0)->state);
        break;
    case SHA_384:
    case SHA_512_224:
    case SHA_512_256:
    case SHA_512:
        Sha2_64InitState(func, ((HashState*)handle)->state);
        startZeroing += sizeof(((Sha2_64State*)0)->state);
        sizeZeroing -= sizeof(((Sha2_64State*)0)->state);
        break;
    }

    memset(startZeroing, 0, sizeZeroing);
}

void GetHashInternal(__inout HashState* state, __in const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output)
{
    assert(state && (output || (!finalize && !output)) && (input || (!input && !inputSize)));

    HashFunc func = state->func;

    switch (func) {
    case SHA1:
        Sha1Get((Sha1State*)state->state, input, inputSize, finalize, output);
        break;
    case SHA_224:
    case SHA_256:
        Sha2_32Get((Sha2_32State*)state->state, input, inputSize, func, finalize, output);
        break;
    case SHA_384:
    case SHA_512_224:
    case SHA_512_256:
    case SHA_512:
        Sha2_64Get((Sha2_64State*)state->state, input, inputSize, func, finalize, output);
        break;
    case SHA3_224:
    case SHA3_256:
    case SHA3_384:
    case SHA3_512:
        Sha3GetHash(state->state, input, inputSize, func, finalize, output);
        break;
    }

    if (finalize)
        ResetHashStateInternal(state);
}

void FreeHashStateInternal(__inout HashHandle handle)
{
    assert(handle);

    HashFunc func = *(HashFunc*)handle;

    memset_s(handle, g_hashFuncsSizesMapping[func].stateAndHeaderSize, 0, g_hashFuncsSizesMapping[func].stateAndHeaderSize);

    FreeBuffer(handle);
}

int InitXofStateInternal(__inout XofHandle* handle, __in Xof func)
{
    assert(handle);

    int status = NO_ERROR;

    EVAL(AllocBuffer(g_XofSizesMapping[func].stateAndHeaderSize, handle));
    *(Xof*)(*handle) = func;
    ResetXofStateInternal(*handle);

exit:
    return status;
}

inline void ResetXofStateInternal(__inout XofHandle handle)
{
    assert(handle);

    memset(((XofState*)handle)->state, 0, g_XofSizesMapping[*(Xof*)handle].stateSize);
}

void GetXofInternal(__inout XofState* state, __in const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output, __in uint64_t outputSize)
{
    assert(state && (output || (!finalize && !output)) && outputSize && (input || (!input && !inputSize)));

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

void FreeXofStateInternal(__inout XofHandle handle)
{
    assert(handle);

    Xof func = *(Xof*)handle;

    memset_s(handle, g_XofSizesMapping[func].stateAndHeaderSize, 0, g_XofSizesMapping[func].stateAndHeaderSize);

    FreeBuffer(handle);
}

int InitPrfStateInternal(__inout PrfHandle* handle, __in Prf func)
{
    assert(handle);

    int status = NO_ERROR;

    EVAL(AllocBuffer(g_PrfSizesMapping[func].stateAndHeaderSize, handle));
    *(Prf*)(*handle) = func;
    ResetPrfStateInternal(*handle);

exit:
    return status;
}

inline void ResetPrfStateInternal(__inout PrfHandle handle)
{
    assert(handle);

    memset(((PrfState*)handle)->state, 0, g_PrfSizesMapping[*(Prf*)handle].stateSize);
}

void GetPrfInternal(__inout PrfState* state, __in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __in bool finalize, __out_opt void* output, __in_opt uint64_t outputSize)
{
    assert(state && (output || (!finalize && !output)) && (input || (!input && !inputSize)) && (key || (!key && !keySize)));

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

void FreePrfStateInternal(__inout PrfHandle handle)
{
    assert(handle);

    Prf func = *(Prf*)handle;

    memset_s(handle, g_PrfSizesMapping[func].stateAndHeaderSize, 0, g_PrfSizesMapping[func].stateAndHeaderSize);

    FreeBuffer(handle);
}
