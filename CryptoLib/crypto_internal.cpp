#include "pch.h"

#include "crypto_internal.h"
#include "paddings.h"
#include "sha-1.h"
#include "sha-2.h"
#include "sha-3.h"
#include "hmac.h"

int InitHashStateInternal(__inout HashHandle* handle, __in HashFunc func)
{
    int status = NO_ERROR;

    EVAL(AllocBuffer(g_hashFuncsSizesMapping[func].stateAndHeaderSize, handle));
    *(HashFunc*)(*handle) = func;
    ResetHashStateInternal(*handle);

exit:
    return status;
}

void ResetHashStateInternal(__inout HashHandle handle)
{
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
    default:
        break;
    }

    memset(startZeroing, 0, sizeZeroing);
}

void GetHashInternal(__inout HashState* state, __out_opt void* output, __in const void* input, __in uint64_t inputSize, __in bool finalize)
{
    HashFunc func = state->func;

    switch (func) {
    case SHA1:
        Sha1Get((Sha1State*)state->state, output, input, inputSize, finalize);
        break;
    case SHA_224:
    case SHA_256:
        Sha2_32Get((Sha2_32State*)state->state, output, input, inputSize, func, finalize);
        break;
    case SHA_384:
    case SHA_512_224:
    case SHA_512_256:
    case SHA_512:
        Sha2_64Get((Sha2_64State*)state->state, output, input, inputSize, func, finalize);
        break;
    case SHA3_224:
    case SHA3_256:
    case SHA3_384:
    case SHA3_512:
        Sha3GetHash(state->state, output, input, inputSize, func, finalize);
        break;
    default:
        break;
    }

    if (finalize)
        ResetHashStateInternal(state);
}

void FreeHashStateInternal(__inout HashHandle handle)
{
    HashFunc func = *(HashFunc*)handle;

    memset_s(handle, g_hashFuncsSizesMapping[func].stateAndHeaderSize, 0, g_hashFuncsSizesMapping[func].stateAndHeaderSize);

    FreeBuffer(handle);
}

int InitXofStateInternal(__inout XofHandle* handle, __in Xof func)
{
    int status = NO_ERROR;

    EVAL(AllocBuffer(g_XofSizesMapping[func].stateAndHeaderSize, handle));
    *(Xof*)(*handle) = func;
    ResetXofStateInternal(*handle);

exit:
    return status;
}

void ResetXofStateInternal(__inout XofHandle handle)
{
    memset(((XofState*)handle)->state, 0, g_XofSizesMapping[*(Xof*)handle].stateSize);
}

void GetXofInternal(__inout XofState* state, __out_opt void* output, __in uint64_t outputSize, __in const void* input, __in uint64_t inputSize, __in bool finalize)
{
    Xof func = state->func;

    switch (func) {
    case SHAKE128:
    case SHAKE256:
        Sha3GetXof(state->state, output, outputSize, input, inputSize, func, finalize);
        break;
    default:
        break;
    }

    if (finalize)
        ResetXofStateInternal(state);
}

void FreeXofStateInternal(__inout XofHandle handle)
{
    Xof func = *(Xof*)handle;

    memset_s(handle, g_XofSizesMapping[func].stateAndHeaderSize, 0, g_XofSizesMapping[func].stateAndHeaderSize);

    FreeBuffer(handle);
}

int InitPrfStateInternal(__inout PrfHandle* handle, __in Prf func)
{
    int status = NO_ERROR;

    EVAL(AllocBuffer(g_PrfSizesMapping[func].stateAndHeaderSize, handle));
    *(Prf*)(*handle) = func;
    ResetPrfStateInternal(*handle);

exit:
    return status;
}

void ResetPrfStateInternal(__inout PrfHandle handle)
{
    memset(((PrfState*)handle)->state, 0, g_PrfSizesMapping[*(Prf*)handle].stateSize);
}

void GetPrfInternal(__inout PrfState* state, __out_opt void* output, __out_opt uint64_t outputSize, __in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __in bool finalize)
{
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
        GetHmac(state->state, output, input, inputSize, key, keySize, func, finalize);
        break;
    }
    default:
        break;
    }

    if (finalize)
        ResetPrfStateInternal(state);
}

void FreePrfStateInternal(__inout PrfHandle handle)
{
    Prf func = *(Prf*)handle;

    memset_s(handle, g_PrfSizesMapping[func].stateAndHeaderSize, 0, g_PrfSizesMapping[func].stateAndHeaderSize);

    FreeBuffer(handle);
}
