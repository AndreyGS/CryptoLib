#include "pch.h"

#include "crypto.h"
#include "crypto_internal.h"

/*
    suffix Internal in function naming == Unsafe
*/

inline int CheckPaddingArguments(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __in void* output, __in uint64_t* outputSize);
inline int GetZeroPaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize);

int GetPadding(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckPaddingArguments(input, inputSize, blockSize, output, outputSize))
        return status;
    
    return GetPaddingInternal(input, inputSize, padding, blockSize, output, outputSize);
}

inline int GetPaddingInternal(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize)
{
    switch (padding) {
    case No_padding:
        // here we don't using '&' operator to theoretically accept blockSize that is not power of two
        if (inputSize % blockSize)
            return ERROR_INAPLICABLE_PADDING_TYPE;
        else {
            *outputSize = inputSize;
            return NO_ERROR;
        }

    case Zero_padding:
        return GetZeroPaddingInternal(input, inputSize, blockSize, output, outputSize);

    default:
        return NO_ERROR;
    }
}

inline int CheckPaddingArguments(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __in void* output, __in uint64_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckInputOutput(input, inputSize, output, outputSize))
        return status;
    else if (!blockSize)
        return ERROR_WRONG_BLOCK_SIZE;
    else
        return NO_ERROR;
}

inline bool IsWholeBlockMultiplier(uint64_t inputSize, uint64_t blockSize)
{
    return !(inputSize & (blockSize - 1));
}

inline void FillBySingleValue(__out void* output, __in unsigned char value, __in uint64_t length)
{
    while (length--)
        *((unsigned char*)output)++ = value;
}

int GetZeroPadding(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckPaddingArguments(input, inputSize, blockSize, output, outputSize))
        return status;
    
    return GetZeroPaddingInternal(input, inputSize, blockSize, output, outputSize);
}

inline int GetZeroPaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize)
{
    uint64_t requiringSize = IsWholeBlockMultiplier(inputSize, blockSize) ? inputSize + blockSize : ((inputSize + blockSize - 1) & ~(blockSize - 1)) + blockSize;

    if (*outputSize < requiringSize) {
        *outputSize = requiringSize;
        return ERROR_WRONG_OUTPUT;
    }

    *outputSize = requiringSize;

    FillBySingleValue((unsigned char*)output + inputSize, '\0', requiringSize - inputSize);

    return 0;
}