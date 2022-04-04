#include "pch.h"
#include "crypto_internal.h"

/*
    suffix Internal in function naming == Unsafe
*/
inline int AddZeroPaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize);
inline int AddPKCSN7PaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize);
inline void CutZeroPaddingInternal(__in uint64_t blockSize, __in const void* paddedOutput, __inout uint64_t* outputSize);
inline void CutPKCSN7PaddingInternal(__in uint64_t blockSize, __in const void* paddedOutput, __inout uint64_t* outputSize);

inline int CheckPaddingInputOutput(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __in void* output, __in uint64_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckInputOutput(input, inputSize, output, outputSize))
        return status;
    else if (!blockSize)
        return ERROR_WRONG_BLOCK_SIZE;
    else
        return NO_ERROR;
}

inline int CheckPaddingOutput(__in uint64_t blockSize, __in const void* paddedOutput, __in uint64_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckOutput(paddedOutput, outputSize))
        return status;
    else if (!blockSize)
        return ERROR_WRONG_BLOCK_SIZE;
    else
        return NO_ERROR;
}

int AddPadding(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckPaddingInputOutput(input, inputSize, blockSize, output, outputSize))
        return status;
    
    return AddPaddingInternal(input, inputSize, padding, blockSize, output, outputSize);
}

inline int AddPaddingInternal(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;

    switch (padding) {
    case No_padding:
        // here we don't using '&' operator to theoretically accept blockSize that is not power of two
        if (inputSize % blockSize)
            status = ERROR_INAPPLICABLE_PADDING_TYPE;
        else {
            if (!*outputSize)
                status = ERROR_WRONG_OUTPUT_SIZE;

            *outputSize = inputSize;
        }
        break;

    case Zero_padding:
        status = AddZeroPaddingInternal(input, inputSize, blockSize, output, outputSize);
        break;

    case PKCSN7_padding:
        status = AddPKCSN7PaddingInternal(input, inputSize, blockSize, output, outputSize);
        break;

    default:
        break;
    }

    return status;
}

int CutPadding(__in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckPaddingOutput(blockSize, output, outputSize))
        return status;

    return CutPaddingInternal(padding, blockSize, output, outputSize);
}

inline int CutPaddingInternal(__in PaddingType padding, __in uint64_t blockSize, __out void* paddedOutput, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;

    switch (padding) {
    case No_padding:
        if (*outputSize % blockSize)
            status = ERROR_INAPPLICABLE_PADDING_TYPE;
        break;

    case Zero_padding:
        CutZeroPaddingInternal(blockSize, paddedOutput, outputSize);
        break;

    case PKCSN7_padding:
        CutPKCSN7PaddingInternal(blockSize, paddedOutput, outputSize);
        break;

    default:
        break;
    }

    return status;
}

inline bool IsWholeBlockMultiplier(uint64_t inputSize, uint64_t blockSize)
{
    return !(inputSize & (blockSize - 1));
}

inline void FillBySingleValue(__out void* output, __in uint8_t value, __in uint64_t length)
{
    while (length--)
        *((uint8_t*)output)++ = value;
}

inline uint64_t GetRequiringOutputSize(__in uint64_t inputSize, __in uint64_t blockSize)
{
    return IsWholeBlockMultiplier(inputSize, blockSize) ? inputSize + blockSize : (inputSize + blockSize - 1) & ~(blockSize - 1);
}

inline int GetPaddingSize(__in uint64_t inputSize, __in uint64_t blockSize, __inout uint64_t* outputSize, __inout uint64_t* paddingSize)
{
    uint64_t requiringSize = GetRequiringOutputSize(inputSize, blockSize);

    if (*outputSize < requiringSize) {
        *outputSize = requiringSize;
        return ERROR_WRONG_OUTPUT_SIZE;
    }
    else {
        *paddingSize = requiringSize - inputSize;
        return NO_ERROR;
    }
}

int AddZeroPadding(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckPaddingInputOutput(input, inputSize, blockSize, output, outputSize))
        return status;
    
    return AddZeroPaddingInternal(input, inputSize, blockSize, output, outputSize);
}

inline int AddZeroPaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;
    uint64_t paddingSize = 0;

    if (status = GetPaddingSize(inputSize, blockSize, outputSize, &paddingSize))
        return status;

    FillBySingleValue((uint8_t*)output + inputSize, 0, paddingSize);

    return NO_ERROR;
}

int AddPKCSN7Padding(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckPaddingInputOutput(input, inputSize, blockSize, output, outputSize))
        return status;
    else if (blockSize > MAX_PKCSN7_BLOCK_SIZE)
        return ERROR_WRONG_BLOCK_SIZE;

    return AddPKCSN7PaddingInternal(input, inputSize, blockSize, output, outputSize);
}

inline int AddPKCSN7PaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;
    uint64_t paddingSize = 0;

    if (status = GetPaddingSize(inputSize, blockSize, outputSize, &paddingSize))
        return status;

    FillBySingleValue((uint8_t*)output + inputSize, paddingSize, paddingSize);

    return NO_ERROR;
}

int CutZeroPadding(__in uint64_t blockSize, __out const void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckPaddingOutput(blockSize, output, outputSize))
        return status;

    CutZeroPaddingInternal(blockSize, output, outputSize);

    return NO_ERROR;
}

inline void CutZeroPaddingInternal(__in uint64_t blockSize, __in const void* paddedOutput, __inout uint64_t* outputSize)
{
    (uint8_t*)paddedOutput += *outputSize;

    for (uint64_t i = blockSize; i; -- *outputSize, --i)
        if (*--((uint8_t*)paddedOutput))
            break;
}

int CutPKCSN7Padding(__in uint64_t blockSize, __out const void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckPaddingOutput(blockSize, output, outputSize))
        return status;

    CutPKCSN7PaddingInternal(blockSize, output, outputSize);

    return NO_ERROR;
}

inline void CutPKCSN7PaddingInternal(__in uint64_t blockSize, __in const void* paddedOutput, __inout uint64_t* outputSize)
{
    *outputSize -= *((uint8_t*)paddedOutput + *outputSize - 1);
}
