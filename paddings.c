#include "pch.h"
#include "crypto_internal.h"

/*
    suffix Internal in function naming == Unsafe
*/
inline int AddZeroPaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock);
inline int AddPKCSN7PaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock);
inline int AddISO7816PaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock);
inline int PullPKCSN7PaddingSizeInternal(__in const void* input, __in uint64_t blockSize, __out uint8_t* paddingSize);
inline int PullZeroPaddingSizeInternal(__in const void* input, __in uint64_t blockSize, __out uint64_t* paddingSize);
inline int PullISO7816PaddingSizeInternal(__in const void* input, __in uint64_t blockSize, __out uint64_t* paddingSize);
inline int CutZeroPaddingInternal(__in uint64_t blockSize, __in const void* output, __inout uint64_t* outputSize);
inline int CutPKCSN7PaddingInternal(__in uint64_t blockSize, __in const void* output, __inout uint64_t* outputSize);
inline int CutISO7816PaddingInternal(__in uint64_t blockSize, __in const void* output, __inout uint64_t* outputSize);

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

int AddPadding(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock)
{
    int status = NO_ERROR;
    if (status = CheckPaddingInputOutput(input, inputSize, blockSize, output, outputSize))
        return status;
    
    return AddPaddingInternal(input, inputSize, padding, blockSize, output, outputSize, fillAllBlock);
}

inline int AddPaddingInternal(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock)
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
        status = AddZeroPaddingInternal(input, inputSize, blockSize, output, outputSize, fillAllBlock);
        break;

    case PKCSN7_padding:
        status = AddPKCSN7PaddingInternal(input, inputSize, blockSize, output, outputSize, fillAllBlock);
        break;

    case ISO_7816_padding:
        status = AddISO7816PaddingInternal(input, inputSize, blockSize, output, outputSize, fillAllBlock);
        break;

    default:
        break;
    }

    return status;
}

int PullPaddingSize(__in PaddingType padding, __in void* input, __in uint64_t blockSize, __out uint64_t* paddingSize)
{
    int status = NO_ERROR;
    if (status = CheckPaddingOutput(blockSize, input, paddingSize)) {
        if (status == ERROR_WRONG_OUTPUT)
            status = ERROR_WRONG_INPUT;
        return status;
    }

    return PullPaddingSizeInternal(padding, input, blockSize, paddingSize);
}

inline int PullPaddingSizeInternal(__in PaddingType padding, __in void* input, __in uint64_t blockSize,  __out uint64_t* paddingSize)
{
    int status = NO_ERROR;

    switch (padding) {
    case No_padding:
        *paddingSize = 0;
        break;

    case Zero_padding:
        status = PullZeroPaddingSizeInternal(input, blockSize, paddingSize);
        break;

    case PKCSN7_padding:
        status = PullPKCSN7PaddingSizeInternal(input, blockSize, (uint8_t*)paddingSize);
        break;

    case ISO_7816_padding:
        status = PullISO7816PaddingSizeInternal(input, blockSize, paddingSize);
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

    case ISO_7816_padding:
        CutISO7816PaddingInternal(blockSize, paddedOutput, outputSize);
        break;

    default:
        break;
    }

    return status;
}

bool IsWholeBlockMultiplier(uint64_t inputSize, uint64_t blockSize)
{
    return !(inputSize & (blockSize - 1));
}

void FillBlockStartByInput(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __in uint64_t paddingSize)
{
    uint64_t length = blockSize - paddingSize;
    uint64_t offset = inputSize - length;
    const uint8_t* p = (uint8_t*)input + offset;
    uint8_t* s = (uint8_t*)output + offset;

    // here not memcpy() cause its input is size_t, and we have uint64_t which is different on non 64-bit platforms
    while (length--)
        *s++ = *p++;
}

void FillBySingleValue(__out void* output, __in uint8_t value, __in uint64_t length)
{
    while (length--)
        *((uint8_t*)output)++ = value;
}

uint64_t GetRequiringOutputSize(__in uint64_t inputSize, __in uint64_t blockSize)
{
    return IsWholeBlockMultiplier(inputSize, blockSize) ? inputSize + blockSize : (inputSize + blockSize - 1) & ~(blockSize - 1);
}

int GetPaddingSize(__in uint64_t inputSize, __in uint64_t blockSize, __inout uint64_t* outputSize, __inout uint64_t* paddingSize)
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

/*
    Zero padding functions
*/

int AddZeroPadding(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock)
{
    int status = NO_ERROR;
    if (status = CheckPaddingInputOutput(input, inputSize, blockSize, output, outputSize))
        return status;
    
    return AddZeroPaddingInternal(input, inputSize, blockSize, output, outputSize, fillAllBlock);
}

inline int AddZeroPaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock)
{
    int status = NO_ERROR;
    uint64_t paddingSize = 0;

    if (status = GetPaddingSize(inputSize, blockSize, outputSize, &paddingSize))
        return status;

    if (fillAllBlock)
        FillBlockStartByInput(input, inputSize, blockSize, output, paddingSize);

    FillBySingleValue((uint8_t*)output + inputSize, 0, paddingSize);

    return NO_ERROR;
}

inline int PullZeroPaddingSizeInternal(__in const void* input, __in uint64_t blockSize, __out uint64_t* paddingSize)
{
    uint8_t* p = (uint8_t*)input + blockSize;
    while (!*--p && blockSize--)
        ++*paddingSize;

    if (*paddingSize == 0)
        return ERROR_PADDING_CORRUPTED;
    else
        return NO_ERROR;
}

int CutZeroPadding(__in uint64_t blockSize, __in const void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckPaddingOutput(blockSize, output, outputSize))
        return status;

    return CutZeroPaddingInternal(blockSize, output, outputSize);
}

inline int CutZeroPaddingInternal(__in uint64_t blockSize, __in const void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;
    uint64_t paddingSize = 0;
    if (status = PullZeroPaddingSizeInternal(output, blockSize, &paddingSize))
        return status;
    else
        return *outputSize -= paddingSize, NO_ERROR;
}

/*
    PKCS#7 padding functions
*/

int AddPKCSN7Padding(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock)
{
    int status = NO_ERROR;
    if (status = CheckPaddingInputOutput(input, inputSize, blockSize, output, outputSize))
        return status;
    else if (blockSize > MAX_PKCSN7_BLOCK_SIZE)
        return ERROR_WRONG_BLOCK_SIZE;

    return AddPKCSN7PaddingInternal(input, inputSize, blockSize, output, outputSize, fillAllBlock);
}

inline int AddPKCSN7PaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock)
{
    int status = NO_ERROR;
    uint64_t paddingSize = 0;

    if (status = GetPaddingSize(inputSize, blockSize, outputSize, &paddingSize))
        return status;

    if (fillAllBlock)
        FillBlockStartByInput(input, inputSize, blockSize, output, paddingSize);

    FillBySingleValue((uint8_t*)output + inputSize, (uint8_t)paddingSize, paddingSize);

    return NO_ERROR;
}

inline int PullPKCSN7PaddingSizeInternal(__in const void* input, __in uint64_t blockSize, __out uint8_t* paddingSize)
{
    *paddingSize = *((uint8_t*)input + blockSize - 1);
    if (*paddingSize == 0)
        return ERROR_PADDING_CORRUPTED;
    else
        return NO_ERROR;
}

int CutPKCSN7Padding(__in uint64_t blockSize, __in const void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckPaddingOutput(blockSize, output, outputSize))
        return status;

    return CutPKCSN7PaddingInternal(blockSize, output, outputSize);
}

inline int CutPKCSN7PaddingInternal(__in uint64_t blockSize, __in const void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;
    uint8_t paddingSize = 0;
    if (status = PullPKCSN7PaddingSizeInternal(output, blockSize, &paddingSize))
        return status;
    else
        return *outputSize -= paddingSize, NO_ERROR;
}

/*
    ISO/IEC 7816-4:2005 padding functions
*/

int AddISO7816Padding(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock)
{
    int status = NO_ERROR;
    if (status = CheckPaddingInputOutput(input, inputSize, blockSize, output, outputSize))
        return status;

    return AddISO7816PaddingInternal(input, inputSize, blockSize, output, outputSize, fillAllBlock);
}

inline int AddISO7816PaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock)
{
    int status = NO_ERROR;
    uint64_t paddingSize = 0;

    if (status = GetPaddingSize(inputSize, blockSize, outputSize, &paddingSize))
        return status;

    if (fillAllBlock)
        FillBlockStartByInput(input, inputSize, blockSize, output, paddingSize);

    ((uint8_t*)output)[inputSize] = 0x80;

    FillBySingleValue((uint8_t*)output + inputSize + 1, 0, paddingSize - 1);

    return NO_ERROR;
}

inline int PullISO7816PaddingSizeInternal(__in const void* input, __in uint64_t blockSize, __out uint64_t* paddingSize)
{
    const uint8_t* p = (uint8_t*)input + blockSize;

    while (blockSize-- && !*--p) 
        ++*paddingSize;

    if (*p != 0x80)
        return ERROR_PADDING_CORRUPTED;
    else
        return ++*paddingSize, NO_ERROR;
}

int CutISO7816Padding(__in uint64_t blockSize, __in const void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckPaddingOutput(blockSize, output, outputSize))
        return status;

    CutISO7816PaddingInternal(blockSize, output, outputSize);

    return NO_ERROR;
}

inline int CutISO7816PaddingInternal(__in uint64_t blockSize, __in const void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;
    uint64_t paddingSize = 0;
    if (status = PullISO7816PaddingSizeInternal(output, blockSize, &paddingSize))
        return status;
    else
        return *outputSize -= paddingSize, NO_ERROR;
}
