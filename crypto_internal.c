#include "pch.h"
#include "crypto_internal.h"

inline int CheckInput(__in const void* input, __in uint64_t inputSize)
{
    if (!input)
        return ERROR_WRONG_INPUT;
    else if (!inputSize)
        return ERROR_WRONG_INPUT_SIZE;
    else
        return NO_ERROR;
}

inline int CheckOutput(__in const void* output, __in const uint64_t* outputSize)
{
    if (!output || !outputSize)
        return ERROR_WRONG_OUTPUT;
    else
        return NO_ERROR;
}

inline int CheckInputOutput(__in const void* input, __in uint64_t inputSize, __in const void* output, __in const uint64_t* outputSize)
{
    return CheckInput(input, inputSize) || CheckOutput(output, outputSize);
}
