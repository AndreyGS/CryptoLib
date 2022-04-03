#include "pch.h"
#include "crypto_internal.h"

inline int CheckInputOutput(__in const void* input, __in uint64_t inputSize, __in void* output, __in uint64_t* outputSize)
{
    if (!input)
        return ERROR_WRONG_INPUT;
    else if (!inputSize)
        return ERROR_WRONG_INPUT_SIZE;
    else if (!output)
        return ERROR_WRONG_OUTPUT;
    else if (!outputSize || !*outputSize)
        return ERROR_WRONG_OUTPUT_SIZE;
    else
        return NO_ERROR;
}