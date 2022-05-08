// paddings.c
//

#include "pch.h"
#include "paddings.h"
#include "crypto_internal.h"

#define SHA_START_LENGTH_OFFSET 56
#define SHA2_START_LENGTH_OFFSET 112

/*
    suffix Internal in function naming == Unsafe
*/
int AddZeroPaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock);
int AddPKCSN7PaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock);
int AddISO7816PaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock);
int PullPKCSN7PaddingSizeInternal(__in const void* input, __in uint64_t blockSize, __out uint8_t* paddingSize);
int PullZeroPaddingSizeInternal(__in const void* input, __in uint64_t blockSize, __out uint64_t* paddingSize);
int PullISO7816PaddingSizeInternal(__in const void* input, __in uint64_t blockSize, __out uint64_t* paddingSize);
int CutZeroPaddingInternal(__in uint64_t blockSize, __in const void* output, __inout uint64_t* outputSize);
int CutPKCSN7PaddingInternal(__in uint64_t blockSize, __in const void* output, __inout uint64_t* outputSize);
int CutISO7816PaddingInternal(__in uint64_t blockSize, __in const void* output, __inout uint64_t* outputSize);

int CheckPaddingInputOutput(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __in void* output, __in uint64_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckInputOutput(input, inputSize, output, outputSize))
        return status;
    else if (!blockSize)
        return ERROR_WRONG_BLOCK_SIZE;
    else
        return NO_ERROR;
}

int CheckPaddingOutput(__in uint64_t blockSize, __in const void* paddedOutput, __in uint64_t* outputSize)
{
    int status = NO_ERROR;
    if (status = CheckOutput(paddedOutput, outputSize))
        return status;
    else if (!blockSize)
        return ERROR_WRONG_BLOCK_SIZE;
    else
        return NO_ERROR;
}

int AddPaddingInternal(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock)
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

            if (fillAllBlock) {
                uint64_t offset = inputSize - blockSize;
                memcpy((uint8_t*)output + offset, (uint8_t*)input + offset, blockSize);
            }
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

int PullPaddingSizeInternal(__in PaddingType padding, __in const void* input, __in uint64_t blockSize,  __out uint64_t* paddingSize)
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

int CutPaddingInternal(__in PaddingType padding, __in uint64_t blockSize, __out void* paddedOutput, __inout uint64_t* outputSize)
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
    return inputSize < blockSize ? false : !(inputSize % blockSize);
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
    return inputSize + blockSize - (IsWholeBlockMultiplier(inputSize, blockSize) ? 0 : inputSize % blockSize);
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

int AddZeroPaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock)
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

int PullZeroPaddingSizeInternal(__in const void* input, __in uint64_t blockSize, __out uint64_t* paddingSize)
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

int CutZeroPaddingInternal(__in uint64_t blockSize, __in const void* output, __inout uint64_t* outputSize)
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

int AddPKCSN7PaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock)
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

int PullPKCSN7PaddingSizeInternal(__in const void* input, __in uint64_t blockSize, __out uint8_t* paddingSize)
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

int CutPKCSN7PaddingInternal(__in uint64_t blockSize, __in const void* output, __inout uint64_t* outputSize)
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

int AddISO7816PaddingInternal(__in const void* input, __in uint64_t inputSize, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock)
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

int PullISO7816PaddingSizeInternal(__in const void* input, __in uint64_t blockSize, __out uint64_t* paddingSize)
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

int CutISO7816PaddingInternal(__in uint64_t blockSize, __in const void* output, __inout uint64_t* outputSize)
{
    int status = NO_ERROR;
    uint64_t paddingSize = 0;
    if (status = PullISO7816PaddingSizeInternal(output, blockSize, &paddingSize))
        return status;
    else
        return *outputSize -= paddingSize, NO_ERROR;
}

/*
    SHA paddings
*/

// output must be zeroed before its passed here
int AddShaPaddingInternal(__in const void* input, __in uint64_t inputSize, __out void* output, __out uint8_t* outputBlocksNum)
{   
    uint16_t lastBlockSize = inputSize % SHA1_BLOCK_SIZE;
    uint64_t messageBitsSize = inputSize << 3; // inputSizeLowPart * BITS_PER_BYTE;

    if (lastBlockSize >= SHA_START_LENGTH_OFFSET) {
        uint64_t paddingFillSize = SHA1_BLOCK_SIZE;
        AddPaddingInternal(input, lastBlockSize, ISO_7816_padding, SHA1_BLOCK_SIZE, output, &paddingFillSize, true);
        ((uint64_t*)output)[15] = Uint64LittleEndianToBigEndian(messageBitsSize);                                               // 15 == ((SHA1_BLOCK_SIZE * 2) / sizeof(uint64_t)) - 1
        *outputBlocksNum = 2;
    }
    else {
        uint64_t paddingFillSize = SHA_START_LENGTH_OFFSET;
        AddPaddingInternal(input, lastBlockSize, ISO_7816_padding, SHA_START_LENGTH_OFFSET, output, &paddingFillSize, true);
        ((uint64_t*)output)[7] = Uint64LittleEndianToBigEndian(messageBitsSize);                                                // 7 == (SHA1_BLOCK_SIZE / sizeof(uint64_t)) - 1
        *outputBlocksNum = 1;
    }

    return NO_ERROR;
}

int AddSha2_64PaddingInternal(__in const void* input, __in uint64_t inputSizeLowPart, __in uint64_t inputSizeHighPart, __out void* output, __out uint8_t* outputBlocksNum)
{
    uint16_t lastBlockSize = inputSizeLowPart % SHA2_BLOCK_SIZE;
    uint64_t messageBitsSizeLow = inputSizeLowPart << 3; // inputSizeLowPart * BITS_PER_BYTE;
    uint64_t messageBitsSizeHigh = (inputSizeHighPart << 3) | (inputSizeLowPart & 0xe000000000000000) >> 61;

    if (lastBlockSize >= SHA2_START_LENGTH_OFFSET) {
        uint64_t paddingFillSize = SHA2_BLOCK_SIZE;
        AddPaddingInternal(input, lastBlockSize, ISO_7816_padding, SHA2_BLOCK_SIZE, output, &paddingFillSize, true);
        ((uint64_t*)output)[30] = Uint64LittleEndianToBigEndian(messageBitsSizeHigh);                                           // 30 == ((SHA2_BLOCK_SIZE * 2) / sizeof(uint64_t)) - 2
        ((uint64_t*)output)[31] = Uint64LittleEndianToBigEndian(messageBitsSizeLow);
        *outputBlocksNum = 2;
    }
    else {
        uint64_t paddingFillSize = SHA2_START_LENGTH_OFFSET;
        AddPaddingInternal(input, lastBlockSize, ISO_7816_padding, SHA2_START_LENGTH_OFFSET, output, &paddingFillSize, true);
        ((uint64_t*)output)[14] = Uint64LittleEndianToBigEndian(messageBitsSizeHigh);                                           // 14 == (SHA2_BLOCK_SIZE / sizeof(uint64_t)) - 2
        ((uint64_t*)output)[15] = Uint64LittleEndianToBigEndian(messageBitsSizeLow);
        *outputBlocksNum = 1;
    }

    return NO_ERROR;
}

int AddSha3PaddingInternal(__in const void* input, __in uint64_t inputSize, __in Sha3Func func, __out void* output, __out uint8_t* outputBlocksNum)
{
    uint16_t blockSize = func == Sha3Func_SHAKE128 || func == Sha3Func_SHAKE256
                       ? g_XofSizesMapping[func == Sha3Func_SHAKE128 ? SHAKE128 : SHAKE256].blockSize
                       : g_hashFuncsSizesMapping[func + SHA3_224].blockSize;
    uint16_t lastBlockSize = inputSize % blockSize;
    uint16_t paddingSize = blockSize - lastBlockSize;

    FillBlockStartByInput(input, lastBlockSize, blockSize, output, paddingSize);

    // Here we're not filling zeros cause it's an internal function and we get already zeroed array as input
    // Sha1 and Sha2 padding functions has the same situation, but there we are using standart function AddPaddingInternal,
    // which is not very nice fits Sha3 padding scheme

    ((uint8_t*)output)[paddingSize ? lastBlockSize : blockSize]          = func == Sha3Func_SHAKE128 || func == Sha3Func_SHAKE256
                                                                         ? 0x1f
                                                                         : 0x06;
    ((uint8_t*)output)[paddingSize ? blockSize - 1 : blockSize * 2 - 1] |= 0x80;

    *outputBlocksNum = paddingSize ? 1 : 2;

    return NO_ERROR;
}
