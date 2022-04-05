#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NO_ERROR                        0x00000000

#define ERROR_WRONG_INPUT               0x80000000
#define ERROR_WRONG_OUTPUT              0x80000001
#define ERROR_WRONG_KEYS                0x80000002
#define ERROR_WRONG_INPUT_SIZE          0x80000003
#define ERROR_WRONG_OUTPUT_SIZE         0x80000004
#define ERROR_WRONG_BLOCK_SIZE          0x80000005
#define ERROR_INAPPLICABLE_PADDING_TYPE 0x80000006
#define ERROR_PADDING_CORRUPTED         0x80000007

#define DES_BLOCK_SIZE                  8
#define MAX_PKCSN7_BLOCK_SIZE           255

typedef enum _PaddingType {
    No_padding,
    Zero_padding,
    PKCSN7_padding,
    ISO10126_padding
} PaddingType;

int AddPadding(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize);

uint64_t* DesGetRoundsKeys(uint64_t extendedKey);
int DesEncrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t* roundsKeys, __out void* output, __inout uint64_t* outputSize);
int DesDecrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t* roundsKeys, __out void* output, __inout uint64_t* outputSize);

uint64_t DesEncryptBlock(uint64_t input, uint64_t* pRoundsKeys);
uint64_t DesDecryptBlock(uint64_t input, uint64_t* pRoundsKeys);

#ifdef __cplusplus
}
#endif
