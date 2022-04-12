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
#define ERROR_WRONG_INIT_VECTOR         0x80000008

#define BITS_PER_BYTE                   8
#define DES_BLOCK_SIZE                  8
#define MAX_PKCSN7_BLOCK_SIZE           255
#define SHA_BLOCK_SIZE                  64
#define SHA2_BLOCK_SIZE                 128

typedef enum _BlockCipherType {
    DES_cipher_type
} BlockCipherType;

typedef enum _BlockCipherMode {
    ECB_mode,
    CBC_mode,
    CFB_mode,
    OFB_mode,
    CTR_mode
} BlockCipherOpMode;

typedef enum _PaddingType {
    No_padding,
    Zero_padding,
    PKCSN7_padding,
    ISO_7816_padding
} PaddingType;

typedef enum _Sha2Variant {
    SHA_224,
    SHA_256,
    SHA_384,
    SHA_512_224,
    SHA_512_256,
    SHA_512
} Sha2Variant;

int AddPadding(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock);

uint64_t* DesGetRoundsKeys(uint64_t extendedKey);
int DesEncrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t* roundsKeys, __out void* output, __inout uint64_t* outputSize,
    __in BlockCipherOpMode mode, __in const void* iv);
int DesDecrypt(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t* roundsKeys, __out void* output, __inout uint64_t* outputSize,
    __in BlockCipherOpMode mode, __in const void* iv);

uint64_t DesEncryptBlock(uint64_t input, uint64_t* pRoundsKeys);
uint64_t DesDecryptBlock(uint64_t input, uint64_t* pRoundsKeys);

int Sha1Get(__in const void* input, __in uint64_t inputSize, __out void* output);
int Sha2Get(__in const void* input, __in uint64_t inputSizeLowPart, __in uint64_t inputSizeHighPart, __in Sha2Variant variant, __out void* output);

#ifdef __cplusplus
}
#endif
