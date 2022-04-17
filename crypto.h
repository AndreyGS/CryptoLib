// crypto.h
//

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NO_ERROR                        0x00000000

#define ERROR_WRONG_INPUT                   0x80000000
#define ERROR_WRONG_OUTPUT                  0x80000001
#define ERROR_WRONG_KEYS                    0x80000002
#define ERROR_WRONG_INPUT_SIZE              0x80000003
#define ERROR_WRONG_OUTPUT_SIZE             0x80000004
#define ERROR_WRONG_BLOCK_SIZE              0x80000005
#define ERROR_INAPPLICABLE_PADDING_TYPE     0x80000006
#define ERROR_PADDING_CORRUPTED             0x80000007
#define ERROR_WRONG_INIT_VECTOR             0x80000008
#define ERROR_HASHING_FUNC_NOT_SUPPORTED    0x80000009
#define ERROR_CIPHER_FUNC_NOT_SUPPORTED     0x8000000a
#define ERROR_WRONG_ITERATIONS_NUMBER       0x8000000b

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

typedef uint32_t _HashFuncs;
typedef enum _HashFunc {
    SHA1,
    SHA_224,
    SHA_256,
    SHA_384,
    SHA_512_224,
    SHA_512_256,
    SHA_512
} HashFunc;

typedef struct _HashFuncsSizes {
    HashFunc func;
    uint16_t blockSize;
    uint16_t outputSize;
} HashFuncsSizes;

// The order of mappings must be equal to the order of HashFunc consts
static HashFuncsSizes g_hashFuncsSizesMappings[] =
{
    { SHA1,          64, 20 },
    { SHA_224,       64, 28 },
    { SHA_256,       64, 32 },
    { SHA_384,      128, 48 },
    { SHA_512_224,  128, 28 },
    { SHA_512_256,  128, 32 },
    { SHA_512,      128, 64 }
};

typedef struct _HashInputNode {
    void* input;
    uint64_t inputSizeLowPart;
    uint64_t inputSizeHighPart;
} HashInputNode;

typedef enum _PRF {
    HMAC_Sha1,
    HMAC_SHA_224,
    HMAC_SHA_256,
    HMAC_SHA_384,
    HMAC_SHA_512_224,
    HMAC_SHA_512_256,
    HMAC_SHA_512
} PRF;

int AddPadding(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock);

int EncryptByBlockCipher(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __in_opt const void* iv);
int DecryptFromBlockCipher(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __in_opt const void* iv);

int GetHash(__in const void* input, __in uint64_t inputSize, __in HashFunc func, __out void* output);
int GetHashEx(__in const void* input, __in uint64_t inputSizeLowPart, __in uint64_t inputSizeHighPart, __in HashFunc func, __out void* output);

// This should be used when we have more than one distantly placed void* chunks of data, that must be hashed as single concatenated input
int GetHashMultiple(__in const HashInputNode* inputList, __in uint64_t inputListSize, __in HashFunc func, __out void* output);

int GetHmac(__in void* input, __in uint64_t inputSize, __in void* key, __in uint64_t keySize, __in HashFunc func, __out void* output, __out_opt uint16_t* outputSize);

// Maximum saltSize you should pass here is 64 bytes
int GetPbkdf2(__in void* salt, __in uint64_t saltSize, __in void* key, __in uint64_t keySize, __in PRF func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize);

// Here is no limit for saltSize except uint64_t length, but salt buffer must include additional 4 bytes for internal processing.
// So if you pass saltSize as 108 bytes, you should allocate 112 bytes for salt.
int GetPbkdf2Ex(__in void* salt, __in uint64_t saltSize, __in void* key, __in uint64_t keySize, __in PRF func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize);

// Get pseudorandom function
int GetPrf(__in void* input, __in uint64_t inputSize, __in void* key, __in uint64_t keySize, __in PRF func, __out void* output, __out_opt uint16_t* outputSize);

#ifdef __cplusplus
}
#endif
