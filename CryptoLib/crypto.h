// crypto.h
//

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NO_ERROR                            0x00000000

#define ERROR_WRONG_INPUT                   0x80000000
#define ERROR_WRONG_OUTPUT                  0x80000001
#define ERROR_WRONG_KEY                     0x80000002
#define ERROR_WRONG_INPUT_SIZE              0x80000003
#define ERROR_WRONG_OUTPUT_SIZE             0x80000004
#define ERROR_WRONG_BLOCK_SIZE              0x80000005
#define ERROR_INAPPLICABLE_PADDING_TYPE     0x80000006
#define ERROR_PADDING_CORRUPTED             0x80000007
#define ERROR_WRONG_INIT_VECTOR             0x80000008
#define ERROR_HASHING_FUNC_NOT_SUPPORTED    0x80000009
#define ERROR_CIPHER_FUNC_NOT_SUPPORTED     0x8000000a
#define ERROR_WRONG_ITERATIONS_NUMBER       0x8000000b
#define ERROR_NO_MEMORY                     0x8000000c
#define ERROR_XOF_NOT_SUPPORTED             0x8000000d
#define ERROR_PRF_FUNC_NOT_SUPPORTED        0x8000000e

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
    SHA_512,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512
} HashFunc;

typedef struct _HashFuncsSizes {
    HashFunc func;
    uint16_t blockSize;
    uint16_t outputSize;
} HashFuncsSizes;

// The order of mappings must be equal to the order of HashFunc consts
static HashFuncsSizes g_hashFuncsSizesMapping[] =
{
    { SHA1,          64, 20 },
    { SHA_224,       64, 28 },
    { SHA_256,       64, 32 },
    { SHA_384,      128, 48 },
    { SHA_512_224,  128, 28 },
    { SHA_512_256,  128, 32 },
    { SHA_512,      128, 64 },
    { SHA3_224,     144, 28 },
    { SHA3_256,     136, 32 },
    { SHA3_384,     104, 48 },
    { SHA3_512,      72, 64 }
};

typedef struct _VoidAndSizeNode {
    void* input;
    uint64_t inputSizeLowPart;
    uint64_t inputSizeHighPart;
} VoidAndSizeNode;

typedef enum _PRF {
    HMAC_SHA1,
    HMAC_SHA_224,
    HMAC_SHA_256,
    HMAC_SHA_384,
    HMAC_SHA_512_224,
    HMAC_SHA_512_256,
    HMAC_SHA_512,
    HMAC_SHA3_224,
    HMAC_SHA3_256,
    HMAC_SHA3_384,
    HMAC_SHA3_512
} PRF;

typedef enum _Xof {
    SHAKE128,
    SHAKE256
} Xof;

typedef struct _XofSizes {
    Xof func;
    uint16_t blockSize;
} XofSizes;

static XofSizes g_XofSizesMapping[] =
{
    { SHAKE128,     168 },
    { SHAKE256,     136 }
};

typedef struct _PrfHashPair {
    PRF prf;
    HashFunc hashFunc;
} PrfHashPair;

static PrfHashPair g_PrfHashPairMapping[] = {
    { HMAC_SHA1,        SHA1        },
    { HMAC_SHA_224,     SHA_224     },
    { HMAC_SHA_256,     SHA_256     },
    { HMAC_SHA_384,     SHA_384     },
    { HMAC_SHA_512_224, SHA_512_224 },
    { HMAC_SHA_512_256, SHA_512_256 },
    { HMAC_SHA_512,     SHA_512     },
    { HMAC_SHA3_224,    SHA3_224    },
    { HMAC_SHA3_256,    SHA3_256    },
    { HMAC_SHA3_384,    SHA3_384    },
    { HMAC_SHA3_512,    SHA3_512    }
};

int AddPadding(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock);

// If you supply outputSize == 0, then function returns ERROR_WRONG_OUTPUT_SIZE error and outputSize variable will contain requiring size
int EncryptByBlockCipher(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __in_opt const void* iv);
int DecryptByBlockCipher(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __in_opt const void* iv);

// Before using GetHash and GetHashEx you should allocate output buffer according to output digest size of respective hashing function
// You may check the numbers with g_hashFuncsSizesMapping array (see "func" and corresponding "blockSize" fields)
int GetHash(__in const void* input, __in uint64_t inputSize, __in HashFunc func, __out void* output);
// Before using GetHash and GetHashEx you should allocate output buffer according to output digest size of respective hashing function
// You may check the numbers with g_hashFuncsSizesMapping array (see "func" and corresponding "blockSize" fields)
// GetHashEx is only need if size of your single input is larger than (2^61 - 1) and you using SHA-224, SHA-256, SHA-384, SHA512/224, SHA512/256 or SHA-512 hashing,
// cause only that functions supports such sizes in current realisation. Unfortunately I do not have a resources for now to fully test its input.
// But partially it was tested and internal cycles should working correctly.
int GetHashEx(__in const void* input, __in uint64_t inputSizeLowPart, __in uint64_t inputSizeHighPart, __in HashFunc func, __out void* output);

// This function should be used when we have more than one distantly placed void* chunks of data, that must be hashed as single concatenated input
// All but last chunks sizes must be divisible by hashing func block size without remainder
int GetHashMultiple(__in const VoidAndSizeNode* inputList, __in uint64_t inputListSize, __in HashFunc func, __out void* output);

int GetXof(__in const void* input, __in uint64_t inputSize, __in Xof func, __out void* output, __in uint64_t outputSize);

// This function should be used when we have more than one distantly placed void* chunks of data, that must be hashed as single concatenated input
// All but last chunks sizes must be divisible by XOF func block size without remainder
int GetXofMultiple(__in const VoidAndSizeNode* inputList, __in uint64_t inputListSize, __in Xof func, __out void* output, __in uint64_t outputSize);

// Get pseudorandom function result (currently only HMAC supported - see PRF enum)
// outputSize parameter is only filled on variable size output XOF funcs - SHAKE128 and SHAKE256 - but KMAC functions are not supported yet,
// For all the rest you may check the numbers with g_hashFuncsSizesMapping array (see respective hash function in "func" and corresponding "blockSize" fields)
int GetPrf(__in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __in PRF func, __out void* output, __in_opt uint64_t outputSize);

// Maximum saltSize you should pass here is 512 bytes
int GetPbkdf2(__in const void* salt, __in uint64_t saltSize, __in const void* key, __in uint64_t keySize, __in PRF func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize);

// Here is no limit for saltSize except uint64_t length, but salt buffer must include additional 4 bytes for internal processing.
// So if you pass saltSize as 1008 bytes, you should allocate 1012 bytes for salt.
int GetPbkdf2Ex(__in void* salt, __in uint64_t saltSize, __in void* key, __in uint64_t keySize, __in PRF func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize);

#ifdef __cplusplus
}
#endif
