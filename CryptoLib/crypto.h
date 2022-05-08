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
#define ERROR_OUTPUT_SIZE_IS_NULL           0x8000000f
#define ERROR_PADDING_NOT_SUPPORTED         0x80000010
#define ERROR_UNSUPPROTED_ENCRYPTION_MODE   0x80000011
#define ERROR_WRONG_STATE                   0x80000012

typedef void* HashState;
typedef void* XofState;
typedef void* PrfState;

typedef enum _BlockCipherType {
    DES_cipher_type,
    TDES_cipher_type,       // 3DES-EDE3 with single IV
    BlockCipherType_max
} BlockCipherType;

#define DES_KEY_SIZE                    8
#define DES_ROUNDS_KEYS_SIZE            128
#define TDES_KEY_SIZE                   24
#define TDES_ROUNDS_KEYS_SIZE           384

typedef enum _BlockCipherOpMode {
    ECB_mode,
    CBC_mode,
    CFB_mode,
    OFB_mode,
    CTR_mode,
    BlockCipherOpMode_max
} BlockCipherOpMode;

typedef enum _PaddingType {
    No_padding,
    Zero_padding,
    PKCSN7_padding,
    ISO_7816_padding,
    PaddingType_max
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
    SHA3_512,
    HashFunc_max
} HashFunc;

typedef struct _HashFuncsSizes {
    HashFunc func;
    uint16_t blockSize;
    uint16_t outputSize;
    uint16_t stateSize;
    uint16_t fullStateSize;
} HashFuncsSizes;

#define SHA1_DIGEST_SIZE                20
#define SHA_224_DIGEST_SIZE             28
#define SHA_256_DIGEST_SIZE             32
#define SHA_384_DIGEST_SIZE             48
#define SHA_512_224_DIGEST_SIZE         28
#define SHA_512_256_DIGEST_SIZE         32
#define SHA_512_DIGEST_SIZE             64
#define SHA3_224_DIGEST_SIZE            28
#define SHA3_256_DIGEST_SIZE            32
#define SHA3_384_DIGEST_SIZE            48
#define SHA3_512_DIGEST_SIZE            64

typedef enum _Prf {
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
    HMAC_SHA3_512,
    Prf_max
} Prf;

typedef enum _Xof {
    SHAKE128,
    SHAKE256,
    Xof_max
} Xof;

int AddPadding(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock);

// If you supply outputSize == 0, then function returns ERROR_WRONG_OUTPUT_SIZE error and outputSize variable will contain requiring size
// For all cipher modes outputSize in DecryptByBlockCipher will return exact bytes length.
// but with OFB if you pass there outputSize < inputSize you will get an error and outputSize returned will be equal inputSize.
// And if there is no error outputSize will always contain exact bytes length.
int EncryptByBlockCipher(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* key, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __inout_opt void* iv);
int DecryptByBlockCipher(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* key, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __inout_opt void* iv);

// Ex version has the roundsKeys input instead of key in main version
int EncryptByBlockCipherEx(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* roundsKeys, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __inout_opt void* iv);
int DecryptByBlockCipherEx(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in const void* roundsKeys, __in BlockCipherType cipherType
    , __out void* output, __inout uint64_t* outputSize, __in BlockCipherOpMode mode, __inout_opt void* iv);

// Check g_blockCipherKeysSizes for key sizes that you should supply with your ouput buffer for get respective rounds keys
int GetBlockCipherRoundsKeys(__in const void* key, __in BlockCipherType cipherType, __out void* output);

// Before using GetHash and GetHashEx you should allocate output buffer according to output digest size of respective hashing function
// You may check the numbers with g_hashFuncsSizesMapping array (see "func" and corresponding "blockSize" fields)
int InitHashState(__in HashFunc func, __inout HashState* state);
int GetHash(__in const void* input, __in uint64_t inputSize, __out void* output, __in bool finalize, __inout HashState state);
void ResetHashState(__inout HashState state);
void FreeHashState(__inout HashState state);

int InitXofState(__in Xof func, __inout XofState* state);
int GetXof(__in const void* input, __in uint64_t inputSize, __out void* output, __in uint64_t outputSize, __in bool finalize, __inout XofState state);
void ResetXofState(__inout XofState state);
void FreeXofState(__inout XofState state);

// Get pseudorandom function result (currently only HMAC supported - see PRF enum)
// outputSize parameter is only filled on variable size output XOF funcs - SHAKE128 and SHAKE256 - but KMAC functions are not supported yet,
// For all the rest you may check the numbers with g_hashFuncsSizesMapping array (see respective hash function in "func" and corresponding "blockSize" fields)
int InitPrfState(__in Prf func, __inout PrfState* state);
int GetPrf(__in const void* input, __in uint64_t inputSize, __in const void* key, __in uint64_t keySize, __out void* output, __in_opt uint64_t outputSize, __in bool finalize, __inout PrfState state);
void ResetPrfState(__inout PrfState state);
void FreePrfState(__inout PrfState state);

// Maximum saltSize you should pass here is 512 bytes
int GetPbkdf2(__in const void* salt, __in uint64_t saltSize, __in const void* key, __in uint64_t keySize, __in Prf func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize);

// Here is no limit for saltSize except uint64_t length, but salt buffer must include additional 4 bytes for internal processing.
// So if you pass saltSize as 1008 bytes, you should allocate 1012 bytes for salt.
int GetPbkdf2Ex(__in const void* salt, __in uint64_t saltSize, __in const void* key, __in uint64_t keySize, __in Prf func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize);

#ifdef __cplusplus
}
#endif
