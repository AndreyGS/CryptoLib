// crypto.h
//

#pragma once

#ifndef KERNEL
#include <stdint.h>
#endif

#ifndef __in
    #define __in 
    #define __out 
    #define __inout 
    #define __in_opt 
    #define __out_opt 
    #define __inout_opt 
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define NO_ERROR                            0x00000000

#define ERROR_NULL_STATE_HANDLE             0x80000001
#define ERROR_NULL_INPUT                    0x80000002
#define ERROR_NULL_OUTPUT                   0x80000003
#define ERROR_NULL_KEY                      0x80000004
#define ERROR_NULL_OUTPUT_SIZE              0x80000005
#define ERROR_NULL_INIT_VECTOR              0x80000006

#define ERROR_UNSUPPORTED_CIPHER_FUNC       0x80000101
#define ERROR_UNSUPPROTED_ENCRYPTION_MODE   0x80000102
#define ERROR_UNSUPPROTED_OPERATION_MODE    0x80000103
#define ERROR_UNSUPPORTED_PADDING_TYPE      0x80000104
#define ERROR_UNSUPPORTED_HASHING_FUNC      0x80000105
#define ERROR_UNSUPPORTED_XOF               0x80000106
#define ERROR_UNSUPPORTED_PRF_FUNC          0x80000107

#define ERROR_WRONG_INPUT_SIZE              0x80000201
#define ERROR_TOO_SMALL_OUTPUT_SIZE         0x80000202
#define ERROR_TOO_SMALL_BLOCK_SIZE          0x80000203
#define ERROR_TOO_SMALL_ITERATIONS_NUMBER   0x80000204
#define ERROR_TOO_BIG_BLOCK_SIZE            0x80000205

#define ERROR_INAPPLICABLE_PADDING_TYPE     0x80000301
#define ERROR_PADDING_CORRUPTED             0x80000302

#define ERROR_NO_MEMORY                     0x80000f01

typedef void* StateHandle;
typedef StateHandle BlockCipherHandle;
typedef StateHandle HashHandle;
typedef StateHandle XofHandle;
typedef StateHandle PrfHandle;

typedef enum _BlockCipherType {
    DES_cipher_type,
    TDES_cipher_type,       // 3DES-EDE3 with single IV
    BlockCipherType_max
} BlockCipherType;

#define DES_KEY_SIZE                    8
#define TDES_KEY_SIZE                   24

#define DES_BLOCK_SIZE                  8
#define TDES_BLOCK_SIZE                 8

#define DES_IV_SIZE                     8
#define TDES_IV_SIZE                    8

typedef enum _BlockCipherOpMode {
    ECB_mode,
    CBC_mode,
    CFB_mode,
    OFB_mode,
    CTR_mode,
    BlockCipherOpMode_max
} BlockCipherOpMode;

typedef enum _CryptoMode {
    Encryption_mode,
    Decryption_mode,
    CryptoMode_max
} CryptoMode;

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

#define SHA1_BLOCK_SIZE 64
#define SHA2_32_BLOCK_SIZE 64
#define SHA2_64_BLOCK_SIZE 128
#define SHA3_224_BLOCK_SIZE 144
#define SHA3_256_BLOCK_SIZE 136
#define SHA3_384_BLOCK_SIZE 104
#define SHA3_512_BLOCK_SIZE 72

typedef enum _Xof {
    SHAKE128,
    SHAKE256,
    Xof_max
} Xof;

#define SHAKE128_BLOCK_SIZE 168
#define SHAKE256_BLOCK_SIZE 136

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

int AddPadding(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in uint64_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock);

// If you supply outputSize == 0, then function returns ERROR_NULL_OUTPUT_SIZE error and outputSize variable will contain requiring size
// For all cipher modes outputSize in DecryptByBlockCipher will return exact bytes length.
// but with OFB if you pass there outputSize < inputSize you will get an error and outputSize returned will be equal inputSize.
// And if there is no error outputSize will always contain exact bytes length.

int InitBlockCipherState(__inout BlockCipherHandle* handle, __in BlockCipherType cipher, __in CryptoMode cryptoMode, __in BlockCipherOpMode opMode, __in PaddingType padding, __in const void* key, __in_opt void* iv);
int ReInitBlockCipherCryptoMode(__inout BlockCipherHandle handle, __in CryptoMode cryptoMode);
int ReInitBlockCipherOpMode(__inout BlockCipherHandle handle, __in BlockCipherOpMode opMode);
int ReInitBlockCipherPaddingType(__inout BlockCipherHandle handle, __in PaddingType padding);
int ReInitBlockCipherIv(__inout BlockCipherHandle handle, __in const void* iv);
int ProcessingByBlockCipher(__inout BlockCipherHandle handle, __in const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output, __inout uint64_t* outputSize);
int FreeBlockCipherState(__inout BlockCipherHandle handle);

// Before using GetHash with finalize flag you should allocate output buffer according to the output digest size of respective hashing function
// You may check the numbers with macros _DIGEST_SIZE like SHA1_DIGEST_SIZE
int InitHashState(__inout HashHandle* handle, __in HashFunc func);
int GetHash(__inout HashHandle handle, __in_opt const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output);
int ResetHashState(__inout HashHandle handle);
int FreeHashState(__inout HashHandle handle);

int InitXofState(__inout XofHandle* handle, __in Xof func);
int GetXof(__inout XofHandle handle, __in_opt const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output, __in uint64_t outputSize);
int ResetXofState(__inout XofHandle handle);
int FreeXofState(__inout XofHandle handle);

// Get pseudorandom function result (currently only HMAC supported - see PRF enum)
// outputSize parameter is only filled on variable size output XOF funcs - SHAKE128 and SHAKE256 - but KMAC functions are not supported yet,
// For all of the rest you may check the numbers with macros _DIGEST_SIZE like SHA1_DIGEST_SIZE
int InitPrfState(__inout PrfHandle* handle, __in Prf func);
int GetPrf(__inout PrfHandle handle, __in_opt const void* input, __in uint64_t inputSize, __in_opt const void* key, __in uint64_t keySize, __in bool finalize, __out_opt void* output, __in_opt uint64_t outputSize);
int ResetPrfState(__inout PrfHandle handle);
int FreePrfState(__inout PrfHandle handle);

// Maximum saltSize you should pass here is 512 bytes
int GetPbkdf2(__in const void* salt, __in uint64_t saltSize, __in const void* key, __in uint64_t keySize, __in Prf func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize);

// Here is no limit for saltSize except uint64_t length, but salt buffer must include additional 4 bytes for internal processing.
// So if you pass saltSize as 1008 bytes, you should allocate 1012 bytes for salt.
int GetPbkdf2Ex(__in const void* salt, __in uint64_t saltSize, __in const void* key, __in uint64_t keySize, __in Prf func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize);

#ifdef __cplusplus
}
#endif
