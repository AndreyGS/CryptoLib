/**
 * @file crypto.h
 * @author Andrey Grabov-Smetankin <ukbpyh@gmail.com>
 * 
 * @section LICENSE
 * 
 * Copyright 2022 Andrey Grabov-Smetankin
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files 
 * (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, 
 * publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO 
 * THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * 
 * @section DESCRIPTON
 * 
 * This file represents public interface, enums and macros of CryptoLib
 */

#pragma once

#ifndef KERNEL
#include <stdint.h>
#endif // !KERNEL

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

/// Return statuses
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

#define MAX_PKCSN7_BLOCK_SIZE               255

typedef void* StateHandle;
typedef StateHandle BlockCipherHandle;
typedef StateHandle HashHandle;
typedef StateHandle XofHandle;
typedef StateHandle PrfHandle;

typedef enum _BlockCipherType {
    DES_cipher_type,
    TDES_cipher_type,       // 3DES-EDE3 with single IV
    AES128_cipher_type,
    AES192_cipher_type,
    AES256_cipher_type,
    BlockCipherType_max
} BlockCipherType;

#define DES_KEY_SIZE                    8
#define TDES_KEY_SIZE                   24

#define AES128_KEY_SIZE                 16
#define AES192_KEY_SIZE                 24
#define AES256_KEY_SIZE                 32

#define DES_BLOCK_SIZE                  8
#define TDES_BLOCK_SIZE                 DES_BLOCK_SIZE

#define AES128_BLOCK_SIZE               16
#define AES192_BLOCK_SIZE               AES128_BLOCK_SIZE
#define AES256_BLOCK_SIZE               AES128_BLOCK_SIZE

#define DES_IV_SIZE                     DES_BLOCK_SIZE
#define TDES_IV_SIZE                    DES_BLOCK_SIZE

#define AES128_IV_SIZE                  AES128_BLOCK_SIZE
#define AES192_BLOCK_SIZE               AES128_BLOCK_SIZE
#define AES256_BLOCK_SIZE               AES128_BLOCK_SIZE

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

/**
 * Adds padding to output with offset by inputSize
 * 
 * If for some reason you wish to add some padding to your data this function may help you.
 * It adds padding to output with offset by inputSize, that is start of padding will be (uint8_t*)offset + inputSize,
 * so you can add padding inplace passing to input and output the same pointer.
 * Also if you use different pointers you may use fillAllBlock flag, that fills start of last block by input data if it (last block) not fully filled.
 * If outputSize is not enough to contain all padding, the function will return ERROR_TOO_SMALL_OUTPUT_SIZE and outputSize variable will contain required size.
 * 
 * @param input data to pad
 * @param inputSize size of data
 * @param padding type
 * @param blockSize size of block to pad
 * @param output buffer that will be filled by pad
 * @param outputSize inputSize + padSize
 * @param fillAllBlock see description of function work
 * 
 * @return status
 * 
*/
int AddPadding(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in size_t blockSize, __out void* output, __inout uint64_t* outputSize, __in bool fillAllBlock);

/**
 * Inits state for block cipher
 * 
 * Before using encryption/decryption by block ciphers you must init respective state with help of this function.
 * When state is no longer need you should free it by call of FreeBlockCipherState
 * 
 * @param handle is a state handle
 * @param cipher type of cipher that will be used in encryption/decryption
 * @param cryptoMode encryption or decryption
 * @param opMode type of operation mode (ECB, CBC, etc)
 * @param padding type of padding that using in encryption/decryption
 * @param key encryption key
 * @param iv initialization vector (for ECB is not used)
 * 
 * @return status
 */
int InitBlockCipherState(__inout BlockCipherHandle* handle, __in BlockCipherType cipher, __in CryptoMode cryptoMode, __in BlockCipherOpMode opMode, __in PaddingType padding, __in const void* key, __in_opt void* iv);

/**
 * ReInits crypto mode (encryption/decryption)
 *
 * @param handle is a state handle that inited by InitBlockCipherState
 * @param cryptoMode new mode
 *
 * @return status
 */
int ReInitBlockCipherCryptoMode(__inout BlockCipherHandle handle, __in CryptoMode cryptoMode);

/**
 * ReInits operation mode (ECB, CBC, etc)
 *
 * @param handle is a state handle that inited by InitBlockCipherState
 * @param opMode new operation mode
 *
 * @return status
 */
int ReInitBlockCipherOpMode(__inout BlockCipherHandle handle, __in BlockCipherOpMode opMode);

/**
 * ReInits padding type
 *
 * @param handle is a state handle that inited by InitBlockCipherState
 * @param opMode new padding type
 *
 * @return status
 */
int ReInitBlockCipherPaddingType(__inout BlockCipherHandle handle, __in PaddingType padding);

/**
 * ReInits initialization vector
 *
 * @param handle is a state handle that inited by InitBlockCipherState
 * @param opMode new initialization vector
 *
 * @return status
 */
int ReInitBlockCipherIv(__inout BlockCipherHandle handle, __in const void* iv);

/**
 * Make processing by block cipher function
 *
 * This is the main encryption/decryption function that using handle inited by InitBlockCipherState handle.
 * If you are using this function for partial input, input size must be exact divisible by block size of current cipher.
 * When you pass the last part of the current data, finalize flag should be true, and otherwise false.
 * In order to avoid problems with data corruption do not reinit any of reinitable params of current handle
 * between calls of ProcessingByBlockCipher with false finalize flag.
 * You must understand that finalize flag only adds/retirives padding to/from input and not resets any field of the state.
 * You should use new IV (if it's not ECB mode) every time you start new data (file) encryption, by setting it with ReInitBlockCipherIv.
 * 
 * @param handle is a state handle that inited by InitBlockCipherState
 * @param input data to encypt/decrypt
 * @param inputSize size of the current input chunk
 * @param finalize flag that indicate last chunk of data
 * @param output buffer allocated by user for output data
 * @param outputSize size of allocated output buffer
 *      for all cipher modes outputSize in will return exact bytes length that output data contain.
 *      If you supply outputSize less than required, then function returns ERROR_TOO_SMALL_OUTPUT_SIZE error and outputSize variable will contain requiring size.
 *      In decryption with OFB_mode strongly recomended to immediately pass output buffer with size not less than inputSize
 *      because calculation of outputSize with OFB_mode decryption includes full input decryption.
 *
 * @return status
 */
int ProcessingByBlockCipher(__inout BlockCipherHandle handle, __in const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output, __inout uint64_t* outputSize);

/**
 * Frees block cipher state
 *
 * @param handle is a state handle that inited by InitBlockCipherState
 * 
 * @return status
 */
int FreeBlockCipherState(__inout BlockCipherHandle handle);

/**
 * Inits state for hash function
 *
 * Before using hashing you must init respective state with help of this function.
 * When state is no longer need you should free it by call of FreeHashState.
 *
 * @param handle is a state handle
 * @param func is a hash function that will be used in hashing
 * 
 * @return status
 */
int InitHashState(__inout HashHandle* handle, __in HashFunc func);

/**
 * Resets internal hash state
 * 
 * If you wish to throw away any processed chunks of data and start to hashing
 * with begining using current handle, you should call this function before.
 * Also state is automaticaly resets after call of GetHash with finalize flag.
 *
 * @param handle is a state handle that inited by InitHashState
 *
 * @return status
 */
int ResetHashState(__inout HashHandle handle);

/**
 * GetHash is make processing by hashing function
 *
 * This is the main hashing function that using handle inited by InitHashState handle.
 * If you using this function for partial input, input size must be exact divisible by block size of current hashing function.
 * (you may check the numbers from macros _BLOCK_SIZE like SHA1_BLOCK_SIZE).
 * When you pass the last part of current data, finalize flag should be true, and otherwise false.
 * In order to avoid problems with data corruption do not reset state by ResetHashState 
 * between calls of GetHash with false finalize flag.
 * Output buffer must be supplied when finalize flag is set.
 * The size of output is the size of respective didgest
 * (you may check the numbers from macros _DIGEST_SIZE like SHA1_DIGEST_SIZE.)
 *
 * @param handle is a state handle that inited by InitBlockCipherState
 * @param input data to hashing
 * @param inputSize size of the current input chunk (if input is nullptr than must be equal to 0)
 * @param finalize flag that indicate last chunk of data
 * @param output buffer allocated by user for output didgest
 *
 * @return status
 */
int GetHash(__inout HashHandle handle, __in_opt const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output);

/**
 * Frees hash function state
 *
 * @param handle is a state handle that inited by InitHashState
 *
 * @return status
 */
int FreeHashState(__inout HashHandle handle);

/**
 * Inits state for XOF
 *
 * Before using hashing you must init respective state with help of this function.
 * When state is no longer need you should free it by call of FreeXofState.
 *
 * @param handle is a state handle
 * @param func is a XOF that will be used in "hashing"
 *
 * @return status
 */
int InitXofState(__inout XofHandle* handle, __in Xof func);

/**
 * Resets internal XOF state
 *
 * If you wish to throw away any processed chunks of data and start to "hashing"
 * with begining using current handle, you should call this function before.
 * Also state is automaticaly resets after call of GetHash with finalize flag.
 *
 * @param handle is a state handle that inited by InitXofState
 *
 * @return status
 */
int ResetXofState(__inout XofHandle handle);

/**
 * GetXof is make processing by XOF
 *
 * This is the main "hashing" function by XOF that using handle inited by InitXofState handle.
 * If you using this function for partial input, input size must be exact divisible by block size of current hashing function.
 * (you may check the numbers from macros _BLOCK_SIZE like SHAKE128_BLOCK_SIZE).
 * When you pass the last part of current data, finalize flag should be true, and otherwise false.
 * In order to avoid problems with data corruption do not reset state by ResetXofState
 * between calls of GetXof with false finalize flag.
 * Output buffer must be supplied when finalize flag is set.
 *
 * @param handle is a state handle that inited by InitBlockCipherState
 * @param input data to hashing
 * @param inputSize size of the current input chunk (if input is nullptr than must be equal to 0)
 * @param finalize flag that indicate last chunk of data
 * @param output buffer allocated by user for output didgest
 * @param outputSize size of output buffer
 *
 * @return status
 */
int GetXof(__inout XofHandle handle, __in_opt const void* input, __in uint64_t inputSize, __in bool finalize, __out_opt void* output, __in uint64_t outputSize);

/**
 * Frees XOF state
 *
 * @param handle is a state handle that inited by InitXofState
 *
 * @return status
 */
int FreeXofState(__inout XofHandle handle);

/**
 * Inits state for pseudo random function
 *
 * Before using PRF you must init respective state with help of this function.
 * When state is no longer need you should free it by call of FreePrfState.
 * Currently only HMAC supported - see PRF enum.
 *
 * @param handle is a state handle
 * @param func is a PRF that will be used
 *
 * @return status
 */
int InitPrfState(__inout PrfHandle* handle, __in Prf func);

/**
 * Resets internal PRF state
 *
 * If you wish to throw away any processed chunks of data and start
 * with begining using current handle, you should call this function before.
 * Also state is automaticaly resets after call of GetHash with finalize flag.
 *
 * @param handle is a state handle that inited by InitPrfState
 *
 * @return status
 */
int ResetPrfState(__inout PrfHandle handle);

/**
 * GetPrf is make processing by hashing function
 *
 * This is the main function that using handle inited by InitPrfState handle.
 * If you using this function for partial input, input size must be exact divisible by block size of respective hashing function.
 * (you may check the numbers from macros _BLOCK_SIZE like SHA1_BLOCK_SIZE).
 * When you pass the last part of current data, finalize flag should be true, and otherwise false.
 * In order to avoid problems with data corruption do not reset state by ResetPrfState
 * between calls of GetPrf with false finalize flag.
 * Output buffer must be supplied when finalize flag is set.
 *
 * @param handle is a state handle that inited by InitBlockCipherState
 * @param input data/message
 * @param inputSize size of the current input chunk (if input is nullptr than must be equal to 0)
 * @param key key
 * @param keySize size of the key (if key is nullptr than must be equal to 0)
 * @param finalize flag that indicate last chunk of data
 * @param output buffer allocated by user for output didgest (for all HMAC functions see respective macros _DIGEST_SIZE like SHA1_DIGEST_SIZE)
 * @param outputSize size of output buffer (currently not supported, cause only HMAC functions with fixed output size is used)
 *
 * @return status
 */
int GetPrf(__inout PrfHandle handle, __in_opt const void* input, __in uint64_t inputSize, __in_opt const void* key, __in uint64_t keySize, __in bool finalize, __out_opt void* output, __in_opt uint64_t outputSize);

/**
 * Frees PRF state
 *
 * @param handle is a state handle that inited by InitPrfState
 *
 * @return status
 */
int FreePrfState(__inout PrfHandle handle);

/**
 * GetPbkdf2 get key by PBKDF2 algorithm
 *
 * @param salt is a salt for password
 * @param saltSize size of the salt
 * @param password password
 * @param passwordSize size of the password
 * @param func PRF that will be used in algorithm
 * @param iterationsNum number of iterations
 * @param output buffer allocated by user for derived key
 * @param outputSize size of output buffer and derived key
 *
 * @return status
 */
int GetPbkdf2(__in_opt const void* salt, __in uint64_t saltSize, __in_opt const void* password, __in uint64_t passwordSize, __in Prf func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize);

#ifdef __cplusplus
}
#endif
