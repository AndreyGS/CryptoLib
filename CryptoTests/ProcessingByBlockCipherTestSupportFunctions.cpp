// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
//  ProcessingByBlockCipherTestSupportFunctions.cpp
//

#include "pch.h"
#include "ProcessingByBlockCipherTestSupportFunctions.h"
#if defined _MSC_VER
#include "windows.h"
#endif

void ProcessingByBlockCipherMainTestFunc(__in const void* input, __in size_t inputSize, __in PaddingType padding, __in const void* key, __in BlockCipherType cipherType
    , __inout size_t outputSize, __in BlockCipherOpMode mode, __in_opt const void* iv
    , __in int expectedStatus, __in_opt const char* expectedRes, bool inPlace, __in CryptoMode enMode, int expLength, const char* fileName, size_t testNum
)
{
    int status = NO_ERROR;

    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(outputSize);

    if (inPlace) {
        memcpy(buffer.get(), input, inputSize);
        input = buffer.get();
    }

    uint64_t blockSize = 0;
    switch (cipherType) {
    case DES_cipher_type:
    case TDES_cipher_type:
        blockSize = DES_BLOCK_SIZE;
        break;
    case AES128_cipher_type:
    case AES192_cipher_type:
    case AES256_cipher_type:
        blockSize = AES_BLOCK_SIZE;
        break;
    default:
        blockSize = 0;
        break;
    }

    BlockCipherHandle handle = nullptr;
    HardwareFeatures hwFeatures = { 0 };
    hwFeatures.avx = true;

    EVAL(InitBlockCipherState(&handle, cipherType, enMode, mode, padding, hwFeatures, key, iv));

    EVAL(ProcessingByBlockCipher(handle, input, inputSize, true, buffer.get(), &outputSize));

    if (expectedRes) {
        std::string result;
        if (enMode == Encryption_mode)
            result = GetHexResult(buffer.get(), outputSize);
        else if (enMode == Decryption_mode)
            result = std::string((const char*)buffer.get(), outputSize);

        std::string expRes(expectedRes);

        if (expLength) {
            bool check = memcmp(result.c_str(), expectedRes, expLength) == 0;
            EXPECT_TRUE(check);
            if (!check) {
                std::cout << "Assert in FileName: " << fileName << "; TestNum: " << testNum << "\n";
#if defined _MSC_VER
                char sprintf[200] = { 0 };
                sprintf_s(sprintf, 200, "Assert in FileName : %s; TestNum: %zu\n", fileName, testNum);
                OutputDebugStringA(sprintf);
#endif
            }
        }
        else
            EXPECT_EQ(result, expRes);
    }

exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == expectedStatus);
}

void ProcessingByBlockCipherTestFunc(__in const void* input, __in size_t inputSize, __in PaddingType padding, __in const void* key, __in BlockCipherType cipherType
    , __inout size_t outputSize, __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in int expectedStatus, __in_opt const char* expectedRes, __in CryptoMode enMode
)
{
    ProcessingByBlockCipherMainTestFunc(input, inputSize, padding, key, cipherType, outputSize, mode, cIv, expectedStatus, expectedRes, false, enMode, 0, nullptr, 0);
}

void ProcessingByBlockCipherTestKAT_AESFunc(__in const void* input, __in size_t inputSize, __in PaddingType padding, __in const void* key, __in BlockCipherType cipherType
    , __inout size_t outputSize, __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in int expectedStatus, __in_opt const char* expectedRes, __in CryptoMode enMode, int expLength, const char* fileName, size_t testNum
)
{
    ProcessingByBlockCipherMainTestFunc(input, inputSize, padding, key, cipherType, outputSize, mode, cIv, expectedStatus, expectedRes, false, enMode, expLength, fileName, testNum);
}

void ProcessingByBlockCipherInPlaceTestFunc(__in const void* input, __in size_t inputSize, __in PaddingType padding, __in const void* key, __in BlockCipherType cipherType
    , __inout size_t outputSize, __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in int expectedStatus, __in_opt const char* expectedRes, __in CryptoMode enMode
)
{
    ProcessingByBlockCipherMainTestFunc(input, inputSize, padding, key, cipherType, outputSize, mode, cIv, expectedStatus, expectedRes, true, enMode, 0, nullptr, 0);
}

void ProcessingByBlockCipherMultipartTestFunc(__in const void* input_1, __in size_t inputSize_1, __in const void* input_2, __in size_t inputSize_2, __in PaddingType padding, __in const void* key, __in BlockCipherType cipherType
    , __in BlockCipherOpMode mode, __in_opt const void* iv
    , __in_opt const char* expectedRes, __in CryptoMode enMode)
{
    size_t blockSize = 0;
    switch (cipherType) {
    case DES_cipher_type:
    case TDES_cipher_type:
        blockSize = DES_BLOCK_SIZE;
        break;
    case AES128_cipher_type:
    case AES192_cipher_type:
    case AES256_cipher_type:
        blockSize = AES_BLOCK_SIZE;
        break;
    default:
        blockSize = 0;
        break;
    }

    size_t lastBlockAddition = blockSize - inputSize_2 % blockSize;

    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(inputSize_1 + inputSize_2 + (lastBlockAddition ? lastBlockAddition : blockSize));

    int status = NO_ERROR;

    size_t outputSize = inputSize_1;

    BlockCipherHandle handle = nullptr;
    HardwareFeatures hwFeatures = { 0 };
    hwFeatures.avx = true;

    EVAL(InitBlockCipherState(&handle, cipherType, enMode, mode, padding, hwFeatures, key, iv));

    if (NO_ERROR == (status = ProcessingByBlockCipher(handle, input_1, inputSize_1, false, buffer.get(), &outputSize))) {
        size_t totalSize = outputSize;
        outputSize = inputSize_2 + (lastBlockAddition ? lastBlockAddition : 0);
        status = ProcessingByBlockCipher(handle, input_2, inputSize_2, true, (uint8_t*)buffer.get() + totalSize, &outputSize);
        totalSize += outputSize;

        if (expectedRes) {
            std::string result;
            if (enMode == Encryption_mode)
                result = GetHexResult(buffer.get(), totalSize);
            else if (enMode == Decryption_mode)
                result = std::string((const char*)buffer.get(), totalSize);

            std::string expRes((const char*)expectedRes);

            EXPECT_EQ(result, expRes);
        }
    }

exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == NO_ERROR);
}
