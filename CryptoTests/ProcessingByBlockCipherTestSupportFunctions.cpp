#include "pch.h"

#include "ProcessingByBlockCipherTestSupportFunctions.h"

void ProcessingByBlockCipherMainTestFunc(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __inout uint64_t outputSize, __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in int expectedStatus, __in_opt const void* expectedRes, __in uint64_t expectedResLength, bool inPlace, __in CryptoMode enMode
)
{
    int status = NO_ERROR;

    std::unique_ptr<uint8_t> buffer(new uint8_t[outputSize]);

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
    default:
        blockSize = 0;
        break;
    }

    std::unique_ptr<uint8_t> iv(nullptr);

    if (cIv) {
        iv = std::unique_ptr<uint8_t>(new uint8_t[blockSize]);
        memcpy(iv.get(), cIv, blockSize);
    }

    BlockCipherHandle handle = nullptr;

    EVAL(InitBlockCipherState(&handle, cipherType, enMode, mode, padding, key, iv.get()));

    EVAL(ProcessingByBlockCipher(handle, input, inputSize, true, buffer.get(), &outputSize));

    if (expectedRes) {
        std::string result;
        if (enMode == Encryption_mode)
            result = GetHexResult(buffer.get(), outputSize);
        else if (enMode == Decryption_mode)
            result = std::string((const char*)buffer.get(), outputSize);

        std::string expRes((const char*)expectedRes);

        EXPECT_EQ(result, expRes);
    }

exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == expectedStatus);
}

void ProcessingByBlockCipherTestFunc(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __inout uint64_t outputSize, __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in int expectedStatus, __in_opt const void* expectedRes, __in uint64_t expectedResLength, __in CryptoMode enMode
)
{
    ProcessingByBlockCipherMainTestFunc(input, inputSize, padding, key, cipherType, outputSize, mode, cIv, expectedStatus, expectedRes, expectedResLength, false, enMode);
}

void ProcessingByBlockCipherInPlaceTestFunc(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __inout uint64_t outputSize, __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in int expectedStatus, __in_opt const void* expectedRes, __in uint64_t expectedResLength, __in CryptoMode enMode
)
{
    ProcessingByBlockCipherMainTestFunc(input, inputSize, padding, key, cipherType, outputSize, mode, cIv, expectedStatus, expectedRes, expectedResLength, true, enMode);
}

void ProcessingByBlockCipherMultipartTestFunc(__in const void* input_1, __in uint64_t inputSize_1, __in const void* input_2, __in uint64_t inputSize_2, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in_opt const void* expectedRes, __in CryptoMode enMode)
{
    uint64_t blockSize = 0;
    switch (cipherType) {
    case DES_cipher_type:
    case TDES_cipher_type:
        blockSize = DES_BLOCK_SIZE;
        break;
    default:
        blockSize = 0;
        break;
    }

    uint64_t lastBlockAddition = blockSize - inputSize_2 % blockSize;

    std::unique_ptr<uint8_t> buffer(new uint8_t[inputSize_1 + inputSize_2 + (lastBlockAddition ? lastBlockAddition : blockSize)]);

    std::unique_ptr<uint8_t> iv(nullptr);

    if (cIv) {
        iv = std::unique_ptr<uint8_t>(new uint8_t[blockSize]);
        memcpy(iv.get(), cIv, blockSize);
    }

    int status = NO_ERROR;

    uint64_t outputSize = inputSize_1;

    BlockCipherHandle handle = nullptr;

    EVAL(InitBlockCipherState(&handle, cipherType, enMode, mode, padding, key, iv.get()));

    if (NO_ERROR == (status = ProcessingByBlockCipher(handle, input_1, inputSize_1, false, buffer.get(), &outputSize))) {
        uint64_t totalSize = outputSize;
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
