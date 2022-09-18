// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
//  ProcessingByBlockCipherCommonT.cpp
//

#include "pch.h"

#include "ProcessingByBlockCipherTestSupportFunctions.h"

TEST(ProcessingByBlockCipherCommonT, NullState) {
    int status = NO_ERROR;
    std::vector<uint8_t> buffer(8);
    size_t outputSize = 8;
    EVAL(ProcessingByBlockCipher(nullptr, TEST_STRING_8, 8, true, buffer.data(), &outputSize));

exit:
    EXPECT_TRUE(status == ERROR_NULL_STATE_HANDLE);
}

TEST(ProcessingByBlockCipherCommonT, NullInput) {
    ProcessingByBlockCipherTestFunc(nullptr, 55, PKCSN7_padding, KEY_8, DES_cipher_type, sizeof(TEST_STRING_8), ECB_mode, nullptr
        , ERROR_NULL_INPUT, nullptr, Decryption_mode);
}

TEST(ProcessingByBlockCipherCommonT, TooSmallInputSize) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_8, 0, PKCSN7_padding, KEY_8, DES_cipher_type, sizeof(TEST_STRING_8), ECB_mode, nullptr
        , ERROR_TOO_SMALL_INPUT_SIZE, nullptr, Decryption_mode);
}

TEST(ProcessingByBlockCipherCommonT, WrongInputSize_2) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_8, 7, PKCSN7_padding, KEY_8, DES_cipher_type, sizeof(TEST_STRING_8), ECB_mode, nullptr
        , ERROR_WRONG_INPUT_SIZE, nullptr, Decryption_mode);
}

TEST(ProcessingByBlockCipherCommonT, NullOutput) {
    int status = NO_ERROR;
    size_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    BlockCipherHandle handle = nullptr;
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, ECB_mode, PKCSN7_padding, nullptr, KEY_8, nullptr));
    EVAL(ProcessingByBlockCipher(handle, TEST_STRING_8, 8, true, nullptr, &outputSize));

exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == ERROR_NULL_OUTPUT);
}

TEST(ProcessingByBlockCipherCommonT, NullOutputSize) {
    int status = NO_ERROR;
    std::vector<uint8_t> buffer(1);
    BlockCipherHandle handle = nullptr;
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, ECB_mode, PKCSN7_padding, nullptr, KEY_8, nullptr));
    EVAL(ProcessingByBlockCipher(handle, TEST_STRING_8, 8, true, buffer.data(), nullptr));

exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == ERROR_NULL_OUTPUT_SIZE);
}

TEST(ProcessingByBlockCipherCommonT, TooSmallOutputSize) {
    int status = NO_ERROR;
    std::vector<uint8_t> buffer(1);
    BlockCipherHandle handle = nullptr;
    size_t outputSize = 7;
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, ECB_mode, PKCSN7_padding, nullptr, KEY_8, nullptr));
    EVAL(ProcessingByBlockCipher(handle, TEST_STRING_8, 8, false, buffer.data(), &outputSize));

exit:
    EXPECT_TRUE(status == ERROR_TOO_SMALL_OUTPUT_SIZE);
}

TEST(ProcessingByBlockCipherCommonT, TooSmallOutputSize2) {
    int status = NO_ERROR;
    BlockCipherHandle handle = nullptr;
    size_t outputSize = 0;
    uint8_t input[] = { 0xb9, 0xe9, 0x8a, 0x3c, 0x77, 0xa5, 0x10, 0x86 };
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Encryption_mode, ECB_mode, PKCSN7_padding, nullptr, KEY_8, nullptr));
    EVAL(ProcessingByBlockCipher(handle, TEST_STRING_8, 8, true, nullptr, &outputSize));

exit:
    EXPECT_TRUE(status == ERROR_TOO_SMALL_OUTPUT_SIZE);
}

TEST(ProcessingByBlockCipherCommonT, TooSmallOutputSize3) {
    int status = NO_ERROR;
    BlockCipherHandle handle = nullptr;
    size_t outputSize = 0;
    uint8_t input[] = { 0xb9, 0xe9, 0x8a, 0x3c, 0x77, 0xa5, 0x10, 0x86 };
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, ECB_mode, PKCSN7_padding, nullptr, KEY_8, nullptr));
    EVAL(ProcessingByBlockCipher(handle, input, 8, true, nullptr, &outputSize));

exit:
    EXPECT_TRUE(status == ERROR_TOO_SMALL_OUTPUT_SIZE);
}
