//  ProcessingByBlockCipherCommonT.cpp
//

#include "pch.h"

#include "ProcessingByBlockCipherTestSupportFunctions.h"

TEST(ProcessingByBlockCipherCommonT, NullState) {
    int status = NO_ERROR;
    uint8_t* buffer = new uint8_t[8];
    uint64_t outputSize = 8;
    EVAL(ProcessingByBlockCipher(nullptr, TEST_STRING_8, 8, true, buffer, &outputSize));

exit:
    EXPECT_TRUE(status == ERROR_NULL_STATE_HANDLE);
    delete[] buffer;
}

TEST(ProcessingByBlockCipherCommonT, NullInput) {
    ProcessingByBlockCipherTestFunc(nullptr, 55, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_8), ECB_mode, nullptr
        , ERROR_NULL_INPUT, nullptr, 0, Decryption_mode);
}

TEST(ProcessingByBlockCipherCommonT, WrongInputSize) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_8, 0, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_8), ECB_mode, nullptr
        , ERROR_WRONG_INPUT_SIZE, nullptr, 0, Decryption_mode);
}

TEST(ProcessingByBlockCipherCommonT, WrongInputSize_2) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_8, 7, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_8), ECB_mode, nullptr
        , ERROR_WRONG_INPUT_SIZE, nullptr, 0, Decryption_mode);
}

TEST(ProcessingByBlockCipherCommonT, NullOutput) {
    int status = NO_ERROR;
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    int8_t key[] = "81cav5AS";
    BlockCipherHandle handle = nullptr;
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, ECB_mode, PKCSN7_padding, key, nullptr));
    EVAL(ProcessingByBlockCipher(handle, TEST_STRING_8, 8, true, nullptr, &outputSize));

exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == ERROR_NULL_OUTPUT);
}

TEST(ProcessingByBlockCipherCommonT, NullOutputSize) {
    int status = NO_ERROR;
    uint8_t* buffer = new uint8_t[1];
    int8_t key[] = "81cav5AS";
    BlockCipherHandle handle = nullptr;
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, ECB_mode, PKCSN7_padding, key, nullptr));
    EVAL(ProcessingByBlockCipher(handle, TEST_STRING_8, 8, true, buffer, nullptr));

exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == ERROR_NULL_OUTPUT_SIZE);
    delete[] buffer;
}

TEST(ProcessingByBlockCipherCommonT, TooSmallOutputSize) {
    int status = NO_ERROR;
    uint8_t* buffer = new uint8_t[1];
    int8_t key[] = "81cav5AS";
    BlockCipherHandle handle = nullptr;
    uint64_t outputSize = 7;
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, ECB_mode, PKCSN7_padding, key, nullptr));
    EVAL(ProcessingByBlockCipher(handle, TEST_STRING_8, 8, false, buffer, &outputSize));

exit:
    EXPECT_TRUE(status == ERROR_TOO_SMALL_OUTPUT_SIZE);
    delete[] buffer;
}

// Temp test
TEST(ProcessingByBlockCipherCommonT, AesRoundsKeys) {
    int status = NO_ERROR;
    BlockCipherHandle handle = nullptr;
    uint8_t* buffer = new uint8_t[1];
    int8_t key[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    InitBlockCipherState(&handle, AES128_cipher_type, Decryption_mode, ECB_mode, PKCSN7_padding, key, nullptr);
}
