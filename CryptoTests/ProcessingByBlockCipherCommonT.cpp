//  ProcessingByBlockCipherCommonT.cpp
//

#include "pch.h"

#include "ProcessingByBlockCipherTestSupportFunctions.h"

TEST(ProcessingByBlockCipherCommonT, NullState) {
    int status = NO_ERROR;
    uint8_t* buffer = new uint8_t[8];
    size_t outputSize = 8;
    EVAL(ProcessingByBlockCipher(nullptr, TEST_STRING_8, 8, true, buffer, &outputSize));

exit:
    EXPECT_TRUE(status == ERROR_NULL_STATE_HANDLE);
    delete[] buffer;
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
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, ECB_mode, PKCSN7_padding, KEY_8, nullptr));
    EVAL(ProcessingByBlockCipher(handle, TEST_STRING_8, 8, true, nullptr, &outputSize));

exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == ERROR_NULL_OUTPUT);
}

TEST(ProcessingByBlockCipherCommonT, NullOutputSize) {
    int status = NO_ERROR;
    uint8_t* buffer = new uint8_t[1];
    BlockCipherHandle handle = nullptr;
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, ECB_mode, PKCSN7_padding, KEY_8, nullptr));
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
    BlockCipherHandle handle = nullptr;
    size_t outputSize = 7;
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, ECB_mode, PKCSN7_padding, KEY_8, nullptr));
    EVAL(ProcessingByBlockCipher(handle, TEST_STRING_8, 8, false, buffer, &outputSize));

exit:
    EXPECT_TRUE(status == ERROR_TOO_SMALL_OUTPUT_SIZE);
    delete[] buffer;
}

// Temp test
TEST(ProcessingByBlockCipherCommonT, AesRoundsKeys) {
    int status = NO_ERROR;
    BlockCipherHandle handle = nullptr;
    size_t outputSize = 64;
    std::unique_ptr<uint8_t> output(new uint8_t[outputSize]);
    uint8_t key[] = { 0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5 };
    uint8_t input_2[] = { 0xd5, 0xf1, 0xea, 0x3b, 0x8e, 0x08, 0xb4, 0xba, 0xa7, 0x8e, 0x7d, 0x91, 0x6c, 0x66, 0x94, 0xb8, 0x16, 0xb3, 0x38, 0x36, 0xac, 0x06, 0x59, 0x7f, 0x8b, 0x48, 0xc4, 0x56, 0xa8, 0x50, 0xef, 0xec, 0x78, 0xf3, 0xd2, 0x4e, 0x41, 0xb1, 0x64, 0x64, 0xb2, 0x4d, 0xf7, 0x4c, 0x01, 0x77, 0x95, 0x00, 0xad, 0x96, 0x40, 0x8b, 0x7a, 0x38, 0xd3, 0xa1, 0x79, 0xea, 0x60, 0x24, 0x21, 0x12, 0x21, 0xcb };
    InitBlockCipherState(&handle, AES128_cipher_type, Decryption_mode, CTR_mode, PKCSN7_padding, TEST_STRING_16, TEST_STRING_16_2);
    ProcessingByBlockCipher(handle, input_2, 64, true, output.get(), &outputSize);

    uint8_t input[] = { 0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34 };
    
    

}
