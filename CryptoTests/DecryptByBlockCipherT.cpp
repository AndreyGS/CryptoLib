//  DecryptByBlockCipherT.cpp
//

#include "pch.h"

#include "common.h"

// Wrong arguments

TEST(DecryptByBlockCipherTest, WrongInput) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(nullptr, 55, ISO_7816_padding, key, DES_cipher_type, buffer, &outputSize, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, WrongInputSize) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(TEST_STRING_8, 0, ISO_7816_padding, key, DES_cipher_type, buffer, &outputSize, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, WrongInputSize_2) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(TEST_STRING_8, 7, ISO_7816_padding, key, DES_cipher_type, buffer, &outputSize, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, WrongPadding) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(TEST_STRING_8, 8, (PaddingType)-1, key, DES_cipher_type, buffer, &outputSize, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_PADDING_NOT_SUPPORTED);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, WrongKey) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(TEST_STRING_8, 8, ISO_7816_padding, nullptr, DES_cipher_type, buffer, &outputSize, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_WRONG_KEY);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, WrongCipherFunc) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(TEST_STRING_8, 8, ISO_7816_padding, key, (BlockCipherType)-1, buffer, &outputSize, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_CIPHER_FUNC_NOT_SUPPORTED);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, WrongOutput) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(TEST_STRING_8, 8, ISO_7816_padding, key, DES_cipher_type, nullptr, &outputSize, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_WRONG_OUTPUT);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, OutputSizeIsNull) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(TEST_STRING_8, 8, ISO_7816_padding, key, DES_cipher_type, buffer, nullptr, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_OUTPUT_SIZE_IS_NULL);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, WrongOutputSize) {
    uint8_t input[] = { 0xb9, 0xe9, 0x8a, 0x3c, 0x77, 0xa5, 0x10, 0x86 };
    uint64_t outputSize = 0;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(input, 8, PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_WRONG_OUTPUT_SIZE);
    EXPECT_EQ(outputSize, 7);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, WrongOpMode) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(TEST_STRING_8, 8, ISO_7816_padding, key, DES_cipher_type, buffer, &outputSize, (BlockCipherOpMode)-1, nullptr);

    EXPECT_TRUE(status == ERROR_UNSUPPROTED_ENCRYPTION_MODE);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, WrongIV) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(TEST_STRING_8, 8, ISO_7816_padding, key, DES_cipher_type, buffer, &outputSize, CBC_mode, nullptr);

    EXPECT_TRUE(status == ERROR_WRONG_INIT_VECTOR);
    delete[] buffer;
}

// Main test

// DES Single

TEST(DecryptByBlockCipherTest, DES_ECB_single) {
    uint8_t input[] = { 0xb9, 0xe9, 0x8a, 0x3c, 0x77, 0xa5, 0x10, 0x86 };
    uint64_t outputSize = 7;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(input, sizeof(input), PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, ECB_mode, nullptr);

    EXPECT_EQ(memcmp(buffer, TEST_STRING_7, 7), 0);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, DES_CBC_single) {
    uint8_t input[] = { 0x1d, 0x2d, 0x5b, 0x11, 0xab, 0x31, 0xc5, 0x12 };
    uint64_t outputSize = 7;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(input, sizeof(input), PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, CBC_mode, TEST_STRING_8);

    EXPECT_EQ(memcmp(buffer, TEST_STRING_7, 7), 0);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, DES_CFB_single) {
    uint8_t input[] = { 0xe2, 0x4a, 0x3e, 0x6a, 0xa8, 0xd6, 0x50, 0x46 };
    uint64_t outputSize = 7;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(input, sizeof(input), PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, CFB_mode, TEST_STRING_8);

    EXPECT_EQ(memcmp(buffer, TEST_STRING_7, 7), 0);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, DES_OFB_single) {
    uint8_t input[] = { 0xe2, 0x4a, 0x3e, 0x6a, 0xa8, 0xd6, 0x50, 0x46 };
    uint64_t outputSize = 7;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(input, sizeof(input), PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, OFB_mode, TEST_STRING_8);

    EXPECT_EQ(memcmp(buffer, TEST_STRING_7, 7), 0);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, DES_CTR_single) {
    uint8_t input[] = { 0xe2, 0x4a, 0x3e, 0x6a, 0xa8, 0xd6, 0x50, 0x46 };
    uint64_t outputSize = 7;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(input, sizeof(input), PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, CTR_mode, TEST_STRING_8);

    EXPECT_EQ(memcmp(buffer, TEST_STRING_7, 7), 0);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

// DES Multi

TEST(DecryptByBlockCipherTest, DES_ECB_multi) {
    uint8_t input[] = { 0x8c, 0xa8, 0xda, 0x07, 0xc0, 0x7a, 0x31, 0xa1, 0x3c, 0x1d, 0xe0, 0xb3, 0x5f, 0x5e, 0xad, 0xd8, 
                        0x85, 0x10, 0xc2, 0xef, 0x3f, 0x16, 0xba, 0x52, 0xa2, 0x7b, 0xa0, 0xf3, 0xe0, 0xcd, 0x8a, 0x71, 
                        0xe4, 0xb6, 0x09, 0x23, 0x95, 0x08, 0x87, 0x55, 0x99, 0xfc, 0xe6, 0x9a, 0x08, 0xad, 0xc9, 0x7a, 
                        0x6d, 0xf6, 0xa5, 0x5b, 0xe1, 0x07, 0x79, 0x1a, 0x1d, 0x26, 0xa6, 0x7e, 0x13, 0x62, 0xc9, 0x61, 
                        0xe3, 0x9e, 0xff, 0x3d, 0xb0, 0x5a, 0xa3, 0x0b, 0xaf, 0xfd, 0x67, 0x6f, 0xa3, 0xea, 0x9c, 0xde, 
                        0x92, 0x84, 0x13, 0x3c, 0x0c, 0xd6, 0x09, 0x94, 0x78, 0x9f, 0xa0, 0xad, 0x29, 0xc9, 0x3d, 0xde, 
                        0x9d, 0x9f, 0xd5, 0x45, 0x4c, 0xe4, 0xa9, 0x11, 0x2b, 0x64, 0x46, 0xfe, 0x66, 0x7f, 0x5e, 0x7e, 
                        0xad, 0x0c, 0x7d, 0x08, 0x5e, 0x69, 0x88, 0xe4, 0xe0, 0xfc, 0xd0, 0xfd, 0x2e, 0xc2, 0x70, 0xe5, 
                        0x5c, 0x5a, 0xc9, 0x11, 0x21, 0x64, 0x2e, 0xd5 };
    uint64_t outputSize = 128;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(input, sizeof(input), PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, ECB_mode, TEST_STRING_8);

    EXPECT_EQ(memcmp(buffer, TEST_STRING_128, 128), 0);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, DES_CBC_multi) {
    uint8_t input[] = { 0x38, 0xb9, 0x49, 0xd3, 0x6c, 0xcf, 0x3b, 0xbc, 0x19, 0xab, 0x71, 0xf4, 0xbe, 0x2b, 0xaa, 0x44, 
                        0x97, 0x5a, 0x4b, 0x63, 0xda, 0x29, 0x9a, 0x5b, 0xeb, 0xda, 0x3d, 0x5c, 0x0d, 0x8a, 0x02, 0x42, 
                        0xf5, 0x79, 0xcb, 0x36, 0x48, 0x63, 0x3c, 0x67, 0xb7, 0x5a, 0x58, 0x77, 0x84, 0x7d, 0x10, 0xb9, 
                        0x89, 0x1e, 0x67, 0x61, 0x29, 0x22, 0x64, 0x9c, 0xbb, 0x80, 0x45, 0x20, 0xf3, 0x07, 0x4d, 0xba, 
                        0x3c, 0x9d, 0x4b, 0x4b, 0x88, 0xbb, 0xd7, 0x54, 0x7b, 0x6b, 0x76, 0x8d, 0xc9, 0x84, 0x21, 0xf9, 
                        0xac, 0x1c, 0xd2, 0x73, 0x1f, 0xc8, 0x5e, 0x57, 0xc5, 0x8f, 0xf5, 0x2a, 0xd5, 0x6a, 0x47, 0xe1, 
                        0x87, 0x65, 0xb9, 0x35, 0xcd, 0x42, 0xa1, 0x3f, 0x38, 0x18, 0x70, 0x8d, 0xf6, 0x54, 0x55, 0x7d, 
                        0x07, 0xa2, 0x9d, 0x6f, 0x0c, 0x7a, 0x6c, 0xda, 0x7c, 0x53, 0x27, 0x91, 0xee, 0x97, 0x58, 0x48, 
                        0xc2, 0xa3, 0xc1, 0x4f, 0xfd, 0x61, 0xf9, 0x53 };
    uint64_t outputSize = 128;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(input, sizeof(input), PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, CBC_mode, TEST_STRING_8);

    EXPECT_EQ(memcmp(buffer, TEST_STRING_128, 128), 0);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, DES_CFB_multi) {
    uint8_t input[] = { 0xe2, 0x4a, 0x32, 0x39, 0xce, 0xda, 0x47, 0x22, 0xa7, 0x79, 0x54, 0x3c, 0xb9, 0xf9, 0x91, 0x91, 
                        0xb4, 0x50, 0xd4, 0x4c, 0xce, 0x1e, 0x67, 0x97, 0xa4, 0x23, 0x5f, 0x65, 0x22, 0xec, 0x40, 0xc9, 
                        0xb9, 0xb2, 0x4e, 0xb5, 0x98, 0x94, 0x98, 0xd0, 0xb6, 0xc6, 0xe1, 0x11, 0xb8, 0x59, 0x7c, 0xa4, 
                        0x76, 0x70, 0x4c, 0x79, 0x96, 0x2b, 0x64, 0x58, 0x4a, 0xb3, 0x17, 0xe3, 0xbd, 0x1e, 0x74, 0x37, 
                        0xf4, 0xf7, 0x73, 0xcc, 0x8a, 0xb8, 0x5a, 0x34, 0x19, 0xaa, 0x50, 0x28, 0xad, 0xa1, 0xaa, 0x76, 
                        0xac, 0xb7, 0x6f, 0x04, 0xe2, 0x01, 0xd2, 0xf9, 0x60, 0x68, 0xa6, 0x9c, 0x41, 0x1e, 0xf7, 0xe6, 
                        0x56, 0x2d, 0x2e, 0xb5, 0x06, 0x2f, 0xf5, 0xc6, 0xac, 0xf2, 0xf6, 0x83, 0x5e, 0xae, 0x0e, 0x28, 
                        0x83, 0xcc, 0xe4, 0xf6, 0x7e, 0xef, 0xaf, 0x75, 0xd9, 0xc6, 0x7d, 0xa4, 0x99, 0xc3, 0x90, 0x22, 
                        0x8a, 0xd8, 0x46, 0x29, 0xaf, 0xc2, 0x06, 0xf3 };
    uint64_t outputSize = 128;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(input, sizeof(input), PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, CFB_mode, TEST_STRING_8);

    EXPECT_EQ(memcmp(buffer, TEST_STRING_128, 128), 0);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, DES_OFB_multi) {
    uint8_t input[] = { 0xe2, 0x4a, 0x32, 0x39, 0xce, 0xda, 0x47, 0x22, 0xb6, 0xe1, 0xb3, 0xef, 0xfe, 0x6e, 0xf3, 0x1d, 
                        0xa7, 0x10, 0xf2, 0x9a, 0xd9, 0x45, 0xf3, 0x5e, 0x3f, 0x65, 0x19, 0x25, 0x42, 0x83, 0xe8, 0x4a, 
                        0x7f, 0xd3, 0x66, 0x5e, 0xf1, 0x83, 0x25, 0xae, 0x11, 0x59, 0xcc, 0xc9, 0xfa, 0xed, 0xcd, 0x8a, 
                        0x5e, 0x35, 0xc1, 0x87, 0xc4, 0x7b, 0x71, 0xd8, 0x00, 0x4f, 0x4c, 0x99, 0x8c, 0x9c, 0x70, 0xe8, 
                        0x11, 0x11, 0x75, 0xb3, 0x0c, 0xe2, 0x88, 0xba, 0xcc, 0x00, 0x84, 0x56, 0x02, 0xc4, 0x63, 0x4a, 
                        0x94, 0xbc, 0x3a, 0x37, 0x6a, 0xad, 0x7e, 0x07, 0xb4, 0x64, 0x3e, 0xbd, 0x72, 0x46, 0xeb, 0xc2, 
                        0x95, 0x97, 0x78, 0xbc, 0xfa, 0x32, 0xc1, 0x40, 0x0a, 0x5f, 0xa5, 0x15, 0x8a, 0x92, 0x13, 0x48, 
                        0x73, 0x2e, 0x35, 0x08, 0x7f, 0xcc, 0xa1, 0xd7, 0x3f, 0x13, 0x95, 0x26, 0x78, 0xe3, 0xb5, 0x7c, 
                        0x34, 0x1b, 0xd4, 0x1a, 0xdd, 0x02, 0xe4, 0x9f };
    uint64_t outputSize = 128;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(input, sizeof(input), PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, OFB_mode, TEST_STRING_8);

    EXPECT_EQ(memcmp(buffer, TEST_STRING_128, 128), 0);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, DES_CTR_multi) {
    uint8_t input[] = { 0xe2, 0x4a, 0x32, 0x39, 0xce, 0xda, 0x47, 0x22, 0xc2, 0xb9, 0x84, 0xa4, 0x70, 0x0d, 0x82, 0x1b, 
                        0x38, 0x67, 0xc7, 0x2f, 0x6c, 0x5d, 0xe3, 0x54, 0xaa, 0x2c, 0xfc, 0x1e, 0x30, 0x7a, 0xd3, 0x5d, 
                        0x96, 0xf1, 0xf3, 0xcd, 0xec, 0x82, 0x1f, 0xc7, 0xf0, 0x93, 0xa9, 0x1f, 0xb3, 0x54, 0x92, 0xd9, 
                        0x3b, 0x37, 0xf7, 0x7d, 0x92, 0xd8, 0x95, 0x60, 0x8f, 0xbb, 0xed, 0x96, 0x84, 0x79, 0xd4, 0x47, 
                        0x1c, 0xd2, 0xe5, 0xf4, 0x76, 0xf1, 0x56, 0x90, 0x4c, 0x44, 0x13, 0x78, 0x6d, 0xd3, 0x97, 0xd5, 
                        0x2c, 0xdd, 0x43, 0x33, 0x5b, 0xbf, 0x4a, 0xeb, 0x10, 0x35, 0xe8, 0xae, 0xd5, 0xb9, 0xb3, 0x78, 
                        0x0c, 0xef, 0x74, 0x28, 0xff, 0xbb, 0x8b, 0x89, 0xfb, 0xec, 0x32, 0xde, 0x02, 0xf9, 0xd8, 0x4d, 
                        0x36, 0xa5, 0x9d, 0x27, 0xc5, 0xf6, 0xd7, 0xe0, 0x81, 0x11, 0x53, 0xb1, 0x4d, 0x2e, 0x0c, 0xc9, 
                        0x8b, 0x06, 0xa7, 0xd4, 0x9d, 0x29, 0xc3, 0x19 };
    uint64_t outputSize = 128;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = DecryptByBlockCipher(input, sizeof(input), PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, CTR_mode, TEST_STRING_8);

    EXPECT_EQ(memcmp(buffer, TEST_STRING_128, 128), 0);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

// 3DES Single

TEST(DecryptByBlockCipherTest, TDES_ECB_single) {
    uint8_t input[] = { 0xd8, 0xa2, 0x72, 0x1a, 0xb3, 0xf5, 0x42, 0xcb };
    uint64_t outputSize = 8;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5ASkv8vwel0ve8hve40";
    int status = DecryptByBlockCipher(input, 8, PKCSN7_padding, key, TDES_cipher_type, buffer, &outputSize, ECB_mode, TEST_STRING_8);

    EXPECT_EQ(memcmp(buffer, TEST_STRING_7, 7), 0);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, TDES_CBC_single) {
    uint8_t input[] = { 0x07, 0x5e, 0x74, 0x32, 0x36, 0x68, 0x64, 0x2d };
    uint64_t outputSize = 8;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5ASkv8vwel0ve8hve40";
    int status = DecryptByBlockCipher(input, 8, PKCSN7_padding, key, TDES_cipher_type, buffer, &outputSize, CBC_mode, TEST_STRING_8);

    EXPECT_EQ(memcmp(buffer, TEST_STRING_7, 7), 0);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, TDES_CFB_single) {
    uint8_t input[] = { 0x83, 0x25, 0x9f, 0xa6, 0x05, 0xf0, 0xf0, 0x0e };
    uint64_t outputSize = 8;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5ASkv8vwel0ve8hve40";
    int status = DecryptByBlockCipher(input, 8, PKCSN7_padding, key, TDES_cipher_type, buffer, &outputSize, CFB_mode, TEST_STRING_8);

    EXPECT_EQ(memcmp(buffer, TEST_STRING_7, 7), 0);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, TDES_OFB_single) {
    uint8_t input[] = { 0x83, 0x25, 0x9f, 0xa6, 0x05, 0xf0, 0xf0, 0x0e };
    uint64_t outputSize = 8;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5ASkv8vwel0ve8hve40";
    int status = DecryptByBlockCipher(input, 8, PKCSN7_padding, key, TDES_cipher_type, buffer, &outputSize, OFB_mode, TEST_STRING_8);

    EXPECT_EQ(memcmp(buffer, TEST_STRING_7, 7), 0);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(DecryptByBlockCipherTest, TDES_CTR_single) {
    uint8_t input[] = { 0x83, 0x25, 0x9f, 0xa6, 0x05, 0xf0, 0xf0, 0x0e };
    uint64_t outputSize = 8;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5ASkv8vwel0ve8hve40";
    int status = DecryptByBlockCipher(input, 8, PKCSN7_padding, key, TDES_cipher_type, buffer, &outputSize, CTR_mode, TEST_STRING_8);

    EXPECT_EQ(memcmp(buffer, TEST_STRING_7, 7), 0);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}
