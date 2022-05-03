//  EncryptByBlockCipherT.cpp
//

#include "pch.h"

#include "common.h"

// Wrong arguments

TEST(EncryptByBlockCipherTest, WrongInput) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(nullptr, 55, ISO_7816_padding, key, DES_cipher_type, buffer, &outputSize, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, WrongInputSize) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_8, 0, ISO_7816_padding, key, DES_cipher_type, buffer, &outputSize, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, WrongPadding) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_8, 8, (PaddingType)-1, key, DES_cipher_type, buffer, &outputSize, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_PADDING_NOT_SUPPORTED);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, WrongKey) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_8, 8, ISO_7816_padding, nullptr , DES_cipher_type, buffer, &outputSize, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_WRONG_KEY);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, WrongCipherFunc) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_8, 8, ISO_7816_padding, key, (BlockCipherType)-1, buffer, &outputSize, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_CIPHER_FUNC_NOT_SUPPORTED);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, WrongOutput) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_8, 8, ISO_7816_padding, key, DES_cipher_type, nullptr, &outputSize, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_WRONG_OUTPUT);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, OutputSizeIsNull) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_8, 8, ISO_7816_padding, key, DES_cipher_type, buffer, nullptr, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_OUTPUT_SIZE_IS_NULL);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, WrongOutputSize) {
    uint64_t outputSize = 0;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_8, 8, ISO_7816_padding, key, DES_cipher_type, buffer, &outputSize, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_WRONG_OUTPUT_SIZE);
    EXPECT_EQ(outputSize, 16);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, WrongOpMode) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_8, 8, ISO_7816_padding, key, DES_cipher_type, buffer, &outputSize, (BlockCipherOpMode)-1, nullptr);

    EXPECT_TRUE(status == ERROR_UNSUPPROTED_ENCRYPTION_MODE);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, WrongIV) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_8, 8, ISO_7816_padding, key, DES_cipher_type, buffer, &outputSize, CBC_mode, nullptr);

    EXPECT_TRUE(status == ERROR_WRONG_INIT_VECTOR);
    delete[] buffer;
}

// Main test

// DES Single

TEST(EncryptByBlockCipherTest, DES_ECB_single) {
    uint64_t outputSize = DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_7, 7, PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, ECB_mode, nullptr);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "b9e98a3c77a51086";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, DES_CBC_single) {
    uint64_t outputSize = DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_7, 7, PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, CBC_mode, TEST_STRING_8);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "1d2d5b11ab31c512";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, DES_CFB_single) {
    uint64_t outputSize = DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_7, 7, PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, CFB_mode, TEST_STRING_8);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "e24a3e6aa8d65046";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, DES_OFB_single) {
    uint64_t outputSize = DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_7, 7, PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, OFB_mode, TEST_STRING_8);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "e24a3e6aa8d65046";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, DES_CTR_single) {
    uint64_t outputSize = DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_7, 7, PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, CTR_mode, TEST_STRING_8);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "e24a3e6aa8d65046";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

// DES Multi

TEST(EncryptByBlockCipherTest, DES_ECB_multi) {
    uint64_t outputSize = sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_128, 128, PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, ECB_mode, nullptr);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "8ca8da07c07a31a13c1de0b35f5eadd88510c2ef3f16ba52a27ba0f3e0cd8a71e4b609239508875599fce69a08adc97a6df6a55be107791a1d2"
                                  "6a67e1362c961e39eff3db05aa30baffd676fa3ea9cde9284133c0cd60994789fa0ad29c93dde9d9fd5454ce4a9112b6446fe667f5e7ead0c7d085e6988e4e0fcd0fd2ec270e55c5ac91121642ed5";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, DES_CBC_multi) {
    uint64_t outputSize = sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_128, 128, PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, CBC_mode, TEST_STRING_8);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "38b949d36ccf3bbc19ab71f4be2baa44975a4b63da299a5bebda3d5c0d8a0242f579cb3648633c67b75a5877847d10b9891e67612922649cbb8"
                                  "04520f3074dba3c9d4b4b88bbd7547b6b768dc98421f9ac1cd2731fc85e57c58ff52ad56a47e18765b935cd42a13f3818708df654557d07a29d6f0c7a6cda7c532791ee975848c2a3c14ffd61f953";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, DES_CFB_multi) {
    uint64_t outputSize = sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_128, 128, PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, CFB_mode, TEST_STRING_8);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "e24a3239ceda4722a779543cb9f99191b450d44cce1e6797a4235f6522ec40c9b9b24eb5989498d0b6c6e111b8597ca476704c79962b64584ab"
                                  "317e3bd1e7437f4f773cc8ab85a3419aa5028ada1aa76acb76f04e201d2f96068a69c411ef7e6562d2eb5062ff5c6acf2f6835eae0e2883cce4f67eefaf75d9c67da499c390228ad84629afc206f3";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, DES_OFB_multi) {
    uint64_t outputSize = sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_128, 128, PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, OFB_mode, TEST_STRING_8);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "e24a3239ceda4722b6e1b3effe6ef31da710f29ad945f35e3f6519254283e84a7fd3665ef18325ae1159ccc9faedcd8a5e35c187c47b71d8004"
                                  "f4c998c9c70e8111175b30ce288bacc00845602c4634a94bc3a376aad7e07b4643ebd7246ebc2959778bcfa32c1400a5fa5158a921348732e35087fcca1d73f13952678e3b57c341bd41add02e49f";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, DES_CTR_multi) {
    uint64_t outputSize = sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_128, 128, PKCSN7_padding, key, DES_cipher_type, buffer, &outputSize, CTR_mode, TEST_STRING_8);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "e24a3239ceda4722c2b984a4700d821b3867c72f6c5de354aa2cfc1e307ad35d96f1f3cdec821fc7f093a91fb35492d93b37f77d92d895608fb"
                                  "bed968479d4471cd2e5f476f156904c4413786dd397d52cdd43335bbf4aeb1035e8aed5b9b3780cef7428ffbb8b89fbec32de02f9d84d36a59d27c5f6d7e0811153b14d2e0cc98b06a7d49d29c319";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}
