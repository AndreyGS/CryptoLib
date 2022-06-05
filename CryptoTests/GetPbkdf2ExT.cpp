//  GetPbkdf2ExT.cpp
//

#include "pch.h"

#include "common.h"

// Wrong arguments

TEST(GetPbkdf2ExTest, WrongInput) {
    uint16_t outputSize = 20;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2Ex(nullptr, 55, TEST_STRING_8, 8, HMAC_SHA1, 100, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_NULL_INPUT);
    delete[] buffer;
}

TEST(GetPbkdf2ExTest, WrongKey) {
    uint16_t outputSize = 20;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2Ex(TEST_STRING_8, 8, nullptr, 55, HMAC_SHA1, 100, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_NULL_KEY);
    delete[] buffer;
}

TEST(GetPbkdf2ExTest, WrongOuput) {
    uint16_t outputSize = 20;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2Ex(TEST_STRING_8, 8, TEST_STRING_8, 8, HMAC_SHA1, 100, nullptr, outputSize);

    EXPECT_TRUE(status == ERROR_NULL_OUTPUT);
    delete[] buffer;
}

TEST(GetPbkdf2ExTest, UnknownPrfFunc) {
    uint16_t outputSize = 20;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2Ex(TEST_STRING_8, 8, TEST_STRING_8, 8, (PRF)-1, 100, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_UNSUPPORTED_PRF_FUNC);
    delete[] buffer;
}

// Main test

TEST(GetPbkdf2ExTest, PBKDF2_HMAC_SHA_1) {
    void* inputBuffer = new uint8_t[517];
    memcpy(inputBuffer, TEST_STRING_513, 513);
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA1].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2Ex(inputBuffer, 513, TEST_STRING_64, 64, HMAC_SHA1, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "d76b21bc0df8715544623c239ff896d216077158";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}
