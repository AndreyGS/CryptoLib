//  GetPbkdf2T.cpp
//

#include "pch.h"

#include "common.h"

// Wrong arguments

TEST(GetPbkdf2Test, WrongInput) {
    uint16_t outputSize = 20;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(nullptr, 55, TEST_STRING_8, 8, HMAC_SHA1, 100, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT);
    delete[] buffer;
}

TEST(GetPbkdf2Test, WrongKey) {
    uint16_t outputSize = 20;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, nullptr, 55, HMAC_SHA1, 100, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_WRONG_KEY);
    delete[] buffer;
}

TEST(GetPbkdf2Test, WrongOuput) {
    uint16_t outputSize = 20;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_8, 8, HMAC_SHA1, 100, nullptr, outputSize);

    EXPECT_TRUE(status == ERROR_WRONG_OUTPUT);
    delete[] buffer;
}

TEST(GetPbkdf2Test, UnknownPrfFunc) {
    uint16_t outputSize = 20;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_8, 8, (PRF)-1, 100, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_PRF_FUNC_NOT_SUPPORTED);
    delete[] buffer;
}
