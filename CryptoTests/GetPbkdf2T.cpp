//  GetPbkdf2T.cpp
//

#include "pch.h"

#include "common.h"

// Wrong arguments

TEST(GetPbkdf2Test, WrongInput) {
    uint16_t outputSize = 20;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(nullptr, 55, TEST_STRING_8, 8, HMAC_SHA1, 100, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_NULL_INPUT);
    delete[] buffer;
}

TEST(GetPbkdf2Test, WrongInputSize) {
    uint16_t outputSize = 20;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_513, 513, TEST_STRING_8, 8, HMAC_SHA1, 100, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
    delete[] buffer;
}

TEST(GetPbkdf2Test, WrongKey) {
    uint16_t outputSize = 20;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, nullptr, 55, HMAC_SHA1, 100, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_NULL_KEY);
    delete[] buffer;
}

TEST(GetPbkdf2Test, WrongOuput) {
    uint16_t outputSize = 20;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_8, 8, HMAC_SHA1, 100, nullptr, outputSize);

    EXPECT_TRUE(status == ERROR_NULL_OUTPUT);
    delete[] buffer;
}

TEST(GetPbkdf2Test, UnknownPrfFunc) {
    uint16_t outputSize = 20;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_8, 8, (PRF)-1, 100, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_UNSUPPORTED_PRF_FUNC);
    delete[] buffer;
}

// Single full block

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA_1_sfb) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA1].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA1, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "e76b87bea20f3913fdfaa7785c3693689f68cb9b";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, PBKDF2_HMAC_SHA_224_sfb) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_224].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_224, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "f71cb1b44e3a775d429e9c1463906f2232dfa7fb43f7722356843328";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA_256_sfb) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_256].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_256, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "59439f1e1d55214a06b6a6b3f37f7b5d48ce99c821ed54b62a44ef08b8e1fbe4";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA_384_sfb) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_384].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_384, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "18b4fdd68fe832fa84afcc5cb0e1d6b30f9f576b49ecb80e2e2e0d1bab38e4d42f50ccbf69d71d5a5b0ce2ffe34c0790";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA_512_224_sfb) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_512_224].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_512_224, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "15faefe22b55ce3b421ee182bdc4d7a9cdb8273ae0ff1b0c9c4eb7d9";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA_512_256_sfb) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_512_256].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_512_256, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "f9bd49fd35f50ea413943631ec1f2e6487f8128e828059eb074aaf8931da2c1a";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA_512_sfb) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_512].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_512, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "32298277cbddfe615b8722ac85ca545038fd8c9d93cf465427c9fd1e25ffb1748b6383dc8556a37687dfe8890db68955f6414c2ecb1fe09965b9c23f11346564";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA3_224_sfb) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA3_224].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_224, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "b8bed9ef53b590ffca453ff78083e0c8c3e4d0019ea086b0f0f972d0";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA3_256_sfb) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA3_256].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_256, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "1ec06c9b80df50d54a143d9cf2da622253d010ce2c846cd52c53590711081cc3";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA3_384_sfb) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA3_384].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_384, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "53273994b0b61f2a9c9b11270546091c764d42af3b83165e342990665d89a83f0ffa8a951662194814529d0b32608734";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA3_512_sfb) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA3_512].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_512, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "d4449177e15928a9536631ba457788231f46a0d400efec330536d7cd906215bda9844f857e08b83a293344e348e92a80cb355f3b2672b770c50c652e7a307503";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

// Single full block + 1 byte (must eval to 2 blocks)

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA_1_db) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA1].outputSize + 1;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA1, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "e76b87bea20f3913fdfaa7785c3693689f68cb9bc4";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, PBKDF2_HMAC_SHA_224_db) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_224].outputSize + 1;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_224, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "f71cb1b44e3a775d429e9c1463906f2232dfa7fb43f772235684332840";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA_256_db) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_256].outputSize + 1;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_256, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "59439f1e1d55214a06b6a6b3f37f7b5d48ce99c821ed54b62a44ef08b8e1fbe43d";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA_384_db) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_384].outputSize + 1;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_384, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "18b4fdd68fe832fa84afcc5cb0e1d6b30f9f576b49ecb80e2e2e0d1bab38e4d42f50ccbf69d71d5a5b0ce2ffe34c0790df";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA_512_224_db) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_512_224].outputSize + 1;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_512_224, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "15faefe22b55ce3b421ee182bdc4d7a9cdb8273ae0ff1b0c9c4eb7d906";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA_512_256_db) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_512_256].outputSize + 1;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_512_256, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "f9bd49fd35f50ea413943631ec1f2e6487f8128e828059eb074aaf8931da2c1a08";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA_512_db) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_512].outputSize + 1;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_512, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "32298277cbddfe615b8722ac85ca545038fd8c9d93cf465427c9fd1e25ffb1748b6383dc8556a37687dfe8890db68955f6414c2ecb1fe09965b9c23f113465649f";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA3_224_db) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA3_224].outputSize + 1;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_224, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "b8bed9ef53b590ffca453ff78083e0c8c3e4d0019ea086b0f0f972d048";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA3_256_db) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA3_256].outputSize + 1;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_256, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "1ec06c9b80df50d54a143d9cf2da622253d010ce2c846cd52c53590711081cc326";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA3_384_db) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA3_384].outputSize + 1;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_384, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "53273994b0b61f2a9c9b11270546091c764d42af3b83165e342990665d89a83f0ffa8a951662194814529d0b326087346b";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPbkdf2Test, PBKDF2_HMAC_SHA3_512_db) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA3_512].outputSize + 1;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_512, 1000, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "d4449177e15928a9536631ba457788231f46a0d400efec330536d7cd906215bda9844f857e08b83a293344e348e92a80cb355f3b2672b770c50c652e7a30750324";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}
