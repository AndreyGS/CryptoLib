//  GetHashMultipleT.cpp
//

#include "pch.h"

#include "common.h"

// Wrong arguments

TEST(GetHashMultipleTest, WrongInput_VoidAndSizeNode) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA1].outputSize];
    int status = GetHashMultiple(nullptr, 55, SHA1, buffer);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT);
    delete[] buffer;
}

TEST(GetHashMultipleTest, WrongInput_ListSize) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA1].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_64, 64 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetHashMultiple(chunks, 0, SHA1, buffer);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
    delete[] buffer;
}

TEST(GetHashMultipleTest, WrongInput_VoidInputSize) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA1].outputSize];
    VoidAndSizeNode chunks[2] = { { nullptr, 64 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetHashMultiple(chunks, 2, SHA1, buffer);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT);
    delete[] buffer;
}

TEST(GetHashMultipleTest, WrongOuput) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA1].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_64, 64 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetHashMultiple(chunks, 2, SHA1, nullptr);

    EXPECT_TRUE(status == ERROR_WRONG_OUTPUT);
    delete[] buffer;
}

TEST(GetHashMultipleTest, UnknownHashFunc) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA1].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_64, 64 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetHashMultiple(chunks, 2, (HashFunc)-1, buffer);

    EXPECT_TRUE(status == ERROR_HASHING_FUNC_NOT_SUPPORTED);
    delete[] buffer;
}

// Test wrong input size of not last chunk

TEST(GetHashMultipleTest, Sha_1_wrongInputSize) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA1].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_55, 55 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetHashMultiple(chunks, 2, SHA1, buffer);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
    delete[] buffer;
}

TEST(GetHashMultipleTest, SHA2_32_wrongInputSize) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_224].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_55, 55 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetHashMultiple(chunks, 2, SHA_224, buffer);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
    delete[] buffer;
}

TEST(GetHashMultipleTest, SHA2_64_wrongInputSize) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_384].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_55, 55 }, { (void*)TEST_STRING_111, 111 } };
    int status = GetHashMultiple(chunks, 2, SHA_384, buffer);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
    delete[] buffer;
}

TEST(GetHashMultipleTest, SHA3_wrongInputSize) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA3_224].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_55, 55 }, { (void*)TEST_STRING_111, 111 } };
    int status = GetHashMultiple(chunks, 2, SHA3_224, buffer);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
    delete[] buffer;
}

// Main test

TEST(GetHashMultipleTest, SHA_1) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA1].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_64, 64 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetHashMultiple(chunks, 2, SHA1, buffer);
    std::string result = GetHexResult(buffer, 20);
    std::string expectingResult = "061433b8ff34f9028616130c99cba42710f529a8";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashMultipleTest, SHA_224) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_224].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_64, 64 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetHashMultiple(chunks, 2, SHA_224, buffer);
    std::string result = GetHexResult(buffer, 28);
    std::string expectingResult = "ad0522cffcd01d1af3dfd035dcdef44f0e05acec910bf948309af94c";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashMultipleTest, SHA_256) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_256].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_64, 64 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetHashMultiple(chunks, 2, SHA_256, buffer);
    std::string result = GetHexResult(buffer, 32);
    std::string expectingResult = "479e3620bd7cee2a41709f1631ff70cc6cd13ec278ec99192cc1cbf8d3d49e2b";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashMultipleTest, SHA_384) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_384].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_128, 128 }, { (void*)TEST_STRING_111, 111 } };
    int status = GetHashMultiple(chunks, 2, SHA_384, buffer);
    std::string result = GetHexResult(buffer, 48);
    std::string expectingResult = "63f79027f67be222a55fa9980b831d0adebf40b5835211936b5d09962954e483e38c452fec4ccfe3b275b8204e8e449a";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashMultipleTest, SHA_512_224) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_512_224].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_128, 128 }, { (void*)TEST_STRING_111, 111 } };
    int status = GetHashMultiple(chunks, 2, SHA_512_224, buffer);
    std::string result = GetHexResult(buffer, 28);
    std::string expectingResult = "f07ba5e6ec62363cd2535dd304a373035b348e068c4332bf3e7dcf01";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashMultipleTest, SHA_512_256) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_512_256].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_128, 128 }, { (void*)TEST_STRING_111, 111 } };
    int status = GetHashMultiple(chunks, 2, SHA_512_256, buffer);
    std::string result = GetHexResult(buffer, 32);
    std::string expectingResult = "790b90795677e05ca5f2a62d0b2bbb8be8cda339ec644796c418b951d91946d1";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashMultipleTest, SHA_512) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_512].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_128, 128 }, { (void*)TEST_STRING_111, 111 } };
    int status = GetHashMultiple(chunks, 2, SHA_512, buffer);
    std::string result = GetHexResult(buffer, 64);
    std::string expectingResult = "9e16d74396ac0e7d3f690517d737ce64ef3813c9d8e3f3f3b68641f16b44660315f14e4aab5f5658d072e6eb4e1a41061cf77b2cf5469ffac43cb4c1d08ab3ad";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashMultipleTest, SHA3_224) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA3_224].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_144, 144 }, { (void*)TEST_STRING_111, 111 } };
    int status = GetHashMultiple(chunks, 2, SHA3_224, buffer);
    std::string result = GetHexResult(buffer, 28);
    std::string expectingResult = "f3e8cc1f33be2dd8f22b5ccef55406ffcf1113776749548b2eff5962";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashMultipleTest, SHA3_256) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA3_256].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_136, 136 }, { (void*)TEST_STRING_111, 111 } };
    int status = GetHashMultiple(chunks, 2, SHA3_256, buffer);
    std::string result = GetHexResult(buffer, 32);
    std::string expectingResult = "513e2561cb08b6e4d07ac3a63a4d97448d34b83e4dd421e000d9c940d8747057";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashMultipleTest, SHA3_384) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA3_384].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_104, 104 }, { (void*)TEST_STRING_111, 111 } };
    int status = GetHashMultiple(chunks, 2, SHA3_384, buffer);
    std::string result = GetHexResult(buffer, 48);
    std::string expectingResult = "323aa3b86b3a4a27a0c8ca8b345dcdfcfd13bef29b96fd94769f1fc83882de484f43d85c9b4e90cc4fc57aa7ebe4765f";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashMultipleTest, SHA3_512) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA3_512].outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_72, 72 }, { (void*)TEST_STRING_111, 111 } };
    int status = GetHashMultiple(chunks, 2, SHA3_512, buffer);
    std::string result = GetHexResult(buffer, 64);
    std::string expectingResult = "e24027c2991abc699b491430dfac067bc1a1d4c33cd40016ac461d99a2d9aa552d1396639cff696ec70dde2726f2f19c96c4c5bfc5475ff78be3381674d5d328";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

