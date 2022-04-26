//  GetXofMultipleT.cpp
//

#include "pch.h"

#include "common.h"

// Wrong arguments

TEST(GetXofMultipleTest, WrongInput_VoidAndSizeNode) {
    uint16_t outputSize = 200;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetXofMultiple(nullptr, 1, SHAKE128, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT);
    delete[] buffer;
}

TEST(GetXofMultipleTest, WrongInput_ListSize) {
    uint16_t outputSize = 200;
    uint8_t* buffer = new uint8_t[outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_64, 64 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetXofMultiple(chunks, 0, SHAKE128, chunks, outputSize);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
    delete[] buffer;
}

TEST(GetXofMultipleTest, WrongInput_VoidInputSize) {
    uint16_t outputSize = 200;
    uint8_t* buffer = new uint8_t[outputSize];
    VoidAndSizeNode chunks[2] = { { nullptr, 64 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetXofMultiple(chunks, 2, SHAKE128, chunks, outputSize);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT);
    delete[] buffer;
}

TEST(GetXofMultipleTest, WrongOuput) {
    uint16_t outputSize = 200;
    uint8_t* buffer = new uint8_t[outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_64, 64 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetXofMultiple(chunks, 2, SHAKE128, nullptr, outputSize);

    EXPECT_TRUE(status == ERROR_WRONG_OUTPUT);
    delete[] buffer;
}

TEST(GetXofMultipleTest, WrongOuputSize) {
    uint16_t outputSize = 200;
    uint8_t* buffer = new uint8_t[outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_64, 64 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetXofMultiple(chunks, 2, SHAKE128, chunks, 0);

    EXPECT_TRUE(status == ERROR_WRONG_OUTPUT_SIZE);
    delete[] buffer;
}

TEST(GetXofMultipleTest, UnknownXofFunc) {
    uint16_t outputSize = 200;
    uint8_t* buffer = new uint8_t[outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_64, 64 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetXofMultiple(chunks, 2, (Xof)-1, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_XOF_NOT_SUPPORTED);
    delete[] buffer;
}

// Test wrong input size of not last chunk

TEST(GetXofMultipleTest, SHAKE128_wrongInputSize) {
    uint16_t outputSize = 200;
    uint8_t* buffer = new uint8_t[outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_55, 55 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetXofMultiple(chunks, 2, SHAKE128, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
    delete[] buffer;
}

TEST(GetXofMultipleTest, SHAKE256_wrongInputSize) {
    uint16_t outputSize = 200;
    uint8_t* buffer = new uint8_t[outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_55, 55 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetXofMultiple(chunks, 2, SHAKE256, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
    delete[] buffer;
}

// Main Test

TEST(GetXofMultipleTest, SHAKE128) {
    uint16_t outputSize = 100;
    uint8_t* buffer = new uint8_t[outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_168, 168 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetXofMultiple(chunks, 2, SHAKE128, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "a5956623334d1b81bf60f1df25d2661187208ae5dc485cd558b8412553e2e40f69eed993d759a"
                                  "fde203fa3a6256d5e555e8b43b60264e2a28d3c5aac1a889206f195e3e52ba36962a26ba7b2b24d65b6d731bdc59950be7180ba100e04fd0ef36f141800";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetXofMultipleTest, SHAKE256) {
    uint16_t outputSize = 100;
    uint8_t* buffer = new uint8_t[outputSize];
    VoidAndSizeNode chunks[2] = { { (void*)TEST_STRING_136, 136 }, { (void*)TEST_STRING_55, 55 } };
    int status = GetXofMultiple(chunks, 2, SHAKE256, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "185b1d33faf4f3cf46d474de5f8db1a9892afb14b1c373460e6f4222df3a0d5b3575092297e6e"
                                  "7e18927edba1f6ea558574f52b7be93294a427dbdc8f11952c38054009d4f8d413fde5fe16a443e2d539ac7bb2d309ddb124f14f071a6903a2bb802ba68";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}
