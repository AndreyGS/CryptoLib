// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
//  AddPaddingT.cpp
//

#include "pch.h"
#include "crypto_internal.h"

// Wrong arguments

TEST(AddPaddingTest, NullInput) {
    int status = NO_ERROR;
    size_t outputSize = 16;
    std::vector<uint8_t> output(outputSize);
    EVAL(AddPadding(nullptr, 1, No_padding, 8, output.data(), &outputSize, false));

exit:
    EXPECT_TRUE(status == ERROR_NULL_INPUT);
}

TEST(AddPaddingTest, NullWrongInputSize) {
    int status = NO_ERROR;
    size_t outputSize = 16;
    std::vector<uint8_t> input(outputSize);
    std::vector<uint8_t> output(outputSize);

    EVAL(AddPadding(input.data(), 0, No_padding, 8, output.data(), &outputSize, false));

exit:
    EXPECT_TRUE(status == ERROR_TOO_SMALL_INPUT_SIZE);
}

TEST(AddPaddingTest, NullOutput) {
    int status = NO_ERROR;
    size_t outputSize = 16;
    std::vector<uint8_t> input(outputSize);

    EVAL(AddPadding(input.data(), outputSize, No_padding, 8, nullptr, &outputSize, false));

exit:
    EXPECT_TRUE(status == ERROR_NULL_OUTPUT);
}

TEST(AddPaddingTest, NullOutputSize) {
    int status = NO_ERROR;
    size_t outputSize = 16;
    std::vector<uint8_t> input(outputSize);
    std::vector<uint8_t> output(outputSize);

    EVAL(AddPadding(input.data(), outputSize, No_padding, 8, output.data(), nullptr, false));

exit:
    EXPECT_TRUE(status == ERROR_NULL_OUTPUT_SIZE);
}

TEST(AddPaddingTest, TooSmallBlockSize) {
    int status = NO_ERROR;
    size_t outputSize = 16;
    std::vector<uint8_t> input(outputSize);
    std::vector<uint8_t> output(outputSize);

    EVAL(AddPadding(input.data(), outputSize, No_padding, 0, output.data(), &outputSize, false));

exit:
    EXPECT_TRUE(status == ERROR_TOO_SMALL_BLOCK_SIZE);
}

TEST(AddPaddingTest, TooBigBlockSize) {
    int status = NO_ERROR;
    size_t outputSize = 16;
    std::vector<uint8_t> input(outputSize);
    std::vector<uint8_t> output(outputSize);

    EVAL(AddPadding(input.data(), 7, PKCSN7_padding, 256, output.data(), &outputSize, false));

exit:
    EXPECT_TRUE(status == ERROR_TOO_BIG_BLOCK_SIZE);
}

// Main test

TEST(AddPaddingTest, MainTest) {
    int status = NO_ERROR;
    unsigned char input_1[] = "abcdefg";
    unsigned char input_2[] = "abcdefgh";
    std::vector<uint8_t> result(16, -1);
    size_t blockSize = 8;
    size_t outputSize = blockSize << 1;
    std::vector<uint8_t> output(outputSize, -1);

    // For every padding type except No_padding there is 4 main test
    // 1. inputSize == blockSize - 1 && fillLastBlock == false
    // 2. inputSize == blockSize - 1 && fillLastBlock == true
    // 3. inputSize == blockSize     && fillLastBlock == false
    // 4. inputSize == blockSize     && fillLastBlock == true
    PaddingType type = No_padding;
    // No padding

    status = AddPadding(input_1, 7, type, blockSize, output.data(), &outputSize, false);
    EXPECT_TRUE(memcmp(result.data(), output.data(), blockSize) == 0 && outputSize == 16 && status == ERROR_INAPPLICABLE_PADDING_TYPE);

    status = AddPadding(input_1, 7, type, blockSize, output.data(), &outputSize, true);
    EXPECT_TRUE(memcmp(result.data(), output.data(), blockSize) == 0 && outputSize == 16 && status == ERROR_INAPPLICABLE_PADDING_TYPE);

    EVAL(AddPadding(input_2, 8, type, blockSize, output.data(), &outputSize, false));
    EXPECT_TRUE(memcmp(result.data(), output.data(), blockSize) == 0 && outputSize == 8);

    outputSize = blockSize << 1;
    EVAL(AddPadding(input_2, 8, type, blockSize, output.data(), &outputSize, true));
    result.assign(input_2, input_2 + 8);
    EXPECT_TRUE(memcmp(result.data(), output.data(), outputSize) == 0 && outputSize == 8);


    // Zero padding
    type = Zero_padding;
    output.assign(outputSize, 0xff);
    EVAL(AddPadding(input_1, 7, type, blockSize, output.data(), &outputSize, false));
    result.assign(7, 0xff);
    result.push_back('\0');
    EXPECT_TRUE(memcmp(result.data(), output.data(), blockSize) == 0 && outputSize == 8);

    output.assign(outputSize, 0xff);
    outputSize = blockSize << 1;
    EVAL(AddPadding(input_1, 7, type, blockSize, output.data(), &outputSize, true));
    result.assign(input_1, input_1 + 7);
    result.push_back('\0');
    EXPECT_TRUE(memcmp(result.data(), output.data(), blockSize) == 0 && outputSize == 8);

    output.assign(outputSize, 0xff);
    outputSize = blockSize << 1;
    EVAL(AddPadding(input_2, 8, type, blockSize, output.data(), &outputSize, false));
    result.assign(8, 0xff);
    for (int i = 0; i < 8; ++i) result.push_back('\0');
    EXPECT_TRUE(memcmp(result.data(), output.data(), outputSize) == 0 && outputSize == 16);

    EVAL(AddPadding(input_2, 8, type, blockSize, output.data(), &outputSize, true));
    EXPECT_TRUE(memcmp(result.data(), output.data(), blockSize) == 0 && outputSize == 16);

    // PKCSN7_padding

    type = PKCSN7_padding;
    output.assign(outputSize, 0xff);
    EVAL(AddPadding(input_1, 7, type, blockSize, output.data(), &outputSize, false));
    result.assign(7, 0xff);
    result.push_back('\001');
    EXPECT_TRUE(memcmp(result.data(), output.data(), blockSize) == 0 && outputSize == 8);

    output.assign(outputSize, 0xff);
    outputSize = blockSize << 1;
    EVAL(AddPadding(input_1, 7, type, blockSize, output.data(), &outputSize, true));
    result.assign(input_1, input_1 + 7);
    result.push_back('\001');
    EXPECT_TRUE(memcmp(result.data(), output.data(), blockSize) == 0 && outputSize == 8);

    output.assign(outputSize, 0xff);
    outputSize = blockSize << 1;
    EVAL(AddPadding(input_2, 8, type, blockSize, output.data(), &outputSize, false));
    result.assign(8, 0xff);
    for (int i = 0; i < 8; ++i) result.push_back(0x08);
    EXPECT_TRUE(memcmp(result.data(), output.data(), outputSize) == 0 && outputSize == 16);

    EVAL(AddPadding(input_2, 8, type, blockSize, output.data(), &outputSize, true));
    EXPECT_TRUE(memcmp(result.data(), output.data(), blockSize) == 0 && outputSize == 16);

    // Two extra PKCSN7 tests
    outputSize = blockSize << 1;
    status = AddPadding(input_2, 8, type, 256, output.data(), &outputSize, false);
    output.assign(outputSize, 0xff);
    result.assign(outputSize, 0xff);
    EXPECT_TRUE(memcmp(result.data(), output.data(), outputSize) == 0 && outputSize == 16 && status == ERROR_TOO_BIG_BLOCK_SIZE);
    status = AddPadding(input_2, 8, type, 256, output.data(), &outputSize, true);
    EXPECT_TRUE(memcmp(result.data(), output.data(), outputSize) == 0 && outputSize == 16 && status == ERROR_TOO_BIG_BLOCK_SIZE);
    status = NO_ERROR;

    // ISO_7816_padding

    type = ISO_7816_padding;
    output.assign(outputSize, 0xff);
    EVAL(AddPadding(input_1, 7, type, blockSize, output.data(), &outputSize, false));
    result.assign(7, 0xff);
    result.push_back(0x80);
    EXPECT_TRUE(memcmp(result.data(), output.data(), blockSize) == 0 && outputSize == 8);

    output.assign(outputSize, 0xff);
    outputSize = blockSize << 1;
    EVAL(AddPadding(input_1, 7, type, blockSize, output.data(), &outputSize, true));
    result.assign(input_1, input_1 + 7);
    result.push_back(0x80);
    EXPECT_TRUE(memcmp(result.data(), output.data(), blockSize) == 0 && outputSize == 8);

    output.assign(outputSize, 0xff);
    outputSize = blockSize << 1;
    EVAL(AddPadding(input_2, 8, type, blockSize, output.data(), &outputSize, false));
    result.assign(8, 0xff);
    result.push_back(0x80);
    for (int i = 0; i < 7; ++i) result.push_back('\0');
    EXPECT_TRUE(memcmp(result.data(), output.data(), outputSize) == 0 && outputSize == 16);

    EVAL(AddPadding(input_2, 8, type, blockSize, output.data(), &outputSize, true));
    EXPECT_TRUE(memcmp(result.data(), output.data(), blockSize) == 0 && outputSize == 16);

exit:
    EXPECT_TRUE(status == NO_ERROR);
}
