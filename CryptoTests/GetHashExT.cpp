//  GetHashExT.cpp
//

#include "pch.h"

#include "common.h"

// Main test

TEST(GetHashExTest, SHA_1) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMapping[SHA1].outputSize];
    int status = GetHashEx(TEST_STRING_55, 55, 0, SHA1, buffer);
    std::string result = GetHexResult(buffer, 20);
    std::string expectingResult = "788283554b3e5624465bea7faccbd35e4fa5e69a";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}
