// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
//  PrfStateFuncsT.cpp
//

#include "pch.h"

#include "common.h"

// InitPrfState

TEST(PrfStateFuncsTest, InitPrfStateWrongPrfFunc) {
    PrfHandle handle;
    EXPECT_TRUE(InitPrfState(&handle, (Prf)-1, nullptr) == ERROR_UNSUPPORTED_PRF_FUNC);
}

TEST(PrfStateFuncsTest, InitPrfStateWrongPrfFunc2) {
    PrfHandle handle;
    EXPECT_TRUE(InitPrfState(&handle, Prf_max, nullptr) == ERROR_UNSUPPORTED_PRF_FUNC);
}

TEST(PrfStateFuncsTest, InitPrfStateWrongHandle) {
    EXPECT_TRUE(InitPrfState(nullptr, HMAC_SHA3_224, nullptr) == ERROR_NULL_STATE_HANDLE);
}

TEST(PrfStateFuncsTest, InitPrfStateMain) {
    int status = NO_ERROR;
    PrfHandle handle = NULL;
    EXPECT_TRUE(InitPrfState(&handle, HMAC_SHA3_224, nullptr) == NO_ERROR);

    EXPECT_EQ(*(Prf*)handle, HMAC_SHA3_224);

    {
        std::vector<uint8_t> test(g_hashFuncsSizesMapping[HMAC_SHA3_224].stateSize, 0);
        EXPECT_TRUE(memcmp(((PrfState*)handle)->state, test.data(), g_hashFuncsSizesMapping[HMAC_SHA3_224].stateSize) == 0);
    }

    if (handle)
        FreePrfState(handle);
}

// ResetPrfState

TEST(PrfStateFuncsTest, ResetPrfStateWrongHandle) {
    EXPECT_TRUE(ResetPrfState(nullptr) == ERROR_NULL_STATE_HANDLE);
}

TEST(PrfStateFuncsTest, ResetPrfStateMain) {
    int status = NO_ERROR;
    PrfHandle handle = NULL;
    bool allOk = false;

    EVAL(InitPrfState(&handle, HMAC_SHA3_224, nullptr));

    EVAL(ResetPrfState(handle));

    EXPECT_EQ(*(HashFunc*)handle, HMAC_SHA3_224);

    {
        std::vector<uint8_t> test(g_hashFuncsSizesMapping[HMAC_SHA3_224].stateSize, 0);
        EXPECT_TRUE(memcmp(((HashState*)handle)->state, test.data(), g_hashFuncsSizesMapping[HMAC_SHA3_224].stateSize) == 0);
    }

    allOk = true;

exit:
    if (handle)
        FreePrfState(handle);

    EXPECT_TRUE(allOk);
}

// FreePrfState

TEST(PrfStateFuncsTest, FreePrfStateWrongHandle) {
    EXPECT_TRUE(FreePrfState(nullptr) == ERROR_NULL_STATE_HANDLE);
}

// Current test working always well only on release version
TEST(PrfStateFuncsTest, FreePrfStateMain) {
    int status = NO_ERROR;
    PrfHandle handle = NULL;
    bool allOk = false;

    EVAL(InitPrfState(&handle, (Prf)(Prf_max - 1), nullptr));

    EVAL(FreePrfState(handle));

    {
        std::vector<uint8_t> test_1(g_hashFuncsSizesMapping[Prf_max - 1].stateAndHeaderSize, 0);
        std::vector<uint8_t> test_2(g_hashFuncsSizesMapping[Prf_max - 1].stateAndHeaderSize, 0xdd);

        EXPECT_TRUE(memcmp(handle, test_1.data(), g_hashFuncsSizesMapping[Prf_max - 1].stateAndHeaderSize) == 0 || memcmp(handle, test_2.data(), g_hashFuncsSizesMapping[Prf_max - 1].stateAndHeaderSize) == 0);
    }

    allOk = true;

exit:
    EXPECT_TRUE(allOk);
}

