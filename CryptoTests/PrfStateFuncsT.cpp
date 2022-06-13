//  PrfStateFuncsT.cpp
//

#include "pch.h"

#include "common.h"

// InitPrfState

TEST(PrfStateFuncsTest, InitPrfStateWrongPrfFunc) {
    PrfHandle handle;
    EXPECT_TRUE(InitPrfState(&handle, (Prf)-1) == ERROR_UNSUPPORTED_PRF_FUNC);
}

TEST(PrfStateFuncsTest, InitPrfStateWrongPrfFunc2) {
    PrfHandle handle;
    EXPECT_TRUE(InitPrfState(&handle, Prf_max) == ERROR_UNSUPPORTED_PRF_FUNC);
}

TEST(PrfStateFuncsTest, InitPrfStateWrongHandle) {
    EXPECT_TRUE(InitPrfState(nullptr, HMAC_SHA3_224) == ERROR_NULL_STATE_HANDLE);
}

TEST(PrfStateFuncsTest, InitPrfStateMain) {
    int status = NO_ERROR;
    PrfHandle handle = NULL;
    EXPECT_TRUE(InitPrfState(&handle, HMAC_SHA3_224) == NO_ERROR);

    EXPECT_EQ(*(Prf*)handle, HMAC_SHA3_224);

    {
        std::unique_ptr<uint8_t> test(new uint8_t[g_hashFuncsSizesMapping[HMAC_SHA3_224].stateSize]);
        memset(test.get(), 0, g_hashFuncsSizesMapping[HMAC_SHA3_224].stateSize);

        EXPECT_TRUE(memcmp(((PrfState*)handle)->state, test.get(), g_hashFuncsSizesMapping[HMAC_SHA3_224].stateSize) == 0);
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

    EVAL(InitPrfState(&handle, HMAC_SHA3_224));

    EVAL(ResetPrfState(handle));

    EXPECT_EQ(*(HashFunc*)handle, HMAC_SHA3_224);

    {
        std::unique_ptr<uint8_t> test(new uint8_t[g_hashFuncsSizesMapping[HMAC_SHA3_224].stateSize]);
        memset(test.get(), 0, g_hashFuncsSizesMapping[HMAC_SHA3_224].stateSize);

        EXPECT_TRUE(memcmp(((HashState*)handle)->state, test.get(), g_hashFuncsSizesMapping[HMAC_SHA3_224].stateSize) == 0);
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

TEST(PrfStateFuncsTest, FreePrfStateMain) {
    int status = NO_ERROR;
    PrfHandle handle = NULL;
    bool allOk = false;

    EVAL(InitPrfState(&handle, (Prf)(Prf_max - 1)));

    EVAL(FreePrfState(handle));

    {
        std::unique_ptr<uint8_t> test(new uint8_t[g_hashFuncsSizesMapping[Prf_max - 1].stateAndHeaderSize]);
        memset(test.get(), 0, g_hashFuncsSizesMapping[Prf_max - 1].stateAndHeaderSize);

        EXPECT_TRUE(memcmp(handle, test.get(), g_hashFuncsSizesMapping[Prf_max - 1].stateAndHeaderSize) == 0);
    }

    allOk = true;

exit:
    EXPECT_TRUE(allOk);
}

