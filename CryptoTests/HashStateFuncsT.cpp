//  HashStateFuncsT.cpp
//

#include "pch.h"

#include "common.h"

// InitHashState

TEST(HashStateFuncsTest, InitHashStateWrongHashFunc) {
    HashHandle handle;
    EXPECT_TRUE(InitHashState(&handle, (HashFunc)-1) == ERROR_UNSUPPORTED_HASHING_FUNC);
}

TEST(HashStateFuncsTest, InitHashStateWrongHashFunc2) {
    HashHandle handle;
    EXPECT_TRUE(InitHashState(&handle, HashFunc_max) == ERROR_UNSUPPORTED_HASHING_FUNC);
}

TEST(HashStateFuncsTest, InitHashStateWrongHandle) {
    EXPECT_TRUE(InitHashState(nullptr, SHA1) == ERROR_NULL_STATE_HANDLE);
}

TEST(HashStateFuncsTest, InitHashStateMain) {
    int status = NO_ERROR;
    HashHandle handle = NULL;
    EXPECT_TRUE(InitHashState(&handle, SHA3_224) == NO_ERROR);

    EXPECT_EQ(*(HashFunc*)handle, SHA3_224);

    {
        std::unique_ptr<uint8_t> test(new uint8_t[g_hashFuncsSizesMapping[SHA3_224].stateSize]);
        memset(test.get(), 0, g_hashFuncsSizesMapping[SHA3_224].stateSize);

        EXPECT_TRUE(memcmp(((HashState*)handle)->state, test.get(), g_hashFuncsSizesMapping[SHA3_224].stateSize) == 0);
    }

    if (handle)
        FreeHashState(handle);
}

// ResetHashState

TEST(HashStateFuncsTest, ResetHashStateWrongHandle) {
    EXPECT_TRUE(ResetHashState(nullptr) == ERROR_NULL_STATE_HANDLE);
}

TEST(HashStateFuncsTest, ResetHashStateMain) {
    int status = NO_ERROR;
    HashHandle handle = NULL;
    bool allOk = false;

    EVAL(InitHashState(&handle, SHA3_224));

    EVAL(ResetHashState(handle));

    EXPECT_EQ(*(HashFunc*)handle, SHA3_224);

    {
        std::unique_ptr<uint8_t> test(new uint8_t[g_hashFuncsSizesMapping[SHA3_224].stateSize]);
        memset(test.get(), 0, g_hashFuncsSizesMapping[SHA3_224].stateSize);

        EXPECT_TRUE(memcmp(((HashState*)handle)->state, test.get(), g_hashFuncsSizesMapping[SHA3_224].stateSize) == 0);
    }

    allOk = true;

exit:
    if (handle)
        FreeHashState(handle);

    EXPECT_TRUE(allOk);
}

// FreeHashState

TEST(HashStateFuncsTest, FreeHashStateWrongHandle) {
    EXPECT_TRUE(FreeHashState(nullptr) == ERROR_NULL_STATE_HANDLE);
}

TEST(HashStateFuncsTest, FreeHashStateMain) {
    int status = NO_ERROR;
    HashHandle handle = NULL;
    bool allOk = false;

    EVAL(InitHashState(&handle, (HashFunc)(HashFunc_max - 1)));

    EVAL(FreeHashState(handle));

    {
        std::unique_ptr<uint8_t> test(new uint8_t[g_hashFuncsSizesMapping[HashFunc_max - 1].stateAndHeaderSize]);
        memset(test.get(), 0, g_hashFuncsSizesMapping[HashFunc_max - 1].stateAndHeaderSize);

        EXPECT_TRUE(memcmp(handle, test.get(), g_hashFuncsSizesMapping[HashFunc_max - 1].stateAndHeaderSize) == 0);
    }

    allOk = true;

exit:
    EXPECT_TRUE(allOk);
}
