// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
//  HashStateFuncsT.cpp
//

#include "pch.h"

#include "common.h"

// InitHashState

TEST(HashStateFuncsTest, InitHashStateWrongHashFunc) {
    HashHandle handle;
    EXPECT_TRUE(InitHashState(&handle, (HashFunc)-1, nullptr) == ERROR_UNSUPPORTED_HASHING_FUNC);
}

TEST(HashStateFuncsTest, InitHashStateWrongHashFunc2) {
    HashHandle handle;
    EXPECT_TRUE(InitHashState(&handle, HashFunc_max, nullptr) == ERROR_UNSUPPORTED_HASHING_FUNC);
}

TEST(HashStateFuncsTest, InitHashStateWrongHandle) {
    EXPECT_TRUE(InitHashState(nullptr, SHA1, nullptr) == ERROR_NULL_STATE_HANDLE);
}

TEST(HashStateFuncsTest, InitHashStateMain) {
    int status = NO_ERROR;
    HashHandle handle = NULL;
    EXPECT_TRUE(InitHashState(&handle, SHA3_224, nullptr) == NO_ERROR);

    EXPECT_EQ(*(HashFunc*)handle, SHA3_224);

    {
        std::vector<uint8_t> test(g_hashFuncsSizesMapping[SHA3_224].stateSize, 0);
        EXPECT_TRUE(memcmp(((HashState*)handle)->state, test.data(), g_hashFuncsSizesMapping[SHA3_224].stateSize) == 0);
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

    EVAL(InitHashState(&handle, SHA3_224, nullptr));

    EVAL(ResetHashState(handle));

    EXPECT_EQ(*(HashFunc*)handle, SHA3_224);

    {
        std::vector<uint8_t> test(g_hashFuncsSizesMapping[SHA3_224].stateSize, 0);
        EXPECT_TRUE(memcmp(((HashState*)handle)->state, test.data(), g_hashFuncsSizesMapping[SHA3_224].stateSize) == 0);
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

// Current test working always well only on release version
TEST(HashStateFuncsTest, FreeHashStateMain) {
    int status = NO_ERROR;
    HashHandle handle = NULL;
    bool allOk = false;

    EVAL(InitHashState(&handle, SHA_512, nullptr));
    EVAL(GetHash(handle, "aee25eaf93c3830774532547d36b4c5328743c7b08785fd391fd419b2001ffdc8811b649cda3102c1846de2eb12b28ce29f5"
        "b40edfe0b670f637eff6f2cbaf69", 128, false, nullptr));

    EVAL(FreeHashState(handle));

    {
        std::vector<uint8_t> test(g_hashFuncsSizesMapping[SHA_512].stateAndHeaderSize, 0);
        // here we adding offset of 8 bytes, cause compiler in release version fills that bytes by some other info after freeing
        EXPECT_TRUE(memcmp((uint8_t*)handle + 8, test.data(), g_hashFuncsSizesMapping[SHA_512].stateAndHeaderSize - 8) == 0);
    }

    allOk = true;

exit:
    EXPECT_TRUE(allOk);
}
