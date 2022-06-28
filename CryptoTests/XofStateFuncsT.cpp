// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
//  XofStateFuncsT.cpp
//

#include "pch.h"

#include "common.h"

// InitXofState

TEST(XofStateFuncsTest, InitXofStateWrongXofFunc) {
    XofHandle handle;
    EXPECT_TRUE(InitXofState(&handle, (Xof)-1) == ERROR_UNSUPPORTED_XOF);
}

TEST(XofStateFuncsTest, InitXofStateWrongXofFunc2) {
    XofHandle handle;
    EXPECT_TRUE(InitXofState(&handle, Xof_max) == ERROR_UNSUPPORTED_XOF);
}

TEST(XofStateFuncsTest, InitXofStateWrongHandle) {
    EXPECT_TRUE(InitXofState(nullptr, SHAKE128) == ERROR_NULL_STATE_HANDLE);
}

TEST(XofStateFuncsTest, InitXofStateMain) {
    int status = NO_ERROR;
    XofHandle handle = NULL;
    EXPECT_TRUE(InitXofState(&handle, SHAKE256) == NO_ERROR);

    EXPECT_EQ(*(Xof*)handle, SHAKE256);

    {
        std::unique_ptr<uint8_t[]> test = std::make_unique<uint8_t[]>(g_XofSizesMapping[SHAKE256].stateSize);
        memset(test.get(), 0, g_XofSizesMapping[SHAKE256].stateSize);

        EXPECT_TRUE(memcmp(((HashState*)handle)->state, test.get(), g_XofSizesMapping[SHAKE256].stateSize) == 0);
    }

    if (handle)
        FreeXofState(handle);
}

// ResetXofState

TEST(XofStateFuncsTest, ResetXofStateWrongHandle) {
    EXPECT_TRUE(ResetXofState(nullptr) == ERROR_NULL_STATE_HANDLE);
}

TEST(XofStateFuncsTest, ResetXofStateMain) {
    int status = NO_ERROR;
    XofHandle handle = NULL;
    bool allOk = false;

    EVAL(InitXofState(&handle, SHAKE256));

    EVAL(ResetXofState(handle));

    EXPECT_EQ(*(Xof*)handle, SHAKE256);

    {
        std::unique_ptr<uint8_t[]> test = std::make_unique<uint8_t[]>(g_XofSizesMapping[SHAKE256].stateSize);
        memset(test.get(), 0, g_XofSizesMapping[SHAKE256].stateSize);

        EXPECT_TRUE(memcmp(((HashState*)handle)->state, test.get(), g_XofSizesMapping[SHAKE256].stateSize) == 0);
    }

    allOk = true;

exit:
    if (handle)
        FreeXofState(handle);

    EXPECT_TRUE(allOk);
}

// FreeXofState

TEST(XofStateFuncsTest, FreeXofStateWrongHandle) {
    EXPECT_TRUE(FreeXofState(nullptr) == ERROR_NULL_STATE_HANDLE);
}

// Current test working always well only on release version
TEST(XofStateFuncsTest, FreeXofStateMain) {
    int status = NO_ERROR;
    XofHandle handle = NULL;
    bool allOk = false;

    EVAL(InitXofState(&handle, SHAKE256));

    EVAL(FreeXofState(handle));

    {
        std::unique_ptr<uint8_t[]> test = std::make_unique<uint8_t[]>(g_XofSizesMapping[SHAKE256].stateAndHeaderSize);
        memset(test.get(), 0, g_XofSizesMapping[SHAKE256].stateAndHeaderSize);

        EXPECT_TRUE(memcmp(handle, test.get(), g_XofSizesMapping[SHAKE256].stateAndHeaderSize) == 0);
    }

    allOk = true;

exit:
    EXPECT_TRUE(allOk);
}
