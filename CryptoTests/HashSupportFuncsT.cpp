//  GetHashT.cpp
//

#include "pch.h"

#include "common.h"

// InitHashState Wrong Args

TEST(GetHashTest, InitHashStateWrongHashFunc) {
    StateHandle state;
    EXPECT_TRUE(InitHashState(&state, (HashFunc)-1) == ERROR_UNSUPPORTED_HASHING_FUNC);
}

TEST(GetHashTest, InitHashStateWrongHashFunc2) {
    StateHandle state;
    EXPECT_TRUE(InitHashState(&state, HashFunc_max) == ERROR_UNSUPPORTED_HASHING_FUNC);
}

TEST(GetHashTest, InitHashStateWrongHandle) {
    EXPECT_TRUE(InitHashState(nullptr, SHA1) == ERROR_WRONG_STATE_HANDLE);
}

// ResetHashState Wrong Args

TEST(GetHashTest, ResetHashStateWrongHashFunc) {
    uint8_t state[8] = {};
    *(HashFunc*)state = (HashFunc )-1;
    EXPECT_TRUE(ResetHashState(state) == ERROR_WRONG_STATE_HANDLE);
}

TEST(GetHashTest, ResetHashStateWrongHashFunc2) {
    uint8_t state[8] = {};
    *(HashFunc*)state = HashFunc_max;
    EXPECT_TRUE(ResetHashState(state) == ERROR_WRONG_STATE_HANDLE);
}

TEST(GetHashTest, ResetHashStateWrongHandle) {
    EXPECT_TRUE(ResetHashState(nullptr) == ERROR_WRONG_STATE_HANDLE);
}
