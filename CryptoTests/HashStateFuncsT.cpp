//  GetHashT.cpp
//

#include "pch.h"

#include "common.h"

// InitHashState Wrong Args

TEST(HashStateFuncsTest, InitHashStateWrongHashFunc) {
    StateHandle state;
    EXPECT_TRUE(InitHashState(&state, (HashFunc)-1) == ERROR_UNSUPPORTED_HASHING_FUNC);
}

TEST(HashStateFuncsTest, InitHashStateWrongHashFunc2) {
    StateHandle state;
    EXPECT_TRUE(InitHashState(&state, HashFunc_max) == ERROR_UNSUPPORTED_HASHING_FUNC);
}

TEST(HashStateFuncsTest, InitHashStateWrongHandle) {
    EXPECT_TRUE(InitHashState(nullptr, SHA1) == ERROR_NULL_STATE_HANDLE);
}

// ResetHashState Wrong Args

TEST(HashStateFuncsTest, ResetHashStateWrongHandle) {
    EXPECT_TRUE(ResetHashState(nullptr) == ERROR_NULL_STATE_HANDLE);
}
