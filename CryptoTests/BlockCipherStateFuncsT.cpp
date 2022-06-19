//  BlockCipherStateFuncsT.cpp
//

#include "pch.h"

#include "ProcessingByBlockCipherTestSupportFunctions.h"

// InitBlockCipherState

TEST(BlockCipherStateFuncsTest, NullStateInit) {
    int status = NO_ERROR;
    int8_t key[] = "81cav5AS";

    EVAL(InitBlockCipherState(nullptr, DES_cipher_type, (CryptoMode)-1, ECB_mode, PKCSN7_padding, key, nullptr));

exit:
    EXPECT_TRUE(status == ERROR_NULL_STATE_HANDLE);
}

TEST(BlockCipherStateFuncsTest, UnsupportedCipherFunc) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_8, 8, PKCSN7_padding, "81cav5AS", (BlockCipherType)-1, sizeof(TEST_STRING_8), ECB_mode, nullptr
        , ERROR_UNSUPPORTED_CIPHER_FUNC, nullptr, 0, Decryption_mode);
}

TEST(BlockCipherStateFuncsTest, UnsupportedEncryptionMode) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_8, 8, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_8), ECB_mode, nullptr
        , ERROR_UNSUPPROTED_ENCRYPTION_MODE, nullptr, 0, (CryptoMode)-1);
}

TEST(BlockCipherStateFuncsTest, UnsupportedOpMode) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_8, 8, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_8), (BlockCipherOpMode)-1, nullptr
        , ERROR_UNSUPPROTED_OPERATION_MODE, nullptr, 0, Decryption_mode);
}

TEST(BlockCipherStateFuncsTest, UnsupportedPadding) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_8, 8, (PaddingType)-1, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_8), ECB_mode, nullptr
        , ERROR_UNSUPPORTED_PADDING_TYPE, nullptr, 0, Decryption_mode);
}

TEST(BlockCipherStateFuncsTest, NullKey) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_8, 8, PKCSN7_padding, nullptr, DES_cipher_type, sizeof(TEST_STRING_8), ECB_mode, nullptr
        , ERROR_NULL_KEY, nullptr, 0, Decryption_mode);
}

TEST(BlockCipherStateFuncsTest, NullIV) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_8, 8, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_8), CBC_mode, nullptr
        , ERROR_NULL_INIT_VECTOR, nullptr, 0, Decryption_mode);
}

TEST(BlockCipherStateFuncsTest, InitBlockCipherStateMain) {
    int status = NO_ERROR;
    int8_t key[] = "81cav5AS";
    BlockCipherHandle handle = nullptr;
    BlockCipherState* state = nullptr;
    uint64_t desIv = 0x0123456789abcdef;

    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Encryption_mode, CBC_mode, No_padding, key, &desIv));
    state = (BlockCipherState*)handle;

    EXPECT_TRUE(state->cipher == DES_cipher_type && state->enMode == Encryption_mode && state->opMode == CBC_mode && state->padding == No_padding && ((DesState*)state->state)->iv == desIv);

    FreeBlockCipherState(handle);

    EVAL(InitBlockCipherState(&handle, (BlockCipherType)(BlockCipherType_max - 1), (CryptoMode)(CryptoMode_max - 1), ECB_mode, (PaddingType)(PaddingType_max - 1), key, nullptr));
    state = (BlockCipherState*)handle;

    EXPECT_TRUE(state->cipher == (BlockCipherType)(BlockCipherType_max - 1) && state->enMode == (CryptoMode)(CryptoMode_max - 1) 
        && state->opMode == ECB_mode && state->padding == (PaddingType)(PaddingType_max - 1));
exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == NO_ERROR);
}

// ReInitBlockCipherCryptoMode

TEST(BlockCipherStateFuncsTest, NullStateReInitCryptoMode) {
    int status = NO_ERROR;
    EVAL(ReInitBlockCipherCryptoMode(nullptr, Encryption_mode));

exit:
    EXPECT_TRUE(status == ERROR_NULL_STATE_HANDLE);
}

TEST(BlockCipherStateFuncsTest, UnsupportedEnModeReInit) {
    int status = NO_ERROR;
    int8_t key[] = "81cav5AS";
    BlockCipherHandle handle = nullptr;
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, ECB_mode, PKCSN7_padding, key, nullptr));
    EVAL(ReInitBlockCipherCryptoMode(handle, (CryptoMode)-1));

exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == ERROR_UNSUPPROTED_ENCRYPTION_MODE);
}

TEST(BlockCipherStateFuncsTest, ReInitBlockCipherCryptoModeMain) {
    int status = NO_ERROR;
    int8_t key[] = "81cav5AS";
    BlockCipherHandle handle = nullptr;
    BlockCipherState* state = nullptr;
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, ECB_mode, PKCSN7_padding, key, nullptr));
    state = (BlockCipherState*)handle;

    EXPECT_EQ(state->enMode, Decryption_mode);

    EVAL(ReInitBlockCipherCryptoMode(handle, Encryption_mode));

    EXPECT_EQ(state->enMode, Encryption_mode);

exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == NO_ERROR);
}

// ReInitBlockCipherOpMode

TEST(BlockCipherStateFuncsTest, NullStateReInitOpMode) {
    int status = NO_ERROR;
    EVAL(ReInitBlockCipherOpMode(nullptr, ECB_mode));

exit:
    EXPECT_TRUE(status == ERROR_NULL_STATE_HANDLE);
}

TEST(BlockCipherStateFuncsTest, UnsupportedOpModeReInit) {
    int status = NO_ERROR;
    int8_t key[] = "81cav5AS";
    BlockCipherHandle handle = nullptr;
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, ECB_mode, PKCSN7_padding, key, nullptr));
    EVAL(ReInitBlockCipherOpMode(handle, (BlockCipherOpMode)-1));

exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == ERROR_UNSUPPROTED_OPERATION_MODE);
}

TEST(BlockCipherStateFuncsTest, ReInitBlockCipherOpModeMain) {
    int status = NO_ERROR;
    int8_t key[] = "81cav5AS";
    BlockCipherHandle handle = nullptr;
    BlockCipherState* state = nullptr;
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, ECB_mode, PKCSN7_padding, key, nullptr));
    state = (BlockCipherState*)handle;

    EXPECT_EQ(state->opMode, ECB_mode);

    EVAL(ReInitBlockCipherOpMode(handle, CTR_mode));

    EXPECT_EQ(state->opMode, CTR_mode);

exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == NO_ERROR);
}

// ReInitBlockCipherPaddingType

TEST(BlockCipherStateFuncsTest, NullStateReInitPadding) {
    int status = NO_ERROR;
    EVAL(ReInitBlockCipherPaddingType(nullptr, No_padding));

exit:

    EXPECT_TRUE(status == ERROR_NULL_STATE_HANDLE);
}

TEST(BlockCipherStateFuncsTest, UnsupportedPaddingReInit) {
    int status = NO_ERROR;
    int8_t key[] = "81cav5AS";
    BlockCipherHandle handle = nullptr;
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, ECB_mode, PKCSN7_padding, key, nullptr));
    EVAL(ReInitBlockCipherPaddingType(handle, (PaddingType)-1));

exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == ERROR_UNSUPPORTED_PADDING_TYPE);
}

TEST(BlockCipherStateFuncsTest, ReInitBlockCipherPaddingTypeMain) {
    int status = NO_ERROR;
    int8_t key[] = "81cav5AS";
    BlockCipherHandle handle = nullptr;
    BlockCipherState* state = nullptr;
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, ECB_mode, No_padding, key, nullptr));
    state = (BlockCipherState*)handle;

    EXPECT_EQ(state->padding, No_padding);

    EVAL(ReInitBlockCipherPaddingType(handle, PKCSN7_padding));

    EXPECT_EQ(state->padding, PKCSN7_padding);

exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == NO_ERROR);
}

// ReInitBlockCipherIv

TEST(BlockCipherStateFuncsTest, NullStateReInitIv) {
    int status = NO_ERROR;
    uint64_t iv = 0;
    EVAL(ReInitBlockCipherIv(nullptr, &iv));

exit:
    EXPECT_TRUE(status == ERROR_NULL_STATE_HANDLE);
}

TEST(BlockCipherStateFuncsTest, NullIvReInit) {
    int status = NO_ERROR;
    int8_t key[] = "81cav5AS";
    BlockCipherHandle handle = nullptr;
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, ECB_mode, PKCSN7_padding, key, nullptr));
    EVAL(ReInitBlockCipherIv(handle, nullptr));

exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == ERROR_NULL_INIT_VECTOR);
}

TEST(BlockCipherStateFuncsTest, ReInitBlockCipherIvMain) {
    int status = NO_ERROR;
    int8_t key[] = "81cav5AS";
    BlockCipherHandle handle = nullptr;
    BlockCipherState* state = nullptr;
    uint64_t iv = 0, ivCopy = iv;

    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Decryption_mode, CBC_mode, No_padding, key, &iv));
    state = (BlockCipherState*)handle;

    EXPECT_EQ(((DesState*)state->state)->iv, ivCopy);

    ivCopy = iv = 0x0123456789abcdef;

    EVAL(ReInitBlockCipherIv(handle, &iv));

    EXPECT_EQ(((DesState*)state->state)->iv, ivCopy);

exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == NO_ERROR);
}

// FreeBlockCipherState

TEST(BlockCipherStateFuncsTest, NullStateFreeState) {
    int status = NO_ERROR;
    EVAL(FreeBlockCipherState(nullptr));

exit:
    EXPECT_TRUE(status == ERROR_NULL_STATE_HANDLE);
}

// Current test working always well only on release version
TEST(BlockCipherStateFuncsTest, FreeBlockCipherStateMain) {
    int status = NO_ERROR;
    int8_t key[] = "81cav5AS";
    BlockCipherHandle handle = nullptr;
    BlockCipherState* state = nullptr;
    void* specificCipherState = nullptr;
    uint64_t iv = 0, ivCopy = iv;
    bool allOk = false;

    EVAL(InitBlockCipherState(&handle, (BlockCipherType)0, Decryption_mode, CBC_mode, No_padding, key, &iv));
    state = (BlockCipherState*)handle;
    specificCipherState = ((BlockCipherState*)handle)->state;

    EVAL(FreeBlockCipherState(handle));
    
    {
        std::unique_ptr<uint8_t> test(new uint8_t[sizeof(DesState)]);
        memset(test.get(), 0, sizeof(DesState));

        EXPECT_TRUE(memcmp(specificCipherState, test.get(), sizeof(DesState)) == 0);
    }

    {
        std::unique_ptr<BlockCipherState> test(new BlockCipherState);
        memset(test.get(), 0, sizeof(BlockCipherState));

        EXPECT_TRUE(memcmp(state, test.get(), sizeof(BlockCipherState)) == 0);
    }

    allOk = true;

exit:
    EXPECT_TRUE(allOk);
}
