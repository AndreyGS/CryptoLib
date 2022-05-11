//  GetXofT.cpp
//

#include "pch.h"

#include "common.h"

void GetXofMainTestFunc(__in const void* input, __in uint64_t inputSize, __in Xof func, __in uint64_t outputSize, __in int expectedStatus, __in_opt const void* expectedRes)
{
    int status = NO_ERROR;
    uint8_t* buffer = new uint8_t[outputSize];
    StateHandle state = NULL;
    EVAL(InitXofState(func, &state));
    EVAL(GetXof(input, inputSize, buffer, outputSize, true, state));

exit:
    FreeXofState(state);

    if (expectedRes) {
        std::string result = GetHexResult(buffer, outputSize);
        std::string expRes((const char*)expectedRes);
        EXPECT_EQ(result, expRes);
    }

    EXPECT_TRUE(status == expectedStatus);
}

void GetXofMultipleTestFunc(__in const void* input1, __in uint64_t inputSize1, __in const void* input2, __in uint64_t inputSize2, __in Xof func, __in uint64_t outputSize,
    __in int expectedStatus, __in_opt const void* expectedRes)
{
    int status = NO_ERROR;
    uint8_t* buffer = new uint8_t[outputSize];
    StateHandle state = NULL;
    EVAL(InitXofState(func, &state));
    EVAL(GetXof(input1, inputSize1, nullptr, outputSize, false, state));
    EVAL(GetXof(input2, inputSize2, buffer, outputSize, true, state));

exit:
    FreeXofState(state);

    if (expectedRes) {
        std::string result = GetHexResult(buffer, outputSize);
        std::string expRes((const char*)expectedRes);
        EXPECT_EQ(result, expRes);
    }

    EXPECT_TRUE(status == expectedStatus);
}

// Wrong arguments

TEST(GetXofTest, WrongInput) {
    GetXofMainTestFunc(nullptr, 55, SHAKE128, 1, ERROR_WRONG_INPUT, nullptr);
}

TEST(GetXofTest, WrongState) {
    int status = NO_ERROR;
    uint8_t* buffer = new uint8_t[1];
    status = GetXof("", 0, buffer, 1, true, nullptr);
    EXPECT_TRUE(status == ERROR_WRONG_STATE_HANDLE);
}

TEST(GetXofTest, WrongOutput) {
    int status = NO_ERROR;
    uint8_t* state = new uint8_t[1];
    status = GetXof("", 0, nullptr, 1, true, state);
    EXPECT_TRUE(status == ERROR_WRONG_OUTPUT);
}

TEST(GetXofTest, WrongOutputSize) {
    GetXofMainTestFunc(nullptr, 0, SHAKE128, 0, ERROR_WRONG_OUTPUT_SIZE, nullptr);
}

TEST(GetXofTest, WrongInputSize) {
    int status = NO_ERROR;
    StateHandle state = nullptr;

    InitXofState(SHAKE128, &state);
    status = GetXof("", 55, state, 1, false, state);
    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
    FreeXofState(state);

    InitXofState(SHAKE256, &state);
    status = GetXof("", 55, state, 1, false, state);
    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
    FreeXofState(state);
}

// Main test
// 1 - full one block (== input + padding) testing
// 2 - full one block + one byte == two blocks testing
// 3 - two blocks testing
// 4 - empty string testing
// 5 - one byte output
// 6 - multiple test

// SHAKE128

TEST(GetXofTest, SHAKE128_oneblock) {
    GetXofMainTestFunc(TEST_STRING_167, 167, SHAKE128, 200, NO_ERROR, "aee25eaf93c3830774532547d36b4c5328743c7b08785fd391fd419b2001ffdc8811b649cda3102c1846de2eb12b28ce29f5"
                                                                      "b40edfe0b670f637eff6f2cbaf691ebe8dda395185006bb5c7509f909c352fc52abbc4f7c28157da7df7a8bb47ee239e037e"
                                                                      "f8d06a4e5b2a3b1620078a31faf9a2ddb6d182966f8b4cc60cb634a51d253255397258a41611492cbf62863d2adb78914c4a"
                                                                      "60de2e8d7df6a4df8fda8483ad148b6908a855a24efc1ca18bf67d022943ebc6674e128015f3fbec6f092eaaa1518a788824");
}

TEST(GetXofTest, SHAKE128_two_block_edge) {
    GetXofMainTestFunc(TEST_STRING_168, 168, SHAKE128, 200, NO_ERROR, "fdb7712fe2ce5d0e37b2ae0ff1716ef9d6763d045d40be7388aa71e421a70eadd87af7a4166bb1ab07de88b9ca51eb0a0f1a"
                                                                      "18210d2322dfbdd0e3858d9ea045f7097192b63c6e6e99e6176befa0e58c3ec9be50579768d3c3c1b80eee3f5ca541b2c39b"
                                                                      "078ad8f6437cf136d3a23685c3e574240e956f3a0ee3755f48956d13aa366af8438a0410fda6996995bd65af732b6104621f"
                                                                      "f5c7ee57e7b0cef27de6c539125ead6d8b41a0527faaeb8cfcb56d665d4c66ca2714f31ac41c152233c5f0c7ae18105e7d81");
}

TEST(GetXofTest, SHAKE128_two_block) {
    GetXofMainTestFunc(TEST_STRING_169, 169, SHAKE128, 200, NO_ERROR, "01ab6286c733243b0cb9d49a1a1ab4d99dee5dcb6f8362c057912a83df9f58ef28edb5fdb5de0f33140a4751e20712b20266"
                                                                      "853f48a5251c9f0f292214a5b7a4fbe66ca7a62274e47d0652c1ea141dfdecb8d5e80f8504ccd0b60539ad17bbba9123a7dc"
                                                                      "c08470048376d6513f6bd1c58da9e22036b0c474879c1cb6064ae2c932b904c71f9df329865457dabf13dcbe627b7c7ce609"
                                                                      "c29b4081c708557889eec8d1a44a06ff8f8e24fac9bbc4ef41478eaa8b2083b3559310656087b837f50cc651ba759b508b0f");
}

TEST(GetXofTest, SHAKE128_empty) {
    GetXofMainTestFunc(nullptr, 0, SHAKE128, 200, NO_ERROR, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01"
                                                            "fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6df"
                                                            "aac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af0007cd9f5e4c"
                                                            "849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b8d23f877");
}

TEST(GetXofTest, SHAKE128_one_byte) {
    GetXofMainTestFunc(nullptr, 0, SHAKE128, 1, NO_ERROR, "7f");
}

TEST(GetXofTest, SHAKE128_multiple) {
    GetXofMultipleTestFunc(TEST_STRING_168, 168, TEST_STRING_7, 7, SHAKE128, 200, NO_ERROR, "af448d96e205c5b99094e5f7854b0fb69c76963c06e172d1f427ecac7d6eecf612298b8452f801ef2bcde0fab31b6b9e34a0"
                                                                                            "7eaa0bf68d0465e990218b61e39a070c6e645deaf9e79978adac142a1c21e188f8f2f607ff3e842fa1ed0fac455d512059bc"
                                                                                            "f3f06ed5bec77a372550926d4729066cc73d24bba690ae86675a2f0668cdc4b5c17763e5a5aa9c5610928172c919553bb6cf"
                                                                                            "a54565d73afa00c16f905186629a133718649494b0f8a905fa4d376e2be69450d5a32e060e68378f024dbd271801e4606282");
}
/*
TEST(GetXofTest, SHAKE128) {
    uint16_t outputSize = 200;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetXof(TEST_STRING_55, 55, SHAKE128, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "bfa6b9a986cabfe77da1562d817b4a721bb25472d949fe769bb61109fbf29d6b360e91fb1dbe6ab92ea7d086"
                                  "eb10e53ef0953b5419ceb3ed7fea41bf7faa93a740b6873384a87f4077bc9cb701f022bcc11175f573f41a7a"
                                  "23396337c8ab98ca9795b0fdba6607a7156250f5045aa3b14be88a76df94f12c7ba2dea979df733d8b9854c6"
                                  "f4f09f96baddbbc5c8384cd6ebbc68e9680d711392c80ed1663a0ac2844e318e024da55a03066ca05577ac47"
                                  "94e47af9f925614c136d27e6335b06b5db4eaf2eafe75fbc";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetXofTest, SHAKE256) {
    uint16_t outputSize = 200;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetXof(TEST_STRING_55, 55, SHAKE256, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "96d5bede72f6679898adf85167cf3cb6c3619fb4ac8019c56eade1febff3c4cecee04007d825bd90404c69fd"
                                  "4fc09f94dc06c607ab7a5b785a38d195fc0a0fe661e7f7b414daf578183ee9a950f508d5b0ff71214f39334a"
                                  "592c3cfa9500529b5b22ecb7e5a9b3d97d471d9ff4f13ff2d714fe537339b926db281ba5c82a3540e669e637"
                                  "23c6375f2a0660f154a495813a5d36d5991b87af55373b1f1541c5f00644d6b8a5a0220993f54eadc73f8969"
                                  "29c588d11a9e6e7d71da79f78fe803cfc7037203884461cc";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

// Full Single Block test

TEST(GetXofTest, SHAKE128_FullSingleBlock) {
    uint16_t outputSize = 200;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetXof(TEST_STRING_168, 168, SHAKE128, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "fdb7712fe2ce5d0e37b2ae0ff1716ef9d6763d045d40be7388aa71e421a70eadd87af7a4166bb1ab07de88b9"
                                  "ca51eb0a0f1a18210d2322dfbdd0e3858d9ea045f7097192b63c6e6e99e6176befa0e58c3ec9be50579768d3"
                                  "c3c1b80eee3f5ca541b2c39b078ad8f6437cf136d3a23685c3e574240e956f3a0ee3755f48956d13aa366af8"
                                  "438a0410fda6996995bd65af732b6104621ff5c7ee57e7b0cef27de6c539125ead6d8b41a0527faaeb8cfcb5"
                                  "6d665d4c66ca2714f31ac41c152233c5f0c7ae18105e7d81";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetXofTest, SHAKE256_FullSingleBlock) {
    uint16_t outputSize = 200;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetXof(TEST_STRING_136, 136, SHAKE256, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "bbec82ba368fc60f61e9bcbb120f78b2e446fc030f8d5abb1e04badcc945bbbd1d2f28871ab054d0043c0504"
                                  "bc719919a0efaf7e72a18c7f403c6507e6981508e1ea9daf5a1280172db34cd2b18b23372454b46be5c3f2f4"
                                  "4f855b30a60befbc28559aaa2d80a560233f3e5c279304208dd181ba54b5f4678704d42b341b22a868897af3"
                                  "05629327c166be959864fac32cca4118c3ea6053b141cbec7216b55b5d7d6f1e3721d0dad3a90efd87e6d33c"
                                  "bd3051edff1b49b027659d415b5deaf365322450759d483f";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

// Empty input test

TEST(GetXofTest, SHAKE128_empty) {
    uint16_t outputSize = 400;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetXof(nullptr, 0, SHAKE128, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0a"
                                  "eefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d9749188"
                                  "35d25e6a435085b2badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cf"
                                  "ad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419df"
                                  "b927e9df07348b196691abaeb580b32def58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee"
                                  "8cc0d4c922a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c26"
                                  "4029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b1de33fd75081f592305f2e4526edc09631b10958"
                                  "f464d889f31ba010250fda7f1368ec2967fc84ef2ae9aff268e0b1700affc6820b523a3d917135f2dff2ee06"
                                  "bfe72b3124721d4a26c04e53a75e30e73a7a9c4a95d91c55d495e9f51dd0b5e9d83c6d5e8ce803aa62b8d654db53d09b";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetXofTest, SHAKE256_empty) {
    uint16_t outputSize = 400;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetXof(nullptr, 0, SHAKE256, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d"
                                  "67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937b"
                                  "ef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86f3d12210"
                                  "9e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d677231395f6147293b68ceab7a9e0c58d"
                                  "864e8efde4e1b9a46cbe854713672f5caaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8"
                                  "e9eb2ea203bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f5a1aaa96d313eacc"
                                  "890936c173cdcd0fab882c45755feb3aed96d477ff96390bf9a66d1368b208e21f7c10d04a3dbd4e360633e5"
                                  "db4b602601c14cea737db3dcf722632cc77851cbdde2aaf0a33a07b373445df490cc8fc1e4160ff118378f11"
                                  "f0477de055a81a9eda57a4a2cfb0c83929d310912f729ec6cfa36c6ac6a75837143045d791cc85eff5b21932f23861bc";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}
*/