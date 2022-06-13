//  GetXofT.cpp
//

#include "pch.h"

#include "common.h"

void GetXofMainTestFunc(__in const void* input, __in uint64_t inputSize, __in Xof func, __in uint64_t outputSize, __in int expectedStatus, __in_opt const void* expectedRes)
{
    int status = NO_ERROR;
    std::unique_ptr<uint8_t> buffer(new uint8_t[outputSize]);
    XofHandle handle = NULL;
    EVAL(InitXofState(&handle, func));
    EVAL(GetXof(handle, input, inputSize, true, buffer.get(), outputSize));

exit:
    if (handle)
        FreeXofState(handle);

    if (expectedRes) {
        std::string result = GetHexResult(buffer.get(), outputSize);
        std::string expRes((const char*)expectedRes);
        EXPECT_EQ(result, expRes);
    }

    EXPECT_TRUE(status == expectedStatus);
}

void GetXofMultipleTestFunc(__in const void* input1, __in uint64_t inputSize1, __in const void* input2, __in uint64_t inputSize2, __in Xof func, __in uint64_t outputSize,
    __in int expectedStatus, __in_opt const void* expectedRes)
{
    int status = NO_ERROR;
    std::unique_ptr<uint8_t> buffer(new uint8_t[outputSize]);
    XofHandle handle = NULL;
    EVAL(InitXofState(&handle, func));
    EVAL(GetXof(handle, input1, inputSize1, false, nullptr, outputSize));
    EVAL(GetXof(handle, input2, inputSize2, true, buffer.get(), outputSize));

exit:
    if (handle)
        FreeXofState(handle);

    if (expectedRes) {
        std::string result = GetHexResult(buffer.get(), outputSize);
        std::string expRes((const char*)expectedRes);
        EXPECT_EQ(result, expRes);
    }

    EXPECT_TRUE(status == expectedStatus);
}

// Wrong arguments

TEST(GetXofTest, WrongState) {
    int status = NO_ERROR;
    std::unique_ptr<uint8_t> buffer(nullptr);
    status = GetXof(nullptr, "", 0, true, buffer.get(), 0);
    EXPECT_TRUE(status == ERROR_NULL_STATE_HANDLE);
}

TEST(GetXofTest, WrongOutput) {
    int status = NO_ERROR;
    XofHandle handle = NULL;
    InitXofState(&handle, SHAKE128);
    status = GetXof(handle, "", 0, true, nullptr, 0);
    FreeXofState(handle);
    EXPECT_TRUE(status == ERROR_NULL_OUTPUT);
}

TEST(GetXofTest, WrongOutputSize) {
    GetXofMainTestFunc(nullptr, 0, SHAKE128, 0, ERROR_NULL_OUTPUT_SIZE, nullptr);
}

TEST(GetXofTest, WrongInput) {
    GetXofMainTestFunc(nullptr, 55, SHAKE128, 1, ERROR_NULL_INPUT, nullptr);
}

TEST(GetXofTest, WrongInputSize) {
    int status = NO_ERROR;
    std::unique_ptr<uint8_t> buffer(nullptr);
    XofHandle handle = nullptr;

    InitXofState(&handle, SHAKE128);
    status = GetXof(handle, "", 55, false, buffer.get(), 1);
    FreeXofState(handle);
    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
    
    InitXofState(&handle, SHAKE256);
    status = GetXof(handle, "", 55, false, buffer.get(), 1);
    FreeXofState(handle);
    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
}

// Main test
// 1 - full one block (== input + padding) testing
// 2 - full one block + one byte == two blocks testing
// 3 - two blocks testing
// 4 - tree plus blocks testing
// 5 - empty string testing
// 6 - one byte output
// 7 - multiple test

// SHAKE128

TEST(GetXofTest, SHAKE128OneBlock) {
    GetXofMainTestFunc(TEST_STRING_167, 167, SHAKE128, 200, NO_ERROR, "aee25eaf93c3830774532547d36b4c5328743c7b08785fd391fd419b2001ffdc8811b649cda3102c1846de2eb12b28ce29f5"
                                                                      "b40edfe0b670f637eff6f2cbaf691ebe8dda395185006bb5c7509f909c352fc52abbc4f7c28157da7df7a8bb47ee239e037e"
                                                                      "f8d06a4e5b2a3b1620078a31faf9a2ddb6d182966f8b4cc60cb634a51d253255397258a41611492cbf62863d2adb78914c4a"
                                                                      "60de2e8d7df6a4df8fda8483ad148b6908a855a24efc1ca18bf67d022943ebc6674e128015f3fbec6f092eaaa1518a788824");
}

TEST(GetXofTest, SHAKE128TwoBlockEdge) {
    GetXofMainTestFunc(TEST_STRING_168, 168, SHAKE128, 200, NO_ERROR, "fdb7712fe2ce5d0e37b2ae0ff1716ef9d6763d045d40be7388aa71e421a70eadd87af7a4166bb1ab07de88b9ca51eb0a0f1a"
                                                                      "18210d2322dfbdd0e3858d9ea045f7097192b63c6e6e99e6176befa0e58c3ec9be50579768d3c3c1b80eee3f5ca541b2c39b"
                                                                      "078ad8f6437cf136d3a23685c3e574240e956f3a0ee3755f48956d13aa366af8438a0410fda6996995bd65af732b6104621f"
                                                                      "f5c7ee57e7b0cef27de6c539125ead6d8b41a0527faaeb8cfcb56d665d4c66ca2714f31ac41c152233c5f0c7ae18105e7d81");
}

TEST(GetXofTest, SHAKE128TwoBlock) {
    GetXofMainTestFunc(TEST_STRING_169, 169, SHAKE128, 200, NO_ERROR, "356cde6512cdd6a27e1f92acb75407158e79c4618c90b89a8012974ff23121251f86bd10c196dab01f383f10d16329f02b5a"
                                                                      "d3338f88002840b46d8732c62d22ec09deab5febbbdda5f38dd9e1b4dbd9bed21b3c7b8dbc65fb72b0293e933f7e7704fd0e"
                                                                      "490ad94748eb161934417ca8f70fb9ef503e753d127927e98cff0f2f19d622f5d9845e1781c252a0cd8b13467252633c198a"
                                                                      "deba2dbd52f9ead25a7b45fc9135ba903b5afe285135fe222c2dcbe60373165cf84d219c37c32248a83108f395fa1d0fb803");
}

TEST(GetXofTest, SHAKE128ThreePlusBlocks) {
    GetXofMainTestFunc(TEST_STRING_513, 513, SHAKE128, 200, NO_ERROR, "72aed7b0b3d93c4349e1614a06c6026852143080c07d542f84fadd9534ae4df301d6fc70d51ecc5bc0c05176c31fd5879ea9"
                                                                      "cb0e8908487a32a9cf2e6004971716a7c50710717aa62697db48da451d09210dd10de26e9d9c4088a4de4d66deec44934352"
                                                                      "191e83ea71b5c30c813b78c3574e8ebccd270155e25ff781bb283c9ff0402c4723849c2600d402021b1c9eecd4a7a4a1908c"
                                                                      "6ec43198d4802df86e000103a4e2cd3a6148048e7b859b63841a40d307a8479a9dc51c07abafce1db40b4da2aef25fadf3c1");
}

TEST(GetXofTest, SHAKE128Empty) {
    GetXofMainTestFunc(nullptr, 0, SHAKE128, 200, NO_ERROR, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01"
                                                            "fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6df"
                                                            "aac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af0007cd9f5e4c"
                                                            "849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b8d23f877");
}

TEST(GetXofTest, SHAKE128OneByte) {
    GetXofMainTestFunc(nullptr, 0, SHAKE128, 1, NO_ERROR, "7f");
}

TEST(GetXofTest, SHAKE128Multiple) {
    GetXofMultipleTestFunc(TEST_STRING_168, 168, TEST_STRING_7, 7, SHAKE128, 200, NO_ERROR, "af448d96e205c5b99094e5f7854b0fb69c76963c06e172d1f427ecac7d6eecf612298b8452f801ef2bcde0fab31b6b9e34a0"
                                                                                            "7eaa0bf68d0465e990218b61e39a070c6e645deaf9e79978adac142a1c21e188f8f2f607ff3e842fa1ed0fac455d512059bc"
                                                                                            "f3f06ed5bec77a372550926d4729066cc73d24bba690ae86675a2f0668cdc4b5c17763e5a5aa9c5610928172c919553bb6cf"
                                                                                            "a54565d73afa00c16f905186629a133718649494b0f8a905fa4d376e2be69450d5a32e060e68378f024dbd271801e4606282");
}

// SHAKE256

TEST(GetXofTest, SHAKE256OneBlock) {
    GetXofMainTestFunc(TEST_STRING_135, 135, SHAKE256, 200, NO_ERROR, "2635db9b92ee783df1b0f86b64aaee43edbaafd9ca1f7b624f064b21326bcbc1552cfd04c746ebbb1a52cc2e12418dbdfc6a"
                                                                      "1ef8f18919adb018c45cd09c6ba6ea7a6864fa86b2b4b9a41e230a7915e082590dbbd8008a39916e9d0a7bf0ffba93dd4f2d"
                                                                      "1e470d3a3277afb50c01ab79e11d8383b4f8b0dde0feb4a3224a8a603a19aab08ee4fa6ec98f1da94d27bb30d3112f4a27b5"
                                                                      "8270f024b815960199d3b9e737f778adc99277341b47aa25a8668f2fd9dfad270b8ecf278baf9fd3d63a975a214752e998e2");
}

TEST(GetXofTest, SHAKE256TwoBlockEdge) {
    GetXofMainTestFunc(TEST_STRING_136, 136, SHAKE256, 200, NO_ERROR, "bbec82ba368fc60f61e9bcbb120f78b2e446fc030f8d5abb1e04badcc945bbbd1d2f28871ab054d0043c0504bc719919a0ef"
                                                                      "af7e72a18c7f403c6507e6981508e1ea9daf5a1280172db34cd2b18b23372454b46be5c3f2f44f855b30a60befbc28559aaa"
                                                                      "2d80a560233f3e5c279304208dd181ba54b5f4678704d42b341b22a868897af305629327c166be959864fac32cca4118c3ea"
                                                                      "6053b141cbec7216b55b5d7d6f1e3721d0dad3a90efd87e6d33cbd3051edff1b49b027659d415b5deaf365322450759d483f");
}

TEST(GetXofTest, SHAKE256TwoBlock) {
    GetXofMainTestFunc(TEST_STRING_137, 137, SHAKE256, 200, NO_ERROR, "3464325a63457dab826af5e375f26d2b8e5aa6def8522aa034abee61bf7edfb000b4ae8fbca8883217f56f03a8c278ee1b64"
                                                                      "0d869ccac2ae1e2f016d84b1c9fe72cd7b762802a77679efa44ea4474ad34d9f8f6ff1980f70bd5142f74672f346f1735164"
                                                                      "0575ddbaa78557ecc672c5dcb9940b5a21fd7e0c73d33fbb3a5d578e324f340e255a3ef669225a14740bafebbe4852dd593b"
                                                                      "0ae4326a457c0c6449d343583cd3a7acd7cc7a4e186a0f07a6084d3639ccf5725bc9834ae367050a7eee4ed5eee1165b180d");
}

TEST(GetXofTest, SHAKE256ThreePlusBlocks) {
    GetXofMainTestFunc(TEST_STRING_513, 513, SHAKE256, 200, NO_ERROR, "b970a686acaebf055faa8b23cd2acbe1292ec8ea44a2884057e6fb8406a064023bf64dafb76979a92b6935fa3410f67bed5f"
                                                                      "18cba66c167f4f59c8126e4f19eb8a8327b8d858d3a4c2fc46db836d1197662076613b7b67c93e4efe2d31f8f33ef7cfee64"
                                                                      "b9dda93f02976f932dc25230fe56ae547a55e7309aeea7a8dc82a537b28ae55717d141732dffae449528799f25135dc3281b"
                                                                      "1bfb8bd3d7befef20ccdcbb11497ac0bc117d45fc22a6799541c275bb7f0cdae577cdf67838691b8571090a38d3877e0f743");
}

TEST(GetXofTest, SHAKE256Empty) {
    GetXofMainTestFunc(nullptr, 0, SHAKE256, 200, NO_ERROR, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc82"
                                                            "1c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec755"
                                                            "46f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957"
                                                            "c62b54dafc3be87567d677231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5caaae314ed9083dab");
}

TEST(GetXofTest, SHAKE256Onebyte) {
    GetXofMainTestFunc(nullptr, 0, SHAKE256, 1, NO_ERROR, "46");
}

TEST(GetXofTest, SHAKE256Multiple) {
    GetXofMultipleTestFunc(TEST_STRING_136, 136, TEST_STRING_7, 7, SHAKE256, 200, NO_ERROR, "916b60d3dbca01340fde3a192fa0c4691c1448c244ee505d44057863d73b19b854c396cc61dfee3a09a0511adc9daa75cfa8"
                                                                                            "b15d9a013f3007303d165d020d266bf2f693f18af0cdb46d9b5d63573962978a6aa1520e0cba2f73ba8d7709e11b96f223f7"
                                                                                            "6c50b4e1a89a8b8ed9d01b79da5bcd0f2f62fa5e0554660a5d45885349544645faae2c499ac685f2378344a386b4c3aa88bb"
                                                                                            "26659c4e49e8384a54b84db4e577e66252f83c0a1a19e787b4ca759770b3ba0f8379c02d27efec726ca85fff80b2fe2baac7");
}
