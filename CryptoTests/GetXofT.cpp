//  GetXofT.cpp
//

#include "pch.h"

#include "common.h"

// Wrong arguments

TEST(GetXofTest, WrongInput) {
    uint16_t outputSize = 200;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetXof(nullptr, 55, SHAKE128, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT);
    delete[] buffer;
}

TEST(GetXofTest, WrongOuput) {
    uint16_t outputSize = 200;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetXof(TEST_STRING_55, 55, SHAKE128, nullptr, outputSize);

    EXPECT_TRUE(status == ERROR_WRONG_OUTPUT);
    delete[] buffer;
}

TEST(GetXofTest, WrongOuputSize) {
    uint16_t outputSize = 200;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetXof(TEST_STRING_55, 55, SHAKE128, buffer, 0);

    EXPECT_TRUE(status == ERROR_WRONG_OUTPUT_SIZE);
    delete[] buffer;
}

TEST(GetXofTest, UnknownXofFunc) {
    uint16_t outputSize = 200;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetXof(TEST_STRING_55, 55, (Xof)-1, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_XOF_NOT_SUPPORTED);
    delete[] buffer;
}

// Main test

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
