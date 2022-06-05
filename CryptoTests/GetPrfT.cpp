//  GetPrfT.cpp
//

#include "pch.h"

#include "common.h"

// Wrong arguments

TEST(GetPrfTest, WrongInput) {
    uint16_t outputSize = 20;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(nullptr, 55, TEST_STRING_8, 8, HMAC_SHA1, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_NULL_INPUT);
    delete[] buffer;
}

TEST(GetPrfTest, WrongKey) {
    uint16_t outputSize = 20;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, nullptr, 55, HMAC_SHA1, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_NULL_KEY);
    delete[] buffer;
}

TEST(GetPrfTest, WrongOuput) {
    uint16_t outputSize = 20;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_8, 8, HMAC_SHA1, nullptr, outputSize);

    EXPECT_TRUE(status == ERROR_NULL_OUTPUT);
    delete[] buffer;
}

TEST(GetPrfTest, UnknownPrfFunc) {
    uint16_t outputSize = 20;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_8, 8, (PRF)-1, buffer, outputSize);

    EXPECT_TRUE(status == ERROR_UNSUPPORTED_PRF_FUNC);
    delete[] buffer;
}

// Key size > hash func block size

TEST(GetPrfTest, HMAC_SHA_1_ks_gt_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA1].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_65, 65, HMAC_SHA1, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "ad1a7578010d69a657c847af6f967332cf4f3620";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA_224_ks_gt_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_224].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_65, 65, HMAC_SHA_224, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "d09530792014811f450d025044ac207d1f1eee0e385493e42855d84a";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA_256_ks_gt_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_256].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_65, 65, HMAC_SHA_256, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "4416baad7b691a200be34c0af6256d0ee216f89c74f3e9b32196c4308b9e148c";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA_384_ks_gt_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_384].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_129, 129, HMAC_SHA_384, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "a873a374a0da1106de3116965fba5f43b8451dcf0f3f4acc3ad13e4c0e7e314065ab7f97252ea3e332a80766e89c18fd";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA_512_224_ks_gt_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_512_224].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_129, 129, HMAC_SHA_512_224, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "10aef0cc4bc8298150eee551e086ea4973b8934997df0df5de727960";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA_512_256_ks_gt_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_512_256].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_129, 129, HMAC_SHA_512_256, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "469452e867205bea49e146d70e9ad52ba57d5581ba908120425f1db421960775";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA_512_ks_gt_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_512].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_129, 129, HMAC_SHA_512, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "33a6877a692190490fa3d40959d1cbea43572eb9622ba4f2c721773b603eeef123db70720839d4465c3d743737da25deb1c9adb25a428b246f05ae536a1ec4f3";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA3_224_ks_gt_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA3_224].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_145, 145, HMAC_SHA3_224, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "f8c458ed54d007aaa866b7236b64bc9d22494603d54f79b8be590c92";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA3_256_ks_gt_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA3_256].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_137, 137, HMAC_SHA3_256, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "a8b15a281d05bbfcc01698e3f8808d34dc837b1fd7de2a016ee363e5dc7540d9";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA3_384_ks_gt_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA3_384].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_105, 105, HMAC_SHA3_384, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "7f2a42b149b7591ba3a2d13aadc3e98adf7ac69c656337333593378ea3eeb2b1252d174d7c3b288af9e89c0ebb187ad0";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA3_512_ks_gt_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA3_512].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_73, 73, HMAC_SHA3_512, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "ed120259c6ea617e126ced4661e580b9a468877faf607c69604a744ed9652a8813051fa17279c6488295b944db88592991e15cee80655e91665db9a5a1e1864f";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

// Key size <= hash func block size

TEST(GetPrfTest, HMAC_SHA_1_ks_le_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA1].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA1, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "8affa762b331242e63e53a648eef409807765ff3";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA_224_ks_le_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_224].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_224, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "c11232376c9371fdfef6e163086b76d5056e3c11f0300933cb67808b";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA_256_ks_le_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_256].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_256, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "b2afbae5135adff77d03142e8676bd97d81ef2dd4ee8b2e6770e7231cc508257";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA_384_ks_le_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_384].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_128, 128, HMAC_SHA_384, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "590a7e6cf2d0aa85d8cc37c2ebdc8ed65ede3e0bd49c9315ac408b11cfc7c2931f099568ff5722bc3d00780965d591fa";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA_512_224_ks_le_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_512_224].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_128, 128, HMAC_SHA_512_224, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "da224947ac5a65bea90fd38b78666252def50890f9a5d9dc5e59a11b";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA_512_256_ks_le_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_512_256].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_128, 128, HMAC_SHA_512_256, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "b8ca5ce8fbf047620331ae260e22d3209af2e8c8fe5ea7e4fd695f7ca1145766";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA_512_ks_le_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA_512].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_128, 128, HMAC_SHA_512, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "2ac18b055b88309956579afc9697bbb43dd4f03182da274ff03d7218c53a717d81c67b65cfc930b31e0cb9fc120b579561104e76793a591732e17efe8ac653e3";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA3_224_ks_le_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA3_224].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_144, 144, HMAC_SHA3_224, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "18dedf04a72521f39fc510cfc08089429de1b72cf282fc11a1745941";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA3_256_ks_le_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA3_256].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_136, 136, HMAC_SHA3_256, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "b271949add285ebbe15c69627a69132277079bfe3c32ac746cbc8e2503268e9e";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA3_384_ks_le_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA3_384].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_104, 104, HMAC_SHA3_384, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "85965e34be21dedfae61fd00d5f408123a8f18bb3ad8c7b77c5b9451d9df3182e7b06086563f4decea48e2de11ec673b";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetPrfTest, HMAC_SHA3_512_ks_le_bs) {
    uint64_t outputSize = g_hashFuncsSizesMapping[SHA3_512].outputSize;
    uint8_t* buffer = new uint8_t[outputSize];
    int status = GetPrf(TEST_STRING_8, 8, TEST_STRING_72, 72, HMAC_SHA3_512, buffer, outputSize);
    std::string result = GetHexResult(buffer, outputSize);
    std::string expectingResult = "3c13fcd383ae5133df21de89fd168f634da08e3bbabc632d87a4feee14d63b13be3439bf8b46c7fe7bcd8330f5d33001f4d2712c5629d490015c9237b6069ad7";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}
