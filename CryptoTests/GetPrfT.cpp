// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
//  GetPrfT.cpp
//

#include "pch.h"

#include "common.h"

void GetPrfMainTestFunc(__in const void* input, __in size_t inputSize, __in const void* key, __in size_t keySize, __in size_t outputSize, __in Prf func, __in int expectedStatus, __in_opt const void* expectedRes)
{
    int status = NO_ERROR;

    // HMAC functions has fixed output size identical to respective hash function
    // but there can be the other, that may have a variable output size
    if (func >= HMAC_SHA1 && func <= HMAC_SHA3_512)
        outputSize = g_hashFuncsSizesMapping[g_PrfSizesMapping[func].hashFunc].didgestSize;

    std::vector<uint8_t> buffer(outputSize);
    PrfHandle handle = NULL;
    EVAL(InitPrfState(&handle, func, nullptr));
    EVAL(GetPrf(handle, input, inputSize, key, keySize, true, buffer.data(), outputSize));

exit:
    if (handle)
        FreePrfState(handle);

    if (expectedRes) {
        std::string result = GetHexResult(buffer.data(), outputSize);
        std::string expRes((const char*)expectedRes);
        EXPECT_EQ(result, expRes);
    }

    EXPECT_TRUE(status == expectedStatus);
}

void GetPrfMultipleTestFunc(__in const void* input1, __in size_t inputSize1, __in const void* input2, __in size_t inputSize2, __in const void* key, __in size_t keySize,
    __in size_t outputSize, __in Prf func, __in int expectedStatus, __in_opt const void* expectedRes)
{
    int status = NO_ERROR;

    // HMAC functions has fixed output size identical to respective hash function
    // but there can be the other, that may have a variable output size
    if (func >= HMAC_SHA1 && func <= HMAC_SHA3_512)
        outputSize = g_hashFuncsSizesMapping[g_PrfSizesMapping[func].hashFunc].didgestSize;

    std::vector<uint8_t> buffer(outputSize);
    PrfHandle handle = NULL;
    EVAL(InitPrfState(&handle, func, nullptr));
    EVAL(GetPrf(handle, input1, inputSize1, key, keySize, false, buffer.data(), outputSize));
    EVAL(GetPrf(handle, input2, inputSize2, key, keySize, true, buffer.data(), outputSize));

exit:
    if (handle)
        FreePrfState(handle);

    if (expectedRes) {
        std::string result = GetHexResult(buffer.data(), outputSize);
        std::string expRes((const char*)expectedRes);
        EXPECT_EQ(result, expRes);
    }

    EXPECT_TRUE(status == expectedStatus);
}

// Wrong arguments

TEST(GetPrfTest, WrongState) {
    size_t outputSize = g_hashFuncsSizesMapping[SHA1].didgestSize;
    std::vector<uint8_t> buffer(1);
    EXPECT_TRUE(GetPrf(nullptr, TEST_STRING_8, 8, TEST_STRING_65, 64, true, buffer.data(), outputSize) == ERROR_NULL_STATE_HANDLE);
}

TEST(GetPrfTest, WrongInput) {
    GetPrfMainTestFunc(nullptr, 8, TEST_STRING_65, 65, 0, HMAC_SHA1, ERROR_NULL_INPUT, nullptr);
}

TEST(GetPrfTest, WrongKey) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, nullptr, 65, 0, HMAC_SHA1, ERROR_NULL_KEY, nullptr);
}

TEST(GetPrfTest, WrongInputSize) {
    int status = NO_ERROR;
    size_t outputSize = g_hashFuncsSizesMapping[SHA1].didgestSize;
    PrfHandle handle = NULL;
    EVAL(InitPrfState(&handle, HMAC_SHA1, nullptr));
    
exit:
    if (handle) {
        EXPECT_TRUE(GetPrf(handle, TEST_STRING_8, 8, TEST_STRING_65, 64, true, nullptr, outputSize) == ERROR_NULL_OUTPUT);
        FreePrfState(handle);
    }
    else
        EXPECT_TRUE(false);
}

TEST(GetPrfTest, WrongOutput) {
    int status = NO_ERROR;
    size_t outputSize = g_hashFuncsSizesMapping[SHA1].didgestSize;
    std::vector<uint8_t> buffer(1);
    PrfHandle handle = NULL;
    EVAL(InitPrfState(&handle, HMAC_SHA1, nullptr));

exit:
    if (handle) {
        EXPECT_TRUE(GetPrf(handle, TEST_STRING_7, 7, TEST_STRING_65, 64, false, buffer.data(), outputSize) == ERROR_WRONG_INPUT_SIZE);
        FreePrfState(handle);
    }
    else
        EXPECT_TRUE(false);
}

// Null Input

TEST(GetPrfTest, NullInput) {
    GetPrfMainTestFunc(nullptr, 0, TEST_STRING_65, 65, 0, HMAC_SHA1, NO_ERROR, "a0de1835d81f34bd42c029fa8ed7a11b37ce71e6");
}

// Null Key

TEST(GetPrfTest, NullKey) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, nullptr, 0, 0, HMAC_SHA1, NO_ERROR, "1d04922aeb3d72b4303375f9158f365a12904c13");
}

// Main test
// 
// 1. Key size > hash func block size
// 2. Key size <= hash func block size
// 3. Multiple input

// HMAC_SHA1

TEST(GetPrfTest, HmacSha1KsGtBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_65, 65, 0, HMAC_SHA1, NO_ERROR, "ad1a7578010d69a657c847af6f967332cf4f3620");
}

TEST(GetPrfTest, HmacSha1KsLeBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, 0, HMAC_SHA1, NO_ERROR, "8affa762b331242e63e53a648eef409807765ff3");
}

TEST(GetPrfTest, HmacSha1Multiple) {
    GetPrfMultipleTestFunc(TEST_STRING_64, 64, TEST_STRING_8, 8, TEST_STRING_64, 64, 0, HMAC_SHA1, NO_ERROR, "96732ba08e5d2177d3705afa54cb691061bf15ad");
}

// HMAC_SHA_224

TEST(GetPrfTest, HmacSha224KsGtBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_65, 65, 0, HMAC_SHA_224, NO_ERROR, "d09530792014811f450d025044ac207d1f1eee0e385493e42855d84a");
}

TEST(GetPrfTest, HmacSha224KsLeBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, 0, HMAC_SHA_224, NO_ERROR, "c11232376c9371fdfef6e163086b76d5056e3c11f0300933cb67808b");
}

TEST(GetPrfTest, HmacSha224Multiple) {
    GetPrfMultipleTestFunc(TEST_STRING_64, 64, TEST_STRING_8, 8, TEST_STRING_64, 64, 0, HMAC_SHA_224, NO_ERROR, "53ce2bd2000ccdea505e8b4a431123b8160b87cfe4eaf455b74bf5f5");
}

// HMAC_SHA_256

TEST(GetPrfTest, HmacSha256KsGtBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_65, 65, 0, HMAC_SHA_256, NO_ERROR, "4416baad7b691a200be34c0af6256d0ee216f89c74f3e9b32196c4308b9e148c");
}

TEST(GetPrfTest, HmacSha256KsLeBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, 0, HMAC_SHA_256, NO_ERROR, "b2afbae5135adff77d03142e8676bd97d81ef2dd4ee8b2e6770e7231cc508257");
}

TEST(GetPrfTest, HmacSha256Multiple) {
    GetPrfMultipleTestFunc(TEST_STRING_64, 64, TEST_STRING_8, 8, TEST_STRING_64, 64, 0, HMAC_SHA_256, NO_ERROR, "008f033547a1127aeba57db3b1134a6a79bdb8ee47d1822c815867b03fad54db");
}

// HMAC_SHA_384

TEST(GetPrfTest, HmacSha384KsGtBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_129, 129, 0, HMAC_SHA_384, NO_ERROR, "a873a374a0da1106de3116965fba5f43b8451dcf0f3f4acc3ad13e4c0e7e314065ab7f97252ea3e332a80766e89c18fd");
}

TEST(GetPrfTest, HmacSha384KsLeBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_128, 128, 0, HMAC_SHA_384, NO_ERROR, "590a7e6cf2d0aa85d8cc37c2ebdc8ed65ede3e0bd49c9315ac408b11cfc7c2931f099568ff5722bc3d00780965d591fa");
}

TEST(GetPrfTest, HmacSha384Multiple) {
    GetPrfMultipleTestFunc(TEST_STRING_128, 128, TEST_STRING_8, 8, TEST_STRING_64, 64, 0, HMAC_SHA_384, NO_ERROR, "2d0490d8035a620b1816397b1bdaf2e7b9dc0e5603fcddbe0ca094a8ebd03bf82d8d927e894c734edd816e769b16d9c4");
}

// HMAC_SHA_512_224

TEST(GetPrfTest, HmacSha512224KsGtBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_129, 129, 0, HMAC_SHA_512_224, NO_ERROR, "10aef0cc4bc8298150eee551e086ea4973b8934997df0df5de727960");
}

TEST(GetPrfTest, HmacSha512224KsLeBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_128, 128, 0, HMAC_SHA_512_224, NO_ERROR, "da224947ac5a65bea90fd38b78666252def50890f9a5d9dc5e59a11b");
}

TEST(GetPrfTest, HmacSha512224Multiple) {
    GetPrfMultipleTestFunc(TEST_STRING_128, 128, TEST_STRING_8, 8, TEST_STRING_64, 64, 0, HMAC_SHA_512_224, NO_ERROR, "d23d5a65f5e8e8063276a949e58d9b67977b23c6aef2141acef004b4");
}

// HMAC_SHA_512_256

TEST(GetPrfTest, HmacSha512256KsGtBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_129, 129, 0, HMAC_SHA_512_256, NO_ERROR, "469452e867205bea49e146d70e9ad52ba57d5581ba908120425f1db421960775");
}

TEST(GetPrfTest, HmacSha512256KsLeBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_128, 128, 0, HMAC_SHA_512_256, NO_ERROR, "b8ca5ce8fbf047620331ae260e22d3209af2e8c8fe5ea7e4fd695f7ca1145766");
}

TEST(GetPrfTest, HmacSha512256Multiple) {
    GetPrfMultipleTestFunc(TEST_STRING_128, 128, TEST_STRING_8, 8, TEST_STRING_64, 64, 0, HMAC_SHA_512_256, NO_ERROR, "e5910b9c9a66ae9fc2b6cf7c55bdd73ee1837876ef54eb329b96b1212517859c");
}

// HMAC_SHA_512

TEST(GetPrfTest, HmacSha512KsGtBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_129, 129, 0, HMAC_SHA_512, NO_ERROR, "33a6877a692190490fa3d40959d1cbea43572eb9622ba4f2c721773b603eeef123db70720839d4465c3d743737da25deb1c9adb25a428b246f05ae536a1ec4f3");
}

TEST(GetPrfTest, HmacSha512KsLeBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_128, 128, 0, HMAC_SHA_512, NO_ERROR, "2ac18b055b88309956579afc9697bbb43dd4f03182da274ff03d7218c53a717d81c67b65cfc930b31e0cb9fc120b579561104e76793a591732e17efe8ac653e3");
}

TEST(GetPrfTest, HmacSha512Multiple) {
    GetPrfMultipleTestFunc(TEST_STRING_128, 128, TEST_STRING_8, 8, TEST_STRING_64, 64, 0, HMAC_SHA_512, NO_ERROR, "4a99a6325850de6ddc067c248ed0345f5b0213ca2ef447e506b69d5a183b1fb19a0afa0fd293616544288dc1b0033a76e652f4a0b0609229ea06c80b8757765e");
}

// HMAC_SHA3_224

TEST(GetPrfTest, HmacSha3224KsGtBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_145, 145, 0, HMAC_SHA3_224, NO_ERROR, "f8c458ed54d007aaa866b7236b64bc9d22494603d54f79b8be590c92");
}

TEST(GetPrfTest, HmacSha3224KsLeBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_144, 144, 0, HMAC_SHA3_224, NO_ERROR, "18dedf04a72521f39fc510cfc08089429de1b72cf282fc11a1745941");
}

TEST(GetPrfTest, HmacSha3224Multiple) {
    GetPrfMultipleTestFunc(TEST_STRING_144, 144, TEST_STRING_8, 8, TEST_STRING_64, 64, 0, HMAC_SHA3_224, NO_ERROR, "bc6dee3501936a22e35cd35095c625ceb66f3f210b0cafd0ebaf931f");
}

// HMAC_SHA3_256

TEST(GetPrfTest, HmacSha3256KsGtBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_137, 137, 0, HMAC_SHA3_256, NO_ERROR, "a8b15a281d05bbfcc01698e3f8808d34dc837b1fd7de2a016ee363e5dc7540d9");
}

TEST(GetPrfTest, HmacSha3256KsLeBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_136, 136, 0, HMAC_SHA3_256, NO_ERROR, "b271949add285ebbe15c69627a69132277079bfe3c32ac746cbc8e2503268e9e");
}

TEST(GetPrfTest, HmacSha3256Multiple) {
    GetPrfMultipleTestFunc(TEST_STRING_136, 136, TEST_STRING_8, 8, TEST_STRING_64, 64, 0, HMAC_SHA3_256, NO_ERROR, "341edd07b8d324abf80e0eeaa7e0b1e0de27c0354f81f09d4a4f789f30a10207");
}

// HMAC_SHA3_384

TEST(GetPrfTest, HmacSha3384KsGtBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_105, 105, 0, HMAC_SHA3_384, NO_ERROR, "7f2a42b149b7591ba3a2d13aadc3e98adf7ac69c656337333593378ea3eeb2b1252d174d7c3b288af9e89c0ebb187ad0");
}

TEST(GetPrfTest, HmacSha3384KsLeBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_104, 104, 0, HMAC_SHA3_384, NO_ERROR, "85965e34be21dedfae61fd00d5f408123a8f18bb3ad8c7b77c5b9451d9df3182e7b06086563f4decea48e2de11ec673b");
}

TEST(GetPrfTest, HmacSha3384Multiple) {
    GetPrfMultipleTestFunc(TEST_STRING_104, 104, TEST_STRING_8, 8, TEST_STRING_64, 64, 0, HMAC_SHA3_384, NO_ERROR, "4de8c3d661aca3a36013bb245e0961450701a731f73e806ffae926fd3f6aabc3cd303ed8152ef634e95f0282a75555a3");
}

// HMAC_SHA3_512

TEST(GetPrfTest, HmacSha3512KsGtBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_73, 73, 0, HMAC_SHA3_512, NO_ERROR, "ed120259c6ea617e126ced4661e580b9a468877faf607c69604a744ed9652a8813051fa17279c6488295b944db88592991e15cee80655e91665db9a5a1e1864f");
}

TEST(GetPrfTest, HmacSha3512KsLeBs) {
    GetPrfMainTestFunc(TEST_STRING_8, 8, TEST_STRING_72, 72, 0, HMAC_SHA3_512, NO_ERROR, "3c13fcd383ae5133df21de89fd168f634da08e3bbabc632d87a4feee14d63b13be3439bf8b46c7fe7bcd8330f5d33001f4d2712c5629d490015c9237b6069ad7");
}

TEST(GetPrfTest, HmacSha3512Multiple) {
    GetPrfMultipleTestFunc(TEST_STRING_72, 72, TEST_STRING_8, 8, TEST_STRING_64, 64, 0, HMAC_SHA3_512, NO_ERROR, "db68a88d409bf0996fe92b423f63b165fedd1e4d28e6977ac57fcbfe8095169930a95a7b75ada3ae85dabab2e2a683a905cf8b22dbedfbdd07544d540a18825d");
}
