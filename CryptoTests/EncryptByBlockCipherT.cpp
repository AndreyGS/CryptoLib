//  EncryptByBlockCipherT.cpp
//

#include "pch.h"

#include "common.h"

void EncryptByBlockCipherMainTestFunc(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __inout uint64_t outputSize, __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in int expectedStatus, __in_opt const void* expectedRes, __in uint64_t expectedResLength, bool inPlace
)
{
    void* buffer = new uint8_t[outputSize];

    if (inPlace) {
        memcpy(buffer, input, inputSize);
        input = buffer;
    }

    uint64_t blockSize = 0;
    switch (cipherType) {
    case DES_cipher_type:
    case TDES_cipher_type:
        blockSize = DES_BLOCK_SIZE;
        break;
    default:
        blockSize = 0;
        break;
    }

    void* iv = nullptr;

    if (cIv) {
        iv = new uint8_t[blockSize];
        memcpy(iv, cIv, blockSize);
    }

    int status = EncryptByBlockCipher(input, inputSize, padding, key, cipherType, buffer, &outputSize, mode, iv);

    if (expectedRes) {
        std::string result = GetHexResult((uint8_t*)buffer, outputSize);
        EXPECT_EQ(memcmp(result.c_str(), expectedRes, expectedResLength), 0);
    }

    EXPECT_TRUE(status == expectedStatus);
    delete[] iv;

    if (!inPlace)
        delete[] buffer;
}

void EncryptByBlockCipherTestFunc(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __inout uint64_t outputSize, __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in int expectedStatus, __in_opt const void* expectedRes, __in uint64_t expectedResLength
)
{
    EncryptByBlockCipherMainTestFunc(input, inputSize, padding, key, cipherType, outputSize, mode, cIv, expectedStatus, expectedRes, expectedResLength, false);
}

void EncryptByBlockCipherInPlaceTestFunc(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __inout uint64_t outputSize, __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in int expectedStatus, __in_opt const void* expectedRes, __in uint64_t expectedResLength
)
{
    EncryptByBlockCipherMainTestFunc(input, inputSize, padding, key, cipherType, outputSize, mode, cIv, expectedStatus, expectedRes, expectedResLength, true);
}

void EncryptByBlockCipherMultipartTestFunc(__in const void* input_1, __in uint64_t inputSize_1, __in const void* input_2, __in uint64_t inputSize_2, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in_opt const void* expectedRes)
{
    uint64_t blockSize = 0;
    switch (cipherType) {
    case DES_cipher_type:
    case TDES_cipher_type:
        blockSize = DES_BLOCK_SIZE;
        break;
    default:
        blockSize = 0;
        break;
    }

    uint64_t lastBlockAddition = blockSize - inputSize_2 % blockSize;

    void* buffer = new uint8_t[inputSize_1 + inputSize_2 + (lastBlockAddition ? 0 : blockSize)];

    void* iv = nullptr;

    if (cIv) {
        iv = new uint8_t[blockSize];
        memcpy(iv, cIv, blockSize);
    }

    int status = NO_ERROR;

    uint64_t outputSize = inputSize_1;
    if (NO_ERROR == (status = EncryptByBlockCipher(input_1, inputSize_1, No_padding, key, cipherType, buffer, &outputSize, mode, iv))) {
        uint64_t totalSize = outputSize;
        outputSize = inputSize_2 + (lastBlockAddition ? lastBlockAddition : blockSize);
        status = EncryptByBlockCipher(input_2, inputSize_2, padding, key, cipherType, (uint8_t*)buffer + totalSize, &outputSize, mode, iv);
        totalSize += outputSize;

        if (expectedRes) {
            std::string result = GetHexResult((uint8_t*)buffer, totalSize);
            EXPECT_EQ(memcmp(result.c_str(), expectedRes, totalSize * 2), 0);
        }
    }

    EXPECT_TRUE(status == NO_ERROR);
    delete[] iv;
}

// Wrong arguments

TEST(EncryptByBlockCipherTest, WrongInput) {
    EncryptByBlockCipherTestFunc(nullptr, 55, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_8) + DES_BLOCK_SIZE, ECB_mode, nullptr
        , ERROR_WRONG_INPUT, nullptr, 0);
}

TEST(EncryptByBlockCipherTest, WrongInputSize) {
    EncryptByBlockCipherTestFunc(TEST_STRING_8, 0, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_8) + DES_BLOCK_SIZE, ECB_mode, nullptr
        , ERROR_WRONG_INPUT_SIZE, nullptr, 0);
}

TEST(EncryptByBlockCipherTest, WrongPadding) {
    EncryptByBlockCipherTestFunc(TEST_STRING_8, 8, (PaddingType)-1, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_8) + DES_BLOCK_SIZE, ECB_mode, nullptr
        , ERROR_PADDING_NOT_SUPPORTED, nullptr, 0);
}

TEST(EncryptByBlockCipherTest, WrongKey) {
    EncryptByBlockCipherTestFunc(TEST_STRING_8, 8, PKCSN7_padding, nullptr, DES_cipher_type, sizeof(TEST_STRING_8) + DES_BLOCK_SIZE, ECB_mode, nullptr
        , ERROR_WRONG_KEY, nullptr, 0);
}

TEST(EncryptByBlockCipherTest, WrongCipherFunc) {
    EncryptByBlockCipherTestFunc(TEST_STRING_8, 8, PKCSN7_padding, "81cav5AS", (BlockCipherType)-1, sizeof(TEST_STRING_8) + DES_BLOCK_SIZE, ECB_mode, nullptr
        , ERROR_CIPHER_FUNC_NOT_SUPPORTED, nullptr, 0);
}

TEST(EncryptByBlockCipherTest, WrongOutput) {
    uint64_t outputSize = sizeof(TEST_STRING_8) + DES_BLOCK_SIZE;
    int status = EncryptByBlockCipher(TEST_STRING_8, 8, ISO_7816_padding, "81cav5AS", DES_cipher_type, nullptr, &outputSize, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_WRONG_OUTPUT);
}

TEST(EncryptByBlockCipherTest, OutputSizeIsNull) {
    uint8_t* buffer = new uint8_t[DES_BLOCK_SIZE];
    int status = EncryptByBlockCipher(TEST_STRING_8, 8, ISO_7816_padding, "81cav5AS", DES_cipher_type, buffer, nullptr, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_OUTPUT_SIZE_IS_NULL);
}

TEST(EncryptByBlockCipherTest, WrongOutputSize) {
    uint64_t outputSize = 0;
    uint8_t* buffer = new uint8_t[outputSize];
    int8_t key[] = "81cav5AS";
    int status = EncryptByBlockCipher(TEST_STRING_8, 8, ISO_7816_padding, key, DES_cipher_type, buffer, &outputSize, ECB_mode, nullptr);

    EXPECT_TRUE(status == ERROR_WRONG_OUTPUT_SIZE);
    EXPECT_EQ(outputSize, 16);
    delete[] buffer;
}

TEST(EncryptByBlockCipherTest, WrongOpMode) {
    EncryptByBlockCipherTestFunc(TEST_STRING_8, 8, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_8) + DES_BLOCK_SIZE, (BlockCipherOpMode)-1, nullptr
        , ERROR_UNSUPPROTED_ENCRYPTION_MODE, nullptr, 0);
}

TEST(EncryptByBlockCipherTest, WrongIV) {
    EncryptByBlockCipherTestFunc(TEST_STRING_8, 8, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_8) + DES_BLOCK_SIZE, CBC_mode, nullptr
        , ERROR_WRONG_INIT_VECTOR, nullptr, 0);
}

// Main test

// DES Single

TEST(EncryptByBlockCipherTest, DES_ECB_single) {
    EncryptByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, "81cav5AS", DES_cipher_type, DES_BLOCK_SIZE, ECB_mode, nullptr
        , NO_ERROR, "b9e98a3c77a51086", 16);

}

TEST(EncryptByBlockCipherTest, DES_CBC_single) {
    EncryptByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, "81cav5AS", DES_cipher_type, DES_BLOCK_SIZE, CBC_mode, TEST_STRING_8
        , NO_ERROR, "1d2d5b11ab31c512", 16);
}

TEST(EncryptByBlockCipherTest, DES_CFB_single) {
    EncryptByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, "81cav5AS", DES_cipher_type, DES_BLOCK_SIZE, CFB_mode, TEST_STRING_8
        , NO_ERROR, "e24a3e6aa8d65046", 16);
}

TEST(EncryptByBlockCipherTest, DES_OFB_single) {
    EncryptByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, "81cav5AS", DES_cipher_type, DES_BLOCK_SIZE, OFB_mode, TEST_STRING_8
        , NO_ERROR, "e24a3e6aa8d65046", 16);
}

TEST(EncryptByBlockCipherTest, DES_CTR_single) {
    EncryptByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, "81cav5AS", DES_cipher_type, DES_BLOCK_SIZE, CTR_mode, TEST_STRING_8
        , NO_ERROR, "e24a3e6aa8d65046", 16);
}

// DES Multi

TEST(EncryptByBlockCipherTest, DES_ECB_multi) {
    EncryptByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, ECB_mode, nullptr
        , NO_ERROR, "8ca8da07c07a31a13c1de0b35f5eadd88510c2ef3f16ba52a27ba0f3e0cd8a71e4b609239508875599fce69a08adc97a6df6a55be107791a1d2"
                    "6a67e1362c961e39eff3db05aa30baffd676fa3ea9cde9284133c0cd60994789fa0ad29c93dde9d9fd5454ce4a9112b6446fe667f5e7ead0c7d085e6988e4e0fcd0fd2ec270e55c5ac91121642ed5", 272);
}

TEST(EncryptByBlockCipherTest, DES_CBC_multi) {
    EncryptByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CBC_mode, TEST_STRING_8
        , NO_ERROR, "38b949d36ccf3bbc19ab71f4be2baa44975a4b63da299a5bebda3d5c0d8a0242f579cb3648633c67b75a5877847d10b9891e67612922649cbb8"
                    "04520f3074dba3c9d4b4b88bbd7547b6b768dc98421f9ac1cd2731fc85e57c58ff52ad56a47e18765b935cd42a13f3818708df654557d07a29d6f0c7a6cda7c532791ee975848c2a3c14ffd61f953", 272);
}

TEST(EncryptByBlockCipherTest, DES_CFB_multi) {
    EncryptByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CFB_mode, TEST_STRING_8
        , NO_ERROR, "e24a3239ceda4722a779543cb9f99191b450d44cce1e6797a4235f6522ec40c9b9b24eb5989498d0b6c6e111b8597ca476704c79962b64584ab"
                    "317e3bd1e7437f4f773cc8ab85a3419aa5028ada1aa76acb76f04e201d2f96068a69c411ef7e6562d2eb5062ff5c6acf2f6835eae0e2883cce4f67eefaf75d9c67da499c390228ad84629afc206f3", 272);
}

TEST(EncryptByBlockCipherTest, DES_OFB_multi) {
    EncryptByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, OFB_mode, TEST_STRING_8
        , NO_ERROR, "e24a3239ceda4722b6e1b3effe6ef31da710f29ad945f35e3f6519254283e84a7fd3665ef18325ae1159ccc9faedcd8a5e35c187c47b71d8004"
                    "f4c998c9c70e8111175b30ce288bacc00845602c4634a94bc3a376aad7e07b4643ebd7246ebc2959778bcfa32c1400a5fa5158a921348732e35087fcca1d73f13952678e3b57c341bd41add02e49f", 272);
}

TEST(EncryptByBlockCipherTest, DES_CTR_multi) {
    EncryptByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CTR_mode, TEST_STRING_8
        , NO_ERROR, "e24a3239ceda4722c2b984a4700d821b3867c72f6c5de354aa2cfc1e307ad35d96f1f3cdec821fc7f093a91fb35492d93b37f77d92d895608fb"
                    "bed968479d4471cd2e5f476f156904c4413786dd397d52cdd43335bbf4aeb1035e8aed5b9b3780cef7428ffbb8b89fbec32de02f9d84d36a59d27c5f6d7e0811153b14d2e0cc98b06a7d49d29c319", 272);
}

// DES Multi in Place

TEST(EncryptByBlockCipherTest, DES_ECB_multi_in_place) {
    EncryptByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, ECB_mode, nullptr
        , NO_ERROR, "8ca8da07c07a31a13c1de0b35f5eadd88510c2ef3f16ba52a27ba0f3e0cd8a71e4b609239508875599fce69a08adc97a6df6a55be107791a1d2"
                    "6a67e1362c961e39eff3db05aa30baffd676fa3ea9cde9284133c0cd60994789fa0ad29c93dde9d9fd5454ce4a9112b6446fe667f5e7ead0c7d085e6988e4e0fcd0fd2ec270e55c5ac91121642ed5", 272);
}

TEST(EncryptByBlockCipherTest, DES_CBC_multi_in_place) {
    EncryptByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CBC_mode, TEST_STRING_8
        , NO_ERROR, "38b949d36ccf3bbc19ab71f4be2baa44975a4b63da299a5bebda3d5c0d8a0242f579cb3648633c67b75a5877847d10b9891e67612922649cbb8"
                    "04520f3074dba3c9d4b4b88bbd7547b6b768dc98421f9ac1cd2731fc85e57c58ff52ad56a47e18765b935cd42a13f3818708df654557d07a29d6f0c7a6cda7c532791ee975848c2a3c14ffd61f953", 272);
}

TEST(EncryptByBlockCipherTest, DES_CFB_multi_in_place) {
    EncryptByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CFB_mode, TEST_STRING_8
        , NO_ERROR, "e24a3239ceda4722a779543cb9f99191b450d44cce1e6797a4235f6522ec40c9b9b24eb5989498d0b6c6e111b8597ca476704c79962b64584ab"
                    "317e3bd1e7437f4f773cc8ab85a3419aa5028ada1aa76acb76f04e201d2f96068a69c411ef7e6562d2eb5062ff5c6acf2f6835eae0e2883cce4f67eefaf75d9c67da499c390228ad84629afc206f3", 272);
}

TEST(EncryptByBlockCipherTest, DES_OFB_multi_in_place) {
    EncryptByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, OFB_mode, TEST_STRING_8
        , NO_ERROR, "e24a3239ceda4722b6e1b3effe6ef31da710f29ad945f35e3f6519254283e84a7fd3665ef18325ae1159ccc9faedcd8a5e35c187c47b71d8004"
                    "f4c998c9c70e8111175b30ce288bacc00845602c4634a94bc3a376aad7e07b4643ebd7246ebc2959778bcfa32c1400a5fa5158a921348732e35087fcca1d73f13952678e3b57c341bd41add02e49f", 272);
}

TEST(EncryptByBlockCipherTest, DES_CTR_multi_in_place) {
    EncryptByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5AS", DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CTR_mode, TEST_STRING_8
        , NO_ERROR, "e24a3239ceda4722c2b984a4700d821b3867c72f6c5de354aa2cfc1e307ad35d96f1f3cdec821fc7f093a91fb35492d93b37f77d92d895608fb"
                    "bed968479d4471cd2e5f476f156904c4413786dd397d52cdd43335bbf4aeb1035e8aed5b9b3780cef7428ffbb8b89fbec32de02f9d84d36a59d27c5f6d7e0811153b14d2e0cc98b06a7d49d29c319", 272);
}

// DES Multipart

TEST(EncryptByBlockCipherTest, DES_ECB_multipart) {
    EncryptByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, "81cav5AS", DES_cipher_type, ECB_mode, nullptr
        , "b622571988bf2347b9e98a3c77a51086");
}

TEST(EncryptByBlockCipherTest, DES_CBC_multipart) {
    EncryptByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, "81cav5AS", DES_cipher_type, CBC_mode, TEST_STRING_8
        , "a70f16366ea7f346bf1b15da2429a772");
}

TEST(EncryptByBlockCipherTest, DES_CFB_multipart) {
    EncryptByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, "81cav5AS", DES_cipher_type, CFB_mode, TEST_STRING_8
        ,  "c54d3a7ce3d64d23f9c975ae8097805a");
}

TEST(EncryptByBlockCipherTest, DES_OFB_multipart) {
    EncryptByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, "81cav5AS", DES_cipher_type, OFB_mode, TEST_STRING_8
        , "c54d3a7ce3d64d2390e8b6bc9769e673");
}

TEST(EncryptByBlockCipherTest, DES_CTR_multipart) {
    EncryptByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, "81cav5AS", DES_cipher_type, CTR_mode, TEST_STRING_8
        , "c54d3a7ce3d64d23e4b081f7190a9775");
}

// 3DES Single

TEST(EncryptByBlockCipherTest, TDES_ECB_single) {
    EncryptByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, DES_BLOCK_SIZE, ECB_mode, nullptr
        , NO_ERROR, "d8a2721ab3f542cb", 16);
}

TEST(EncryptByBlockCipherTest, TDES_CBC_single) {
    EncryptByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, DES_BLOCK_SIZE, CBC_mode, TEST_STRING_8
        , NO_ERROR, "075e74323668642d", 16);
}

TEST(EncryptByBlockCipherTest, TDES_CFB_single) {
    EncryptByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, DES_BLOCK_SIZE, CFB_mode, TEST_STRING_8
        , NO_ERROR, "2263e26f84a9165f", 16);
}

TEST(EncryptByBlockCipherTest, TDES_OFB_single) {
    EncryptByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, DES_BLOCK_SIZE, OFB_mode, TEST_STRING_8
        , NO_ERROR, "2263e26f84a9165f", 16);
}

TEST(EncryptByBlockCipherTest, TDES_CTR_single) {
    EncryptByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, DES_BLOCK_SIZE, CTR_mode, TEST_STRING_8
        , NO_ERROR, "2263e26f84a9165f", 16);
}

// 3DES Multi

TEST(EncryptByBlockCipherTest, TDES_ECB_multi) {
    EncryptByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, ECB_mode, nullptr
        , NO_ERROR, "3933842094a7bed7784ad34d8ac29c73b1e6f7b64205e89077fc45e6da0dc73047807cdcf29133f2d7b2ba13baa8af1ec078c79c07cd773d2d1" 
                    "0ceabdadbdd1f234bdb9a0a882e027f78ed91279fecb246fb170987fcefa8e4cb1e05850ec8744fccb5556052b1ca04e7ede117b83526550cf1519bdb3cfa1466de5e8178a758adff9406fb2aa6d7", 16);
}

TEST(EncryptByBlockCipherTest, TDES_CBC_multi) {
    EncryptByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CBC_mode, TEST_STRING_8
        , NO_ERROR, "ba1976b002c886673370a0014d1bc216e445c728afae86dcd23abb2c02f282b25ac6d7cc245336d6d5d3a9f4973b87b68b1cbde6828d3dee296" 
                    "a5bca512713e51591e7bf049c825929a70530697cf9d5013b87424cf589d28b2a833adbbf6cbecb5be03b06d696424fa84d72d64adcaa40e27dd4571ec5a4f6513fa95eaed8cec5ff7d1b60d8f963", 16);
}

TEST(EncryptByBlockCipherTest, TDES_CFB_multi) {
    EncryptByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CFB_mode, TEST_STRING_8
        , NO_ERROR, "2263ee3ce2a5013b2008cc55336536b911aba94c7f3e96240ec9960c4e1316235688a15c369e9f2b919fc49ef1259d0160c89be6a7adcc4bec0" 
                    "de6ae5e270f33c60f1751c6fe231d9652d0d51bd798494d6cd7859036e42d3491099b4209d7a02153175c62dbf0090ee9c3c4405f1e95c144a9008287792510e9ccf4a4a02640402ff0e68dd55c92", 16);
}

TEST(EncryptByBlockCipherTest, TDES_OFB_multi) {
    EncryptByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, OFB_mode, TEST_STRING_8
        , NO_ERROR, "2263ee3ce2a5013b806dd21b9e62e7a0fb964dee8a52cd0b64d2c1bee79af825fce933498467e3e8b80ed49defaade868ca96aac43356b100f8" 
                    "2a99365656d8c36034615eb0d68aa3a19efee2d58b9d2ea8f7e72047ecafdad16f7fd1707effde188612c2bb1fdb0c53a57232aa548ede2e10858c82e2eb33df59c3e065b256b0426cb618b5db43c", 16);
}

TEST(EncryptByBlockCipherTest, TDES_CTR_multi) {
    EncryptByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CTR_mode, TEST_STRING_8
        , NO_ERROR, "2263ee3ce2a5013bfa8726195a4aa657402761eda98c6382dcc224071aa502d7f9d40f0324caa54dd83da170bec685f2be4ceff7a33318ae4d8" 
                    "52b83df238f9075c340787b2c1339275b3faae567a167266f349c6fe937d2f2203afef3a09a7dda329a2da3712024d17473f9acaebc03e984c6045a1a7a8dfbe2b8c333f2508301d1bfd0287b3b0c", 16);
}

// 3DES Multi in Place

TEST(EncryptByBlockCipherTest, TDES_ECB_multi_in_place) {
    EncryptByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, ECB_mode, nullptr
        , NO_ERROR, "3933842094a7bed7784ad34d8ac29c73b1e6f7b64205e89077fc45e6da0dc73047807cdcf29133f2d7b2ba13baa8af1ec078c79c07cd773d2d1"
                    "0ceabdadbdd1f234bdb9a0a882e027f78ed91279fecb246fb170987fcefa8e4cb1e05850ec8744fccb5556052b1ca04e7ede117b83526550cf1519bdb3cfa1466de5e8178a758adff9406fb2aa6d7", 16);
}

TEST(EncryptByBlockCipherTest, TDES_CBC_multi_in_place) {
    EncryptByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CBC_mode, TEST_STRING_8
        , NO_ERROR, "ba1976b002c886673370a0014d1bc216e445c728afae86dcd23abb2c02f282b25ac6d7cc245336d6d5d3a9f4973b87b68b1cbde6828d3dee296"
                    "a5bca512713e51591e7bf049c825929a70530697cf9d5013b87424cf589d28b2a833adbbf6cbecb5be03b06d696424fa84d72d64adcaa40e27dd4571ec5a4f6513fa95eaed8cec5ff7d1b60d8f963", 16);
}

TEST(EncryptByBlockCipherTest, TDES_CFB_multi_in_place) {
    EncryptByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CFB_mode, TEST_STRING_8
        , NO_ERROR, "2263ee3ce2a5013b2008cc55336536b911aba94c7f3e96240ec9960c4e1316235688a15c369e9f2b919fc49ef1259d0160c89be6a7adcc4bec0"
                    "de6ae5e270f33c60f1751c6fe231d9652d0d51bd798494d6cd7859036e42d3491099b4209d7a02153175c62dbf0090ee9c3c4405f1e95c144a9008287792510e9ccf4a4a02640402ff0e68dd55c92", 16);
}

TEST(EncryptByBlockCipherTest, TDES_OFB_multi_in_place) {
    EncryptByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, OFB_mode, TEST_STRING_8
        , NO_ERROR, "2263ee3ce2a5013b806dd21b9e62e7a0fb964dee8a52cd0b64d2c1bee79af825fce933498467e3e8b80ed49defaade868ca96aac43356b100f8"
                    "2a99365656d8c36034615eb0d68aa3a19efee2d58b9d2ea8f7e72047ecafdad16f7fd1707effde188612c2bb1fdb0c53a57232aa548ede2e10858c82e2eb33df59c3e065b256b0426cb618b5db43c", 16);
}

TEST(EncryptByBlockCipherTest, TDES_CTR_multi_in_place) {
    EncryptByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CTR_mode, TEST_STRING_8
        , NO_ERROR, "2263ee3ce2a5013bfa8726195a4aa657402761eda98c6382dcc224071aa502d7f9d40f0324caa54dd83da170bec685f2be4ceff7a33318ae4d8"
                    "52b83df238f9075c340787b2c1339275b3faae567a167266f349c6fe937d2f2203afef3a09a7dda329a2da3712024d17473f9acaebc03e984c6045a1a7a8dfbe2b8c333f2508301d1bfd0287b3b0c", 16);
}

// 3DES Multipart

TEST(EncryptByBlockCipherTest, TDES_ECB_multipart) {
    EncryptByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, ECB_mode, nullptr
        , "760b8b1ca4c0655ed8a2721ab3f542cb");
}

TEST(EncryptByBlockCipherTest, TDES_CBC_multipart) {
    EncryptByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, CBC_mode, TEST_STRING_8
        , "9424ebd9f5942c845111f237a9762073");
}

TEST(EncryptByBlockCipherTest, TDES_CFB_multipart) {
    EncryptByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, CFB_mode, TEST_STRING_8
        , "0564e679cfa90b3a2deac33c78bd4ec3");
}

TEST(EncryptByBlockCipherTest, TDES_OFB_multipart) {
    EncryptByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, OFB_mode, TEST_STRING_8
        , "0564e679cfa90b3aa664d748f765f2ce");
}

TEST(EncryptByBlockCipherTest, TDES_CTR_multipart) {
    EncryptByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, "81cav5ASkv8vwel0ve8hve40", TDES_cipher_type, CTR_mode, TEST_STRING_8
        , "0564e679cfa90b3adc8e234a334db339");
}
