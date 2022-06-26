//  ProcessingByBlockCipherEncryptionT.cpp
//

#include "pch.h"

#include "ProcessingByBlockCipherTestSupportFunctions.h"

// Wrong arguments

TEST(ProcessingByBlockCipherEncryptionTest, TooSmallOutputSize) {
    int status = NO_ERROR;
    uint8_t input[] = { 0xb9, 0xe9, 0x8a, 0x3c, 0x77, 0xa5, 0x10, 0x86 };
    uint64_t outputSize = 0;
    uint8_t* buffer = new uint8_t[outputSize];
    BlockCipherHandle handle = nullptr;
    EVAL(InitBlockCipherState(&handle, DES_cipher_type, Encryption_mode, ECB_mode, PKCSN7_padding, KEY_8, nullptr));
    EVAL(ProcessingByBlockCipher(handle, input, 8, true, buffer, &outputSize));

exit:
    if (handle)
        FreeBlockCipherState(handle);

    EXPECT_TRUE(status == ERROR_TOO_SMALL_OUTPUT_SIZE);
    EXPECT_EQ(outputSize, 16);
    delete[] buffer;
}

// Main test

// DES Single

TEST(ProcessingByBlockCipherEncryptionTest, DesECBsingle) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, KEY_8, DES_cipher_type, DES_BLOCK_SIZE, ECB_mode, nullptr
        , NO_ERROR, "b9e98a3c77a51086", Encryption_mode);

}

TEST(ProcessingByBlockCipherEncryptionTest, DesCBCsingle) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, KEY_8, DES_cipher_type, DES_BLOCK_SIZE, CBC_mode, TEST_STRING_8
        , NO_ERROR, "1d2d5b11ab31c512", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, DesCFBsingle) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, KEY_8, DES_cipher_type, DES_BLOCK_SIZE, CFB_mode, TEST_STRING_8
        , NO_ERROR, "e24a3e6aa8d65046", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, DesOFBsingle) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, KEY_8, DES_cipher_type, DES_BLOCK_SIZE, OFB_mode, TEST_STRING_8
        , NO_ERROR, "e24a3e6aa8d65046", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, DesCTRsingle) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, KEY_8, DES_cipher_type, DES_BLOCK_SIZE, CTR_mode, TEST_STRING_8
        , NO_ERROR, "e24a3e6aa8d65046", Encryption_mode);
}

// DES Multi

TEST(ProcessingByBlockCipherEncryptionTest, DesECBmulti) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_8, DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, ECB_mode, nullptr
        , NO_ERROR, "8ca8da07c07a31a13c1de0b35f5eadd88510c2ef3f16ba52a27ba0f3e0cd8a71e4b609239508875599fce69a08adc97a6df6a55be107791a1d2"
                    "6a67e1362c961e39eff3db05aa30baffd676fa3ea9cde9284133c0cd60994789fa0ad29c93dde9d9fd5454ce4a9112b6446fe667f5e7ead0c7d085e6988e4e0fcd0fd2ec270e55c5ac91121642ed5", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, DesCBCmulti) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_8, DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CBC_mode, TEST_STRING_8
        , NO_ERROR, "38b949d36ccf3bbc19ab71f4be2baa44975a4b63da299a5bebda3d5c0d8a0242f579cb3648633c67b75a5877847d10b9891e67612922649cbb8"
                    "04520f3074dba3c9d4b4b88bbd7547b6b768dc98421f9ac1cd2731fc85e57c58ff52ad56a47e18765b935cd42a13f3818708df654557d07a29d6f0c7a6cda7c532791ee975848c2a3c14ffd61f953", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, DesCFBmulti) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_8, DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CFB_mode, TEST_STRING_8
        , NO_ERROR, "e24a3239ceda4722a779543cb9f99191b450d44cce1e6797a4235f6522ec40c9b9b24eb5989498d0b6c6e111b8597ca476704c79962b64584ab"
                    "317e3bd1e7437f4f773cc8ab85a3419aa5028ada1aa76acb76f04e201d2f96068a69c411ef7e6562d2eb5062ff5c6acf2f6835eae0e2883cce4f67eefaf75d9c67da499c390228ad84629afc206f3", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, DesOFBmulti) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_8, DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, OFB_mode, TEST_STRING_8
        , NO_ERROR, "e24a3239ceda4722b6e1b3effe6ef31da710f29ad945f35e3f6519254283e84a7fd3665ef18325ae1159ccc9faedcd8a5e35c187c47b71d8004"
                    "f4c998c9c70e8111175b30ce288bacc00845602c4634a94bc3a376aad7e07b4643ebd7246ebc2959778bcfa32c1400a5fa5158a921348732e35087fcca1d73f13952678e3b57c341bd41add02e49f", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, DesCTRmulti) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_8, DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CTR_mode, TEST_STRING_8
        , NO_ERROR, "e24a3239ceda4722c2b984a4700d821b3867c72f6c5de354aa2cfc1e307ad35d96f1f3cdec821fc7f093a91fb35492d93b37f77d92d895608fb"
                    "bed968479d4471cd2e5f476f156904c4413786dd397d52cdd43335bbf4aeb1035e8aed5b9b3780cef7428ffbb8b89fbec32de02f9d84d36a59d27c5f6d7e0811153b14d2e0cc98b06a7d49d29c319", Encryption_mode);
}

// DES Multi in Place

TEST(ProcessingByBlockCipherEncryptionTest, DesECBmultiinplace) {
    ProcessingByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_8, DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, ECB_mode, nullptr
        , NO_ERROR, "8ca8da07c07a31a13c1de0b35f5eadd88510c2ef3f16ba52a27ba0f3e0cd8a71e4b609239508875599fce69a08adc97a6df6a55be107791a1d2"
                    "6a67e1362c961e39eff3db05aa30baffd676fa3ea9cde9284133c0cd60994789fa0ad29c93dde9d9fd5454ce4a9112b6446fe667f5e7ead0c7d085e6988e4e0fcd0fd2ec270e55c5ac91121642ed5", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, DesCBCmultiinplace) {
    ProcessingByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_8, DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CBC_mode, TEST_STRING_8
        , NO_ERROR, "38b949d36ccf3bbc19ab71f4be2baa44975a4b63da299a5bebda3d5c0d8a0242f579cb3648633c67b75a5877847d10b9891e67612922649cbb8"
                    "04520f3074dba3c9d4b4b88bbd7547b6b768dc98421f9ac1cd2731fc85e57c58ff52ad56a47e18765b935cd42a13f3818708df654557d07a29d6f0c7a6cda7c532791ee975848c2a3c14ffd61f953", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, DesCFBmultiinplace) {
    ProcessingByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_8, DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CFB_mode, TEST_STRING_8
        , NO_ERROR, "e24a3239ceda4722a779543cb9f99191b450d44cce1e6797a4235f6522ec40c9b9b24eb5989498d0b6c6e111b8597ca476704c79962b64584ab"
                    "317e3bd1e7437f4f773cc8ab85a3419aa5028ada1aa76acb76f04e201d2f96068a69c411ef7e6562d2eb5062ff5c6acf2f6835eae0e2883cce4f67eefaf75d9c67da499c390228ad84629afc206f3", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, DesOFBmultiinplace) {
    ProcessingByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_8, DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, OFB_mode, TEST_STRING_8
        , NO_ERROR, "e24a3239ceda4722b6e1b3effe6ef31da710f29ad945f35e3f6519254283e84a7fd3665ef18325ae1159ccc9faedcd8a5e35c187c47b71d8004"
                    "f4c998c9c70e8111175b30ce288bacc00845602c4634a94bc3a376aad7e07b4643ebd7246ebc2959778bcfa32c1400a5fa5158a921348732e35087fcca1d73f13952678e3b57c341bd41add02e49f", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, DesCTRmultiinplace) {
    ProcessingByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_8, DES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CTR_mode, TEST_STRING_8
        , NO_ERROR, "e24a3239ceda4722c2b984a4700d821b3867c72f6c5de354aa2cfc1e307ad35d96f1f3cdec821fc7f093a91fb35492d93b37f77d92d895608fb"
                    "bed968479d4471cd2e5f476f156904c4413786dd397d52cdd43335bbf4aeb1035e8aed5b9b3780cef7428ffbb8b89fbec32de02f9d84d36a59d27c5f6d7e0811153b14d2e0cc98b06a7d49d29c319", Encryption_mode);
}

// DES Multipart

TEST(ProcessingByBlockCipherEncryptionTest, DesECBmultipart) {
    ProcessingByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, KEY_8, DES_cipher_type, ECB_mode, nullptr
        , "b622571988bf2347b9e98a3c77a51086", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, DesCBCmultipart) {
    ProcessingByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, KEY_8, DES_cipher_type, CBC_mode, TEST_STRING_8
        , "a70f16366ea7f346bf1b15da2429a772", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, DesCFBmultipart) {
    ProcessingByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, KEY_8, DES_cipher_type, CFB_mode, TEST_STRING_8
        ,  "c54d3a7ce3d64d23f9c975ae8097805a", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, DesOFBmultipart) {
    ProcessingByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, KEY_8, DES_cipher_type, OFB_mode, TEST_STRING_8
        , "c54d3a7ce3d64d2390e8b6bc9769e673", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, DesCTRmultipart) {
    ProcessingByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, KEY_8, DES_cipher_type, CTR_mode, TEST_STRING_8
        , "c54d3a7ce3d64d23e4b081f7190a9775", Encryption_mode);
}

// 3DES Single

TEST(ProcessingByBlockCipherEncryptionTest, TdesECBsingle) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, KEY_24, TDES_cipher_type, DES_BLOCK_SIZE, ECB_mode, nullptr
        , NO_ERROR, "d8a2721ab3f542cb", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, TdesCBCsingle) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, KEY_24, TDES_cipher_type, DES_BLOCK_SIZE, CBC_mode, TEST_STRING_8
        , NO_ERROR, "075e74323668642d", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, TdesCFBsingle) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, KEY_24, TDES_cipher_type, DES_BLOCK_SIZE, CFB_mode, TEST_STRING_8
        , NO_ERROR, "2263e26f84a9165f", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, TdesOFBsingle) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, KEY_24, TDES_cipher_type, DES_BLOCK_SIZE, OFB_mode, TEST_STRING_8
        , NO_ERROR, "2263e26f84a9165f", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, TdesCTRsingle) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_7, 7, PKCSN7_padding, KEY_24, TDES_cipher_type, DES_BLOCK_SIZE, CTR_mode, TEST_STRING_8
        , NO_ERROR, "2263e26f84a9165f", Encryption_mode);
}

// 3DES Multi

TEST(ProcessingByBlockCipherEncryptionTest, TdesECBmulti) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_24, TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, ECB_mode, nullptr
        , NO_ERROR, "3933842094a7bed7784ad34d8ac29c73b1e6f7b64205e89077fc45e6da0dc73047807cdcf29133f2d7b2ba13baa8af1ec078c79c07cd773d2d1" 
                    "0ceabdadbdd1f234bdb9a0a882e027f78ed91279fecb246fb170987fcefa8e4cb1e05850ec8744fccb5556052b1ca04e7ede117b83526550cf1519bdb3cfa1466de5e8178a758adff9406fb2aa6d7", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, TdesCBCmulti) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_24, TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CBC_mode, TEST_STRING_8
        , NO_ERROR, "ba1976b002c886673370a0014d1bc216e445c728afae86dcd23abb2c02f282b25ac6d7cc245336d6d5d3a9f4973b87b68b1cbde6828d3dee296" 
                    "a5bca512713e51591e7bf049c825929a70530697cf9d5013b87424cf589d28b2a833adbbf6cbecb5be03b06d696424fa84d72d64adcaa40e27dd4571ec5a4f6513fa95eaed8cec5ff7d1b60d8f963", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, TdesCFBmulti) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_24, TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CFB_mode, TEST_STRING_8
        , NO_ERROR, "2263ee3ce2a5013b2008cc55336536b911aba94c7f3e96240ec9960c4e1316235688a15c369e9f2b919fc49ef1259d0160c89be6a7adcc4bec0" 
                    "de6ae5e270f33c60f1751c6fe231d9652d0d51bd798494d6cd7859036e42d3491099b4209d7a02153175c62dbf0090ee9c3c4405f1e95c144a9008287792510e9ccf4a4a02640402ff0e68dd55c92", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, TdesOFBmulti) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_24, TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, OFB_mode, TEST_STRING_8
        , NO_ERROR, "2263ee3ce2a5013b806dd21b9e62e7a0fb964dee8a52cd0b64d2c1bee79af825fce933498467e3e8b80ed49defaade868ca96aac43356b100f8" 
                    "2a99365656d8c36034615eb0d68aa3a19efee2d58b9d2ea8f7e72047ecafdad16f7fd1707effde188612c2bb1fdb0c53a57232aa548ede2e10858c82e2eb33df59c3e065b256b0426cb618b5db43c", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, TdesCTRmulti) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_24, TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CTR_mode, TEST_STRING_8
        , NO_ERROR, "2263ee3ce2a5013bfa8726195a4aa657402761eda98c6382dcc224071aa502d7f9d40f0324caa54dd83da170bec685f2be4ceff7a33318ae4d8" 
                    "52b83df238f9075c340787b2c1339275b3faae567a167266f349c6fe937d2f2203afef3a09a7dda329a2da3712024d17473f9acaebc03e984c6045a1a7a8dfbe2b8c333f2508301d1bfd0287b3b0c", Encryption_mode);
}

// 3DES Multi in Place

TEST(ProcessingByBlockCipherEncryptionTest, TdesECBmultiinplace) {
    ProcessingByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_24, TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, ECB_mode, nullptr
        , NO_ERROR, "3933842094a7bed7784ad34d8ac29c73b1e6f7b64205e89077fc45e6da0dc73047807cdcf29133f2d7b2ba13baa8af1ec078c79c07cd773d2d1"
                    "0ceabdadbdd1f234bdb9a0a882e027f78ed91279fecb246fb170987fcefa8e4cb1e05850ec8744fccb5556052b1ca04e7ede117b83526550cf1519bdb3cfa1466de5e8178a758adff9406fb2aa6d7", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, TdesCBCmultiinplace) {
    ProcessingByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_24, TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CBC_mode, TEST_STRING_8
        , NO_ERROR, "ba1976b002c886673370a0014d1bc216e445c728afae86dcd23abb2c02f282b25ac6d7cc245336d6d5d3a9f4973b87b68b1cbde6828d3dee296"
                    "a5bca512713e51591e7bf049c825929a70530697cf9d5013b87424cf589d28b2a833adbbf6cbecb5be03b06d696424fa84d72d64adcaa40e27dd4571ec5a4f6513fa95eaed8cec5ff7d1b60d8f963", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, TdesCFBmultiinplace) {
    ProcessingByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_24, TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CFB_mode, TEST_STRING_8
        , NO_ERROR, "2263ee3ce2a5013b2008cc55336536b911aba94c7f3e96240ec9960c4e1316235688a15c369e9f2b919fc49ef1259d0160c89be6a7adcc4bec0"
                    "de6ae5e270f33c60f1751c6fe231d9652d0d51bd798494d6cd7859036e42d3491099b4209d7a02153175c62dbf0090ee9c3c4405f1e95c144a9008287792510e9ccf4a4a02640402ff0e68dd55c92", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, TdesOFBmultiinplace) {
    ProcessingByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_24, TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, OFB_mode, TEST_STRING_8
        , NO_ERROR, "2263ee3ce2a5013b806dd21b9e62e7a0fb964dee8a52cd0b64d2c1bee79af825fce933498467e3e8b80ed49defaade868ca96aac43356b100f8"
                    "2a99365656d8c36034615eb0d68aa3a19efee2d58b9d2ea8f7e72047ecafdad16f7fd1707effde188612c2bb1fdb0c53a57232aa548ede2e10858c82e2eb33df59c3e065b256b0426cb618b5db43c", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, TdesCTRmultiinplace) {
    ProcessingByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_24, TDES_cipher_type, sizeof(TEST_STRING_128) - 1 + DES_BLOCK_SIZE, CTR_mode, TEST_STRING_8
        , NO_ERROR, "2263ee3ce2a5013bfa8726195a4aa657402761eda98c6382dcc224071aa502d7f9d40f0324caa54dd83da170bec685f2be4ceff7a33318ae4d8"
                    "52b83df238f9075c340787b2c1339275b3faae567a167266f349c6fe937d2f2203afef3a09a7dda329a2da3712024d17473f9acaebc03e984c6045a1a7a8dfbe2b8c333f2508301d1bfd0287b3b0c", Encryption_mode);
}

// 3DES Multipart

TEST(ProcessingByBlockCipherEncryptionTest, TdesECBmultipart) {
    ProcessingByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, KEY_24, TDES_cipher_type, ECB_mode, nullptr
        , "760b8b1ca4c0655ed8a2721ab3f542cb", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, TdesCBCmultipart) {
    ProcessingByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, KEY_24, TDES_cipher_type, CBC_mode, TEST_STRING_8
        , "9424ebd9f5942c845111f237a9762073", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, TdesCFBmultipart) {
    ProcessingByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, KEY_24, TDES_cipher_type, CFB_mode, TEST_STRING_8
        , "0564e679cfa90b3a2deac33c78bd4ec3", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, TdesOFBmultipart) {
    ProcessingByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, KEY_24, TDES_cipher_type, OFB_mode, TEST_STRING_8
        , "0564e679cfa90b3aa664d748f765f2ce", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, TdesCTRmultipart) {
    ProcessingByBlockCipherMultipartTestFunc(TEST_STRING_8, 8, TEST_STRING_7, 7, PKCSN7_padding, KEY_24, TDES_cipher_type, CTR_mode, TEST_STRING_8
        , "0564e679cfa90b3adc8e234a334db339", Encryption_mode);
}

// AES128 Single

TEST(ProcessingByBlockCipherEncryptionTest, Aes128ECBsingle) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_15, 15, PKCSN7_padding, KEY_16, AES128_cipher_type, AES_BLOCK_SIZE, ECB_mode, nullptr
        , NO_ERROR, "b35e00710a0b578e637a67ce79f81080", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, Aes128CBCsingle) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_15, 15, PKCSN7_padding, KEY_16, AES128_cipher_type, AES_BLOCK_SIZE, CBC_mode, TEST_STRING_16
        , NO_ERROR, "c393f04a988159be12f70315d17da45d", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, Aes128CFBsingle) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_15, 15, PKCSN7_padding, KEY_16, AES128_cipher_type, AES_BLOCK_SIZE, CFB_mode, TEST_STRING_16
        , NO_ERROR, "ac8e3a20c3d8edc9fa227a110686d908", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, Aes128OFBsingle) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_15, 15, PKCSN7_padding, KEY_16, AES128_cipher_type, AES_BLOCK_SIZE, OFB_mode, TEST_STRING_16
        , NO_ERROR, "ac8e3a20c3d8edc9fa227a110686d908", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, Aes128CTRsingle) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_15, 15, PKCSN7_padding, KEY_16, AES128_cipher_type, AES_BLOCK_SIZE, CTR_mode, TEST_STRING_16
        , NO_ERROR, "ac8e3a20c3d8edc9fa227a110686d908", Encryption_mode);
}

// AES128 Multi

TEST(ProcessingByBlockCipherEncryptionTest, Aes128ECBmulti) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_16, AES128_cipher_type, sizeof(TEST_STRING_128) - 1 + AES_BLOCK_SIZE, ECB_mode, nullptr
        , NO_ERROR, "84a07604e5d77700ce6038fb29ebdc9ee1d024b49907cd8fad94a73f589f01d2fc5213b0c079eb1166be71ba955f3a92210e41a6c09e2c9e906ca54dfc9dbd1097ec17283daa662c"
                    "56d26116cb801720934ad14af9dd0d6e5649be69bdbda792141d4e4e2cd5160ccaa0460e40573c48d61dca9bff19cb60d21bfd5fbf5adc74fd2583a4301513e0e795d98d6fe11c1e", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, Aes128CBCmulti) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_16, AES128_cipher_type, sizeof(TEST_STRING_128) - 1 + AES_BLOCK_SIZE, CBC_mode, TEST_STRING_16
        , NO_ERROR, "fda6d08b9161d3d99e9fc20a5ea6431d06ef9a7203ad84428133b219752c73d342ef1a38d545a72fde839a741efd00c104ab1c70a121ae2e7cec151901a201cf6c8ebc07a2b166e8"
                    "291aadcf9a1a2ee7d2221044cc17606c6502fb381fefb18bd66527ec8b8e8fd9daff58858fd446c1f2c42b74c7096becc307b7694600fb02c03655795f56f862806f6c2cd6dbc058", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, Aes128CFBmulti) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_16, AES128_cipher_type, sizeof(TEST_STRING_128) - 1 + AES_BLOCK_SIZE, CFB_mode, TEST_STRING_16
        , NO_ERROR, "ac8e3a20e6d2edc9a8377e503bc8da6677617c1a4afc4cae7f7b14bc57bdf83383e90823bf6f3dae42853019dea9a472d67cf293df069450589371af0d7c577fdd98674c50596268"
                    "b7353547f87976c6d4eb4da3b53b844410087c239a5ad29c79ffad2ccef194bbce068c4b79f92a87b2300ea14a01967b467d5ffc92bcce545102d3ab0bd518b12ae8c66f9aa726bf", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, Aes128OFBmulti) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_16, AES128_cipher_type, sizeof(TEST_STRING_128) - 1 + AES_BLOCK_SIZE, OFB_mode, TEST_STRING_16
        , NO_ERROR, "ac8e3a20e6d2edc9a8377e503bc8da662dffcff4c40c795e934eb8d5223ca362eb9882f577b44bbf4456b789f7c9c7d93544b684cf3071b0d9ec6427f87778ff05be288b2342f855"
                    "1caf74cbb7390504e1b32e8ac759953177e87870909a1a9a0cb2341afdbda85904e98149efc2c50fb291341e9dad065eeb42c00bc387befbe5e2f4d526bcca85154988e3d23abb75", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, Aes128CTRmulti) {
    ProcessingByBlockCipherTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_16, AES128_cipher_type, sizeof(TEST_STRING_128) - 1 + AES_BLOCK_SIZE, CTR_mode, TEST_STRING_16
        , NO_ERROR, "ac8e3a20e6d2edc9a8377e503bc8da66999e234f2dd0cdad2b96ae57af3cbb86d89cc1e09979aa71c87e5e9aa58f60fbf83ec3113bd1909d5975e1a4d2797e23a385122f0bda57c8"
                    "2fdecc14123d8aa365a4945228ee8fc41e09f38b85ac924bb6c52fbe59a85f8dfeb772f5a5047848d718385d0f11940c50792f2099e60c5ab632329ac130c64e37d357ed466ae265", Encryption_mode);
}

// AES128 Multi in Place

TEST(ProcessingByBlockCipherEncryptionTest, Aes128ECBmultiinplace) {
    ProcessingByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_16, AES128_cipher_type, sizeof(TEST_STRING_128) - 1 + AES_BLOCK_SIZE, ECB_mode, nullptr
        , NO_ERROR, "84a07604e5d77700ce6038fb29ebdc9ee1d024b49907cd8fad94a73f589f01d2fc5213b0c079eb1166be71ba955f3a92210e41a6c09e2c9e906ca54dfc9dbd1097ec17283daa662c"
                    "56d26116cb801720934ad14af9dd0d6e5649be69bdbda792141d4e4e2cd5160ccaa0460e40573c48d61dca9bff19cb60d21bfd5fbf5adc74fd2583a4301513e0e795d98d6fe11c1e", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, Aes128CBCmultiinplace) {
    ProcessingByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_16, AES128_cipher_type, sizeof(TEST_STRING_128) - 1 + AES_BLOCK_SIZE, CBC_mode, TEST_STRING_16
        , NO_ERROR, "fda6d08b9161d3d99e9fc20a5ea6431d06ef9a7203ad84428133b219752c73d342ef1a38d545a72fde839a741efd00c104ab1c70a121ae2e7cec151901a201cf6c8ebc07a2b166e8"
                    "291aadcf9a1a2ee7d2221044cc17606c6502fb381fefb18bd66527ec8b8e8fd9daff58858fd446c1f2c42b74c7096becc307b7694600fb02c03655795f56f862806f6c2cd6dbc058", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, Aes128CFBmultiinplace) {
    ProcessingByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_16, AES128_cipher_type, sizeof(TEST_STRING_128) - 1 + AES_BLOCK_SIZE, CFB_mode, TEST_STRING_16
        , NO_ERROR, "ac8e3a20e6d2edc9a8377e503bc8da6677617c1a4afc4cae7f7b14bc57bdf83383e90823bf6f3dae42853019dea9a472d67cf293df069450589371af0d7c577fdd98674c50596268"
                    "b7353547f87976c6d4eb4da3b53b844410087c239a5ad29c79ffad2ccef194bbce068c4b79f92a87b2300ea14a01967b467d5ffc92bcce545102d3ab0bd518b12ae8c66f9aa726bf", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, Aes128OFBmultiinplace) {
    ProcessingByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_16, AES128_cipher_type, sizeof(TEST_STRING_128) - 1 + AES_BLOCK_SIZE, OFB_mode, TEST_STRING_16
        , NO_ERROR, "ac8e3a20e6d2edc9a8377e503bc8da662dffcff4c40c795e934eb8d5223ca362eb9882f577b44bbf4456b789f7c9c7d93544b684cf3071b0d9ec6427f87778ff05be288b2342f855"
                    "1caf74cbb7390504e1b32e8ac759953177e87870909a1a9a0cb2341afdbda85904e98149efc2c50fb291341e9dad065eeb42c00bc387befbe5e2f4d526bcca85154988e3d23abb75", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, Aes128CTRmultiinplace) {
    ProcessingByBlockCipherInPlaceTestFunc(TEST_STRING_128, 128, PKCSN7_padding, KEY_16, AES128_cipher_type, sizeof(TEST_STRING_128) - 1 + AES_BLOCK_SIZE, CTR_mode, TEST_STRING_16
        , NO_ERROR, "ac8e3a20e6d2edc9a8377e503bc8da66999e234f2dd0cdad2b96ae57af3cbb86d89cc1e09979aa71c87e5e9aa58f60fbf83ec3113bd1909d5975e1a4d2797e23a385122f0bda57c8"
                    "2fdecc14123d8aa365a4945228ee8fc41e09f38b85ac924bb6c52fbe59a85f8dfeb772f5a5047848d718385d0f11940c50792f2099e60c5ab632329ac130c64e37d357ed466ae265", Encryption_mode);
}

// AES128 Multipart

TEST(ProcessingByBlockCipherEncryptionTest, Aes128ECBmultipart) {
    ProcessingByBlockCipherMultipartTestFunc(TEST_STRING_16, 16, TEST_STRING_15, 15, PKCSN7_padding, KEY_16, AES128_cipher_type, ECB_mode, nullptr
        , "f8e65f00a0b789acda56127072a6bc09b35e00710a0b578e637a67ce79f81080", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, Aes128CBCmultipart) {
    ProcessingByBlockCipherMultipartTestFunc(TEST_STRING_16, 16, TEST_STRING_15, 15, PKCSN7_padding, KEY_16, AES128_cipher_type, CBC_mode, TEST_STRING_16_2
        , "919da970c956d23c111e4a7f1e89fd8f450815c37cc264c1b5471281e0180cd0", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, Aes128CFBmultipart) {
    ProcessingByBlockCipherMultipartTestFunc(TEST_STRING_16, 16, TEST_STRING_15, 15, PKCSN7_padding, KEY_16, AES128_cipher_type, CFB_mode, TEST_STRING_16_2
        , "c7c1f5eed4aaa93ac1654bc0e47d06524c03c3cb898095f271efb21e7d9dd546", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, Aes128OFBmultipart) {
    ProcessingByBlockCipherMultipartTestFunc(TEST_STRING_16, 16, TEST_STRING_15, 15, PKCSN7_padding, KEY_16, AES128_cipher_type, OFB_mode, TEST_STRING_16_2
        , "c7c1f5eed4aaa93ac1654bc0e47d06522c31581f939355b5a0f3b7ff3a85f3ae", Encryption_mode);
}

TEST(ProcessingByBlockCipherEncryptionTest, Aes128CTRmultipart) {
    ProcessingByBlockCipherMultipartTestFunc(TEST_STRING_16, 16, TEST_STRING_15, 15, PKCSN7_padding, KEY_16, AES128_cipher_type, CTR_mode, TEST_STRING_16_2
        , "c7c1f5eed4aaa93ac1654bc0e47d0652fca796d915ccd44eca17580d1adb5877", Encryption_mode);
}
