//  GetHashT.cpp
//

#include "pch.h"

#include "common.h"

void GetHashMainTestFunc(__in const void* input, __in uint64_t inputSize, __in HashFunc func, __in int expectedStatus, __in_opt const void* expectedRes)
{
    int status = NO_ERROR;
    size_t outputSize = g_hashFuncsSizesMapping[func].didgestSize;
    std::unique_ptr<uint8_t> buffer(new uint8_t[outputSize]);
    HashHandle handle = NULL;
    EVAL(InitHashState(&handle, func));
    EVAL(GetHash(handle, buffer.get(), input, inputSize, true));

exit:
    FreeHashState(handle);

    if (expectedRes) {
        std::string result = GetHexResult(buffer.get(), outputSize);
        std::string expRes((const char*)expectedRes);
        EXPECT_EQ(result, expRes);
    }

    EXPECT_TRUE(status == expectedStatus);
}

void GetHashMultipleTestFunc(__in const void* input1, __in uint64_t inputSize1, __in const void* input2, __in uint64_t inputSize2, __in HashFunc func,
    __in int expectedStatus, __in_opt const void* expectedRes)
{
    int status = NO_ERROR;
    size_t outputSize = g_hashFuncsSizesMapping[func].didgestSize;
    std::unique_ptr<uint8_t> buffer(new uint8_t[outputSize]);
    HashHandle handle = NULL;
    EVAL(InitHashState(&handle, func));
    EVAL(GetHash(handle, nullptr, input1, inputSize1, false));
    EVAL(GetHash(handle, buffer.get(), input2, inputSize2, true));

exit:
    FreeHashState(handle);

    if (expectedRes) {
        std::string result = GetHexResult(buffer.get(), outputSize);
        std::string expRes((const char*)expectedRes);
        EXPECT_EQ(result, expRes);
    }
    else

    EXPECT_TRUE(status == expectedStatus);
}

// Wrong arguments

TEST(GetHashTest, WrongState) {
    int status = NO_ERROR;
    std::unique_ptr<uint8_t> buffer(nullptr);
    status = GetHash(nullptr, buffer.get(), "", 0, true);
    EXPECT_TRUE(status == ERROR_WRONG_STATE_HANDLE);
}

TEST(GetHashTest, WrongOutput) {
    int status = NO_ERROR;
    HashHandle handle = nullptr;
    InitHashState(&handle, SHA_224);
    status = GetHash(handle, nullptr, "", 0, true);
    FreeHashState(handle);
    EXPECT_TRUE(status == ERROR_WRONG_OUTPUT);
}

TEST(GetHashTest, WrongInput) {
    GetHashMainTestFunc(nullptr, 55, SHA1, ERROR_WRONG_INPUT, nullptr);
}

TEST(GetHashTest, WrongInputSize) {
    int status = NO_ERROR;
    HashHandle handle = nullptr;
    std::unique_ptr<uint8_t> buffer(new uint8_t[1]);

    InitHashState(&handle, SHA1);
    status = GetHash(handle, buffer.get(), "", 55, false);
    FreeHashState(handle);
    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);

    InitHashState(&handle, SHA_224);
    status = GetHash(handle, buffer.get(), "", 55, false);
    FreeHashState(handle);
    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);

    InitHashState(&handle, SHA_256);
    status = GetHash(handle, buffer.get(), "", 55, false);
    FreeHashState(handle);
    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);

    InitHashState(&handle, SHA_384);
    status = GetHash(handle, buffer.get(), "", 55, false);
    FreeHashState(handle);
    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);

    InitHashState(&handle, SHA_512_224);
    status = GetHash(handle, buffer.get(), "", 55, false);
    FreeHashState(handle);
    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);

    InitHashState(&handle, SHA_512_256);
    status = GetHash(handle, buffer.get(), "", 55, false);
    FreeHashState(handle);
    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);

    InitHashState(&handle, SHA_512);
    status = GetHash(handle, buffer.get(), "", 55, false);
    FreeHashState(handle);
    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);

    InitHashState(&handle, SHA3_224);
    status = GetHash(handle, buffer.get(), "", 55, false);
    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
    FreeHashState(handle);

    InitHashState(&handle, SHA3_256);
    status = GetHash(handle, buffer.get(), "", 55, false);
    FreeHashState(handle);
    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);

    InitHashState(&handle, SHA3_384);
    status = GetHash(handle, buffer.get(), "", 55, false);
    FreeHashState(handle);
    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);

    InitHashState(&handle, SHA3_512);
    status = GetHash(handle, buffer.get(), "", 55, false);
    FreeHashState(handle);
    EXPECT_TRUE(status == ERROR_WRONG_INPUT_SIZE);
}

// Main test
// 1 - full one block (== input + padding) testing
// 2 - full one block + one byte == two blocks testing
// 3 - two blocks testing
// 4 - tree plus blocks testing
// 5 - empty string testing
// 6 - multiple test

// SHA1

TEST(GetHashTest, SHA1OneBlock) {
    GetHashMainTestFunc(TEST_STRING_55, 55, SHA1, NO_ERROR, "788283554b3e5624465bea7faccbd35e4fa5e69a");
}

TEST(GetHashTest, SHA1TwoBlocksEdge) {
    GetHashMainTestFunc(TEST_STRING_56, 56, SHA1, NO_ERROR, "0dce05c502cb6109450a96db539317621ad060f5");
}

TEST(GetHashTest, SHA1TwoBlocks) {
    GetHashMainTestFunc(TEST_STRING_65, 65, SHA1, NO_ERROR, "36e84bd69dd58be92872fc098f018f7cbcd7320f");
}

TEST(GetHashTest, SHA1ThreePlusBlocks) {
    GetHashMainTestFunc(TEST_STRING_513, 513, SHA1, NO_ERROR, "51d952049de40ad88a950c006f26a570a851b0d5");
}

TEST(GetHashTest, SHA1Empty) {
    GetHashMainTestFunc("", 0, SHA1, NO_ERROR, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

TEST(GetHashTest, SHA1Multiple) {
    GetHashMultipleTestFunc(TEST_STRING_64, 64, TEST_STRING_7, 7, SHA1, NO_ERROR, "0b9c93866279761317de745e1389fc14fb1d5897");
}

// SHA_224

TEST(GetHashTest, SHA224OneBlock) {
    GetHashMainTestFunc(TEST_STRING_55, 55, SHA_224, NO_ERROR, "f42efda622936572b6cbdbbf1d788b39028de7558a9d5983b3246c9e");
}

TEST(GetHashTest, SHA224TwoBlocksEdge) {
    GetHashMainTestFunc(TEST_STRING_56, 56, SHA_224, NO_ERROR, "b56a99317a53178efdc371a2550c7572801700529a22ca909da422eb");
}

TEST(GetHashTest, SHA224TwoBlocks) {
    GetHashMainTestFunc(TEST_STRING_65, 65, SHA_224, NO_ERROR, "a6c4b53217c6aa44fdc1d4b3f2f764cc34a69894bd8e804ae86c3a53");
}

TEST(GetHashTest, SHA224ThreePlusBlocks) {
    GetHashMainTestFunc(TEST_STRING_513, 513, SHA_224, NO_ERROR, "474b265cedf686a5507ec156b96f6d43972aed4ce30cbf2c242f16c5");
}

TEST(GetHashTest, SHA224Empty) {
    GetHashMainTestFunc("", 0, SHA_224, NO_ERROR, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
}

TEST(GetHashTest, SHA224Multiple) {
    GetHashMultipleTestFunc(TEST_STRING_64, 64, TEST_STRING_7, 7, SHA_224, NO_ERROR, "18fbd6c4f971fc76b5afee284435806860a6b075eed50544fe942890");
}

// SHA_256

TEST(GetHashTest, SHA256Oneblock) {
    GetHashMainTestFunc(TEST_STRING_55, 55, SHA_256, NO_ERROR, "63928216d8be268f9f700ee984bd45775aa4a9639ea89521289b0f59b56e9a05");
}

TEST(GetHashTest, SHA256TwoBlocksEdge) {
    GetHashMainTestFunc(TEST_STRING_56, 56, SHA_256, NO_ERROR, "f7e76c1079ad43073905cb98fe78bcd6a3e486e5e9a29c4ca81643a38a619fd9");
}

TEST(GetHashTest, SHA256TwoBlocks) {
    GetHashMainTestFunc(TEST_STRING_65, 65, SHA_256, NO_ERROR, "805d67eb01f3bd011c7f36f4b3da9031b91b02f438ae50cd18c355afc25d208e");
}

TEST(GetHashTest, SHA256ThreePlusBlocks) {
    GetHashMainTestFunc(TEST_STRING_513, 513, SHA_256, NO_ERROR, "4cc048c062a093087e209f10959fb9bd311d2958990ef5211c2a09836e7dd8c0");
}

TEST(GetHashTest, SHA256Empty) {
    GetHashMainTestFunc("", 0, SHA_256, NO_ERROR, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(GetHashTest, SHA256Multiple) {
    GetHashMultipleTestFunc(TEST_STRING_64, 64, TEST_STRING_7, 7, SHA_256, NO_ERROR, "43e172404b346fc0ab5d939fd2db8219820ce0d55a0099649ec317ebee84f4ab");
}

// SHA_384

TEST(GetHashTest, SHA384Oneblock) {
    GetHashMainTestFunc(TEST_STRING_111, 111, SHA_384, NO_ERROR, "592671d8fcd41813cb7885d47bf158631ca0a0dfdcdacf47f77f178a5ac8c926caf722bb769b0e1eb8fd2568adce8b01");
}

TEST(GetHashTest, SHA384TwoBlocksEdge) {
    GetHashMainTestFunc(TEST_STRING_112, 112, SHA_384, NO_ERROR, "f250cd74e472b2b137547a3cd3d7b26649f496c835cd667b2ca939df45d602aa3698cf18c81944a29c1591fbf50c7128");
}

TEST(GetHashTest, SHA384TwoBlocks) {
    GetHashMainTestFunc(TEST_STRING_129, 129, SHA_384, NO_ERROR, "349f8174a0c87b704a2fe3fdf776ce61212a76c25b3863c4ffdaed823c290aec23e5b575dadb73cc44ca427065392608");
}

TEST(GetHashTest, SHA384ThreePlusBlocks) {
    GetHashMainTestFunc(TEST_STRING_513, 513, SHA_384, NO_ERROR, "4d4818a4b861104a52b3e25729ca0aad6466a16d2325a99abf4bd65e552ea9e894342e6a693ed411f12111f77fef1c73");
}

TEST(GetHashTest, SHA384Empty) {
    GetHashMainTestFunc("", 0, SHA_384, NO_ERROR, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
}

TEST(GetHashTest, SHA384Multiple) {
    GetHashMultipleTestFunc(TEST_STRING_128, 128, TEST_STRING_7, 7, SHA_384, NO_ERROR, "ac28f5846b0f8897e2f3f524fb13f3d39260bb22baf2e1cc7320e2adde65733841a10b47dbe3642d6a88ef4bd682e9da");
}

// SHA_512_224

TEST(GetHashTest, SHA512224Oneblock) {
    GetHashMainTestFunc(TEST_STRING_111, 111, SHA_512_224, NO_ERROR, "e2e1efb2bd9349b4127af3008615aba325a8c2845d7b8dc05b7cefec");
}

TEST(GetHashTest, SHA512224TwoBlocksEdge) {
    GetHashMainTestFunc(TEST_STRING_112, 112, SHA_512_224, NO_ERROR, "01ab1f27fe41644cb178d160b0165d2b56ab768a7ef0306784dad21a");
}

TEST(GetHashTest, SHA512224TwoBlocks) {
    GetHashMainTestFunc(TEST_STRING_129, 129, SHA_512_224, NO_ERROR, "7ae594a1ea9b6a3607c282a192585f32c5c58fe3af359653407c546a");
}

TEST(GetHashTest, SHA512224ThreePlusBlocks) {
    GetHashMainTestFunc(TEST_STRING_513, 513, SHA_512_224, NO_ERROR, "f112d0281f3ecc0621a1e8b489d3b0cb3dbf16f918969f95771c950c");
}

TEST(GetHashTest, SHA512224Empty) {
    GetHashMainTestFunc("", 0, SHA_512_224, NO_ERROR, "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
}

TEST(GetHashTest, SHA512224Multiple) {
    GetHashMultipleTestFunc(TEST_STRING_128, 128, TEST_STRING_7, 7, SHA_512_224, NO_ERROR, "3923eff7aa720037ff886f5816e7da70dd38f590f75bdd5575dfd9e5");
}

// SHA_512_256

TEST(GetHashTest, SHA512256Oneblock) {
    GetHashMainTestFunc(TEST_STRING_111, 111, SHA_512_256, NO_ERROR, "97db84eab9593a2895685f7e9402351186f330946fcd34942805dc20b1de249e");
}

TEST(GetHashTest, SHA512256TwoBlocksEdge) {
    GetHashMainTestFunc(TEST_STRING_112, 112, SHA_512_256, NO_ERROR, "83cf580ac27ef74ca00074df83e63e4c2acefecd412bbe2ab8d19df6454b50d4");
}

TEST(GetHashTest, SHA512256TwoBlocks) {
    GetHashMainTestFunc(TEST_STRING_129, 129, SHA_512_256, NO_ERROR, "062bc8c9a5107dd3164348ec5575df285f52f357a52ab806b8e6a31a936eb1c8");
}

TEST(GetHashTest, SHA512256ThreePlusBlocks) {
    GetHashMainTestFunc(TEST_STRING_513, 513, SHA_512_256, NO_ERROR, "1f347c3060a8b67d92343aa8cff82f906c35af631ce7e4312b7bdd6034fcbf97");
}

TEST(GetHashTest, SHA512256Empty) {
    GetHashMainTestFunc("", 0, SHA_512_256, NO_ERROR, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
}

TEST(GetHashTest, SHA512256Multiple) {
    GetHashMultipleTestFunc(TEST_STRING_128, 128, TEST_STRING_7, 7, SHA_512_256, NO_ERROR, "c083b69c677d22e6d6e2e87479e0381e18dffa09590e5306db087d521889d92b");
}

// SHA_512

TEST(GetHashTest, SHA512Oneblock) {
    GetHashMainTestFunc(TEST_STRING_111, 111, SHA_512, NO_ERROR, "b1dd9abad41141faca005751488b468c67fdb6b0a699ac462ea7b8e05410d5704794eb4e1d3518e702d01c6027ef95f8d31414e8d114729f6c8f815a40db9a2b");
}

TEST(GetHashTest, SHA512TwoBlocksEdge) {
    GetHashMainTestFunc(TEST_STRING_112, 112, SHA_512, NO_ERROR, "cf2b9e638e8c51eae229b6b1313826d1371fcd4c2ba0abe420b4f85f2ed999a6f39a7f94422a46bbfdac8592d39efeb4fef01523d8bb098bdc888db7adb6fa92");
}

TEST(GetHashTest, SHA512TwoBlocks) {
    GetHashMainTestFunc(TEST_STRING_129, 129, SHA_512, NO_ERROR, "d91f475271657357427fb50334fc18d509801d70a224f9606ce8db09ed945e57c078842f766898b91efe6644369a2e808e2344d2a63805be3bac3ea44c74e755");
}

TEST(GetHashTest, SHA512ThreePlusBlocks) {
    GetHashMainTestFunc(TEST_STRING_513, 513, SHA_512, NO_ERROR, "e3f84efbb63e886a303e4f7f7f1da1c0e4b0dffe3dc538bba8afca32fb4397cd9fe4a43210e4ad97f505c8a615061875e31714f53e8f8a04c7502c5a75222360");
}

TEST(GetHashTest, SHA512Empty) {
    GetHashMainTestFunc("", 0, SHA_512, NO_ERROR, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

TEST(GetHashTest, SHA512Multiple) {
    GetHashMultipleTestFunc(TEST_STRING_128, 128, TEST_STRING_7, 7, SHA_512, NO_ERROR, "2a0e5bba07920ae55654d8d2e3de9a813a96ed3e5a8d5d5e35b26586c4008611a867307bdb4822b40896209862e729fd62d030e3a1a8ba938f119e67877b53e0");
}

// SHA3_224

TEST(GetHashTest, SHA3224Oneblock) {
    GetHashMainTestFunc(TEST_STRING_143, 143, SHA3_224, NO_ERROR, "dde1d7550f1c1eae68158d3bb4224fca878d44e0dd2dd5e042eaa730");
}

TEST(GetHashTest, SHA3224TwoBlocksEdge) {
    GetHashMainTestFunc(TEST_STRING_144, 144, SHA3_224, NO_ERROR, "cfac1ceed1ec81fa1f9d630b7c130f2e152a36edd329123eeb389998");
}

TEST(GetHashTest, SHA3224TwoBlocks) {
    GetHashMainTestFunc(TEST_STRING_145, 145, SHA3_224, NO_ERROR, "45314ecb5a664ee11982907d27fe8920551bb21113fd7b0899d4bb4b");
}

TEST(GetHashTest, SHA3224ThreePlusBlocks) {
    GetHashMainTestFunc(TEST_STRING_513, 513, SHA3_224, NO_ERROR, "7f0f77cdc3bb1aac48c93e1c4a4f157982774e411ff745c10e6fb537");
}

TEST(GetHashTest, SHA3224Empty) {
    GetHashMainTestFunc("", 0, SHA3_224, NO_ERROR, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
}

TEST(GetHashTest, SHA3224Multiple) {
    GetHashMultipleTestFunc(TEST_STRING_144, 144, TEST_STRING_7, 7, SHA3_224, NO_ERROR, "e5f77eaeffd00de3ecd2a209ba376f7b969af727f5553b39bdbe128e");
}


// SHA3_256

TEST(GetHashTest, SHA3256Oneblock) {
    GetHashMainTestFunc(TEST_STRING_135, 135, SHA3_256, NO_ERROR, "ecc422c8c0919a3789ec65bc161b2ec0059ba0ae5596b6098ac0800c139d4fc4");
}

TEST(GetHashTest, SHA3256TwoBlocksEdge) {
    GetHashMainTestFunc(TEST_STRING_136, 136, SHA3_256, NO_ERROR, "17209330cc1cfaf85a36c3e631c723ea4cd852a1cf9be52ea607cf28ff257366");
}

TEST(GetHashTest, SHA3256TwoBlocks) {
    GetHashMainTestFunc(TEST_STRING_137, 137, SHA3_256, NO_ERROR, "3adccf9bc44f0054341a126b91303ea8ab4a08e84c8bd1a6ddd9a54f0360fc51");
}

TEST(GetHashTest, SHA3256ThreePlusBlocks) {
    GetHashMainTestFunc(TEST_STRING_513, 513, SHA3_256, NO_ERROR, "d553931ee68093100d83727bcf7b644111434b309b196fa2fbfce26f632bcdc0");
}

TEST(GetHashTest, SHA3256Empty) {
    GetHashMainTestFunc("", 0, SHA3_256, NO_ERROR, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
}

TEST(GetHashTest, SHA3256Multiple) {
    GetHashMultipleTestFunc(TEST_STRING_136, 136, TEST_STRING_7, 7, SHA3_256, NO_ERROR, "41141e0a58c704ce468297c612c5e34dfb50acf7dd7088c7632980149af26645");
}

// SHA3_384

TEST(GetHashTest, SHA3384Oneblock) {
    GetHashMainTestFunc(TEST_STRING_103, 103, SHA3_384, NO_ERROR, "042f43b2c7541ce4b07c9c22ba65fa8d318b3e8c5637a50afb0af5fcfad0aba266bf9ffb69d35dc3e12437a0a0fef2da");
}

TEST(GetHashTest, SHA3384TwoBlocksEdge) {
    GetHashMainTestFunc(TEST_STRING_104, 104, SHA3_384, NO_ERROR, "85fea65f966e0620af79d65be954d25a421f8c7a4c6a95e454fa130d8e2d3d6a128891956281f1cbe982234890404073");
}

TEST(GetHashTest, SHA3384TwoBlocks) {
    GetHashMainTestFunc(TEST_STRING_105, 105, SHA3_384, NO_ERROR, "2427c969adfb327e50ae6cf653e31166b11ba52c2b0f2f8227266d36480eb360df575787430190a57c4d9ed654e7f451");
}

TEST(GetHashTest, SHA3384ThreePlusBlocks) {
    GetHashMainTestFunc(TEST_STRING_513, 513, SHA3_384, NO_ERROR, "acafd5c8d808cb426ef96ef745ed616c92324c31440047283037fb8ae3bb8fe7b58e5bd1956c0748ad694ff95b3a89c8");
}

TEST(GetHashTest, SHA3384Empty) {
    GetHashMainTestFunc("", 0, SHA3_384, NO_ERROR, "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
}

TEST(GetHashTest, SHA3384Multiple) {
    GetHashMultipleTestFunc(TEST_STRING_104, 104, TEST_STRING_7, 7, SHA3_384, NO_ERROR, "2119f8e30f4a45964558495c467b30f5bddf6a869b76dd033d233fc364308afbb2148339faf0b1e75bfa3bd31ac8f7ba");
}

// SHA3_512

TEST(GetHashTest, SHA3512Oneblock) {
    GetHashMainTestFunc(TEST_STRING_71, 71, SHA3_512, NO_ERROR, "aa1e254c831111c318c2bbd07da1000b053312417582585218697b9dd13b8a9502818a7c627a9ea591094c2fd3a7829d8a3cc3b7979cc4e9e535ff22107c73e4");
}

TEST(GetHashTest, SHA3512TwoBlocksEdge) {
    GetHashMainTestFunc(TEST_STRING_72, 72, SHA3_512, NO_ERROR, "81c4079df448fe8172060b15041571be980918d9614585386dd02568933670d1752b270c84aa8d026fc99863ed1d75f25991e6723fcdf12f07d0ddd83f99c4aa");
}

TEST(GetHashTest, SHA3512TwoBlocks) {
    GetHashMainTestFunc(TEST_STRING_73, 73, SHA3_512, NO_ERROR, "c75fc5c699b3c010f603d04aed344c3509046cede3e1e26743c0de717d67765ff340b2f6f443fa870ce1850919e520799f6a062ea1020b25c04d38ef8349d87b");
}

TEST(GetHashTest, SHA3512ThreePlusBlocks) {
    GetHashMainTestFunc(TEST_STRING_513, 513, SHA3_512, NO_ERROR, "85cbc6c27d713bb7b77a997e740d5285191e6725c79c714ddb4e321745c5c3156e684c9998fcd8e5c13dea6fc9da305de0c6db9a8c1a40c7a7de7d39e1afb79f");
}

TEST(GetHashTest, SHA3512Empty) {
    GetHashMainTestFunc("", 0, SHA3_512, NO_ERROR, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
}

TEST(GetHashTest, SHA3512Multiple) {
    GetHashMultipleTestFunc(TEST_STRING_72, 72, TEST_STRING_7, 7, SHA3_512, NO_ERROR, "46b735b64f820beabf31fdfda931a3549b64da6da96ddee5c97f69796adaf29e4481a3243ea625539f609b8b3beba8c4069309080feed0deeb58a715d2dec528");
}
