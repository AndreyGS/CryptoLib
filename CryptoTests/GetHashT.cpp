#include "pch.h"

#include "common.h"

TEST(GetHashTest, WrongInput) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA1].outputSize];
    int status = GetHash(nullptr, 55, SHA1, buffer);

    EXPECT_TRUE(status == ERROR_WRONG_INPUT);
    delete[] buffer;
}

TEST(GetHashTest, WrongOuput) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA1].outputSize];
    int status = GetHash(TEST_STRING_55, 55, SHA1, nullptr);

    EXPECT_TRUE(status == ERROR_WRONG_OUTPUT);
    delete[] buffer;
}

TEST(GetHashTest, UnknownHashFunc) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA1].outputSize];
    int status = GetHash(TEST_STRING_55, 55, (HashFunc)-1, buffer);

    EXPECT_TRUE(status == ERROR_HASHING_FUNC_NOT_SUPPORTED);
    delete[] buffer;
}

TEST(GetHashTest, Sha_1) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA1].outputSize];
    int status = GetHash(TEST_STRING_55, 55, SHA1, buffer);
    std::string result = GetHexResult(buffer, 20);
    std::string expectingResult = "788283554b3e5624465bea7faccbd35e4fa5e69a";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA_224) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_224].outputSize];
    int status = GetHash(TEST_STRING_55, 55, SHA_224, buffer);
    std::string result = GetHexResult(buffer, 28);
    std::string expectingResult = "f42efda622936572b6cbdbbf1d788b39028de7558a9d5983b3246c9e";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA_256) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_256].outputSize];
    int status = GetHash(TEST_STRING_55, 55, SHA_256, buffer);
    std::string result = GetHexResult(buffer, 32);
    std::string expectingResult = "63928216d8be268f9f700ee984bd45775aa4a9639ea89521289b0f59b56e9a05";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA_384) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_384].outputSize];
    int status = GetHash(TEST_STRING_111, 111, SHA_384, buffer);
    std::string result = GetHexResult(buffer, 48);
    std::string expectingResult = "592671d8fcd41813cb7885d47bf158631ca0a0dfdcdacf47f77f178a5ac8c926caf722bb769b0e1eb8fd2568adce8b01";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA_512_224) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_512_224].outputSize];
    int status = GetHash(TEST_STRING_111, 111, SHA_512_224, buffer);
    std::string result = GetHexResult(buffer, 28);
    std::string expectingResult = "e2e1efb2bd9349b4127af3008615aba325a8c2845d7b8dc05b7cefec";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA_512_256) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_512_256].outputSize];
    int status = GetHash(TEST_STRING_111, 111, SHA_512_256, buffer);
    std::string result = GetHexResult(buffer, 32);
    std::string expectingResult = "97db84eab9593a2895685f7e9402351186f330946fcd34942805dc20b1de249e";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA_512) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_512].outputSize];
    int status = GetHash(TEST_STRING_111, 111, SHA_512, buffer);
    std::string result = GetHexResult(buffer, 64);
    std::string expectingResult = "b1dd9abad41141faca005751488b468c67fdb6b0a699ac462ea7b8e05410d5704794eb4e1d3518e702d01c6027ef95f8d31414e8d114729f6c8f815a40db9a2b";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA3_224) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA3_224].outputSize];
    int status = GetHash(TEST_STRING_111, 111, SHA3_224, buffer);
    std::string result = GetHexResult(buffer, 28);
    std::string expectingResult = "d40ad02a0095100e5b75050d36eee84179b362eb07859a42edcfe1aa";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA3_256) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA3_256].outputSize];
    int status = GetHash(TEST_STRING_111, 111, SHA3_256, buffer);
    std::string result = GetHexResult(buffer, 32);
    std::string expectingResult = "40caae9e0cb87c02464bea62b756337519140aa4fe08f2f79f68acdef1c9f7ce";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA3_384) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA3_384].outputSize];
    int status = GetHash(TEST_STRING_111, 111, SHA3_384, buffer);
    std::string result = GetHexResult(buffer, 48);
    std::string expectingResult = "eabe91b02b768cc16dc8d536501e1895528520adbc89091c570068cb769e1b0fa802b3c846c5d6ddba2a2c9bac26deca";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA3_512) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA3_512].outputSize];
    int status = GetHash(TEST_STRING_111, 111, SHA3_512, buffer);
    std::string result = GetHexResult(buffer, 64);
    std::string expectingResult = "485dad72c9718dad11d711fceba23c705e8e1353fd295138ffa025365e0d48935d8327f8102fee7eefeee2732d97d9e7e2c97eabd3065f1cc2c89d75c64bc649";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

// Empty input test

TEST(GetHashTest, Sha_1_empty) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA1].outputSize];
    int status = GetHash(nullptr, 0, SHA1, buffer);
    std::string result = GetHexResult(buffer, 20);
    std::string expectingResult = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA_224_empty) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_224].outputSize];
    int status = GetHash(nullptr, 0, SHA_224, buffer);
    std::string result = GetHexResult(buffer, 28);
    std::string expectingResult = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA_256_empty) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_256].outputSize];
    int status = GetHash(nullptr, 0, SHA_256, buffer);
    std::string result = GetHexResult(buffer, 32);
    std::string expectingResult = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA_384_empty) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_384].outputSize];
    int status = GetHash(nullptr, 0, SHA_384, buffer);
    std::string result = GetHexResult(buffer, 48);
    std::string expectingResult = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA_512_224_empty) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_512_224].outputSize];
    int status = GetHash(nullptr, 0, SHA_512_224, buffer);
    std::string result = GetHexResult(buffer, 28);
    std::string expectingResult = "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA_512_256_empty) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_512_256].outputSize];
    int status = GetHash(nullptr, 0, SHA_512_256, buffer);
    std::string result = GetHexResult(buffer, 32);
    std::string expectingResult = "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA_512_empty) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA_512].outputSize];
    int status = GetHash(nullptr, 0, SHA_512, buffer);
    std::string result = GetHexResult(buffer, 64);
    std::string expectingResult = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA3_224_empty) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA3_224].outputSize];
    int status = GetHash(nullptr, 0, SHA3_224, buffer);
    std::string result = GetHexResult(buffer, 28);
    std::string expectingResult = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA3_256_empty) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA3_256].outputSize];
    int status = GetHash(nullptr, 0, SHA3_256, buffer);
    std::string result = GetHexResult(buffer, 32);
    std::string expectingResult = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA3_384_empty) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA3_384].outputSize];
    int status = GetHash(nullptr, 0, SHA3_384, buffer);
    std::string result = GetHexResult(buffer, 48);
    std::string expectingResult = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}

TEST(GetHashTest, SHA3_512_empty) {
    uint8_t* buffer = new uint8_t[g_hashFuncsSizesMappings[SHA3_512].outputSize];
    int status = GetHash(nullptr, 0, SHA3_512, buffer);
    std::string result = GetHexResult(buffer, 64);
    std::string expectingResult = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";

    EXPECT_EQ(result, expectingResult);
    EXPECT_TRUE(status == NO_ERROR);
    delete[] buffer;
}
