//  GetPbkdf2T.cpp
//

#include "pch.h"

#include "common.h"

void GetPbkdf2MainTestFunc(__in_opt const void* salt, __in uint64_t saltSize, __in_opt const void* password, __in uint64_t passwordSize, __in Prf func, __in uint64_t iterationsNum, __in uint64_t outputSize, __in int expectedStatus, __in_opt const void* expectedRes)
{
    int status = NO_ERROR;
    std::unique_ptr<uint8_t> buffer(new uint8_t[outputSize]);
    EVAL(GetPbkdf2(salt, saltSize, password, passwordSize, func, iterationsNum, buffer.get(), outputSize));

exit:

    if (expectedRes) {
        std::string result = GetHexResult(buffer.get(), outputSize);
        std::string expRes((const char*)expectedRes);
        EXPECT_EQ(result, expRes);
    }

    EXPECT_TRUE(status == expectedStatus);
}

// Wrong arguments

TEST(GetPbkdf2Test, WrongInput) {
    GetPbkdf2MainTestFunc(nullptr, 8, TEST_STRING_64, 64, HMAC_SHA1, 1000, g_hashFuncsSizesMapping[SHA1].didgestSize, ERROR_NULL_INPUT, nullptr);
}

TEST(GetPbkdf2Test, WrongKey) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, nullptr, 64, HMAC_SHA1, 1000, g_hashFuncsSizesMapping[SHA1].didgestSize, ERROR_NULL_KEY, nullptr);
}

TEST(GetPbkdf2Test, UnknownPrfFunc) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, (Prf)-1, 1000, g_hashFuncsSizesMapping[SHA1].didgestSize, ERROR_UNSUPPORTED_PRF_FUNC, nullptr);
}

TEST(GetPbkdf2Test, WrongItNumber) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA1, 0, g_hashFuncsSizesMapping[SHA1].didgestSize, ERROR_TOO_SMALL_ITERATIONS_NUMBER, nullptr);
}

TEST(GetPbkdf2Test, WrongOuput) {
    uint16_t outputSize = 20;
    EXPECT_TRUE(GetPbkdf2(TEST_STRING_8, 8, TEST_STRING_8, 8, HMAC_SHA1, 100, nullptr, outputSize) == ERROR_NULL_OUTPUT);
}

TEST(GetPbkdf2Test, WrongOutputSize) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA1, 1000, 0, ERROR_TOO_SMALL_OUTPUT_SIZE, nullptr);
}

// Main test
// 
// 1. OutputSize == Single full block of hashing function
// 2. OutputSize == Single full block + 1 byte (must eval to 2 blocks)
// 3. Single iteration
// 4. Null salt
// 5. Null password

// HMAC_SHA1

TEST(GetPbkdf2Test, Pbkdf2HmacSha1sfb) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA1, 1000, g_hashFuncsSizesMapping[SHA1].didgestSize, NO_ERROR, "e76b87bea20f3913fdfaa7785c3693689f68cb9b");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha1db) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA1, 1000, g_hashFuncsSizesMapping[SHA1].didgestSize + 1, NO_ERROR, "e76b87bea20f3913fdfaa7785c3693689f68cb9bc4");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha1sit) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA1, 1, g_hashFuncsSizesMapping[SHA1].didgestSize, NO_ERROR, "e4184d3d916558a85418d58c1b0c486974d242df");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha1NullSalt) {
    GetPbkdf2MainTestFunc(nullptr, 0, TEST_STRING_64, 64, HMAC_SHA1, 1000, g_hashFuncsSizesMapping[SHA1].didgestSize, NO_ERROR, "1f8f98ec39052647579b54cc7a0fc7b05b525a10");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha1NullPwd) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, nullptr, 0, HMAC_SHA1, 1000, g_hashFuncsSizesMapping[SHA1].didgestSize, NO_ERROR, "691bf337906e8813adef39513f58bcc8f27167b6");
}

// HMAC_SHA_224

TEST(GetPbkdf2Test, Pbkdf2HmacSha224sfb) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_224, 1000, g_hashFuncsSizesMapping[SHA_224].didgestSize, NO_ERROR, "f71cb1b44e3a775d429e9c1463906f2232dfa7fb43f7722356843328");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha224db) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_224, 1000, g_hashFuncsSizesMapping[SHA_224].didgestSize + 1, NO_ERROR, "f71cb1b44e3a775d429e9c1463906f2232dfa7fb43f772235684332840");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha224sit) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_224, 1, g_hashFuncsSizesMapping[SHA_224].didgestSize, NO_ERROR, "ac785a37a9021304f22124d1ca81091c2f8100c28d48c70059c85fa1");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha224NullSalt) {
    GetPbkdf2MainTestFunc(nullptr, 0, TEST_STRING_64, 64, HMAC_SHA_224, 1000, g_hashFuncsSizesMapping[SHA_224].didgestSize, NO_ERROR, "0b2e2efc74ff5bfc0f7e5e7d8c6d599c7f8e1b2a8db3de980e78a17b");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha224NullPwd) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, nullptr, 0, HMAC_SHA_224, 1000, g_hashFuncsSizesMapping[SHA_224].didgestSize, NO_ERROR, "53b16a5ed0c3f5f92275086e7a408d3e85d7ba772996697927a98409");
}

// HMAC_SHA_256

TEST(GetPbkdf2Test, Pbkdf2HmacSha256sfb) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_256, 1000, g_hashFuncsSizesMapping[SHA_256].didgestSize, NO_ERROR, "59439f1e1d55214a06b6a6b3f37f7b5d48ce99c821ed54b62a44ef08b8e1fbe4");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha256db) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_256, 1000, g_hashFuncsSizesMapping[SHA_256].didgestSize + 1, NO_ERROR, "59439f1e1d55214a06b6a6b3f37f7b5d48ce99c821ed54b62a44ef08b8e1fbe43d");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha256sit) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_256, 1, g_hashFuncsSizesMapping[SHA_256].didgestSize, NO_ERROR, "beddab9f725254b580bd80f97e9020eb1e58b92f0cc3c537ed73c61692164d45");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha256NullSalt) {
    GetPbkdf2MainTestFunc(nullptr, 0, TEST_STRING_64, 64, HMAC_SHA_256, 1000, g_hashFuncsSizesMapping[SHA_256].didgestSize, NO_ERROR, "232d0aa29b04bbe5b48371d887891ac0f7b127bf23a7957e21e496825828c6cc");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha256NullPwd) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, nullptr, 0, HMAC_SHA_256, 1000, g_hashFuncsSizesMapping[SHA_256].didgestSize, NO_ERROR, "b5bb3d644b1b12943861251cb73946b6960fc7b0b6124e88ebadc0e00ab959b5");
}

// HMAC_SHA_384

TEST(GetPbkdf2Test, Pbkdf2HmacSha384sfb) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_384, 1000, g_hashFuncsSizesMapping[SHA_384].didgestSize, NO_ERROR, "18b4fdd68fe832fa84afcc5cb0e1d6b30f9f576b49ecb80e2e2e0d1bab38e4d42f50ccbf69d71d5a5b0ce2ffe34c0790");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha384db) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_384, 1000, g_hashFuncsSizesMapping[SHA_384].didgestSize + 1, NO_ERROR, "18b4fdd68fe832fa84afcc5cb0e1d6b30f9f576b49ecb80e2e2e0d1bab38e4d42f50ccbf69d71d5a5b0ce2ffe34c0790df");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha384sit) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_384, 1, g_hashFuncsSizesMapping[SHA_384].didgestSize, NO_ERROR, "550e9783640f94bdcfe44b70bde470a367cd6601c0d3643db8926d38fceada066b89bd603b8f30f619d97bf096bfc6f6");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha384NullSalt) {
    GetPbkdf2MainTestFunc(nullptr, 0, TEST_STRING_64, 64, HMAC_SHA_384, 1000, g_hashFuncsSizesMapping[SHA_384].didgestSize, NO_ERROR, "8b6b0b96c5151aaec7eda3c65632460449c86356861f92925dfac93a1c9b3dca5505bfff969e95960db9ff0f76afe836");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha384NullPwd) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, nullptr, 0, HMAC_SHA_384, 1000, g_hashFuncsSizesMapping[SHA_384].didgestSize, NO_ERROR, "ccef9692e5a1ba2b7ff4eb307e23f36dbdd1dac770f521557c5a319b0d94e29718028b46d5df499bf4a50fd4d1a08714");
}

// HMAC_SHA_512_224

TEST(GetPbkdf2Test, Pbkdf2HmacSha512224sfb) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_512_224, 1000, g_hashFuncsSizesMapping[SHA_512_224].didgestSize, NO_ERROR, "15faefe22b55ce3b421ee182bdc4d7a9cdb8273ae0ff1b0c9c4eb7d9");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha512224db) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_512_224, 1000, g_hashFuncsSizesMapping[SHA_512_224].didgestSize + 1, NO_ERROR, "15faefe22b55ce3b421ee182bdc4d7a9cdb8273ae0ff1b0c9c4eb7d906");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha512224sit) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_512_224, 1, g_hashFuncsSizesMapping[SHA_512_224].didgestSize, NO_ERROR, "6a58cac66791d6e86ef007039b1c6e7f8dad33bbda3c9caf254fc673");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha512224NullSalt) {
    GetPbkdf2MainTestFunc(nullptr, 0, TEST_STRING_64, 64, HMAC_SHA_512_224, 1000, g_hashFuncsSizesMapping[SHA_512_224].didgestSize, NO_ERROR, "8cdeb96d62a2114c18ef5eb37218af653fa52768aade5065a34d895d");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha512224NullPwd) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, nullptr, 0, HMAC_SHA_512_224, 1000, g_hashFuncsSizesMapping[SHA_512_224].didgestSize, NO_ERROR, "3ecc07d5dce8d435921b10a68fbc291ead0ec31fac72e9381cee2372");
}

// HMAC_SHA_512_256

TEST(GetPbkdf2Test, Pbkdf2HmacSha512256sfb) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_512_256, 1000, g_hashFuncsSizesMapping[SHA_512_256].didgestSize, NO_ERROR, "f9bd49fd35f50ea413943631ec1f2e6487f8128e828059eb074aaf8931da2c1a");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha512256db) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_512_256, 1000, g_hashFuncsSizesMapping[SHA_512_256].didgestSize + 1, NO_ERROR, "f9bd49fd35f50ea413943631ec1f2e6487f8128e828059eb074aaf8931da2c1a08");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha512256sit) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_512_256, 1, g_hashFuncsSizesMapping[SHA_512_256].didgestSize, NO_ERROR, "c41e144502a62644ee0cae8c3a7a6cfb0885163a8db6cea0cf74c48acc05b4d1");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha512256NullSalt) {
    GetPbkdf2MainTestFunc(nullptr, 0, TEST_STRING_64, 64, HMAC_SHA_512_256, 1000, g_hashFuncsSizesMapping[SHA_512_256].didgestSize, NO_ERROR, "e68ed3d7f81174707b483f6089b52dc6dcb7e2f73cf173f7ebc079f07b810080");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha512256NullPwd) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, nullptr, 0, HMAC_SHA_512_256, 1000, g_hashFuncsSizesMapping[SHA_512_256].didgestSize, NO_ERROR, "e2bbe5ffd9464efe47eece9002df073788b58b95b6d39552a11bcab4c32df78d");
}

// HMAC_SHA_512

TEST(GetPbkdf2Test, Pbkdf2HmacSha512sfb) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_512, 1000, g_hashFuncsSizesMapping[SHA_512].didgestSize, NO_ERROR, "32298277cbddfe615b8722ac85ca545038fd8c9d93cf465427c9fd1e25ffb1748b6383dc8556a37687dfe8890db68955f6414c2ecb1fe09965b9c23f11346564");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha512db) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_512, 1000, g_hashFuncsSizesMapping[SHA_512].didgestSize + 1, NO_ERROR, "32298277cbddfe615b8722ac85ca545038fd8c9d93cf465427c9fd1e25ffb1748b6383dc8556a37687dfe8890db68955f6414c2ecb1fe09965b9c23f113465649f");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha512sit) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA_512, 1, g_hashFuncsSizesMapping[SHA_512].didgestSize, NO_ERROR, "60a266c786bfa101cf132b044081a52158e7ba59635861f9c172e8e4af5d4f7b61eab287b83d1d33c5391cabb288ab826677e4bb2e07b6386c980d267a678b28");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha512NullSalt) {
    GetPbkdf2MainTestFunc(nullptr, 0, TEST_STRING_64, 64, HMAC_SHA_512, 1000, g_hashFuncsSizesMapping[SHA_512].didgestSize, NO_ERROR, "6e39525c09ba0b1a7fd4252a46ff419caae2f4fab8a5fe9f8f1f81cf00d6f2ca060bc5cc010333af27c83fe91b28203c147f81633971664a48bf2a1300cd7427");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha512NullPwd) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, nullptr, 0, HMAC_SHA_512, 1000, g_hashFuncsSizesMapping[SHA_512].didgestSize, NO_ERROR, "1da00a75593a361ec21d8d8e5e9752bd198ae0b5063794a3a5a6ca986eea41ef2bf8c5acdaa31872210a293fa9022fb5d85b20fdc704512dba1d455548b6283b");
}

// HMAC_SHA3_224

TEST(GetPbkdf2Test, Pbkdf2HmacSha3224sfb) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_224, 1000, g_hashFuncsSizesMapping[SHA3_224].didgestSize, NO_ERROR, "b8bed9ef53b590ffca453ff78083e0c8c3e4d0019ea086b0f0f972d0");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha3224db) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_224, 1000, g_hashFuncsSizesMapping[SHA3_224].didgestSize + 1, NO_ERROR, "b8bed9ef53b590ffca453ff78083e0c8c3e4d0019ea086b0f0f972d048");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha3224sit) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_224, 1, g_hashFuncsSizesMapping[SHA3_224].didgestSize, NO_ERROR, "6bed01f2fe3af67a63a2bf181bf57f500cf1651b0e9fc9fcda48efaa");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha3224NullSalt) {
    GetPbkdf2MainTestFunc(nullptr, 0, TEST_STRING_64, 64, HMAC_SHA3_224, 1000, g_hashFuncsSizesMapping[SHA3_224].didgestSize, NO_ERROR, "bacd64f9f588285aa3d52e910863257a1ccf96eb3a534d51314eb926");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha3224NullPwd) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, nullptr, 0, HMAC_SHA3_224, 1000, g_hashFuncsSizesMapping[SHA3_224].didgestSize, NO_ERROR, "8c0bc564685dcf5e5b2799d9ccda7f94c90261b0e0b9047c6595389d");
}

// HMAC_SHA3_256

TEST(GetPbkdf2Test, Pbkdf2HmacSha3256sfb) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_256, 1000, g_hashFuncsSizesMapping[SHA3_256].didgestSize, NO_ERROR, "1ec06c9b80df50d54a143d9cf2da622253d010ce2c846cd52c53590711081cc3");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha3256db) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_256, 1000, g_hashFuncsSizesMapping[SHA3_256].didgestSize + 1, NO_ERROR, "1ec06c9b80df50d54a143d9cf2da622253d010ce2c846cd52c53590711081cc326");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha3256sit) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_256, 1, g_hashFuncsSizesMapping[SHA3_256].didgestSize, NO_ERROR, "a3ed9f09aedeb4d11e9d226448ee5aa4bf93a58a7dfac619269e48d229499f71");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha3256NullSalt) {
    GetPbkdf2MainTestFunc(nullptr, 0, TEST_STRING_64, 64, HMAC_SHA3_256, 1000, g_hashFuncsSizesMapping[SHA3_256].didgestSize, NO_ERROR, "cc18590bd2e2902f38481c95945a2f8e84c211468c179de3be7944bc24d87de2");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha3256NullPwd) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, nullptr, 0, HMAC_SHA3_256, 1000, g_hashFuncsSizesMapping[SHA3_256].didgestSize, NO_ERROR, "6d48b7b19f668523bdd8426e265bcc9acd483f53e2c62b1f7e1046857fc8c9fa");
}

// HMAC_SHA3_384

TEST(GetPbkdf2Test, Pbkdf2HmacSha3384sfb) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_384, 1000, g_hashFuncsSizesMapping[SHA3_384].didgestSize, NO_ERROR, "53273994b0b61f2a9c9b11270546091c764d42af3b83165e342990665d89a83f0ffa8a951662194814529d0b32608734");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha3384db) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_384, 1000, g_hashFuncsSizesMapping[SHA3_384].didgestSize + 1, NO_ERROR, "53273994b0b61f2a9c9b11270546091c764d42af3b83165e342990665d89a83f0ffa8a951662194814529d0b326087346b");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha3384sit) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_384, 1, g_hashFuncsSizesMapping[SHA3_384].didgestSize, NO_ERROR, "568dc9e82e8fd5063973fc96b54d9355a72c7fa171537b9a4fc185b1d80c48271866440c44c2ac8d4d2040822084f7c9");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha3384NullSalt) {
    GetPbkdf2MainTestFunc(nullptr, 0, TEST_STRING_64, 64, HMAC_SHA3_384, 1000, g_hashFuncsSizesMapping[SHA3_384].didgestSize, NO_ERROR, "9e607f54d71729a5df58a1283f5e8ee0ee3bc8ce61cfb7875e946a8a5950112459897952eafa2fb20c95b9315e8abd2a");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha3384NullPwd) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, nullptr, 0, HMAC_SHA3_384, 1000, g_hashFuncsSizesMapping[SHA3_384].didgestSize, NO_ERROR, "fbb52fc15d59c3a7208a33f08d9015f2c9db318bafcfd8b3f486ab4a8d3d990e362ceaadad3e9b561ed815bbd1c10d4c");
}

// HMAC_SHA3_512

TEST(GetPbkdf2Test, Pbkdf2HmacSha3512sfb) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_512, 1000, g_hashFuncsSizesMapping[SHA3_512].didgestSize, NO_ERROR, "d4449177e15928a9536631ba457788231f46a0d400efec330536d7cd906215bda9844f857e08b83a293344e348e92a80cb355f3b2672b770c50c652e7a307503");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha3512db) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_512, 1000, g_hashFuncsSizesMapping[SHA3_512].didgestSize + 1, NO_ERROR, "d4449177e15928a9536631ba457788231f46a0d400efec330536d7cd906215bda9844f857e08b83a293344e348e92a80cb355f3b2672b770c50c652e7a30750324");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha3512sit) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, TEST_STRING_64, 64, HMAC_SHA3_512, 1, g_hashFuncsSizesMapping[SHA3_512].didgestSize, NO_ERROR, "09eba44db42a77d88c9e29a81b296c3d8bbd5d6526cabcce73b9f32606f00282894ec63ae5a6a715ffe1b9a84a1ab53ff838bbc7b5ce6be2aaf240142f9e1609");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha3512NullSalt) {
    GetPbkdf2MainTestFunc(nullptr, 0, TEST_STRING_64, 64, HMAC_SHA3_512, 1000, g_hashFuncsSizesMapping[SHA3_512].didgestSize, NO_ERROR, "93da522e57435a9a6f3b2d2e0911c1da6fa2ca3cd2fc5813ef93fe66fa3b6b93a385b94dab946dd836f33c1a6e15f7b6a9e35bff36262e87c5570fea2be3b42e");
}

TEST(GetPbkdf2Test, Pbkdf2HmacSha3512NullPwd) {
    GetPbkdf2MainTestFunc(TEST_STRING_8, 8, nullptr, 0, HMAC_SHA3_512, 1000, g_hashFuncsSizesMapping[SHA3_512].didgestSize, NO_ERROR, "9457ed8d1742bdf924a9e32fec8f1c619e77f18cd90a51b6f8f7159f37bf4d8591dad2450beda6dde2227834e8edfc17555c65e05828f52b8c860146a893b1f1");
}
