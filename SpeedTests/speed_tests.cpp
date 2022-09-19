#include "pch.h"
#include "crypto.h"

void PrintTruncHashAux(HashHandle handle, uint8_t* input, size_t inputSize, uint8_t* didgest)
{
    if (GetHash(handle, input, inputSize, true, didgest))
        throw "";

    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)didgest[0] << "..." << std::setw(2) << std::setfill('0') << (int)didgest[SHA1_DIGEST_SIZE - 1];
}

void TestAesSpeedAux(BlockCipherType cipher, CryptoMode cryptoMode, HardwareFeatures& hwFeatures
    , const std::vector<uint8_t>& input, std::vector<uint8_t>& output, HashHandle hashHandle, std::vector<uint8_t>& didgestBuffer)
{
    int status = NO_ERROR;

    const char KEY_16[] = "81cav5ASkv8vwel0";
    const char KEY_24[] = "which is listed on somer";
    const char KEY_32[] = "arguments than any operator that";

    const void* key = cipher == AES128_cipher_type ? KEY_16 : cipher == AES192_cipher_type ? KEY_24 : KEY_32;

    BlockCipherHandle cipherHandle = nullptr;
    HardwareFeatures hwFeatures_orig = hwFeatures;
    size_t outputSize = output.size();

    std::chrono::time_point<std::chrono::high_resolution_clock> startTime;
    std::chrono::time_point<std::chrono::high_resolution_clock> finishTime;
    double elapsedTime = 0;

    if (InitBlockCipherState(&cipherHandle, cipher, cryptoMode, CBC_mode, No_padding, &hwFeatures, key, KEY_16))
        throw;

    if (hwFeatures_orig.aeskle != hwFeatures.aeskle || hwFeatures_orig.aesni != hwFeatures.aesni || hwFeatures_orig.avx != hwFeatures.avx
        || hwFeatures_orig.vaes != hwFeatures.vaes || hwFeatures_orig.vex_aes != hwFeatures.vex_aes)
    {
        std::cout << "not supported\n";
    }
    else
    {
        startTime = std::chrono::high_resolution_clock::now();

        try {
            if (ProcessingByBlockCipher(cipherHandle, input.data(), input.size(), true, output.data(), &outputSize))
                throw "";

            finishTime = std::chrono::high_resolution_clock::now();
            elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();

            std::cout << "time elapsed: " << elapsedTime
                << "s, speed: " << 16 / elapsedTime
                << "Mb/s, truncated sha1 of encrypted data: ";

            PrintTruncHashAux(hashHandle, output.data(), output.size(), didgestBuffer.data());
        }
        catch (...) {
            FreeBlockCipherState(cipherHandle);
            throw;
        }
    }

    std::cout << "\n\n";
    FreeBlockCipherState(cipherHandle);
}

void TestAesSpeed()
{
    constexpr size_t testVectorsSize = 0x1000000;
    std::vector<uint8_t> input(testVectorsSize); // 16Mb;
    std::vector<uint8_t> output(testVectorsSize);
    std::vector<uint8_t> didgestBuffer(SHA1_DIGEST_SIZE);

    std::srand(0);

    for (size_t i = 0; i < testVectorsSize; ++i)
        input.data()[i] = (char)std::rand();

    BlockCipherHandle cipherHandle = nullptr;
    HashHandle hashHandle = NULL;
    if (InitHashState(&hashHandle, SHA1))
        throw "";

    try {
        HardwareFeatures hwFeatures = { 0 };

        std::cout << "Speed tests of AES\n";
        std::cout << "Test vectors 16mb length, CBC_mode, No_padding \n";
        std::cout << "--------------------------------------------------------------------------\n";
        std::cout << "Encryption\n";
        std::cout << "\n";

        // AES128_cipher_type
        std::cout << "AES128_cipher_type\n\n";
        std::cout << "Software:\n";
        TestAesSpeedAux(AES128_cipher_type, Encryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);

        hwFeatures.aesni = true;
        std::cout << "AESNI:\n";
        TestAesSpeedAux(AES128_cipher_type, Encryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);

        hwFeatures.avx = true;
        std::cout << "AVX:\n";
        TestAesSpeedAux(AES128_cipher_type, Encryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);

        std::cout << "------------------------\n\n";
        hwFeatures.avx = hwFeatures.aesni = false;
        // AES192_cipher_type
        std::cout << "AES192_cipher_type\n\n";
        std::cout << "Software:\n";
        TestAesSpeedAux(AES192_cipher_type, Encryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);

        hwFeatures.aesni = true;
        std::cout << "AESNI:\n";
        TestAesSpeedAux(AES192_cipher_type, Encryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);

        hwFeatures.avx = true;
        std::cout << "AVX:\n";
        TestAesSpeedAux(AES192_cipher_type, Encryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);

        std::cout << "------------------------\n\n";
        hwFeatures.avx = hwFeatures.aesni = false;
        // AES256_cipher_type
        std::cout << "AES256_cipher_type\n\n";
        std::cout << "Software:\n";
        TestAesSpeedAux(AES256_cipher_type, Encryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);
        hwFeatures.aesni = true;
        std::cout << "AESNI:\n";
        TestAesSpeedAux(AES256_cipher_type, Encryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);

        hwFeatures.avx = true;
        std::cout << "AVX:\n";
        TestAesSpeedAux(AES256_cipher_type, Encryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);

        hwFeatures.avx = hwFeatures.aesni = false;

        std::cout << "\-----------------------------------------------\n\n\n";

        std::cout << "Decryption\n";
        std::cout << "\n";

        // AES128_cipher_type
        std::cout << "AES128_cipher_type\n\n";
        std::cout << "Software:\n";
        TestAesSpeedAux(AES128_cipher_type, Decryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);

        hwFeatures.aesni = true;
        std::cout << "AESNI:\n";
        TestAesSpeedAux(AES128_cipher_type, Decryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);

        hwFeatures.avx = true;
        std::cout << "AVX:\n";
        TestAesSpeedAux(AES128_cipher_type, Decryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);

        std::cout << "------------------------\n\n";
        hwFeatures.avx = hwFeatures.aesni = false;
        // AES192_cipher_type
        std::cout << "AES192_cipher_type\n\n";
        std::cout << "Software:\n";
        TestAesSpeedAux(AES192_cipher_type, Decryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);

        hwFeatures.aesni = true;
        std::cout << "AESNI:\n";
        TestAesSpeedAux(AES192_cipher_type, Decryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);

        hwFeatures.avx = true;
        std::cout << "AVX:\n";
        TestAesSpeedAux(AES192_cipher_type, Decryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);

        std::cout << "------------------------\n\n";
        hwFeatures.avx = hwFeatures.aesni = false;
        // AES256_cipher_type
        std::cout << "AES256_cipher_type\n\n";
        std::cout << "Software:\n";
        TestAesSpeedAux(AES256_cipher_type, Decryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);
        hwFeatures.aesni = true;
        std::cout << "AESNI:\n";
        TestAesSpeedAux(AES256_cipher_type, Decryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);

        hwFeatures.avx = true;
        std::cout << "AVX:\n";
        TestAesSpeedAux(AES256_cipher_type, Decryption_mode, hwFeatures, input, output, hashHandle, didgestBuffer);

        hwFeatures.avx = hwFeatures.aesni = false;
    }
    catch (...) {
        FreeHashState(hashHandle);
        throw;
    }

    FreeHashState(hashHandle);
}

int main()
{
    try {
        TestAesSpeed();
    }
    catch (...) {
        std::cout << "Something went wrong. Aborting...\n";
    }
}
