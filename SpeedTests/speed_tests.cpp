#include "pch.h"
#include "crypto.h"

void PrintTruncHashAux(HashHandle handle, uint8_t* input, size_t inputSize, uint8_t* didgest)
{
    GetHash(handle, input, inputSize, true, didgest);
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)didgest[0] << "..." << std::setw(2) << std::setfill('0') << (int)didgest[SHA1_DIGEST_SIZE - 1];
}

int main()
{
    do {
        std::unique_ptr<uint8_t[]> didgest;
        std::unique_ptr<uint8_t[]> testVectorInput;
        std::unique_ptr<uint8_t[]> testVectorOutput;
        size_t testVectorsSize = 0x1000000; // 16Mb
        std::chrono::time_point<std::chrono::high_resolution_clock> startTime;
        std::chrono::time_point<std::chrono::high_resolution_clock> finishTime;

        try {
            didgest = std::make_unique<uint8_t[]>(SHA1_DIGEST_SIZE);
            testVectorInput = std::make_unique<uint8_t[]>(testVectorsSize);
            testVectorOutput = std::make_unique<uint8_t[]>(testVectorsSize);
        }
        catch (...) {
            break;
        }

        std::srand(0);

        for (size_t i = 0; i < testVectorsSize;)
            testVectorInput.get()[i++] = (char)std::rand();

        HashHandle hashHandle = NULL;
        if (InitHashState(&hashHandle, SHA1))
            break;

        double elapsedTime = 0;

        const char KEY_16[] = "81cav5ASkv8vwel0";
        const char KEY_24[] = "which is listed on somer";
        const char KEY_32[] = "arguments than any operator that";
        BlockCipherHandle cipherHandle = nullptr;
        HardwareFeatures hwFeatures = { 0 };

        std::cout << "Speed tests of AES\n";
        std::cout << "Test vectors 16mb length, CBC_mode, No_padding \n";
        std::cout << "--------------------------------------------------------------------------\n";
        std::cout << "Encryption\n";
        std::cout << "\n";

        // AES128_cipher_type
        std::cout << "AES128_cipher_type\n\n";
        std::cout << "Software:\n";

        InitBlockCipherState(&cipherHandle, AES128_cipher_type, Encryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_16, KEY_16);
        startTime = std::chrono::high_resolution_clock::now();
        ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
        finishTime = std::chrono::high_resolution_clock::now();
        elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
        std::cout << "time elapsed: " << elapsedTime
            << "s, speed: " << 1 / (elapsedTime / 16)
            << "Mb/s, truncated sha1 of encrypted data: ";
        PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        std::cout << "\n\n";
        FreeBlockCipherState(cipherHandle);

        hwFeatures.aesni = true;
        std::cout << "AESNI:\n";

        InitBlockCipherState(&cipherHandle, AES128_cipher_type, Encryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_16, KEY_16);
        if (!hwFeatures.aesni)
            std::cout << "not supported\n";
        else {
            startTime = std::chrono::high_resolution_clock::now();
            ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
            finishTime = std::chrono::high_resolution_clock::now();
            elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
            std::cout << "time elapsed: " << elapsedTime
                << "s, speed: " << 1 / (elapsedTime / 16)
                << "Mb/s, truncated sha1 of encrypted data: ";
            PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        }
        std::cout << "\n\n";
        FreeBlockCipherState(cipherHandle);

        hwFeatures.avx = true;
        std::cout << "AVX:\n";

        InitBlockCipherState(&cipherHandle, AES128_cipher_type, Encryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_16, KEY_16);
        if (!hwFeatures.avx)
            std::cout << "not supported\n";
        else {
            startTime = std::chrono::high_resolution_clock::now();
            ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
            finishTime = std::chrono::high_resolution_clock::now();
            elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
            std::cout << "time elapsed: " << elapsedTime
                << "s, speed: " << 1 / (elapsedTime / 16)
                << "Mb/s, truncated sha1 of encrypted data: ";
            PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        }
        std::cout << "\n------------------------\n\n";
        FreeBlockCipherState(cipherHandle);

        // AES192_cipher_type
        hwFeatures.aesni = false, hwFeatures.avx = false;
        std::cout << "AES192_cipher_type\n\n";
        std::cout << "Software:\n";

        InitBlockCipherState(&cipherHandle, AES192_cipher_type, Encryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_24, KEY_16);
        startTime = std::chrono::high_resolution_clock::now();
        ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
        finishTime = std::chrono::high_resolution_clock::now();
        elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
        std::cout << "time elapsed: " << elapsedTime
            << "s, speed: " << 1 / (elapsedTime / 16)
            << "Mb/s, truncated sha1 of encrypted data: ";
        PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        std::cout << "\n\n";
        FreeBlockCipherState(cipherHandle);

        hwFeatures.aesni = true;
        std::cout << "AESNI:\n";

        InitBlockCipherState(&cipherHandle, AES192_cipher_type, Encryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_24, KEY_16);
        if (!hwFeatures.aesni)
            std::cout << "not supported\n";
        else {
            startTime = std::chrono::high_resolution_clock::now();
            ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
            finishTime = std::chrono::high_resolution_clock::now();
            elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
            std::cout << "time elapsed: " << elapsedTime
                << "s, speed: " << 1 / (elapsedTime / 16)
                << "Mb/s, truncated sha1 of encrypted data: ";
            PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        }
        std::cout << "\n\n";
        FreeBlockCipherState(cipherHandle);

        hwFeatures.avx = true;
        std::cout << "AVX:\n";

        InitBlockCipherState(&cipherHandle, AES192_cipher_type, Encryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_24, KEY_16);
        if (!hwFeatures.avx)
            std::cout << "not supported\n";
        else {
            startTime = std::chrono::high_resolution_clock::now();
            ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
            finishTime = std::chrono::high_resolution_clock::now();
            elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
            std::cout << "time elapsed: " << elapsedTime
                << "s, speed: " << 1 / (elapsedTime / 16)
                << "Mb/s, truncated sha1 of encrypted data: ";
            PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        }
        std::cout << "\n------------------------\n\n";
        FreeBlockCipherState(cipherHandle);

        // AES256_cipher_type
        hwFeatures.aesni = false, hwFeatures.avx = false;
        std::cout << "AES256_cipher_type\n\n";
        std::cout << "Software:\n";

        InitBlockCipherState(&cipherHandle, AES256_cipher_type, Encryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_32, KEY_16);
        startTime = std::chrono::high_resolution_clock::now();
        ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
        finishTime = std::chrono::high_resolution_clock::now();
        elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
        std::cout << "time elapsed: " << elapsedTime
            << "s, speed: " << 1 / (elapsedTime / 16)
            << "Mb/s, truncated sha1 of encrypted data: ";
        PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        std::cout << "\n\n";
        FreeBlockCipherState(cipherHandle);

        hwFeatures.aesni = true;
        std::cout << "AESNI:\n";

        InitBlockCipherState(&cipherHandle, AES256_cipher_type, Encryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_32, KEY_16);
        if (!hwFeatures.aesni)
            std::cout << "not supported\n";
        else {
            startTime = std::chrono::high_resolution_clock::now();
            ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
            finishTime = std::chrono::high_resolution_clock::now();
            elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
            std::cout << "time elapsed: " << elapsedTime
                << "s, speed: " << 1 / (elapsedTime / 16)
                << "Mb/s, truncated sha1 of encrypted data: ";
            PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        }
        std::cout << "\n\n";
        FreeBlockCipherState(cipherHandle);

        hwFeatures.avx = true;
        std::cout << "AVX:\n";

        InitBlockCipherState(&cipherHandle, AES256_cipher_type, Encryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_32, KEY_16);
        if (!hwFeatures.avx)
            std::cout << "not supported\n";
        else {
            startTime = std::chrono::high_resolution_clock::now();
            ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
            finishTime = std::chrono::high_resolution_clock::now();
            elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
            std::cout << "time elapsed: " << elapsedTime
                << "s, speed: " << 1 / (elapsedTime / 16)
                << "Mb/s, truncated sha1 of encrypted data: ";
            PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        }
        std::cout << "\n-----------------------------------------------\n\n\n";
        FreeBlockCipherState(cipherHandle);

        std::cout << "Decryption\n";
        std::cout << "\n";

        // AES128_cipher_type
        hwFeatures.aesni = false, hwFeatures.avx = false;
        std::cout << "AES128_cipher_type\n\n";
        std::cout << "Software:\n";

        InitBlockCipherState(&cipherHandle, AES128_cipher_type, Decryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_16, KEY_16);
        startTime = std::chrono::high_resolution_clock::now();
        ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
        finishTime = std::chrono::high_resolution_clock::now();
        elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
        std::cout << "time elapsed: " << elapsedTime
            << "s, speed: " << 1 / (elapsedTime / 16)
            << "Mb/s, truncated sha1 of encrypted data: ";
        PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        std::cout << "\n\n";
        FreeBlockCipherState(cipherHandle);

        hwFeatures.aesni = true;
        std::cout << "AESNI:\n";

        InitBlockCipherState(&cipherHandle, AES128_cipher_type, Decryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_16, KEY_16);
        if (!hwFeatures.aesni)
            std::cout << "not supported\n";
        else {
            startTime = std::chrono::high_resolution_clock::now();
            ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
            finishTime = std::chrono::high_resolution_clock::now();
            elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
            std::cout << "time elapsed: " << elapsedTime
                << "s, speed: " << 1 / (elapsedTime / 16)
                << "Mb/s, truncated sha1 of encrypted data: ";
            PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        }
        std::cout << "\n\n";
        FreeBlockCipherState(cipherHandle);

        hwFeatures.avx = true;
        std::cout << "AVX:\n";

        InitBlockCipherState(&cipherHandle, AES128_cipher_type, Decryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_16, KEY_16);
        if (!hwFeatures.avx)
            std::cout << "not supported\n";
        else {
            startTime = std::chrono::high_resolution_clock::now();
            ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
            finishTime = std::chrono::high_resolution_clock::now();
            elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
            std::cout << "time elapsed: " << elapsedTime
                << "s, speed: " << 1 / (elapsedTime / 16)
                << "Mb/s, truncated sha1 of encrypted data: ";
            PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        }
        std::cout << "\n------------------------\n\n";
        FreeBlockCipherState(cipherHandle);

        // AES192_cipher_type
        hwFeatures.aesni = false, hwFeatures.avx = false;
        std::cout << "AES192_cipher_type\n\n";
        std::cout << "Software:\n";

        InitBlockCipherState(&cipherHandle, AES192_cipher_type, Decryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_24, KEY_16);
        startTime = std::chrono::high_resolution_clock::now();
        ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
        finishTime = std::chrono::high_resolution_clock::now();
        elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
        std::cout << "time elapsed: " << elapsedTime
            << "s, speed: " << 1 / (elapsedTime / 16)
            << "Mb/s, truncated sha1 of encrypted data: ";
        PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        std::cout << "\n\n";
        FreeBlockCipherState(cipherHandle);

        hwFeatures.aesni = true;
        std::cout << "AESNI:\n";

        InitBlockCipherState(&cipherHandle, AES192_cipher_type, Decryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_24, KEY_16);
        if (!hwFeatures.aesni)
            std::cout << "not supported\n";
        else {
            startTime = std::chrono::high_resolution_clock::now();
            ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
            finishTime = std::chrono::high_resolution_clock::now();
            elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
            std::cout << "time elapsed: " << elapsedTime
                << "s, speed: " << 1 / (elapsedTime / 16)
                << "Mb/s, truncated sha1 of encrypted data: ";
            PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        }
        std::cout << "\n\n";
        FreeBlockCipherState(cipherHandle);

        hwFeatures.avx = true;
        std::cout << "AVX:\n";

        InitBlockCipherState(&cipherHandle, AES192_cipher_type, Decryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_24, KEY_16);
        if (!hwFeatures.avx)
            std::cout << "not supported\n";
        else {
            startTime = std::chrono::high_resolution_clock::now();
            ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
            finishTime = std::chrono::high_resolution_clock::now();
            elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
            std::cout << "time elapsed: " << elapsedTime
                << "s, speed: " << 1 / (elapsedTime / 16)
                << "Mb/s, truncated sha1 of encrypted data: ";
            PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        }
        std::cout << "\n------------------------\n\n";
        FreeBlockCipherState(cipherHandle);

        // AES256_cipher_type
        hwFeatures.aesni = false, hwFeatures.avx = false;
        std::cout << "AES256_cipher_type\n\n";
        std::cout << "Software:\n";

        InitBlockCipherState(&cipherHandle, AES256_cipher_type, Decryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_32, KEY_16);
        startTime = std::chrono::high_resolution_clock::now();
        ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
        finishTime = std::chrono::high_resolution_clock::now();
        elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
        std::cout << "time elapsed: " << elapsedTime
            << "s, speed: " << 1 / (elapsedTime / 16)
            << "Mb/s, truncated sha1 of encrypted data: ";
        PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        std::cout << "\n\n";
        FreeBlockCipherState(cipherHandle);

        hwFeatures.aesni = true;
        std::cout << "AESNI:\n";

        InitBlockCipherState(&cipherHandle, AES256_cipher_type, Decryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_32, KEY_16);
        if (!hwFeatures.aesni)
            std::cout << "not supported\n";
        else {
            startTime = std::chrono::high_resolution_clock::now();
            ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
            finishTime = std::chrono::high_resolution_clock::now();
            elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
            std::cout << "time elapsed: " << elapsedTime
                << "s, speed: " << 1 / (elapsedTime / 16)
                << "Mb/s, truncated sha1 of encrypted data: ";
            PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        }
        std::cout << "\n\n";
        FreeBlockCipherState(cipherHandle);

        hwFeatures.avx = true;
        std::cout << "AVX:\n";

        InitBlockCipherState(&cipherHandle, AES256_cipher_type, Decryption_mode, CBC_mode, No_padding, &hwFeatures, KEY_32, KEY_16);
        if (!hwFeatures.avx)
            std::cout << "not supported\n";
        else {
            startTime = std::chrono::high_resolution_clock::now();
            ProcessingByBlockCipher(cipherHandle, testVectorInput.get(), testVectorsSize, true, testVectorOutput.get(), &testVectorsSize);
            finishTime = std::chrono::high_resolution_clock::now();
            elapsedTime = std::chrono::duration<double>(finishTime - startTime).count();
            std::cout << "time elapsed: " << elapsedTime
                << "s, speed: " << 1 / (elapsedTime / 16)
                << "Mb/s, truncated sha1 of encrypted data: ";
            PrintTruncHashAux(hashHandle, testVectorOutput.get(), testVectorsSize, didgest.get());
        }
        std::cout << "\n-----------------------------------------------\n\n\n";
        FreeBlockCipherState(cipherHandle);

    } while (false);
}
