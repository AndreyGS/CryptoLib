// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
//  ProcessingByBlockCipherKAT_AES.cpp
//

#include "pch.h"
#include "ProcessingByBlockCipherTestSupportFunctions.h"
#include "zip.h"

TEST(ProcessingByBlockCipherKAT_AES, MainTest) {
    struct zip_t* zip = zip_open("../NIST_KAT_AES.zip", 0, 'r');

    for (ssize_t i = 0, n = zip_entries_total(zip); i < n; ++i) {
        zip_entry_openbyindex(zip, i);
        if (!zip_entry_isdir(zip)) {
            const char* name = zip_entry_name(zip);

            // First get ecnryption operation mode from file name
            BlockCipherOpMode opMode = ECB_mode;
            if (strstr(name, "CFB")) {
                // Current condition is about files that have tests with not full AES block
                if (name[4] != '2')
                    continue;
                else
                    opMode = CFB_mode;
            }
            else if (strstr(name, "CBC"))
                opMode = CBC_mode;
            else if (strstr(name, "OFB"))
                opMode = OFB_mode;

            // Next we need to get key size
            BlockCipherType cipher = AES128_cipher_type;
            int keyLen = 32; // in hexadecimal symbols
            if (strstr(name, "192")) {
                cipher = AES192_cipher_type;
                keyLen = 48;
            }
            else if (strstr(name, "256")) {
                cipher = AES256_cipher_type;
                keyLen = 64;
            }

            // Encryption or decryption
            CryptoMode enMode = Encryption_mode;
            if (strstr(name, "d."))
                enMode = Decryption_mode;

            size_t fileSize = (size_t)zip_entry_size(zip);
            std::unique_ptr<const char[]> contents = std::make_unique<const char[]>(fileSize);
            zip_entry_noallocread(zip, (void*)contents.get(), fileSize);

            const char* cursor = contents.get();

            while (cursor) {
                unsigned char key[32] = { 0 };
                unsigned char iv[16] = { 0 };
                unsigned char input[16] = { 0 };

                // Get key
                cursor = strstr(cursor, "KEY");
                if (!cursor)
                    break;
                cursor += 6; // "KEY = " and next comes key in hexadecimal 

                ConvertHexStrToBin(cursor, key);
                
                if (!(opMode == ECB_mode)) {
                    // Get IV
                    cursor = strstr(cursor, "IV");
                    cursor += 5; // "IV = "
                    ConvertHexStrToBin(cursor, iv);
                }

                std::string result;
                result.resize(32, 0);

                if (enMode == Encryption_mode) {
                    // Get encrypted data
                    cursor = strstr(cursor, "PLAINTEXT");
                    cursor += 12; // "PLAINTEXT = "

                    ConvertHexStrToBin(cursor, input);

                    cursor = strstr(cursor, "CIPHERTEXT");
                    cursor += 13; // "CIPHERTEXT = "

                    result = std::string(cursor, 32);
                }
                else {
                    // Get decrypted data
                    cursor = strstr(cursor, "CIPHERTEXT");
                    cursor += 13; // "CIPHERTEXT = "

                    ConvertHexStrToBin(cursor, input);

                    cursor = strstr(cursor, "PLAINTEXT");
                    cursor += 12; // "PLAINTEXT = "

                    ConvertHexStrToBin(cursor, (unsigned char*)result.c_str());
                }

                ProcessingByBlockCipherTestKAT_AESFunc(input, 16, No_padding, key, cipher, 16, opMode, iv, NO_ERROR, result.c_str(), enMode, enMode == Encryption_mode ? 32 : 16, name, i);
            }
        }
        zip_entry_close(zip);
    }
    zip_close(zip);
}
