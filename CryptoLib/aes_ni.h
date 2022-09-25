/**
 * @file aes_ni.h
 * @author Andrey Grabov-Smetankin <ukbpyh@gmail.com>
 *
 * @section LICENSE
 *
 * Copyright 2022 Andrey Grabov-Smetankin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#pragma once

#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

void Aes128AvxKeySchedule(__in const void* key, __out void* roundKeys, __out void* decryptionRoundKeys);
void Aes192AvxKeySchedule(__in const void* key, __out void* roundKeys, __out void* decryptionRoundKeys);
void Aes256AvxKeySchedule(__in const void* key, __out void* roundKeys, __out void* decryptionRoundKeys);

void Aes128NiKeySchedule(__in const void* key, __out void* roundKeys, __out void* decryptionRoundKeys);
void Aes192NiKeySchedule(__in const void* key, __out void* roundKeys, __out void* decryptionRoundKeys);
void Aes256NiKeySchedule(__in const void* key, __out void* roundKeys, __out void* decryptionRoundKeys);


/**
*   The next 4 functions are temporarily not used. If there will be full assembly-language AES algorithm they may be usefull
* 
void PrepareXmmRegistersForAesAvx(__in const uint64_t* roundKeys, __in  BlockCipherType type, __inout  uint64_t* xmmRegsBuffer);
void RestoreXmmRegistersFromAesAvx(__in BlockCipherType type, __in  uint64_t* xmmRegsBuffer);

void PrepareXmmRegistersForAesNi(__in const uint64_t* roundKeys, __inout  uint64_t* xmmRegsBuffer);
void RestoreXmmRegistersFromAesNi(__in uint64_t* xmmRegsBuffer);
*
*/

void Aes128NiEncryptBlock(__in const uint64_t* roundKeys, __in  const uint64_t* input, __out uint64_t* output);
void Aes192NiEncryptBlock(__in const uint64_t* roundKeys, __in  const uint64_t* input, __out uint64_t* output);
void Aes256NiEncryptBlock(__in const uint64_t* roundKeys, __in  const uint64_t* input, __out uint64_t* output);
void Aes128NiDecryptBlock(__in const uint64_t* roundKeys, __in  const uint64_t* input, __out uint64_t* output);
void Aes192NiDecryptBlock(__in const uint64_t* roundKeys, __in  const uint64_t* input, __out uint64_t* output);
void Aes256NiDecryptBlock(__in const uint64_t* roundKeys, __in  const uint64_t* input, __out uint64_t* output);

void Aes128AvxEncryptBlock(__in const uint64_t* roundKeys, __in  const uint64_t* input, __out uint64_t* output);
void Aes192AvxEncryptBlock(__in const uint64_t* roundKeys, __in  const uint64_t* input, __out uint64_t* output);
void Aes256AvxEncryptBlock(__in const uint64_t* roundKeys, __in  const uint64_t* input, __out uint64_t* output);
void Aes128AvxDecryptBlock(__in const uint64_t* roundKeys, __in  const uint64_t* input, __out uint64_t* output);
void Aes192AvxDecryptBlock(__in const uint64_t* roundKeys, __in  const uint64_t* input, __out uint64_t* output);
void Aes256AvxDecryptBlock(__in const uint64_t* roundKeys, __in  const uint64_t* input, __out uint64_t* output);

void SecureClearRegistersUsedInAes();

#ifdef __cplusplus
}
#endif