// kdf.h
//

#pragma once

#include "crypto_internal.h"

int GetPbkdf2Internal(__in const void* salt, __in uint64_t saltSize, __in const void* key, __in uint64_t keySize, __in PRF func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize);
