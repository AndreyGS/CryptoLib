// kdf.h
//

#pragma once

#include "crypto_internal.h"

int GetPbkdf2Internal(__in const void* salt, __in uint64_t saltSize, __in const void* password, __in uint64_t passwordSize, __in Prf func, __in uint64_t iterationsNum, __out void* output, __in uint64_t outputSize);
