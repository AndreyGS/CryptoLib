// sha-2.h
//

#pragma once

#include "crypto_helpers.h"

int Sha2_32Get(__in const VoidAndSizeNode* inputList, __in uint64_t inputListSize, __in HashFunc func, __out uint32_t* output);
int Sha2_64Get(__in const VoidAndSizeNode* inputList, __in uint64_t inputListSize, __in HashFunc func, __out uint64_t* output);
