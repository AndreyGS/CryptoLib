// sha-2.h
//

#pragma once

#include "crypto_helpers.h"

void Sha2_32Get(__in const HashInputNode* inputList, __in uint64_t inputListSize, __in HashFunc func, __out uint32_t* output);
void Sha2_64Get(__in const HashInputNode* inputList, __in uint64_t inputListSize, __in HashFunc func, __out uint64_t* output);
