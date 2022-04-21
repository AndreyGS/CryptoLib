// sha-3.h
//

#pragma once

#include "crypto_helpers.h"

void Sha3Get(__in const HashInputNode* inputList, __in uint64_t inputListSize, __in HashFunc func, __out uint64_t* output, __in_opt uint16_t outputSize);
