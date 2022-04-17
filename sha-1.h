// sha-1.h
//

#pragma once

#include "crypto_helpers.h"

int Sha1Get(__in const HashInputNode* inputList, __in uint64_t inputListSize, __out void* output);
