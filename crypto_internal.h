// crypto_internal.h
//

#pragma once

#include "crypto_helpers.h"

int GetHashMultipleInternal(__in const HashInputNode* inputList, __in uint64_t inputListSize, __in HashFunc func, __out void* output);
