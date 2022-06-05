#pragma once

#include "common.h"

void ProcessingByBlockCipherMainTestFunc(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __inout uint64_t outputSize, __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in int expectedStatus, __in_opt const void* expectedRes, __in uint64_t expectedResLength, bool inPlace, __in CryptoMode enMode
);

void ProcessingByBlockCipherTestFunc(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __inout uint64_t outputSize, __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in int expectedStatus, __in_opt const void* expectedRes, __in uint64_t expectedResLength, __in CryptoMode enMode
);

void ProcessingByBlockCipherInPlaceTestFunc(__in const void* input, __in uint64_t inputSize, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __inout uint64_t outputSize, __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in int expectedStatus, __in_opt const void* expectedRes, __in uint64_t expectedResLength, __in CryptoMode enMode
);

void ProcessingByBlockCipherMultipartTestFunc(__in const void* input_1, __in uint64_t inputSize_1, __in const void* input_2, __in uint64_t inputSize_2, __in PaddingType padding, __in void* key, __in BlockCipherType cipherType
    , __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in_opt const void* expectedRes, __in CryptoMode enMode
);
