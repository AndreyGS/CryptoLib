//  ProcessingByBlockCipherTestSupportFunctions.h
//

#pragma once

#include "common.h"

void ProcessingByBlockCipherTestFunc(__in const void* input, __in size_t inputSize, __in PaddingType padding, __in const void* key, __in BlockCipherType cipherType
    , __inout size_t outputSize, __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in int expectedStatus, __in_opt const char* expectedRes, __in CryptoMode enMode
);

void ProcessingByBlockCipherTestKAT_AESFunc(__in const void* input, __in size_t inputSize, __in PaddingType padding, __in const void* key, __in BlockCipherType cipherType
    , __inout size_t outputSize, __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in int expectedStatus, __in_opt const char* expectedRes, __in CryptoMode enMode, int expLength, const char* fileName, size_t testNum
);

void ProcessingByBlockCipherInPlaceTestFunc(__in const void* input, __in size_t inputSize, __in PaddingType padding, __in const void* key, __in BlockCipherType cipherType
    , __inout size_t outputSize, __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in int expectedStatus, __in_opt const char* expectedRes, __in CryptoMode enMode
);

void ProcessingByBlockCipherMultipartTestFunc(__in const void* input_1, __in size_t inputSize_1, __in const void* input_2, __in size_t inputSize_2, __in PaddingType padding, __in const void* key, __in BlockCipherType cipherType
    , __in BlockCipherOpMode mode, __in_opt const void* cIv
    , __in_opt const char* expectedRes, __in CryptoMode enMode
);
