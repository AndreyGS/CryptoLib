// crypto_helpers.h
//

#pragma once

#include "crypto.h"

#define EVAL(expr) { status = expr; if (status < 0) goto exit; }

int CheckInput(__in const void* input, __in uint64_t inputSize);
int CheckOutput(__in const void* output, __in const uint64_t* outputSize);
int CheckInputOutput(__in const void* input, __in uint64_t inputSize, __in const void* output, __in const uint64_t* outputSize);
int CheckBlockCipherPrimaryArguments(const void* input, uint64_t inputSize, PaddingType padding, const uint64_t* key, BlockCipherType cipherType, const void* output, const uint64_t* outputSize, BlockCipherOpMode mode, const void* iv);
int CheckHashAndXofPrimaryArguments(const StateHandle state, const void* input, uint64_t inputSize, bool finalize, const void* output);

extern inline uint32_t Uint32BigEndianLeftRotateByOne(uint32_t word);
extern inline uint32_t Uint32BigEndianLeftRotate(uint32_t word, int rounds);
extern inline uint32_t Uint32BigEndianRightRotate(uint32_t word, int rounds);
extern inline uint64_t Uint64BigEndianRightRotate(uint64_t word, int rounds);

// All "le to be" funcs also working as "be to le", obviously
extern inline uint32_t Uint32LittleEndianToBigEndian(uint32_t input);
extern inline uint64_t Uint64LittleEndianToBigEndian(uint64_t input);
extern inline uint64_t Uint64LittleEndianToBigEndianBits(uint64_t input);

extern inline int AllocBuffer(size_t size, void**);
extern inline void FreeBuffer(void* buffer);

int FillLastDecryptedBlockInternal(__in PaddingType padding, __in uint64_t blockSize, __in const void* lastOutputBlock, __in uint64_t inputSize, __out void* output, __inout uint64_t* outputSize);
