// crypto_helpers.h
//

#pragma once

#include "crypto.h"

#define EVAL(expr) { status = expr; if (status < 0) goto exit; }

int CheckInput(__in const void* input, __in uint64_t inputSize);
int CheckOutput(__in const void* output, __in const uint64_t* outputSize);
int CheckInputOutput(__in const void* input, __in uint64_t inputSize, __in const void* output, __in const uint64_t* outputSize);
int CheckBlockCipherPrimaryArguments(const void* input, uint64_t inputSize, uint64_t* roundsKeys, void* output, uint64_t* outputSize, BlockCipherOpMode mode, const void* iv);

extern inline uint32_t Uint32BigEndianLeftRotateByOne(uint32_t word);
extern inline uint32_t Uint32BigEndianLeftRotate(uint32_t word, int rounds);
extern inline uint32_t Uint32BigEndianRightRotate(uint32_t word, int rounds);
extern inline uint64_t Uint64BigEndianRightRotate(uint64_t word, int rounds);

// All "le to be" funcs also working as "be to le", obviously
extern inline uint32_t Uint32LittleEndianToBigEndian(uint32_t input);
extern inline uint64_t Uint64LittleEndianToBigEndian(uint64_t input);
extern inline uint64_t Uint64LittleEndianToBigEndianBits(uint64_t input);

extern inline void* AllocBuffer(size_t size);
extern inline void FreeBuffer(void* buffer);