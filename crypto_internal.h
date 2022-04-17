#pragma once

#include "crypto.h"

int CheckInput(__in const void* input, __in uint64_t inputSize);
int CheckOutput(__in const void* output, __in const uint64_t* outputSize);
int CheckInputOutput(__in const void* input, __in uint64_t inputSize, __in const void* output, __in const uint64_t* outputSize);
int CheckBlockCipherPrimaryArguments(const void* input, uint64_t inputSize, uint64_t* roundsKeys, void* output, uint64_t* outputSize, BlockCipherOpMode mode, const void* iv);

extern inline uint32_t Uint32BigEndianLeftRotateByOne(uint32_t word);
extern inline uint32_t Uint32BigEndianLeftRotate(uint32_t word, int rounds);
extern inline uint64_t Uint64LittleEndianToBigEndian(uint64_t input);
extern inline uint32_t Uint32LittleEndianToBigEndian(uint32_t input);
extern inline uint32_t Uint32BigEndianRightRotate(uint32_t word, int rounds);
extern inline uint64_t Uint64BigEndianRightRotate(uint64_t word, int rounds);
