#pragma once

#include "crypto.h"

const char TEST_STRING_7[] = "This is";
const char TEST_STRING_8[] = "somekind";
const char TEST_STRING_55[] = "ofthe test strings fortesting proposes, sowhat to write";
const char TEST_STRING_64[] = "here I don't really now. Maybe it should be something clever or ";
const char TEST_STRING_72[] = "hm Competition.This Standard also specifies the KECCAK - p family of mat";
const char TEST_STRING_104[] = "tance of the KECCAK algorithm that NIST selected as the winner of the SHA - 3 Cryptographic Hash Algorit";
const char TEST_STRING_111[] = "it can be so stupid that no one should see this. I don't really now, like I said before, but I must to finishit";
const char TEST_STRING_128[] = "The Federal Information Processing Standards (FIPS) Publication Series of the National Institute of Standards and Technology(NIS";
const char TEST_STRING_136[] = "is the official series of publications relating to standards and guidelines adopted and promulgated under the provisions of the Federal ";
const char TEST_STRING_144[] = "This Standard specifies the Secure Hash Algorithm-3 (SHA-3) family of functions on binary data.Each of the SHA - 3 functions is based on an inst";
const char TEST_STRING_168[] = "Information Security Management Act(FISMA) of 2002. Comments concerning FIPS publications are welcomed and should be addressed to the Director, Information Technology L";

#define STR_ERROR_WRONG_INPUT                   "ERROR_WRONG_INPUT"
#define STR_ERROR_WRONG_OUTPUT                  "ERROR_WRONG_OUTPUT"
#define STR_ERROR_WRONG_KEYS                    "ERROR_WRONG_KEYS"
#define STR_ERROR_WRONG_INPUT_SIZE              "ERROR_WRONG_INPUT_SIZE"
#define STR_ERROR_WRONG_OUTPUT_SIZE             "ERROR_WRONG_OUTPUT_SIZE"
#define STR_ERROR_WRONG_BLOCK_SIZE              "ERROR_WRONG_BLOCK_SIZE"
#define STR_ERROR_INAPPLICABLE_PADDING_TYPE     "ERROR_INAPPLICABLE_PADDING_TYPE"
#define STR_ERROR_PADDING_CORRUPTED             "ERROR_PADDING_CORRUPTED"
#define STR_ERROR_WRONG_INIT_VECTOR             "ERROR_WRONG_INIT_VECTOR"
#define STR_ERROR_HASHING_FUNC_NOT_SUPPORTED    "ERROR_HASHING_FUNC_NOT_SUPPORTED"
#define STR_ERROR_CIPHER_FUNC_NOT_SUPPORTED     "ERROR_CIPHER_FUNC_NOT_SUPPORTED"
#define STR_ERROR_WRONG_ITERATIONS_NUMBER       "ERROR_WRONG_ITERATIONS_NUMBER"
#define STR_ERROR_NO_MEMORY                     "ERROR_NO_MEMORY"

#define GET_ERROR_TXT(error) #error

char GetHexSymbol(uint8_t input);

std::string GetHexResult(const uint8_t* input, uint64_t inputSize);
