#include "pch.h"

#include "common.h"

char GetHexSymbol(uint8_t input)
{
    switch (input) {
    case 0: return '0';
    case 1: return '1';
    case 2: return '2';
    case 3: return '3';
    case 4: return '4';
    case 5: return '5';
    case 6: return '6';
    case 7: return '7';
    case 8: return '8';
    case 9: return '9';
    case 10: return 'a';
    case 11: return 'b';
    case 12: return 'c';
    case 13: return 'd';
    case 14: return 'e';
    case 15: return 'f';
    default:
        return '\0';
    }
}

std::string GetHexResult(const uint8_t* input, uint64_t inputSize)
{
    std::string str;
    str.resize(inputSize << 1);

    for (uint64_t i = 0, j = 0; i < inputSize; ++i) {
        str[j++] = GetHexSymbol(input[i] >> 4);
        str[j++] = GetHexSymbol(input[i] & 0x0f);
    }

    return str;
}
