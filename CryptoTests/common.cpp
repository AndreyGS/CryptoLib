// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
//  common.cpp
//

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

std::string GetHexResult(const uint8_t* input, size_t inputSize)
{
    std::string str;
    str.resize(inputSize << 1);

    for (size_t i = 0, j = 0; i < inputSize; ++i) {
        str[j++] = GetHexSymbol(input[i] >> 4);
        str[j++] = GetHexSymbol(input[i] & 0x0f);
    }

    return str;
}

void ConvertHexStrToBin(const char* input, unsigned char* output)
{
    while ((input[0] >= '0' && input[0] <= '9') || (input[0] >= 'a' && input[0] <= 'f') || (input[0] >= 'A' && input[0] <= 'F')) {
        if (input[0] >= '0' && input[0] <= '9')
            *output = (input[0] - '0') << 4;
        else if (input[0] == 'a' || input[0] == 'A')
            *output = 160;
        else if (input[0] == 'b' || input[0] == 'B')
            *output = 176;
        else if (input[0] == 'c' || input[0] == 'C')
            *output = 192;
        else if (input[0] == 'd' || input[0] == 'D')
            *output = 208;
        else if (input[0] == 'e' || input[0] == 'E')
            *output = 224;
        else if (input[0] == 'f' || input[0] == 'F')
            *output = 240;

        if (input[1] >= '0' && input[1] <= '9')
            *output += input[1] - '0';
        else if (input[1] == 'a' || input[1] == 'A')
            *output += 10;
        else if (input[1] == 'b' || input[1] == 'B')
            *output += 11;
        else if (input[1] == 'c' || input[1] == 'C')
            *output += 12;
        else if (input[1] == 'd' || input[1] == 'D')
            *output += 13;
        else if (input[1] == 'e' || input[1] == 'E')
            *output += 14;
        else if (input[1] == 'f' || input[1] == 'F')
            *output += 15;

        ++output;
        input += 2;
    }
}