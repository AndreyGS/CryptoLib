// This is an independent project of an individual developer. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/**
 * @file consts.c
 * @author Andrey Grabov-Smetankin <ukbpyh@gmail.com>
 *
 * @section LICENSE
 *
 * Copyright 2022 Andrey Grabov-Smetankin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include "pch.h"

const uint8_t ONES_IN_BYTE[] = {
    0, 1, 1, 2, 1, 2, 2, 3,

    1, 2, 2, 3, 2, 3, 3, 4,

    1, 2, 2, 3, 2, 3, 3, 4,
    2, 3, 3, 4, 3, 4, 4, 5,

    1, 2, 2, 3, 2, 3, 3, 4,
    2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5,
    3, 4, 4, 5, 4, 5, 5, 6,

    1, 2, 2, 3, 2, 3, 3, 4,
    2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5,
    3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5,
    3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6,
    4, 5, 5, 6, 5, 6, 6, 7,

    1, 2, 2, 3, 2, 3, 3, 4,
    2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5,
    3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5,
    3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6,
    4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5,
    3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6,
    4, 5, 5, 6, 5, 6, 6, 7,
    3, 4, 4, 5, 4, 5, 5, 6,
    4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7,
    5, 6, 6, 7, 6, 7, 7, 8
};

const bool IS_EVEN[] = {
    true,  false, false, true,  false, true,  true,  false,

    false, true,  true,  false, true,  false, false, true,

    false, true,  true,  false, true,  false, false, true,
    true,  false, false, true,  false, true,  true,  false,

    false, true,  true,  false, true,  false, false, true,
    true,  false, false, true,  false, true,  true,  false,
    true,  false, false, true,  false, true,  true,  false,
    false, true,  true,  false, true,  false, false, true,

    false, true,  true,  false, true,  false, false, true,
    true,  false, false, true,  false, true,  true,  false,
    true,  false, false, true,  false, true,  true,  false,
    false, true,  true,  false, true,  false, false, true,
    true,  false, false, true,  false, true,  true,  false,
    false, true,  true,  false, true,  false, false, true,
    false, true,  true,  false, true,  false, false, true,
    true,  false, false, true,  false, true,  true,  false,

    false, true,  true,  false, true,  false, false, true,
    true,  false, false, true,  false, true,  true,  false,
    true,  false, false, true,  false, true,  true,  false,
    false, true,  true,  false, true,  false, false, true,
    true,  false, false, true,  false, true,  true,  false,
    false, true,  true,  false, true,  false, false, true,
    false, true,  true,  false, true,  false, false, true,
    true,  false, false, true,  false, true,  true,  false,
    true,  false, false, true,  false, true,  true,  false,
    false, true,  true,  false, true,  false, false, true,
    false, true,  true,  false, true,  false, false, true,
    true,  false, false, true,  false, true,  true,  false,
    false, true,  true,  false, true,  false, false, true,
    true,  false, false, true,  false, true,  true,  false,
    true,  false, false, true,  false, true,  true,  false,
    false, true,  true,  false, true,  false, false, true
};
