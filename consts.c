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
