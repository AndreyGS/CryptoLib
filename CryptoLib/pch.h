// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

#ifndef KERNEL
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <stdlib.h>
#endif

#if defined(__STDC_LIB_EXT1__) && !defined(KERNEL)
#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>
#else
errno_t memset_s(void* dest, rsize_t destsz, int ch, rsize_t count);
#endif

#define ALIGN_TO_8_BYTES(x) (((x) + 7) & 7)

//#define GET_FIELD_OFFSET(type, field) &((#type*)0)->#field

#endif //PCH_H
