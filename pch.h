// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <stdlib.h>

#ifdef __STDC_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>
#else
    errno_t memset_s(void* dest, rsize_t destsz, int ch, rsize_t count);
    #ifdef _WIN32 
        #include <Windows.h>
        #undef NO_ERROR
    #endif
#endif
        
#endif //PCH_H
