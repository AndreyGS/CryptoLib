// pch.c: source file corresponding to the pre-compiled header
//

#include "pch.h"

// When you are using pre-compiled headers, this source file is necessary for compilation to succeed.

#ifndef __STDC_LIB_EXT1__
    #ifdef _WIN32
        errno_t memset_s(void* dest, rsize_t destsz, int ch, rsize_t count)
        {
            SecureZeroMemory(dest, count);
            return 0;
        }
    #else
        errno_t memset_s(void* dest, rsize_t destsz, int ch, rsize_t count)
        {
            if (count)
                while (count--)
                    *((uint8_t*)dest)++ = (uint8_t)ch;
        }
    #endif // _WIN32
#endif // __STDC_LIB_EXT1__
