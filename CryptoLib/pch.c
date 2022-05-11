// pch.c: source file corresponding to the pre-compiled header
//

#include "pch.h"

// When you are using pre-compiled headers, this source file is necessary for compilation to succeed.

#ifndef __STDC_LIB_EXT1__
errno_t memset_s(void* dest, rsize_t destsz, int ch, rsize_t count)
{
    if (dest && destsz >= count) {
        if (count & 7) {
            ++count;
            volatile uint8_t* p = (uint8_t*)dest - 1;
            while (--count)
                *++p = (uint8_t)ch;
        }
        else {
            count = (count >> 3) + 1;
            volatile uint64_t* p = (uint64_t*)dest - 1;
            while (--count)
                *++p = (uint64_t)ch;
        }
    }

    return 0;
}
#endif // __STDC_LIB_EXT1__
