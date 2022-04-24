// pch.c: source file corresponding to the pre-compiled header
//

#include "pch.h"

// When you are using pre-compiled headers, this source file is necessary for compilation to succeed.

#ifndef __STDC_LIB_EXT1__
errno_t memset_s(void* dest, rsize_t destsz, int ch, rsize_t count)
{
    if (count) {
        volatile uint8_t* p = dest;
        while (count--)
            *p++ = (uint8_t)ch;
    }

    return 0;
}
#endif // __STDC_LIB_EXT1__
