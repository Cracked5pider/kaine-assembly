#ifndef KN_DOTNET_DEFS_H
#define KN_DOTNET_DEFS_H

#include <windows.h>

typedef struct _BUFFER {
    union {
        ULONG_PTR u;
        PVOID     p;
        PSTR      a;
        PWSTR     w;
        PWSTR*    wa;
    } Buffer;

    ULONG Length;
} BUFFER, *PBUFFER;

#define H_LIB_NTDLL      0x70e61753
#define H_LIB_KERNEL32   0xadd31df0
#define H_LIB_KERNELBASE 0x6F1259F0
#define H_LIB_MSCOREE    0xab2079d
#define H_LIB_MSVCRT     0x7a21064e
#define H_LIB_OLE32      0xe44617fe
#define H_LIB_SHELL32    0x296b54ac
#define H_LIB_USER32     0x2208cf13
#define H_LIB_AMSI       0x85B53BE6

#endif //KN_DOTNET_DEFS_H
