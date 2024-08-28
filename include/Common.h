#ifndef KN_DOTNET_COMMON_H
#define KN_DOTNET_COMMON_H

#include <windows.h>

//
// module specific headers
//
#include <Native.h>
#include <Macros.h>
#include <Ext.h>
#include <Defs.h>
#include <ClrHost.h>
#include <Constexpr.h>
#include <Hwbp.h>
#include <KaineDef.h>

typedef struct _MODULE {
    BOOL  LdrLoaded;
    PVOID Base;
} MODULE;

typedef struct _INSTANCE
{
    ARG_CTX Ctx;

    struct {
        //
        // ntdll.dll
        //
        D_API( LdrLoadDll )
        D_API( RtlAllocateHeap )
        D_API( RtlFreeHeap )
        D_API( RtlAddVectoredExceptionHandler )
        D_API( RtlRemoveVectoredExceptionHandler )
        D_API( NtClose );
        PVOID NtTraceEvent;

        //
        // kernelbase.dll
        //
        D_API( CommandLineToArgvW )
        union {
            D_API( CreatePipe )

            struct {
                D_API( CreateNamedPipeW )
                D_API( ConnectNamedPipe )
                D_API( DisconnectNamedPipe )
                D_API( WriteFile )
                D_API( FlushFileBuffers )
            };
        };
        D_API( AllocConsole )
        D_API( GetConsoleWindow )
        D_API( FreeConsole )

        //
        // user32.dll
        //
        D_API( ShowWindow )

        //
        // mscoree.dll
        //
        D_API( CLRCreateInstance )

        //
        // oleaut32.dll
        //
        D_API( SafeArrayCreate )
        D_API( SafeArrayDestroy )
        D_API( SafeArrayCreateVector )
        D_API( SafeArrayPutElement )
        D_API( SafeArrayGetLBound )
        D_API( SafeArrayGetUBound )
        D_API( SafeArrayGetElement )
        D_API( SysAllocString )
        D_API( SysFreeString )

        //
        // amsi.dll
        //
        PVOID AmsiScanBuffer;
    } Win32;

    PVOID Ntdll;
    PVOID KernelBase;
    PVOID User32;
    PVOID Mscoree;
    PVOID Ole32;
    PVOID Amsi;
} INSTANCE, *PINSTANCE;


namespace memory {
    __forceinline
    void copy(
        _Out_ PVOID Dst,
        _In_  PVOID Src,
        _In_  ULONG Len
    ) {
        __builtin_memcpy( Dst, Src, Len );
    }

    __forceinline
    void zero(
        _Inout_ PVOID Ptr,
        _In_    ULONG Len
    ) {
        RtlSecureZeroMemory( Ptr, Len );
    }
}

#endif // KN_DOTNET_COMMON_H
