#ifndef KN_DOTNET_EXT_H
#define KN_DOTNET_EXT_H

#include <windows.h>
#include <Macros.h>

EXTERN_C PVOID KnRipData(
    VOID
);

EXTERN_C PVOID LdrModuleHandle(
    _In_ ULONG Hash
);

PVOID KNAPI LdrFunction(
    _In_ PVOID Library,
    _In_ ULONG Function
);

ULONG KNAPI KnDeobfuscate(
    _In_ ULONG Value
);

SIZE_T KNAPI KnUtilStrLenW(
    _In_ PCWSTR String
);

SIZE_T KNAPI KnUtilStrCmpW(
    _In_ PWSTR String1,
    _In_ PWSTR String2,
    _In_ ULONG Size
);

__forceinline
VOID KnUnicodeString(
    _Out_ PUNICODE_STRING Unicode,
    _In_  PWSTR           String
) {
    Unicode->MaximumLength = ( Unicode->Length = KnUtilStrLenW( String ) * sizeof( WCHAR ) ) + sizeof( WCHAR );
    Unicode->Buffer        = String;
}

__forceinline
VOID KnUnicodeZero(
    _In_ PUNICODE_STRING Unicode
) {
    RtlSecureZeroMemory( Unicode->Buffer, Unicode->Length );
    RtlSecureZeroMemory( Unicode, sizeof( UNICODE_STRING ) );
}

EXTERN_C ULONG KnHashString(
    _In_ PVOID  String,
    _In_ SIZE_T Length
);

VOID KNAPI KnSleepShared(
    _In_ ULONG64 MilliSec
);

#endif
