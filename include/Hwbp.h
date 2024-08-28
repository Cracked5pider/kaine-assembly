#ifndef KN_DOTNET_HWBP_H
#define KN_DOTNET_HWBP_H

#include <windows.h>

__forceinline
ULONG_PTR ExContextReturnAddr(
    _In_ PCONTEXT Context
) {
    return * ( PULONG_PTR ) Context->Rsp;
}

__forceinline
ULONG_PTR ExContextArgument(
    _In_ PCONTEXT Context,
    _In_ ULONG    Argc
) {
    switch ( Argc ) {
        case 0 : return Context->Rcx;
        case 1 : return Context->Rdx;
        case 2 : return Context->R8;
        case 3 : return Context->R9;
        default: return * ( PULONG_PTR ) ( Context->Rsp + ( ( Argc + 1 ) * sizeof( PVOID ) ) );
    }
}

__forceinline
VOID ExContextSetInstruction(
    _In_ PCONTEXT  Context,
    _In_ ULONG_PTR Pointer
) {
    Context->Rip = Pointer;
}

__forceinline
VOID ExContextAdjustStack(
    _In_ PCONTEXT Context,
    _In_ ULONG    Adjust
) {
    Context->Rsp += Adjust;
}

__forceinline
VOID ExContextSetReturn(
    _In_ PCONTEXT  Context,
    _In_ ULONG_PTR Return
) {
    Context->Rax = Return;
}

NTSTATUS HwbpEngineBreakpoint(
    _In_ ULONG Position,
    _In_ PVOID Function
);

LONG HwbpExceptionEtw(
    _Inout_ PEXCEPTION_POINTERS Exceptions
);

LONG HwbpExceptionAmsi(
    _Inout_ PEXCEPTION_POINTERS Exceptions
);

LONG HwbpExceptionEtwAmsi(
    _Inout_ PEXCEPTION_POINTERS Exceptions
);

#endif //KN_DOTNET_HWBP_H
