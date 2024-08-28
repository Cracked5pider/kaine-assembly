#ifndef KAINE_MODULES_KAINEDEF_H
#define KAINE_MODULES_KAINEDEF_H

#include <windows.h>

#define PIPE_BUFFER_LENGTH 0x10000

#define KN_DOTNET_FLAG_PIPE            1 << 0  // write output back to a pipe
#define KN_DOTNET_FLAG_APPDOMAIN       1 << 2  // specified a custom app domain
#define KN_DOTNET_FLAG_LIST_VERSION    1 << 3  // list all .NET versions
#define KN_DOTNET_FLAG_LIST_APPDOMAINS 1 << 4  // list all app domains in the current process
#define KN_DOTNET_FLAG_INJECTED        1 << 5  // check if the loader has been injected. behaviours are going to change based on this flag like connecting back to the pipe
#define KN_DOTNET_FLAG_LOAD            1 << 6  // load and keep the assembly in memory
#define KN_DOTNET_FLAG_INVOKE          1 << 7  // invoke loaded assembly in memory
#define KN_DOTNET_FLAG_BYPASS_ETW      1 << 8  // patch etw using hardware breakpoints
#define KN_DOTNET_FLAG_BYPASS_AMSI     1 << 9  // patch amsi using hardware breakpoints
#define KN_DOTNET_FLAG_UNLOAD          1 << 10 // unload specified app domain

typedef struct _DOTNET_FLAGS {
    union {
        ULONG Value;

        struct {
            ULONG Pipe        : 1;
            ULONG             : 1;
            ULONG AppDomain   : 1;
            ULONG ListVersion : 1;
            ULONG ListDomains : 1;
            ULONG IsInjected  : 1;
            ULONG KeepLoaded  : 1;
            ULONG Invoke      : 1;
            ULONG BypassEtw   : 1;
            ULONG BypassAmsi  : 1;
            ULONG Unload      : 1;
        };
    };
} DOTNET_FLAGS;

typedef struct _ARG_CTX {
    DOTNET_FLAGS Flags;

    union {
        struct {
            BUFFER Assembly;
            BUFFER Arguments;
            BUFFER AppDomain;
            BUFFER Version;
            BUFFER PipeName;
        } Invoke;

        struct {
            ULONG ( *AddBytes )(
                _Inout_ PBUFFER Buffer,
                _In_    PVOID   Data,
                _In_    ULONG   Size
            );

            BUFFER Version;
            BUFFER Domain;
        } Misc;
    };

    struct {
        union {
            PBUFFER Buffer;

            struct {
                HANDLE Read;
                HANDLE Write;
                HANDLE StdoutBkg;
            } IoPipe;
        };
    } Return;

} ARG_CTX, *PARG_CTX;

typedef struct _ROUTINE_CTX {
    DOTNET_FLAGS Flags;
    ULONG        PacketId;
    BUFFER       PipeName;
    HANDLE       Pipe;
    BUFFER       Memory;
    HANDLE       Process;
} ROUTINE_CTX, *PROUTINE_CTX;

#endif //KAINE_MODULES_KAINEDEF_H
