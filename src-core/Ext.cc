#include <Common.h>

/*!
 * @brief
 *  Hashing data
 *
 * @param String
 *  Data/String to hash
 *
 * @param Length
 *  size of data/string to hash.
 *  if 0 then hash data til null terminator is found.
 *
 * @return
 *  hash of specified data/string
 */
ULONG KNAPI KnHashString(
    _In_ PVOID  String,
    _In_ SIZE_T Length
) {
    ULONG  Hash = { 0 };
    PUCHAR Ptr  = { 0 };
    UCHAR  Char = { 0 };

    if ( ! String ) {
        return 0;
    }

    Hash = H_MAGIC_KEY;
    Ptr  = ( PUCHAR ) String;

    do {
        Char = *Ptr;

        if ( ! Length ) {
            if ( ! *Ptr ) break;
        } else {
            if ( U_PTR( Ptr - U_PTR( String ) ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( Char >= 'a' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << 5 ) + Hash ) + Char;

        ++Ptr;
    } while ( TRUE );

    return Hash;
}

SIZE_T KNAPI KnUtilStrLenW(
    _In_ PCWSTR String
) {
    PCWSTR String2;

    for ( String2 = String; *String2; ++String2 );

    return ( String2 - String );
}

SIZE_T KNAPI KnUtilStrCmpW(
    _In_ PWSTR String1,
    _In_ PWSTR String2,
    _In_ ULONG Size
) {
    PWSTR s1 = { 0 };
    PWSTR s2 = { 0 };
    WCHAR c1 = { 0 };
    WCHAR c2 = { 0 };

    if ( ! ( s1 = String1 ) || ! ( s2 = String2 ) ) {
        return -1;
    }

    while ( Size-- ) {
        c1 = *s1;
        c2 = *s2;

        if ( c1 != c2 ) {
            return ( c1 - c2 );
        }

        if ( ! c1 ) {
            return 0;
        }

        ++s1;
        ++s2;
    }

    return 0;
}

/*!
 * @brief
 *  resolve module from peb
 *
 * @param Buffer
 *  Buffer: either string or hash
 *
 * @param Hashed
 *  is the Buffer a hash value
 *
 * @return
 *  module base pointer
 */
PVOID KNAPI LdrModuleHandle(
    _In_ ULONG Hash
) {
    KN_RANGE_LIST( NtCurrentPeb()->Ldr->InLoadOrderModuleList, PLDR_DATA_TABLE_ENTRY, {
        if ( ! Hash ) {
            return Entry->DllBase;
        }

        if ( KnHashString( Entry->BaseDllName.Buffer, Entry->BaseDllName.Length ) == Hash ) {
            return Entry->DllBase;
        }
    } )

    return NULL;
}

/*!
 * @brief
 *  retrieve image header
 *
 * @param Image
 *  image base pointer to retrieve header from
 *
 * @return
 *  pointer to Nt Header
 */
FUNC PIMAGE_NT_HEADERS LdrpImageHeader(
    _In_ PVOID Image
) {
    PIMAGE_DOS_HEADER DosHeader = { 0 };
    PIMAGE_NT_HEADERS NtHeader  = { 0 };

    DosHeader = C_PTR( Image );

    if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
        return NULL;
    }

    NtHeader = C_PTR( U_PTR( Image ) + DosHeader->e_lfanew );

    if ( NtHeader->Signature != IMAGE_NT_SIGNATURE ) {
        return NULL;
    }

    return NtHeader;
}

PVOID KNAPI LdrFunction(
    _In_ PVOID Library,
    _In_ ULONG Function
) {
    PVOID                   Address    = { 0 };
    PIMAGE_NT_HEADERS       NtHeader   = { 0 };
    PIMAGE_EXPORT_DIRECTORY ExpDir     = { 0 };
    SIZE_T                  ExpDirSize = { 0 };
    PDWORD                  AddrNames  = { 0 };
    PDWORD                  AddrFuncs  = { 0 };
    PWORD                   AddrOrdns  = { 0 };
    PCHAR                   FuncName   = { 0 };

    //
    // sanity check arguments
    //
    if ( ! Library || ! Function ) {
        return NULL;
    }

    //
    // retrieve header of library
    //
    if ( ! ( NtHeader = LdrpImageHeader( Library ) ) ) {
        return NULL;
    }

    //
    // parse the header export address table
    //
    ExpDir     = C_PTR( Library + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExpDirSize = NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
    AddrNames  = C_PTR( Library + ExpDir->AddressOfNames );
    AddrFuncs  = C_PTR( Library + ExpDir->AddressOfFunctions );
    AddrOrdns  = C_PTR( Library + ExpDir->AddressOfNameOrdinals );

    //
    // iterate over export address table director
    //
    for ( DWORD i = 0; i < ExpDir->NumberOfNames; i++ ) {
        //
        // retrieve function name
        //
        FuncName = A_PTR( U_PTR( Library ) + AddrNames[ i ] );

        //
        // hash function name from Iat and
        // check the function name is what we are searching for.
        // if not found keep searching.
        //
        if ( KnHashString( FuncName, 0 ) != Function ) {
            continue;
        }

        //
        // resolve function pointer
        //
        Address = C_PTR( U_PTR( Library ) + AddrFuncs[ AddrOrdns[ i ] ] );

        //
        // check if function is a forwarded function
        //
        if ( ( U_PTR( Address ) >= U_PTR( ExpDir ) ) &&
             ( U_PTR( Address ) <  U_PTR( ExpDir ) + ExpDirSize )
        ) {
            //
            // TODO: need to add support for forwarded functions
            //
            __debugbreak();
        }

        break;
    }

    return Address;
}

ULONG64 KNAPI KnSharedTimeStamp(
    VOID
) {
    LARGE_INTEGER TimeStamp = {
            .LowPart	= USER_SHARED_DATA->SystemTime.LowPart,
            .HighPart	= USER_SHARED_DATA->SystemTime.High1Time
    };

    return TimeStamp.QuadPart;
}

VOID KNAPI KnSleepShared(
    _In_ ULONG64 MilliSec
) {
    ULONG64	Start = KnSharedTimeStamp() + ( MilliSec * 10000 );

    for ( SIZE_T RandomNmbr = 0x00; KnSharedTimeStamp() < Start; RandomNmbr++ );

    if ( ( KnSharedTimeStamp() - Start ) > 2000 ) {
        return;
    }
}