#ifndef KN_DOTNET_EXOBF_H
#define KN_DOTNET_EXOBF_H

#include <windows.h>
#include <Macros.h>

constexpr ULONG ExprHashStringA(
    _In_ PCHAR String
) {
    ULONG Hash = 0;
    CHAR  Char = 0;

    Hash = H_MAGIC_KEY;

    if ( ! String ) {
        return 0;
    }

    while ( ( Char = *String++ ) ) {
        /* turn current character to uppercase */
        if ( Char >= 'a' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << H_MAGIC_SEED ) + Hash ) + Char;
    }

    return Hash;
}

#define HASH_STR( x )  U_PTR( ExprHashStringA( ( x ) ) )

#endif //KN_DOTNET_EXOBF_H
