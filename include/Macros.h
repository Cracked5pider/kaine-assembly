#ifndef KN_DOTNET_MACROS_H
#define KN_DOTNET_MACROS_H

#define KnSelf _Inout_opt_ PINSTANCE Instance
#define Self   Instance

//
// utils macros
//
#define D_API( x )               __typeof__( x ) * x;
#define V_API( x )               __typeof__( x ) *
#define D_SEC( x )               __attribute__( ( section( ".text$" #x "" ) ) )
#define D_SEC( x )               __attribute__( ( section( ".text$" #x "" ) ) )
#define FUNC                     D_SEC( B )
#define KNAPI                    D_SEC( B )
#define G_SYM( x )               C_PTR( U_PTR( __DATA_PTR ) - ( U_PTR( &KnRipData ) - U_PTR( x ) ) )
#define KN_READONLY              __attribute__( ( section( ".rdata" ) ) )
#define NtGetLastError()         ( Self->Teb->LastErrorValue )
#define NtSetLastError( x )      ( Self->Teb->LastErrorValue = x )
#define MmRangeCheck( p, b, l )  ( ( U_PTR( p ) >= U_PTR( b ) ) && ( U_PTR( p ) < ( U_PTR( b ) + l ) ) )
#define KnSymbolPointer()        PVOID __DATA_PTR = KnRipData();

#define KN_RANGE_RESOLVE( m, e ) KN_RANGE_RESOLVEEX( m, m, e, { return FALSE; } )
#define KN_RANGE_RESOLVEEX( mm, m, e, x )                                                                                                \
    for ( int i = 0; ( FIELD_OFFSET( INSTANCE, Win32.mm ) + ( i * sizeof( PVOID ) ) ) <= ( FIELD_OFFSET( INSTANCE, Win32.e ) ); i++ ) {  \
        if ( ! ( ( & Self.Win32.mm )[ i ] = LdrFunctionH( m, ( & Self.Win32.mm )[ i ] ) ) ) { x };                                       \
    }

#define KN_RANGE_LIST( HEAD_LIST, TYPE, SCOPE )     \
    {                                               \
        PLIST_ENTRY __Head = ( & HEAD_LIST );       \
        PLIST_ENTRY __Next = { 0 };                 \
        TYPE        Entry  = (TYPE)__Head->Flink;   \
        for ( ; __Head != (PLIST_ENTRY)Entry; ) {   \
            __Next = ((PLIST_ENTRY)Entry)->Flink;   \
            SCOPE                                   \
            Entry = (TYPE)(__Next);                 \
        }                                           \
    }

//
// casting macros
//
#define C_PTR( x )   ( ( PVOID    ) ( x ) )
#define H_PTR( x )   ( ( HANDLE   ) ( C_PTR( x ) ) )
#define U_PTR( x )   ( ( UINT_PTR ) ( x ) )
#define U_PTR32( x ) ( ( ULONG    ) ( x ) )
#define U_PTR64( x ) ( ( ULONG64  ) ( x ) )
#define A_PTR( x )   ( ( PCHAR   )  ( x ) )
#define W_PTR( x )   ( ( PWCHAR   ) ( x ) )

//
// dereference memory macros
//
#define C_DEF( x )   ( * ( PVOID*  ) ( x ) )
#define C_DEF08( x ) ( * ( UINT8*  ) ( x ) )
#define C_DEF16( x ) ( * ( UINT16* ) ( x ) )
#define C_DEF32( x ) ( * ( UINT32* ) ( x ) )
#define C_DEF64( x ) ( * ( UINT64* ) ( x ) )

//
// Hashing key
//
#define H_MAGIC_KEY  5381 /* also xor this key       */
#define H_MAGIC_SEED 5    /* also xor or change this */

#endif //KN_DOTNET_MACROS_H
