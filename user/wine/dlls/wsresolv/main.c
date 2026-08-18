/*
 * wsresolv main — the exported entry table, the report channel, and the
 * heap plumbing (see wsresolv.h).
 *
 * ws2_32's seam resolves ONE export, __wine_unix_call_funcs, and indexes
 * it by enum ws_unix_funcs (dlls/ws2_32/ws2_32_private.h). The table
 * below is that enum written out in order; the C_ASSERT pins the count so
 * a wine pin bump that grows the surface fails this build instead of
 * dispatching off the table's end.
 */
#include <stdio.h>

#include "wsresolv.h"

void resolv_report( const char *format, ... )
{
    char text[256];
    WCHAR wide[256];
    UNICODE_STRING str;
    va_list args;
    int len, i;

    va_start( args, format );
    len = _vsnprintf( text, sizeof(text) - 1, format, args );
    va_end( args );
    if (len < 0) return;
    if (len > (int)sizeof(text) - 1) len = (int)sizeof(text) - 1;

    for (i = 0; i < len; i++) wide[i] = (unsigned char)text[i];
    str.Buffer = wide;
    str.Length = len * sizeof(WCHAR);
    str.MaximumLength = str.Length;
    NtDisplayString( &str );
}

void *resolv_alloc( unsigned int size )
{
    return RtlAllocateHeap( NtCurrentTeb()->Peb->ProcessHeap, 0, size );
}

void resolv_free( void *ptr )
{
    if (ptr) RtlFreeHeap( NtCurrentTeb()->Peb->ProcessHeap, 0, ptr );
}

extern NTSTATUS resolv_getaddrinfo( void *args );
extern NTSTATUS resolv_gethostbyaddr( void *args );
extern NTSTATUS resolv_gethostbyname( void *args );
extern NTSTATUS resolv_gethostname( void *args );
extern NTSTATUS resolv_getnameinfo( void *args );

typedef NTSTATUS (*resolv_entry)( void *args );

DECLSPEC_EXPORT const resolv_entry __wine_unix_call_funcs[] =
{
    resolv_getaddrinfo,
    resolv_gethostbyaddr,
    resolv_gethostbyname,
    resolv_gethostname,
    resolv_getnameinfo,
};

C_ASSERT( ARRAY_SIZE(__wine_unix_call_funcs) == ws_unix_funcs_count );

BOOL WINAPI DllMain( HINSTANCE instance, DWORD reason, void *reserved )
{
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
