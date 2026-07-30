/*
 * srv_glue.c - the glue BOTH links need.
 *
 * Sources compiled under WINE_UNIX_LIB -- the wineserver files in the server
 * link (server/{object,handle,user,atom,...}.c), and win32u's own sources in
 * the DLL -- expect a handful of things ntdll.so exports, a few libc corners
 * ucrtbase does not carry, and mingw's internal printf entry points. None of
 * that is specific to either link, so it is spelled once here.
 *
 * It lives in its own file because everything else in win32u/glue.c -- the
 * user-mode callback pair, the pthread wrappers, the FreeType symbol table,
 * the display driver hooks -- belongs to the DLL alone and would drag it
 * into the server if it came along. Moved verbatim out of win32u/glue.c; no
 * behaviour changed. It is the ONLY file of the wineserver-lite tree the DLL
 * still takes: since the in-process dispatch mode went away the DLL links no
 * state machine at all, only the transport client beside it.
 */

#include <pthread.h>
#include <corecrt_stdio_config.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ntstatus.h"
#include "win32u_private.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(win32u);

/* --- 5. what WINE_UNIX_LIB expects ntdll.so to export ----------------------
 *
 * Under WINE_UNIX_LIB these are real calls into ntdll.so rather than the
 * inline TEB reads the PE headers use (winnt.h, processthreadsapi.h). The
 * definitions are the inline ones, spelled once here. */

struct _TEB * WINAPI NtCurrentTeb(void)
{
    struct _TEB *teb;

    __asm__( "movq %%gs:0x30,%0" : "=r" (teb) );
    return teb;
}

HANDLE WINAPI PsGetCurrentProcessId(void)
{
    return NtCurrentTeb()->ClientId.UniqueProcess;
}

HANDLE WINAPI PsGetCurrentThreadId(void)
{
    return NtCurrentTeb()->ClientId.UniqueThread;
}

/* win32u/syscall.c narrows allocations for a WoW64 client; there is no
 * 32-bit client here (x86_64 only, ADR 0006), so the whole address space is
 * available - the same value Wine uses for a pure 64-bit process. */
ULONG_PTR zero_bits = 0;

/* musl's error hook: Wine's PE build leaves errno alone too. */
void math_error( int type, const char *name, double x, double y, double result ) { }

/* --- 6. the last few libc corners ------------------------------------------
 *
 * ucrtbase covers everything win32u actually calls except these. strdup is
 * real (opentype.c and the server's atom code use it); the descriptor calls
 * are reachable only from wineserver paths this build refuses elsewhere, so
 * they refuse here too rather than pretending to have a file system. The
 * font backend's own file calls are NOT here -- they are implemented, over
 * Nt*, in font_unix.c. */

char *strdup( const char *str )
{
    size_t size = strlen( str ) + 1;
    char *copy = malloc( size );

    if (copy) memcpy( copy, str, size );
    return copy;
}

int dup( int fd )
{
    ERR( "no unix descriptors in this build\n" );
    return -1;
}

ssize_t pread( int fd, void *buffer, size_t count, off_t offset )
{
    ERR( "no unix descriptors in this build\n" );
    return -1;
}

char *realpath( const char *path, char *resolved )
{
    ERR( "no unix paths in this build\n" );
    return NULL;
}

/* --- 7b. the printf family -------------------------------------------------
 *
 * mingw's stdio.h routes the v*printf family through its own ANSI-conforming
 * copies in libmingwex, which this DLL does not link (it would bring a
 * second CRT alongside ucrtbase). The mingw spellings are therefore defined
 * here, over ucrtbase's real entry points.
 *
 * Over __stdio_common_vsprintf, NOT over vsnprintf: mingw's stdio.h defines
 * vsnprintf AS __mingw_vsnprintf, so a definition that calls vsnprintf calls
 * itself. (It compiles, links, and tail-calls into `jmp .`; the guest sat
 * there spinning at CPL=3 until QEMU's registers said which symbol it was.)
 * __stdio_common_vsprintf is UCRT's actual ABI underneath all of them and no
 * macro rewrites it.
 *
 * The locale parameter is spelled _locale_t, UCRT's own type, rather than a
 * plain void *: newer mingw stdio.h declares both of these itself, and a
 * declaration that disagrees in any parameter type is a hard error there
 * (it was merely a redundant redeclaration on the mingw that had neither).
 * Both callers below pass NULL, so the spelling is all that changes.
 */

int __cdecl __stdio_common_vsprintf( unsigned __int64 options, char *buffer, size_t count,
                                     const char *format, _locale_t locale, va_list args );
int __cdecl __stdio_common_vsscanf( unsigned __int64 options, const char *input, size_t count,
                                    const char *format, _locale_t locale, va_list args );

/* Ask for C99 truncation semantics (return the length that WOULD have been
 * written, always NUL-terminate) rather than MSVC's -1. The flag is UCRT's,
 * so it comes from UCRT's header rather than being typed here (G8). */
static int prsk_vsnprintf( char *buffer, size_t count, const char *format, va_list args )
{
    return __stdio_common_vsprintf( _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR, buffer, count,
                                    format, NULL, args );
}

int __mingw_vsnprintf( char *buffer, size_t count, const char *format, va_list args )
{
    return prsk_vsnprintf( buffer, count, format, args );
}

int __ms_vsnprintf( char *buffer, size_t count, const char *format, va_list args )
{
    return prsk_vsnprintf( buffer, count, format, args );
}

/* The variadic spelling, needed because the two mingw generations disagree
 * about whether it is a symbol at all -- and they disagree in a way that
 * makes the obvious `int snprintf(...)` wrong on one of them:
 *
 * - mingw 14 only DECLARES snprintf, and asm-aliases __ms_snprintf onto the
 *   symbol `snprintf` (_mingw_mac.h __MINGW_ASM_CALL, reached from stdio.h
 *   via __MINGW_UCRT_ASM_CALL), so every caller here leaves win32u.dll with
 *   an undefined reference this DLL has to answer, like every other CRT
 *   entry point it stands in for.
 * - the older stdio.h (Ubuntu's, what CI builds with) instead DEFINES
 *   snprintf itself, as an inline expanding onto __ms_vsnprintf above --
 *   nothing to link, and an out-of-line definition of that same C identifier
 *   is a hard redefinition error.
 *
 * So define the symbol without declaring the identifier: the asm label names
 * `snprintf` for the linker while the C name stays private, which the older
 * header's inline cannot collide with. Unconditional and correct on both --
 * it is the entry point the newer toolchain links against, and one
 * unreferenced function on the older one. */
int prsk_snprintf( char *buffer, size_t count, const char *format, ... ) __asm__("snprintf");
int prsk_snprintf( char *buffer, size_t count, const char *format, ... )
{
    va_list args;
    int ret;

    va_start( args, format );
    ret = prsk_vsnprintf( buffer, count, format, args );
    va_end( args );
    return ret;
}

int __mingw_vsscanf( const char *input, const char *format, va_list args )
{
    return __stdio_common_vsscanf( 0, input, (size_t)-1, format, NULL, args );
}

int __ms_vsscanf( const char *input, const char *format, va_list args )
{
    return __mingw_vsscanf( input, format, args );
}

int __mingw_vasprintf( char **out, const char *format, va_list args )
{
    va_list copy;
    int len;

    va_copy( copy, args );
    len = prsk_vsnprintf( NULL, 0, format, copy );
    va_end( copy );
    if (len < 0 || !(*out = malloc( len + 1 ))) return -1;
    return prsk_vsnprintf( *out, len + 1, format, args );
}

int asprintf( char **out, const char *format, ... )
{
    va_list args;
    int ret;

    va_start( args, format );
    ret = __mingw_vasprintf( out, format, args );
    va_end( args );
    return ret;
}

/* Only wineserver's dump helpers print to a FILE*, and there is no stderr
 * here - diagnostics go to serial (prsk_log above). */
int __mingw_vfprintf( FILE *file, const char *format, va_list args ) { return 0; }
int __mingw_vfscanf( FILE *file, const char *format, va_list args ) { return -1; }
int __ms_vfscanf( FILE *file, const char *format, va_list args ) { return -1; }
int fprintf( FILE *file, const char *format, ... ) { return 0; }
int fscanf( FILE *file, const char *format, ... ) { return -1; }


/* --- serial diagnostics ----------------------------------------------------
 *
 * The kernel's own convention (docs/08): machine-readable prefixes, human
 * text after. NtDisplayString is the transport the kernel's [KTEST] lines
 * use, so a refusal from in here lands in the same log the harness greps.
 *
 * Here rather than in shim.c because BOTH links diagnose: the DLL no longer
 * carries the state machine, but its transport still has to name a failure. */

void prsk_log( const char *format, ... )
{
    char text[512];
    WCHAR wide[512];
    UNICODE_STRING str;
    va_list args;
    int len, i;

    va_start( args, format );
    len = vsnprintf( text, sizeof(text) - 1, format, args );
    va_end( args );
    if (len < 0) return;
    if (len > (int)sizeof(text) - 1) len = sizeof(text) - 1;

    for (i = 0; i < len; i++) wide[i] = (unsigned char)text[i];
    str.Buffer = wide;
    str.Length = len * sizeof(WCHAR);
    str.MaximumLength = str.Length;
    NtDisplayString( &str );
}

/* --- the fd boundary -------------------------------------------------------
 *
 * win32u calls these on the paths that would pass a unix fd to the server.
 * There are no fds here, so each refuses BY NAME (Art. 12) rather than
 * answering.
 *
 * They live here, not in shim.c, and that placement is load-bearing: win32u
 * references them whether or not the state machine is in the link, and the
 * pinned ntdll EXPORTS all three. A definition carried only by shim.c
 * therefore stops being a refusal the moment the DLL drops shim.o -- the
 * linker silently rebinds the call to ntdll's import and the unbuilt path
 * starts answering plausibly, which is exactly what Art. 12 forbids and
 * exactly what happened to wine_server_handle_to_fd when the state machine
 * left the DLL. The link rule for win32u.dll now asserts that no wine_server_*
 * import survives, so a fourth one cannot repeat it. */

void wine_server_send_fd( int fd )
{
    prsk_log( "[KTEST] wineserver-lite: wine_server_send_fd is unbuilt\n" );
}

NTSTATUS CDECL wine_server_fd_to_handle( int fd, unsigned int access, unsigned int attributes,
                                         HANDLE *handle )
{
    prsk_log( "[KTEST] wineserver-lite: wine_server_fd_to_handle is unbuilt\n" );
    *handle = NULL;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS CDECL wine_server_handle_to_fd( HANDLE handle, unsigned int access, int *unix_fd,
                                         unsigned int *options )
{
    prsk_log( "[KTEST] wineserver-lite: wine_server_handle_to_fd is unbuilt\n" );
    return STATUS_NOT_IMPLEMENTED;
}
