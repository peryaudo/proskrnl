/*
 * srv_glue.c - the glue BOTH links of the GUI object model need.
 *
 * The wineserver files compiled here (server/{object,handle,user,atom,...}.c)
 * are unix sources: they expect a handful of things ntdll.so exports under
 * WINE_UNIX_LIB, a few libc corners ucrtbase does not carry, and mingw's
 * internal printf entry points. None of that is specific to win32u.
 *
 * It lives in its own file because GUI-3 gave the state machine a second
 * link: win32u.dll (the in-process mode) and wineserver-lite.exe (the
 * server process) both compile the same server objects, so both need this,
 * while everything else in win32u/glue.c -- the user-mode callback pair, the
 * pthread wrappers, the FreeType symbol table, the display driver hooks --
 * belongs to the DLL alone and would drag it into the server if it came
 * along. Moved verbatim out of win32u/glue.c; no behaviour changed.
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
 */

int __cdecl __stdio_common_vsprintf( unsigned __int64 options, char *buffer, size_t count,
                                     const char *format, void *locale, va_list args );
int __cdecl __stdio_common_vsscanf( unsigned __int64 options, const char *input, size_t count,
                                    const char *format, void *locale, va_list args );

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
 * here - diagnostics go to serial (user/wine/server/shim.c prsk_log). */
int __mingw_vfprintf( FILE *file, const char *format, va_list args ) { return 0; }
int __mingw_vfscanf( FILE *file, const char *format, va_list args ) { return -1; }
int __ms_vfscanf( FILE *file, const char *format, va_list args ) { return -1; }
int fprintf( FILE *file, const char *format, ... ) { return 0; }
int fscanf( FILE *file, const char *format, ... ) { return -1; }

