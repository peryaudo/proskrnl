/*
 * proskrnl_glue.c - everything the proskrnl build of Wine's conhost needs
 * that Wine's build environment provided (M9).
 *
 * conhost itself is NOT copied: the Makefile compiles the pinned tree's
 * programs/conhost/{conhost.c,proskrnl.c} directly, where the wineserver
 * seam lives as a runtime-dormant fork commit on the proskrnl-target branch
 * (behind !__wine_unix_call_dispatcher - Art. 10 / docs/06). This file
 * carries only what the standalone PE build lacks:
 *
 *   1. the process entry: open \Device\ConDrv\Server and then either open a
 *      window or take the \Device\Serial0 tty pair (HACK-004) and hand wmain
 *      its headless command line
 *   2. the mini CRT (heap over kernel32, string/memory over own loops)
 *
 * There is ONE conhost binary. It used to be two links from these sources —
 * a headless one whose user32 and window.c references were satisfied by
 * stand-ins, and a windowed one with the real ones — baked as conhost.exe on
 * different images, so which console a boot had was a property of its media.
 * That link is now the only one, and which mode it RUNS in is the boot's
 * derived `ConsoleWindow` (= `Gui && !Serial`; user/smss/smss.c).
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <wctype.h>
#include <windef.h>
#include <winbase.h>
#include <wincon.h>
#include <winuser.h>
#include <winternl.h>
#include <ntstatus.h>

/* --- 1. the process entry --------------------------------------------------- */

/* One authority for the server image's on-disk name (Art. 11): the same
 * macro win32u's transport probe uses. Names only — the wire structs need
 * Wine's protocol types, which conhost does not carry. */
#define PRSK_TRANSPORT_NAMES_ONLY
#include "proskrnl_bootflag.h"
#include "../../wineserver-lite/common/transport.h"

int __cdecl wmain( int argc, WCHAR *argv[] );

static void display( const char *text )
{
    WCHAR wide[128];
    UNICODE_STRING string;
    USHORT n = 0;

    while (text[n] && n < 127)
    {
        wide[n] = (WCHAR)(unsigned char)text[n];
        n++;
    }
    string.Length = (USHORT)(n * sizeof(WCHAR));
    string.MaximumLength = string.Length;
    string.Buffer = wide;
    NtDisplayString( &string );
}

static HANDLE open_device( const WCHAR *path, ACCESS_MASK access )
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    HANDLE handle = NULL;
    NTSTATUS status;

    name.Buffer = (WCHAR *)path;
    for (name.Length = 0; path[name.Length / sizeof(WCHAR)]; name.Length += sizeof(WCHAR)) ;
    name.MaximumLength = name.Length + sizeof(WCHAR);
    attr.Length = sizeof(attr);
    attr.RootDirectory = NULL;
    attr.ObjectName = &name;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    attr.SecurityDescriptor = NULL;
    attr.SecurityQualityOfService = NULL;
    status = NtCreateFile( &handle, access | SYNCHRONIZE, &attr, &io, NULL,
                           FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN,
                           FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0 );
    return status ? NULL : handle;
}

/* The REAL command line, parsed. Whoever launched this conhost decided its
 * mode there: stock kernelbase's alloc_console spawns
 * `conhost.exe --server 0x%x` (windowed; dlls/kernelbase/console.c
 * 472-475, `--headless` appended only for no-window allocs), and smss's
 * boot-console launch passes `--headless` plus the tty pair in the std
 * handles (user/smss/launch.c SmssStartConhost). conhost's arguments are
 * unquoted single tokens except argv[0], so the split is: a quoted or bare
 * first token, then whitespace-separated words (wmain's own parser,
 * conhost.c 3030-3080, consumes them pairwise). */
#define CONHOST_MAX_ARGS 16

void __attribute__((ms_abi)) conhost_start( void *peb )
{
    static WCHAR cmdline[512];
    static WCHAR *argv[CONHOST_MAX_ARGS + 1];
    RTL_USER_PROCESS_PARAMETERS *params = NtCurrentTeb()->Peb->ProcessParameters;
    int argc = 0;
    int headless = 0;
    int ret = 1;

    (void)peb;

    unsigned int chars = params->CommandLine.Length / sizeof(WCHAR);
    if (chars > 511) chars = 511;
    memcpy( cmdline, params->CommandLine.Buffer, chars * sizeof(WCHAR) );
    cmdline[chars] = 0;

    WCHAR *p = cmdline;
    while (*p && argc < CONHOST_MAX_ARGS)
    {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        if (*p == '"')
        {
            argv[argc++] = ++p;
            while (*p && *p != '"') p++;
        }
        else
        {
            argv[argc++] = p;
            while (*p && *p != ' ' && *p != '\t') p++;
        }
        if (*p) *p++ = 0;
    }
    argv[argc] = NULL;
    for (int i = 1; i < argc; i++)
        if (!wcscmp( argv[i], L"--headless" )) headless = 1;

    if (!headless)
    {
        /* conhost is a desktop-server CLIENT at image-load time (user32
         * -> win32u connects during Ldr init). Every image carries the
         * server now, so this check is no longer about the media -- it is
         * the G12 refusal for a broken bake: without the server win32u
         * would go in-process and this conhost would become the desktop's
         * OWNER, the split-brain user/wine/wineserver-lite/client/call.c
         * names. Refuse loudly instead of running wrong. */
        HANDLE srv_image = open_device( PRSK_SRV_IMAGE, FILE_READ_ATTRIBUTES );
        if (!srv_image)
        {
            display( "[KTEST] conhost FAIL "
                     "(window mode with no wineserver-lite on this volume: a broken bake)\n" );
            ExitProcess( 1 );
        }
        NtClose( srv_image );
        /* The gui5con leg's marker (tests/run/run.sh awaits it) — retired
         * with the leg's rework to a client-allocated console. */
        display( "[KTEST] gui5con conhost mode=window\n" );
    }

    ret = wmain( argc, argv );
    if (ret)
        display( "[KTEST] conhost FAIL (wmain returned nonzero)\n" );
    ExitProcess( (UINT)ret );
}

/* --- 2. the mini CRT -------------------------------------------------------- */

void *malloc( size_t size )
{
    return HeapAlloc( GetProcessHeap(), 0, size ? size : 1 );
}

void *calloc( size_t count, size_t size )
{
    return HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, count && size ? count * size : 1 );
}

void *realloc( void *ptr, size_t size )
{
    if (!ptr) return malloc( size );
    return HeapReAlloc( GetProcessHeap(), 0, ptr, size ? size : 1 );
}

void free( void *ptr )
{
    if (ptr) HeapFree( GetProcessHeap(), 0, ptr );
}

void *memcpy( void *dst, const void *src, size_t n )
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

void *memmove( void *dst, const void *src, size_t n )
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    if (d < s)
        while (n--) *d++ = *s++;
    else
        while (n--) d[n] = s[n];
    return dst;
}

void *memset( void *dst, int value, size_t n )
{
    unsigned char *d = dst;
    while (n--) *d++ = (unsigned char)value;
    return dst;
}

int memcmp( const void *a, const void *b, size_t n )
{
    const unsigned char *x = a, *y = b;
    for (; n; n--, x++, y++)
        if (*x != *y) return *x < *y ? -1 : 1;
    return 0;
}

size_t strlen( const char *s )
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

size_t wcslen( const wchar_t *s )
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

int wcscmp( const wchar_t *a, const wchar_t *b )
{
    while (*a && *a == *b) { a++; b++; }
    return (int)*a - (int)*b;
}

/* Wine's msvcrt wchar.h maps wcsdup to an inline over _wcsdup. */
wchar_t *_wcsdup( const wchar_t *str )
{
    size_t bytes = (wcslen( str ) + 1) * sizeof(wchar_t);
    wchar_t *copy = malloc( bytes );
    if (copy) memcpy( copy, str, bytes );
    return copy;
}

/* The tty escape builder's sprintf: literal text + the %u/%d/%s/%c subset.
 * Wine's msvcrt stdio.h lowers sprintf onto __stdio_common_vsprintf (the
 * ucrt shape), so that is the symbol provided. */
static int mini_vsprintf( char *buffer, const char *format, va_list args )
{
    char *out = buffer;

    while (*format)
    {
        if (*format != '%')
        {
            *out++ = *format++;
            continue;
        }
        format++;
        switch (*format++)
        {
        case 'u':
        case 'd':
        {
            char digits[12];
            int count = 0;
            unsigned int value;
            if (format[-1] == 'd')
            {
                int signedValue = va_arg( args, int );
                if (signedValue < 0)
                {
                    *out++ = '-';
                    signedValue = -signedValue;
                }
                value = (unsigned int)signedValue;
            }
            else value = va_arg( args, unsigned int );
            do
            {
                digits[count++] = (char)('0' + value % 10);
                value /= 10;
            } while (value);
            while (count) *out++ = digits[--count];
            break;
        }
        case 's':
        {
            const char *str = va_arg( args, const char * );
            while (*str) *out++ = *str++;
            break;
        }
        case 'c':
            *out++ = (char)va_arg( args, int );
            break;
        case '%':
            *out++ = '%';
            break;
        default:
            *out++ = '?';
            break;
        }
    }
    *out = 0;
    return (int)(out - buffer);
}

int __cdecl __stdio_common_vsprintf( unsigned __int64 options, char *buffer, size_t length,
                                     const char *format, _locale_t locale, va_list args )
{
    (void)options;
    (void)length; /* conhost's escape buffers are sized for their formats */
    (void)locale;
    return mini_vsprintf( buffer, format, args );
}

long wcstol( const wchar_t *str, wchar_t **end, int base )
{
    long value = 0;
    int negative = 0;

    while (*str == ' ' || *str == '\t') str++;
    if (*str == '-') { negative = 1; str++; }
    else if (*str == '+') str++;
    if ((base == 0 || base == 16) && str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
    {
        base = 16;
        str += 2;
    }
    else if (base == 0)
        base = (str[0] == '0') ? 8 : 10;

    for (;;)
    {
        int digit;
        wchar_t ch = *str;
        if (ch >= '0' && ch <= '9') digit = ch - '0';
        else if (ch >= 'a' && ch <= 'z') digit = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'Z') digit = ch - 'A' + 10;
        else break;
        if (digit >= base) break;
        value = value * base + digit;
        str++;
    }
    if (end) *end = (wchar_t *)str;
    return negative ? -value : value;
}

int iswalnum( wint_t ch )
{
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
}

/* window.c's additions (GUI-5): wcscpy for the registry key composition,
 * _wtoi for the font-size dialog, abs for the selection rectangle — real
 * calls under -fno-builtin, harmlessly unused in the headless link. */
wchar_t *wcscpy( wchar_t *dst, const wchar_t *src )
{
    wchar_t *ret = dst;
    while ((*dst++ = *src++)) ;
    return ret;
}

int _wtoi( const wchar_t *str )
{
    return (int)wcstol( str, NULL, 10 );
}

int abs( int value )
{
    return value < 0 ? -value : value;
}
