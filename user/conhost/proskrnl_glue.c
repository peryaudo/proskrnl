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
 *   1. the process entry: open \Device\ConDrv\Server + the \Device\Serial0
 *      tty pair (HACK-004), then hand wmain its headless command line
 *   2. the mini CRT (heap over kernel32, string/memory over own loops)
 *   3. no-op stands-ins for user32 + window.c (headless: never executed) -
 *      except VkKeyScanW, whose ASCII slice the edit line dispatches on
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

int __cdecl wmain( int argc, WCHAR *argv[] );

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

void __attribute__((ms_abi)) conhost_start( void *peb )
{
    static WCHAR arg_server[19]; /* L"0x" + 16 digits */
    static WCHAR *argv[] = { (WCHAR *)L"conhost.exe", (WCHAR *)L"--headless",
                             (WCHAR *)L"--width", (WCHAR *)L"80",
                             (WCHAR *)L"--height", (WCHAR *)L"25",
                             (WCHAR *)L"--server", arg_server, NULL };
    HANDLE server, tty_in, tty_out;
    ULONG_PTR value;
    int pos = 0;
    int ret = 1;

    (void)peb;

    server = open_device( L"\\Device\\ConDrv\\Server",
                          FILE_WRITE_PROPERTIES | FILE_READ_PROPERTIES |
                          FILE_READ_DATA | FILE_WRITE_DATA );
    tty_in = open_device( L"\\Device\\Serial0", FILE_READ_DATA );
    tty_out = open_device( L"\\Device\\Serial0", FILE_WRITE_DATA );

    if (server && tty_in && tty_out)
    {
        /* wmain's headless path takes the tty pair from the std handles. */
        SetStdHandle( STD_INPUT_HANDLE, tty_in );
        SetStdHandle( STD_OUTPUT_HANDLE, tty_out );
        SetStdHandle( STD_ERROR_HANDLE, tty_out );

        value = (ULONG_PTR)server;
        arg_server[pos++] = '0';
        arg_server[pos++] = 'x';
        for (int shift = 60; shift >= 0; shift -= 4)
        {
            static const WCHAR digits[] = L"0123456789abcdef";
            arg_server[pos++] = digits[(value >> shift) & 0xf];
        }
        arg_server[pos] = 0;

        ret = wmain( 8, argv );
    }
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

/* --- 3. user32 + window.c stands-ins ---------------------------------------- */

/* Key-code conversion without a keyboard layout: the ASCII slice of the
 * US-layout mapping user32's VkKeyScanW documents (low byte = virtual key,
 * bit 8 = shift, bit 9 = control). The edit line dispatches Enter/Backspace
 * /Escape by VIRTUAL KEY (conhost's std_key_map), so these must be real;
 * everything unmapped returns -1 and the character still inserts by its
 * UnicodeChar. */
SHORT WINAPI VkKeyScanW( WCHAR ch )
{
    if (ch == '\r') return VK_RETURN;
    if (ch == '\b') return VK_BACK;
    if (ch == '\t') return VK_TAB;
    if (ch == 0x1b) return VK_ESCAPE;
    if (ch == ' ') return VK_SPACE;
    if (ch >= '0' && ch <= '9') return (SHORT)ch;
    if (ch >= 'A' && ch <= 'Z') return (SHORT)(0x100 | ch);
    if (ch >= 'a' && ch <= 'z') return (SHORT)(ch - 'a' + 'A');
    if (ch >= 1 && ch <= 26) return (SHORT)(0x200 | ('A' + ch - 1)); /* ^A..^Z */
    return -1;
}

UINT WINAPI MapVirtualKeyW( UINT code, UINT type )
{
    (void)code;
    (void)type;
    return 0;
}

/* Window-mode machinery: unreachable in headless mode. */
DWORD WINAPI MsgWaitForMultipleObjects( DWORD count, const HANDLE *handles, BOOL all,
                                        DWORD timeout, DWORD mask )
{
    (void)mask;
    return WaitForMultipleObjects( count, handles, all, timeout );
}

BOOL WINAPI PeekMessageW( MSG *msg, HWND hwnd, UINT first, UINT last, UINT remove )
{
    (void)msg; (void)hwnd; (void)first; (void)last; (void)remove;
    return FALSE;
}

BOOL WINAPI TranslateMessage( const MSG *msg )
{
    (void)msg;
    return FALSE;
}

LRESULT WINAPI DispatchMessageW( const MSG *msg )
{
    (void)msg;
    return 0;
}

BOOL WINAPI SetWindowTextW( HWND hwnd, LPCWSTR text )
{
    (void)hwnd; (void)text;
    return FALSE;
}

BOOL WINAPI ShowWindow( HWND hwnd, INT cmd )
{
    (void)hwnd; (void)cmd;
    return FALSE;
}

struct console;
struct screen_buffer;

void update_console_font( struct console *console, const WCHAR *face_name, size_t face_name_size,
                          unsigned int height, unsigned int weight )
{
    (void)console; (void)face_name; (void)face_name_size; (void)height; (void)weight;
}

BOOL init_window( struct console *console )
{
    (void)console;
    return FALSE; /* no GUI before M11+ (docs/02) */
}

void init_message_window( struct console *console )
{
    (void)console;
}

void update_window_region( struct console *console, const RECT *update )
{
    (void)console; (void)update;
}

void update_window_config( struct console *console, BOOL delay )
{
    (void)console; (void)delay;
}

void teardown_window( struct console *console )
{
    (void)console;
}
