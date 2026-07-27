/*
 * headless_stubs.c - the HEADLESS conhost's stand-ins for user32 and for
 * window.c's interface (split out of proskrnl_glue.c at GUI-5, verbatim).
 *
 * The headless link (the CONHOST Makefile target, baked on every image
 * whose console is the serial transport) carries no user32 and no
 * window.c, so these satisfy conhost.c's references: real code only where
 * the headless path actually executes it (VkKeyScanW's ASCII slice - the
 * edit line dispatches by virtual key), no-ops everywhere the window path
 * is unreachable. The WINDOWED link (CONHOST_GUI) gets all of this from
 * the real user32 import library and the real window.c instead, and must
 * NOT compile this file.
 */
#include <stdarg.h>
#include <stddef.h>
#include <windef.h>
#include <winbase.h>
#include <wincon.h>
#include <winuser.h>

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
    return FALSE; /* no GUI in the headless link (the windowed one is CONHOST_GUI) */
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
