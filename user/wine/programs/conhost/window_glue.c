/*
 * window_glue.c - the conhost window path's glue (GUI-5).
 *
 * conhost compiles the pinned tree's real window.c and links the real
 * user32/gdi32/advapi32, so almost nothing needs standing in. What is
 * left is comctl32: window.c reaches it only from config_dialog (the
 * Properties/Defaults menu items), and upstream's own Makefile.in makes it
 * a DELAYIMPORT for exactly that reason. Mirror that semantics by hand —
 * LoadLibraryW + GetProcAddress on first call — rather than a load-time
 * import: mingw's delay-import helper machinery does not exist under
 * -nostdlib, and a load-time import would make conhost's startup depend on
 * a DllMain path no boot has ever exercised (the GUI-2 imm32 delay-import
 * abort is the cautionary precedent, docs/02). comctl32.dll IS baked, so an
 * interactively opened dialog can genuinely work;
 * if the load fails anyway, each forwarder refuses loudly with the API's
 * real failure shape (Art. 12).
 */
#include <stdarg.h>
#include <stddef.h>
#include <windef.h>
#include <winbase.h>
#include <winuser.h>
#include <winternl.h>
#include <prsht.h>
#include <commctrl.h>

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

static FARPROC comctl32_proc( const char *name )
{
    static HMODULE module;
    FARPROC proc = NULL;

    if (!module) module = LoadLibraryW( L"comctl32.dll" );
    if (module) proc = GetProcAddress( module, name );
    if (!proc)
        display( "[KTEST] gui5con conhost comctl32 unavailable (config dialog refused)\n" );
    return proc;
}

void WINAPI InitCommonControls( void )
{
    void (WINAPI *proc)(void) = (void (WINAPI *)(void))comctl32_proc( "InitCommonControls" );
    if (proc) proc();
}

HPROPSHEETPAGE WINAPI CreatePropertySheetPageW( const PROPSHEETPAGEW *page )
{
    HPROPSHEETPAGE (WINAPI *proc)( const PROPSHEETPAGEW * ) =
        (HPROPSHEETPAGE (WINAPI *)( const PROPSHEETPAGEW * ))
            comctl32_proc( "CreatePropertySheetPageW" );
    return proc ? proc( page ) : NULL;
}

INT_PTR WINAPI PropertySheetW( const PROPSHEETHEADERW *header )
{
    INT_PTR (WINAPI *proc)( const PROPSHEETHEADERW * ) =
        (INT_PTR (WINAPI *)( const PROPSHEETHEADERW * ))comctl32_proc( "PropertySheetW" );
    return proc ? proc( header ) : -1;
}
