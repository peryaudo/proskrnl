/*
 * user/wine/programs/rundll32/proskrnl_glue.c — standalone-PE glue for Wine's rundll32 (CUI-1).
 *
 * wineboot --init applies wine.inf by spawning `rundll32.exe
 * setupapi,InstallHinfSection <section> 128 <inf>` children — the Cm
 * integration exercise ADR 0008 promises. The pinned tree's own PE build
 * provides rundll32.o UNMODIFIED (programs/rundll32/x86_64-windows); this
 * file supplies the cmd.exe-glue-style rest: the CRT entry (rundll32 is a
 * -municode windows app: wide argv, wWinMain) and the four user32 imports —
 * rundll32 registers a class and creates a never-shown top-level window for
 * DLLs that expect an HWND parent; headless stand-ins satisfy that without
 * the M12 GUI path (Art. 7). Same precedent as user/wine/programs/cmd/proskrnl_glue.c.
 */
#include <stdarg.h>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

/* ---- ucrtbase app-startup surface (user/wine/programs/cmd/proskrnl_glue.c precedent) --- */

void __cdecl _set_app_type(int);
int __cdecl _initialize_wide_environment(void);
int __cdecl _configure_wide_argv(int);
void __cdecl exit(int);

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int); /* programs/rundll32/rundll32.c */

/* ---- CRT entry ----------------------------------------------------------- */

/* lpCmdLine skips the (possibly quoted) program token, the way the CRT's
 * WinMain startup derives it from GetCommandLineW. */
static WCHAR *skip_program_token(WCHAR *commandLine)
{
    WCHAR *p = commandLine;
    if (*p == L'"')
    {
        p++;
        while (*p != 0 && *p != L'"')
            p++;
        if (*p == L'"')
            p++;
    }
    else
    {
        while (*p != 0 && *p != L' ' && *p != L'\t')
            p++;
    }
    while (*p == L' ' || *p == L'\t')
        p++;
    return p;
}

void __attribute__((used)) rundll32_start(void)
{
    _set_app_type(1 /* _crt_console_app: no GUI error popups here */);
    _initialize_wide_environment();
    _configure_wide_argv(1);
    exit(wWinMain((HINSTANCE)GetModuleHandleW(NULL), NULL, skip_program_token(GetCommandLineW()),
                  SW_SHOWNORMAL));
}

/* ---- user32 stand-ins ---------------------------------------------------- */

/* rundll32 creates a WS_VISIBLE top-level window purely as a parent HWND for
 * window-expecting DLL entry points; setupapi's InstallHinfSection only
 * carries it into UI callbacks that never fire headless. A NULL HWND is the
 * honest CUI answer. */
static ATOM WINAPI glue_RegisterClassExW(const WNDCLASSEXW *wc)
{
    (void)wc;
    return 1; /* any nonzero atom: rundll32 ignores the value */
}

static HCURSOR WINAPI glue_LoadCursorW(HINSTANCE instance, LPCWSTR name)
{
    (void)instance;
    (void)name;
    return NULL;
}

static HWND WINAPI glue_CreateWindowExW(DWORD exStyle, LPCWSTR className, LPCWSTR windowName,
                                        DWORD style, int x, int y, int width, int height,
                                        HWND parent, HMENU menu, HINSTANCE instance, void *param)
{
    (void)exStyle;
    (void)className;
    (void)windowName;
    (void)style;
    (void)x;
    (void)y;
    (void)width;
    (void)height;
    (void)parent;
    (void)menu;
    (void)instance;
    (void)param;
    return NULL;
}

static LRESULT WINAPI glue_DefWindowProcW(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    (void)hwnd;
    (void)msg;
    (void)wparam;
    (void)lparam;
    return 0;
}

/* ---- dllimport indirection ----------------------------------------------- */

/* rundll32.o was compiled against user32's dllimport declarations; its calls
 * go through __imp_* pointers (user/wine/programs/cmd/proskrnl_glue.c precedent). */
ATOM(WINAPI *__imp_RegisterClassExW)(const WNDCLASSEXW *) = glue_RegisterClassExW;
HCURSOR(WINAPI *__imp_LoadCursorW)(HINSTANCE, LPCWSTR) = glue_LoadCursorW;
HWND(WINAPI *__imp_CreateWindowExW)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int, int, HWND, HMENU,
                                    HINSTANCE, void *) = glue_CreateWindowExW;
LRESULT(WINAPI *__imp_DefWindowProcW)(HWND, UINT, WPARAM, LPARAM) = glue_DefWindowProcW;
