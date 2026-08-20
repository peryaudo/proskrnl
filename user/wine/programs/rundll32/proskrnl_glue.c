/*
 * user/wine/programs/rundll32/proskrnl_glue.c — standalone-PE glue for Wine's rundll32 (CUI-1).
 *
 * wineboot --init applies wine.inf by spawning `rundll32.exe
 * setupapi,InstallHinfSection <section> 128 <inf>` children — the Cm
 * integration exercise ADR 0008 promises. The pinned tree's own PE build
 * provides rundll32.o UNMODIFIED (programs/rundll32/x86_64-windows); this
 * file supplies the cmd.exe-glue-style rest: the CRT entry (rundll32 is a
 * -municode windows app: wide argv, wWinMain).
 *
 * Its four user32 imports used to be stood in here — rundll32 registers a
 * class and creates a never-shown top-level window for DLLs that expect an
 * HWND parent, and a CUI image carried no user32 to do it with. One image
 * bakes exactly one user32.dll now, so the import library is linked and the
 * window is real (never shown, as upstream intends).
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
