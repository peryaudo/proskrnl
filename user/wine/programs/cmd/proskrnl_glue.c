/*
 * user/wine/programs/cmd/proskrnl_glue.c — standalone-PE glue for Wine's cmd.exe (M10).
 *
 * Wine's cmd sources (third_party/wine/programs/cmd/*.c, compiled unmodified
 * by the pinned tree's own PE build) import five user32 and four shell32
 * functions besides the kernel32/kernelbase/ntdll/advapi32/ucrtbase surface
 * proskrnl bakes. Those nine used to be STOOD IN here — user32/shell32 were
 * the GUI path and a CUI image did not carry them — and the stand-ins are
 * gone: one image bakes exactly one user32.dll and one shell32.dll, so cmd
 * links the pinned import libraries and calls the real ones. What is left is
 * the CRT entry point the exe needs (the ucrtbase startup sequence a CRT
 * startup object would run).
 *
 * The stand-ins were not merely redundant: each was a SECOND implementation
 * of a documented API (LoadStringW over the image's own resources,
 * SHGetFileInfoW(SHGFI_EXETYPE) over GetBinaryTypeW, ShellExecuteExW
 * refusing), and a second implementation is the thing Art. 11 is about — it
 * cannot drift from the real one while it is the only one, and it cannot
 * help drifting once both exist.
 */
#include <stdarg.h>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

/* ---- the ucrtbase app-startup surface ------------------------------------
 * Called in the order a console CRT startup object runs it (ucrt docs); the
 * prebuilt cmd objects read argv through __p___argc/__p___wargv exactly like
 * any /MD MSVC exe. */
void __cdecl _set_app_type(int);
int __cdecl _initialize_wide_environment(void);
int __cdecl _configure_wide_argv(int);
int *__cdecl __p___argc(void);
WCHAR ***__cdecl __p___wargv(void);
void __cdecl exit(int);

int __cdecl wmain(int argc, WCHAR *argv[]); /* programs/cmd/wcmdmain.c */

/* ---- CRT entry ----------------------------------------------------------- */

void __attribute__((used)) cmd_start(void)
{
    _set_app_type(1 /* _crt_console_app */);
    _initialize_wide_environment();
    _configure_wide_argv(1 /* _crt_argv_expanded_arguments? no: unexpanded */);
    exit(wmain(*__p___argc(), *__p___wargv()));
}
