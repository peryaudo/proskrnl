/*
 * user/wine/programs/taskkill/proskrnl_glue.c — standalone-PE glue for Wine's taskkill.exe
 * (CUI-4).
 *
 * The CUI-4 acceptance's process killer (docs/02 "a tasklist/taskkill pair
 * works against live processes"). The pinned tree's own PE build provides
 * taskkill.o UNMODIFIED (programs/taskkill/x86_64-windows); this file
 * supplies the wide CRT entry.
 *
 * Its five user32 imports used to be stood in here, because a CUI image
 * carried no user32: LoadStringW and wsprintfW as real bodies, and
 * EnumWindows / GetWindowThreadProcessId / PostMessageW — taskkill's
 * GRACEFUL path, which asks a process's windows to close — as honest
 * failures. One image bakes exactly one user32.dll now, so all five are the
 * real ones. The graceful path therefore genuinely enumerates the desktop's
 * windows; against a process that has none it still finds nothing and the
 * caller falls back to /f, which goes straight to
 * OpenProcess(PROCESS_TERMINATE) + TerminateProcess — the CUI-4
 * foreign-terminate path the acceptance drives.
 */
#include <stdarg.h>

#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

/* ---- ntdll/ucrtbase imports the glue leans on --------------------------- */

NTSYSAPI NTSTATUS NTAPI LdrFindResource_U(HMODULE, const void *, ULONG,
                                          const IMAGE_RESOURCE_DATA_ENTRY **);
NTSYSAPI NTSTATUS NTAPI LdrAccessResource(HMODULE, const IMAGE_RESOURCE_DATA_ENTRY *, void **,
                                          ULONG *);
NTSYSAPI int __cdecl _vsnwprintf(WCHAR *, size_t, const WCHAR *, va_list);

void __cdecl _set_app_type(int);
int __cdecl _initialize_wide_environment(void);
int __cdecl _configure_wide_argv(int);
int *__cdecl __p___argc(void);
WCHAR ***__cdecl __p___wargv(void);
void __cdecl exit(int);

int __cdecl wmain(int argc, WCHAR *argv[]); /* programs/taskkill/taskkill.c */

/* ---- CRT entry ----------------------------------------------------------- */

void __attribute__((used)) taskkill_start(void)
{
    _set_app_type(1 /* _crt_console_app */);
    _initialize_wide_environment();
    _configure_wide_argv(1);
    exit(wmain(*__p___argc(), *__p___wargv()));
}
