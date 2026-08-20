/*
 * user/wine/programs/tasklist/proskrnl_glue.c — standalone-PE glue for Wine's tasklist.exe
 * (CUI-4).
 *
 * The CUI-4 acceptance's process lister (docs/02 "a tasklist/taskkill pair
 * works against live processes"). The pinned tree's own PE build provides
 * tasklist.o UNMODIFIED (programs/tasklist/x86_64-windows); this file
 * supplies the cmd.exe-glue-style rest: the wide CRT entry. Its ONE user32
 * import (LoadStringW) used to be stood in here over the image's own string
 * resources, because a CUI image carried no user32; one image bakes exactly
 * one user32.dll now, so the import library is linked and the real one runs.
 *
 * The kernel surface tasklist drives is CUI-4's:
 * CreateToolhelp32Snapshot -> NtQuerySystemInformation(SystemProcessInformation),
 * then per row OpenProcess -> NtOpenProcess, ProcessIdToSessionId ->
 * NtQueryInformationProcess(ProcessSessionInformation) and
 * GetProcessMemoryInfo -> ProcessVmCounters.
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

/* The ucrtbase app-startup surface, in the order a console CRT startup
 * object runs it (user/wine/programs/cmd/proskrnl_glue.c precedent). */
void __cdecl _set_app_type(int);
int __cdecl _initialize_wide_environment(void);
int __cdecl _configure_wide_argv(int);
int *__cdecl __p___argc(void);
WCHAR ***__cdecl __p___wargv(void);
void __cdecl exit(int);

int __cdecl wmain(int argc, WCHAR *argv[]); /* programs/tasklist/tasklist.c */

/* ---- CRT entry ----------------------------------------------------------- */

void __attribute__((used)) tasklist_start(void)
{
    _set_app_type(1 /* _crt_console_app */);
    _initialize_wide_environment();
    _configure_wide_argv(1);
    exit(wmain(*__p___argc(), *__p___wargv()));
}
