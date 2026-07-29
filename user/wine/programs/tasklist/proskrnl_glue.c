/*
 * user/wine/programs/tasklist/proskrnl_glue.c — standalone-PE glue for Wine's tasklist.exe
 * (CUI-4).
 *
 * The CUI-4 acceptance's process lister (docs/02 "a tasklist/taskkill pair
 * works against live processes"). The pinned tree's own PE build provides
 * tasklist.o UNMODIFIED (programs/tasklist/x86_64-windows); this file
 * supplies the cmd.exe-glue-style rest: the wide CRT entry and the ONE
 * user32 import tasklist references — LoadStringW, over the image's own
 * string resources, which is a resource read rather than anything GUI
 * (user32 proper is the GUI path, off the image per Art. 7).
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

/* ---- user32 stand-in ----------------------------------------------------- */

/* LoadStringW over the image's own RT_STRING resources: strings live in
 * bundles of 16 counted WCHAR strings, bundle id = (id >> 4) + 1, entry =
 * id & 15 (MS resource format; Wine dlls/user32/resource.c is the reference
 * implementation). Same body as user/wine/programs/cmd/proskrnl_glue.c's. */
int WINAPI LoadStringW(HINSTANCE instance, UINT id, WCHAR *buffer, int buflen)
{
    if (buffer == NULL || buflen == 0)
        return 0;
    HMODULE module = instance;
    if (module == NULL)
        module =
            (HMODULE)NtCurrentTeb()->ProcessEnvironmentBlock->Reserved3[1]; /* ImageBaseAddress */

    struct
    {
        ULONG_PTR type;
        ULONG_PTR name;
        ULONG_PTR language;
    } info;
    info.type = 6; /* RT_STRING */
    info.name = (id >> 4) + 1;
    info.language = 0;

    const IMAGE_RESOURCE_DATA_ENTRY *entry;
    void *data;
    ULONG size;
    if (LdrFindResource_U(module, &info, 3, &entry) != STATUS_SUCCESS ||
        LdrAccessResource(module, entry, &data, &size) != STATUS_SUCCESS)
    {
        buffer[0] = 0;
        return 0;
    }
    const WCHAR *p = data;
    const WCHAR *end = (const WCHAR *)((const char *)data + size);
    for (unsigned i = 0; i < (id & 15) && p < end; i++)
        p += *p + 1; /* counted strings */
    if (p >= end)
    {
        buffer[0] = 0;
        return 0;
    }
    int length = *p;
    if (length >= buflen)
        length = buflen - 1;
    for (int i = 0; i < length; i++)
        buffer[i] = p[1 + i];
    buffer[length] = 0;
    return length;
}

/* The import thunk the unmodified tasklist.o references. */
int(WINAPI *__imp_LoadStringW)(HINSTANCE, UINT, WCHAR *, int) = LoadStringW;
