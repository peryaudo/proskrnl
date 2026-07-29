/*
 * user/taskkill/proskrnl_glue.c — standalone-PE glue for Wine's taskkill.exe
 * (CUI-4).
 *
 * The CUI-4 acceptance's process killer (docs/02 "a tasklist/taskkill pair
 * works against live processes"). The pinned tree's own PE build provides
 * taskkill.o UNMODIFIED (programs/taskkill/x86_64-windows); this file
 * supplies the wide CRT entry and the four user32 imports it references.
 *
 * Two of those are real here: LoadStringW (a resource read, same body as
 * user/cmd/proskrnl_glue.c) and wsprintfW (plain formatting over ntdll's
 * _vsnwprintf). The other two — EnumWindows and GetWindowThreadProcessId,
 * plus PostMessageW — belong to taskkill's GRACEFUL path, which asks a
 * process's windows to close. proskrnl has no windows until GUI-2 (Art. 7),
 * so they fail honestly: EnumWindows enumerates nothing, so taskkill reports
 * that it could not close the process gracefully and the caller uses /f —
 * which goes straight to OpenProcess(PROCESS_TERMINATE) + TerminateProcess,
 * the CUI-4 foreign-terminate path. A stand-in that pretended to succeed
 * would be the fabricated answer Art. 12 forbids.
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

/* ---- user32 stand-ins ---------------------------------------------------- */

/* LoadStringW over the image's own RT_STRING resources (MS resource format;
 * Wine dlls/user32/resource.c is the reference implementation). */
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

/* Plain wide formatting; no GUI content (tests/winetest/glue/user32_stubs.c does the
 * same over ntdll's _vsnwprintf). */
int WINAPIV wsprintfW(WCHAR *buffer, const WCHAR *format, ...)
{
    va_list args;
    va_start(args, format);
    int written = _vsnwprintf(buffer, 1024, format, args);
    va_end(args);
    if (written < 0)
    {
        buffer[0] = 0;
        written = 0;
    }
    return written;
}

/* The graceful-close path's window surface: there are no windows before
 * GUI-2, so the enumeration finds nothing and the post fails. taskkill then
 * reports the process could not be closed gracefully; /f does not come here. */
BOOL WINAPI EnumWindows(WNDENUMPROC callback, LPARAM param)
{
    (void)callback;
    (void)param;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

DWORD WINAPI GetWindowThreadProcessId(HWND window, DWORD *processId)
{
    (void)window;
    if (processId != NULL)
        *processId = 0;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

BOOL WINAPI PostMessageW(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    (void)window;
    (void)message;
    (void)wparam;
    (void)lparam;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/* The import thunks the unmodified taskkill.o references. */
int(WINAPI *__imp_LoadStringW)(HINSTANCE, UINT, WCHAR *, int) = LoadStringW;
int(WINAPIV *__imp_wsprintfW)(WCHAR *, const WCHAR *, ...) = wsprintfW;
BOOL(WINAPI *__imp_EnumWindows)(WNDENUMPROC, LPARAM) = EnumWindows;
DWORD(WINAPI *__imp_GetWindowThreadProcessId)(HWND, DWORD *) = GetWindowThreadProcessId;
BOOL(WINAPI *__imp_PostMessageW)(HWND, UINT, WPARAM, LPARAM) = PostMessageW;
