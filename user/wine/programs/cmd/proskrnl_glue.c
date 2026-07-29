/*
 * user/wine/programs/cmd/proskrnl_glue.c — standalone-PE glue for Wine's cmd.exe (M10).
 *
 * Wine's cmd sources (third_party/wine/programs/cmd/*.c, compiled unmodified
 * by the pinned tree's own PE build) import five user32 and four shell32
 * functions besides the kernel32/kernelbase/ntdll/advapi32/ucrtbase surface
 * proskrnl bakes. user32/shell32 are the M12 GUI path — constitutionally off
 * M10 (Art. 7: everything outside the CUI core stays subtractable) — so this
 * file stands those nine functions in with CUI-faithful implementations over
 * ntdll/kernelbase, plus the CRT entry point the exe needs (the ucrtbase
 * startup sequence a CRT startup object would run). Same precedent as
 * user/wine/programs/conhost/proskrnl_glue.c.
 */
#include <stdarg.h>

#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <shellapi.h>

/* ---- ntdll/ucrtbase imports the glue leans on --------------------------- */

NTSYSAPI NTSTATUS NTAPI LdrFindResource_U(HMODULE, const void *, ULONG,
                                          const IMAGE_RESOURCE_DATA_ENTRY **);
NTSYSAPI NTSTATUS NTAPI LdrAccessResource(HMODULE, const IMAGE_RESOURCE_DATA_ENTRY *, void **,
                                          ULONG *);
NTSYSAPI WCHAR NTAPI RtlUpcaseUnicodeChar(WCHAR);
NTSYSAPI int __cdecl _vsnwprintf(WCHAR *, size_t, const WCHAR *, va_list);
/* iswalpha comes from mingw ctype.h, resolved against the ucrtbase import lib */

/* The ucrtbase app-startup surface (called in the order a console CRT
 * startup object runs it — ucrt docs; the prebuilt cmd objects read argv
 * through __p___argc/__p___wargv exactly like any /MD MSVC exe). */
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

/* ---- user32 stand-ins ---------------------------------------------------- */

/* LoadStringW over the image's own RT_STRING resources: strings live in
 * bundles of 16 counted WCHAR strings, bundle id = (id >> 4) + 1, entry =
 * id & 15 (MS resource format; Wine dlls/user32/resource.c is the
 * reference implementation). */
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

DWORD WINAPI CharUpperBuffW(WCHAR *str, DWORD length)
{
    for (DWORD i = 0; i < length; i++)
        str[i] = RtlUpcaseUnicodeChar(str[i]);
    return length;
}

BOOL WINAPI IsCharAlphaW(WCHAR c)
{
    return (iswalpha)(c) != 0;
}

/* Single-byte-codepage next (the baked codepages are 437/1252 — no lead
 * bytes); cmd uses it only to walk ANSI environment-ish strings. */
LPSTR WINAPI CharNextExA(WORD codepage, LPCSTR ptr, DWORD flags)
{
    (void)codepage;
    (void)flags;
    if (*ptr == '\0')
        return (LPSTR)ptr;
    return (LPSTR)ptr + 1;
}

int WINAPIV wsprintfW(WCHAR *buffer, const WCHAR *format, ...)
{
    va_list args;
    va_start(args, format);
    int n = _vsnwprintf(buffer, 1024, format, args); /* wsprintf's documented cap */
    va_end(args);
    return n < 0 ? 0 : n;
}

/* ---- shell32 stand-ins --------------------------------------------------- */

/* `start` and shell verbs need the shell — out of the CUI core. Loud, honest
 * failure: SE_ERR_ACCESSDENIED keeps cmd's error reporting on its normal
 * path. */
BOOL WINAPI ShellExecuteExW(SHELLEXECUTEINFOW *info)
{
    if (info != NULL)
        info->hInstApp = (HINSTANCE)(ULONG_PTR)SE_ERR_ACCESSDENIED;
    SetLastError(ERROR_ACCESS_DENIED);
    return FALSE;
}

/* cmd probes the executable with this before SHGetFileInfoW(SHGFI_EXETYPE)
 * — a < 32 return makes it treat the child as GUI and NOT WAIT for it
 * (spawn_external_full_path), losing the errorlevel. An existing file is
 * its own executable here (no shell associations on the CUI core). */
HINSTANCE WINAPI FindExecutableW(const WCHAR *file, const WCHAR *directory, WCHAR *result)
{
    (void)directory;
    if (GetFileAttributesW(file) == INVALID_FILE_ATTRIBUTES)
    {
        if (result != NULL)
            result[0] = 0;
        return (HINSTANCE)(ULONG_PTR)SE_ERR_FNF;
    }
    if (result != NULL)
    {
        int i = 0;
        while (file[i] != 0 && i < MAX_PATH - 1)
        {
            result[i] = file[i];
            i++;
        }
        result[i] = 0;
    }
    /* > 32 = success (MS FindExecutable documentation; values <= 32 are the
     * SE_ERR_* failures cmd checks against). */
    return (HINSTANCE)(ULONG_PTR)33;
}

/* cmd asks only for SHGFI_EXETYPE (is this runnable / GUI or CUI); answer
 * through the loader like kernel32's GetBinaryTypeW would. */
DWORD_PTR WINAPI SHGetFileInfoW(const WCHAR *path, DWORD attributes, SHFILEINFOW *info,
                                UINT infoSize, UINT flags)
{
    (void)attributes;
    (void)info;
    (void)infoSize;
    if (flags != SHGFI_EXETYPE)
        return 0;
    DWORD type;
    if (!GetBinaryTypeW(path, &type))
        return 0;
    if (type == SCS_32BIT_BINARY || type == SCS_64BIT_BINARY)
    {
        /* SHGFI_EXETYPE contract (MS SHGetFileInfo documentation): LOWORD =
         * 'PE'||'\0\0' with HIWORD 0 means a console executable — exactly
         * the shape cmd tests (wcmdmain.c spawn_external_full_path:
         * `console && !HIWORD(console)`). */
        return 0x00004550;
    }
    return 0;
}

int WINAPI SHFileOperationW(SHFILEOPSTRUCTW *op)
{
    (void)op;
    return ERROR_ACCESS_DENIED; /* deltree-style ops degrade loudly */
}

/* ---- dllimport indirection ----------------------------------------------- */

/* The cmd objects were compiled with the user32/shell32 headers' dllimport
 * declarations, so their calls go through __imp_* pointers; point those at
 * the stand-ins above (what an import-library thunk would have provided). */
int(WINAPI *__imp_LoadStringW)(HINSTANCE, UINT, WCHAR *, int) = LoadStringW;
DWORD(WINAPI *__imp_CharUpperBuffW)(WCHAR *, DWORD) = CharUpperBuffW;
BOOL(WINAPI *__imp_IsCharAlphaW)(WCHAR) = IsCharAlphaW;
LPSTR(WINAPI *__imp_CharNextExA)(WORD, LPCSTR, DWORD) = CharNextExA;
int(WINAPIV *__imp_wsprintfW)(WCHAR *, const WCHAR *, ...) = wsprintfW;
BOOL(WINAPI *__imp_ShellExecuteExW)(SHELLEXECUTEINFOW *) = ShellExecuteExW;
HINSTANCE(WINAPI *__imp_FindExecutableW)(const WCHAR *, const WCHAR *, WCHAR *) = FindExecutableW;
DWORD_PTR(WINAPI *__imp_SHGetFileInfoW)
(const WCHAR *, DWORD, SHFILEINFOW *, UINT, UINT) = SHGetFileInfoW;
int(WINAPI *__imp_SHFileOperationW)(SHFILEOPSTRUCTW *) = SHFileOperationW;
