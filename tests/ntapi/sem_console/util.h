/*
 * sem_console/util.h — shared helpers for the per-client console tests.
 *
 * The operative spec is wineserver's console object machinery
 * (third_party/wine server/console.c): \Device\ConDrv\Server mints a fresh
 * console server per open; "Reference" relative to a server mints THE
 * console for that server, once; "Connection" relative to a console binds
 * the opening process; Input/Output/ScreenBuffer opens and their I/O route
 * through the CALLER's binding at call time, never a captured console.
 * kernelbase's alloc_console / init_console / AttachConsole
 * (dlls/kernelbase/console.c) are the client half whose open shapes the
 * helpers below reproduce byte for byte.
 *
 * Same two-mode arrangement as sem_net/util.h: the condrv ioctl codes and
 * the RTL_USER_PROCESS_PARAMETERS offsets mingw's headers omit are declared
 * here as the pinned tree spells them — the oracle run itself validates
 * every value (a wrong code or offset would answer differently against the
 * real wineserver). The kernel's generated copies live in abi/ntcondrv.h
 * (G4); tests use the system NT headers plus these local declarations,
 * never abi/ (ntapi.h's header comment).
 */
#ifndef NTAPI_SEM_CONSOLE_UTIL_H
#define NTAPI_SEM_CONSOLE_UTIL_H

#include "../ntapi.h"

#define W(s) u##s

#include <string.h>   /* declarations only: the .exe links no CRT; ntapi.c defines them */
#include <winioctl.h> /* CTL_CODE, FILE_DEVICE_CONSOLE */

/* Prototypes mingw's winternl.h omits (as wine/include/winternl.h). */
NTSYSAPI NTSTATUS NTAPI NtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                     PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                              PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

/* mingw's winnt.h omits the aliases (wine/include/winnt.h 5574-5576). */
#ifndef FILE_READ_PROPERTIES
#define FILE_READ_PROPERTIES FILE_READ_EA
#endif
#ifndef FILE_WRITE_PROPERTIES
#define FILE_WRITE_PROPERTIES FILE_WRITE_EA
#endif

/* --- the condrv boundary, as wine/include/wine/condrv.h spells it -------- */

#define IOCTL_CONDRV_GET_MODE CTL_CODE(FILE_DEVICE_CONSOLE, 0, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_CONDRV_BIND_PID CTL_CODE(FILE_DEVICE_CONSOLE, 51, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* The create-time console sentinels (wine/include/wine/condrv.h 198-201). */
#define CON_HANDLE_ALLOC           ((HANDLE)(LONG_PTR) - 1)
#define CON_HANDLE_ALLOC_NO_WINDOW ((HANDLE)(LONG_PTR) - 2)
#define CON_HANDLE_SHELL           ((HANDLE)(LONG_PTR) - 3)
#define CON_HANDLE_SHELL_NO_WINDOW ((HANDLE)(LONG_PTR) - 4)

static inline int is_console_sentinel(HANDLE handle)
{
    return handle == CON_HANDLE_ALLOC || handle == CON_HANDLE_ALLOC_NO_WINDOW ||
           handle == CON_HANDLE_SHELL || handle == CON_HANDLE_SHELL_NO_WINDOW;
}

/* PEB+0x20 -> RTL_USER_PROCESS_PARAMETERS; ConsoleHandle at +0x10
 * (wine/include/winternl.h PEB / RTL_USER_PROCESS_PARAMETERS x64 layout —
 * the sem_ps/wow64_process.c offset-mirror pattern; mingw's winternl.h
 * hides both fields in Reserved blocks). */
#define PEB64_PROCESS_PARAMS 0x020
#define PARAMS64_CONSOLE     0x010

static inline HANDLE console_handle(void)
{
    const BYTE *peb = (const BYTE *)NtCurrentTeb()->ProcessEnvironmentBlock;
    const BYTE *params;
    HANDLE value;
    memcpy(&params, peb + PEB64_PROCESS_PARAMS, sizeof(params));
    memcpy(&value, params + PARAMS64_CONSOLE, sizeof(value));
    return value;
}

/* --- plumbing ------------------------------------------------------------- */

static inline void init_ustr(UNICODE_STRING *str, const void *wide)
{
    const unsigned short *p = (const unsigned short *)wide;
    unsigned len = 0;
    while (p[len])
        len++;
    str->Length = (USHORT)(len * 2);
    str->MaximumLength = (USHORT)(len * 2 + 2);
    str->Buffer = (PWSTR)(void *)p;
}

static inline void init_attr(OBJECT_ATTRIBUTES *attr, HANDLE root, UNICODE_STRING *name,
                             ULONG flags)
{
    attr->Length = sizeof(*attr);
    attr->RootDirectory = root;
    attr->ObjectName = name;
    attr->Attributes = flags;
    attr->SecurityDescriptor = NULL;
    attr->SecurityQualityOfService = NULL;
}

static inline NTSTATUS condrv_open(HANDLE *out, HANDLE root, const void *name16, ACCESS_MASK access,
                                   ULONG attributes, ULONG options)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    init_ustr(&name, name16);
    init_attr(&attr, root, &name, attributes);
    *out = NULL;
    return NtCreateFile(out, access, &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                        options & FILE_SYNCHRONOUS_IO_NONALERT
                            ? 0
                            : FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_OPEN, options, NULL, 0);
}

/* kernelbase create_console_server (dlls/kernelbase/console.c 241-255). */
static inline NTSTATUS open_server(HANDLE *out)
{
    return condrv_open(out, NULL, W("\\Device\\ConDrv\\Server"),
                       FILE_WRITE_PROPERTIES | FILE_READ_PROPERTIES | SYNCHRONIZE, OBJ_INHERIT,
                       FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
}

/* kernelbase create_console_reference (257-271): relative "Reference". */
static inline NTSTATUS open_reference(HANDLE *out, HANDLE root)
{
    return condrv_open(out, root, W("Reference"),
                       FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_PROPERTIES |
                           FILE_READ_PROPERTIES | SYNCHRONIZE,
                       0, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
}

/* kernelbase create_console_connection (273-286): root == NULL -> absolute. */
static inline NTSTATUS open_connection(HANDLE *out, HANDLE root)
{
    return condrv_open(out, root, root ? W("Connection") : W("\\Device\\ConDrv\\Connection"),
                       FILE_WRITE_PROPERTIES | FILE_READ_PROPERTIES | SYNCHRONIZE, 0,
                       FILE_NON_DIRECTORY_FILE);
}

/* kernelbase init_console_std_handles (288-340): absolute Input/Output,
 * FILE_CREATE. The disposition difference is deliberate — reproduce it. */
static inline NTSTATUS open_device(HANDLE *out, const void *name16)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    init_ustr(&name, name16);
    init_attr(&attr, NULL, &name, OBJ_INHERIT);
    *out = NULL;
    return NtCreateFile(out,
                        FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE | FILE_READ_ATTRIBUTES |
                            FILE_WRITE_ATTRIBUTES,
                        &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

static inline NTSTATUS open_input(HANDLE *out)
{
    return open_device(out, W("\\Device\\ConDrv\\Input"));
}

static inline NTSTATUS open_output(HANDLE *out)
{
    return open_device(out, W("\\Device\\ConDrv\\Output"));
}

static inline NTSTATUS open_screen_buffer(HANDLE *out)
{
    return open_device(out, W("\\Device\\ConDrv\\ScreenBuffer"));
}

/* IOCTL_CONDRV_BIND_PID on a connection handle (kernelbase AttachConsole,
 * dlls/kernelbase/console.c 368-401: input = one unsigned int pid). */
static inline NTSTATUS bind_pid(HANDLE connection, DWORD pid)
{
    IO_STATUS_BLOCK iosb;
    unsigned int value = pid;
    return NtDeviceIoControlFile(connection, NULL, NULL, NULL, &iosb, IOCTL_CONDRV_BIND_PID, &value,
                                 sizeof(value), NULL, 0);
}

/* IOCTL_CONDRV_GET_MODE: on an UNBOUND caller this refuses at the binding
 * check (wineserver console_input_ioctl), before anything could park on a
 * console server — safe to issue with no conhost serving the console. */
static inline NTSTATUS get_mode(HANDLE handle, ULONG *mode)
{
    IO_STATUS_BLOCK iosb;
    return NtDeviceIoControlFile(handle, NULL, NULL, NULL, &iosb, IOCTL_CONDRV_GET_MODE, NULL, 0,
                                 mode, sizeof(*mode));
}

static inline void close_if(HANDLE handle)
{
    if (handle)
        NtClose(handle);
}

/* --- the silent-child / exit-code protocol (sem_ps/inherit.c) ------------- */

/* Child verdicts travel as an exit-code bitmask over this base; the base is
 * above every bit so a crashed child (0xC0000005...) can never collide with
 * a legitimate verdict. */
#define CHILD_BASE 0x1000

static inline const WCHAR *wstr_find(const WCHAR *haystack, const WCHAR *needle)
{
    size_t nlen = 0;
    while (needle[nlen])
        nlen++;
    for (; *haystack; haystack++)
    {
        size_t i = 0;
        while (i < nlen && haystack[i] == needle[i])
            i++;
        if (i == nlen)
            return haystack;
    }
    return NULL;
}

static inline DWORD parse_dword(const WCHAR *hex)
{
    DWORD value = 0;
    while ((*hex >= '0' && *hex <= '9') || (*hex >= 'a' && *hex <= 'f'))
    {
        value = value * 16 + (DWORD)(*hex <= '9' ? *hex - '0' : *hex - 'a' + 10);
        hex++;
    }
    return value;
}

static inline int emit_hex(WCHAR *out, DWORD value)
{
    WCHAR digits[9];
    int n = 0;
    do
    {
        int d = value & 0xf;
        digits[n++] = (WCHAR)(d <= 9 ? '0' + d : 'a' + d - 10);
        value >>= 4;
    } while (value);
    for (int i = 0; i < n; i++)
        out[i] = digits[n - 1 - i];
    return n;
}

static inline int build_cmdline(WCHAR *out, const WCHAR *exe, const WCHAR *marker)
{
    int n = 0;
    out[n++] = '"';
    for (int i = 0; exe[i]; i++)
        out[n++] = exe[i];
    out[n++] = '"';
    out[n++] = ' ';
    for (int i = 0; marker[i]; i++)
        out[n++] = marker[i];
    out[n] = 0;
    return n;
}

static inline BOOL run_child(WCHAR *cmdline, DWORD flags, DWORD *code_out)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi))
        return FALSE;
    if (WaitForSingleObject(pi.hProcess, 30000) != WAIT_OBJECT_0)
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
    BOOL got = GetExitCodeProcess(pi.hProcess, code_out);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return got;
}

#endif /* NTAPI_SEM_CONSOLE_UTIL_H */
