/*
 * dll/conprobe_gui.c — the GUI-subsystem console probe for
 * sem_console/subsystem_gate.c.
 *
 * A minimal PE built with -Wl,--subsystem,windows (the one property under
 * test: IMAGE_SUBSYSTEM_WINDOWS_GUI in its own header) that reports what
 * console state it was born with, as an exit-code bitmask over the same
 * CHILD_BASE protocol the sem_console parents use. It deliberately shares
 * no harness code: no ntapi.c, no console output — a GUI probe that
 * printed would beg the question.
 *
 * Lives under dll/ so the Makefile's test glob (which excludes this
 * directory) never grades it as a test; baked at C:\ for the proskrnl
 * sweep, built beside the test .exes for the oracle.
 */
#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

NTSYSAPI NTSTATUS NTAPI NtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                     PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

/* Mirrors sem_console/subsystem_gate.c (SG_GUI_*). */
#define CHILD_BASE   0x1000
#define GUI_NULL     0x01
#define GUI_SENTINEL 0x02
#define GUI_WINDOW   0x04
#define GUI_BOUND    0x08

/* wine/include/winternl.h PEB / RTL_USER_PROCESS_PARAMETERS x64 offsets
 * (the sem_console/util.h mirror); wine/include/wine/condrv.h sentinels. */
#define PEB64_PROCESS_PARAMS 0x020
#define PARAMS64_CONSOLE     0x010

static HANDLE probe_console_handle(void)
{
    const BYTE *peb = (const BYTE *)NtCurrentTeb()->ProcessEnvironmentBlock;
    const BYTE *params;
    HANDLE value;
    __builtin_memcpy(&params, peb + PEB64_PROCESS_PARAMS, sizeof(params));
    __builtin_memcpy(&value, params + PARAMS64_CONSOLE, sizeof(value));
    return value;
}

static int is_sentinel(HANDLE handle)
{
    LONG_PTR value = (LONG_PTR)handle;
    return value <= -1 && value >= -4;
}

/* kernelbase init_console_std_handles' Input open shape
 * (dlls/kernelbase/console.c 288-340). */
static NTSTATUS probe_open_input(HANDLE *out)
{
    static WCHAR path[] = L"\\Device\\ConDrv\\Input";
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    name.Length = sizeof(path) - sizeof(WCHAR);
    name.MaximumLength = sizeof(path);
    name.Buffer = path;
    attr.Length = sizeof(attr);
    attr.RootDirectory = NULL;
    attr.ObjectName = &name;
    attr.Attributes = 0;
    attr.SecurityDescriptor = NULL;
    attr.SecurityQualityOfService = NULL;
    *out = NULL;
    return NtCreateFile(out,
                        FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE | FILE_READ_ATTRIBUTES |
                            FILE_WRITE_ATTRIBUTES,
                        &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

void gui_start(void *peb_arg)
{
    (void)peb_arg;
    DWORD code = CHILD_BASE;
    HANDLE console = probe_console_handle(), input = NULL;

    if (console == NULL)
        code |= GUI_NULL;
    else if (is_sentinel(console))
        code |= GUI_SENTINEL;
    if (GetConsoleWindow() != NULL)
        code |= GUI_WINDOW;
    if (probe_open_input(&input) == 0)
        code |= GUI_BOUND;
    if (input)
        NtClose(input);
    ExitProcess(code);
}
