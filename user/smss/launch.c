/* user/smss/launch.c — process launching over the raw NtCreateUserProcess
 * boundary: the kernel's old PsRunUserImage duties, done from ring 3.
 *
 * Children created without a console or an explicit command line get NO
 * parameter block — the kernel synthesizes the default furniture
 * (kernel/ps/peb.c PspBuildDefaultParams), exactly as it did for its own
 * launches. Console children need an explicit block (the create-path
 * console/std fixups only run on caller-supplied parameters —
 * kernel/ps/process.c), so one is built from smss's OWN furniture (which
 * IS the kernel default: smss is a params-less kernel launch) plus the
 * ConDrv handles below.
 *
 * The console handles are opened from \Device\ConDrv by name — Connection
 * for the child's ConsoleHandle, Input for hStdInput, one Output shared by
 * hStdOutput/hStdError — the exact device paths the pinned kernelbase opens
 * for itself (third_party/wine dlls/kernelbase/console.c
 * create_console_connection / init_console_std_handles:
 * \Device\ConDrv\{Connection,Input,Output}) and
 * the same one-open-two-std shape the kernel's create-time seeding used
 * to build. smss itself never touches the console with them (it prints via
 * NtDisplayString), so it stays OFF the console: its EPROCESS is never
 * console-attached and the Ctrl+C fanout can never select the session
 * manager (kernel/ps/process.c PsPropagateConsoleCtrlEvent).
 */
#include "user/smss/smss.h"

#include "abi/ntcondrv.h"

static HANDLE console_connection;
static HANDLE console_input;
static HANDLE console_output;
static int console_ready;

int smss_console_available(void)
{
    return console_ready;
}

NTSTATUS smss_spawn(const WCHAR *nt_path, const WCHAR *cmdline, int console, HANDLE *process_out,
                    HANDLE *thread_out)
{
    NTSTATUS status;
    USHORT chars = 0;
    while (nt_path[chars] != 0)
        chars++;

    /* Explicit parameters only when needed; RtlDestroyProcessParameters
     * frees the block after the create captured it. */
    RTL_USER_PROCESS_PARAMETERS *params = 0;
    if (console || cmdline != 0)
    {
        /* The DOS spelling: the NT path minus \??\ (the PEB builder's rule,
         * kernel/ps/process.c NtCreateUserProcess). */
        WCHAR dos[128];
        USHORT skip = (chars >= 4 && nt_path[0] == '\\' && nt_path[1] == '?' && nt_path[2] == '?' &&
                       nt_path[3] == '\\')
                          ? 4
                          : 0;
        USHORT n = 0;
        while (nt_path[skip + n] != 0 && n < 127)
        {
            dos[n] = nt_path[skip + n];
            n++;
        }
        dos[n] = 0;

        UNICODE_STRING image, cmd;
        smss_init_ustr(&image, dos);
        smss_init_ustr(&cmd, cmdline != 0 ? cmdline : dos);
        status = RtlCreateProcessParametersEx(
            &params, &image, &smss_own_params->DllPath, &smss_own_params->CurrentDirectory.DosPath,
            &cmd, smss_own_params->Environment, &image /* window title = image, the kernel rule */,
            0, 0, 0, PROCESS_PARAMS_FLAG_NORMALIZED);
        if (status != STATUS_SUCCESS)
            return status;
        if (console)
        {
            /* The create-path fixups re-duplicate these smss handles into
             * the child's table and write the child values back. */
            params->ConsoleHandle = console_connection;
            params->hStdInput = console_input;
            params->hStdOutput = console_output;
            params->hStdError = console_output;
        }
    }

    struct
    {
        SIZE_T total_length;
        PS_ATTRIBUTE attributes[2];
    } attr_list;
    PS_CREATE_INFO create_info;
    CLIENT_ID client_id;
    client_id.UniqueProcess = 0;
    client_id.UniqueThread = 0;

    attr_list.total_length = sizeof(attr_list);
    attr_list.attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    attr_list.attributes[0].Size = (SIZE_T)chars * sizeof(WCHAR);
    attr_list.attributes[0].ValuePtr = (void *)nt_path;
    attr_list.attributes[0].ReturnLength = 0;
    attr_list.attributes[1].Attribute = PS_ATTRIBUTE_CLIENT_ID;
    attr_list.attributes[1].Size = sizeof(client_id);
    attr_list.attributes[1].ValuePtr = &client_id;
    attr_list.attributes[1].ReturnLength = 0;

    for (unsigned i = 0; i < sizeof(create_info); i++)
        ((unsigned char *)&create_info)[i] = 0;
    create_info.Size = sizeof(create_info);

    HANDLE process = 0, thread = 0;
    status = NtCreateUserProcess(&process, &thread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, 0, 0, 0,
                                 0, params, &create_info, (PS_ATTRIBUTE_LIST *)&attr_list);
    if (params != 0)
        RtlDestroyProcessParameters(params);
    if (status == STATUS_SUCCESS &&
        (create_info.State != PsCreateSuccess || client_id.UniqueProcess == 0))
        status = STATUS_UNSUCCESSFUL;
    if (status != STATUS_SUCCESS)
        return status;
    *process_out = process;
    *thread_out = thread;
    return STATUS_SUCCESS;
}

NTSTATUS smss_run(const WCHAR *nt_path, const WCHAR *cmdline, int console, ULONG timeout_ms,
                  NTSTATUS *exit_out)
{
    HANDLE process = 0, thread = 0;
    NTSTATUS status = smss_spawn(nt_path, cmdline, console, &process, &thread);
    if (status != STATUS_SUCCESS)
        return status;

    LARGE_INTEGER timeout;
    const LARGE_INTEGER *timeout_ptr = 0;
    if (timeout_ms != 0)
    {
        timeout.QuadPart = -(LONGLONG)timeout_ms * 10000; /* relative, 100 ns */
        timeout_ptr = &timeout;
    }
    status = NtWaitForSingleObject(process, FALSE, timeout_ptr);
    if (status != STATUS_SUCCESS)
    {
        /* STATUS_TIMEOUT: still running; no foreign terminate exists
         * (docs/03), so the handles stay leaked rather than freeing a live
         * process. */
        return status == STATUS_TIMEOUT ? STATUS_TIMEOUT : status;
    }

    *exit_out = STATUS_UNSUCCESSFUL;
    PROCESS_BASIC_INFORMATION basic;
    ULONG returned = 0;
    status = NtQueryInformationProcess(process, ProcessBasicInformation, &basic, sizeof(basic),
                                       &returned);
    if (status == STATUS_SUCCESS)
        *exit_out = basic.ExitStatus;
    NtClose(thread);
    NtClose(process);
    return STATUS_SUCCESS;
}

/* wineserver-lite (HACK-003) is a system service, not a GUI app: it must be
 * running before ANYTHING that loads win32u, because every such process is
 * one of its clients. Started first, fire-and-forget: the handles are kept
 * forever because the process never exits. Probe/skip on the image file, so
 * this is a no-op on every serverless image. */
void smss_start_wineserver(void)
{
    static const WCHAR path[] = WSTR("\\??\\C:\\windows\\system32\\wineserver-lite.exe");
    if (!smss_file_exists(path, 0))
        return; /* no server on this image: win32u stays in-process */

    static HANDLE process, thread;
    NTSTATUS status = smss_spawn(path, 0, 0, &process, &thread);
    if (status != STATUS_SUCCESS)
        smss_printf("[KTEST] gui3 server FAIL (create=%x)\n", SMSS_HEX(status));
}

/* `attributes` carries OBJ_INHERIT for the two std opens: NT console std
 * handles are born inheritable, and the create-path std fixup copies the
 * SOURCE handle's attributes into the child (ObpDuplicateIntoTable with
 * sameAttributes) — so a console child's own std handles stay
 * inherit-marked and its pipeline children receive them through cmd's
 * inherit-all copy at the same values (sem_ps/inherit semantics). The
 * Connection open stays uninheritable, like the old kernel seeding. */
static NTSTATUS open_condrv(const WCHAR *nt_path, ULONG attributes, HANDLE *handle_out)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    smss_init_ustr(&name, nt_path);
    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.ObjectName = &name;
    attr.Attributes = OBJ_CASE_INSENSITIVE | attributes;
    attr.SecurityDescriptor = 0;
    attr.SecurityQualityOfService = 0;
    return NtCreateFile(handle_out, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &attr, &iosb, 0,
                        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
}

/* Has a console server attached? A forwarded verb answers
 * STATUS_INVALID_DEVICE_STATE fast while there is no conhost (drivers/
 * condrv.c CondrvForward) and round-trips once one is pumping. */
static int console_server_attached(void)
{
    IO_STATUS_BLOCK iosb;
    ULONG mode = 0;
    NTSTATUS status = NtDeviceIoControlFile(console_input, 0, 0, 0, &iosb, IOCTL_CONDRV_GET_MODE, 0,
                                            0, &mode, sizeof(mode));
    return status == STATUS_SUCCESS;
}

/* Start the M9 console server: conhost, pumping the kernel ConDrv transport
 * with the COM1 serial tty behind it (HACK-004). Fire-and-forget — conhost
 * outlives every console client. Absent conhost.exe (the hermetic test
 * images) is not an error: console requests then fail fast and nothing here
 * blocks. */
void smss_start_conhost(void)
{
    static const WCHAR path[] = WSTR("\\??\\C:\\windows\\system32\\conhost.exe");
    if (!smss_file_exists(path, 0))
        return;

    static HANDLE process, thread;
    NTSTATUS status = smss_spawn(path, 0, 0, &process, &thread);
    if (status != STATUS_SUCCESS)
    {
        smss_printf("[KTEST] conhost FAIL (create=%x)\n", SMSS_HEX(status));
        return;
    }

    /* The console handles the children will inherit; opening needs no
     * server, only \Device\ConDrv itself. */
    status = open_condrv(WSTR("\\Device\\ConDrv\\Connection"), 0, &console_connection);
    if (status == STATUS_SUCCESS)
        status = open_condrv(WSTR("\\Device\\ConDrv\\Input"), OBJ_INHERIT, &console_input);
    if (status == STATUS_SUCCESS)
        status = open_condrv(WSTR("\\Device\\ConDrv\\Output"), OBJ_INHERIT, &console_output);
    if (status != STATUS_SUCCESS)
    {
        smss_printf("[KTEST] conhost FAIL (condrv open=%x)\n", SMSS_HEX(status));
        return;
    }

    /* 30 s, not 10: the windowed conhost (GUI-5) loads user32/gdi32/win32u
     * and completes its desktop-server connect before it can open the
     * ConDrv server device — a long prologue under TCG. The headless
     * conhost attaches in a fraction of either bound; only the failure
     * detection latency changes. */
    for (int waited_ms = 0; waited_ms < 30000; waited_ms += 100)
    {
        if (console_server_attached())
        {
            console_ready = 1;
            smss_say("[KTEST] conhost up\n");
            return;
        }
        smss_sleep_ms(100);
    }
    smss_say("[KTEST] conhost FAIL (no server attach)\n");
}
