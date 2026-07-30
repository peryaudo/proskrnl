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

static HANDLE SmssConsoleConnection;
static HANDLE SmssConsoleInput;
static HANDLE SmssConsoleOutput;
static int SmssConsoleReady;

int SmssConsoleAvailable(void)
{
    return SmssConsoleReady;
}

NTSTATUS SmssSpawn(const WCHAR *ntPath, const WCHAR *cmdline, int console, HANDLE *processOut,
                   HANDLE *threadOut)
{
    NTSTATUS status;
    USHORT chars = 0;
    while (ntPath[chars] != 0)
        chars++;

    /* Explicit parameters only when needed; RtlDestroyProcessParameters
     * frees the block after the create captured it. */
    RTL_USER_PROCESS_PARAMETERS *params = 0;
    if (console || cmdline != 0)
    {
        /* The DOS spelling: the NT path minus \??\ (the PEB builder's rule,
         * kernel/ps/process.c NtCreateUserProcess). */
        WCHAR dos[128];
        USHORT skip = (chars >= 4 && ntPath[0] == '\\' && ntPath[1] == '?' && ntPath[2] == '?' &&
                       ntPath[3] == '\\')
                          ? 4
                          : 0;
        USHORT n = 0;
        while (ntPath[skip + n] != 0 && n < 127)
        {
            dos[n] = ntPath[skip + n];
            n++;
        }
        dos[n] = 0;

        UNICODE_STRING image, cmd;
        SmssInitUnicodeString(&image, dos);
        SmssInitUnicodeString(&cmd, cmdline != 0 ? cmdline : dos);
        status = RtlCreateProcessParametersEx(
            &params, &image, &SmssOwnParams->DllPath, &SmssOwnParams->CurrentDirectory.DosPath,
            &cmd, SmssOwnParams->Environment, &image /* window title = image, the kernel rule */, 0,
            0, 0, PROCESS_PARAMS_FLAG_NORMALIZED);
        if (status != STATUS_SUCCESS)
            return status;
        if (console)
        {
            /* The create-path fixups re-duplicate these smss handles into
             * the child's table and write the child values back. */
            params->ConsoleHandle = SmssConsoleConnection;
            params->hStdInput = SmssConsoleInput;
            params->hStdOutput = SmssConsoleOutput;
            params->hStdError = SmssConsoleOutput;
        }
    }

    struct
    {
        SIZE_T totalLength;
        PS_ATTRIBUTE attributes[2];
    } attrList;
    PS_CREATE_INFO createInfo;
    CLIENT_ID clientId;
    clientId.UniqueProcess = 0;
    clientId.UniqueThread = 0;

    attrList.totalLength = sizeof(attrList);
    attrList.attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    attrList.attributes[0].Size = (SIZE_T)chars * sizeof(WCHAR);
    attrList.attributes[0].ValuePtr = (void *)ntPath;
    attrList.attributes[0].ReturnLength = 0;
    attrList.attributes[1].Attribute = PS_ATTRIBUTE_CLIENT_ID;
    attrList.attributes[1].Size = sizeof(clientId);
    attrList.attributes[1].ValuePtr = &clientId;
    attrList.attributes[1].ReturnLength = 0;

    for (unsigned i = 0; i < sizeof(createInfo); i++)
        ((unsigned char *)&createInfo)[i] = 0;
    createInfo.Size = sizeof(createInfo);

    HANDLE process = 0, thread = 0;
    status = NtCreateUserProcess(&process, &thread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, 0, 0, 0,
                                 0, params, &createInfo, (PS_ATTRIBUTE_LIST *)&attrList);
    if (params != 0)
        RtlDestroyProcessParameters(params);
    if (status == STATUS_SUCCESS &&
        (createInfo.State != PsCreateSuccess || clientId.UniqueProcess == 0))
        status = STATUS_UNSUCCESSFUL;
    if (status != STATUS_SUCCESS)
        return status;
    *processOut = process;
    *threadOut = thread;
    return STATUS_SUCCESS;
}

NTSTATUS SmssRun(const WCHAR *ntPath, const WCHAR *cmdline, int console, ULONG timeoutMs,
                 NTSTATUS *exitOut)
{
    HANDLE process = 0, thread = 0;
    NTSTATUS status = SmssSpawn(ntPath, cmdline, console, &process, &thread);
    if (status != STATUS_SUCCESS)
        return status;

    LARGE_INTEGER timeout;
    const LARGE_INTEGER *timeoutPtr = 0;
    if (timeoutMs != 0)
    {
        timeout.QuadPart = -(LONGLONG)timeoutMs * 10000; /* relative, 100 ns */
        timeoutPtr = &timeout;
    }
    status = NtWaitForSingleObject(process, FALSE, timeoutPtr);
    if (status != STATUS_SUCCESS)
    {
        /* STATUS_TIMEOUT: still running; no foreign terminate exists
         * (docs/03), so the handles stay leaked rather than freeing a live
         * process. */
        return status == STATUS_TIMEOUT ? STATUS_TIMEOUT : status;
    }

    *exitOut = STATUS_UNSUCCESSFUL;
    PROCESS_BASIC_INFORMATION basic;
    ULONG returned = 0;
    status = NtQueryInformationProcess(process, ProcessBasicInformation, &basic, sizeof(basic),
                                       &returned);
    if (status == STATUS_SUCCESS)
        *exitOut = basic.ExitStatus;
    NtClose(thread);
    NtClose(process);
    return STATUS_SUCCESS;
}

/* wineserver-lite (HACK-003) is a system service, not a GUI app: it must be
 * running before ANYTHING that loads win32u, because every such process is
 * one of its clients. Started first, fire-and-forget: the handles are kept
 * forever because the process never exits. Probe/skip on the image file, so
 * this is a no-op on every serverless image. */
void SmssStartWineServer(void)
{
    static const WCHAR path[] = WSTR("\\??\\C:\\windows\\system32\\wineserver-lite.exe");
    if (!SmssFileExists(path, 0))
        return; /* no server on this image: win32u stays in-process */

    static HANDLE SmssWineServerProcess, SmssWineServerThread;
    NTSTATUS status = SmssSpawn(path, 0, 0, &SmssWineServerProcess, &SmssWineServerThread);
    if (status != STATUS_SUCCESS)
        SmssPrintf("[KTEST] gui3 server FAIL (create=%x)\n", SMSS_HEX(status));
}

/* `attributes` carries OBJ_INHERIT for the two std opens: NT console std
 * handles are born inheritable, and the create-path std fixup copies the
 * SOURCE handle's attributes into the child (ObpDuplicateIntoTable with
 * sameAttributes) — so a console child's own std handles stay
 * inherit-marked and its pipeline children receive them through cmd's
 * inherit-all copy at the same values (sem_ps/inherit semantics). The
 * Connection open stays uninheritable, like the old kernel seeding. */
static NTSTATUS SmssOpenConDrv(const WCHAR *ntPath, ULONG attributes, HANDLE *handleOut)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    SmssInitUnicodeString(&name, ntPath);
    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.ObjectName = &name;
    attr.Attributes = OBJ_CASE_INSENSITIVE | attributes;
    attr.SecurityDescriptor = 0;
    attr.SecurityQualityOfService = 0;
    /* The generated FILE_GENERIC_* masks (abi/ntioapi.h) share SYNCHRONIZE, so
     * the read|write OR reads as redundant to the lint; it is not. */
    /* NOLINTNEXTLINE(misc-redundant-expression) */
    return NtCreateFile(handleOut, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &attr, &iosb, 0,
                        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
}

/* Has a console server attached? A forwarded verb answers
 * STATUS_INVALID_DEVICE_STATE fast while there is no conhost (drivers/
 * condrv.c CondrvForward) and round-trips once one is pumping. */
static int SmssConsoleServerAttached(void)
{
    IO_STATUS_BLOCK iosb;
    ULONG mode = 0;
    NTSTATUS status = NtDeviceIoControlFile(SmssConsoleInput, 0, 0, 0, &iosb, IOCTL_CONDRV_GET_MODE,
                                            0, 0, &mode, sizeof(mode));
    return status == STATUS_SUCCESS;
}

/* Start the M9 console server: conhost, pumping the kernel ConDrv transport
 * with the COM1 serial tty behind it (HACK-004). Fire-and-forget — conhost
 * outlives every console client. Absent conhost.exe (the hermetic test
 * images) is not an error: console requests then fail fast and nothing here
 * blocks. */
void SmssStartConhost(void)
{
    static const WCHAR path[] = WSTR("\\??\\C:\\windows\\system32\\conhost.exe");
    if (!SmssFileExists(path, 0))
        return;

    static HANDLE SmssConhostProcess, SmssConhostThread;
    NTSTATUS status = SmssSpawn(path, 0, 0, &SmssConhostProcess, &SmssConhostThread);
    if (status != STATUS_SUCCESS)
    {
        SmssPrintf("[KTEST] conhost FAIL (create=%x)\n", SMSS_HEX(status));
        return;
    }

    /* The console handles the children will inherit; opening needs no
     * server, only \Device\ConDrv itself. */
    status = SmssOpenConDrv(WSTR("\\Device\\ConDrv\\Connection"), 0, &SmssConsoleConnection);
    if (status == STATUS_SUCCESS)
        status = SmssOpenConDrv(WSTR("\\Device\\ConDrv\\Input"), OBJ_INHERIT, &SmssConsoleInput);
    if (status == STATUS_SUCCESS)
        status = SmssOpenConDrv(WSTR("\\Device\\ConDrv\\Output"), OBJ_INHERIT, &SmssConsoleOutput);
    if (status != STATUS_SUCCESS)
    {
        SmssPrintf("[KTEST] conhost FAIL (condrv open=%x)\n", SMSS_HEX(status));
        return;
    }

    /* 30 s, not 10: the windowed conhost (GUI-5) loads user32/gdi32/win32u
     * and completes its desktop-server connect before it can open the
     * ConDrv server device — a long prologue under TCG. The headless
     * conhost attaches in a fraction of either bound; only the failure
     * detection latency changes. */
    for (int waitedMs = 0; waitedMs < 30000; waitedMs += 100)
    {
        if (SmssConsoleServerAttached())
        {
            SmssConsoleReady = 1;
            SmssSay("[KTEST] conhost up\n");
            return;
        }
        SmssSleep(100);
    }
    SmssSay("[KTEST] conhost FAIL (no server attach)\n");
}
