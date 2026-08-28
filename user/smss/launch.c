/* user/smss/launch.c — process launching over the raw NtCreateUserProcess
 * boundary: the kernel's old PsRunUserImage duties, done from ring 3.
 *
 * Every child gets an explicit parameter block built from smss's own
 * furniture (which IS the kernel default: smss is a params-less kernel
 * launch), because the console field always carries a value now — the
 * boot console for console children, CONSOLE_HANDLE_SHELL_NO_WINDOW for
 * scripted console-less ones (SmssSpawn says why).
 *
 * M11: the boot console is minted through the STOCK alloc_console open
 * sequence (third_party/wine dlls/kernelbase/console.c 404-499): a
 * \Device\ConDrv\Server open, "Reference" relative to it minting the
 * console, conhost.exe spawned with `--server 0x%x` through
 * value-preserving handle-list inheritance, and the server handle closed
 * once the child owns it. smss keeps ONLY the console (Reference) handle:
 * it is what console children are seeded with, and holding it forever is
 * what keeps the boot console — and its conhost — alive (drivers/condrv.c
 * CondrvClientGone). smss itself never binds (no Connection open), so its
 * EPROCESS stays off every console and the Ctrl+C fanout can never select
 * the session manager (kernel/ps/process.c PsPropagateConsoleCtrlEvent).
 *
 * Children are seeded the PSEUDOCONSOLE-attach way (dlls/kernelbase/
 * process.c 606-622: ConsoleHandle = the console, ConsoleFlags |= 2, no
 * std handles): the child's own init_console (dlls/kernelbase/console.c
 * 2400-2407) opens its Connection — which binds it — and mints its std
 * handles from the ConsoleFlags & 2 request. */
#include "user/smss/smss.h"

#include "abi/ntcondrv.h"

static HANDLE SmssConsoleHandle; /* the boot console (a Reference open) */
static int SmssConsoleReady;

int SmssConsoleAvailable(void)
{
    return SmssConsoleReady;
}

NTSTATUS SmssSpawn(const WCHAR *ntPath, const WCHAR *cmdline, int console,
                   const WCHAR *currentDirectory, HANDLE *processOut, HANDLE *threadOut)
{
    NTSTATUS status;
    USHORT chars = 0;
    while (ntPath[chars] != 0)
        chars++;

    /* Every child gets an explicit parameter block now (the console field
     * always carries a value); RtlDestroyProcessParameters frees it after
     * the create captured it. */
    RTL_USER_PROCESS_PARAMETERS *params = 0;
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

        UNICODE_STRING image, cmd, cwd;
        SmssInitUnicodeString(&image, dos);
        SmssInitUnicodeString(&cmd, cmdline != 0 ? cmdline : dos);
        /* The directory the child starts in. A caller that names none
         * inherits smss's own, which is the kernel default
         * C:\windows\system32\ (kernel/ps/peb.c PspBuildDefaultParams) --
         * the same way a child of the oracle's runner inherits whatever
         * directory the runner was `cd`'d into. */
        if (currentDirectory != 0)
            SmssInitUnicodeString(&cwd, currentDirectory);
        status = RtlCreateProcessParametersEx(
            &params, &image, &SmssOwnParams->DllPath,
            currentDirectory != 0 ? &cwd : &SmssOwnParams->CurrentDirectory.DosPath, &cmd,
            SmssOwnParams->Environment, &image /* window title = image, the kernel rule */, 0, 0, 0,
            PROCESS_PARAMS_FLAG_NORMALIZED);
        if (status != STATUS_SUCCESS)
            return status;
        if (console == 1)
        {
            /* The pseudoconsole-attach seeding (header comment): the
             * create-path fixup re-duplicates the console handle into the
             * child; the child binds and builds its own std handles. */
            params->ConsoleHandle = SmssConsoleHandle;
            params->ConsoleFlags = 2;
        }
        else if (console == 2)
        {
            /* A desktop console client: the ALLOC sentinel is what
             * kernelbase's CreateProcess hands a console-less parent's CUI
             * child (dlls/kernelbase/process.c 196-204), and the child's
             * init_console answers it with the stock alloc_console — its
             * own console, its own windowed conhost (the gui5con leg's
             * subject). */
            params->ConsoleHandle = CONSOLE_HANDLE_ALLOC;
        }
        else
        {
            /* A console-less scripted child is seeded the way the ORACLE's
             * runner-launched processes arrive: ntdll's unix side hands a
             * redirected, non-tty process CONSOLE_HANDLE_SHELL_NO_WINDOW
             * (dlls/ntdll/unix/env.c 1369-1370), which init_console leaves
             * alone — so a CUI child of a console-less chain does NOT
             * AllocConsole itself a conhost. Without this, both runners
             * diverge: the sem_ps job pins count the conhost.exe an
             * ALLOC-sentinel child would spawn into the job. A child that
             * SHOULD alloc (sem_console/subsystem_gate) FreeConsoles first,
             * which nulls the sentinel — the oracle's own arrangement. */
            params->ConsoleHandle = CONSOLE_HANDLE_SHELL_NO_WINDOW;
        }
        params->hStdInput = 0;
        params->hStdOutput = 0;
        params->hStdError = 0;
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

NTSTATUS SmssRun(const WCHAR *ntPath, const WCHAR *cmdline, int console,
                 const WCHAR *currentDirectory, ULONG timeoutMs, NTSTATUS *exitOut)
{
    HANDLE process = 0, thread = 0;
    NTSTATUS status = SmssSpawn(ntPath, cmdline, console, currentDirectory, &process, &thread);
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
 * forever because the process never exits.
 *
 * Only on a GUI boot. `Gui=0` is CUI-ONLY, not headless-with-a-desktop: there
 * is no desktop, so there is nothing for a desktop server to serve, and a
 * user32 call that would create a window FAILS at runtime (the client half
 * reads the same flag -- user/wine/wineserver-lite/client/call.c
 * transport_init -- so it neither waits for the server nor falls back
 * in-process). The gate used to be a probe for the file on the volume, from
 * when a CUI image simply did not carry the server; one image carries it
 * either way now, so the file stopped distinguishing anything and the BOOT
 * decides. */
void SmssStartWineServer(void)
{
    if (!SmssIsGuiBoot())
    {
        SmssSay("smss: CUI-only boot; no desktop server\n");
        return;
    }
    /* No probe: on a GUI boot the server is REQUIRED, so a missing file is a
     * bringup failure to say out loud (SmssSpawn below), not a reason to
     * quietly come up without a desktop. */
    static const WCHAR path[] = WSTR("\\??\\C:\\windows\\system32\\wineserver-lite.exe");
    static HANDLE SmssWineServerProcess, SmssWineServerThread;
    NTSTATUS status = SmssSpawn(path, 0, 0, 0, &SmssWineServerProcess, &SmssWineServerThread);
    if (status != STATUS_SUCCESS)
        SmssPrintf("[KTEST] gui3 server FAIL (create=%x)\n", SMSS_HEX(status));
}

/* One \Device\ConDrv (or \Device\Serial0) open, absolute or relative to
 * `root`, with the exact access shape kernelbase's console opens carry.
 * `attributes` carries OBJ_INHERIT where a handle must survive into a
 * child's table at its value (the server handle `--server 0x%x` names;
 * the tty pair the headless conhost reads its std handles from). */
static NTSTATUS SmssOpenConDrv(HANDLE root, const WCHAR *ntPath, ULONG attributes,
                               HANDLE *handleOut)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    SmssInitUnicodeString(&name, ntPath);
    attr.Length = sizeof(attr);
    attr.RootDirectory = root;
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

/* Spawn conhost with the server handle in a PS_ATTRIBUTE_HANDLE_LIST under
 * PROCESS_CREATE_FLAGS_INHERIT_HANDLES — the alloc_console spawn shape
 * (dlls/kernelbase/console.c 469-476). The listed copy preserves handle
 * VALUES (sem_ps/inherit.c), which is what makes the `--server 0x%x` text
 * valid in the child. The tty pair rides the std-handle fields (values
 * preserved the same way). */
static NTSTATUS SmssSpawnConhost(const WCHAR *cmdline, HANDLE serverHandle, HANDLE ttyIn,
                                 HANDLE ttyOut, HANDLE *processOut, HANDLE *threadOut)
{
    static const WCHAR path[] = WSTR("\\??\\C:\\windows\\system32\\conhost.exe");
    static const WCHAR image[] = WSTR("C:\\windows\\system32\\conhost.exe");
    USHORT chars = 0;
    while (path[chars] != 0)
        chars++;

    RTL_USER_PROCESS_PARAMETERS *params = 0;
    UNICODE_STRING imageString, cmd;
    SmssInitUnicodeString(&imageString, image);
    SmssInitUnicodeString(&cmd, cmdline);
    NTSTATUS status = RtlCreateProcessParametersEx(
        &params, &imageString, &SmssOwnParams->DllPath, &SmssOwnParams->CurrentDirectory.DosPath,
        &cmd, SmssOwnParams->Environment, &imageString, 0, 0, 0, PROCESS_PARAMS_FLAG_NORMALIZED);
    if (status != STATUS_SUCCESS)
        return status;
    params->hStdInput = ttyIn;
    params->hStdOutput = ttyOut;
    params->hStdError = ttyOut;

    struct
    {
        SIZE_T totalLength;
        PS_ATTRIBUTE attributes[3];
    } attrList;
    PS_CREATE_INFO createInfo;
    CLIENT_ID clientId;
    clientId.UniqueProcess = 0;
    clientId.UniqueThread = 0;
    HANDLE handleList[1] = {serverHandle};

    attrList.totalLength = sizeof(attrList);
    attrList.attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    attrList.attributes[0].Size = (SIZE_T)chars * sizeof(WCHAR);
    attrList.attributes[0].ValuePtr = (void *)path;
    attrList.attributes[0].ReturnLength = 0;
    attrList.attributes[1].Attribute = PS_ATTRIBUTE_CLIENT_ID;
    attrList.attributes[1].Size = sizeof(clientId);
    attrList.attributes[1].ValuePtr = &clientId;
    attrList.attributes[1].ReturnLength = 0;
    attrList.attributes[2].Attribute = PS_ATTRIBUTE_HANDLE_LIST;
    attrList.attributes[2].Size = sizeof(handleList);
    attrList.attributes[2].ValuePtr = handleList;
    attrList.attributes[2].ReturnLength = 0;

    for (unsigned i = 0; i < sizeof(createInfo); i++)
        ((unsigned char *)&createInfo)[i] = 0;
    createInfo.Size = sizeof(createInfo);

    HANDLE process = 0, thread = 0;
    status = NtCreateUserProcess(&process, &thread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, 0, 0,
                                 PROCESS_CREATE_FLAGS_INHERIT_HANDLES, 0, params, &createInfo,
                                 (PS_ATTRIBUTE_LIST *)&attrList);
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

/* Start the boot console: mint it through the stock open sequence (header
 * comment) and hand it to a conhost of our own spawning. Fire-and-forget —
 * this conhost outlives every console client because smss holds the
 * console handle forever.
 *
 * No probe: the PRODUCT image carries conhost.exe on every boot, so "is it
 * there" decides nothing, and skipping silently on its absence would turn a
 * broken bake into a boot with no console rather than into a failure anyone
 * reads. SmssSpawnConhost says so out loud instead.
 *
 * A hermetic kernel fixture carries no conhost and no console clients; it says
 * so by NAMING a fixture leg, from which the kernel derives `Userland`
 * (kernel/cm/registry.c CmpNoUserlandLegs) -- the volume cannot tell a fixture
 * that never had the file apart from a product bake that lost it. */
void SmssStartConhost(void)
{
    if (!SmssHasUserland())
    {
        SmssSay("smss: no Windows userland on this boot; conhost skipped\n");
        return;
    }

    /* Server, then the console minted on it (create_console_server /
     * create_console_reference). */
    HANDLE server = 0;
    NTSTATUS status = SmssOpenConDrv(0, WSTR("\\Device\\ConDrv\\Server"), OBJ_INHERIT, &server);
    if (status == STATUS_SUCCESS)
        status = SmssOpenConDrv(server, WSTR("Reference"), 0, &SmssConsoleHandle);
    if (status != STATUS_SUCCESS)
    {
        SmssPrintf("[KTEST] conhost FAIL (console mint=%x)\n", SMSS_HEX(status));
        return;
    }

    /* The boot console is ALWAYS the serial console (issue #232, HACK-004):
     * every boot — GUI boots included — keeps the serial debug channel, and
     * a desktop console is a thing a CLIENT allocates (stock alloc_console
     * spawns its own windowed conhost). The `--server 0x%x` text is the
     * handle's VALUE, preserved into the child by the listed copy. */
    WCHAR cmdline[96];
    static const WCHAR prefix[] = WSTR("conhost.exe --headless --width 80 --height 25 --server 0x");
    int n = 0;
    while (prefix[n] != 0)
    {
        cmdline[n] = prefix[n];
        n++;
    }
    ULONG_PTR value = (ULONG_PTR)server;
    for (int shift = 60; shift >= 0; shift -= 4)
    {
        static const WCHAR digits[] = WSTR("0123456789abcdef");
        cmdline[n++] = digits[(value >> shift) & 0xf];
    }
    cmdline[n] = 0;

    HANDLE ttyIn = 0, ttyOut = 0;
    status = SmssOpenConDrv(0, WSTR("\\Device\\Serial0"), OBJ_INHERIT, &ttyIn);
    if (status == STATUS_SUCCESS)
        status = SmssOpenConDrv(0, WSTR("\\Device\\Serial0"), OBJ_INHERIT, &ttyOut);
    if (status != STATUS_SUCCESS)
    {
        SmssPrintf("[KTEST] conhost FAIL (tty open=%x)\n", SMSS_HEX(status));
        return;
    }

    static HANDLE SmssConhostProcess, SmssConhostThread;
    status =
        SmssSpawnConhost(cmdline, server, ttyIn, ttyOut, &SmssConhostProcess, &SmssConhostThread);
    /* The child owns its copies now; closing smss's ends this side's claim
     * (alloc_console's own CloseHandle(server) moment). On failure the
     * closes are the unwind. */
    NtClose(server);
    if (ttyIn != 0)
        NtClose(ttyIn);
    if (ttyOut != 0)
        NtClose(ttyOut);
    if (status != STATUS_SUCCESS)
    {
        SmssPrintf("[KTEST] conhost FAIL (create=%x)\n", SMSS_HEX(status));
        return;
    }

    /* The attach probe: one GET_MODE through the console object. It queues
     * on the console's request stream and completes when conhost's first
     * pump answers it; a conhost that dies instead fails it fast
     * (drivers/condrv.c CondrvServerGone fails every parked verb). */
    IO_STATUS_BLOCK iosb;
    ULONG mode = 0;
    status = NtDeviceIoControlFile(SmssConsoleHandle, 0, 0, 0, &iosb, IOCTL_CONDRV_GET_MODE, 0, 0,
                                   &mode, sizeof(mode));
    if (status != STATUS_SUCCESS)
    {
        SmssPrintf("[KTEST] conhost FAIL (no server attach: %x)\n", SMSS_HEX(status));
        return;
    }
    SmssConsoleReady = 1;
    SmssSay("[KTEST] conhost up\n");
}
