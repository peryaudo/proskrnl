/* user/smss/firstboot.c — the CUI-1 firstboot hand-off (docs/02, docs/04).
 *
 * Runs `wineboot.exe --init` synchronously and propagates its exit status:
 * wineboot applies wine.inf's machine-state registry payload through
 * rundll32/setupapi children and stamps C:\windows\.update-timestamp, whose
 * freshness check (against the baked wine.inf's mtime) makes later boots
 * skip the work — idempotence comes from wineboot itself, no proskrnl-side
 * marker.
 *
 * The environment mirrors what Wine's loader gives wineboot: WINEDATADIR
 * points get_wine_inf_path at the baked INF and WINECONFIGDIR is where the
 * timestamp lands — both in the \??\ NT form wineboot expects (it rewrites
 * the prefix to \\?\ itself; a bare DOS path would be corrupted by that
 * rewrite). The rest is the kernel's own first-process furniture
 * (kernel/ps/peb.c PspDefaultEnvironment), inherited by the rundll32
 * grandchildren through CreateProcess env passthrough.
 */
#include "user/smss/smss.h"

static const WCHAR FirstbootImageDos[] = WSTR("C:\\windows\\system32\\wineboot.exe");
static const WCHAR FirstbootImageNt[] = WSTR("\\??\\C:\\windows\\system32\\wineboot.exe");
static const WCHAR FirstbootCommandLine[] = WSTR("C:\\windows\\system32\\wineboot.exe --init");
static const WCHAR FirstbootCurrentDir[] = WSTR("C:\\windows");

/* Alphabetical, as NT keeps environment blocks sorted (peb.c precedent). */
static const WCHAR FirstbootEnvironment[] = WSTR("COMSPEC=C:\\windows\\system32\\cmd.exe\0"
                                                 "PATH=C:\\windows\\system32\0"
                                                 "SystemDrive=C:\0"
                                                 "SystemRoot=C:\\windows\0"
                                                 "TEMP=C:\\windows\\temp\0"
                                                 "TMP=C:\\windows\\temp\0"
                                                 "WINECONFIGDIR=\\??\\C:\\windows\0"
                                                 "WINEDATADIR=\\??\\C:\\windows\\inf\0"
                                                 "windir=C:\\windows\0");

/* Open a file under \??\C: for reading; 0 if it is not there. */
static HANDLE FirstbootOpenRead(const WCHAR *ntPath)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE file = 0;
    SmssInitUnicodeString(&name, ntPath);
    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.ObjectName = &name;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    attr.SecurityDescriptor = 0;
    attr.SecurityQualityOfService = 0;
    NTSTATUS status = NtCreateFile(&file, FILE_GENERIC_READ, &attr, &iosb, 0, FILE_ATTRIBUTE_NORMAL,
                                   FILE_SHARE_READ, FILE_OPEN,
                                   FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    return status == STATUS_SUCCESS ? file : 0;
}

/* Has wineboot already initialised this prefix?
 *
 * This must be wineboot's OWN predicate, not an approximation of it, because
 * the two decide the same thing one after the other: if smss thinks the prefix
 * is fresh and wineboot disagrees, smss swaps an inf wineboot then ignores; if
 * smss thinks it is initialised and wineboot disagrees, wineboot runs the FULL
 * RegisterDlls pass on a boot that has no desktop to register against -- the
 * ~150-process flail the registry-only payload exists to prevent.
 *
 * wineboot's rule (programs/wineboot/wineboot.c update_wineprefix ->
 * update_timestamp): the prefix is current when C:\windows\.update-timestamp
 * holds the decimal mtime of wine.inf. Testing only that the stamp EXISTS is
 * weaker in exactly the case that matters -- a stamp left by a different inf.
 */
static int FirstbootPrefixIsInitialised(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE inf = FirstbootOpenRead(WSTR("\\??\\C:\\windows\\inf\\wine.inf"));
    if (inf == 0)
        return 0; /* no payload to be current with */
    FILE_BASIC_INFORMATION basic;
    NTSTATUS status =
        NtQueryInformationFile(inf, &iosb, &basic, sizeof(basic), FileBasicInformation);
    NtClose(inf);
    if (status != STATUS_SUCCESS)
        return 0;

    /* NT time (100 ns since 1601) -> the unix seconds wineboot compares.
     * 116444736000000000 is the 1601->1970 delta; see RtlTimeToSecondsSince1970
     * in the pinned tree (dlls/ntdll/time.c), which is this same constant. */
    LONGLONG unixSeconds = (basic.LastWriteTime.QuadPart - 116444736000000000LL) / 10000000LL;

    HANDLE stamp = FirstbootOpenRead(WSTR("\\??\\C:\\windows\\.update-timestamp"));
    if (stamp == 0)
        return 0;
    char text[64];
    status = NtReadFile(stamp, 0, 0, 0, &iosb, text, sizeof(text) - 1, 0, 0);
    NtClose(stamp);
    if (status != STATUS_SUCCESS)
        return 0;
    text[iosb.Information < sizeof(text) ? iosb.Information : sizeof(text) - 1] = 0;

    /* wineboot writes "disable" to pin a prefix; honour it the same way. */
    const char *disable = "disable";
    int i = 0;
    while (disable[i] != 0 && text[i] == disable[i])
        i++;
    if (disable[i] == 0)
        return 1;

    LONGLONG stamped = 0;
    for (i = 0; text[i] >= '0' && text[i] <= '9'; i++)
        stamped = stamped * 10 + (text[i] - '0');
    return i != 0 && stamped == unixSeconds;
}

/* A boot with no DESKTOP applies the registry-only inf.
 *
 * wine.inf's [RegisterDllsSection] is COM self-registration: setupapi runs
 * each DLL's DllRegisterServer, which needs an apartment, which needs a
 * message window. On a CUI-only boot there is no desktop to put one on, so
 * every entry fails its way through CreateWindow, CoMarshalInterface and an
 * rpcss that will not start — ~150 processes and the whole boot budget, to
 * register the shell's classes on a machine with no shell.
 *
 * Both payloads are baked (Makefile WINE_INF_FULL / WINE_INF_CUI); this
 * installs the one this boot means. Idempotent by SIZE: wineboot's freshness
 * check keys on wine.inf's mtime, so rewriting it every boot would re-run the
 * whole prefix update on boots that had already done it.
 */
/* 0 on success (including "nothing to do"), nonzero when the swap was needed
 * and FAILED. The failure has to reach FirstbootRun: every one of the paths
 * below used to print `[KTEST] firstboot FAIL (...)` and `return` from a void
 * function, after which FirstbootRun carried on and could print `[KTEST]
 * firstboot PASS` for the same boot -- and the harness greps for PASS. Worse
 * than a false green on its own: wineboot then applies the FULL inf on a
 * desktopless boot, which is the ~150-process flail this swap exists to
 * prevent. */
static int FirstbootInstallInf(void)
{
    if (SmssIsGuiBoot())
        return 0; /* the full payload is what the image already carries */

    /* Nothing to choose on a prefix that is already initialised.
     *
     * This is not a boot decision read off the volume (smss makes none —
     * SmssIsGuiBoot above is the decision); it is the same idempotence
     * wineboot itself keeps, asked one step earlier. wineboot's freshness
     * check keys on wine.inf's MTIME, so swapping the payload under an
     * already-updated prefix would re-run the whole prefix update to install
     * a subset of what that prefix already has -- ~90 seconds on this box, on
     * every CUI boot of an image whose first boot was a GUI one. That is
     * exactly the arrangement the harness now uses: one image, warmed once
     * (Makefile IMG_TEST_WARM), copied per leg.
     *
     * \.update-timestamp is wineboot's own stamp, written at the end of the
     * update (programs/wineboot/wineboot.c update_wineprefix), and the
     * predicate above is wineboot's own -- the stamp's VALUE against wine.inf's
     * mtime, not the file's mere presence. It says the prefix is current with
     * whatever inf was installed when it ran, which on a warm image is the
     * full one and on this leg's own boot 1 is the CUI one; either way there
     * is nothing left for this function to install. */
    if (FirstbootPrefixIsInitialised())
        return 0;

    static UCHAR FirstbootInfBuffer[128 * 1024];
    HANDLE src = 0, dst = 0;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;

    SmssInitUnicodeString(&name, WSTR("\\??\\C:\\windows\\inf\\wine-cui.inf"));
    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.ObjectName = &name;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    attr.SecurityDescriptor = 0;
    attr.SecurityQualityOfService = 0;
    NTSTATUS status = NtCreateFile(&src, FILE_GENERIC_READ, &attr, &iosb, 0, FILE_ATTRIBUTE_NORMAL,
                                   FILE_SHARE_READ, FILE_OPEN,
                                   FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    if (status != STATUS_SUCCESS)
    {
        SmssPrintf("[KTEST] firstboot FAIL (no wine-cui.inf, %x)\n", SMSS_HEX(status));
        return 1;
    }
    status = NtReadFile(src, 0, 0, 0, &iosb, FirstbootInfBuffer, sizeof(FirstbootInfBuffer), 0, 0);
    ULONG bytes = (ULONG)iosb.Information;
    NtClose(src);
    if (status != STATUS_SUCCESS || bytes == 0 || bytes == sizeof(FirstbootInfBuffer))
    {
        SmssPrintf("[KTEST] firstboot FAIL (wine-cui.inf read %x, %u bytes)\n", SMSS_HEX(status),
                   (unsigned int)bytes);
        return 1;
    }

    SmssInitUnicodeString(&name, WSTR("\\??\\C:\\windows\\inf\\wine.inf"));
    status = NtCreateFile(&dst, FILE_GENERIC_READ, &attr, &iosb, 0, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ, FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    if (status == STATUS_SUCCESS)
    {
        FILE_STANDARD_INFORMATION info;
        NTSTATUS query =
            NtQueryInformationFile(dst, &iosb, &info, sizeof(info), FileStandardInformation);
        NtClose(dst);
        if (query == STATUS_SUCCESS && info.EndOfFile.QuadPart == (LONGLONG)bytes)
            return 0; /* already the CUI payload: leave the mtime alone */
    }

    status = NtCreateFile(&dst, FILE_GENERIC_WRITE, &attr, &iosb, 0, FILE_ATTRIBUTE_NORMAL, 0,
                          FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                          0, 0);
    if (status != STATUS_SUCCESS)
    {
        SmssPrintf("[KTEST] firstboot FAIL (wine.inf open for write %x)\n", SMSS_HEX(status));
        return 1;
    }
    status = NtWriteFile(dst, 0, 0, 0, &iosb, FirstbootInfBuffer, bytes, 0, 0);
    NtClose(dst);
    if (status != STATUS_SUCCESS)
    {
        SmssPrintf("[KTEST] firstboot FAIL (wine.inf write %x)\n", SMSS_HEX(status));
        return 1;
    }
    SmssPrintf("smss: firstboot: CUI-only boot, installed the registry-only inf (%u bytes)\n",
               (unsigned int)bytes);
    return 0;
}

NTSTATUS FirstbootRun(void)
{
    NTSTATUS status;

    if (FirstbootInstallInf() != 0)
        return 0x43;
    SmssSay("smss: firstboot: running wineboot --init\n");

    UNICODE_STRING image, cmdline, curdir;
    SmssInitUnicodeString(&image, FirstbootImageDos);
    SmssInitUnicodeString(&cmdline, FirstbootCommandLine);
    SmssInitUnicodeString(&curdir, FirstbootCurrentDir);

    RTL_USER_PROCESS_PARAMETERS *params = 0;
    status = RtlCreateProcessParametersEx(&params, &image, 0, &curdir, &cmdline,
                                          (PWSTR)FirstbootEnvironment, 0, 0, 0, 0,
                                          PROCESS_PARAMS_FLAG_NORMALIZED);
    if (status != STATUS_SUCCESS)
    {
        SmssSay("smss: firstboot: RtlCreateProcessParametersEx failed\n");
        return 0x41;
    }

    HANDLE process = 0, thread = 0;
    CLIENT_ID clientId;
    clientId.UniqueProcess = 0;
    clientId.UniqueThread = 0;
    {
        struct
        {
            SIZE_T totalLength;
            PS_ATTRIBUTE attributes[2];
        } attrList;
        PS_CREATE_INFO createInfo;
        USHORT chars = 0;
        while (FirstbootImageNt[chars] != 0)
            chars++;

        attrList.totalLength = sizeof(attrList);
        attrList.attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
        attrList.attributes[0].Size = (SIZE_T)chars * sizeof(WCHAR);
        attrList.attributes[0].ValuePtr = (void *)FirstbootImageNt;
        attrList.attributes[0].ReturnLength = 0;
        attrList.attributes[1].Attribute = PS_ATTRIBUTE_CLIENT_ID;
        attrList.attributes[1].Size = sizeof(clientId);
        attrList.attributes[1].ValuePtr = &clientId;
        attrList.attributes[1].ReturnLength = 0;

        for (unsigned i = 0; i < sizeof(createInfo); i++)
            ((unsigned char *)&createInfo)[i] = 0;
        createInfo.Size = sizeof(createInfo);

        status = NtCreateUserProcess(&process, &thread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, 0, 0,
                                     0, 0, params, &createInfo, (PS_ATTRIBUTE_LIST *)&attrList);
    }
    RtlDestroyProcessParameters(params);
    if (status != STATUS_SUCCESS)
    {
        SmssSay("smss: firstboot: NtCreateUserProcess(wineboot) failed\n");
        return 0x42;
    }

    NTSTATUS childStatus = 0x43;
    status = NtWaitForSingleObject(process, FALSE, 0);
    if (status == STATUS_SUCCESS)
    {
        PROCESS_BASIC_INFORMATION basic;
        ULONG returned = 0;
        status = NtQueryInformationProcess(process, ProcessBasicInformation, &basic, sizeof(basic),
                                           &returned);
        if (status == STATUS_SUCCESS)
        {
            childStatus = basic.ExitStatus;
        }
    }
    NtClose(thread);
    NtClose(process);
    SmssSay(childStatus == 0 ? "smss: firstboot: wineboot complete\n"
                             : "smss: firstboot: wineboot failed\n");
    return childStatus;
}
