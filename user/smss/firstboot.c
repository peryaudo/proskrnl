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

NTSTATUS FirstbootRun(void)
{
    NTSTATUS status;

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
