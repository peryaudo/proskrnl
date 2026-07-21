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

static const WCHAR image_dos[] = WSTR("C:\\windows\\system32\\wineboot.exe");
static const WCHAR image_nt[] = WSTR("\\??\\C:\\windows\\system32\\wineboot.exe");
static const WCHAR command_line[] = WSTR("C:\\windows\\system32\\wineboot.exe --init");
static const WCHAR current_dir[] = WSTR("C:\\windows");

/* Alphabetical, as NT keeps environment blocks sorted (peb.c precedent). */
static const WCHAR environment[] = WSTR("COMSPEC=C:\\windows\\system32\\cmd.exe\0"
                                        "PATH=C:\\windows\\system32\0"
                                        "SystemDrive=C:\0"
                                        "SystemRoot=C:\\windows\0"
                                        "TEMP=C:\\windows\\temp\0"
                                        "TMP=C:\\windows\\temp\0"
                                        "WINECONFIGDIR=\\??\\C:\\windows\0"
                                        "WINEDATADIR=\\??\\C:\\windows\\inf\0"
                                        "windir=C:\\windows\0");

NTSTATUS firstboot_run(void)
{
    NTSTATUS status;

    smss_say("smss: firstboot: running wineboot --init\n");

    UNICODE_STRING image, cmdline, curdir;
    smss_init_ustr(&image, image_dos);
    smss_init_ustr(&cmdline, command_line);
    smss_init_ustr(&curdir, current_dir);

    RTL_USER_PROCESS_PARAMETERS *params = 0;
    status = RtlCreateProcessParametersEx(&params, &image, 0, &curdir, &cmdline, (PWSTR)environment,
                                          0, 0, 0, 0, PROCESS_PARAMS_FLAG_NORMALIZED);
    if (status != STATUS_SUCCESS)
    {
        smss_say("smss: firstboot: RtlCreateProcessParametersEx failed\n");
        return 0x41;
    }

    HANDLE process = 0, thread = 0;
    CLIENT_ID client_id;
    client_id.UniqueProcess = 0;
    client_id.UniqueThread = 0;
    {
        struct
        {
            SIZE_T total_length;
            PS_ATTRIBUTE attributes[2];
        } attr_list;
        PS_CREATE_INFO create_info;
        USHORT chars = 0;
        while (image_nt[chars] != 0)
            chars++;

        attr_list.total_length = sizeof(attr_list);
        attr_list.attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
        attr_list.attributes[0].Size = (SIZE_T)chars * sizeof(WCHAR);
        attr_list.attributes[0].ValuePtr = (void *)image_nt;
        attr_list.attributes[0].ReturnLength = 0;
        attr_list.attributes[1].Attribute = PS_ATTRIBUTE_CLIENT_ID;
        attr_list.attributes[1].Size = sizeof(client_id);
        attr_list.attributes[1].ValuePtr = &client_id;
        attr_list.attributes[1].ReturnLength = 0;

        for (unsigned i = 0; i < sizeof(create_info); i++)
            ((unsigned char *)&create_info)[i] = 0;
        create_info.Size = sizeof(create_info);

        status = NtCreateUserProcess(&process, &thread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, 0, 0,
                                     0, 0, params, &create_info, (PS_ATTRIBUTE_LIST *)&attr_list);
    }
    RtlDestroyProcessParameters(params);
    if (status != STATUS_SUCCESS)
    {
        smss_say("smss: firstboot: NtCreateUserProcess(wineboot) failed\n");
        return 0x42;
    }

    NTSTATUS child_status = 0x43;
    status = NtWaitForSingleObject(process, FALSE, 0);
    if (status == STATUS_SUCCESS)
    {
        PROCESS_BASIC_INFORMATION basic;
        ULONG returned = 0;
        status = NtQueryInformationProcess(process, ProcessBasicInformation, &basic, sizeof(basic),
                                           &returned);
        if (status == STATUS_SUCCESS)
        {
            child_status = basic.ExitStatus;
        }
    }
    NtClose(thread);
    NtClose(process);
    smss_say(child_status == 0 ? "smss: firstboot: wineboot complete\n"
                               : "smss: firstboot: wineboot failed\n");
    return child_status;
}
