/* user/smss/smss.c — the M8 smss-equivalent: the initial user process
 * (docs/02 "boot completes as kernel → smss-equiv → test process").
 *
 * A native MS-ABI PE linked only against the pinned Wine PE ntdll, started
 * by the kernel exactly like hello.exe (ntdll's loader runs first). Duties,
 * NT-smss-shaped but minimal:
 *
 *   1. prove the registry is up from ring 3 — the SYSTEM hive the kernel
 *      mounted must resolve (\Registry\Machine opens);
 *   2. launch the next process (the M7 acceptance client hello.exe) through
 *      the real NtCreateUserProcess boundary (PS_ATTRIBUTE_IMAGE_NAME);
 *   3. wait for it and exit with ITS exit code, so the kernel's chain
 *      verdict reflects the whole kernel → smss → hello pipeline.
 *
 * User clients follow the test-code conventions (Wine style, docs/15
 * exemption). Exit 0 = the whole chain passed; a distinct code per step.
 */
#include "user/smss/smss.h"

#include "abi/ntregapi.h"

void smss_say(const char *ascii)
{
    WCHAR wide[80];
    USHORT n = 0;
    while (ascii[n] != '\0' && n < 79)
    {
        wide[n] = (WCHAR)(unsigned char)ascii[n];
        n++;
    }
    UNICODE_STRING string;
    string.Length = (USHORT)(n * sizeof(WCHAR));
    string.MaximumLength = string.Length;
    string.Buffer = wide;
    NtDisplayString(&string);
}

void smss_init_ustr(UNICODE_STRING *str, const WCHAR *wide)
{
    USHORT n = 0;
    while (wide[n] != 0)
        n++;
    str->Length = (USHORT)(n * sizeof(WCHAR));
    str->MaximumLength = (USHORT)(str->Length + sizeof(WCHAR));
    str->Buffer = (PWSTR)wide;
}

static const WCHAR next_image[] = WSTR("\\??\\C:\\hello.exe");

void smss_start(void *peb_arg)
{
    NTSTATUS status;

    smss_say("smss: initial process up\n");

    /* CUI-1: `smss.exe firstboot` runs the wineboot hand-off instead of the
     * M8 chain (user/smss/firstboot.c). The kernel decides by command line
     * (KiRunFirstBoot), same image either way. */
    {
        PEB *peb = peb_arg;
        RTL_USER_PROCESS_PARAMETERS *params = peb != 0 ? peb->ProcessParameters : 0;
        if (params != 0 && params->CommandLine.Buffer != 0)
        {
            static const WCHAR word[] = WSTR("firstboot");
            const WCHAR *cmd = params->CommandLine.Buffer;
            USHORT len = (USHORT)(params->CommandLine.Length / sizeof(WCHAR));
            for (USHORT i = 0; i + 9 <= len; i++)
            {
                USHORT k = 0;
                while (k < 9 && cmd[i + k] == word[k])
                    k++;
                if (k == 9)
                {
                    NtTerminateProcess((HANDLE) ~(ULONG_PTR)0, firstboot_run());
                }
            }
        }
    }

    /* 1. The registry the kernel mounted must be reachable from ring 3. */
    {
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        HANDLE machine;
        smss_init_ustr(&name, WSTR("\\Registry\\Machine"));
        attr.Length = sizeof(attr);
        attr.RootDirectory = 0;
        attr.ObjectName = &name;
        attr.Attributes = OBJ_CASE_INSENSITIVE;
        attr.SecurityDescriptor = 0;
        attr.SecurityQualityOfService = 0;
        status = NtOpenKey(&machine, KEY_READ, &attr);
        if (status != STATUS_SUCCESS)
        {
            smss_say("smss: registry not reachable\n");
            NtTerminateProcess((HANDLE) ~(ULONG_PTR)0, 0x10);
        }
        NtClose(machine);
    }

    /* 2. Launch the next process via the NtCreateUserProcess boundary. */
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
        while (next_image[chars] != 0)
            chars++;

        attr_list.total_length = sizeof(attr_list);
        attr_list.attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
        attr_list.attributes[0].Size = (SIZE_T)chars * sizeof(WCHAR);
        attr_list.attributes[0].ValuePtr = (void *)next_image;
        attr_list.attributes[0].ReturnLength = 0;
        attr_list.attributes[1].Attribute = PS_ATTRIBUTE_CLIENT_ID;
        attr_list.attributes[1].Size = sizeof(client_id);
        attr_list.attributes[1].ValuePtr = &client_id;
        attr_list.attributes[1].ReturnLength = 0;

        for (unsigned i = 0; i < sizeof(create_info); i++)
            ((unsigned char *)&create_info)[i] = 0;
        create_info.Size = sizeof(create_info);

        status = NtCreateUserProcess(&process, &thread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, 0, 0,
                                     0, 0, 0, &create_info, (PS_ATTRIBUTE_LIST *)&attr_list);
        if (status != STATUS_SUCCESS || create_info.State != PsCreateSuccess ||
            client_id.UniqueProcess == 0)
        {
            smss_say("smss: NtCreateUserProcess failed\n");
            NtTerminateProcess((HANDLE) ~(ULONG_PTR)0, 0x20);
        }
    }

    /* 3. Wait for the child; exit with its code. */
    NTSTATUS child_status = 0x30;
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
            smss_say(child_status == 0 ? "smss: chain complete\n" : "smss: child failed\n");
        }
    }
    NtClose(thread);
    NtClose(process);
    NtTerminateProcess((HANDLE) ~(ULONG_PTR)0, child_status);
    for (;;)
    {
    }
}
