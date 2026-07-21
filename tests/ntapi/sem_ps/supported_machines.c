/*
 * sem_ps/supported_machines.c — NtQuerySystemInformationEx(
 * SystemSupportedProcessorArchitectures) (CUI-1).
 *
 * wineboot gates its whole rundll32/InstallHinfSection machinery on this
 * query (third_party/wine programs/wineboot/wineboot.c: a failure zeroes
 * machines[0].Machine and the DefaultInstall pass never runs), so CUI-1
 * pins the answer's shape here, greened on the pinned oracle first (Art. 5).
 * Semantics from third_party/wine dlls/ntdll/unix/system.c
 * NtQuerySystemInformationEx: the query blob is the target process HANDLE
 * (NULL handle allowed — no per-process machine then), the answer is a
 * native-first array of one-DWORD bitfield entries plus an all-zero
 * terminator, ret_size reports (count + 1) entries even when the buffer is
 * too small, and a missing/short query blob is STATUS_INVALID_PARAMETER
 * before ret_size is touched. Tolerant of extra non-native entries so a
 * wow64-enabled oracle build stays green; proskrnl (64-bit only) answers
 * exactly native + terminator.
 */
#include "util.h"

/* wine/include/winternl.h SYSTEM_INFORMATION_CLASS (mingw's winternl.h
 * enum stops far earlier; same numbering). Mirrored in generated
 * abi/ntpsapi.h. */
#define PS_SystemSupportedProcessorArchitectures ((SYSTEM_INFORMATION_CLASS)181)

/* wine/include/winnt.h SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION
 * (absent from mingw's headers); one DWORD of bitfields. */
typedef struct
{
    ULONG Machine : 16;
    ULONG KernelMode : 1;
    ULONG UserMode : 1;
    ULONG Native : 1;
    ULONG Process : 1;
    ULONG WoW64Container : 1;
    ULONG ReservedZero0 : 11;
} PS_SUPPORTED_MACHINE;

/* winternl.h omits this; declared as wine/include/winternl.h does. */
NTSYSAPI NTSTATUS NTAPI NtQuerySystemInformationEx(SYSTEM_INFORMATION_CLASS, const void *, ULONG,
                                                   void *, ULONG, ULONG *);

START_TEST(supported_machines)
{
    NTSTATUS status;
    PS_SUPPORTED_MACHINE machines[8];
    HANDLE process = NtCurrentProcess();
    ULONG returnLength;

    /* --- the wineboot call shape ----------------------------------------- */
    memset(machines, 0xcc, sizeof(machines));
    returnLength = 0;
    status = NtQuerySystemInformationEx(PS_SystemSupportedProcessorArchitectures, &process,
                                        sizeof(process), machines, sizeof(machines), &returnLength);
    ok(status == STATUS_SUCCESS, "query -> %08lx", (unsigned long)status);
    ok(returnLength >= 2 * sizeof(machines[0]), "return length %lu", (unsigned long)returnLength);
    ok(returnLength % sizeof(machines[0]) == 0, "return length %lu not whole entries",
       (unsigned long)returnLength);
    ULONG count = returnLength / sizeof(machines[0]);
    ok(count <= 8, "entry count %lu", (unsigned long)count);

    /* Entry 0 is the native machine (system.c fills it first): x86-64,
     * runnable in both modes. wineboot only consumes .Machine, but the
     * kernel/user/native bits are what mark it native. */
    ok(machines[0].Machine == IMAGE_FILE_MACHINE_AMD64, "native machine %#x",
       (unsigned)machines[0].Machine);
    ok(machines[0].Native == 1, "native bit %u", (unsigned)machines[0].Native);
    ok(machines[0].KernelMode == 1, "kernel-mode bit %u", (unsigned)machines[0].KernelMode);
    ok(machines[0].UserMode == 1, "user-mode bit %u", (unsigned)machines[0].UserMode);
    ok(machines[0].ReservedZero0 == 0, "reserved bits %#x", (unsigned)machines[0].ReservedZero0);

    /* The last reported entry is the all-zero terminator (memset above was
     * 0xcc, so a zero here was written by the kernel). */
    PS_SUPPORTED_MACHINE last = machines[count - 1];
    ok(last.Machine == 0 && last.Native == 0 && last.UserMode == 0 && last.KernelMode == 0,
       "terminator entry not zero (machine %#x)", (unsigned)last.Machine);

    /* Entries between native and terminator (a wow64-capable oracle) are
     * user-mode-only, never native. */
    for (ULONG i = 1; i + 1 < count; i++)
    {
        ok(machines[i].Native == 0 && machines[i].UserMode == 1, "entry %lu native=%u usermode=%u",
           (unsigned long)i, (unsigned)machines[i].Native, (unsigned)machines[i].UserMode);
    }

    /* --- a NULL process handle in the query blob is accepted ------------- */
    HANDLE nullProcess = NULL;
    status = NtQuerySystemInformationEx(PS_SystemSupportedProcessorArchitectures, &nullProcess,
                                        sizeof(nullProcess), machines, sizeof(machines), NULL);
    ok(status == STATUS_SUCCESS, "NULL process handle -> %08lx", (unsigned long)status);

    /* --- error legs (system.c, before ret_size is written) --------------- */
    status = NtQuerySystemInformationEx(PS_SystemSupportedProcessorArchitectures, NULL, 0, machines,
                                        sizeof(machines), NULL);
    ok(status == STATUS_INVALID_PARAMETER, "no query blob -> %08lx", (unsigned long)status);

    ULONG shortQuery = 0;
    status = NtQuerySystemInformationEx(PS_SystemSupportedProcessorArchitectures, &shortQuery,
                                        sizeof(shortQuery), machines, sizeof(machines), NULL);
    ok(status == STATUS_INVALID_PARAMETER, "short query blob -> %08lx", (unsigned long)status);

    /* Too-small answer buffer: STATUS_BUFFER_TOO_SMALL, and ret_size still
     * reports the needed length (the epilogue writes len unconditionally). */
    returnLength = 0;
    status =
        NtQuerySystemInformationEx(PS_SystemSupportedProcessorArchitectures, &process,
                                   sizeof(process), machines, sizeof(machines[0]), &returnLength);
    ok(status == STATUS_BUFFER_TOO_SMALL, "small buffer -> %08lx", (unsigned long)status);
    ok(returnLength >= 2 * sizeof(machines[0]), "small-buffer return length %lu",
       (unsigned long)returnLength);
}
