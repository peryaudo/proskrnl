/*
 * sem_ps/wow64_machines.c — the machine table (WOW64 milestone).
 *
 * Before ntdll will build a WOW64 process it asks the kernel which machines
 * this system runs and in what role: SystemSupportedProcessorArchitectures
 * takes a process handle and answers a NULL-terminated array of
 * SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION rows, one per
 * machine, with flags saying whether the machine is the native one, whether
 * it can host a WoW64 container, and — the one field that depends on the
 * HANDLE rather than the system — whether the named process is that
 * machine. That last bit is how RtlWow64GetProcessMachines answers, which
 * is how kernelbase's IsWow64Process2 answers.
 *
 * Pinned here from a 64-bit caller:
 *   - the system's row set, queried for the current process: AMD64 present
 *     and native, I386 present and able to host a WoW64 container, list
 *     NULL-terminated;
 *   - the per-handle Process bit: set on the AMD64 row for a 64-bit target
 *     and on the I386 row for a WOW64 target, never both;
 *   - the emulation view: SystemEmulationBasicInformation from a 64-bit
 *     caller reports the same address range as SystemBasicInformation (the
 *     narrowing is a property of the CALLER, not of the system, so a 64-bit
 *     caller sees no narrowing at all).
 *
 * Oracle-first (G5): every assert below is measured on the pinned Wine.
 */
#include "util.h"

#include <string.h> /* declarations only: the .exe links no CRT (ntapi.c) */

/* wine/include/winternl.h: SystemSupportedProcessorArchitectures = 181,
 * SystemEmulationBasicInformation = 62. Wrong values would answer
 * STATUS_INVALID_INFO_CLASS on the oracle, so the oracle run validates
 * them. */
#define PS_SystemSupportedProcessorArchitectures ((SYSTEM_INFORMATION_CLASS)181)
#define PS_SystemEmulationBasicInformation       ((SYSTEM_INFORMATION_CLASS)62)

/* wine/include/winternl.h SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION:
 * a machine word plus a bitfield. Spelled as a flags word here because the
 * bit POSITIONS are what the pin is about. */
typedef struct
{
    ULONG Machine : 16;
    ULONG KernelMode : 1;
    ULONG UserMode : 1;
    ULONG Native : 1;
    ULONG Process : 1;
    ULONG WoW64Container : 1;
    ULONG ReservedZero0 : 11;
} NTAPI_ARCHITECTURES_INFORMATION;

/* wine/include/winnt.h. */
#define PS_IMAGE_FILE_MACHINE_I386  0x014c
#define PS_IMAGE_FILE_MACHINE_AMD64 0x8664

/* SYSTEM_BASIC_INFORMATION, x64 layout as wine/include/winternl.h; mingw's
 * winternl.h spells only part of it (the system_fixed_classes mirror). */
typedef struct
{
    ULONG unknown;
    ULONG KeMaximumIncrement;
    ULONG PageSize;
    ULONG MmNumberOfPhysicalPages;
    ULONG MmLowestPhysicalPage;
    ULONG MmHighestPhysicalPage;
    ULONG AllocationGranularity;
    ULONG_PTR LowestUserAddress;
    ULONG_PTR HighestUserAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    BYTE NumberOfProcessors;
} NTAPI_SYSTEM_BASIC_INFORMATION;

static NTAPI_ARCHITECTURES_INFORMATION machines[8];

/* Find the row for `machine`, or NULL. The list is NULL-terminated by a row
 * whose Machine is 0, so the search doubles as the termination check. */
static NTAPI_ARCHITECTURES_INFORMATION *find_machine(ULONG machine, ULONG count)
{
    ULONG i;
    for (i = 0; i < count && machines[i].Machine != 0; i++)
    {
        if (machines[i].Machine == machine)
        {
            return &machines[i];
        }
    }
    return NULL;
}

START_TEST(wow64_machines)
{
    NTSTATUS status;
    ULONG return_length;

    /* --- the system's row set, asked about the 64-bit self -------------- */
    HANDLE self = GetCurrentProcess();
    memset(machines, 0, sizeof(machines));
    return_length = 0;
    status = NtQuerySystemInformationEx(PS_SystemSupportedProcessorArchitectures, &self,
                                        sizeof(self), machines, sizeof(machines), &return_length);
    ok(status == STATUS_SUCCESS, "SupportedProcessorArchitectures(self) -> %08lx",
       (unsigned long)status);
    ok(return_length != 0 && return_length % sizeof(machines[0]) == 0,
       "return length %lu is not a whole number of rows", (unsigned long)return_length);
    ULONG count = return_length / (ULONG)sizeof(machines[0]);

    NTAPI_ARCHITECTURES_INFORMATION *amd64 = find_machine(PS_IMAGE_FILE_MACHINE_AMD64, count);
    NTAPI_ARCHITECTURES_INFORMATION *i386 = find_machine(PS_IMAGE_FILE_MACHINE_I386, count);
    ok(amd64 != NULL, "no AMD64 row in %lu rows", (unsigned long)count);
    ok(i386 != NULL, "no I386 row in %lu rows", (unsigned long)count);
    /* The terminator is a row of zeroes AFTER the real ones. */
    ok(machines[count - 1].Machine == 0, "row %lu is not the terminator (machine %lx)",
       (unsigned long)count - 1, (unsigned long)machines[count - 1].Machine);
    if (amd64 == NULL || i386 == NULL)
    {
        skip("no machine table to measure");
        return;
    }

    ok(amd64->Native, "AMD64 is not native");
    ok(amd64->UserMode, "AMD64 has no user mode");
    ok(amd64->Process, "AMD64.Process clear for a 64-bit process");
    ok(!i386->Native, "I386 claims to be native");
    ok(i386->UserMode, "I386 has no user mode");
    ok(i386->WoW64Container, "I386 cannot host a WoW64 container");
    ok(!i386->Process, "I386.Process set for a 64-bit process");

    /* --- the same query about a WOW64 child ----------------------------- */
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    BOOL created = CreateProcessA("C:\\windows\\syswow64\\cmd.exe", NULL, NULL, NULL, FALSE,
                                  CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    todo_proskrnl ok(created, "CreateProcessA(syswow64\\cmd.exe) -> %lu",
                     (unsigned long)GetLastError());
    if (created)
    {
        memset(machines, 0, sizeof(machines));
        return_length = 0;
        status = NtQuerySystemInformationEx(PS_SystemSupportedProcessorArchitectures, &pi.hProcess,
                                            sizeof(pi.hProcess), machines, sizeof(machines),
                                            &return_length);
        ok(status == STATUS_SUCCESS, "SupportedProcessorArchitectures(wow64 child) -> %08lx",
           (unsigned long)status);
        count = return_length / (ULONG)sizeof(machines[0]);
        amd64 = find_machine(PS_IMAGE_FILE_MACHINE_AMD64, count);
        i386 = find_machine(PS_IMAGE_FILE_MACHINE_I386, count);
        ok(amd64 != NULL && i386 != NULL, "machine rows missing for the child");
        if (amd64 != NULL && i386 != NULL)
        {
            /* The whole point of the class: the SAME system table, with the
             * Process bit moved to the machine the HANDLE names. */
            ok(i386->Process, "I386.Process clear for a WOW64 process");
            ok(!amd64->Process, "AMD64.Process set for a WOW64 process");
            ok(amd64->Native, "AMD64 stopped being native for a WOW64 handle");
        }
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    /* --- the emulation view from a 64-bit caller ------------------------ */
    NTAPI_SYSTEM_BASIC_INFORMATION basic;
    NTAPI_SYSTEM_BASIC_INFORMATION emulated;
    memset(&basic, 0, sizeof(basic));
    memset(&emulated, 0, sizeof(emulated));
    status = NtQuerySystemInformation(SystemBasicInformation, &basic, sizeof(basic), NULL);
    ok(status == STATUS_SUCCESS, "SystemBasicInformation -> %08lx", (unsigned long)status);
    status = NtQuerySystemInformation(PS_SystemEmulationBasicInformation, &emulated,
                                      sizeof(emulated), NULL);
    ok(status == STATUS_SUCCESS, "SystemEmulationBasicInformation -> %08lx", (unsigned long)status);
    /* MEASURED: from a 64-bit caller the emulation view is the ordinary
     * one. The narrowing to the 32-bit address range is a property of the
     * CALLER being a guest, which a 64-bit test cannot be — so this arm is
     * a regression pin on "does not narrow", not on the narrowed values. */
    ok(emulated.HighestUserAddress == basic.HighestUserAddress,
       "emulation HighestUserAddress %p != basic %p", (void *)emulated.HighestUserAddress,
       (void *)basic.HighestUserAddress);
    ok(emulated.PageSize == basic.PageSize, "emulation PageSize %lu != basic %lu",
       (unsigned long)emulated.PageSize, (unsigned long)basic.PageSize);
}
