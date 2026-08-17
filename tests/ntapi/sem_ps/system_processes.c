/*
 * sem_ps/system_processes.c — NtQuerySystemInformation(SystemProcessInformation).
 *
 * The shape kernel32's CreateToolhelp32Snapshot walks (dlls/kernel32/
 * toolhelp.c fetch_process_thread): a chained buffer of
 * SYSTEM_PROCESS_INFORMATION entries, each followed by its
 * SYSTEM_THREAD_INFORMATION[] array, linked by NextEntryOffset (0 ends the
 * chain). tasklist.exe is the ultimate consumer; without this class there is
 * no tasklist/toolhelp shape at all (docs/02 CUI-4).
 *
 * Producer contract from ntdll's unix side (dlls/ntdll/unix/system.c
 * get_system_process_info): call with a too-small buffer ->
 * STATUS_INFO_LENGTH_MISMATCH with the needed size in the return length;
 * grow and retry (kernel32 doubles). ProcessName is the image BASE name as a
 * UNICODE_STRING; dwThreadCount matches the trailing array. The caller must
 * find its own pid in the walk. Green on the pinned Wine oracle first
 * (Art. 5).
 */
#include "util.h"

/* mingw's winternl.h exposes SYSTEM_PROCESS_INFORMATION with Reserved fields
 * (the non-__WINESRC__ branch); declare the named layout the producer fills,
 * byte-identical to wine/include/winternl.h's __WINESRC__ branch. */
typedef struct
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    DWORD dwTickCount;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    DWORD dwCurrentPriority;
    DWORD dwBasePriority;
    DWORD dwContextSwitches;
    DWORD dwThreadState;
    DWORD dwWaitReason;
    DWORD dwUnknown;
} ps_system_thread_info;

typedef struct
{
    ULONG NextEntryOffset;
    DWORD dwThreadCount;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ProcessName;
    DWORD dwBasePriority;
    HANDLE UniqueProcessId;
    HANDLE ParentProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    /* VM_COUNTERS_EX (0x30) + IO_COUNTERS (0x30) precede the thread array.
     * Named rather than an opaque 0x60 blob since the kernel fills them:
     * the shapes are wine/include/winternl.h's VM_COUNTERS_EX and winnt.h's
     * IO_COUNTERS, and the compile-time check below is that the pair still
     * lands the thread array where the record's layout says (offset 0x100,
     * abi/ntpsapi.h's static_assert on the kernel side). */
    struct
    {
        SIZE_T PeakVirtualSize;
        SIZE_T VirtualSize;
        ULONG  PageFaultCount;
        SIZE_T PeakWorkingSetSize;
        SIZE_T WorkingSetSize;
        SIZE_T QuotaPeakPagedPoolUsage;
        SIZE_T QuotaPagedPoolUsage;
        SIZE_T QuotaPeakNonPagedPoolUsage;
        SIZE_T QuotaNonPagedPoolUsage;
        SIZE_T PagefileUsage;
        SIZE_T PeakPagefileUsage;
        SIZE_T PrivateUsage;
    } vmCounters;
    IO_COUNTERS ioCounters;
    ps_system_thread_info ti[1];
} ps_system_process_info;

_Static_assert(__builtin_offsetof(ps_system_process_info, ti) == 0x100,
               "SYSTEM_PROCESS_INFORMATION thread array offset (x64)");

/* mingw's winternl.h spells KERNEL_USER_TIMES' members FILETIME; declare the
 * named layout, byte-identical to wine/include/winternl.h. */
typedef struct
{
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
} ps_kernel_user_times;

/* mingw's winternl.h names PROCESS_BASIC_INFORMATION's parent field
 * "Reserved3"; declare the named layout, byte-identical to
 * wine/include/winternl.h PROCESS_BASIC_INFORMATION. */
typedef struct
{
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} ps_process_basic_information;

START_TEST(system_processes)
{
    NTSTATUS status;
    ULONG size = 0;

    /* A zero-length probe reports the needed size and never succeeds. */
    status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &size);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "empty probe -> %08lx", (unsigned long)status);
    ok(size != 0, "empty probe returned a zero needed-size");

    /* The kernel32 grow loop: start small, double on mismatch. */
    ULONG capacity = 4096;
    BYTE *buffer = NULL;
    for (;;)
    {
        buffer = (BYTE *)HeapAlloc(GetProcessHeap(), 0, capacity);
        ok(buffer != NULL, "HeapAlloc %lu", (unsigned long)capacity);
        size = 0;
        status = NtQuerySystemInformation(SystemProcessInformation, buffer, capacity, &size);
        if (status != STATUS_INFO_LENGTH_MISMATCH)
            break;
        HeapFree(GetProcessHeap(), 0, buffer);
        capacity *= 2;
        ok(capacity <= (64u << 20), "grow loop runaway");
    }
    ok(status == STATUS_SUCCESS, "filled query -> %08lx", (unsigned long)status);

    /* Walk the NextEntryOffset chain; find our own pid and sanity-check it. */
    DWORD selfPid = GetCurrentProcessId();
    int found = 0;
    int entries = 0;
    ULONG offset = 0;
    for (;;)
    {
        ps_system_process_info *entry = (ps_system_process_info *)(buffer + offset);
        entries++;
        ok((BYTE *)entry + sizeof(*entry) <= buffer + size, "entry %d overruns the buffer",
           entries);

        if ((DWORD)(ULONG_PTR)entry->UniqueProcessId == selfPid)
        {
            found = 1;
            ok(entry->dwThreadCount >= 1, "self reports %lu threads",
               (unsigned long)entry->dwThreadCount);
            /* ProcessName is a base name: non-empty, no path separator, and
             * Length is a byte count of the WCHARs (so even). */
            ok(entry->ProcessName.Length != 0, "self ProcessName is empty");
            ok((entry->ProcessName.Length & 1) == 0, "self ProcessName.Length %u is odd",
               entry->ProcessName.Length);
            if (entry->ProcessName.Buffer)
            {
                ULONG chars = entry->ProcessName.Length / sizeof(WCHAR);
                int hasSep = 0;
                for (ULONG i = 0; i < chars; i++)
                    if (entry->ProcessName.Buffer[i] == L'\\' ||
                        entry->ProcessName.Buffer[i] == L'/')
                        hasSep = 1;
                ok(!hasSep, "self ProcessName is a base name, not a path");
            }

            /* The row's ParentProcessId and ProcessBasicInformation's
             * InheritedFromUniqueProcessId are the same fact — the creator's
             * pid. No nonzero assertion here: a session-root process (each
             * oracle test is one) genuinely answers 0 on both sides. The
             * pinned nonzero contract is the spawned-child check after the
             * walk. */
            /* The row's TIMES and MEMORY are the same facts the per-process
             * classes answer, and the snapshot is where taskmgr's Processes
             * tab reads them — so a kernel that filled the record but left
             * these zero would satisfy every assertion above and still show
             * a machine where nothing has ever run.
             *
             * CreationTime is pinned by EQUALITY rather than by being
             * nonzero, which is the deterministic half: both readers take it
             * from one stamp (the oracle's is the server's start_time, for
             * ProcessTimes at dlls/ntdll/unix/process.c and for this record
             * at unix/system.c get_system_process_info), so they cannot
             * differ. The CPU times can only be compared as MONOTONIC — the
             * two queries are separated in time, and a process that has used
             * less than a tick legitimately reports zero on either. */
            ps_kernel_user_times times;
            status = NtQueryInformationProcess(NtCurrentProcess(), ProcessTimes, &times,
                                               sizeof(times), NULL);
            ok(status == STATUS_SUCCESS, "self ProcessTimes -> %08lx", (unsigned long)status);
            ok(entry->CreationTime.QuadPart == times.CreateTime.QuadPart,
               "row CreationTime %lld != ProcessTimes CreateTime %lld",
               (long long)entry->CreationTime.QuadPart, (long long)times.CreateTime.QuadPart);
            ok(entry->CreationTime.QuadPart != 0, "row CreationTime is zero");
            ok(entry->KernelTime.QuadPart + entry->UserTime.QuadPart <=
                   times.KernelTime.QuadPart + times.UserTime.QuadPart,
               "row CPU time %lld ran ahead of the later ProcessTimes %lld",
               (long long)(entry->KernelTime.QuadPart + entry->UserTime.QuadPart),
               (long long)(times.KernelTime.QuadPart + times.UserTime.QuadPart));

            /* A live process occupies memory; VirtualSize is the reservation
             * the working set sits inside, so it can never be the smaller of
             * the two. Nothing pins an amount — that is the machine's. */
            ok(entry->vmCounters.WorkingSetSize != 0, "row WorkingSetSize is zero");
            ok(entry->vmCounters.VirtualSize >= entry->vmCounters.WorkingSetSize,
               "row VirtualSize %lu < WorkingSetSize %lu",
               (unsigned long)entry->vmCounters.VirtualSize,
               (unsigned long)entry->vmCounters.WorkingSetSize);

            ps_process_basic_information pbi;
            status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessBasicInformation, &pbi,
                                               sizeof(pbi), NULL);
            ok(status == STATUS_SUCCESS, "self basic info -> %08lx", (unsigned long)status);
            ok((DWORD)(ULONG_PTR)entry->ParentProcessId == (DWORD)pbi.InheritedFromUniqueProcessId,
               "row parent %lu != basic-info parent %lu",
               (unsigned long)(ULONG_PTR)entry->ParentProcessId,
               (unsigned long)pbi.InheritedFromUniqueProcessId);
        }

        if (entry->NextEntryOffset == 0)
            break;
        /* Entries are 8-aligned and monotonically forward. */
        ok((entry->NextEntryOffset & 7) == 0, "NextEntryOffset %lu is unaligned",
           (unsigned long)entry->NextEntryOffset);
        offset += entry->NextEntryOffset;
        ok(offset < size, "chain walked past the buffer");
    }
    ok(found, "own pid %lu not present in the process list", (unsigned long)selfPid);
    ok(entries >= 1, "empty process list");

    HeapFree(GetProcessHeap(), 0, buffer);

    /* InheritedFromUniqueProcessId IS the creator's pid: spawn a SUSPENDED
     * child of this same .exe — it never executes an instruction, so no
     * child-side protocol — and read the field through the creation handle.
     * A kernel that leaves it zero silently kills every consumer that finds
     * a process's parent by pid (wineserver-lite's connect-time desktop
     * inheritance at GUI-6 was exactly that: matched nothing, quietly fell
     * back, and every GUI child self-created its desktop). */
    WCHAR self[MAX_PATH];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    ok(GetModuleFileNameW(NULL, self, MAX_PATH) != 0, "GetModuleFileNameW failed %lu",
       (unsigned long)GetLastError());
    BOOL created =
        CreateProcessW(self, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    ok(created, "CreateProcessW(suspended self) failed %lu", (unsigned long)GetLastError());
    if (created)
    {
        ps_process_basic_information childInfo;
        status = NtQueryInformationProcess(pi.hProcess, PS_ProcessBasicInformation, &childInfo,
                                           sizeof(childInfo), NULL);
        ok(status == STATUS_SUCCESS, "child basic info -> %08lx", (unsigned long)status);
        ok((DWORD)childInfo.InheritedFromUniqueProcessId == selfPid,
           "child's parent is %lu, expected us (%lu)",
           (unsigned long)childInfo.InheritedFromUniqueProcessId, (unsigned long)selfPid);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    /* ProcessSessionInformation: the exact-ULONG session-id read
     * ProcessIdToSessionId issues (dlls/kernelbase/process.c); tasklist hits
     * it per row. */
    DWORD sessionId = 0xdeadbeef;
    ULONG retLen = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessSessionInformation, &sessionId,
                                       sizeof(sessionId), &retLen);
    ok(status == STATUS_SUCCESS, "ProcessSessionInformation -> %08lx", (unsigned long)status);
    ok(retLen == sizeof(sessionId), "ProcessSessionInformation returned %lu bytes",
       (unsigned long)retLen);
}
