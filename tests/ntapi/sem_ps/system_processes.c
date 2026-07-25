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
    /* VM_COUNTERS_EX (0x30) + IO_COUNTERS (0x30) precede the thread array;
     * we only reach the header fields above, and the array via ti offset. */
    BYTE vmAndIo[0x60];
    ps_system_thread_info ti[1];
} ps_system_process_info;

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
