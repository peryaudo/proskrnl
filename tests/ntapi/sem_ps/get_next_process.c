/*
 * sem_ps/get_next_process.c — NtGetNextProcess.
 *
 * The process-enumeration primitive (a handle-returning walk, unlike the
 * SystemProcessInformation snapshot). Contract from wineserver's
 * get_next_process (server/process.c): flags > 1 -> STATUS_INVALID_PARAMETER;
 * last = 0 starts at the head (flags 0) or tail (flags 1); each step is a
 * fresh handle to the next process, skipping any the caller cannot open; the
 * walk ends with STATUS_NO_MORE_ENTRIES. Green on the pinned Wine oracle
 * first (Art. 5).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtGetNextProcess(HANDLE, ACCESS_MASK, ULONG, ULONG, HANDLE *);

START_TEST(get_next_process)
{
    NTSTATUS status;
    HANDLE next;

    /* Only forward (0) and backward (1) walks exist. */
    next = (HANDLE)(ULONG_PTR)0xdead;
    status = NtGetNextProcess(NULL, PROCESS_QUERY_INFORMATION, 0, 2, &next);
    ok(status == STATUS_INVALID_PARAMETER, "flags 2 -> %08lx", (unsigned long)status);

    /* Forward walk: at least our own process, each step a fresh handle whose
     * query names a real pid, then NO_MORE_ENTRIES. Our own pid must appear. */
    DWORD selfPid = GetCurrentProcessId();
    HANDLE last = NULL;
    int count = 0;
    int foundSelf = 0;
    for (;;)
    {
        next = NULL;
        status = NtGetNextProcess(last, PROCESS_QUERY_INFORMATION, 0, 0, &next);
        if (last)
            NtClose(last);
        if (status != STATUS_SUCCESS || count >= 256)
            break;
        ok(next != NULL, "walk step %d returned a null handle", count);
        count++;

        PROCESS_BASIC_INFORMATION pbi;
        memset(&pbi, 0, sizeof(pbi));
        ULONG retLen = 0;
        if (NtQueryInformationProcess(next, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen) ==
            STATUS_SUCCESS)
        {
            if ((DWORD)(ULONG_PTR)pbi.UniqueProcessId == selfPid)
                foundSelf = 1;
        }
        last = next;
    }
    ok(status == STATUS_NO_MORE_ENTRIES, "walk end -> %08lx", (unsigned long)status);
    ok(count >= 1, "no processes enumerated");
    ok(foundSelf, "own pid %lu not found in the walk", (unsigned long)selfPid);
}
