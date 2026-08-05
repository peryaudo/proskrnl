/*
 * sem_ps/process_priority_boost.c — ProcessPriorityBoost round-trips, and
 * the two directions reject a bad size DIFFERENTLY.
 *
 * W2 of docs/21: the class kernel32:thread's sweep reaches once the thread
 * classes stop refusing. proskrnl boosts no priorities at all (docs/03
 * "Deliberate simplifications"), so nothing acts on this flag — but a query
 * that ignored the set would make the class disagree with itself, which is
 * the silent-plausible answer G12 forbids.
 *
 * The detail worth pinning is the asymmetry, because it is exactly what an
 * implementation written from the documentation rather than from the oracle
 * flattens into one status (dlls/ntdll/unix/process.c):
 *
 *   QUERY: `if (size != len) return STATUS_INFO_LENGTH_MISMATCH;`
 *          `if (!info) ret = STATUS_ACCESS_VIOLATION;`
 *   SET:   `if (size != sizeof(ULONG)) return STATUS_INVALID_PARAMETER;`
 *
 * Oracle-first (G5).
 */
#include "../ntapi.h"

NTSYSAPI NTSTATUS NTAPI NtQueryInformationThread(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtSetInformationThread(HANDLE, THREADINFOCLASS, PVOID, ULONG);

START_TEST(process_priority_boost)
{
    NTSTATUS status;
    ULONG returnLength;
    ULONG disableBoost;
    HANDLE self = (HANDLE)(LONG_PTR)-1; /* NtCurrentProcess */

    /* --- it starts enabled (the disable flag clear) ---------------------- */
    disableBoost = 0xdead;
    returnLength = 0;
    status = NtQueryInformationProcess(self, ProcessPriorityBoost, &disableBoost,
                                       sizeof(disableBoost), &returnLength);
    ok(status == STATUS_SUCCESS, "query boost -> %08lx", (unsigned long)status);
    ok(returnLength == sizeof(ULONG), "query returned %lu bytes", (unsigned long)returnLength);
    ok(disableBoost == 0, "boost starts disabled (%lu)", (unsigned long)disableBoost);

    /* --- and it round-trips ---------------------------------------------- */
    disableBoost = 1;
    status =
        NtSetInformationProcess(self, ProcessPriorityBoost, &disableBoost, sizeof(disableBoost));
    ok(status == STATUS_SUCCESS, "set boost -> %08lx", (unsigned long)status);

    disableBoost = 0xdead;
    status = NtQueryInformationProcess(self, ProcessPriorityBoost, &disableBoost,
                                       sizeof(disableBoost), &returnLength);
    ok(status == STATUS_SUCCESS, "re-query boost -> %08lx", (unsigned long)status);
    ok(disableBoost == 1, "boost flag did not stick (%lu)", (unsigned long)disableBoost);

    /* --- the asymmetry: a bad size costs each direction a different status */
    status = NtQueryInformationProcess(self, ProcessPriorityBoost, &disableBoost, 1, &returnLength);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short query -> %08lx", (unsigned long)status);

    status = NtSetInformationProcess(self, ProcessPriorityBoost, &disableBoost, 1);
    ok(status == STATUS_INVALID_PARAMETER, "short set -> %08lx", (unsigned long)status);

    /* --- a NULL buffer on the query is an ACCESS VIOLATION ---------------- */
    status =
        NtQueryInformationProcess(self, ProcessPriorityBoost, NULL, sizeof(ULONG), &returnLength);
    ok(status == STATUS_ACCESS_VIOLATION, "NULL query buffer -> %08lx", (unsigned long)status);

    /* --- the process flag is COPIED INTO the threads, not consulted by
     * them -----------------------------------------------------------------
     * This is the distinction, and it is the one an implementation reaches
     * for the wrong answer on. Both readings agree that a process-wide
     * disable shows up on the thread; they disagree about what a
     * thread-level set does AFTERWARDS. The oracle's server settles it
     * (third_party/wine server/process.c set_process_disable_boost): the
     * process value is ASSIGNED to every thread on its thread_list, so a
     * later thread set overrides it and the process keeps its own value. A
     * query-time OR of the two flags could never report that state, and
     * kernel32:thread thread.c:806-812 asserts precisely it. */
    {
        ULONG threadDisabled;
        ULONG on = 1, off = 0;
        HANDLE selfThread = (HANDLE)(LONG_PTR)-2;

        status = NtSetInformationProcess(self, ProcessPriorityBoost, &on, sizeof(on));
        ok(status == STATUS_SUCCESS, "disable boost process-wide -> %08lx", (unsigned long)status);

        threadDisabled = 0xdead;
        status = NtQueryInformationThread(selfThread, ThreadPriorityBoost, &threadDisabled,
                                          sizeof(threadDisabled), &returnLength);
        ok(status == STATUS_SUCCESS, "thread boost query -> %08lx", (unsigned long)status);
        ok(threadDisabled == 1, "process disable did not reach the thread (%lu)",
           (unsigned long)threadDisabled);

        /* Now the half that separates copy from lookup. */
        status = NtSetInformationThread(selfThread, ThreadPriorityBoost, &off, sizeof(off));
        ok(status == STATUS_SUCCESS, "re-enable boost on the thread -> %08lx",
           (unsigned long)status);

        threadDisabled = 0xdead;
        status = NtQueryInformationThread(selfThread, ThreadPriorityBoost, &threadDisabled,
                                          sizeof(threadDisabled), &returnLength);
        ok(status == STATUS_SUCCESS, "thread boost re-query -> %08lx", (unsigned long)status);
        ok(threadDisabled == 0, "the thread set did not override the process (%lu)",
           (unsigned long)threadDisabled);

        /* ...while the PROCESS still reads what the process set. */
        disableBoost = 0xdead;
        status = NtQueryInformationProcess(self, ProcessPriorityBoost, &disableBoost,
                                           sizeof(disableBoost), &returnLength);
        ok(status == STATUS_SUCCESS, "process boost re-query -> %08lx", (unsigned long)status);
        ok(disableBoost == 1, "the thread set leaked back into the process (%lu)",
           (unsigned long)disableBoost);

        status = NtSetInformationProcess(self, ProcessPriorityBoost, &off, sizeof(off));
        ok(status == STATUS_SUCCESS, "re-enable boost -> %08lx", (unsigned long)status);
    }

    /* --- ProcessAffinityMask: one CPU, one bit ---------------------------
     * The same fact ThreadAffinityMask reports, and true rather than
     * approximate because Art. 3 mandates uniprocessor. Exact length here,
     * unlike the thread class, which truncates. */
    {
        ULONG_PTR affinity = 0;
        returnLength = 0;
        status = NtQueryInformationProcess(self, ProcessAffinityMask, &affinity, sizeof(affinity),
                                           &returnLength);
        ok(status == STATUS_SUCCESS, "ProcessAffinityMask -> %08lx", (unsigned long)status);
        ok(affinity != 0, "process affinity mask is empty");
        ok(returnLength == sizeof(affinity), "affinity returned %lu bytes",
           (unsigned long)returnLength);

        status = NtQueryInformationProcess(self, ProcessAffinityMask, &affinity, 1, &returnLength);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "short affinity -> %08lx", (unsigned long)status);
    }

    /* Put it back, so a rerun starts where this one did. */
    disableBoost = 0;
    (void)NtSetInformationProcess(self, ProcessPriorityBoost, &disableBoost, sizeof(disableBoost));
}
