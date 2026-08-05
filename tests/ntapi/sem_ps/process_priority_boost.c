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

    /* Put it back, so a rerun starts where this one did. */
    disableBoost = 0;
    (void)NtSetInformationProcess(self, ProcessPriorityBoost, &disableBoost, sizeof(disableBoost));
}
