/*
 * sem_ps/thread_info_sweep.c — the thread info classes a suite SWEEPS.
 *
 * W2a of docs/21. `dlls/kernel32/tests/thread.c` test_thread_info walks
 * every THREADINFOCLASS from 0 upward and tolerates a refusal:
 *
 *     status = pNtQueryInformationThread( thread, i, buf, info_size[i], &ret_len );
 *     if (status == STATUS_NOT_IMPLEMENTED)   continue;
 *     if (status == STATUS_INVALID_INFO_CLASS) continue;
 *     if (status == STATUS_UNSUCCESSFUL)       continue;
 *
 * proskrnl cannot answer the first of those three to anything — the armed
 * boot makes it a panic (Art. 12) — so every class in the sweep has to
 * answer either its value or one of the other two. That is the whole item.
 *
 * Two groups, and they are pinned differently:
 *
 *   ThreadHideFromDebugger is a REAL per-thread flag the oracle implements
 *   (dlls/ntdll/unix/thread.c), so it is pinned normally, including the
 *   documented ordering quirk its own comment describes: the class touches
 *   *ret_len BEFORE any other check, so an unwritable ret_len is
 *   STATUS_ACCESS_VIOLATION even when the length is also wrong. "TP Shell
 *   Service depends on" it, per that comment — it is observable, so it is
 *   the contract.
 *
 *   ThreadPriority, ThreadBasePriority, ThreadImpersonationToken,
 *   ThreadEventPair_Reusable, ThreadZeroTlsCell, ThreadPerformanceCount and
 *   ThreadSetTlsArrayAddress are the set-only/obsolete group the oracle
 *   REFUSES (they share its `FIXME(...); return STATUS_NOT_IMPLEMENTED;`
 *   arm). An oracle answering NOT_IMPLEMENTED is unbuilt, not authoritative
 *   (G12), so those go in a beyond_oracle block: proskrnl answers
 *   STATUS_INVALID_INFO_CLASS, which is what a non-queryable class is, and
 *   which the sweep above accepts by name.
 */
#include "../ntapi.h"

/* THREADINFOCLASS values mingw's winternl.h omits, spelled exactly as the
 * pinned tree spells them (third_party/wine/include/winternl.h, the
 * _THREADINFOCLASS enum) — the same convention sem_port/timers.c uses for
 * TIMER_TYPE. In proskrnl mode abi/ntpsapi.h already defines them, so these
 * only fill the oracle build's gap. */
#ifndef ThreadEventPair_Reusable
#define ThreadEventPair_Reusable  ((THREADINFOCLASS)8)
#endif
#ifndef ThreadZeroTlsCell
#define ThreadZeroTlsCell         ((THREADINFOCLASS)10)
#endif
#ifndef ThreadPerformanceCount
#define ThreadPerformanceCount    ((THREADINFOCLASS)11)
#endif
#ifndef ThreadSetTlsArrayAddress
#define ThreadSetTlsArrayAddress  ((THREADINFOCLASS)15)
#endif
#ifndef ThreadHideFromDebugger
#define ThreadHideFromDebugger    ((THREADINFOCLASS)17)
#endif

/* The set-only / obsolete group: queried, never queryable. */
static const struct
{
    THREADINFOCLASS cls;
    const char *name;
} refused[] = {
    {ThreadPriority, "ThreadPriority"},
    {ThreadBasePriority, "ThreadBasePriority"},
    {ThreadImpersonationToken, "ThreadImpersonationToken"},
    {ThreadEventPair_Reusable, "ThreadEventPair_Reusable"},
    {ThreadZeroTlsCell, "ThreadZeroTlsCell"},
    {ThreadPerformanceCount, "ThreadPerformanceCount"},
    {ThreadSetTlsArrayAddress, "ThreadSetTlsArrayAddress"},
};

START_TEST(thread_info_sweep)
{
    NTSTATUS status;
    ULONG returnLength;
    BOOLEAN hidden;
    HANDLE self = (HANDLE)(LONG_PTR)-2; /* NtCurrentThread */

    /* --- ThreadHideFromDebugger: a real flag, and it starts clear -------- */
    returnLength = 0;
    hidden = TRUE;
    status = NtQueryInformationThread(self, ThreadHideFromDebugger, &hidden, sizeof(hidden),
                                      &returnLength);
    ok(status == STATUS_SUCCESS, "query hide-from-debugger -> %08lx", (unsigned long)status);
    ok(hidden == FALSE, "thread starts hidden");
    ok(returnLength == sizeof(BOOLEAN), "returned %lu bytes", (unsigned long)returnLength);

    /* A wrong length is a length complaint. */
    status = NtQueryInformationThread(self, ThreadHideFromDebugger, &hidden, sizeof(hidden) + 1,
                                      &returnLength);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "wrong length -> %08lx", (unsigned long)status);

    /* ...but an unwritable ret_len beats it, because the class touches
     * ret_len first. Both wrong at once: ACCESS_VIOLATION wins. */
    status = NtQueryInformationThread(self, ThreadHideFromDebugger, &hidden, sizeof(hidden) + 1,
                                      (PULONG)(ULONG_PTR)4);
    ok(status == STATUS_ACCESS_VIOLATION, "unwritable ret_len -> %08lx", (unsigned long)status);

    /* --- setting it takes a ZERO length, and the query sees it ----------- */
    status = NtSetInformationThread(self, ThreadHideFromDebugger, NULL, 0);
    ok(status == STATUS_SUCCESS, "set hide-from-debugger -> %08lx", (unsigned long)status);
    hidden = FALSE;
    status = NtQueryInformationThread(self, ThreadHideFromDebugger, &hidden, sizeof(hidden),
                                      &returnLength);
    ok(status == STATUS_SUCCESS, "re-query -> %08lx", (unsigned long)status);
    ok(hidden == TRUE, "flag did not stick");

    /* A non-zero length on the SET side is a length complaint. */
    status = NtSetInformationThread(self, ThreadHideFromDebugger, &hidden, sizeof(hidden));
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "set with length -> %08lx", (unsigned long)status);

    /* --- the set-only group refuses, and NOT with NOT_IMPLEMENTED -------- */
    beyond_oracle
    {
        for (unsigned i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
        {
            UCHAR buffer[32];
            returnLength = 0;
            status = NtQueryInformationThread(self, refused[i].cls, buffer, sizeof(buffer),
                                              &returnLength);
            ok(status == STATUS_INVALID_INFO_CLASS, "%s query -> %08lx", refused[i].name,
               (unsigned long)status);
        }
    }
}
