/*
 * sem_wait/pseudo_handle_multi.c — pseudo-handles are legal in a
 * single-object wait and ILLEGAL in a multiple-object one.
 *
 * Convicted by the winetest gate, and it costs more than its assertions:
 * kernel32:sync reaches this check, proskrnl WAITS instead of refusing, the
 * test then enters a wait that never completes, and the pair burns its full
 * 300-second timeout on every sweep.
 *
 * The asymmetry is the contract, and kernel32:sync states it in its own
 * comment (sync.c:1483): "in contrast to WaitForSingleObject, all
 * pseudo-handles are not allowed in WaitForMultipleObjects and
 * NtWaitForMultipleObjects". So this is not "pseudo-handles do not work" —
 * NtWaitForSingleObject resolves them, and a kernel that rejected them
 * everywhere would fail the first half of this test.
 *
 * WHY IT REGRESSED HERE. proskrnl only recently taught
 * ObReferenceObjectByHandle to resolve -1 and -2 (the fix that unblocked
 * kernel32:thread). That made the single-object form work — and silently
 * made the multiple-object form WAIT on a process or thread object instead
 * of refusing. A capability added in one place changed behaviour in
 * another, which is the whole reason this file exists as a separate pin.
 *
 * Oracle-first (G5).
 */
#include "../ntapi.h"

NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtWaitForMultipleObjects(ULONG, const HANDLE *, ULONG, BOOLEAN,
                                                 PLARGE_INTEGER);

/* The two pseudo-handles, spelled here because mingw's headers define them
 * as macros only for the Win32 spellings. Values are NT's (-1 current
 * process, -2 current thread), cited to Microsoft's NtCurrentProcess /
 * NtCurrentThread documentation. */
#define PRS_CURRENT_PROCESS ((HANDLE)(LONG_PTR)-1)
#define PRS_CURRENT_THREAD  ((HANDLE)(LONG_PTR)-2)

START_TEST(pseudo_handle_multi)
{
    NTSTATUS status;
    LARGE_INTEGER zero;
    HANDLE handles[1];

    zero.QuadPart = 0; /* poll: never block, whatever the answer */

    /* --- the single-object form ACCEPTS them ----------------------------- */
    status = NtWaitForSingleObject(PRS_CURRENT_PROCESS, FALSE, &zero);
    ok(status == STATUS_TIMEOUT, "single wait on the current process -> %08lx",
       (unsigned long)status);
    status = NtWaitForSingleObject(PRS_CURRENT_THREAD, FALSE, &zero);
    ok(status == STATUS_TIMEOUT, "single wait on the current thread -> %08lx",
       (unsigned long)status);

    /* --- and the multiple-object form REFUSES them ----------------------
     * STATUS_INVALID_HANDLE, and immediately: the timeout above is zero, so
     * a kernel that waited would still return here, but with STATUS_TIMEOUT
     * instead — which is exactly the wrong answer proskrnl gave, and the
     * one that sends kernel32:sync into a wait it never leaves. */
    handles[0] = PRS_CURRENT_PROCESS;
    status = NtWaitForMultipleObjects(1, handles, 0 /* WaitAll */, FALSE, &zero);
    ok(status == STATUS_INVALID_HANDLE, "multi wait on the current process -> %08lx",
       (unsigned long)status);

    handles[0] = PRS_CURRENT_THREAD;
    status = NtWaitForMultipleObjects(1, handles, 0, FALSE, &zero);
    ok(status == STATUS_INVALID_HANDLE, "multi wait on the current thread -> %08lx",
       (unsigned long)status);

    /* WaitAny takes the same answer: the refusal is about the HANDLE, not
     * about the wait mode. */
    handles[0] = PRS_CURRENT_PROCESS;
    status = NtWaitForMultipleObjects(1, handles, 1 /* WaitAny */, FALSE, &zero);
    ok(status == STATUS_INVALID_HANDLE, "multi WaitAny on the current process -> %08lx",
       (unsigned long)status);

    /* --- a REAL handle still works in the multiple-object form ----------
     * The assertion that keeps the fix from being "reject everything". */
    {
        HANDLE event = NULL;
        status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
        ok(status == STATUS_SUCCESS, "create an event -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            handles[0] = event;
            status = NtWaitForMultipleObjects(1, handles, 1, FALSE, &zero);
            ok(status == STATUS_TIMEOUT, "multi wait on a real event -> %08lx",
               (unsigned long)status);
            NtClose(event);
        }
    }
}
