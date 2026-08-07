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

/* The pseudo-handles, spelled here because mingw's headers define them as
 * macros only for the Win32 spellings. Values are NT's, cited to
 * Microsoft's NtCurrentProcess / NtCurrentThread documentation and to
 * GetCurrentProcessToken / GetCurrentThreadToken /
 * GetCurrentThreadEffectiveToken, whose documented return values are
 * (HANDLE)-4, (HANDLE)-5 and (HANDLE)-6. -3 is documented by nothing and is
 * named here only because it lies inside the range the boundary refuses. */
#define PRS_CURRENT_PROCESS        ((HANDLE)(LONG_PTR) - 1)
#define PRS_CURRENT_THREAD         ((HANDLE)(LONG_PTR) - 2)
#define PRS_UNASSIGNED             ((HANDLE)(LONG_PTR) - 3)
#define PRS_PROCESS_TOKEN          ((HANDLE)(LONG_PTR) - 4)
#define PRS_THREAD_TOKEN           ((HANDLE)(LONG_PTR) - 5)
#define PRS_THREAD_EFFECTIVE_TOKEN ((HANDLE)(LONG_PTR) - 6)

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

    /* --- and the refusal covers the WHOLE pseudo-handle range -----------
     * Not just -1 and -2. The oracle's own predicate is one comparison —
     * `(ULONG)(ULONG_PTR)handle >= 0xfffffffa` (third_party/wine
     * dlls/ntdll/unix/sync.c, is_pseudo_handle), applied in
     * NtWaitForMultipleObjects before anything else — so the range is
     * -1 .. -6 and every value in it answers STATUS_INVALID_HANDLE.
     *
     * The three token values are what make this worth its own block. A
     * kernel that special-cases only the process/thread pair RESOLVES -4
     * and -6 to the caller's token, finds a non-waitable object, and
     * answers STATUS_OBJECT_TYPE_MISMATCH — a plausible status for a wrong
     * reason, and one no caller can distinguish from a real type error.
     * kernel32:sync asserts the range at sync.c:1496/:1511/:1513/:1530/
     * :1532, two of the six failing at each, which is exactly those two.
     *
     * -5 (the thread token) reaches the same answer by a different route
     * whenever nothing is impersonating: there is no such token to resolve.
     * It is listed anyway — the point is that the ANSWER does not depend on
     * which route, and a later impersonation change must not move it. */
    {
        static const struct
        {
            HANDLE handle;
            const char *name;
        } pseudoHandles[] = {
            {PRS_CURRENT_PROCESS, "the current process (-1)"},
            {PRS_CURRENT_THREAD, "the current thread (-2)"},
            {PRS_UNASSIGNED, "the unassigned value (-3)"},
            {PRS_PROCESS_TOKEN, "the process token (-4)"},
            {PRS_THREAD_TOKEN, "the thread token (-5)"},
            {PRS_THREAD_EFFECTIVE_TOKEN, "the effective token (-6)"},
        };
        unsigned int i;

        for (i = 0; i < sizeof(pseudoHandles) / sizeof(pseudoHandles[0]); i++)
        {
            handles[0] = pseudoHandles[i].handle;
            status = NtWaitForMultipleObjects(1, handles, 1 /* WaitAny */, FALSE, &zero);
            ok(status == STATUS_INVALID_HANDLE, "multi WaitAny on %s -> %08lx",
               pseudoHandles[i].name, (unsigned long)status);
            status = NtWaitForMultipleObjects(1, handles, 0 /* WaitAll */, FALSE, &zero);
            ok(status == STATUS_INVALID_HANDLE, "multi WaitAll on %s -> %08lx",
               pseudoHandles[i].name, (unsigned long)status);
        }
    }

    /* The refusal is about the handle wherever it sits in the array, not
     * about being first — kernel32:sync moves it to the last index and
     * repeats every assertion (sync.c:1516-:1534). A kernel that checked
     * only handles[0] would pass everything above and still fail there. */
    {
        HANDLE event = NULL;
        HANDLE pair[2];
        status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
        ok(status == STATUS_SUCCESS, "create an event -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            pair[0] = event;
            pair[1] = PRS_PROCESS_TOKEN;
            status = NtWaitForMultipleObjects(2, pair, 1, FALSE, &zero);
            ok(status == STATUS_INVALID_HANDLE, "multi wait with a pseudo-handle last -> %08lx",
               (unsigned long)status);
            NtClose(event);
        }
    }

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
