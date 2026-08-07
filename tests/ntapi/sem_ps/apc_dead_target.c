/*
 * sem_ps/apc_dead_target.c — what NtQueueApcThread does when it CANNOT
 * deliver: a terminated target, and a NULL routine.
 *
 * Two rules, both from one function in the pinned server
 * (third_party/wine server/thread.c, static queue_apc), in the order it
 * applies them:
 *
 *   1. `if (thread->state == TERMINATED) return 0;` — and the caller,
 *      DECL_HANDLER(queue_apc), turns that 0 into STATUS_UNSUCCESSFUL.
 *      A queue request at a dead thread FAILS. It does not quietly
 *      succeed having thrown the APC away.
 *
 *   2. `if (!(queue = get_apc_queue( thread, apc->call.type ))) return 1;`
 *      — get_apc_queue has no queue for APC_NONE, which is the type the
 *      client sends when the routine is NULL (dlls/ntdll/unix/thread.c
 *      NtQueueApcThreadEx2 adds the call data only `if (func)`). So a NULL
 *      routine SUCCEEDS and does nothing at all: nothing stored, nothing
 *      woken, no alertable wait disturbed.
 *
 * The two interact, which is why they are pinned together: rule 1 is
 * checked BEFORE rule 2, so a NULL routine aimed at a dead thread still
 * fails. A kernel that returns early on a NULL routine gets that backwards
 * and nothing else in the suite notices.
 *
 * Convicted by kernel32:sync's test_QueueUserAPC (sync.c:3040 and :3042 on
 * the status after TerminateThread, :3048/:3049 on the ERROR_GEN_FAILURE
 * kernelbase maps STATUS_UNSUCCESSFUL to, and :3062-:3064 on the NULL
 * routine NOT turning the following SleepEx into a WAIT_IO_COMPLETION).
 * proskrnl answered STATUS_SUCCESS to every one of them: the APC was
 * dropped for a dead target with no way for the caller to find out.
 *
 * Oracle-first (G5).
 */
#include "util.h"

typedef VOID(NTAPI *ps_apcfunc)(ULONG_PTR, ULONG_PTR, ULONG_PTR);
NTSYSAPI NTSTATUS NTAPI NtQueueApcThread(HANDLE, ps_apcfunc, ULONG_PTR, ULONG_PTR, ULONG_PTR);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

#ifndef NtCurrentThread
#define NtCurrentThread() ((HANDLE) ~(ULONG_PTR)1)
#endif

static volatile LONG apc_calls;

static VOID NTAPI count_apc(ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3)
{
    (void)a1;
    (void)a2;
    (void)a3;
    InterlockedIncrement(&apc_calls);
}

static DWORD WINAPI park_forever(LPVOID unused)
{
    (void)unused;
    for (;;)
    {
        Sleep(10000);
    }
}

START_TEST(apc_dead_target)
{
    NTSTATUS status;
    HANDLE thread;
    DWORD tid = 0, waited;

    /* --- a TERMINATED target refuses ------------------------------------
     * Created suspended and killed without ever running, exactly as
     * kernel32:sync does it, so there is no window in which the thread is
     * alive and the queue would legitimately succeed. */
    thread = CreateThread(NULL, 0, park_forever, NULL, CREATE_SUSPENDED, &tid);
    ok(thread != NULL, "CreateThread -> %lu", (unsigned long)GetLastError());
    if (thread == NULL)
    {
        return;
    }
    ok(TerminateThread(thread, 0xdeadbeef) != 0, "TerminateThread -> %lu",
       (unsigned long)GetLastError());
    waited = WaitForSingleObject(thread, 5000);
    ok(waited == WAIT_OBJECT_0, "wait for the terminated thread -> %lu", (unsigned long)waited);

    status = NtQueueApcThread(thread, count_apc, 0, 0, 0);
    ok(status == STATUS_UNSUCCESSFUL, "queue an APC at a terminated thread -> %08lx",
       (unsigned long)status);

    /* Rule 1 before rule 2: the NULL routine does not get to the "accept
     * and drop" arm, because the target is already gone. */
    status = NtQueueApcThread(thread, NULL, 0, 0, 0);
    ok(status == STATUS_UNSUCCESSFUL, "queue a NULL APC at a terminated thread -> %08lx",
       (unsigned long)status);

    /* The refusal is about the thread's STATE, not about the handle — an
     * invalid handle still reads as an invalid handle, and a kernel that
     * collapsed the two would pass everything above. */
    status = NtQueueApcThread((HANDLE)(ULONG_PTR)0xdeadbeef, count_apc, 0, 0, 0);
    ok(status == STATUS_INVALID_HANDLE, "queue an APC at a bad handle -> %08lx",
       (unsigned long)status);

    NtClose(thread);

    /* --- a NULL routine on a LIVE target succeeds and does nothing ------ */
    apc_calls = 0;
    status = NtQueueApcThread(NtCurrentThread(), NULL, 0, 0, 0);
    ok(status == STATUS_SUCCESS, "queue a NULL APC at the current thread -> %08lx",
       (unsigned long)status);

    /* Nothing was queued, so an alertable wait is NOT interrupted: it runs
     * its timeout out and ends normally, never with STATUS_USER_APC. This
     * is the assertion that separates "accepted and dropped" from "accepted
     * and delivered as an empty APC" — the second would end the wait early
     * with STATUS_USER_APC and turn kernel32:sync's SleepEx into a
     * WAIT_IO_COMPLETION.
     *
     * The expected status is STATUS_SUCCESS, not STATUS_TIMEOUT: an expired
     * delay is a SUCCESS at this entry point. NtDelayExecution folds the
     * two in so many words —
     *
     *     if ((status = server_wait( ... )) == STATUS_TIMEOUT)
     *         status = STATUS_SUCCESS;
     *     (third_party/wine dlls/ntdll/unix/sync.c)
     *
     * — which is what makes SleepEx's `WAIT_OBJECT_0` reachable at all,
     * since SleepEx returns WAIT_IO_COMPLETION only for STATUS_USER_APC and
     * 0 for everything else. */
    {
        LARGE_INTEGER delay;
        delay.QuadPart = -100000; /* 10 ms, relative */
        status = NtDelayExecution(TRUE, &delay);
        ok(status == STATUS_SUCCESS, "alertable delay after a NULL APC -> %08lx",
           (unsigned long)status);
        ok(apc_calls == 0, "a NULL APC ran something: %ld", (long)apc_calls);
    }

    /* And a REAL APC still arrives at the same alertable point — the
     * assertion that keeps the fix from being "drop everything". */
    {
        LARGE_INTEGER delay;
        apc_calls = 0;
        status = NtQueueApcThread(NtCurrentThread(), count_apc, 0, 0, 0);
        ok(status == STATUS_SUCCESS, "queue a real APC at the current thread -> %08lx",
           (unsigned long)status);
        ok(apc_calls == 0, "the APC ran before an alertable point: %ld", (long)apc_calls);
        delay.QuadPart = -100000;
        status = NtDelayExecution(TRUE, &delay);
        ok(status == STATUS_USER_APC, "alertable delay after a real APC -> %08lx",
           (unsigned long)status);
        ok(apc_calls == 1, "the APC ran %ld times, wanted 1", (long)apc_calls);
    }
}
