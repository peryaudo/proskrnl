/* kernel/ke/apc.c — user-mode APC queues and alerts (M7).
 *
 * docs/05 makes the APC *mechanism and delivery timing* the forced (NT-shaped)
 * part of Ke: a user APC queued to a thread runs KiUserApcDispatcher in ring 3
 * the next time the thread reaches an alertable wait, NtTestAlert, or a
 * NtContinue that re-tests alerts — never at an arbitrary point. What proskrnl
 * does NOT build is the kernel-mode / special-APC machinery and IRQL-gated
 * delivery: nothing observes those (docs/03, Art. 3). Under the one dispatcher
 * lock (uniprocessor, no preemption) the queue is a plain list touched only
 * from thread context, so this is a small state machine.
 *
 * The actual ring-3 frame construction lives in kernel/ps/usermode.c
 * (KiDeliverUserApc); this file owns the queue and the wake.
 */
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h"
#include "kernel/init/panic.h"
#include "kernel/mm/pool.h"

/* THE release path for a user-APC block (ke.h states the contract). A block
 * that came out of a UserApcReserve goes back to it — which is also how the
 * reserve becomes queueable again, so "one APC at a time" is a consequence of
 * where the storage lives rather than a rule anybody enforces. The pinned
 * server releases the association from the same place, apc_destroy
 * (server/thread.c), for the same reason: every way an APC ends passes
 * through the block's own teardown. */
void KiFreeUserApc(PKAPC apc)
{
    if (apc == 0)
    {
        return;
    }
    if (apc->reserveObject != 0)
    {
        ObpReleaseApcReserve(apc);
        return;
    }
    MiFreePool(apc);
}

BOOLEAN KiInsertQueueUserApc(PKTHREAD thread, PKAPC apc)
{
    uint64_t flags = KiAcquireDispatcherLock();
    if (thread->state == KI_THREAD_STATE_TERMINATED)
    {
        /* A terminated thread will never reach an alertable point, so the
         * APC can only sit on the list forever -- and the queue is
         * unbounded, so looping NtQueueApcThread at an exited thread leaked
         * pool without limit (docs/review-2026-07 §7). Dropping it here is
         * observably identical (it was never going to run) and costs
         * nothing.
         *
         * It is not, however, SILENT. The pinned server refuses the queue
         * outright for a terminated target — `if (thread->state ==
         * TERMINATED) return 0;` in server/thread.c queue_apc, whose caller
         * turns the 0 into STATUS_UNSUCCESSFUL — and kernel32:sync asserts
         * exactly that after TerminateThread (sync.c:3040/:3042), plus the
         * ERROR_GEN_FAILURE kernelbase maps it to (:3048/:3049). Answering
         * STATUS_SUCCESS for an APC that was thrown away is the plausible
         * lie G12 exists to forbid, so the drop is reported. */
        KiReleaseDispatcherLock(flags);
        KiFreeUserApc(apc);
        return FALSE;
    }
    if (apc == 0)
    {
        /* The server's APC_NONE: a queue request carrying no routine is
         * ACCEPTED and then discarded, because get_apc_queue() has no queue
         * for that type and queue_apc returns 1 before reaching the list
         * (server/thread.c). Nothing is stored and nothing is woken — which
         * is why kernel32:sync's SleepEx(100, TRUE) after one of these
         * sleeps its full 100 ms and returns WAIT_OBJECT_0 rather than
         * WAIT_IO_COMPLETION (sync.c:3062-:3064). The terminated check
         * above still applies to it, and in that order. */
        KiReleaseDispatcherLock(flags);
        return TRUE;
    }
    InsertTailList(&thread->userApcListHead, &apc->apcListEntry);
    thread->userApcPending = TRUE;

    /* If the target is parked in an ALERTABLE wait, an incoming user APC
     * completes that wait with STATUS_USER_APC; the APC is delivered on the
     * way back to ring 3 (apcDeliverPending). A non-alertable wait is left
     * undisturbed — the APC waits for the next alertable point (NT). */
    if (thread->state == KI_THREAD_STATE_WAITING && thread->waitAlertable)
    {
        thread->apcDeliverPending = TRUE;
        thread->waitAlertable = FALSE;
        KiUnwaitThreadWithStatus(thread, STATUS_USER_APC);
    }
    KiReleaseDispatcherLock(flags);
    return TRUE;
}

BOOLEAN KiUserApcPending(PKTHREAD thread)
{
    return thread->apcDeliverPending && !IsListEmpty(&thread->userApcListHead);
}

BOOLEAN KiTestAlertCurrentThread(void)
{
    PKTHREAD thread = KiCurrentThread;
    ASSERT(KiIsDispatcherLockHeld());
    BOOLEAN result = FALSE;
    if (thread->alerted)
    {
        thread->alerted = FALSE;
        result = TRUE;
    }
    if (!IsListEmpty(&thread->userApcListHead))
    {
        thread->apcDeliverPending = TRUE;
        result = TRUE;
    }
    return result;
}

/* Release every APC still queued to a thread that is exiting. The blocks are
 * owned by the queue, and nothing else can release them once the thread is
 * gone (docs/review-2026-07 §7). Called from KiTerminateThread with the
 * dispatcher lock held — which the release path tolerates because it only
 * ever reaches the pool or a reserve-object dereference, neither of which
 * takes a lock or parks. */
void KiDrainUserApcQueue(PKTHREAD thread)
{
    ASSERT(KiIsDispatcherLockHeld());
    while (!IsListEmpty(&thread->userApcListHead))
    {
        PKAPC apc = CONTAINING_RECORD(thread->userApcListHead.Flink, KAPC, apcListEntry);
        RemoveEntryList(&apc->apcListEntry);
        KiFreeUserApc(apc);
    }
    thread->userApcPending = FALSE;
    thread->apcDeliverPending = FALSE;
}
