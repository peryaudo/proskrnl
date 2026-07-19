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
#include "kernel/init/panic.h"

void KiInsertQueueUserApc(PKTHREAD thread, PKAPC apc)
{
    uint64_t flags = KiAcquireDispatcherLock();
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
