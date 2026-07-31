/* kernel/ke/wait.c — dispatcher header, wait blocks, KeWaitFor* (M2).
 *
 * The contract-bearing file of Ke (docs/05, docs/12): wait-any/wait-all over
 * an arbitrary object mix, with the NT satisfaction side effects —
 * synchronization events/timers auto-reset for exactly one waiter, semaphores
 * decrement, mutants recurse for their owner and report abandonment,
 * notification objects wake everybody and stay signalled. Under Art. 3 (one
 * dispatcher lock, uniprocessor, no preemption) this is a plain state
 * machine: a waiter is satisfied *by the signaller*, never re-races.
 *
 * Timeouts ride the same machinery: a waiting thread arms its own KTIMER and
 * hangs a WaitAny block with waitKey == STATUS_TIMEOUT on it, so a timer
 * expiry wakes the thread through the ordinary KiWaitTest path.
 *
 * `alertable` is accepted but never alerts: APC delivery lands with M3/M4.
 */
#include "kernel/ke/ke.h"
#include "kernel/init/panic.h"

void KiInitializeDispatcherHeader(PDISPATCHER_HEADER header, UCHAR type, LONG signalState)
{
    header->type = type;
    header->absolute = 0;
    header->size = 0;
    header->inserted = 0;
    header->signalState = signalState;
    InitializeListHead(&header->waitListHead);
}

/* Would a wait by `thread` on `object` complete right now? */
static int KiIsSatisfiable(PDISPATCHER_HEADER object, PKTHREAD thread)
{
    if (object->signalState > 0)
    {
        return 1;
    }
    if (object->type == KI_OBJECT_MUTANT && ((PKMUTANT)object)->ownerThread == thread)
    {
        return 1; /* recursive acquisition by the owner */
    }
    return 0;
}

/* Apply the NT side effect of completing one wait on `object` for `thread`.
 * Returns 1 when an abandoned mutant was acquired (the wait status must say
 * STATUS_ABANDONED_WAIT_0 + index). */
static int KiSatisfyObject(PDISPATCHER_HEADER object, PKTHREAD thread)
{
    switch (object->type)
    {
    case KI_OBJECT_SYNCHRONIZATION_EVENT:
    case KI_OBJECT_SYNCHRONIZATION_TIMER:
        object->signalState = 0;
        return 0;
    case KI_OBJECT_SEMAPHORE:
        ASSERT(object->signalState > 0); /* a wait may only consume a count */
        object->signalState--;
        return 0;
    case KI_OBJECT_MUTANT:
    {
        PKMUTANT mutant = (PKMUTANT)object;
        int wasAbandoned = mutant->abandoned != 0;
        object->signalState--;
        if (mutant->ownerThread != thread)
        {
            mutant->ownerThread = thread;
            mutant->abandoned = FALSE;
            InsertTailList(&thread->mutantListHead, &mutant->mutantListEntry);
        }
        return wasAbandoned;
    }
    default:
        /* Notification events/timers and threads stay signalled. */
        return 0;
    }
}

/* Remove a thread from every wait it is part of, record the wait outcome, and
 * make it runnable. Lock held. */
static void KiUnwaitThread(PKTHREAD thread, NTSTATUS status)
{
    ASSERT(thread->state == KI_THREAD_STATE_WAITING);
    for (PKWAIT_BLOCK block = thread->waitBlockList; block != 0; block = block->nextWaitBlock)
    {
        RemoveEntryList(&block->waitListEntry);
    }
    thread->waitBlockList = 0;
    if (thread->timerArmed)
    {
        RemoveEntryList(&thread->timerWaitBlock.waitListEntry);
        if (thread->timer.header.inserted)
        {
            KiRemoveTimer(&thread->timer);
        }
        thread->timerArmed = FALSE;
    }
    thread->waitStatus = status;
    KiReadyThread(thread);
}

void KiUnwaitThreadWithStatus(PKTHREAD thread, NTSTATUS status)
{
    ASSERT(KiIsDispatcherLockHeld());
    KiUnwaitThread(thread, status);
}

void KiAlertWaitingThread(PKTHREAD thread)
{
    ASSERT(KiIsDispatcherLockHeld());
    ASSERT(thread->state == KI_THREAD_STATE_WAITING);
    KiUnwaitThread(thread, STATUS_ALERTED);
}

/* CUI-4: pull a foreign-terminated thread out of its wait so it reaches a
 * ring-3 edge and reaps itself (KiProcessPendingUserSignals). Only ever
 * called for a user thread (ASSERT) — kernel-internal waits (cm hive mutex,
 * PsRunUserImageEx joins, the reaper) are never terminate targets, so they are
 * never aborted. The wait returns STATUS_THREAD_IS_TERMINATING, which each
 * indefinite-wait site propagates up rather than re-waiting on. */
void KiAbortThreadWait(PKTHREAD thread)
{
    ASSERT(KiIsDispatcherLockHeld());
    ASSERT(thread->threadObject != 0);
    if (thread->state == KI_THREAD_STATE_WAITING)
    {
        KiUnwaitThread(thread, STATUS_THREAD_IS_TERMINATING);
    }
}

/* Would a wait by the current user thread fail outright because a foreign
 * terminate is pending? Checked at the top of every indefinite wait so a
 * re-wait loop (npfs re-park, the condrv serial poll, the byte-lock retry)
 * cannot trap a dying thread short of its reaping edge. */
static BOOLEAN KiWaitAbortedForTermination(PKTHREAD thread)
{
    return thread->terminating && thread->threadObject != 0;
}

/* Are all objects of a wait-all thread simultaneously satisfiable? The
 * timeout timer block is deliberately outside waitBlockList. */
static int KiIsWaitAllSatisfiable(PKTHREAD thread)
{
    for (PKWAIT_BLOCK block = thread->waitBlockList; block != 0; block = block->nextWaitBlock)
    {
        if (!KiIsSatisfiable(block->object, thread))
        {
            return 0;
        }
    }
    return 1;
}

/* Satisfy every object of a wait-all thread at once (this is the atomicity
 * NT promises: nothing is consumed until everything is available). Returns
 * the completed wait's status. */
static NTSTATUS KiSatisfyWaitAll(PKTHREAD thread)
{
    NTSTATUS status = STATUS_SUCCESS;
    for (PKWAIT_BLOCK block = thread->waitBlockList; block != 0; block = block->nextWaitBlock)
    {
        if (KiSatisfyObject(block->object, thread) && status == STATUS_SUCCESS)
        {
            /* BARE STATUS_ABANDONED_WAIT_0, with no index added. A wait-all
             * completes as STATUS_WAIT_0 (index 0, because there is no
             * single satisfying object), and abandonment adds the abandoned
             * base to THAT: third_party/wine server/thread.c check_wait
             * returns STATUS_WAIT_0 for SELECT_WAIT_ALL and end_wait then
             * does `if (wait->abandoned) status += STATUS_ABANDONED_WAIT_0;`
             * (docs/review-2026-07 §9). Adding the block's index reported an
             * abandoned index a wait-all never has. */
            status = STATUS_ABANDONED_WAIT_0;
        }
    }
    return status;
}

void KiWaitTest(PDISPATCHER_HEADER object)
{
    ASSERT(KiIsDispatcherLockHeld());
restart:
    if (object->signalState <= 0)
    {
        return;
    }
    for (PLIST_ENTRY entry = object->waitListHead.Flink; entry != &object->waitListHead;
         entry = entry->Flink)
    {
        PKWAIT_BLOCK block = CONTAINING_RECORD(entry, KWAIT_BLOCK, waitListEntry);
        PKTHREAD thread = block->thread;
        if (block->waitType == WaitAny)
        {
            /* The timeout block's waitKey is STATUS_TIMEOUT itself; object
             * blocks hold their index (STATUS_WAIT_0 == 0). */
            NTSTATUS status = (NTSTATUS)block->waitKey;
            if (KiSatisfyObject(object, thread))
            {
                status = STATUS_ABANDONED_WAIT_0 + block->waitKey;
            }
            KiUnwaitThread(thread, status);
            goto restart; /* the wait lists just changed under the loop */
        }
        if (KiIsWaitAllSatisfiable(thread))
        {
            NTSTATUS status = KiSatisfyWaitAll(thread);
            KiUnwaitThread(thread, status);
            goto restart;
        }
    }
}

/* --- consistency-sweep checks (kernel/init/verify.c; lock held) ------------ */

static BOOLEAN KiIsDispatcherType(UCHAR type)
{
    switch (type)
    {
    case KI_OBJECT_NOTIFICATION_EVENT:
    case KI_OBJECT_SYNCHRONIZATION_EVENT:
    case KI_OBJECT_MUTANT:
    case KI_OBJECT_PROCESS:
    case KI_OBJECT_SEMAPHORE:
    case KI_OBJECT_THREAD:
    case KI_OBJECT_NOTIFICATION_TIMER:
    case KI_OBJECT_SYNCHRONIZATION_TIMER:
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOLEAN KiWaitListContains(PDISPATCHER_HEADER object, PKWAIT_BLOCK block)
{
    for (PLIST_ENTRY entry = object->waitListHead.Flink; entry != &object->waitListHead;
         entry = entry->Flink)
    {
        if (entry == &block->waitListEntry)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/* Every waiter on an object's wait list must be a WAITING thread that
 * actually armed this block (its waitBlockList chain or its timeout block) —
 * a stale block here is a use-after-unwait about to satisfy a dead wait. */
void KiVerifyWaitList(PDISPATCHER_HEADER object)
{
    ASSERT(KiIsDispatcherLockHeld());
    if (object->waitListHead.Flink == 0)
    {
        return; /* still-zeroed body: the private create window (ob.h contract) */
    }
    ASSERT(KiIsDispatcherType(object->type));
    for (PLIST_ENTRY entry = object->waitListHead.Flink; entry != &object->waitListHead;
         entry = entry->Flink)
    {
        ASSERT(entry->Flink->Blink == entry && entry->Blink->Flink == entry);
        PKWAIT_BLOCK block = CONTAINING_RECORD(entry, KWAIT_BLOCK, waitListEntry);
        ASSERT(block->object == object);
        PKTHREAD thread = block->thread;
        ASSERT(thread != 0);
        ASSERT(thread->state == KI_THREAD_STATE_WAITING);
        BOOLEAN owned = block == &thread->timerWaitBlock && thread->timerArmed;
        for (PKWAIT_BLOCK b = thread->waitBlockList; !owned && b != 0; b = b->nextWaitBlock)
        {
            owned = b == block;
        }
        ASSERT(owned);
    }
}

/* The thread-side mirror: a thread's scheduling state must agree with the
 * queue/list it claims to be on. Callable for any enumerable thread. */
void KiVerifyThreadWaitState(PKTHREAD thread)
{
    ASSERT(KiIsDispatcherLockHeld());
    switch (thread->state)
    {
    case KI_THREAD_STATE_INITIALIZED:
        ASSERT(thread->waitBlockList == 0);
        ASSERT(thread->suspendCount >= 0);
        break;
    case KI_THREAD_STATE_READY:
        ASSERT(thread->waitBlockList == 0);
        ASSERT(KiIsThreadOnReadyQueue(thread));
        break;
    case KI_THREAD_STATE_RUNNING:
        ASSERT(thread == KiCurrentThread);
        break;
    case KI_THREAD_STATE_WAITING:
        ASSERT(thread->waitBlockList != 0 || thread->timerArmed);
        for (PKWAIT_BLOCK block = thread->waitBlockList; block != 0; block = block->nextWaitBlock)
        {
            ASSERT(block->thread == thread);
            ASSERT(block->object != 0);
            ASSERT(KiIsDispatcherType(((PDISPATCHER_HEADER)block->object)->type));
            ASSERT(KiWaitListContains(block->object, block));
        }
        if (thread->timerArmed)
        {
            ASSERT(thread->timer.header.inserted != 0);
            ASSERT(thread->timerWaitBlock.thread == thread);
            ASSERT(KiWaitListContains(&thread->timer.header, &thread->timerWaitBlock));
        }
        break;
    case KI_THREAD_STATE_TERMINATED:
        ASSERT(thread->header.signalState == 1);
        break;
    default:
        KiPanic("KiVerifyThreadWaitState: invalid thread state");
    }
    /* Owned mutants: ownership is a value held in two places (the mutant's
     * ownerThread and the thread's mutant list) — they must agree. */
    for (PLIST_ENTRY entry = thread->mutantListHead.Flink; entry != &thread->mutantListHead;
         entry = entry->Flink)
    {
        PKMUTANT mutant = CONTAINING_RECORD(entry, KMUTANT, mutantListEntry);
        ASSERT(mutant->header.type == KI_OBJECT_MUTANT);
        ASSERT(mutant->ownerThread == thread);
        ASSERT(mutant->header.signalState <= 0);
    }
}

LONG KiReleaseMutant(PKMUTANT mutant, BOOLEAN abandoned)
{
    ASSERT(mutant->header.type == KI_OBJECT_MUTANT);
    LONG previous = mutant->header.signalState;
    if (abandoned)
    {
        /* Full release regardless of recursion depth; flag the next owner. */
        mutant->header.signalState = 1;
        mutant->abandoned = TRUE;
    }
    else
    {
        if (mutant->ownerThread != KiCurrentThread)
        {
            KiPanic("KeReleaseMutex: caller does not own the mutex "
                    "(STATUS_MUTANT_NOT_OWNED)");
        }
        ASSERT(mutant->header.signalState <= 0); /* owned: 0 or recursion-negative */
        mutant->header.signalState++;
    }
    if (mutant->header.signalState == 1)
    {
        mutant->ownerThread = 0;
        RemoveEntryList(&mutant->mutantListEntry);
        KiWaitTest(&mutant->header);
    }
    return previous;
}

/* Park the current thread on its armed waits and switch away; the eventual
 * KiUnwaitThread has stored the outcome in waitStatus. Lock held. */
static NTSTATUS KiCommitWait(PKTHREAD thread)
{
    thread->state = KI_THREAD_STATE_WAITING;
    KiSwapToNext();
    return thread->waitStatus;
}

static void KiArmWaitTimeout(PKTHREAD thread, PLARGE_INTEGER timeout)
{
    thread->timerWaitBlock.thread = thread;
    thread->timerWaitBlock.object = &thread->timer.header;
    thread->timerWaitBlock.nextWaitBlock = 0;
    thread->timerWaitBlock.waitKey = (USHORT)STATUS_TIMEOUT;
    thread->timerWaitBlock.waitType = WaitAny;
    thread->timer.header.signalState = 0;
    InsertTailList(&thread->timer.header.waitListHead, &thread->timerWaitBlock.waitListEntry);
    KiInsertTimer(&thread->timer, KiComputeDueTime(timeout));
    thread->timerArmed = TRUE;
}

NTSTATUS KeWaitForMultipleObjects(ULONG count, void *objects[], WAIT_TYPE waitType,
                                  KWAIT_REASON waitReason, KPROCESSOR_MODE waitMode,
                                  BOOLEAN alertable, PLARGE_INTEGER timeout,
                                  PKWAIT_BLOCK waitBlockArray)
{
    PKTHREAD thread = KiCurrentThread;

    if (count == 0 || count > MAXIMUM_WAIT_OBJECTS)
    {
        KiPanic("KeWaitForMultipleObjects: invalid object count");
    }
    ASSERT(waitType == WaitAny || waitType == WaitAll);
    PKWAIT_BLOCK blocks = waitBlockArray;
    if (blocks == 0)
    {
        if (count > KI_THREAD_WAIT_OBJECTS)
        {
            KiPanic("KeWaitForMultipleObjects: > 3 objects need a wait block array");
        }
        blocks = thread->waitBlocks;
    }

    /* A wait-all may not name the same object twice. Nothing de-duplicated
     * the array, so KiSatisfyWaitAll consumed a count-1 semaphore twice and
     * fired KiSatisfyObject's ASSERT(signalState > 0) -- an unprivileged
     * kernel halt from two identical handles (docs/review-2026-07 §2).
     *
     * The refusal, rather than a tolerated double-consume, is NT's documented
     * contract: WaitForMultipleObjects, lpHandles -- "the array ... may not
     * contain multiple copies of the same handle", and such a call fails with
     * ERROR_INVALID_PARAMETER
     * (https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitformultipleobjects).
     * The oracle cannot arbitrate this one: the pinned Wine's server has the
     * identical assertion (server/semaphore.c semaphore_sync_satisfied,
     * `assert( sem->count )`) and dies on the same input, so it is unbuilt
     * there in the sense Art. 12 means. WaitAny is untouched -- it satisfies
     * exactly one object, so duplicates are harmless and legal. */
    if (waitType == WaitAll)
    {
        for (ULONG i = 1; i < count; i++)
        {
            for (ULONG j = 0; j < i; j++)
            {
                if (objects[i] == objects[j])
                {
                    return STATUS_INVALID_PARAMETER;
                }
            }
        }
    }

    uint64_t flags = KiAcquireDispatcherLock();

    /* A foreign-terminated thread never parks (CUI-4): fail the wait so it
     * unwinds to its reaping edge. */
    if (KiWaitAbortedForTermination(thread))
    {
        KiReleaseDispatcherLock(flags);
        return STATUS_THREAD_IS_TERMINATING;
    }

    /* Immediate satisfaction — checked before any timeout, including 0. */
    if (waitType == WaitAny)
    {
        for (ULONG i = 0; i < count; i++)
        {
            PDISPATCHER_HEADER object = objects[i];
            if (KiIsSatisfiable(object, thread))
            {
                NTSTATUS status = STATUS_WAIT_0 + (NTSTATUS)i;
                if (KiSatisfyObject(object, thread))
                {
                    status = STATUS_ABANDONED_WAIT_0 + (NTSTATUS)i;
                }
                KiReleaseDispatcherLock(flags);
                return status;
            }
        }
    }
    else
    {
        int allReady = 1;
        for (ULONG i = 0; i < count; i++)
        {
            if (!KiIsSatisfiable(objects[i], thread))
            {
                allReady = 0;
                break;
            }
        }
        if (allReady)
        {
            NTSTATUS status = STATUS_SUCCESS;
            for (ULONG i = 0; i < count; i++)
            {
                if (KiSatisfyObject(objects[i], thread) && status == STATUS_SUCCESS)
                {
                    status = STATUS_ABANDONED_WAIT_0; /* bare: see KiSatisfyWaitAll */
                }
            }
            KiReleaseDispatcherLock(flags);
            return status;
        }
    }

    /* Alertable + a user APC already queued: complete immediately with
     * STATUS_USER_APC and deliver on the way back to ring 3 (M7). Checked
     * before the zero-timeout early-out, as NT does. */
    if (alertable && (thread->userApcPending || thread->alerted))
    {
        if (thread->userApcPending)
        {
            thread->apcDeliverPending = TRUE;
        }
        NTSTATUS alertStatus = thread->userApcPending ? STATUS_USER_APC : STATUS_ALERTED;
        /* Consume the alert ONLY when the alert is what completed the wait.
         * Clearing it on the STATUS_USER_APC branch too silently destroyed a
         * pending alert the caller had not been told about
         * (docs/review-2026-07 §9). */
        if (alertStatus == STATUS_ALERTED)
        {
            thread->alerted = FALSE;
        }
        KiReleaseDispatcherLock(flags);
        return alertStatus;
    }

    if (timeout != 0 && timeout->QuadPart == 0)
    {
        KiReleaseDispatcherLock(flags);
        return STATUS_TIMEOUT;
    }

    for (ULONG i = 0; i < count; i++)
    {
        blocks[i].thread = thread;
        blocks[i].object = objects[i];
        blocks[i].nextWaitBlock = (i + 1 < count) ? &blocks[i + 1] : 0;
        blocks[i].waitKey = (USHORT)i;
        blocks[i].waitType = (USHORT)waitType;
        InsertTailList(&((PDISPATCHER_HEADER)objects[i])->waitListHead, &blocks[i].waitListEntry);
    }
    thread->waitBlockList = blocks;
    if (timeout != 0)
    {
        KiArmWaitTimeout(thread, timeout);
    }

    thread->waitAlertable = alertable; /* M7: a user APC can complete it */
    NTSTATUS status = KiCommitWait(thread);
    thread->waitAlertable = FALSE;
    KiReleaseDispatcherLock(flags);
    return status;
}

NTSTATUS KeWaitForSingleObject(void *object, KWAIT_REASON waitReason, KPROCESSOR_MODE waitMode,
                               BOOLEAN alertable, PLARGE_INTEGER timeout)
{
    return KeWaitForMultipleObjects(1, &object, WaitAny, waitReason, waitMode, alertable, timeout,
                                    0);
}

NTSTATUS KeDelayExecutionThread(KPROCESSOR_MODE waitMode, BOOLEAN alertable,
                                PLARGE_INTEGER interval)
{
    if (interval == 0)
    {
        KiPanic("KeDelayExecutionThread: NULL interval");
    }
    uint64_t flags = KiAcquireDispatcherLock();
    PKTHREAD thread = KiCurrentThread;

    /* A foreign-terminated thread never parks (CUI-4). */
    if (KiWaitAbortedForTermination(thread))
    {
        KiReleaseDispatcherLock(flags);
        return STATUS_THREAD_IS_TERMINATING;
    }

    /* Alertable + a user APC (or alert) already pending: complete
     * immediately, exactly as the object waits do (sem_file/apc_completion
     * pins the STATUS_USER_APC result and the delivery at this point). */
    if (alertable && (thread->userApcPending || thread->alerted))
    {
        if (thread->userApcPending)
        {
            thread->apcDeliverPending = TRUE;
        }
        NTSTATUS alertStatus = thread->userApcPending ? STATUS_USER_APC : STATUS_ALERTED;
        /* Consume the alert ONLY when the alert is what completed the wait.
         * Clearing it on the STATUS_USER_APC branch too silently destroyed a
         * pending alert the caller had not been told about
         * (docs/review-2026-07 §9). */
        if (alertStatus == STATUS_ALERTED)
        {
            thread->alerted = FALSE;
        }
        KiReleaseDispatcherLock(flags);
        return alertStatus;
    }

    if (interval->QuadPart == 0)
    {
        /* NT: a zero delay yields the remainder of the timeslice. */
        KiReleaseDispatcherLock(flags);
        KiYield();
        return STATUS_SUCCESS;
    }

    thread->waitBlockList = 0; /* a pure timer wait */
    KiArmWaitTimeout(thread, interval);
    thread->waitAlertable = alertable; /* a user APC can complete the delay */
    NTSTATUS status = KiCommitWait(thread);
    thread->waitAlertable = FALSE;
    KiReleaseDispatcherLock(flags);

    return status == STATUS_TIMEOUT ? STATUS_SUCCESS : status;
}
