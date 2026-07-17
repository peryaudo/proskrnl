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
            status = STATUS_ABANDONED_WAIT_0 + block->waitKey;
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

    uint64_t flags = KiAcquireDispatcherLock();

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
                    status = STATUS_ABANDONED_WAIT_0 + (NTSTATUS)i;
                }
            }
            KiReleaseDispatcherLock(flags);
            return status;
        }
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

    NTSTATUS status = KiCommitWait(thread);
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
    if (interval->QuadPart == 0)
    {
        /* NT: a zero delay yields the remainder of the timeslice. */
        KiYield();
        return STATUS_SUCCESS;
    }

    uint64_t flags = KiAcquireDispatcherLock();
    PKTHREAD thread = KiCurrentThread;
    thread->waitBlockList = 0; /* a pure timer wait */
    KiArmWaitTimeout(thread, interval);
    NTSTATUS status = KiCommitWait(thread);
    KiReleaseDispatcherLock(flags);

    return status == STATUS_TIMEOUT ? STATUS_SUCCESS : status;
}
