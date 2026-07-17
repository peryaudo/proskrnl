/* kernel/ke/sched.c — the priority scheduler (M2).
 *
 * Internals are free (docs/05): 32 ready queues (one per KPRIORITY level, NT's
 * 0..31 range) with a summary bitmap, strict highest-priority-first, FIFO
 * within a level. Under Art. 3 there is no preemption: a thread runs until it
 * waits, yields, or terminates; interrupts only ready threads. The dispatcher
 * lock is a plain interrupt disable — the only lock in the kernel.
 *
 * The boot context becomes the idle thread: after KiSystemStartup spawns the
 * first real thread it falls into KiIdleLoop and never blocks again. The idle
 * thread lives outside the ready queues; KiSwapToNext falls back to it when
 * every queue is empty.
 */
#include "kernel/ke/ke.h"
#include "kernel/init/panic.h"
#include "kernel/lib/string.h"

PKTHREAD KiCurrentThread;

static KTHREAD KiIdleThread; /* the boot context; stack is Limine's */
static LIST_ENTRY KiReadyQueues[KI_PRIORITY_LEVELS];
static uint32_t KiReadySummary; /* bit n set <=> queue n non-empty */

/* arch/x86_64/ctxswitch.S; call and return with the dispatcher lock held. */
void KiSwapContext(PKTHREAD oldThread, PKTHREAD newThread);

uint64_t KiAcquireDispatcherLock(void)
{
    uint64_t flags;
    __asm__ volatile("pushfq; popq %0; cli" : "=r"(flags) : : "memory");
    return flags;
}

void KiReleaseDispatcherLock(uint64_t flags)
{
    __asm__ volatile("pushq %0; popfq" : : "r"(flags) : "memory", "cc");
}

void KiInitializeScheduler(void)
{
    for (int level = 0; level < KI_PRIORITY_LEVELS; level++)
    {
        InitializeListHead(&KiReadyQueues[level]);
    }
    KiReadySummary = 0;

    KiInitializeDispatcherHeader(&KiIdleThread.header, KI_OBJECT_THREAD, 0);
    KiIdleThread.state = KI_THREAD_STATE_RUNNING;
    KiIdleThread.priority = 0;
    InitializeListHead(&KiIdleThread.mutantListHead);
    KeInitializeTimerEx(&KiIdleThread.timer, NotificationTimer);
    KiCurrentThread = &KiIdleThread;
}

PKTHREAD KeGetCurrentThread(void)
{
    return KiCurrentThread;
}

void KiReadyThread(PKTHREAD thread)
{
    if (thread == &KiIdleThread)
    {
        KiPanic("KiReadyThread: the idle thread never queues");
    }
    ASSERT(KiIsDispatcherLockHeld());
    ASSERT(thread->priority >= 0 && thread->priority < KI_PRIORITY_LEVELS);
    /* READY would double-queue its readyListEntry; TERMINATED never runs again. */
    ASSERT(thread->state != KI_THREAD_STATE_READY);
    ASSERT(thread->state != KI_THREAD_STATE_TERMINATED);
    thread->state = KI_THREAD_STATE_READY;
    InsertTailList(&KiReadyQueues[thread->priority], &thread->readyListEntry);
    KiReadySummary |= 1U << thread->priority;
}

/* Dequeue the highest-priority ready thread, or 0 when all queues are empty. */
static PKTHREAD KiSelectNextThread(void)
{
    if (KiReadySummary == 0)
    {
        return 0;
    }
    int level = 31 - __builtin_clz(KiReadySummary);
    PKTHREAD thread =
        CONTAINING_RECORD(RemoveHeadList(&KiReadyQueues[level]), KTHREAD, readyListEntry);
    ASSERT(thread->state == KI_THREAD_STATE_READY);
    ASSERT(thread->priority == level); /* queue and summary bit agree */
    if (IsListEmpty(&KiReadyQueues[level]))
    {
        KiReadySummary &= ~(1U << level);
    }
    return thread;
}

/* Switch to the best ready thread (or idle). The caller has already put the
 * current thread where it belongs (wait lists, ready queue, or nowhere for
 * termination/idle); lock held on entry and on return. */
void KiSwapToNext(void)
{
    PKTHREAD old = KiCurrentThread;
    ASSERT(KiIsDispatcherLockHeld());
    ASSERT(old->state != KI_THREAD_STATE_RUNNING); /* caller re-states first */
    PKTHREAD next = KiSelectNextThread();
    if (next == 0)
    {
        next = &KiIdleThread;
    }
    if (next == old)
    {
        old->state = KI_THREAD_STATE_RUNNING;
        return;
    }
    next->state = KI_THREAD_STATE_RUNNING;
    KiCurrentThread = next;
    KiSwapContext(old, next);
    /* Now back on `old`'s stack, someone having switched to us again. */
}

void KiYield(void)
{
    uint64_t flags = KiAcquireDispatcherLock();
    PKTHREAD current = KiCurrentThread;
    if (current == &KiIdleThread)
    {
        KiPanic("KiYield: from the idle thread");
    }
    KiReadyThread(current); /* tail of its level: equal-priority round-robin */
    KiSwapToNext();
    KiReleaseDispatcherLock(flags);
}

__attribute__((noreturn)) void KiIdleLoop(void)
{
    if (KiCurrentThread != &KiIdleThread)
    {
        KiPanic("KiIdleLoop: not on the boot/idle context");
    }
    for (;;)
    {
        __asm__ volatile("cli");
        if (KiReadySummary != 0)
        {
            KiIdleThread.state = KI_THREAD_STATE_READY;
            KiSwapToNext();
        }
        /* sti;hlt back-to-back: an interrupt arriving in between still wakes
         * the hlt (sti takes effect after the next instruction). */
        __asm__ volatile("sti; hlt");
    }
}
