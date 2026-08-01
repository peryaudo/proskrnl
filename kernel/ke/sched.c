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
#include "kernel/ps/ps.h"
#include "kernel/init/panic.h"
#include "kernel/init/trace.h"
#include "kernel/init/verify.h"
#include "kernel/lib/string.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/io.h"

PKTHREAD KiCurrentThread;

static KTHREAD KiIdleThread; /* the boot context; stack is Limine's */

/* CUI-6: the clock tick asks (timer.c) so idle ticks land in idle time. */
BOOLEAN KiThreadIsIdle(PKTHREAD thread)
{
    return thread == &KiIdleThread;
}
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
    KiIdleThread.suspendCount = 0;
    KeInitializeEvent(&KiIdleThread.suspendGate, NotificationEvent, TRUE);
    KiIdleThread.terminating = FALSE;
    KiIdleThread.terminateStatus = STATUS_SUCCESS;
    /* The boot context: a system thread on Limine's stack. stackTop stays 0
     * (the idle thread never leads to a ring crossing). */
    KiIdleThread.process = PsInitialSystemProcess;
    KiIdleThread.previousMode = KernelMode;
    ASSERT(KiIdleThread.process != 0); /* Ps init precedes the scheduler */
    KiIdleThread.trapFrame = 0;
    InitializeListHead(&KiIdleThread.userApcListHead);
    InitializeListHead(&KiIdleThread.mutantListHead);
    KeInitializeEvent(&KiIdleThread.syncIoCancelEvent, NotificationEvent, FALSE);
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

/* --- consistency-sweep checks (kernel/init/verify.c; lock held) ------------ */

BOOLEAN KiIsThreadOnReadyQueue(PKTHREAD thread)
{
    if (thread->priority < 0 || thread->priority >= KI_PRIORITY_LEVELS)
    {
        return FALSE;
    }
    for (PLIST_ENTRY entry = KiReadyQueues[thread->priority].Flink;
         entry != &KiReadyQueues[thread->priority]; entry = entry->Flink)
    {
        if (entry == &thread->readyListEntry)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/* The queues and the summary bitmap are one value owned in two places; every
 * queued thread's state/priority must agree with the queue holding it. */
void KiVerifyScheduler(void)
{
    ASSERT(KiIsDispatcherLockHeld());
    ASSERT(KiCurrentThread != 0);
    ASSERT(KiCurrentThread->state == KI_THREAD_STATE_RUNNING);
    for (int level = 0; level < KI_PRIORITY_LEVELS; level++)
    {
        BOOLEAN queued = !IsListEmpty(&KiReadyQueues[level]);
        BOOLEAN flagged = (KiReadySummary & (1U << level)) != 0;
        ASSERT(queued == flagged);
        for (PLIST_ENTRY entry = KiReadyQueues[level].Flink; entry != &KiReadyQueues[level];
             entry = entry->Flink)
        {
            ASSERT(entry->Flink->Blink == entry && entry->Blink->Flink == entry);
            PKTHREAD thread = CONTAINING_RECORD(entry, KTHREAD, readyListEntry);
            ASSERT(thread->state == KI_THREAD_STATE_READY);
            ASSERT(thread->priority == level);
            ASSERT(thread->header.type == KI_OBJECT_THREAD);
            ASSERT(thread->process != 0);
        }
    }
}

/* Program the machine for `next` (M4): the ring-crossing stack (TSS.RSP0 +
 * the syscall entry stack), the user GS base (its TEB), and CR3 when the
 * address space changes. Under Art. 3 this is the ONLY place hardware
 * thread state changes — context switches happen nowhere else. */
static void KiLoadThreadHardwareState(PKTHREAD next)
{
    if (next->stackTop != 0)
    {
        KiSetKernelStack(next->stackTop);
    }
    KiSetUserGsBase((uint64_t)(uintptr_t)next->teb);

    uint64_t pml4 = next->process->addressSpace.pml4Physical;
    uint64_t cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    if (cr3 != pml4)
    {
        __asm__ volatile("mov %0, %%cr3" : : "r"(pml4) : "memory");
    }
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
    KiTraceEvent(KiTraceSwap, (uint64_t)(uintptr_t)old, (uint64_t)(uintptr_t)next, 0);
    KiLoadThreadHardwareState(next);
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

/* CUI-4: the one preemption point, taken at the timer interrupt's return to
 * ring 3 (kernel/init/panic.c). Art. 3 forbids preempting kernel code, but a
 * switch AT a user-mode return is explicitly sanctioned (docs/09) — and it is
 * required: without it a ring-3 busy loop that issues no syscalls never yields,
 * starving every other thread (a killer can never run to stop it; taskkill /
 * Ctrl+C would hang). Round-robin only when another thread of at least this
 * one's priority is ready, so strict priority still holds and an otherwise
 * idle CPU keeps running the current thread. */
void KiPreemptAtUserReturn(void)
{
    uint64_t flags = KiAcquireDispatcherLock();
    PKTHREAD current = KiCurrentThread;
    if (current != &KiIdleThread && KiReadySummary != 0)
    {
        int highestReady = 31 - __builtin_clz(KiReadySummary);
        if (highestReady >= current->priority)
        {
            KiReadyThread(current); /* tail of its level */
            KiSwapToNext();
        }
    }
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
        /* Idle is the one context guaranteed to see every other thread at a
         * blocking point: sweep the executive's cross-references here
         * (throttled inside; interrupts are already off = lock held). */
        KiVerifyKernelStateIdle();
        /* sti;hlt back-to-back: an interrupt arriving in between still wakes
         * the hlt (sti takes effect after the next instruction). */
        __asm__ volatile("sti; hlt");
    }
}
