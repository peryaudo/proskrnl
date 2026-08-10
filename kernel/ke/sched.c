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
#include "kernel/lib/dbgprint.h"
#include "kernel/init/verify.h"
#include "kernel/lib/string.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/io.h"

PKTHREAD KiCurrentThread;

/* CUI-8 (docs/20 R2): see ke.h — set only around IoDrainDeviceCompletions,
 * asserted against in the allocators. */
BOOLEAN KiInCompletionDrain;

/* Non-blocking regions (issue #96 A; contract in ke.h). */
ULONG KiNoBlockDepth;
const char *KiNoBlockReason = "";

void KiEnterNoBlockRegion(const char *reason)
{
    KiNoBlockDepth++;
    KiNoBlockReason = reason;
}

void KiLeaveNoBlockRegion(void)
{
    ASSERT(KiNoBlockDepth != 0);
    KiNoBlockDepth--;
}

void KiAssertMayBlock(const char *primitive)
{
    if (KiNoBlockDepth != 0)
    {
        /* Name both halves before dying: which primitive was reached, and
         * which region promised it would not be (the panic dump is the
         * debugger — Art. 9). */
        DbgPrint("[PANIC] %s reached from the non-blocking region '%s'\n", primitive,
                 KiNoBlockReason);
        KiPanic("KI_MAY_BLOCK: a park was reached from a non-blocking region");
    }
}

/* --- release obligations (issue #96 B; contract in ke.h) ------------------ */

void KiPushObligation(const char *name, void *object)
{
    PKTHREAD thread = KeGetCurrentThread();
    if (thread->obligationCount >= KI_MAX_OBLIGATIONS)
    {
        DbgPrint("[PANIC] obligation stack full taking '%s' on %p\n", name, object);
        KiPanic("KiPushObligation: obligation stack overflow");
    }
    thread->obligations[thread->obligationCount].name = name;
    thread->obligations[thread->obligationCount].object = object;
    thread->obligationCount++;
}

void KiPopObligation(const char *name, void *object)
{
    PKTHREAD thread = KeGetCurrentThread();
    if (thread->obligationCount == 0)
    {
        DbgPrint("[PANIC] releasing '%s' on %p with nothing outstanding\n", name, object);
        KiPanic("KiPopObligation: release without a matching take");
    }
    KI_OBLIGATION *top = &thread->obligations[thread->obligationCount - 1];
    if (top->name != name || top->object != object)
    {
        /* Out of order: the release does not pair with the innermost take.
         * Caught here, where the stack trace still names both, rather than as
         * an unexplained leftover at the syscall exit. */
        DbgPrint("[PANIC] releasing '%s' on %p, but the innermost hold is '%s' on %p\n", name,
                 object, top->name, top->object);
        KiPanic("KiPopObligation: obligations released out of order");
    }
    thread->obligationCount--;
}

void KiAssertNoObligations(const char *where)
{
    PKTHREAD thread = KeGetCurrentThread();
    if (thread == 0 || thread->obligationCount == 0)
    {
        return;
    }
    for (ULONG i = 0; i < thread->obligationCount; i++)
    {
        DbgPrint("[PANIC] leaked obligation %lu/%lu at %s: '%s' on %p\n", (unsigned long)(i + 1),
                 (unsigned long)thread->obligationCount, where, thread->obligations[i].name,
                 thread->obligations[i].object);
    }
    KiPanic("KiAssertNoObligations: the kernel was left holding something");
}

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
    KiIdleThread.rundownWait = FALSE;
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

/* --- deterministic schedule strings (issue #96 D; contract in ke.h) -------- */

static const UCHAR *KiScheduleString; /* 0 == off, the default for every run */
static ULONG KiScheduleLength;
static KI_SCHEDULE_TRACE KiScheduleTrace;

void KiArmSchedule(const UCHAR *bytes, ULONG length)
{
    ASSERT(KiScheduleString == 0); /* not nestable */
    memset(&KiScheduleTrace, 0, sizeof(KiScheduleTrace));
    KiScheduleLength = length;
    KiScheduleString = bytes;
}

void KiDisarmSchedule(PKI_SCHEDULE_TRACE traceOut)
{
    KiScheduleString = 0;
    KiScheduleLength = 0;
    if (traceOut != 0)
    {
        *traceOut = KiScheduleTrace;
    }
}

/* Take the `index`-th ready thread in priority order (0 == what the default
 * policy would pick). Unlinks it wherever it sits and repairs the summary. */
static PKTHREAD KiTakeReadyThread(ULONG index)
{
    for (int level = KI_PRIORITY_LEVELS - 1; level >= 0; level--)
    {
        for (PLIST_ENTRY entry = KiReadyQueues[level].Flink; entry != &KiReadyQueues[level];
             entry = entry->Flink)
        {
            if (index-- != 0)
            {
                continue;
            }
            PKTHREAD thread = CONTAINING_RECORD(entry, KTHREAD, readyListEntry);
            RemoveEntryList(entry);
            if (IsListEmpty(&KiReadyQueues[level]))
            {
                KiReadySummary &= ~(1U << level);
            }
            return thread;
        }
    }
    KiPanic("KiTakeReadyThread: index past the end of the ready set");
}

/* How many threads are ready right now — the branching factor of this
 * scheduling decision. Only walked while a schedule is armed. */
static ULONG KiCountReadyThreads(void)
{
    ULONG count = 0;
    for (int level = 0; level < KI_PRIORITY_LEVELS; level++)
    {
        for (PLIST_ENTRY entry = KiReadyQueues[level].Flink; entry != &KiReadyQueues[level];
             entry = entry->Flink)
        {
            count++;
        }
    }
    return count;
}

/* Dequeue the highest-priority ready thread, or 0 when all queues are empty. */
static PKTHREAD KiSelectNextThread(void)
{
    if (KiReadySummary == 0)
    {
        return 0;
    }
    /* The one predicate the default path pays for the exploration harness. */
    if (KiScheduleString != 0)
    {
        ULONG options = KiCountReadyThreads();
        ULONG index = 0;
        if (options > 1)
        {
            ULONG choice = KiScheduleTrace.choiceCount;
            if (choice < KI_SCHEDULE_MAX_CHOICES)
            {
                if (choice < KiScheduleLength)
                {
                    index = KiScheduleString[choice] % options;
                    KiScheduleTrace.consumed++;
                }
                KiScheduleTrace.options[choice] = (UCHAR)options;
                KiScheduleTrace.chosen[choice] = (UCHAR)index;
                KiScheduleTrace.choiceCount++;
                KiScheduleTrace.preemptions += index != 0 ? 1 : 0;
            }
            else
            {
                /* Past the trace's capacity the run still completes, on the
                 * default policy — but say so, because a truncated trace
                 * means the harness's enumeration was not exhaustive and a
                 * silent cap reads as "explored everything" (Art. 12). */
                KiScheduleTrace.overflowed = TRUE;
            }
        }
        return KiTakeReadyThread(index);
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
    /* WOW64: the compat-mode FS descriptor is per-thread (it is BASED at the
     * thread's TEB32), so it is switched here with the rest of the hardware
     * thread state. Uniprocessor, so one GDT slot rewritten in place stands
     * in for NT's per-processor GDT (Art. 3). A thread of a 64-bit process
     * answers 0, which also clears the selector the return path loads. */
    KiSetUserFs32Base(PspWow64Fs32Base(next));

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
    /* Issue #96 C: the outgoing thread is about to let others run, so every
     * probe it took before this point is now stale. Advanced HERE, at the one
     * switch site, and only when a switch really happens — a wait satisfied
     * without yielding the CPU gave nobody a chance to unmap anything and
     * must not cost a re-probe. */
    old->parkGeneration++;
    next->state = KI_THREAD_STATE_RUNNING;
    KiCurrentThread = next;
    KiTraceEvent(KiTraceSwap, (uint64_t)(uintptr_t)old, (uint64_t)(uintptr_t)next, 0);
    KiLoadThreadHardwareState(next);
    KiSwapContext(old, next);
    /* Now back on `old`'s stack, someone having switched to us again. */
}

void KiYield(void)
{
    KI_MAY_BLOCK();
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
        /* CUI-8 (docs/19 §5b): harvest device completions before the ready
         * check, so a drain-readied thread is swapped to immediately. */
        ULONG inFlight = IoDrainDeviceCompletions();
        if (KiReadySummary != 0)
        {
            KiIdleThread.state = KI_THREAD_STATE_READY;
            KiSwapToNext();
            /* Back from running other threads: the pre-swap inFlight is
             * stale — the thread that just ran may have submitted a batch
             * and parked, and falling through to its == 0 answer would hlt
             * with transfers in flight (up to a full tick of added latency,
             * on EVERY await in the stress configuration). Re-drain and
             * re-sample instead. */
            continue;
        }
        /* Idle is the one context guaranteed to see every other thread at a
         * blocking point: sweep the executive's cross-references here
         * (throttled inside; interrupts are already off = lock held). */
        KiVerifyKernelStateIdle();
        if (inFlight != 0)
        {
            /* Transfers in flight: poll, don't hlt. No completion interrupt
             * exists to cut a hlt short (docs/19 §5b — no interrupt path),
             * so sleeping here would tax every transfer with up to a full
             * tick of latency; sti-pause still lets the tick preempt. */
            __asm__ volatile("sti; pause");
            continue;
        }
        /* sti;hlt back-to-back: an interrupt arriving in between still wakes
         * the hlt (sti takes effect after the next instruction). */
        __asm__ volatile("sti; hlt");
    }
}
