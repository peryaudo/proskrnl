/* kernel/ke/thread.c — kernel thread creation and termination (M2).
 *
 * KTHREAD's internal layout is ours (docs/03). Threads are dispatcher objects:
 * the header is signalled at termination and never reset, so joining a thread
 * is an ordinary KeWaitForSingleObject. PsCreateSystemThread (handles,
 * OBJECT_ATTRIBUTES) needs Ob and arrives at M3+; until then creation is the
 * internal KiCreateThread.
 */
#include "kernel/ke/ke.h"
#include "kernel/ps/ps.h"
#include "kernel/mm/pool.h"
#include "kernel/init/panic.h"

#include <stddef.h>

#define KI_KERNEL_STACK_SIZE (16ULL * 1024)

/* ctxswitch.S restores RSP from this slot; keep the offsets welded. */
_Static_assert(offsetof(KTHREAD, kernelStack) == 24,
               "KTHREAD.kernelStack offset must match ctxswitch.S");

/* First code of every thread, reached by KiSwapContext's ret with the
 * dispatcher lock held (see KiSwapToNext); release it, run, terminate. */
static void KiThreadStartup(void)
{
    ASSERT(KiCurrentThread->state == KI_THREAD_STATE_RUNNING);
    ASSERT(KiCurrentThread->startRoutine != 0);
    /* RFLAGS: IF | the always-one reserved bit. */
    KiReleaseDispatcherLock(0x202);
    KiCurrentThread->startRoutine(KiCurrentThread->startContext);
    KiTerminateThread();
}

PKTHREAD KiCreateThread(KPRIORITY priority, void (*startRoutine)(void *), void *startContext)
{
    return KiCreateThreadEx(priority, startRoutine, startContext, 0, 0);
}

PKTHREAD KiCreateThreadEx(KPRIORITY priority, void (*startRoutine)(void *), void *startContext,
                          struct EPROCESS *process, void *teb)
{
    if (priority < 0 || priority >= KI_PRIORITY_LEVELS)
    {
        KiPanic("KiCreateThread: priority out of range");
    }
    PKTHREAD thread = MiAllocatePool(sizeof(KTHREAD));
    void *stack = MiAllocatePool(KI_KERNEL_STACK_SIZE);
    if (thread == 0 || stack == 0)
    {
        KiPanic("KiCreateThread: out of pool");
    }

    KiInitializeDispatcherHeader(&thread->header, KI_OBJECT_THREAD, 0);
    thread->stackBase = stack;
    thread->stackTop = (uint64_t)(uintptr_t)stack + KI_KERNEL_STACK_SIZE;
    thread->process = process != 0 ? process : PsInitialSystemProcess;
    thread->teb = teb;
    thread->previousMode = KernelMode;
    ASSERT(thread->process != 0); /* Ps init precedes every thread */
    thread->priority = priority;
    thread->startRoutine = startRoutine;
    thread->startContext = startContext;
    InitializeListHead(&thread->mutantListHead);
    /* The thread's private timeout timer (wait.c arms it for timed waits). */
    KeInitializeTimerEx(&thread->timer, NotificationTimer);

    /* Build the initial stack so KiSwapContext's pops + ret enter
     * KiThreadStartup with a 0 return address (ends stack traces) and the
     * ABI-correct rsp % 16 == 8 at function entry. */
    uint64_t *stackPointer = (uint64_t *)((char *)stack + KI_KERNEL_STACK_SIZE);
    *--stackPointer = 0; /* fake caller return address / trace terminator */
    *--stackPointer = (uint64_t)(uintptr_t)KiThreadStartup;
    for (int i = 0; i < 6; i++)
    {
        *--stackPointer = 0; /* rbp, rbx, r12..r15 */
    }
    /* 8 slots below a 16-aligned top: KiSwapContext's 6 pops + ret leave
     * rsp % 16 == 8 at KiThreadStartup entry, as the ABI requires. */
    ASSERT(((uintptr_t)stackPointer & 0xF) == 0);
    thread->kernelStack = (uint64_t)(uintptr_t)stackPointer;

    uint64_t flags = KiAcquireDispatcherLock();
    KiReadyThread(thread);
    KiReleaseDispatcherLock(flags);
    return thread;
}

__attribute__((noreturn)) void KiTerminateThread(void)
{
    KiAcquireDispatcherLock(); /* released forever with this context */
    PKTHREAD thread = KiCurrentThread;

    /* NT semantics: dying while owning mutants abandons them — each is fully
     * released (whatever the recursion depth) and the next acquirer is told
     * via STATUS_ABANDONED_WAIT_0 + index. */
    while (!IsListEmpty(&thread->mutantListHead))
    {
        PKMUTANT mutant = CONTAINING_RECORD(thread->mutantListHead.Flink, KMUTANT, mutantListEntry);
        KiReleaseMutant(mutant, TRUE);
    }

    thread->state = KI_THREAD_STATE_TERMINATED;
    thread->header.signalState = 1; /* never reset: joins always satisfy */
    KiWaitTest(&thread->header);

    KiSwapToNext();
    KiPanic("KiTerminateThread: terminated thread was rescheduled");
}

void KiDeleteThread(PKTHREAD thread)
{
    ASSERT(thread != KiCurrentThread);
    if (thread->state != KI_THREAD_STATE_TERMINATED)
    {
        KiPanic("KiDeleteThread: thread not terminated");
    }
    MiFreePool(thread->stackBase);
    MiFreePool(thread);
}
