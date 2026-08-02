/* kernel/ke/event.c — notification and synchronization events (M2).
 *
 * The exact NT split (docs/02 M2): a notification (manual-reset) event wakes
 * every waiter and stays signalled until reset; a synchronization (auto-reset)
 * event releases exactly one waiter and resets when a wait is satisfied.
 * Signatures per Wine's ntoskrnl exports (dlls/ntoskrnl.exe/sync.c).
 */
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h" /* KPROCESSOR_MODE enum for the gate acquire's wait */
#include "kernel/init/panic.h"

/* Wrong-object bugs (a semaphore passed as an event, a stale pointer) show up
 * as an alien type tag before they corrupt a wait list. */
static void KiAssertIsEvent(PRKEVENT event)
{
    ASSERT(event->header.type == KI_OBJECT_NOTIFICATION_EVENT ||
           event->header.type == KI_OBJECT_SYNCHRONIZATION_EVENT);
}

void KeInitializeEvent(PRKEVENT event, EVENT_TYPE type, BOOLEAN state)
{
    KiInitializeDispatcherHeader(&event->header,
                                 type == NotificationEvent ? KI_OBJECT_NOTIFICATION_EVENT
                                                           : KI_OBJECT_SYNCHRONIZATION_EVENT,
                                 state ? 1 : 0);
}

/* The `wait` argument is NT's hint that the caller will immediately wait; it
 * only ever optimized lock hand-off, which one dispatcher lock makes moot. */
LONG KeSetEvent(PRKEVENT event, KPRIORITY increment, BOOLEAN wait)
{
    uint64_t flags = KiAcquireDispatcherLock();
    KiAssertIsEvent(event);
    LONG previous = event->header.signalState;
    event->header.signalState = 1;
    KiWaitTest(&event->header);
    KiReleaseDispatcherLock(flags);
    return previous;
}

/* NtPulseEvent's engine: release the waiters satisfiable right now, leave
 * the event non-signalled. Internal Ki name — Wine exports no KePulseEvent
 * (docs/15: absent from the Wine tree means the NT name is not taken). */
LONG KiPulseEvent(PRKEVENT event)
{
    uint64_t flags = KiAcquireDispatcherLock();
    KiAssertIsEvent(event);
    LONG previous = event->header.signalState;
    event->header.signalState = 1;
    KiWaitTest(&event->header);
    event->header.signalState = 0;
    KiReleaseDispatcherLock(flags);
    return previous;
}

LONG KeResetEvent(PRKEVENT event)
{
    uint64_t flags = KiAcquireDispatcherLock();
    KiAssertIsEvent(event);
    LONG previous = event->header.signalState;
    event->header.signalState = 0;
    KiReleaseDispatcherLock(flags);
    return previous;
}

void KeClearEvent(PRKEVENT event)
{
    KeResetEvent(event);
}

/* Acquire a synchronization event used as a binary-semaphore gate (CUI-8:
 * the fat32 volume gate, docs/20 R1; the file-object I/O lock). The common
 * case is an ordinary wait; the one caller class whose wait refuses — a
 * terminating thread's rundown I/O (KiWaitAbortedForTermination) — parks
 * anyway under the rundownWait exemption. It must PARK, not try/yield:
 * KiYield re-readies the caller at the tail of ITS OWN priority level and
 * the scheduler is strict highest-first, so a dying thread above the
 * holder's priority would re-select itself forever and the holder could
 * never reach its release — a permanent FS-wide hang; and even at equal
 * priority a release hands the signal to a QUEUED waiter, which a
 * non-queuing retry loop can be starved against indefinitely. A queued
 * wait has neither problem, and the park is bounded: the holder's own
 * device waits complete by DEVICE action harvested at the tick/idle
 * drains, so every gate hold ends.
 *
 * KNOWN LIMIT — priority inversion (docs/20 §11.2): "every gate hold ends"
 * assumes the holder RUNS once its device wait completes. Under the strict
 * highest-first scheduler with no boost (the drain's KeSetEvent passes
 * increment 0), a compute-bound thread above the holder's priority keeps a
 * readied holder off the CPU indefinitely, and every waiter of any
 * priority hangs behind it — a shape the pre-CUI-8 spin-synchronous FS
 * could not produce. Tolerated while every baked workload is
 * single-priority; the exit is a boost at the drain's wake (NT's
 * IO_DISK_INCREMENT shape), taken when a workload convicts it. */
void KiAcquireEventGate(PRKEVENT event)
{
    ASSERT(event->header.type == KI_OBJECT_SYNCHRONIZATION_EVENT);
    PKTHREAD thread = KeGetCurrentThread();
    for (;;)
    {
        NTSTATUS status = KeWaitForSingleObject(event, Executive, KernelMode, FALSE, 0);
        if (status == STATUS_SUCCESS)
        {
            return;
        }
        ASSERT(status == STATUS_THREAD_IS_TERMINATING);
        ASSERT(!thread->rundownWait); /* gates never nest */
        thread->rundownWait = TRUE;
        status = KeWaitForSingleObject(event, Executive, KernelMode, FALSE, 0);
        thread->rundownWait = FALSE;
        if (status == STATUS_SUCCESS)
        {
            return;
        }
    }
}

LONG KeReadStateEvent(PRKEVENT event)
{
    return event->header.signalState;
}
