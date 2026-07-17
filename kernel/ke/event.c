/* kernel/ke/event.c — notification and synchronization events (M2).
 *
 * The exact NT split (docs/02 M2): a notification (manual-reset) event wakes
 * every waiter and stays signalled until reset; a synchronization (auto-reset)
 * event releases exactly one waiter and resets when a wait is satisfied.
 * Signatures per Wine's ntoskrnl exports (dlls/ntoskrnl.exe/sync.c).
 */
#include "kernel/ke/ke.h"
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

LONG KeReadStateEvent(PRKEVENT event)
{
    return event->header.signalState;
}
