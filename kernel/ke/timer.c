/* kernel/ke/timer.c — kernel timers and the clock tick (M2).
 *
 * KTIMERs live on one due-time-ordered list. The clock interrupt (irq.c →
 * KiUpdateClock) advances KeTickCount / interrupt time and signals expired
 * timers through the ordinary KiWaitTest path, which is also how thread wait
 * timeouts fire (wait.c arms the thread's own KTIMER). Notification vs
 * synchronization timers mirror events: stay-signalled vs one-waiter-reset.
 *
 * Due times: NT's negative QuadPart = relative (100 ns units) is honored
 * exactly. A positive QuadPart means absolute *system time* in NT; there is
 * no wall clock until KUSER_SHARED_DATA (M7), so until then positive values
 * are absolute interrupt time — kernel-internal, unobservable from user mode.
 * DPCs are dropped by design (docs/03): a non-NULL KDPC panics.
 */
#include "kernel/ke/ke.h"
#include "kernel/init/panic.h"

volatile uint64_t KeTickCount;
static volatile uint64_t KiInterruptTime; /* 100 ns units since boot */

static LIST_ENTRY KiTimerListHead;

void KiInitializeTimerList(void)
{
    InitializeListHead(&KiTimerListHead);
    KeTickCount = 0;
    KiInterruptTime = 0;
}

ULONGLONG KeQueryInterruptTime(void)
{
    uint64_t flags = KiAcquireDispatcherLock();
    ULONGLONG now = KiInterruptTime;
    KiReleaseDispatcherLock(flags);
    return now;
}

uint64_t KiComputeDueTime(PLARGE_INTEGER timeout)
{
    if (timeout->QuadPart < 0)
    {
        /* Relative: unsigned negation avoids UB on the most-negative value. */
        return KiInterruptTime + (0 - (uint64_t)timeout->QuadPart);
    }
    return (uint64_t)timeout->QuadPart;
}

void KiInsertTimer(PKTIMER timer, uint64_t dueInterruptTime)
{
    ASSERT(KiIsDispatcherLockHeld());
    ASSERT(timer->header.inserted == 0); /* double insert corrupts the list */
    timer->dueTime.QuadPart = dueInterruptTime;
    timer->header.inserted = 1;

    PLIST_ENTRY entry = KiTimerListHead.Flink;
    while (entry != &KiTimerListHead &&
           CONTAINING_RECORD(entry, KTIMER, timerListEntry)->dueTime.QuadPart <= dueInterruptTime)
    {
        entry = entry->Flink; /* FIFO among equal deadlines */
    }
    /* Insert before `entry`. */
    InsertTailList(entry, &timer->timerListEntry);
}

void KiRemoveTimer(PKTIMER timer)
{
    ASSERT(KiIsDispatcherLockHeld());
    ASSERT(timer->header.inserted != 0);
    RemoveEntryList(&timer->timerListEntry);
    timer->header.inserted = 0;
}

void KiUpdateClock(void)
{
    ASSERT(KiIsDispatcherLockHeld()); /* interrupt context: IF is clear */
    KeTickCount++;
    KiInterruptTime += KI_100NS_PER_TICK;

    while (!IsListEmpty(&KiTimerListHead))
    {
        PKTIMER timer = CONTAINING_RECORD(KiTimerListHead.Flink, KTIMER, timerListEntry);
        if (timer->dueTime.QuadPart > KiInterruptTime)
        {
            break;
        }
        KiRemoveTimer(timer);
        if (timer->period != 0)
        {
            /* Periodic: re-arm relative to now (a late tick must not cause
             * an expiry storm). period is in milliseconds, per NT. */
            KiInsertTimer(timer, KiInterruptTime + (uint64_t)timer->period * KI_100NS_PER_TICK);
        }
        timer->header.signalState = 1;
        KiWaitTest(&timer->header);
    }
}

void KeInitializeTimerEx(PKTIMER timer, TIMER_TYPE type)
{
    KiInitializeDispatcherHeader(&timer->header,
                                 type == NotificationTimer ? KI_OBJECT_NOTIFICATION_TIMER
                                                           : KI_OBJECT_SYNCHRONIZATION_TIMER,
                                 0);
    timer->dueTime.QuadPart = 0;
    timer->dpc = 0;
    timer->period = 0;
}

void KeInitializeTimer(PKTIMER timer)
{
    KeInitializeTimerEx(timer, NotificationTimer);
}

BOOLEAN KeSetTimerEx(PKTIMER timer, LARGE_INTEGER dueTime, LONG period, PKDPC dpc)
{
    if (dpc != 0)
    {
        KiPanic("KeSetTimerEx: DPCs are dropped by design (docs/03)");
    }
    if (period < 0)
    {
        KiPanic("KeSetTimerEx: negative period");
    }
    uint64_t flags = KiAcquireDispatcherLock();
    BOOLEAN wasPending = timer->header.inserted != 0;
    if (wasPending)
    {
        KiRemoveTimer(timer);
    }
    timer->header.signalState = 0;
    timer->period = period;
    KiInsertTimer(timer, KiComputeDueTime(&dueTime));
    KiReleaseDispatcherLock(flags);
    return wasPending;
}

BOOLEAN KeSetTimer(PKTIMER timer, LARGE_INTEGER dueTime, PKDPC dpc)
{
    return KeSetTimerEx(timer, dueTime, 0, dpc);
}

BOOLEAN KeCancelTimer(PKTIMER timer)
{
    uint64_t flags = KiAcquireDispatcherLock();
    BOOLEAN wasPending = timer->header.inserted != 0;
    if (wasPending)
    {
        KiRemoveTimer(timer);
    }
    KiReleaseDispatcherLock(flags);
    return wasPending;
}
