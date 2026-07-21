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

#include "abi/ntkeapi.h"

volatile uint64_t KeTickCount;
static volatile uint64_t KiInterruptTime; /* 100 ns units since boot */

/* The KUSER_SHARED_DATA page, once Ps has built it (0 before that). */
void *KiUserSharedData;

/* System time base: a fixed date (2026-01-01) as 100 ns since 1601-01-01 —
 * the same no-RTC rule as file timestamps (docs/03, fs/fat32/fat.c
 * FatCurrentNtTime): present, ordered, monotonic; never compared to a wall
 * clock. 155228 days 1601→2026: 425 years * 365 + 103 leap days (Gregorian
 * rules per the MS FILETIME documentation,
 * https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime;
 * cross-check: 1601→1970 is 134774 days — Wine server/fd.c ticks_1601_to_1970
 * (369 * 365 + 89) — plus 20454 days 1970→2026). */
#define KI_SYSTEM_TIME_BASE (155228ULL * 86400ULL * 10000000ULL)

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

void KeQuerySystemTime(LARGE_INTEGER *time)
{
    time->QuadPart = (LONGLONG)(KI_SYSTEM_TIME_BASE + KeQueryInterruptTime());
}

/* One KSYSTEM_TIME store in the order Wine's readers expect: High2Time,
 * LowPart, High1Time — a reader spins until High1 == High2 (third_party/wine
 * dlls/kernelbase/sync.c GetTickCount64; writer: server/fd.c
 * set_user_shared_data_time). volatile stores suffice on x86 (total store
 * order — same argument as server/fd.c atomic_store_ulong). */
static void KiWriteKSystemTime(volatile KSYSTEM_TIME *target, uint64_t value)
{
    target->High2Time = (LONG)(value >> 32);
    target->LowPart = (ULONG)value;
    target->High1Time = (LONG)(value >> 32);
}

/* Mirror the clocks into KUSER_SHARED_DATA. TickCount is milliseconds
 * (server/fd.c: tick_count = monotonic_time / 10000; kernelbase's readers
 * ignore TickCountMultiplier); SystemTime = the fixed base + uptime. */
static void KiUpdateUserSharedDataTime(void)
{
    KUSER_SHARED_DATA *usd = KiUserSharedData;
    if (usd == 0)
    {
        return;
    }
    uint64_t tickMs = KiInterruptTime / 10000;
    KiWriteKSystemTime(&usd->InterruptTime, KiInterruptTime);
    KiWriteKSystemTime(&usd->SystemTime, KI_SYSTEM_TIME_BASE + KiInterruptTime);
    KiWriteKSystemTime(&usd->TickCount, tickMs);
    usd->TickCountLowDeprecated = (ULONG)tickMs;
}

void KiSeedUserSharedDataTime(void)
{
    uint64_t flags = KiAcquireDispatcherLock();
    KiUpdateUserSharedDataTime();
    KiReleaseDispatcherLock(flags);
}

uint64_t KiComputeDueTime(PLARGE_INTEGER timeout)
{
    if (timeout->QuadPart < 0)
    {
        /* Relative: unsigned negation avoids UB on the most-negative value. */
        return KiInterruptTime + (0 - (uint64_t)timeout->QuadPart);
    }
    /* Absolute: 100 ns since 1601 in SYSTEM time (the NT timeout contract;
     * Wine dlls/ntdll/unix/sync.c get_absolute_timeout). The timer queue
     * runs on interrupt time, and SystemTime == BASE + InterruptTime
     * (KeQuerySystemTime above), so the due converts by the fixed base; a
     * deadline at or before the base is already in the past. Exercised by
     * ntdll:sync test_wait_on_address's absolute RtlWaitOnAddress timeout —
     * the untranslated value parked the wait for ~4 billion seconds. */
    if ((uint64_t)timeout->QuadPart <= KI_SYSTEM_TIME_BASE)
    {
        return KiInterruptTime;
    }
    return (uint64_t)timeout->QuadPart - KI_SYSTEM_TIME_BASE;
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
    KiUpdateUserSharedDataTime();

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
