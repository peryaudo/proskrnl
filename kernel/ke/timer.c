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
#include "arch/x86_64/lapic.h"

#include "abi/ntkeapi.h"

volatile uint64_t KeTickCount;
static volatile uint64_t KiInterruptTime; /* 100 ns units since boot */

/* The TSC as of the last tick — the base the sub-tick interpolation below
 * measures from. Written by KiUpdateClock and read by KiTickFraction, both
 * under the dispatcher lock, so a reader never pairs one tick's
 * KiInterruptTime with another tick's TSC. */
static uint64_t KiTickTsc;

/* The KUSER_SHARED_DATA page, once Ps has built it (0 before that). */
void *KiUserSharedData;

/* System time base: 100 ns since 1601-01-01 at boot, seeded from the CMOS
 * RTC (arch/x86_64/rtc.c, CUI-1) before the first clock interrupt; system
 * time is base + interrupt time everywhere below. The initializer is the
 * fallback when the CMOS content is implausible — the old fixed-date rule
 * (docs/03): 2026-01-01, present/ordered/monotonic but not wall-true.
 * 155228 days 1601→2026: 425 years * 365 + 103 leap days (Gregorian rules
 * per the MS FILETIME documentation,
 * https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime;
 * cross-check: 1601→1970 is 134774 days — Wine server/fd.c ticks_1601_to_1970
 * (369 * 365 + 89) — plus 20454 days 1970→2026). */
uint64_t KiSystemTimeBase = 155228ULL * 86400ULL * 10000000ULL;

static LIST_ENTRY KiTimerListHead;

void KiInitializeTimerList(void)
{
    InitializeListHead(&KiTimerListHead);
    KeTickCount = 0;
    KiInterruptTime = 0;
    KiTickTsc = KiReadTimestampCounter();
}

/* How far into the current tick we are, in 100 ns units — 0 .. one tick short
 * of the next one. The tick is what the clock IS; this only subdivides it, so
 * that the precise system time Windows promises under 1 us
 * (GetSystemTimePreciseAsFileTime, learn.microsoft.com) is not quantised to
 * the scheduler's 1 ms (docs/03 "Sub-tick system time").
 *
 * Two properties carry the whole design, and both come from the CLAMP rather
 * than from the TSC being trustworthy:
 *
 *   - Monotone. The result is strictly less than one tick, so the reading can
 *     never reach the value the next tick will publish, however fast the TSC
 *     runs relative to the LAPIC.
 *   - Bounded error. A TSC that drifts (a processor without an invariant TSC
 *     changing P-state, say) only ever mis-places a reading INSIDE its own
 *     tick, because the next tick re-bases it. The worst case is the accuracy
 *     the clock already had before interpolation.
 *
 * Clamping in TSC units rather than after the conversion is also what keeps
 * the multiply from overflowing: delta is below one millisecond's worth of
 * cycles by the time it is scaled. */
static uint64_t KiTickFraction(void)
{
    ASSERT(KiIsDispatcherLockHeld());
    /* The gate measures cycles per MILLISECOND and the tick is 1 ms; a tick
     * of another length would need the rate converted, not just reused. */
    _Static_assert(KI_100NS_PER_TICK == 10000ULL, "tick is 1 ms, KiTscPerMillisecond's unit");
    uint64_t rate = KiTscPerMillisecond;
    if (rate == 0)
    {
        return 0; /* before KiInitializeClock: the tick is all there is */
    }
    uint64_t delta = KiReadTimestampCounter() - KiTickTsc;
    if (delta >= rate)
    {
        return KI_100NS_PER_TICK - 1;
    }
    return (delta * KI_100NS_PER_TICK) / rate;
}

/* Remaining time for NtQueryTimer, computed HERE because the subtraction needs
 * the clock the timer queue actually expires against — KiUpdateClock's
 * comparison below, and KiComputeDueTime's basis above — which is the raw
 * tick, deliberately not the sub-tick reading. The caller used to spell that
 * clock `KeTickCount * KI_100NS_PER_TICK`: numerically identical, since the
 * two advance together, but a second expression of one quantity, and the kind
 * that a change to how the tick advances has to find in two places (Art. 11).
 * Negative once past due — the NT shape; an unarmed timer has no due point. */
LONGLONG KiQueryTimerRemainingTime(PKTIMER timer)
{
    ASSERT(KiIsDispatcherLockHeld());
    if (timer->header.inserted == 0)
    {
        return 0;
    }
    return (LONGLONG)timer->dueTime.QuadPart - (LONGLONG)KiInterruptTime;
}

ULONGLONG KeQueryInterruptTime(void)
{
    uint64_t flags = KiAcquireDispatcherLock();
    ULONGLONG now = KiInterruptTime + KiTickFraction();
    KiReleaseDispatcherLock(flags);
    return now;
}

void KeQuerySystemTime(LARGE_INTEGER *time)
{
    time->QuadPart = (LONGLONG)(KiSystemTimeBase + KeQueryInterruptTime());
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
 * ignore TickCountMultiplier); SystemTime = the boot-time base + uptime. */
static void KiUpdateUserSharedDataTime(void)
{
    KUSER_SHARED_DATA *usd = KiUserSharedData;
    if (usd == 0)
    {
        return;
    }
    /* The RAW tick times, deliberately: the page is a MIRROR published once
     * per tick, so writing an interpolated value into it would only date the
     * snapshot, never refresh it. That leaves the page one fraction behind
     * what a query answers — the same relation Windows has between
     * SharedUserData and the precise clock, and the direction the ordering
     * pins depend on (page <= query, tests/ntapi/sem_ps/time.c). */
    uint64_t tickMs = KiInterruptTime / 10000;
    KiWriteKSystemTime(&usd->InterruptTime, KiInterruptTime);
    KiWriteKSystemTime(&usd->SystemTime, KiSystemTimeBase + KiInterruptTime);
    KiWriteKSystemTime(&usd->TickCount, tickMs);
    usd->TickCountLowDeprecated = (ULONG)tickMs;
}
/* CUI-7 (NtSetSystemTime): move the wall-clock base so base + uptime lands
 * on `newTime`, and republish the shared page immediately. Armed absolute
 * timers are NOT re-evaluated — their due points were fixed against the
 * interrupt clock at arm time (KiComputeDueTime) and stand; NT re-signals
 * them on a clock change, a recorded deviation with no baked consumer
 * (docs/03 "CUI-7" notes). */
void KeSetSystemTime(LONGLONG newTime)
{
    uint64_t flags = KiAcquireDispatcherLock();
    /* Against the same clock KeQuerySystemTime reads — tick plus fraction —
     * so the caller's instant is the one a query answers next. Rebasing off
     * the tick alone would land the clock up to one tick past `newTime`. */
    KiSystemTimeBase = (uint64_t)newTime - (KiInterruptTime + KiTickFraction());
    KiReleaseDispatcherLock(flags);
    KiUpdateUserSharedDataTime();
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
        /* Relative: unsigned negation avoids UB on the most-negative value.
         *
         * Deliberately the TICK, not the sub-tick reading KiTickFraction
         * gives: a due time is compared against KiInterruptTime by the queue,
         * so arming it off a finer clock would move every timeout later by
         * the fraction, up to a whole extra tick. The cost of leaving it is
         * that a wait armed late in a tick can expire slightly EARLY against
         * the interval it asked for — which has always been true here and is
         * now merely measurable, the clock having become finer than the
         * queue. NT rounds the other way. Nothing pins a wait's lower bound
         * yet, so this stays as it is until something does (docs/21 W13). */
        return KiInterruptTime + (0 - (uint64_t)timeout->QuadPart);
    }
    /* Absolute: 100 ns since 1601 in SYSTEM time (the NT timeout contract;
     * Wine dlls/ntdll/unix/sync.c get_absolute_timeout). The timer queue
     * runs on interrupt time, and SystemTime == BASE + InterruptTime
     * (KeQuerySystemTime above), so the due converts by the fixed base; a
     * deadline at or before the base is already in the past. Exercised by
     * ntdll:sync test_wait_on_address's absolute RtlWaitOnAddress timeout —
     * the untranslated value parked the wait for ~4 billion seconds. */
    if ((uint64_t)timeout->QuadPart <= KiSystemTimeBase)
    {
        return KiInterruptTime;
    }
    return (uint64_t)timeout->QuadPart - KiSystemTimeBase;
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

/* Consistency-sweep check (kernel/init/verify.c; lock held): the due-time
 * order KiInsertTimer maintains, and every entry's inserted flag — the flag
 * and list membership are one value owned in two places. */
void KiVerifyTimerList(void)
{
    ASSERT(KiIsDispatcherLockHeld());
    uint64_t previousDue = 0;
    for (PLIST_ENTRY entry = KiTimerListHead.Flink; entry != &KiTimerListHead; entry = entry->Flink)
    {
        ASSERT(entry->Flink->Blink == entry && entry->Blink->Flink == entry);
        PKTIMER timer = CONTAINING_RECORD(entry, KTIMER, timerListEntry);
        ASSERT(timer->header.inserted != 0);
        ASSERT(timer->header.type == KI_OBJECT_NOTIFICATION_TIMER ||
               timer->header.type == KI_OBJECT_SYNCHRONIZATION_TIMER);
        ASSERT(timer->dueTime.QuadPart >= previousDue);
        previousDue = timer->dueTime.QuadPart;
        ASSERT(timer->period >= 0);
        KiVerifyWaitList(&timer->header);
    }
}

/* CUI-6: machine-wide CPU-time totals (ke.h). Charged below, one tick to
 * exactly one bucket, so their sum always equals KiInterruptTime. */
volatile uint64_t KiIdleTime100ns;
volatile uint64_t KiTotalKernelTime100ns;
volatile uint64_t KiTotalUserTime100ns;

void KiUpdateClock(BOOLEAN interruptedUser)
{
    ASSERT(KiIsDispatcherLockHeld()); /* interrupt context: IF is clear */
    KeTickCount++;
    KiInterruptTime += KI_100NS_PER_TICK;
    /* Re-base the sub-tick interpolation on this tick. Taken here rather than
     * at the interrupt's entry, so the fraction is measured from a point the
     * clock has already accounted for: interrupt latency lands the base
     * slightly LATE, which only makes a reading lag, never overshoot. */
    KiTickTsc = KiReadTimestampCounter();

    /* CUI-6: whole-tick sampling accounting, NT's clock-interrupt shape —
     * the interrupted thread is charged the whole tick, kernel or user by
     * the interrupted CS; the idle thread's ticks (and any tick before the
     * scheduler exists) are idle time. One tick, one bucket: the invariant
     * below is the subsystem's cheapest defence. */
    PKTHREAD current = KiCurrentThread;
    if (current == 0 || KiThreadIsIdle(current))
    {
        KiIdleTime100ns += KI_100NS_PER_TICK;
    }
    else if (interruptedUser)
    {
        current->userTime100ns += KI_100NS_PER_TICK;
        KiTotalUserTime100ns += KI_100NS_PER_TICK;
    }
    else
    {
        current->kernelTime100ns += KI_100NS_PER_TICK;
        KiTotalKernelTime100ns += KI_100NS_PER_TICK;
    }
    ASSERT(KiIdleTime100ns + KiTotalKernelTime100ns + KiTotalUserTime100ns == KiInterruptTime);

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

    /* CUI-8 (docs/19 §5b): harvest device completions each tick, so a
     * parked issuer wakes within a millisecond even when compute-bound
     * threads keep the machine out of idle. The wake this performs
     * (KeSetEvent → KiWaitTest) is the same ready-never-switch edge the
     * timer expiry above already drives (irq.c's contract). */
    IoDrainDeviceCompletions();
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
