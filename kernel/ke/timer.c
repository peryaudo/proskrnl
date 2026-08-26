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
#include "kernel/init/profile.h"
#include "kernel/init/panic.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/syscall/syscall.h"
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

/* How far the fraction below may interpolate past the last accounted tick.
 * NOT one tick, and NOT unbounded — both ends of the range are load-bearing:
 *
 *   - One tick (the original clamp) FROZE the query clock for as long as a
 *     clock interrupt was late: on a loaded CI host the LAPIC tick lags
 *     whole milliseconds behind the TSC, every query in that window answered
 *     the same saturated value, and the first tick after it published the
 *     whole catch-up as one >= 1 ms step — exactly the step kernel32:time's
 *     time.c:843 (and sem_ps/precise_time.c's verbatim pin of it) reject.
 *   - Unbounded (or the tick side's one-second catch-up bound) would let the
 *     query run arbitrarily far ahead of the tick-granular USD page during a
 *     stall, and the one boundary assertion pointing the query-vs-page
 *     direction the other way tolerates only 50 ms of it:
 *     third_party/wine/dlls/ntdll/tests/time.c:457 excuses
 *     `NtQuerySystemTime > USD SystemTime` only inside
 *     `todo_wine_if(t1 - t2 < 50 * TICKSPERMSEC)` (docs/03 "Sub-tick
 *     system time").
 *
 * So: 40 ticks — the query clock rides through every late-tick window CI has
 * actually produced (single-digit milliseconds) with 10 ms of margin under
 * the 50 ms tolerance. A tick later than THIS still saturates the fraction,
 * and the step out of that window trips time.c:843 only past 41 ms of
 * lateness — a regime the one-tick clamp entered at two. */
#define KI_MAX_FRACTION_TICKS 40ULL

/* How far past the last accounted tick we are, in 100 ns units. The tick is
 * what the clock IS; this only subdivides it, so that the precise system time
 * Windows promises under 1 us (GetSystemTimePreciseAsFileTime,
 * learn.microsoft.com) is not quantised to the scheduler's 1 ms (docs/03
 * "Sub-tick system time").
 *
 * Two properties carry the whole design, and both come from the CLAMP rather
 * than from the TSC being trustworthy:
 *
 *   - Monotone. Tick base plus fraction together measure one TSC delta from
 *     one base: KiUpdateClock folds whole ticks of that delta into the base
 *     (KiTicksElapsed) and re-bases the remainder into the fraction, so the
 *     sum is continuous across the tick and a reading never steps back.
 *   - Bounded error. A TSC that lies mis-places a reading by at most the
 *     clamp (40 ms) before the next tick re-bases it.
 *
 * Clamping in TSC units rather than after the conversion is also what keeps
 * the multiply from overflowing: delta is below 40 ms worth of cycles by the
 * time it is scaled. */
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
    if (delta >= rate * KI_MAX_FRACTION_TICKS)
    {
        return KI_MAX_FRACTION_TICKS * KI_100NS_PER_TICK - 1;
    }
    return (delta * KI_100NS_PER_TICK) / rate;
}

/* Start the interpolation base at the instant the clock does. Called by
 * KiInitializeClock with interrupts still off, because the base set in
 * KiInitializeTimerList predates calibration by the length of the PIT gate
 * plus whatever boot work sits between them — and the first tick, which now
 * measures how much time actually passed (KiTicksElapsed), would otherwise
 * hand all of that to uptime as though the clock had been running through
 * it. */
void KiResetTickBase(void)
{
    KiTickTsc = KiReadTimestampCounter();
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
        /* Diagnostic, not an invariant: a multi-hour RELATIVE timeout is
         * legal NT, but in this machine's baked workload it has only ever
         * been the product of a caller's unit confusion (a QPC-tick count
         * armed as milliseconds reads as ~5 days). One rate-limited serial
         * line moves that smoking gun from "inferred days later from a
         * parked thread" to "logged at arm time with the caller's ring-3
         * RIP". Never an ASSERT — asserting a heuristic is what Art. 6/G12
         * forbid. Threshold 1 h in 100 ns units. */
        static uint32_t KiSuspectTimeoutBudget = 64;
        uint64_t relative100ns = 0 - (uint64_t)timeout->QuadPart;
        if (relative100ns > 36000000000ULL && KiSuspectTimeoutBudget != 0)
        {
            KiSuspectTimeoutBudget--;
            PKTHREAD thread = KeGetCurrentThread();
            uint64_t userRip = (thread != 0 && thread->trapFrame != 0) ? thread->trapFrame->rip : 0;
            DbgPrint("[SUSPECT] relative timeout %lu ms rip=%#018lx syscall=%s raw=%#lx\n",
                     relative100ns / 10000, userRip,
                     (thread != 0 && thread->lastSyscall != ~(uint64_t)0)
                         ? KiSystemCallName(thread->lastSyscall)
                         : "-",
                     (uint64_t)timeout->QuadPart);
        }
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

/* Ticks this interrupt is worth. The LAPIC delivers one interrupt per
 * programmed period, but the period is only what the platform PROMISED: a
 * hypervisor that does not schedule its guest, or that coalesces a queued
 * interrupt, delivers one interrupt after several periods have passed.
 * Advancing by exactly one tick per interrupt deleted the difference
 * permanently — and undetectably, because re-basing the interpolation on the
 * current TSC erased the evidence in the same breath.
 *
 * So the TSC decides how FAR the clock moves and the interrupt only decides
 * WHEN it moves. That is the division Linux draws between a clocksource (a
 * counter you read) and a clockevent (a timer that interrupts), and it is what
 * makes the fraction above a subdivision of real time rather than of the
 * platform's good intentions.
 *
 * The bound is one second's worth of ticks: past that the reading is evidence
 * of a lying counter rather than of a stalled platform, and KiTicksElapsed
 * says what taking the bound costs. */
#define KI_MAX_CATCHUP_TICKS 1000ULL

/* Ticks added beyond one per interrupt since boot — how much time this
 * platform failed to deliver on schedule and the clock recovered. Reported by
 * the panic dump (Art. 9): a clock that is behind is invisible without it. */
volatile uint64_t KiCatchUpTicks;

static uint64_t KiTicksElapsed(uint64_t elapsed, uint64_t rate)
{
    if (rate == 0)
    {
        return 1; /* before KiInitializeClock: the interrupt is all there is */
    }
    uint64_t ticks = elapsed / rate;
    if (ticks == 0)
    {
        /* The interrupt beat the TSC to the millisecond. The two are
         * calibrated against each other but not locked, so the LAPIC may
         * arrive a few cycles early; an interrupt is worth at least the tick
         * it was programmed for, and returning 0 would stall the clock — and
         * with it the timer queue — for as long as the skew lasted. */
        return 1;
    }
    if (ticks > KI_MAX_CATCHUP_TICKS)
    {
        /* A bound, not a policy: the only way to get here is a TSC that moved
         * by more than a second's worth of cycles in one tick, which means the
         * counter lied rather than that the platform stalled that long. Taking
         * the bound makes the clock run slow and recover over the following
         * ticks (the base below advances by whole ticks, so the remainder is
         * still owed); trusting the reading would move the clock by years. */
        return KI_MAX_CATCHUP_TICKS;
    }
    return ticks;
}

void KiUpdateClock(BOOLEAN interruptedUser)
{
    ASSERT(KiIsDispatcherLockHeld()); /* interrupt context: IF is clear */
    uint64_t now = KiReadTimestampCounter();
    uint64_t rate = KiTscPerMillisecond;
    uint64_t elapsed = now - KiTickTsc;
    uint64_t ticks = KiTicksElapsed(elapsed, rate);
    uint64_t advance = ticks * KI_100NS_PER_TICK;

    KeTickCount += ticks;
    KiInterruptTime += advance;
    KiCatchUpTicks += ticks - 1;

    /* Re-base the sub-tick interpolation by WHOLE ticks rather than onto
     * `now`. The cycles left over — up to one tick's worth — are time that has
     * genuinely passed and that no tick has accounted for yet, so they must
     * stay in the fraction; assigning `now` here would round them away once
     * per millisecond, which is the same leak in miniature that advancing by
     * one tick per interrupt was in the large. When the bound in KiTicksElapsed
     * capped the advance, the leftover exceeds a whole tick and stays visible
     * through the fraction (up to its own KI_MAX_FRACTION_TICKS clamp) until
     * the following ticks catch up.
     *
     * THE BASE MUST NEVER PASS `now`. KiTickFraction subtracts it from a later
     * TSC read as UNSIGNED, so a base in the future does not read as a small
     * negative offset — it underflows to something enormous, trips the clamp,
     * and pins the fraction at its bound for as long as
     * the condition lasts. That is exactly what the "interrupt arrived early"
     * case above produces if its invented tick is also allowed to advance the
     * base: measured, as sem_ps/perf_counter and sem_ps/precise_time going red
     * together while every other clock test stayed green. Charging a tick the
     * TSC has not yet reached is the right answer for the CLOCK — an interrupt
     * is worth at least its period — and the wrong answer for the BASE, so the
     * two part company here. */
    if (rate != 0 && ticks * rate <= elapsed)
    {
        KiTickTsc += ticks * rate;
    }
    else
    {
        KiTickTsc = now;
    }

    /* CUI-6: whole-tick sampling accounting, NT's clock-interrupt shape —
     * the interrupted thread is charged the whole tick, kernel or user by
     * the interrupted CS; the idle thread's ticks (and any tick before the
     * scheduler exists) are idle time. One tick, one bucket: the invariant
     * below is the subsystem's cheapest defence.
     *
     * Recovered ticks are charged the same way, all of them to the interrupted
     * thread. Sampling has no better answer — nothing recorded who was running
     * during time the platform never interrupted us for — and the alternative
     * of leaving them uncharged would break the invariant, which is worth more
     * than the precision it would buy. */
    PKTHREAD current = KiCurrentThread;
    if (current == 0 || KiThreadIsIdle(current))
    {
        KiIdleTime100ns += advance;
    }
    else if (interruptedUser)
    {
        current->userTime100ns += advance;
        KiTotalUserTime100ns += advance;
    }
    else
    {
        current->kernelTime100ns += advance;
        KiTotalKernelTime100ns += advance;
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

    /* The guest-clocked completion-latency BOUND (docs/19 §11c): the blk
     * MSI is the primary harvest (microseconds), but its injection rides
     * the host's scheduling of the emulator's main loop, which a contended
     * host can lag arbitrarily in guest-relative time — measured: Wine's
     * one-second empty-desktop close (server/winstation.c) beat a client's
     * I/O-parked startup on the CI runner, killing the gui6 session
     * desktop. The tick is guest time, so draining here restores the 1 ms
     * ceiling those user-space timeouts implicitly price in. A dead ISR is
     * still loud: the §11e delivery verdict gates on ISR-path harvests,
     * not on this backstop's absence. Idempotent when the ISR already
     * harvested; respects the §8.1 completion hold (VioBlkDrain). */
    IoDrainDeviceCompletions();

    /* The profiler's once-a-second delta line (kernel/init/profile.h): the
     * clock is the only periodic edge in the kernel, and a boot profile needs
     * to say WHEN a service was busy, not just how much. A no-op unless
     * armed, and it neither waits nor allocates — the tick region must not
     * block (G14).  */
    KiProfileTick();
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
