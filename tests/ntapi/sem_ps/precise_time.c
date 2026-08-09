/*
 * sem_ps/precise_time.c — the system clock's RESOLUTION, not its value
 * (docs/21 W13's residue: kernel32:time's last failing assertion).
 *
 * sem_ps/time.c already pins that the clocks ADVANCE and stay ordered. This
 * one pins the finer promise underneath: the precise system time must move by
 * LESS THAN a millisecond between two calls that report different values.
 * That is Windows' documented distinction between the two file-time getters
 * ("GetSystemTimePreciseAsFileTime function", learn.microsoft.com: "the
 * highest possible level of precision (<1us)"), and it is what
 * kernel32:time's test_GetSystemTimePreciseAsFileTime measures at time.c:843.
 *
 * WHICH ENTRY POINT, and why it is not NtQuerySystemTime. The resolution
 * assertions below go through RtlGetSystemTimePrecise, because that is the
 * function kernelbase's GetSystemTimePreciseAsFileTime calls
 * (third_party/wine dlls/kernelbase/file.c) and because it is precise on the
 * ORACLE unconditionally — its unixlib arm reads CLOCK_REALTIME
 * (dlls/ntdll/unix/sync.c unix_system_time_precise). The oracle's
 * NtQuerySystemTime is NOT: it picks CLOCK_REALTIME_COARSE whenever the host
 * kernel reports a resolution of 1 ms or better (dlls/ntdll/unix/sync.c
 * NtQuerySystemTime), so a resolution assertion aimed straight at it would be
 * green or red according to the developer box's CONFIG_HZ. On proskrnl the
 * two are the same clock — the fork's arm in dlls/ntdll/time.c answers
 * RtlGetSystemTimePrecise out of NtQuerySystemTime, KUSER_SHARED_DATA being
 * the only clock there — so this convicts the kernel exactly as directly.
 *
 * The last block is the guard that keeps a sub-tick clock HONEST rather than
 * merely fast-moving: a counter interpolating between ticks must still agree
 * with the tick it interpolates, so the precise clock's advance across a real
 * delay has to match the delay.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQuerySystemTime(PLARGE_INTEGER);
NTSYSAPI LONGLONG NTAPI RtlGetSystemTimePrecise(void);

#define TICKS_PER_MS  10000LL
#define TICKS_PER_SEC 10000000LL

/* Spin until RtlGetSystemTimePrecise reports something other than `from`, and
 * return the reading. The bound exists so a frozen clock FAILS AN ASSERTION
 * instead of wedging the leg — docs/21 W10 lesson 2 — and it has to be
 * counted in iterations rather than in time, there being no second clock to
 * trust. A thousand-fold margin over the worst case either runner can present
 * (a whole 1 ms tick, ~1000 iterations at proskrnl's syscall cost) is wide
 * enough never to trip and small enough that eight frozen steps cost seconds,
 * not the leg's timeout. */
static LONGLONG wait_for_change(LONGLONG from, int *spun_out)
{
    LONGLONG now = from;
    int i;
    for (i = 0; i < 1000000 && now == from; i++)
    {
        now = RtlGetSystemTimePrecise();
    }
    *spun_out = (now == from);
    return now;
}

START_TEST(precise_time)
{
    NTSTATUS status;
    LARGE_INTEGER queried;
    LONGLONG precise, next, diff;
    int stuck = 0, i;

    /* --- the two clocks name the same instant ------------------------------ */
    /* kernel32:time's own first precise-clock assertion (time.c:833), one
     * layer down: the coarse getter and the precise one must not be 100 ms
     * apart. A precise clock built on a SEPARATE time base rather than on an
     * interpolation of this one fails here and nowhere else. */
    status = NtQuerySystemTime(&queried);
    ok(status == STATUS_SUCCESS, "NtQuerySystemTime -> %08lx", (unsigned long)status);
    precise = RtlGetSystemTimePrecise();
    diff = precise - queried.QuadPart;
    if (diff < 0)
        diff = -diff;
    ok(diff < 100 * TICKS_PER_MS, "coarse and precise %lld (100 ns units) apart", (long long)diff);

    /* --- monotone, sample by sample ---------------------------------------- */
    /* An interpolated clock reads two things — a tick base and a hardware
     * counter — and a reader that catches the two mid-update, or a counter
     * read the processor is free to move, steps BACKWARDS. Nothing else here
     * can see that: every other assertion holds for a clock that jitters. */
    precise = RtlGetSystemTimePrecise();
    LONGLONG lowest = 0;
    int backwards = 0;
    for (i = 0; i < 500000; i++)
    {
        next = RtlGetSystemTimePrecise();
        if (next < precise)
        {
            backwards++;
            if (lowest == 0 || precise - next > lowest)
                lowest = precise - next;
        }
        precise = next;
    }
    ok(backwards == 0, "precise clock stepped back %d times (worst %lld, 100 ns units)", backwards,
       (long long)lowest);

    /* --- the resolution itself --------------------------------------------- */
    /* kernel32:time time.c:843 verbatim: find the next value the clock
     * reports and require the step to be under one millisecond. A clock that
     * only moves on the scheduler tick steps by exactly one tick and fails —
     * which is what this pin exists to convict. Repeated, because a first
     * step can be short by luck (landing just before a tick) while every
     * later one is a whole tick. */
    for (i = 0; i < 8; i++)
    {
        precise = RtlGetSystemTimePrecise();
        next = wait_for_change(precise, &stuck);
        ok(!stuck, "precise clock frozen at %lld (step %d)", (long long)precise, i);
        if (stuck)
            break;
        diff = next - precise;
        ok(diff > 0 && diff < TICKS_PER_MS,
           "step %d advanced by %lld (100 ns units; want 0 < d < 10000)", i, (long long)diff);
    }

    /* --- and it still measures real time ----------------------------------- */
    /* The precise clock's whole value is that it subdivides the tick without
     * DRIFTING from it. A counter converted with a wrong frequency, or one
     * that free-runs instead of being re-based each tick, keeps every
     * assertion above and fails this: 100 ms of sleeping must read as
     * something like 100 ms. The window is wide on purpose — the point is a
     * broken conversion, not scheduler accuracy. */
    {
        LARGE_INTEGER delay;
        LONGLONG before = RtlGetSystemTimePrecise();
        delay.QuadPart = -(100 * TICKS_PER_MS); /* 100 ms relative */
        status = NtDelayExecution(FALSE, &delay);
        ok(status == STATUS_SUCCESS, "NtDelayExecution -> %08lx", (unsigned long)status);
        LONGLONG after = RtlGetSystemTimePrecise();
        diff = after - before;
        ok(diff >= 50 * TICKS_PER_MS && diff <= 2 * TICKS_PER_SEC, "100 ms delay read as %lld ms",
           (long long)(diff / TICKS_PER_MS));
    }
}
