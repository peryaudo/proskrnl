/*
 * sem_ps/perf_counter.c — NtQueryPerformanceCounter's RESOLUTION and RATE,
 * not merely its direction (docs/22 §4c).
 *
 * sem_ps/process_query.c already pins that the counter is monotone and the
 * frequency nonzero. Those hold for a counter that only moves on the
 * scheduler tick, which is the failure this file exists to convict:
 *
 *   "QueryPerformanceCounter ... reads the performance counter and returns the
 *    total number of ticks that have occurred" — where a tick is
 *    1 / QueryPerformanceFrequency, NOT the clock interrupt. Microsoft states
 *    the separation outright: "Is QueryPerformanceCounter() the same as the
 *    Win32 GetTickCount() or GetTickCount64() function?  No."
 *   (learn.microsoft.com, "Acquiring high-resolution time stamps".)
 *
 * An implementation that returns a variable the clock interrupt last wrote
 * satisfies every assertion in process_query.c and fails the resolution leg
 * below: its steps are all exactly one tick's worth of counts.
 *
 * WHAT IS DELIBERATELY NOT ASSERTED. Windows 8 and later promise a resolution
 * under 1 us, and it is tempting to pin that here. It would be the wrong
 * assertion, because what this test can observe is not resolution but
 * PRECISION, and Microsoft's own formula for it is
 *
 *     Precision = MAX[Resolution, AccessTime]
 *
 * (same page). Every reading below costs a syscall on proskrnl — the QPC
 * user-mode bypass is unreachable while Wine's PE-side RtlQueryPerformanceCounter
 * has no bypass path (docs/22 §4d) — so the smallest observable step is bounded
 * by the ring transition, not by the counter. Pinning 1 us would therefore
 * convict the syscall cost and call it a clock defect. One tick is the bound
 * that means what it says: finer than the clock interrupt.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQuerySystemTime(PLARGE_INTEGER);

#define TICKS_PER_MS  10000LL
#define TICKS_PER_SEC 10000000LL

/* Enough back-to-back reads to cross several clock interrupts on either
 * runner, so a tick-quantised counter is guaranteed to show its step rather
 * than sit inside one tick for the whole loop. */
#define SAMPLES 200000

START_TEST(perf_counter)
{
    NTSTATUS status;
    LARGE_INTEGER counter, frequency, second, frequency2;
    LONGLONG prev, cur, step, countsPerMs;
    int i;

    /* --- the frequency is fixed, and it is the one both sides agree on ----- */
    /* "The frequency of the performance counter is fixed at system boot and is
     * consistent across all processors so you only need to query the frequency
     * ... as the application initializes, and then cache the result." A
     * frequency that moved between two calls would break every caller that
     * takes that advice. */
    status = NtQueryPerformanceCounter(&counter, &frequency);
    ok(status == STATUS_SUCCESS, "QueryPerformanceCounter -> %08lx", (unsigned long)status);
    ok(frequency.QuadPart > 0, "frequency %lld", (long long)frequency.QuadPart);
    status = NtQueryPerformanceCounter(&second, &frequency2);
    ok(status == STATUS_SUCCESS, "QueryPerformanceCounter(2) -> %08lx", (unsigned long)status);
    ok(frequency2.QuadPart == frequency.QuadPart, "frequency moved: %lld -> %lld",
       (long long)frequency.QuadPart, (long long)frequency2.QuadPart);

    /* 10 MHz — one count per 100 ns, so a count is a FILETIME unit. This is
     * the value Windows reports "when running under a hypervisor that
     * implements the hypervisor version 1.0 interface (or always in some newer
     * versions of Windows)" (same page), the value the oracle hardcodes
     * (third_party/wine dlls/ntdll/time.c TICKSPERSEC, returned by
     * RtlQueryPerformanceFrequency), and the value the kernel reports
     * (kernel/ps/query.c NtQueryPerformanceCounter). Pinned because the two
     * halves of this pair must not drift apart, NOT as a general NT contract:
     * MS is explicit that "you shouldn't assume QueryPerformanceFrequency will
     * return a value derived from the hardware frequency". */
    ok(frequency.QuadPart == TICKS_PER_SEC, "frequency %lld (want 10 MHz)",
       (long long)frequency.QuadPart);

    if (frequency.QuadPart < 1000)
    {
        skip("frequency %lld too low to reason about a millisecond", (long long)frequency.QuadPart);
        return;
    }
    countsPerMs = frequency.QuadPart / 1000;

    /* --- resolution: the steps are FINER than the clock interrupt --------- */
    /* One pass, three verdicts, because they must be measured over the same
     * samples: the counter never steps back ("Is the performance counter
     * monotonic (non-decreasing)? Yes."), it does move, and the smallest step
     * it takes is smaller than one millisecond's worth of counts.
     *
     * That last bound is proskrnl's clock interrupt period (kernel/ke/ke.h
     * KI_100NS_PER_TICK) rather than NT's 15.625 ms, on purpose: it is the
     * tighter of the two, so the assertion convicts a tick-quantised counter
     * on either runner. A counter that only moves on the interrupt takes steps
     * of EXACTLY countsPerMs and fails here and nowhere else in the suite. */
    status = NtQueryPerformanceCounter(&counter, NULL);
    ok(status == STATUS_SUCCESS, "QueryPerformanceCounter(loop) -> %08lx", (unsigned long)status);
    prev = counter.QuadPart;
    LONGLONG smallest = 0;
    LONGLONG largest = 0;
    int backwards = 0, moves = 0;
    for (i = 0; i < SAMPLES; i++)
    {
        NtQueryPerformanceCounter(&counter, NULL);
        cur = counter.QuadPart;
        if (cur < prev)
        {
            backwards++;
        }
        else if (cur > prev)
        {
            step = cur - prev;
            moves++;
            if (smallest == 0 || step < smallest)
                smallest = step;
            if (step > largest)
                largest = step;
        }
        prev = cur;
    }
    ok(backwards == 0, "counter stepped back %d times in %d samples", backwards, SAMPLES);
    ok(moves > 0, "counter never moved across %d samples", SAMPLES);
    ok(smallest > 0 && smallest < countsPerMs,
       "smallest step %lld counts (want 0 < s < %lld, one clock tick); largest %lld, %d moves",
       (long long)smallest, (long long)countsPerMs, (long long)largest, moves);

    /* --- rate: the counts mean what the frequency says they mean ---------- */
    /* Resolution without rate is a counter that ticks fast and lies about how
     * fast. Convert a real delay through the reported frequency and require
     * the answer back. The window is wide on purpose — this convicts a wrong
     * conversion, not scheduler accuracy — and the delay is expressed in the
     * OTHER unit (100 ns, NtDelayExecution's) so a single wrong constant
     * cannot cancel itself out on both sides. */
    {
        LARGE_INTEGER delay;
        LONGLONG before, after, elapsedMs;

        status = NtQueryPerformanceCounter(&counter, NULL);
        ok(status == STATUS_SUCCESS, "QueryPerformanceCounter(before) -> %08lx",
           (unsigned long)status);
        before = counter.QuadPart;

        delay.QuadPart = -(100 * TICKS_PER_MS); /* 100 ms, relative */
        status = NtDelayExecution(FALSE, &delay);
        ok(status == STATUS_SUCCESS, "NtDelayExecution -> %08lx", (unsigned long)status);

        status = NtQueryPerformanceCounter(&counter, NULL);
        ok(status == STATUS_SUCCESS, "QueryPerformanceCounter(after) -> %08lx",
           (unsigned long)status);
        after = counter.QuadPart;

        elapsedMs = (after - before) / countsPerMs;
        ok(elapsedMs >= 50 && elapsedMs <= 2000, "100 ms delay read as %lld ms by the counter",
           (long long)elapsedMs);
    }

    /* --- and it keeps step with the system clock -------------------------- */
    /* Two clocks over one interval. On the oracle these are genuinely separate
     * sources (dlls/ntdll/unix/sync.c: the counter is CLOCK_BOOTTIME, the
     * system time CLOCK_REALTIME), so this is a real cross-check there; on
     * proskrnl they are one clock in two units, and the leg then convicts a
     * broken conversion between the two rather than a drift. Both are 100 ns
     * units at 10 MHz, so they are directly comparable. */
    {
        LARGE_INTEGER delay, systemBefore, systemAfter;
        LONGLONG counterElapsed, systemElapsed, apart;

        status = NtQuerySystemTime(&systemBefore);
        ok(status == STATUS_SUCCESS, "NtQuerySystemTime -> %08lx", (unsigned long)status);
        status = NtQueryPerformanceCounter(&counter, NULL);
        ok(status == STATUS_SUCCESS, "QueryPerformanceCounter(pair) -> %08lx",
           (unsigned long)status);

        delay.QuadPart = -(100 * TICKS_PER_MS);
        status = NtDelayExecution(FALSE, &delay);
        ok(status == STATUS_SUCCESS, "NtDelayExecution(pair) -> %08lx", (unsigned long)status);

        status = NtQueryPerformanceCounter(&second, NULL);
        ok(status == STATUS_SUCCESS, "QueryPerformanceCounter(pair2) -> %08lx",
           (unsigned long)status);
        status = NtQuerySystemTime(&systemAfter);
        ok(status == STATUS_SUCCESS, "NtQuerySystemTime(2) -> %08lx", (unsigned long)status);

        counterElapsed = (second.QuadPart - counter.QuadPart) / countsPerMs;
        systemElapsed = (systemAfter.QuadPart - systemBefore.QuadPart) / TICKS_PER_MS;
        apart = counterElapsed - systemElapsed;
        if (apart < 0)
            apart = -apart;
        ok(apart <= 50, "counter says %lld ms, system clock says %lld ms",
           (long long)counterElapsed, (long long)systemElapsed);
    }
}
