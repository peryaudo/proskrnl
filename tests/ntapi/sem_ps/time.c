/*
 * sem_ps/time.c — KUSER_SHARED_DATA time fields tick + NtQuerySystemTime (M10).
 *
 * GetTickCount64 / QueryInterruptTime / GetSystemTimeAsFileTime in Wine's
 * kernelbase read the shared page's TickCount / InterruptTime / SystemTime
 * lock-free with the High1Time/High2Time protocol (third_party/wine
 * dlls/kernelbase/sync.c GetTickCount64), so a kernel that maps the page once
 * and never ticks it freezes every user-mode clock. This test pins the
 * observable contract: the fields advance across a delay, the two-halves
 * protocol is consistent, and NtQuerySystemTime is monotone and agrees with
 * the page's SystemTime. Per the docs/03 time rule, only ordering and
 * monotonicity are asserted — never wall-clock values.
 */
#include "util.h"

/* The x64 shared page VA (third_party/wine dlls/ntdll/unix/virtual.c
 * user_shared_data = (void *)0x7ffe0000). mingw's user-mode headers omit
 * KUSER_SHARED_DATA (a DDK type), so the fields read here are declared at
 * their fixed offsets as wine/include/ddk/wdm.h lays them out; the same
 * offsets are static_assert-pinned in the kernel's generated abi/ntkeapi.h. */
struct ksystem_time
{
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
};

#define USD_BASE                  ((volatile BYTE *)0x7ffe0000)
#define USD_TICK_COUNT_MULTIPLIER (*(volatile ULONG *)(USD_BASE + 0x004))
#define USD_INTERRUPT_TIME        (*(volatile struct ksystem_time *)(USD_BASE + 0x008))
#define USD_SYSTEM_TIME           (*(volatile struct ksystem_time *)(USD_BASE + 0x014))
#define USD_TICK_COUNT            (*(volatile struct ksystem_time *)(USD_BASE + 0x320))

/* The reader side of the two-halves protocol, exactly as kernelbase's
 * GetTickCount64 spells it. */
static ULONGLONG read_ksystem_time(volatile struct ksystem_time *t)
{
    ULONG high, low;
    do
    {
        high = t->High1Time;
        low = t->LowPart;
    } while (high != (ULONG)t->High2Time);
    return (ULONGLONG)high << 32 | low;
}

START_TEST(time)
{
    NTSTATUS status;
    LARGE_INTEGER delay, t1, t2;

    /* TickCountMultiplier is set once at boot and nonzero (Wine:
     * dlls/ntdll/unix/virtual.c sets 1 << 24; readers ignore it). */
    ok(USD_TICK_COUNT_MULTIPLIER != 0, "TickCountMultiplier is zero");

    ULONGLONG interrupt1 = read_ksystem_time(&USD_INTERRUPT_TIME);
    ULONGLONG system1 = read_ksystem_time(&USD_SYSTEM_TIME);
    ULONGLONG tick1 = read_ksystem_time(&USD_TICK_COUNT);
    ok(interrupt1 != 0, "InterruptTime is zero at start");
    ok(system1 != 0, "SystemTime is zero at start");

    status = NtQuerySystemTime(&t1);
    ok(status == STATUS_SUCCESS, "NtQuerySystemTime -> %08lx", (unsigned long)status);
    ok(t1.QuadPart > 0, "system time not positive (%lld)", (long long)t1.QuadPart);

    /* CUI-1: the clock is wall-true (CMOS RTC on proskrnl, the host clock on
     * the oracle), so SystemTime must be past a floor of 2026-02-01 — one
     * month after the retired fixed-date base, so a kernel that silently
     * fell back to it fails here instead of shipping frozen 2026-01-01
     * timestamps. 155228 days 1601->2026-01-01 (kernel/ke/timer.c derivation,
     * MS FILETIME docs) + 31. */
    {
        ULONGLONG floor2026feb = (155228ULL + 31) * 86400ULL * 10000000ULL;
        ok((ULONGLONG)t1.QuadPart > floor2026feb, "system time %lld predates 2026-02-01",
           (long long)t1.QuadPart);
    }

    /* Sleep 60 ms; every clock must move. The advance lower bound is 20 ms —
     * loose enough for scheduling noise and the oracle's 16 ms page-update
     * cadence (third_party/wine server/fd.c user_shared_data_timeout). */
    delay.QuadPart = -600000; /* 60 ms relative, 100 ns units */
    status = NtDelayExecution(FALSE, &delay);
    ok(status == STATUS_SUCCESS, "NtDelayExecution -> %08lx", (unsigned long)status);

    ULONGLONG interrupt2 = read_ksystem_time(&USD_INTERRUPT_TIME);
    ULONGLONG system2 = read_ksystem_time(&USD_SYSTEM_TIME);
    ULONGLONG tick2 = read_ksystem_time(&USD_TICK_COUNT);

    ok(interrupt2 >= interrupt1 + 200000, "InterruptTime advanced %llu -> %llu",
       (unsigned long long)interrupt1, (unsigned long long)interrupt2);
    ok(system2 > system1, "SystemTime advanced %llu -> %llu", (unsigned long long)system1,
       (unsigned long long)system2);
    ok(tick2 >= tick1 + 1, "TickCount advanced %llu -> %llu", (unsigned long long)tick1,
       (unsigned long long)tick2);
    /* TickCount is milliseconds of InterruptTime (server/fd.c: tick_count =
     * monotonic_time / 10000): the deltas agree to within the update cadence. */
    ok(tick2 - tick1 <= (interrupt2 - interrupt1) / 10000 + 32,
       "TickCount delta %llu vs InterruptTime delta %llu inconsistent",
       (unsigned long long)(tick2 - tick1), (unsigned long long)(interrupt2 - interrupt1));

    status = NtQuerySystemTime(&t2);
    ok(status == STATUS_SUCCESS, "NtQuerySystemTime(2) -> %08lx", (unsigned long)status);
    ok(t2.QuadPart >= t1.QuadPart + 200000, "NtQuerySystemTime advanced %lld -> %lld",
       (long long)t1.QuadPart, (long long)t2.QuadPart);

    /* The page's SystemTime and NtQuerySystemTime read the same clock: a page
     * snapshot taken BEFORE the delay precedes a query made after it. */
    ok(system1 <= (ULONGLONG)t2.QuadPart, "page SystemTime %llu ahead of NtQuerySystemTime %lld",
       (unsigned long long)system1, (long long)t2.QuadPart);
}
