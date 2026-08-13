/*
 * sem_ps/clock_rate.c — the interrupt clock keeps REAL time under kernel
 * load, measured against the invariant TSC.
 *
 * sem_ps/time.c pins that the clocks advance; precise_time.c pins their
 * resolution. This one pins their RATE: a millisecond of wall time is a
 * millisecond of NtQueryPerformanceCounter, even while the kernel itself is
 * busy. The failure it convicts is tick coalescing — a kernel that keeps
 * interrupts disabled across whole system services (proskrnl's dispatcher
 * lock, Art. 3) receives ONE clock interrupt for a multi-millisecond
 * interrupt-off span (the xAPIC IRR holds a single pending instance of a
 * vector, Intel SDM Vol. 3A §11.8.4), and a tick handler that counts
 * "interrupts received" rather than "time elapsed" then loses the
 * difference. Measured on QEMU/KVM before the fix, a syscall-dense boot lost
 * ~90% of its guest seconds — user-observably, SAFlashPlayer.exe computed a
 * frame deadline from rdtsc against a timeGetTime that had fallen minutes
 * behind, armed a five-DAY winmm sleep, and froze on its first frame.
 *
 * Shape: calibrate TSC-per-QPC-unit across an idle sleep (both runners keep
 * honest time while idle — proskrnl's idle loop halts with interrupts
 * enabled), then burn wall time in a syscall-heavy loop (MEM_COMMIT of 4 MiB
 * — the kernel zeroes the pages inline, a long interrupt-off span each
 * call), and require the clock's advance across the burn to be at least half
 * of what the TSC says elapsed. The oracle's clocks are the host's
 * (CLOCK_MONOTONIC) and track the TSC by construction, so this passes there
 * unconditionally; rdtsc is unprivileged on both runners (CR4.TSD clear).
 * The loop is bounded by the TSC, not by the clock under test, so a frozen
 * clock fails the assertion instead of wedging the leg (docs/21 W10).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR, SIZE_T *, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG);

static unsigned long long read_tsc(void)
{
    unsigned int lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)hi << 32) | lo;
}

START_TEST(clock_rate)
{
    NTSTATUS status;
    LARGE_INTEGER q1, q2, q3, freq, delay;

    /* Calibration: TSC cycles per QPC unit across an idle 200 ms sleep. The
     * ratio is taken between the same two instants on both clocks, so it is
     * immune to the sleep overshooting on a loaded host. */
    status = NtQueryPerformanceCounter(&q1, &freq);
    ok(status == STATUS_SUCCESS, "NtQueryPerformanceCounter -> %08lx", (unsigned long)status);
    ok(freq.QuadPart > 0, "frequency not positive (%lld)", (long long)freq.QuadPart);
    unsigned long long t1 = read_tsc();

    delay.QuadPart = -2000000; /* 200 ms relative, 100 ns units */
    status = NtDelayExecution(FALSE, &delay);
    ok(status == STATUS_SUCCESS, "NtDelayExecution -> %08lx", (unsigned long)status);

    status = NtQueryPerformanceCounter(&q2, NULL);
    ok(status == STATUS_SUCCESS, "NtQueryPerformanceCounter(2) -> %08lx", (unsigned long)status);
    unsigned long long t2 = read_tsc();

    ok(q2.QuadPart > q1.QuadPart, "QPC did not advance across a 200 ms sleep (%lld -> %lld)",
       (long long)q1.QuadPart, (long long)q2.QuadPart);
    ok(t2 > t1, "TSC did not advance across a 200 ms sleep");
    if (q2.QuadPart <= q1.QuadPart || t2 <= t1)
        return; /* no usable calibration; the failures above already convict */

    unsigned long long qpcDelta = (unsigned long long)(q2.QuadPart - q1.QuadPart);
    unsigned long long tscPerQpcUnit = (t2 - t1) / qpcDelta;
    ok(tscPerQpcUnit > 0, "TSC slower than the QPC unit?");
    if (tscPerQpcUnit == 0)
        return;

    /* Burn ~1.5 s of WALL time (TSC-bounded) in commit/free of 4 MiB — on
     * proskrnl each commit zeroes 1024 pages inline under the dispatcher
     * lock, which is exactly the interrupt-off span that coalesces ticks. */
    unsigned long long burnEnd = t2 + 15ULL * (t2 - t1) / 2; /* 1.5 s in TSC cycles */
    int allocFailures = 0;
    while (read_tsc() < burnEnd)
    {
        PVOID base = NULL;
        SIZE_T size = 4 * 1024 * 1024;
        status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size,
                                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (status != STATUS_SUCCESS)
        {
            allocFailures++;
            break;
        }
        /* One store per commit: on the oracle the pages are lazy, and a loop
         * of pure mmap/munmap would measure the host's VMA bookkeeping
         * rather than any kernel time. One touch keeps both runners honest
         * without turning the test into a memset benchmark. */
        *(volatile unsigned char *)base = 1;
        SIZE_T freeSize = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &base, &freeSize, MEM_RELEASE);
        if (status != STATUS_SUCCESS)
        {
            allocFailures++;
            break;
        }
    }
    ok(allocFailures == 0, "commit/free loop failed with %08lx", (unsigned long)status);

    status = NtQueryPerformanceCounter(&q3, NULL);
    ok(status == STATUS_SUCCESS, "NtQueryPerformanceCounter(3) -> %08lx", (unsigned long)status);
    unsigned long long t3 = read_tsc();

    unsigned long long measured = (unsigned long long)(q3.QuadPart - q2.QuadPart);
    unsigned long long expected = (t3 - t2) / tscPerQpcUnit;

    /* The conviction: the clock kept at least half of real time — a
     * coalescing kernel keeps ~10%, an honest one ~100%, so the bound is far
     * from both. The upper bound guards the same property from the other
     * side (a clock RACING the TSC is the same bug mirrored) with the same
     * 2x margin. */
    ok(measured >= expected / 2,
       "clock lost time under kernel load: QPC advanced %llu of %llu expected units",
       (unsigned long long)measured, (unsigned long long)expected);
    ok(measured <= expected * 2,
       "clock ran fast under kernel load: QPC advanced %llu of %llu expected units",
       (unsigned long long)measured, (unsigned long long)expected);
}
