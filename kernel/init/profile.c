/* kernel/init/profile.c — see profile.h. Debug instrumentation only. */
#include "kernel/init/profile.h"
#include "kernel/ke/ke.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/init/panic.h"
#include "kernel/syscall/syscall.h"

#include "arch/x86_64/lapic.h"

#include "abi/syscall_numbers.h"

BOOLEAN KiProfileEnabled = FALSE;

/* One row per syscall id. 264 ids * 40 bytes ~ 10 KiB of static data, the
 * trace ring's order of magnitude (kernel/init/trace.c) and for the same
 * reason: a debug channel pays in static memory, never in a pool allocation
 * the machine it is diagnosing has to succeed at. */
typedef struct
{
    uint64_t count;
    uint64_t wallTsc; /* entry -> exit, INCLUDING every park in between */
    uint64_t cpuTsc;  /* on-CPU only: parks subtracted at KiSwapToNext */
    uint64_t previousCount;
    uint64_t previousWallTsc; /* the last tick line's readings, for its deltas */
    uint64_t previousCpuTsc;
} KI_SYSCALL_PROFILE;

static KI_SYSCALL_PROFILE KiSyscallProfile[NTSYS_SYSCALL_LIMIT];
/* The volume counters (profile.h): events and their amounts, plus the last
 * tick line's readings for its delta. */
static uint64_t KiProfileCounters[KiProfileCounterCount];
static uint64_t KiProfileAmounts[KiProfileCounterCount];
static uint64_t KiProfilePreviousAmounts[KiProfileCounterCount];

void KiProfileCount(KI_PROFILE_COUNTER counter, uint64_t amount)
{
    if (!KiProfileEnabled || (unsigned)counter >= (unsigned)KiProfileCounterCount)
    {
        return;
    }
    KiProfileCounters[counter]++;
    KiProfileAmounts[counter] += amount;
}

static uint64_t KiProfileTickLast;  /* KeTickCount at the last delta line */
static uint64_t KiProfileIdleLast;  /* idle milliseconds at the same instant */
static uint64_t KiProfileStartTick; /* when arming happened */

void KiEnableProfiling(void)
{
    KiProfileEnabled = TRUE;
    KiProfileStartTick = KeTickCount;
    KiProfileTickLast = KeTickCount;
    KiProfileIdleLast = KiIdleTime100ns / KI_100NS_PER_TICK;
    DbgPrint("[PROF] boot profiler armed (Hardware\\qemu Profile): serial lines are "
             "timestamped, syscall totals ride the panic dump\n");
}

/* Cycles -> milliseconds, with the clock's own rate. Before calibration the
 * rate is 0 and there is nothing honest to report, so the profiler answers 0
 * rather than dividing. */
static uint64_t KiProfileMilliseconds(uint64_t cycles)
{
    uint64_t rate = KiTscPerMillisecond;
    return rate != 0 ? cycles / rate : 0;
}

void KiProfileSyscallEnter(PKTHREAD thread, uint64_t number)
{
    if (!KiProfileEnabled || thread == 0 || number >= NTSYS_SYSCALL_LIMIT)
    {
        return;
    }
    uint64_t now = KiReadTimestampCounter();
    /* +1 so that 0 is "no syscall in flight" — id 0 is a real service. */
    thread->profileSyscall = number + 1;
    thread->profileEntryTsc = now;
    thread->profileResumeTsc = now;
    thread->profileCpuTsc = 0;
}

void KiProfileSyscallExit(PKTHREAD thread)
{
    if (!KiProfileEnabled || thread == 0 || thread->profileSyscall == 0)
    {
        return;
    }
    uint64_t number = thread->profileSyscall - 1;
    uint64_t now = KiReadTimestampCounter();
    KI_SYSCALL_PROFILE *row = &KiSyscallProfile[number];
    row->count++;
    row->wallTsc += now - thread->profileEntryTsc;
    row->cpuTsc += thread->profileCpuTsc + (now - thread->profileResumeTsc);
    thread->profileSyscall = 0;
}

void KiProfileSwitch(PKTHREAD old, PKTHREAD next)
{
    if (!KiProfileEnabled)
    {
        return;
    }
    ASSERT(KiIsDispatcherLockHeld());
    uint64_t now = KiReadTimestampCounter();
    /* `old` stops accruing here whether or not it is inside a service; a
     * thread with none in flight simply has nothing to bank. */
    if (old != 0 && old->profileSyscall != 0)
    {
        old->profileCpuTsc += now - old->profileResumeTsc;
    }
    if (next != 0)
    {
        next->profileResumeTsc = now;
    }
}

/* The busiest rows of the WHOLE run, by the given key. A selection scan
 * rather than a sort: the array is never reordered (a dump must not perturb
 * what a later dump reports) and `wanted` is a handful. */
static int KiProfileTopRow(int byCpu, uint64_t below)
{
    int best = -1;
    uint64_t bestValue = 0;
    for (int id = 0; id < (int)NTSYS_SYSCALL_LIMIT; id++)
    {
        uint64_t value = byCpu ? KiSyscallProfile[id].cpuTsc : KiSyscallProfile[id].wallTsc;
        if (KiSyscallProfile[id].count == 0 || value >= below || value <= bestValue)
        {
            continue;
        }
        best = id;
        bestValue = value;
    }
    return best;
}

static void KiDumpProfileColumn(const char *title, int byCpu, int wanted)
{
    DbgPrint("  %s\n", title);
    uint64_t below = ~(uint64_t)0;
    for (int rank = 0; rank < wanted; rank++)
    {
        int id = KiProfileTopRow(byCpu, below);
        if (id < 0)
        {
            break;
        }
        const KI_SYSCALL_PROFILE *row = &KiSyscallProfile[id];
        below = byCpu ? row->cpuTsc : row->wallTsc;
        if (below == 0)
        {
            break;
        }
        DbgPrint("    %s calls=%lu wall=%lums cpu=%lums\n", KiSystemCallName((uint64_t)id),
                 row->count, KiProfileMilliseconds(row->wallTsc),
                 KiProfileMilliseconds(row->cpuTsc));
    }
}

void KiDumpSyscallProfile(void)
{
    if (!KiProfileEnabled)
    {
        return;
    }
    uint64_t calls = 0;
    uint64_t cpuTsc = 0;
    for (int id = 0; id < (int)NTSYS_SYSCALL_LIMIT; id++)
    {
        calls += KiSyscallProfile[id].count;
        cpuTsc += KiSyscallProfile[id].cpuTsc;
    }
    /* The boot's whole time budget in three numbers, so a reader can tell a
     * kernel-bound boot from a Wine-bound one before reading a single row:
     * uptime is the wall clock, idle is what the machine spent with nobody
     * runnable (KiUpdateClock's sampling), and syscall-cpu is what ring 0
     * spent inside services. Ring-3 CPU is what is left over. */
    uint64_t uptime = KeTickCount - KiProfileStartTick;
    uint64_t idle = KiIdleTime100ns / KI_100NS_PER_TICK;
    uint64_t kernel = KiProfileMilliseconds(cpuTsc);
    DbgPrint(
        "[PROF] syscalls=%lu over %lums: idle=%lums syscall-cpu=%lums rest(ring-3+irq)=%lums\n",
        calls, uptime, idle, kernel, uptime > idle + kernel ? uptime - idle - kernel : 0);
    DbgPrint("[PROF] volume: reads=%lu (%lu sectors, %lu of them uncached "
             "single-sector metadata) writes=%lu (%lu sectors) "
             "whole-file cache loads=%lu (%lu KiB)\n",
             KiProfileCounters[KiProfileBlockRead], KiProfileAmounts[KiProfileBlockRead],
             KiProfileCounters[KiProfileMetaRead], KiProfileCounters[KiProfileBlockWrite],
             KiProfileAmounts[KiProfileBlockWrite], KiProfileCounters[KiProfileFileCacheLoad],
             KiProfileAmounts[KiProfileFileCacheLoad] / 1024);
    KiDumpProfileColumn("by WALL time (a service that waits is a service that blocks someone):", 0,
                        12);
    KiDumpProfileColumn("by ON-CPU time (a service that costs is a service that computes):", 1, 12);
}

/* One ranking on the once-a-second line: the top services of THIS second by
 * the given key, each with the calls it took and the milliseconds it spent.
 * The scan mirrors KiProfileTopRow's — no reordering, a handful wanted. */
static void KiProfileTickColumn(const char *label, int byCpu)
{
    DbgPrint(" %s:", label);
    uint64_t below = ~(uint64_t)0;
    for (int rank = 0; rank < 4; rank++)
    {
        int best = -1;
        uint64_t bestDelta = 0;
        for (int id = 0; id < (int)NTSYS_SYSCALL_LIMIT; id++)
        {
            const KI_SYSCALL_PROFILE *row = &KiSyscallProfile[id];
            uint64_t delta =
                byCpu ? row->cpuTsc - row->previousCpuTsc : row->wallTsc - row->previousWallTsc;
            if (delta >= below || delta <= bestDelta)
            {
                continue;
            }
            best = id;
            bestDelta = delta;
        }
        if (best < 0 || bestDelta == 0)
        {
            break;
        }
        below = bestDelta;
        DbgPrint(" %s(%lu/%lums)", KiSystemCallName((uint64_t)best),
                 KiSyscallProfile[best].count - KiSyscallProfile[best].previousCount,
                 KiProfileMilliseconds(bestDelta));
    }
}

/* Once a second, the delta: which services this second went into. The
 * aggregate cannot say WHEN — a boot that spends its first ten seconds in
 * one service and its last ten in another reads identically to one that
 * mixes them — and "when" is exactly what a phase-by-phase boot profile is.
 */
void KiProfileTick(void)
{
    if (!KiProfileEnabled)
    {
        return;
    }
    ASSERT(KiIsDispatcherLockHeld());
    if (KeTickCount - KiProfileTickLast < 1000)
    {
        return;
    }
    uint64_t idle = KiIdleTime100ns / KI_100NS_PER_TICK;
    /* How much of the second nobody was runnable. A profiled boot whose slow
     * stretch is mostly idle is waiting for something (a device, a timeout),
     * not computing — and that is a different investigation from a busy one,
     * so the line says which before it says what. */
    DbgPrint("[PROF] +1s idle=%lums/%lums", idle - KiProfileIdleLast,
             KeTickCount - KiProfileTickLast);
    DbgPrint(" blk=%lur/%luw sectors, %lu file loads",
             KiProfileAmounts[KiProfileBlockRead] - KiProfilePreviousAmounts[KiProfileBlockRead],
             KiProfileAmounts[KiProfileBlockWrite] - KiProfilePreviousAmounts[KiProfileBlockWrite],
             KiProfileCounters[KiProfileFileCacheLoad] -
                 KiProfilePreviousAmounts[KiProfileFileCacheLoad]);
    KiProfilePreviousAmounts[KiProfileBlockRead] = KiProfileAmounts[KiProfileBlockRead];
    KiProfilePreviousAmounts[KiProfileBlockWrite] = KiProfileAmounts[KiProfileBlockWrite];
    KiProfilePreviousAmounts[KiProfileFileCacheLoad] = KiProfileCounters[KiProfileFileCacheLoad];
    KiProfileIdleLast = idle;
    KiProfileTickLast = KeTickCount;

    /* BOTH keys on the line, because either alone misleads. Ranked by wall,
     * the list is always the parking services (a client blocked on the
     * server, a pump on its completion port) — true and useless. Ranked by
     * on-CPU, it is what the machine actually computed in that second, which
     * is the answer to "why is this second passing at all" only when the
     * machine was not simply idle. Read them together with the idle share
     * the panic dump prints. */
    KiProfileTickColumn("cpu", 1);
    KiProfileTickColumn("wall", 0);
    DbgPrint("\n");
    for (int id = 0; id < (int)NTSYS_SYSCALL_LIMIT; id++)
    {
        KiSyscallProfile[id].previousWallTsc = KiSyscallProfile[id].wallTsc;
        KiSyscallProfile[id].previousCpuTsc = KiSyscallProfile[id].cpuTsc;
        KiSyscallProfile[id].previousCount = KiSyscallProfile[id].count;
    }
}
