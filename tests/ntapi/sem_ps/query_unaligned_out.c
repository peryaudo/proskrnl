/*
 * sem_ps/query_unaligned_out.c — the process and system query classes a
 * WOW64 thunk forwards UNTRANSLATED accept a 4-mod-8 output buffer.
 *
 * misaligned_out.c pinned this for the two time queries, whose output is a
 * bare LARGE_INTEGER. The same thing is true of every class wow64.dll passes
 * straight down, and those are named in the pinned tree rather than guessed:
 *
 *   ProcessIoCounters, ProcessTimes  — dlls/wow64/process.c
 *       wow64_NtQueryInformationProcess groups them with a bare
 *       `return NtQueryInformationProcess( handle, class, ptr, len, retlen )`
 *       under a `FIXME: check buffer alignment` comment, i.e. the 32-bit
 *       caller's pointer reaches the 64-bit kernel exactly as it was;
 *   SystemPerformanceInformation, SystemProcessorPerformanceInformation,
 *   SystemProcessorIdleCycleTimeInformation — dlls/wow64/system.c
 *       wow64_NtQuerySystemInformation lists them in the pass-through arm.
 *
 * Every one of them leads with (or is entirely made of) 8-byte counters, and
 * an i386 caller's stack struct is 4-byte aligned — so the ordinary WOW64
 * call is a 4-mod-8 output. A kernel that probes these for 8-byte alignment
 * answers STATUS_DATATYPE_MISALIGNMENT where the oracle answers the counters,
 * and Wine's PE callers do not check the status: that is exactly how the
 * misaligned time queries fed SAFlashPlayer.exe uninitialized stack garbage.
 *
 * Each case asserts the value was WRITTEN, not just the status: the answer
 * through the misaligned pointer must equal (or, for a monotone counter,
 * bracket) the answer through an aligned one. Values are read back with
 * memcpy — the TEST must not commit the misaligned access it is pinning
 * against.
 *
 * Oracle-first (G5).
 */
#include "util.h"

/* Info-class values as wine/include/winternl.h (times.c carries the same
 * local spellings; mingw's enums omit some of the names). */
#define PS_ProcessIoCounters                       ((PROCESSINFOCLASS)2)
#define PS_ProcessTimes                            ((PROCESSINFOCLASS)4)
#define PS_SystemPerformanceInformation            ((SYSTEM_INFORMATION_CLASS)2)
#define PS_SystemProcessorPerformanceInformation   ((SYSTEM_INFORMATION_CLASS)8)
#define PS_SystemProcessorIdleCycleTimeInformation ((SYSTEM_INFORMATION_CLASS)83)

/* The x64 SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION layout, as
 * wine/include/winternl.h (times.c carries the same local shape). */
typedef struct
{
    LARGE_INTEGER idle_time;
    LARGE_INTEGER kernel_time;
    LARGE_INTEGER user_time;
    LARGE_INTEGER reserved1[2];
    ULONG reserved2;
} ps_processor_perf;

/* 8-aligned slab the deltas offset into. */
static long long aligned_store[256];

static void *slot(unsigned delta)
{
    memset(aligned_store, 0xa5, sizeof(aligned_store));
    return (unsigned char *)aligned_store + delta;
}

START_TEST(query_unaligned_out)
{
    NTSTATUS status;
    ULONG retlen;

    /* --- ProcessTimes ----------------------------------------------------
     * Create/exit stamps are fixed for the life of the process, so they must
     * come back byte-identical; the CPU counters only grow, so they are
     * bracketed instead. */
    {
        LARGE_INTEGER before[4], after[4], got[4];

        retlen = 0;
        status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessTimes, before,
                                           sizeof(before), &retlen);
        ok(status == STATUS_SUCCESS, "aligned ProcessTimes -> %08lx", (unsigned long)status);

        void *at = slot(4);
        ok(((ULONG_PTR)at & 7) == 4, "ProcessTimes slot is 4-mod-8 (%p)", at);
        retlen = 0;
        status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessTimes, at, sizeof(got),
                                           &retlen);
        ok(status == STATUS_SUCCESS, "4-mod-8 ProcessTimes -> %08lx", (unsigned long)status);
        ok(retlen == sizeof(got), "4-mod-8 ProcessTimes retlen %lu", (unsigned long)retlen);
        memcpy(got, at, sizeof(got));

        status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessTimes, after,
                                           sizeof(after), &retlen);
        ok(status == STATUS_SUCCESS, "aligned ProcessTimes again -> %08lx", (unsigned long)status);

        ok(got[0].QuadPart == before[0].QuadPart, "CreateTime %lld / %lld",
           (long long)got[0].QuadPart, (long long)before[0].QuadPart);
        ok(got[1].QuadPart == before[1].QuadPart, "ExitTime %lld / %lld",
           (long long)got[1].QuadPart, (long long)before[1].QuadPart);
        ok(got[2].QuadPart >= before[2].QuadPart && got[2].QuadPart <= after[2].QuadPart,
           "KernelTime %lld outside [%lld,%lld]", (long long)got[2].QuadPart,
           (long long)before[2].QuadPart, (long long)after[2].QuadPart);
        ok(got[3].QuadPart >= before[3].QuadPart && got[3].QuadPart <= after[3].QuadPart,
           "UserTime %lld outside [%lld,%lld]", (long long)got[3].QuadPart,
           (long long)before[3].QuadPart, (long long)after[3].QuadPart);
    }

    /* --- ProcessIoCounters: six ULONGLONGs, all monotone ------------------ */
    {
        ULONGLONG before[6], after[6], got[6];
        unsigned i;

        retlen = 0;
        status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessIoCounters, before,
                                           sizeof(before), &retlen);
        ok(status == STATUS_SUCCESS, "aligned ProcessIoCounters -> %08lx", (unsigned long)status);

        void *at = slot(4);
        retlen = 0;
        status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessIoCounters, at,
                                           sizeof(got), &retlen);
        ok(status == STATUS_SUCCESS, "4-mod-8 ProcessIoCounters -> %08lx", (unsigned long)status);
        ok(retlen == sizeof(got), "4-mod-8 ProcessIoCounters retlen %lu", (unsigned long)retlen);
        memcpy(got, at, sizeof(got));

        status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessIoCounters, after,
                                           sizeof(after), &retlen);
        ok(status == STATUS_SUCCESS, "aligned ProcessIoCounters again -> %08lx",
           (unsigned long)status);
        for (i = 0; i < 6; i++)
        {
            ok(got[i] >= before[i] && got[i] <= after[i], "IoCounters[%u] %llu outside [%llu,%llu]",
               i, (unsigned long long)got[i], (unsigned long long)before[i],
               (unsigned long long)after[i]);
        }
    }

    /* --- SystemProcessorPerformanceInformation --------------------------- *
     * One entry per processor; the first entry's idle time is monotone. */
    {
        LARGE_INTEGER before[8], after[8], got[8];
        ULONG entry = (ULONG)sizeof(ps_processor_perf);

        retlen = 0;
        status = NtQuerySystemInformation(PS_SystemProcessorPerformanceInformation, before, entry,
                                          &retlen);
        ok(status == STATUS_SUCCESS, "aligned processor perf -> %08lx", (unsigned long)status);

        void *at = slot(4);
        retlen = 0;
        status =
            NtQuerySystemInformation(PS_SystemProcessorPerformanceInformation, at, entry, &retlen);
        ok(status == STATUS_SUCCESS, "4-mod-8 processor perf -> %08lx", (unsigned long)status);
        ok(retlen == entry, "4-mod-8 processor perf retlen %lu", (unsigned long)retlen);
        memcpy(got, at, entry);

        status = NtQuerySystemInformation(PS_SystemProcessorPerformanceInformation, after, entry,
                                          &retlen);
        ok(status == STATUS_SUCCESS, "aligned processor perf again -> %08lx",
           (unsigned long)status);
        ok(got[0].QuadPart >= before[0].QuadPart && got[0].QuadPart <= after[0].QuadPart,
           "IdleTime %lld outside [%lld,%lld]", (long long)got[0].QuadPart,
           (long long)before[0].QuadPart, (long long)after[0].QuadPart);
    }

    /* --- SystemPerformanceInformation ------------------------------------ *
     * A long struct of counters. Only that it SUCCEEDS and reports its own
     * length is pinned: individual fields move between calls, and what they
     * contain is already pinned elsewhere. */
    {
        unsigned char big[1024];
        ULONG needed = 0;

        status =
            NtQuerySystemInformation(PS_SystemPerformanceInformation, big, sizeof(big), &needed);
        ok(status == STATUS_SUCCESS || status == STATUS_INFO_LENGTH_MISMATCH,
           "aligned system perf -> %08lx", (unsigned long)status);
        if (status == STATUS_SUCCESS && needed != 0 && needed <= sizeof(aligned_store) - 8)
        {
            ULONG got = 0;
            void *at = slot(4);
            status = NtQuerySystemInformation(PS_SystemPerformanceInformation, at, needed, &got);
            ok(status == STATUS_SUCCESS, "4-mod-8 system perf -> %08lx", (unsigned long)status);
            ok(got == needed, "4-mod-8 system perf retlen %lu / %lu", (unsigned long)got,
               (unsigned long)needed);
        }
    }

    /* --- SystemProcessorIdleCycleTimeInformation -------------------------- *
     * A bare ULONG64 per processor: the whole answer is 8-byte counters, and
     * the class exists to be watched growing. */
    {
        ULONG64 before[8], got[8];

        retlen = 0;
        status = NtQuerySystemInformation(PS_SystemProcessorIdleCycleTimeInformation, before,
                                          sizeof(ULONG64), &retlen);
        if (status == STATUS_SUCCESS)
        {
            void *at = slot(4);
            retlen = 0;
            status = NtQuerySystemInformation(PS_SystemProcessorIdleCycleTimeInformation, at,
                                              sizeof(ULONG64), &retlen);
            ok(status == STATUS_SUCCESS, "4-mod-8 idle cycle time -> %08lx", (unsigned long)status);
            memcpy(got, at, sizeof(ULONG64));
            ok(got[0] >= before[0], "idle cycle time went backwards (%llu / %llu)",
               (unsigned long long)got[0], (unsigned long long)before[0]);
        }
    }
}
