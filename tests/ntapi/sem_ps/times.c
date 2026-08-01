/*
 * sem_ps/times.c — ProcessTimes, ThreadTimes and
 * SystemProcessorPerformanceInformation (CUI-6).
 *
 * The GetProcessTimes/GetThreadTimes/GetSystemTimes surface. Oracle
 * behaviour pinned from the pinned tree: ProcessTimes wants sizeof
 * exactly — a short buffer refuses with the needed length, an over-long
 * one fills the struct AND refuses (dlls/ntdll/unix/process.c); self
 * user+kernel time is real and grows under a CPU burn; ThreadTimes carries
 * real create/exit stamps (server/thread.c) and real CPU time for a live
 * thread (unix/thread.c get_thread_times); the processor-performance class
 * scales its answer to whole entries, refuses a zero-entry buffer, folds
 * idle INTO kernel time, and idle grows while the machine sleeps
 * (unix/system.c).
 */
#include "util.h"

/* Info-class values as wine/include/winternl.h (mingw's enums omit some
 * names; the oracle run validates the values). */
#ifndef NtCurrentThread
#define NtCurrentThread() ((HANDLE) ~(ULONG_PTR)1)
#endif

#define PS_ProcessTimes                          ((PROCESSINFOCLASS)4)
#define PS_ThreadTimes                           ((THREADINFOCLASS)1)
#define PS_SystemProcessorPerformanceInformation ((SYSTEM_INFORMATION_CLASS)8)

/* x64 layouts as wine/include/winternl.h (snake_case per the harness
 * convention for locally declared shapes). */
typedef struct
{
    LARGE_INTEGER create_time;
    LARGE_INTEGER exit_time;
    LARGE_INTEGER kernel_time;
    LARGE_INTEGER user_time;
} ps_kernel_user_times;

typedef struct
{
    LARGE_INTEGER idle_time;
    LARGE_INTEGER kernel_time;
    LARGE_INTEGER user_time;
    LARGE_INTEGER reserved1[2];
    ULONG reserved2;
} ps_processor_perf;

NTSYSAPI NTSTATUS NTAPI NtQuerySystemTime(PLARGE_INTEGER);

static LONGLONG now_100ns(void)
{
    LARGE_INTEGER now;
    NtQuerySystemTime(&now);
    return now.QuadPart;
}

/* Burn wall-clock CPU for ~ms milliseconds (no sleeping — the point is to
 * accumulate charged time). */
static void burn_ms(LONGLONG ms)
{
    volatile ULONG sink = 0;
    LONGLONG until = now_100ns() + ms * 10000;
    while (now_100ns() < until)
    {
        for (int i = 0; i < 1000; i++)
        {
            sink += (ULONG)i;
        }
    }
}

static volatile LONG spinner_stop;
static DWORD WINAPI spinner_worker(void *param)
{
    (void)param;
    volatile ULONG sink = 0;
    while (!spinner_stop)
    {
        for (int i = 0; i < 1000; i++)
        {
            sink += (ULONG)i;
        }
    }
    return 0;
}

static DWORD WINAPI brief_worker(void *param)
{
    (void)param;
    return 0;
}

START_TEST(times)
{
    NTSTATUS status;
    ps_kernel_user_times times1, times2;
    ULONG retlen;

    /* --- ProcessTimes length protocol ------------------------------------ */
    retlen = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessTimes, &times1,
                                       sizeof(times1) - 1, &retlen);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short ProcessTimes -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(times1), "short ProcessTimes retlen %lu", (unsigned long)retlen);
    {
        /* An over-long buffer is filled AND refused. */
        char big[sizeof(ps_kernel_user_times) + 8];
        memset(big, 0, sizeof(big));
        retlen = 0;
        status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessTimes, big, sizeof(big),
                                           &retlen);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "long ProcessTimes -> %08lx",
           (unsigned long)status);
        ok(((ps_kernel_user_times *)big)->create_time.QuadPart != 0, "long buffer still filled");
    }

    /* --- ProcessTimes on self --------------------------------------------- */
    memset(&times1, 0, sizeof(times1));
    retlen = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessTimes, &times1, sizeof(times1),
                                       &retlen);
    ok(status == STATUS_SUCCESS, "ProcessTimes -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(times1), "ProcessTimes retlen %lu", (unsigned long)retlen);
    ok(times1.create_time.QuadPart > 0, "create time set");
    ok(times1.create_time.QuadPart <= now_100ns(), "create time not in the future");
    ok(times1.exit_time.QuadPart == 0, "exit time zero while alive");

    burn_ms(150);
    memset(&times2, 0, sizeof(times2));
    status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessTimes, &times2, sizeof(times2),
                                       NULL);
    ok(status == STATUS_SUCCESS, "ProcessTimes after burn -> %08lx", (unsigned long)status);
    ok(times2.user_time.QuadPart + times2.kernel_time.QuadPart > 0, "cpu time accumulated");
    ok(times2.user_time.QuadPart >= times1.user_time.QuadPart &&
           times2.kernel_time.QuadPart >= times1.kernel_time.QuadPart,
       "cpu time nondecreasing");
    ok(times2.create_time.QuadPart == times1.create_time.QuadPart, "create time stable");

    /* --- ThreadTimes on self ----------------------------------------------- */
    memset(&times1, 0, sizeof(times1));
    retlen = 0;
    status = NtQueryInformationThread(NtCurrentThread(), PS_ThreadTimes, &times1, sizeof(times1),
                                      &retlen);
    ok(status == STATUS_SUCCESS, "ThreadTimes self -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(times1), "ThreadTimes retlen %lu", (unsigned long)retlen);
    ok(times1.create_time.QuadPart > 0, "thread create time set");
    ok(times1.exit_time.QuadPart == 0, "thread exit time zero while alive");
    ok(times1.user_time.QuadPart + times1.kernel_time.QuadPart > 0,
       "self thread cpu time after the burn");

    /* --- ThreadTimes on a live foreign spinner ------------------------------ */
    spinner_stop = 0;
    HANDLE spinner = CreateThread(NULL, 0, spinner_worker, NULL, 0, NULL);
    ok(spinner != NULL, "create spinner");
    Sleep(150); /* the sleep hands the machine to the spinner */
    memset(&times1, 0, sizeof(times1));
    status = NtQueryInformationThread(spinner, PS_ThreadTimes, &times1, sizeof(times1), NULL);
    ok(status == STATUS_SUCCESS, "ThreadTimes foreign -> %08lx", (unsigned long)status);
    ok(times1.create_time.QuadPart > 0, "foreign create time set");
    ok(times1.exit_time.QuadPart == 0, "foreign exit time zero while alive");
    ok(times1.user_time.QuadPart + times1.kernel_time.QuadPart > 0, "foreign spinner charged");
    InterlockedExchange(&spinner_stop, 1);
    WaitForSingleObject(spinner, 5000);
    CloseHandle(spinner);

    /* --- ThreadTimes on an exited thread ------------------------------------ */
    HANDLE brief = CreateThread(NULL, 0, brief_worker, NULL, 0, NULL);
    ok(brief != NULL, "create brief worker");
    WaitForSingleObject(brief, 5000);
    memset(&times1, 0, sizeof(times1));
    status = NtQueryInformationThread(brief, PS_ThreadTimes, &times1, sizeof(times1), NULL);
    ok(status == STATUS_SUCCESS, "ThreadTimes exited -> %08lx", (unsigned long)status);
    ok(times1.exit_time.QuadPart != 0, "exited thread has exit time");
    ok(times1.exit_time.QuadPart >= times1.create_time.QuadPart, "exit >= create");
    CloseHandle(brief);

    /* --- SystemProcessorPerformanceInformation ------------------------------ */
    ps_processor_perf perf1, perf2;
    retlen = 0xdead;
    status = NtQuerySystemInformation(PS_SystemProcessorPerformanceInformation, &perf1, 0, &retlen);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "zero-entry perf -> %08lx", (unsigned long)status);
    ok(retlen == 0, "zero-entry perf retlen %lu", (unsigned long)retlen);

    memset(&perf1, 0, sizeof(perf1));
    retlen = 0;
    status = NtQuerySystemInformation(PS_SystemProcessorPerformanceInformation, &perf1,
                                      sizeof(perf1), &retlen);
    ok(status == STATUS_SUCCESS, "one-entry perf -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(perf1), "one-entry perf retlen %lu", (unsigned long)retlen);
    ok(perf1.kernel_time.QuadPart >= perf1.idle_time.QuadPart, "kernel time folds idle in");

    Sleep(60);
    memset(&perf2, 0, sizeof(perf2));
    status = NtQuerySystemInformation(PS_SystemProcessorPerformanceInformation, &perf2,
                                      sizeof(perf2), NULL);
    ok(status == STATUS_SUCCESS, "perf again -> %08lx", (unsigned long)status);
    ok(perf2.idle_time.QuadPart > perf1.idle_time.QuadPart, "idle time grew across a sleep");
    ok(perf2.kernel_time.QuadPart >= perf1.kernel_time.QuadPart &&
           perf2.user_time.QuadPart >= perf1.user_time.QuadPart,
       "perf counters nondecreasing");
}
