/*
 * sem_port/timers.c — waitable timer objects (M10).
 *
 * kernelbase's CreateWaitableTimer/SetWaitableTimer are direct wrappers
 * (dlls/kernelbase/sync.c) and ntdll's timer queues arm one via
 * NtCreateTimer/NtSetTimer (dlls/ntdll/threadpool.c) — msvcrt and every
 * CUI-grade timeout path sit on top. Pinned: notification vs
 * synchronization signalling (mirrors events), the previous-state
 * write-backs, cancel, periodic re-fire, and TimerBasicInformation.
 */
#include "../ntapi.h"

typedef void(CALLBACK *PTIMER_APC_ROUTINE)(PVOID, ULONG, LONG);
NTSYSAPI NTSTATUS NTAPI NtCreateTimer(HANDLE *, ACCESS_MASK, const OBJECT_ATTRIBUTES *, ULONG);
NTSYSAPI NTSTATUS NTAPI NtSetTimer(HANDLE, const LARGE_INTEGER *, PTIMER_APC_ROUTINE, PVOID,
                                   BOOLEAN, ULONG, BOOLEAN *);
NTSYSAPI NTSTATUS NTAPI NtCancelTimer(HANDLE, BOOLEAN *);
typedef enum _TIMER_INFORMATION_CLASS
{
    TimerBasicInformation = 0
} TIMER_INFORMATION_CLASS;
typedef struct _TIMER_BASIC_INFORMATION
{
    LARGE_INTEGER RemainingTime;
    BOOLEAN TimerState;
} TIMER_BASIC_INFORMATION;
NTSYSAPI NTSTATUS NTAPI NtQueryTimer(HANDLE, TIMER_INFORMATION_CLASS, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

#ifndef TIMER_ALL_ACCESS
#define TIMER_ALL_ACCESS 0x001F0003 /* wine/include/winnt.h */
#endif
/* TIMER_TYPE values as wine/include/winternl.h defines them. */
#define TIMER_NOTIFICATION    0
#define TIMER_SYNCHRONIZATION 1

static NTSTATUS wait_ms(HANDLE handle, LONGLONG ms)
{
    LARGE_INTEGER timeout;
    timeout.QuadPart = -ms * 10000;
    return NtWaitForSingleObject(handle, FALSE, &timeout);
}

START_TEST(timers)
{
    NTSTATUS status;
    HANDLE notify = NULL, sync = NULL;
    LARGE_INTEGER due;
    BOOLEAN previous;

    status = NtCreateTimer(&notify, TIMER_ALL_ACCESS, NULL, TIMER_NOTIFICATION);
    ok(status == STATUS_SUCCESS, "create notification -> %08lx", (unsigned long)status);
    status = NtCreateTimer(&sync, TIMER_ALL_ACCESS, NULL, TIMER_SYNCHRONIZATION);
    ok(status == STATUS_SUCCESS, "create synchronization -> %08lx", (unsigned long)status);

    /* Unset timers are not signalled. */
    ok(wait_ms(notify, 0) == STATUS_TIMEOUT, "fresh notification signalled");
    ok(wait_ms(sync, 0) == STATUS_TIMEOUT, "fresh synchronization signalled");

    /* Arm 40 ms out: TimerState off, RemainingTime positive, then it fires;
     * a notification timer stays signalled for every waiter. */
    due.QuadPart = -400000;
    previous = TRUE;
    status = NtSetTimer(notify, &due, NULL, NULL, FALSE, 0, &previous);
    ok(status == STATUS_SUCCESS, "set notification -> %08lx", (unsigned long)status);
    ok(!previous, "previous state set (%d)", previous);

    TIMER_BASIC_INFORMATION info;
    ULONG returned = 0;
    memset(&info, 0, sizeof(info));
    status = NtQueryTimer(notify, TimerBasicInformation, &info, sizeof(info), &returned);
    ok(status == STATUS_SUCCESS, "query armed -> %08lx", (unsigned long)status);
    ok(!info.TimerState, "armed timer already signalled");
    ok(info.RemainingTime.QuadPart > 0, "armed remaining %lld",
       (long long)info.RemainingTime.QuadPart);

    ok(wait_ms(notify, 5000) == STATUS_SUCCESS, "notification never fired");
    ok(wait_ms(notify, 0) == STATUS_SUCCESS, "notification did not stay signalled");
    memset(&info, 0, sizeof(info));
    status = NtQueryTimer(notify, TimerBasicInformation, &info, sizeof(info), NULL);
    ok(status == STATUS_SUCCESS, "query fired -> %08lx", (unsigned long)status);
    ok(info.TimerState, "fired timer not signalled");

    /* Synchronization: one wait consumes the signal. */
    previous = TRUE;
    status = NtSetTimer(sync, &due, NULL, NULL, FALSE, 0, &previous);
    ok(status == STATUS_SUCCESS && !previous, "set synchronization -> %08lx prev %d",
       (unsigned long)status, previous);
    ok(wait_ms(sync, 5000) == STATUS_SUCCESS, "synchronization never fired");
    ok(wait_ms(sync, 0) == STATUS_TIMEOUT, "synchronization stayed signalled");

    /* Cancel disarms a pending timer (state reports not-signalled). */
    due.QuadPart = -10000000; /* 1 s out */
    NtSetTimer(notify, &due, NULL, NULL, FALSE, 0, NULL);
    previous = TRUE;
    status = NtCancelTimer(notify, &previous);
    ok(status == STATUS_SUCCESS, "cancel -> %08lx", (unsigned long)status);
    ok(!previous, "cancelled timer reported signalled");
    ok(wait_ms(notify, 100) == STATUS_TIMEOUT, "cancelled timer fired");

    /* Periodic synchronization timer: consecutive waits are satisfied by
     * consecutive periods. */
    due.QuadPart = -300000; /* first fire 30 ms */
    status = NtSetTimer(sync, &due, NULL, NULL, FALSE, 30, NULL);
    ok(status == STATUS_SUCCESS, "set periodic -> %08lx", (unsigned long)status);
    ok(wait_ms(sync, 5000) == STATUS_SUCCESS, "periodic fire 1");
    ok(wait_ms(sync, 5000) == STATUS_SUCCESS, "periodic fire 2");
    NtCancelTimer(sync, NULL);

    NtClose(notify);
    NtClose(sync);
}
