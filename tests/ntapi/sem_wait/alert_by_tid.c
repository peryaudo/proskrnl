/*
 * sem_wait/alert_by_tid.c — the thread-id alert pair (M10).
 *
 * NtWaitForAlertByThreadId / NtAlertThreadByThreadId are the primitive under
 * ntdll's RtlWaitOnAddress, contended SRW locks, and contended critical
 * sections (dlls/ntdll/sync.c) — the moment two threads share a heap lock,
 * a kernel that fakes these spins or deadlocks. The contract (Wine
 * dlls/ntdll/unix/sync.c): one latched alert bit per thread id — alerting a
 * thread that is not waiting arms the bit and its NEXT wait consumes it
 * (STATUS_ALERTED); a wait with no pending alert blocks until the alert or
 * the timeout (STATUS_TIMEOUT). The wait's address argument is opaque.
 */
#include "../ntapi.h"

NTSYSAPI NTSTATUS NTAPI NtAlertThreadByThreadId(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtWaitForAlertByThreadId(const void *, const LARGE_INTEGER *);

static HANDLE main_tid;
static NTSTATUS waiter_status;

static DWORD WINAPI waiter_thread(void *param)
{
    /* Blocking wait (generous 5 s bound so a lost alert still terminates the
     * run); the main thread alerts us ~50 ms in. */
    LARGE_INTEGER bound;
    int dummy = 0;
    (void)param;
    bound.QuadPart = -50000000;
    waiter_status = NtWaitForAlertByThreadId(&dummy, &bound);
    /* Wake the main thread symmetrically: alert flows both directions. */
    NtAlertThreadByThreadId(main_tid);
    return 0;
}

START_TEST(alert_by_tid)
{
    NTSTATUS status;
    LARGE_INTEGER timeout;
    int dummy = 0;

    HANDLE self = (HANDLE)(ULONG_PTR)GetCurrentThreadId();
    main_tid = self;

    /* No alert pending: a zero timeout comes straight back. */
    timeout.QuadPart = 0;
    status = NtWaitForAlertByThreadId(&dummy, &timeout);
    ok(status == STATUS_TIMEOUT, "wait with no alert -> %08lx", (unsigned long)status);

    /* A short bounded wait with no alert times out (and actually waits). */
    timeout.QuadPart = -100000; /* 10 ms */
    status = NtWaitForAlertByThreadId(&dummy, &timeout);
    ok(status == STATUS_TIMEOUT, "bounded wait -> %08lx", (unsigned long)status);

    /* The latch: alert self (not waiting), then consume it. */
    status = NtAlertThreadByThreadId(self);
    ok(status == STATUS_SUCCESS, "alert self -> %08lx", (unsigned long)status);
    timeout.QuadPart = 0;
    status = NtWaitForAlertByThreadId(&dummy, &timeout);
    ok(status == STATUS_ALERTED, "consume latched alert -> %08lx", (unsigned long)status);

    /* Consumed: the next zero-timeout wait times out again. */
    status = NtWaitForAlertByThreadId(&dummy, &timeout);
    ok(status == STATUS_TIMEOUT, "latch consumed -> %08lx", (unsigned long)status);

    /* Two alerts collapse into one latch bit. */
    NtAlertThreadByThreadId(self);
    status = NtAlertThreadByThreadId(self);
    ok(status == STATUS_SUCCESS, "double alert -> %08lx", (unsigned long)status);
    status = NtWaitForAlertByThreadId(&dummy, &timeout);
    ok(status == STATUS_ALERTED, "consume double alert -> %08lx", (unsigned long)status);
    status = NtWaitForAlertByThreadId(&dummy, &timeout);
    ok(status == STATUS_TIMEOUT, "double alert was one latch -> %08lx", (unsigned long)status);

    /* Cross-thread: wake a blocked waiter, then be woken back by it. */
    DWORD waiter_id = 0;
    HANDLE thread = CreateThread(NULL, 0, waiter_thread, NULL, 0, &waiter_id);
    ok(thread != NULL, "CreateThread");
    Sleep(50); /* let the waiter block */
    status = NtAlertThreadByThreadId((HANDLE)(ULONG_PTR)waiter_id);
    ok(status == STATUS_SUCCESS, "alert waiter -> %08lx", (unsigned long)status);

    timeout.QuadPart = -50000000; /* 5 s bound on the wake-back */
    status = NtWaitForAlertByThreadId(&dummy, &timeout);
    ok(status == STATUS_ALERTED, "wake-back -> %08lx", (unsigned long)status);

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    ok(waiter_status == STATUS_ALERTED, "waiter unblocked -> %08lx", (unsigned long)waiter_status);
}
