/*
 * sem_ps/apc_ex.c — NtQueueApcThreadEx2 and NtAlertResumeThread (CUI-6).
 *
 * QueueUserAPC2's back end (dlls/kernelbase/thread.c always calls Ex2 with a
 * NULL reserve handle) and the alert+resume pair. Oracle behaviour pinned
 * from the pinned tree: Ex2 with QUEUE_USER_APC_FLAGS_NONE is exactly
 * NtQueueApcThread (dlls/ntdll/unix/thread.c funnels the classic entry
 * point into Ex2); the special flag is accepted and delivered at the same
 * alertable points — the server carries SERVER_USER_APC_SPECIAL but reads
 * it only to refuse wow64 targets (server/thread.c queue_apc), so special
 * and normal user APCs behave identically at this boundary and the oracle
 * is the spec (Art. 6); the target handle needs THREAD_SET_CONTEXT
 * (server/thread.c APC_USER). NtAlertResumeThread's resume half is real —
 * it IS NtResumeThread with the previous-count write-back
 * (dlls/ntdll/unix/thread.c) — while its alert half sits under a FIXME the
 * unix side drops, so the alert delivery is pinned beyond_oracle against
 * the documented NT contract (the routine "resumes the thread and delivers
 * an alert": ZwAlertResumeThread, Windows Internals' alert delivery — an
 * alertable wait in the target completes with STATUS_ALERTED; the pinned
 * tree's own FIXME "should alert thread" names the missing half).
 */
#include "util.h"

typedef VOID(NTAPI *ps_apcfunc)(ULONG_PTR, ULONG_PTR, ULONG_PTR);
NTSYSAPI NTSTATUS NTAPI NtQueueApcThread(HANDLE, ps_apcfunc, ULONG_PTR, ULONG_PTR, ULONG_PTR);
NTSYSAPI NTSTATUS NTAPI NtQueueApcThreadEx2(HANDLE, HANDLE, ULONG, ps_apcfunc, ULONG_PTR, ULONG_PTR,
                                            ULONG_PTR);
NTSYSAPI NTSTATUS NTAPI NtAlertResumeThread(HANDLE, PULONG);
NTSYSAPI NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG,
                                          ULONG);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

#ifndef NtCurrentThread
#define NtCurrentThread() ((HANDLE) ~(ULONG_PTR)1)
#endif
/* wine/include/processthreadsapi.h QUEUE_USER_APC_FLAGS (mingw may omit). */
#ifndef QUEUE_USER_APC_FLAGS_NONE
#define QUEUE_USER_APC_FLAGS_NONE 0
#endif
#ifndef QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC
#define QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC 0x00000001
#endif

static volatile LONG apc_calls;
static volatile ULONG_PTR apc_last_a1, apc_last_a2, apc_last_a3;

static VOID NTAPI count_apc(ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3)
{
    apc_last_a1 = a1;
    apc_last_a2 = a2;
    apc_last_a3 = a3;
    InterlockedIncrement(&apc_calls);
}

static NTSTATUS alertable_poll(void)
{
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    return NtDelayExecution(TRUE, &zero);
}

/* Parked worker for the access-denied probe: sits non-alertably on an event
 * so a queued APC cannot fire in it. */
static HANDLE park_event;
static DWORD WINAPI parked_worker(void *param)
{
    (void)param;
    WaitForSingleObject(park_event, 10000);
    return 0;
}

/* Worker for the alert half: one long alertable delay, status recorded. */
static volatile LONG alert_status = -1;
static DWORD WINAPI alertable_worker(void *param)
{
    (void)param;
    LARGE_INTEGER timeout;
    timeout.QuadPart = -3000 * 10000LL; /* 3 s */
    InterlockedExchange(&alert_status, (LONG)NtDelayExecution(TRUE, &timeout));
    return 0;
}

static volatile LONG resumed_ran;
static DWORD WINAPI resumed_worker(void *param)
{
    (void)param;
    InterlockedExchange(&resumed_ran, 1);
    return 0;
}

START_TEST(apc_ex)
{
    NTSTATUS status;
    ULONG count;

    /* --- Ex2 with flags NONE is the classic queue ------------------------- */
    apc_calls = 0;
    status = NtQueueApcThreadEx2(NtCurrentThread(), NULL, QUEUE_USER_APC_FLAGS_NONE, count_apc, 11,
                                 22, 33);
    ok(status == STATUS_SUCCESS, "Ex2 none -> %08lx", (unsigned long)status);
    status = alertable_poll();
    ok(status == STATUS_USER_APC, "alertable poll -> %08lx", (unsigned long)status);
    ok(apc_calls == 1, "apc ran %ld times", (long)apc_calls);
    ok(apc_last_a1 == 11 && apc_last_a2 == 22 && apc_last_a3 == 33, "apc args %lu %lu %lu",
       (unsigned long)apc_last_a1, (unsigned long)apc_last_a2, (unsigned long)apc_last_a3);

    /* --- the special flag is accepted and delivered the same way ---------- */
    apc_calls = 0;
    status = NtQueueApcThreadEx2(NtCurrentThread(), NULL, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
                                 count_apc, 44, 55, 66);
    ok(status == STATUS_SUCCESS, "Ex2 special -> %08lx", (unsigned long)status);
    status = alertable_poll();
    ok(status == STATUS_USER_APC, "special poll -> %08lx", (unsigned long)status);
    ok(apc_calls == 1, "special apc ran %ld times", (long)apc_calls);
    ok(apc_last_a1 == 44, "special apc arg %lu", (unsigned long)apc_last_a1);

    /* --- classic NtQueueApcThread still works (same engine) --------------- */
    apc_calls = 0;
    status = NtQueueApcThread(NtCurrentThread(), count_apc, 77, 0, 0);
    ok(status == STATUS_SUCCESS, "classic queue -> %08lx", (unsigned long)status);
    status = alertable_poll();
    ok(status == STATUS_USER_APC, "classic poll -> %08lx", (unsigned long)status);
    ok(apc_calls == 1 && apc_last_a1 == 77, "classic apc %ld/%lu", (long)apc_calls,
       (unsigned long)apc_last_a1);

    /* --- target access: an under-privileged handle refuses ---------------- */
    park_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(park_event != NULL, "create park event");
    HANDLE parked = CreateThread(NULL, 0, parked_worker, NULL, 0, NULL);
    ok(parked != NULL, "create parked worker");
    HANDLE limited = NULL;
    status = NtDuplicateObject(NtCurrentProcess(), parked, NtCurrentProcess(), &limited,
                               THREAD_QUERY_INFORMATION, 0, 0);
    ok(status == STATUS_SUCCESS, "dup limited -> %08lx", (unsigned long)status);
    status = NtQueueApcThreadEx2(limited, NULL, QUEUE_USER_APC_FLAGS_NONE, count_apc, 1, 2, 3);
    ok(status == STATUS_ACCESS_DENIED, "under-privileged queue -> %08lx", (unsigned long)status);
    NtClose(limited);
    SetEvent(park_event);
    WaitForSingleObject(parked, 5000);
    CloseHandle(parked);
    CloseHandle(park_event);

    /* --- NtAlertResumeThread: the resume half is real ---------------------- */
    resumed_ran = 0;
    HANDLE suspended = CreateThread(NULL, 0, resumed_worker, NULL, CREATE_SUSPENDED, NULL);
    ok(suspended != NULL, "create suspended worker");
    count = 0xdead;
    status = NtAlertResumeThread(suspended, &count);
    ok(status == STATUS_SUCCESS, "alert-resume suspended -> %08lx", (unsigned long)status);
    ok(count == 1, "previous suspend count %lu", (unsigned long)count);
    WaitForSingleObject(suspended, 5000);
    ok(resumed_ran == 1, "resumed thread ran");
    CloseHandle(suspended);

    /* --- ...and the alert half wakes an alertable wait --------------------- */
    HANDLE alerted = CreateThread(NULL, 0, alertable_worker, NULL, 0, NULL);
    ok(alerted != NULL, "create alertable worker");
    Sleep(100); /* let it park in the alertable delay */
    count = 0xdead;
    status = NtAlertResumeThread(alerted, &count);
    ok(status == STATUS_SUCCESS, "alert-resume running -> %08lx", (unsigned long)status);
    ok(count == 0, "running thread previous count %lu", (unsigned long)count);
    beyond_oracle
    {
        /* The alert wakes the 3 s alertable delay early with STATUS_ALERTED
         * (ZwAlertResumeThread's documented contract; the pinned unix side
         * drops the alert under its own FIXME "should alert thread"). */
        DWORD wait = WaitForSingleObject(alerted, 1000);
        ok(wait == WAIT_OBJECT_0, "alerted worker woke early (wait %lu)", (unsigned long)wait);
        ok(alert_status == (LONG)STATUS_ALERTED, "alertable delay -> %08lx",
           (unsigned long)alert_status);
    }
    WaitForSingleObject(alerted, 5000); /* oracle: the delay simply expires */
    CloseHandle(alerted);
}
