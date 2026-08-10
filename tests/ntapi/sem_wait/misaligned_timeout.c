/*
 * sem_wait/misaligned_timeout.c — the wait surface takes a 4-aligned timeout.
 *
 * Every Nt wait takes its relative/absolute deadline through a
 * `const LARGE_INTEGER *` the CALLER owns, and nothing in the WOW64 path
 * re-aligns it: the pinned Wine's thunks hand the 32-bit pointer straight
 * down (dlls/wow64/sync.c wow64_NtDelayExecution / wow64_NtWaitForSingleObject
 * / wow64_NtWaitForMultipleObjects / wow64_NtWaitForAlertByThreadId all just
 * `get_ptr` it). A 32-bit caller's LARGE_INTEGER is only 4-byte aligned — an
 * i386 stack local holding one lands on a 4-boundary — so the deadline a
 * 64-bit kernel reads is routinely at `addr % 8 == 4`.
 *
 * These are therefore NOT hostile inputs; they are the ordinary WOW64 shape,
 * and the wait must read the value rather than refuse it. The cases below
 * hand every entry point that takes a deadline — the three object waits,
 * NtDelayExecution, NtWaitForAlertByThreadId, and NtSetTimer's due time — a
 * deliberately 4-aligned one from native 64-bit code, which is the same thing
 * the kernel sees under WOW64 minus the shelf.
 */
#include "../ntapi.h"

NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtWaitForMultipleObjects(ULONG, const HANDLE *, ULONG, BOOLEAN,
                                                 PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtAlertThreadByThreadId(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtWaitForAlertByThreadId(const void *, const LARGE_INTEGER *);
typedef void(CALLBACK *PTIMER_APC_ROUTINE)(PVOID, ULONG, LONG);

NTSYSAPI NTSTATUS NTAPI NtCreateTimer(HANDLE *, ACCESS_MASK, const OBJECT_ATTRIBUTES *, ULONG);
NTSYSAPI NTSTATUS NTAPI NtSetTimer(HANDLE, const LARGE_INTEGER *, PTIMER_APC_ROUTINE, PVOID,
                                   BOOLEAN, LONG, BOOLEAN *);
NTSYSAPI NTSTATUS NTAPI NtCancelTimer(HANDLE, BOOLEAN *);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

/* Same spellings and same source as sem_port/timer_close_armed.c, the other
 * test that arms one of these. */
#ifndef TIMER_ALL_ACCESS
#define TIMER_ALL_ACCESS 0x001F0003 /* wine/include/winnt.h */
#endif
#define TIMER_NOTIFICATION 0

#ifndef __WAIT_TYPE_DECLARED
#define __WAIT_TYPE_DECLARED
typedef enum _WAIT_TYPE
{
    WaitAll,
    WaitAny
} WAIT_TYPE;
#endif

/* A deadline at `% 8 == 4`. The union is 8-aligned by the ABI, so the offset
 * is taken from a byte array and the LARGE_INTEGER written through memcpy —
 * a `LARGE_INTEGER *` cast of a misaligned address is UB in the TEST too. */
static unsigned char slab[32];

static PLARGE_INTEGER misaligned_deadline(LONGLONG value)
{
    /* Land exactly on a 4-mod-8 address whatever the slab's own alignment. */
    unsigned char *at = (unsigned char *)((((ULONG_PTR)slab + 8) & ~(ULONG_PTR)7) + 4);
    memcpy(at, &value, sizeof(value));
    return (PLARGE_INTEGER)at;
}

START_TEST(misaligned_timeout)
{
    NTSTATUS status;
    PLARGE_INTEGER deadline;

    /* The premise: the address really is 4-mod-8. */
    deadline = misaligned_deadline(0);
    ok(((ULONG_PTR)deadline & 7) == 4, "deadline is 4-mod-8 (%p)", (void *)deadline);

    /* NtDelayExecution: a 10 ms relative delay through a 4-aligned deadline. */
    deadline = misaligned_deadline(-100000);
    status = NtDelayExecution(FALSE, deadline);
    ok(status == STATUS_SUCCESS, "NtDelayExecution(4-aligned) -> %08lx", (unsigned long)status);

    /* NtWaitForSingleObject on an unsignalled event: zero timeout comes
     * straight back, and the zero has to be READ to get there. */
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(event != NULL, "CreateEventW");
    deadline = misaligned_deadline(0);
    status = NtWaitForSingleObject(event, FALSE, deadline);
    ok(status == STATUS_TIMEOUT, "NtWaitForSingleObject(4-aligned 0) -> %08lx",
       (unsigned long)status);

    /* A nonzero relative deadline on the same handle actually parks. */
    deadline = misaligned_deadline(-100000);
    status = NtWaitForSingleObject(event, FALSE, deadline);
    ok(status == STATUS_TIMEOUT, "NtWaitForSingleObject(4-aligned 10ms) -> %08lx",
       (unsigned long)status);

    /* Signalled: the deadline is read but never reached. */
    SetEvent(event);
    deadline = misaligned_deadline(-100000);
    status = NtWaitForSingleObject(event, FALSE, deadline);
    ok(status == STATUS_WAIT_0, "NtWaitForSingleObject(4-aligned, signalled) -> %08lx",
       (unsigned long)status);
    ResetEvent(event);

    /* NtWaitForMultipleObjects, both wait types. */
    HANDLE handles[2];
    handles[0] = event;
    handles[1] = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(handles[1] != NULL, "CreateEventW 2");
    deadline = misaligned_deadline(-100000);
    status = NtWaitForMultipleObjects(2, handles, WaitAny, FALSE, deadline);
    ok(status == STATUS_TIMEOUT, "NtWaitForMultipleObjects(any, 4-aligned) -> %08lx",
       (unsigned long)status);
    deadline = misaligned_deadline(-100000);
    status = NtWaitForMultipleObjects(2, handles, WaitAll, FALSE, deadline);
    ok(status == STATUS_TIMEOUT, "NtWaitForMultipleObjects(all, 4-aligned) -> %08lx",
       (unsigned long)status);

    /* NtWaitForAlertByThreadId — the one RtlWaitOnAddress reaches, and the
     * one a WOW64 SAFlashPlayer.exe trips on its first contended lock. */
    int dummy = 0;
    deadline = misaligned_deadline(0);
    status = NtWaitForAlertByThreadId(&dummy, deadline);
    ok(status == STATUS_TIMEOUT, "NtWaitForAlertByThreadId(4-aligned 0) -> %08lx",
       (unsigned long)status);

    deadline = misaligned_deadline(-100000);
    status = NtWaitForAlertByThreadId(&dummy, deadline);
    ok(status == STATUS_TIMEOUT, "NtWaitForAlertByThreadId(4-aligned 10ms) -> %08lx",
       (unsigned long)status);

    /* A latched alert is consumed through the same misaligned deadline. */
    status = NtAlertThreadByThreadId((HANDLE)(ULONG_PTR)GetCurrentThreadId());
    ok(status == STATUS_SUCCESS, "alert self -> %08lx", (unsigned long)status);
    deadline = misaligned_deadline(-100000);
    status = NtWaitForAlertByThreadId(&dummy, deadline);
    ok(status == STATUS_ALERTED, "NtWaitForAlertByThreadId(4-aligned, alerted) -> %08lx",
       (unsigned long)status);

    /* NtSetTimer's due time is the same shape as a wait deadline and reaches
     * the kernel through the same 4-aligned WOW64 pointer, so it is read the
     * same way. (An APC routine is refused here — unbuilt, docs/03 — so this
     * arms the object form, which is what the threadpool waits on.) */
    HANDLE timer = NULL;
    status = NtCreateTimer(&timer, TIMER_ALL_ACCESS, NULL, TIMER_NOTIFICATION);
    ok(status == STATUS_SUCCESS, "NtCreateTimer -> %08lx", (unsigned long)status);
    if (status == STATUS_SUCCESS)
    {
        deadline = misaligned_deadline(-100000);
        status = NtSetTimer(timer, deadline, NULL, NULL, FALSE, 0, NULL);
        ok(status == STATUS_SUCCESS, "NtSetTimer(4-aligned) -> %08lx", (unsigned long)status);
        /* And the timer really was armed with THAT value: 10 ms in, a wait on
         * it completes rather than timing out at 5 s. */
        deadline = misaligned_deadline(-50000000);
        status = NtWaitForSingleObject(timer, FALSE, deadline);
        ok(status == STATUS_WAIT_0, "the 4-aligned due time armed the timer -> %08lx",
           (unsigned long)status);
        NtCancelTimer(timer, NULL);
        NtClose(timer);
    }

    CloseHandle(handles[1]);
    CloseHandle(event);
}
