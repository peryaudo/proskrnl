/*
 * sem_wait/notification_event.c
 *
 * Contract: a NotificationEvent stays signalled until explicitly reset (every
 * waiter is released), whereas a SynchronizationEvent auto-resets (exactly one
 * waiter is released per set). This is a wrong-contract-shaped behaviour
 * (docs/08): it must be written against the oracle BEFORE the kernel implements
 * NtCreateEvent, or the implementation would certify whatever it happened to do.
 *
 * Oracle build: Nt* resolve against the host ntdll (Wine/Windows).
 * proskrnl build: lit up at M4; add to manifest.txt when NtCreateEvent lands.
 */
#include "../ntapi.h"

/* Prototypes winternl.h omits (declared as Wine's own ntdll tests do). In
 * proskrnl mode they come from the generated abi/ntobapi.h. */
#if defined(NTAPI_ORACLE)
NTSYSAPI NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, EVENT_TYPE,
                                      BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtSetEvent(HANDLE, PLONG);
NTSYSAPI NTSTATUS NTAPI NtResetEvent(HANDLE, PLONG);
NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);
#elif defined(NTAPI_PROSKRNL)
#include "abi/ntobapi.h"
#endif

/* wait with a zero timeout: returns STATUS_SUCCESS if signalled now, else
 * STATUS_TIMEOUT. Never blocks. */
static NTSTATUS wait_now(HANDLE event)
{
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    return NtWaitForSingleObject(event, FALSE, &zero);
}

START_TEST(notification_event)
{
    HANDLE event;
    NTSTATUS status;

    /* NotificationEvent, initially signalled. */
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, TRUE);
    ok(status == STATUS_SUCCESS, "NtCreateEvent -> %08lx", (unsigned long)status);

    /* Signalled state persists: two consecutive waits both succeed, no reset. */
    ok(wait_now(event) == STATUS_SUCCESS, "1st wait on signalled notification event");
    ok(wait_now(event) == STATUS_SUCCESS, "2nd wait must still succeed (no auto-reset)");

    /* After an explicit reset, a zero-timeout wait must time out. */
    NtResetEvent(event, NULL);
    ok(wait_now(event) == STATUS_TIMEOUT, "wait after reset must time out");

    /* Set again releases waiters until the next reset. */
    NtSetEvent(event, NULL);
    ok(wait_now(event) == STATUS_SUCCESS, "wait after set succeeds");

    /* NtSetEvent returns the previous signalled state via the optional second
     * parameter (proskrnl implements this since M4 — the tag that once marked
     * it not-yet-done is gone, so the kernel is now held to it). */
    {
        LONG previous = -1;
        NtSetEvent(event, &previous);
        ok(previous == 1, "NtSetEvent returns previous signalled state");
    }

    NtClose(event);
}
