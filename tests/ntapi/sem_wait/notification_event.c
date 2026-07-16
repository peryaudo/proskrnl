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
 * proskrnl mode these come from abi/ntkeapi.h instead. */
#if defined(NTAPI_ORACLE)
NTSYSAPI NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                      EVENT_TYPE, BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtSetEvent(HANDLE, PLONG);
NTSYSAPI NTSTATUS NTAPI NtResetEvent(HANDLE, PLONG);
NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);
#endif

/* wait with a zero timeout: returns STATUS_SUCCESS if signalled now, else
 * STATUS_TIMEOUT. Never blocks. */
static NTSTATUS wait_now(HANDLE Event)
{
    LARGE_INTEGER Zero;
    Zero.QuadPart = 0;
    return NtWaitForSingleObject(Event, FALSE, &Zero);
}

START_TEST(notification_event)
{
    HANDLE Event;
    NTSTATUS Status;

    /* NotificationEvent, initially signalled. */
    Status = NtCreateEvent(&Event, EVENT_ALL_ACCESS, NULL, NotificationEvent, TRUE);
    ok(Status == STATUS_SUCCESS, "NtCreateEvent -> %08lx", (unsigned long)Status);

    /* Signalled state persists: two consecutive waits both succeed, no reset. */
    ok(wait_now(Event) == STATUS_SUCCESS, "1st wait on signalled notification event");
    ok(wait_now(Event) == STATUS_SUCCESS, "2nd wait must still succeed (no auto-reset)");

    /* After an explicit reset, a zero-timeout wait must time out. */
    NtResetEvent(Event, NULL);
    ok(wait_now(Event) == STATUS_TIMEOUT, "wait after reset must time out");

    /* Set again releases waiters until the next reset. */
    NtSetEvent(Event, NULL);
    ok(wait_now(Event) == STATUS_SUCCESS, "wait after set succeeds");

    /*
     * Example of the convention: suppose proskrnl's very first NtSetEvent does
     * not yet return the previous state via the optional second parameter.
     * Keep the test live (it guards everything above) but mark the one corner:
     */
    {
        LONG Previous = -1;
        NtSetEvent(Event, &Previous);
        todo_proskrnl {
            ok(Previous == 1, "NtSetEvent returns previous signalled state");
        }
    }

    NtClose(Event);
}
