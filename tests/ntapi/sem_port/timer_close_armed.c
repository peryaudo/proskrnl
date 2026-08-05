/*
 * sem_port/timer_close_armed.c — closing the last handle to an ARMED timer.
 *
 * Convicted by the winetest gate: kernel32:timer panicked proskrnl with
 * `[KASAN] invalid read of 8 bytes` / `KASAN: use after free` inside
 * KiUpdateClock (kernel/ke/timer.c), last syscall NtClose. The KTIMER
 * object was freed with its handle while still LINKED in the dispatcher's
 * due-time list, so the next clock tick walked into freed pool. Nothing in
 * tests/ntapi had ever closed an armed timer.
 *
 * This is the ownership audit Art. 11 asks for, written as a test: what
 * happens if every handle closes at the earliest legal moment? For a timer
 * the earliest legal moment is "armed, before it expires", and the only
 * observable requirement is that the machine keeps running afterwards —
 * so the test arms a timer, drops it, and then keeps making syscalls
 * across several tick boundaries. On the oracle that is unremarkable; on
 * proskrnl it was fatal, which is exactly the differential Art. 6 wants.
 *
 * The same shape is repeated for a PERIODIC timer, because the expiry path
 * re-inserts one (kernel/ke/timer.c "Periodic: re-arm relative to now") —
 * a freed periodic timer is walked, removed and put BACK on the list, so
 * it is the case a cancel-on-delete could plausibly still get wrong.
 */
#include "../ntapi.h"

typedef void(CALLBACK *PTIMER_APC_ROUTINE)(PVOID, ULONG, LONG);
NTSYSAPI NTSTATUS NTAPI NtCreateTimer(HANDLE *, ACCESS_MASK, const OBJECT_ATTRIBUTES *, ULONG);
NTSYSAPI NTSTATUS NTAPI NtSetTimer(HANDLE, const LARGE_INTEGER *, PTIMER_APC_ROUTINE, PVOID,
                                   BOOLEAN, ULONG, BOOLEAN *);
NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LONG, BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

#ifndef TIMER_ALL_ACCESS
#define TIMER_ALL_ACCESS 0x001F0003 /* wine/include/winnt.h */
#endif
#define TIMER_NOTIFICATION    0
#define TIMER_SYNCHRONIZATION 1

static void sleep_ms(LONGLONG ms)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -ms * 10000;
    NtDelayExecution(FALSE, &interval);
}

/* Keep the machine busy across tick boundaries and prove it still answers:
 * a freed-but-linked timer is walked by the CLOCK, not by this thread, so
 * the damage only shows if we survive long enough to be scheduled again. */
static void survive_ticks(const char *what)
{
    for (int i = 0; i < 10; i++)
    {
        HANDLE event = NULL;
        NTSTATUS status =
            NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, 1 /* Notification */, FALSE);
        ok(status == STATUS_SUCCESS, "%s: create event %d -> %08lx", what, i,
           (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(event);
        sleep_ms(20);
    }
}

START_TEST(timer_close_armed)
{
    NTSTATUS status;
    HANDLE timer = NULL;
    LARGE_INTEGER due;

    /* --- one-shot: armed far enough out that it is still pending ---------- */
    status = NtCreateTimer(&timer, TIMER_ALL_ACCESS, NULL, TIMER_NOTIFICATION);
    ok(status == STATUS_SUCCESS, "create one-shot -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        due.QuadPart = -1000000; /* 100 ms out: pending when the handle goes */
        status = NtSetTimer(timer, &due, NULL, NULL, FALSE, 0, NULL);
        ok(status == STATUS_SUCCESS, "arm one-shot -> %08lx", (unsigned long)status);
        /* The last handle, dropped while the timer is still on the list. */
        status = NtClose(timer);
        ok(status == STATUS_SUCCESS, "close armed one-shot -> %08lx", (unsigned long)status);
        survive_ticks("one-shot");
    }

    /* --- periodic: the expiry path re-inserts it ------------------------- */
    timer = NULL;
    status = NtCreateTimer(&timer, TIMER_ALL_ACCESS, NULL, TIMER_SYNCHRONIZATION);
    ok(status == STATUS_SUCCESS, "create periodic -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        due.QuadPart = -100000; /* 10 ms, then every 10 ms */
        status = NtSetTimer(timer, &due, NULL, NULL, FALSE, 10, NULL);
        ok(status == STATUS_SUCCESS, "arm periodic -> %08lx", (unsigned long)status);
        status = NtClose(timer);
        ok(status == STATUS_SUCCESS, "close armed periodic -> %08lx", (unsigned long)status);
        survive_ticks("periodic");
    }

    /* --- and one that expires WHILE the handle is still held, then closes -
     * the already-expired timer is off the list, so this is the control:
     * whatever the delete path does must be safe for an unlinked timer too. */
    timer = NULL;
    status = NtCreateTimer(&timer, TIMER_ALL_ACCESS, NULL, TIMER_NOTIFICATION);
    ok(status == STATUS_SUCCESS, "create expiring -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        LARGE_INTEGER timeout;
        due.QuadPart = -100000; /* 10 ms */
        status = NtSetTimer(timer, &due, NULL, NULL, FALSE, 0, NULL);
        ok(status == STATUS_SUCCESS, "arm expiring -> %08lx", (unsigned long)status);
        timeout.QuadPart = -5000000; /* 500 ms */
        status = NtWaitForSingleObject(timer, FALSE, &timeout);
        ok(status == STATUS_SUCCESS, "wait expiring -> %08lx", (unsigned long)status);
        status = NtClose(timer);
        ok(status == STATUS_SUCCESS, "close expired -> %08lx", (unsigned long)status);
        survive_ticks("expired");
    }
}
