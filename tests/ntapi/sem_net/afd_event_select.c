/*
 * sem_net/afd_event_select.c — IOCTL_AFD_EVENT_SELECT and
 * IOCTL_AFD_GET_EVENTS: the mask+event arm, the pending-events latch
 * (reported once, consumed), the persistent per-bit status array, and the
 * event-as-INPUT-POINTER (sic) reset convention.
 *
 * From ws2_32:afd test_event_select / test_get_events /
 * test_get_events_reset, and ws2_32's own call sites
 * (dlls/ws2_32/socket.c WSAEnumNetworkEvents passes the event HANDLE as
 * the input-buffer POINTER with length 0 — the convention this file's
 * name is about). One deliberate scope cut: the wine tests' rows for
 * these verbs on the ORACLE write the refusal's IOSB, so the pins here
 * assert that too.
 */
#include "util.h"

struct afd_event_select_params
{
    HANDLE event;
    int mask;
};

struct afd_get_events_params
{
    int flags;
    int status[13];
};

static NTSTATUS event_select(HANDLE s, HANDLE event, int mask, IO_STATUS_BLOCK *iosb)
{
    struct afd_event_select_params params;
    params.event = event;
    params.mask = mask;
    poison_iosb(iosb);
    return NtDeviceIoControlFile(s, NULL, NULL, NULL, iosb, IOCTL_AFD_EVENT_SELECT, &params,
                                 sizeof(params), NULL, 0);
}

static NTSTATUS get_events(HANDLE s, HANDLE resetEvent, struct afd_get_events_params *out)
{
    IO_STATUS_BLOCK iosb;
    memset(out, 0xcc, sizeof(*out));
    poison_iosb(&iosb);
    return NtDeviceIoControlFile(s, NULL, NULL, NULL, &iosb, IOCTL_AFD_GET_EVENTS, resetEvent, 0,
                                 out, sizeof(*out));
}

static void test_event_select_validation(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE client = NULL, server = NULL;
    NTSTATUS status;

    if (!tcp_pair(&client, &server))
        return;

    /* NULL params — and the IOSB CARRIES the refusal (these verbs write
     * it; the RECV family's refusals do not — both measured). */
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(client, NULL, NULL, NULL, &iosb, IOCTL_AFD_EVENT_SELECT, NULL, 0,
                                   NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "null select -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_INVALID_PARAMETER, "null select iosb %08lx",
       (unsigned long)iosb.Status);
    ok(iosb.Information == 0, "null select information %lx", (unsigned long)iosb.Information);

    /* A zero event with a live mask. */
    status = event_select(client, NULL, ~0, &iosb);
    ok(status == STATUS_INVALID_PARAMETER, "no-event select -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_INVALID_PARAMETER, "no-event select iosb %08lx",
       (unsigned long)iosb.Status);

    /* GET_EVENTS with no output buffer. */
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(client, NULL, NULL, NULL, &iosb, IOCTL_AFD_GET_EVENTS, NULL, 0,
                                   NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "no-out get-events -> %08lx", (unsigned long)status);

    NtClose(client);
    NtClose(server);
}

static void test_events_latch(void)
{
    struct afd_get_events_params events;
    IO_STATUS_BLOCK iosb;
    HANDLE client = NULL, server = NULL, event;
    unsigned i;
    NTSTATUS status;

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!tcp_pair(&client, &server))
        return;

    /* Arm for everything: the fresh connection's WRITE|CONNECT edges are
     * pending, so the event fires and GET_EVENTS reports them. */
    status = event_select(client, event, ~0, &iosb);
    ok(status == STATUS_SUCCESS, "select -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "select iosb %08lx", (unsigned long)iosb.Status);
    ok(is_signaled(event), "the armed event did not fire on pending edges");

    status = get_events(client, NULL, &events);
    ok(status == STATUS_SUCCESS, "get-events -> %08lx", (unsigned long)status);
    ok(events.flags == (AFD_POLL_WRITE | AFD_POLL_CONNECT), "flags %#x", events.flags);
    for (i = 0; i < 13; i++)
        ok(events.status[i] == 0, "status[%u] %#x", i, events.status[i]);

    /* The latch: reported once — a second read sees nothing. */
    status = get_events(client, NULL, &events);
    ok(status == STATUS_SUCCESS, "second get-events -> %08lx", (unsigned long)status);
    ok(events.flags == 0, "second flags %#x", events.flags);

    /* A fresh edge re-raises: the peer's send lands READ. Reset first so
     * the wait below really waits for the EDGE (the arm's own firing left
     * the manual-reset event set) — the delivery is asynchronous on both
     * runners and the event is the signal ws2_32 itself waits on. */
    ResetEvent(event);
    status = afd_send_wait(server, "x", 1, NULL);
    ok(status == STATUS_SUCCESS, "send -> %08lx", (unsigned long)status);
    ok(wait_done(event), "the event never re-fired");
    status = get_events(client, NULL, &events);
    ok(status == STATUS_SUCCESS, "read get-events -> %08lx", (unsigned long)status);
    ok((events.flags & AFD_POLL_READ) != 0, "read flags %#x", events.flags);

    NtClose(client);
    NtClose(server);
    CloseHandle(event);
}

static void test_event_as_input_pointer_resets(void)
{
    struct afd_get_events_params events;
    IO_STATUS_BLOCK iosb;
    HANDLE client = NULL, server = NULL, event;
    NTSTATUS status;

    event = CreateEventW(NULL, TRUE, TRUE, NULL); /* SIGNALLED */
    if (!tcp_pair(&client, &server))
        return;

    status = event_select(client, event, ~0, &iosb);
    ok(status == STATUS_SUCCESS, "select -> %08lx", (unsigned long)status);
    status = get_events(client, NULL, &events);
    ok(status == STATUS_SUCCESS, "drain -> %08lx", (unsigned long)status);

    SetEvent(event);
    /* The sic convention: the INPUT POINTER is the event handle, length
     * 0 — the call reports (nothing) and RESETS that event atomically. */
    status = get_events(client, event, &events);
    ok(status == STATUS_SUCCESS, "reset get-events -> %08lx", (unsigned long)status);
    ok(events.flags == 0, "reset flags %#x", events.flags);
    ok(!is_signaled(event), "the input-pointer event was not reset");

    /* Clearing the selection: event 0, mask 0. */
    status = event_select(client, NULL, 0, &iosb);
    ok(status == STATUS_SUCCESS, "clear select -> %08lx", (unsigned long)status);

    NtClose(client);
    NtClose(server);
    CloseHandle(event);
}

/* Consuming SOME of the ring re-raises the READ edge (ws2_32's FD_READ
 * re-enable: the ws2_32:afd test_read_write row — one byte read out of
 * four leaves FD_READ reported again); draining it does not. */
static void test_read_relatch(void)
{
    struct afd_get_events_params events;
    IO_STATUS_BLOCK iosb;
    HANDLE client = NULL, server = NULL, event;
    char buffer[8];
    ULONG got = 0;
    NTSTATUS status;

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!tcp_pair(&client, &server))
        return;

    status = event_select(client, event, AFD_POLL_READ, &iosb);
    ok(status == STATUS_SUCCESS, "select -> %08lx", (unsigned long)status);

    ResetEvent(event);
    status = afd_send_wait(server, "data", 4, NULL);
    ok(status == STATUS_SUCCESS, "send -> %08lx", (unsigned long)status);
    ok(wait_done(event), "the event never fired");
    status = get_events(client, NULL, &events);
    ok(status == STATUS_SUCCESS, "get-events -> %08lx", (unsigned long)status);
    ok((events.flags & AFD_POLL_READ) != 0, "read flags %#x", events.flags);

    /* One byte out of four: READ re-latches. */
    status = afd_recv_wait(client, buffer, 1, &got);
    ok(status == STATUS_SUCCESS && got == 1, "partial recv -> %08lx/%lu", (unsigned long)status,
       (unsigned long)got);
    status = get_events(client, NULL, &events);
    ok(status == STATUS_SUCCESS, "re-latch get-events -> %08lx", (unsigned long)status);
    ok((events.flags & AFD_POLL_READ) != 0, "re-latched flags %#x", events.flags);

    /* The rest: drained, no READ. */
    status = afd_recv_wait(client, buffer, sizeof(buffer), &got);
    ok(status == STATUS_SUCCESS && got == 3, "drain recv -> %08lx/%lu", (unsigned long)status,
       (unsigned long)got);
    status = get_events(client, NULL, &events);
    ok(status == STATUS_SUCCESS, "drained get-events -> %08lx", (unsigned long)status);
    ok((events.flags & AFD_POLL_READ) == 0, "drained flags %#x", events.flags);

    NtClose(client);
    NtClose(server);
    CloseHandle(event);
}

START_TEST(afd_event_select)
{
    test_event_select_validation();
    test_events_latch();
    test_read_relatch();
    test_event_as_input_pointer_resets();
}
