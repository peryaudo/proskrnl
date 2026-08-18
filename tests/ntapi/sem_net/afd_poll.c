/*
 * sem_net/afd_poll.c — IOCTL_AFD_POLL: the validation ladder, the
 * zero-timeout snapshot, level-triggered readiness, the park satisfied by
 * a same-thread edge, timeout expiry, per-entry handle resolution, and
 * the exclusive-displacement rule.
 *
 * From ws2_32:afd test_poll / test_poll_exclusive, loopback-only. Every
 * "did not fire" verdict is an immediate is_signaled() probe — never a
 * timed wait on nothing (docs/19 §11c) — and every parked poll is
 * completed by this thread's own action.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQuerySystemTime(PLARGE_INTEGER);

#define POLL_ONE_SIZE   ((ULONG)offsetof(struct afd_poll_params, sockets[1]))
#define POLL_EMPTY_SIZE ((ULONG)offsetof(struct afd_poll_params, sockets[0]))

struct afd_poll_params
{
    LONGLONG timeout;
    unsigned int count;
    BOOLEAN exclusive;
    BOOLEAN padding[3];
    struct afd_poll_socket
    {
        ULONG_PTR socket;
        int flags;
        int status;
    } sockets[4];
};

#define AFD_TIMEOUT_INFINITE 0x7fffffffffffffffLL

static NTSTATUS poll_raw(HANDLE via, HANDLE event, IO_STATUS_BLOCK *iosb,
                         struct afd_poll_params *in, ULONG in_size, struct afd_poll_params *out,
                         ULONG out_size)
{
    poison_iosb(iosb);
    return NtDeviceIoControlFile(via, event, NULL, NULL, iosb, IOCTL_AFD_POLL, in, in_size, out,
                                 out_size);
}

/* One-socket poll driven to its final shape (the wine check_poll shape). */
static void check_poll_flags(HANDLE s, HANDLE event, int mask, int expect, int line)
{
    struct afd_poll_params in, out;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    memset(&in, 0, sizeof(in));
    in.timeout = -1000 * 10000LL; /* 1 s relative — never reached: the
                                   * condition is already true */
    in.count = 1;
    in.sockets[0].socket = (ULONG_PTR)s;
    in.sockets[0].flags = mask;
    in.sockets[0].status = (int)0xdeadbeef;
    memset(&out, 0, sizeof(out));
    ResetEvent(event);
    status = poll_raw(s, event, &iosb, &in, POLL_ONE_SIZE, &out, POLL_ONE_SIZE);
    if (status == STATUS_PENDING)
    {
        ntapi_okv(wait_done(event), __FILE__, line, "poll never completed");
        status = iosb.Status;
    }
    ntapi_okv(status == STATUS_SUCCESS, __FILE__, line, "poll -> %08lx", (unsigned long)status);
    ntapi_okv(iosb.Information == POLL_ONE_SIZE, __FILE__, line, "poll information %lx",
              (unsigned long)iosb.Information);
    ntapi_okv(out.count == 1, __FILE__, line, "poll count %u", out.count);
    ntapi_okv(out.sockets[0].socket == (ULONG_PTR)s, __FILE__, line, "poll socket echo");
    ntapi_okv(out.sockets[0].flags == expect, __FILE__, line, "poll flags %#x != %#x",
              out.sockets[0].flags, expect);
    ntapi_okv(out.sockets[0].status == 0, __FILE__, line, "poll status %#x", out.sockets[0].status);
}
#define CHECK_POLL(s, event, mask, expect) check_poll_flags(s, event, mask, expect, __LINE__)

static void test_poll_validation(void)
{
    struct afd_poll_params in, out;
    IO_STATUS_BLOCK iosb;
    HANDLE s = NULL, event;
    NTSTATUS status;

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    status = afd_tcp(&s, FALSE);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);

    memset(&in, 0, sizeof(in));
    in.count = 1; /* sockets[0].socket == 0: an invalid handle */

    status = poll_raw(s, event, &iosb, &in, POLL_ONE_SIZE, NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "no out -> %08lx", (unsigned long)status);
    status = poll_raw(s, event, &iosb, NULL, 0, &out, POLL_ONE_SIZE);
    ok(status == STATUS_INVALID_PARAMETER, "no in -> %08lx", (unsigned long)status);
    status = poll_raw(s, event, &iosb, &in, POLL_ONE_SIZE + 1, &out, POLL_ONE_SIZE);
    ok(status == STATUS_INVALID_PARAMETER, "out < in -> %08lx", (unsigned long)status);
    status = poll_raw(s, event, &iosb, &in, POLL_ONE_SIZE - 1, &out, POLL_ONE_SIZE - 1);
    ok(status == STATUS_INVALID_PARAMETER, "short in -> %08lx", (unsigned long)status);
    /* Sizes fine (out may exceed in): the zero HANDLE is what refuses. */
    status = poll_raw(s, event, &iosb, &in, POLL_ONE_SIZE, &out, POLL_ONE_SIZE + 1);
    ok(status == STATUS_INVALID_HANDLE, "bad socket -> %08lx", (unsigned long)status);
    in.count = 0;
    status = poll_raw(s, event, &iosb, &in, POLL_ONE_SIZE, &out, POLL_ONE_SIZE);
    ok(status == STATUS_INVALID_PARAMETER, "count 0 -> %08lx", (unsigned long)status);

    CloseHandle(event);
    NtClose(s);
}

static void test_poll_snapshot_and_levels(void)
{
    struct afd_poll_params in, out;
    struct sockaddr_in bound;
    IO_STATUS_BLOCK iosb;
    HANDLE listener = NULL, device = NULL, event;
    NTSTATUS status;

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    status = afd_tcp(&listener, FALSE);
    ok(status == STATUS_SUCCESS, "listener -> %08lx", (unsigned long)status);
    status = afd_bind_loopback(listener, 0, &bound);
    ok(status == STATUS_SUCCESS, "bind -> %08lx", (unsigned long)status);
    status = afd_listen(listener, 1);
    ok(status == STATUS_SUCCESS, "listen -> %08lx", (unsigned long)status);

    /* The zero-timeout snapshot with nothing ready: inline SUCCESS, the
     * output is the EMPTY params head. */
    memset(&in, 0, sizeof(in));
    in.timeout = 0;
    in.count = 1;
    in.sockets[0].socket = (ULONG_PTR)listener;
    in.sockets[0].flags = ~0;
    in.sockets[0].status = (int)0xdeadbeef;
    memset(&out, 0, sizeof(out));
    status = poll_raw(listener, event, &iosb, &in, POLL_ONE_SIZE, &out, POLL_ONE_SIZE);
    ok(status == STATUS_SUCCESS, "snapshot -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "snapshot iosb %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == POLL_EMPTY_SIZE, "snapshot information %lx",
       (unsigned long)iosb.Information);
    ok(out.count == 0, "snapshot count %u", out.count);
    ok(out.timeout == 0, "snapshot timeout echo %llx", (unsigned long long)out.timeout);

    /* A poll may be issued VIA a bare device handle — the entries carry
     * their own socket handles. */
    status = afd_open(&device, FALSE);
    ok(status == STATUS_SUCCESS, "device open -> %08lx", (unsigned long)status);
    memset(&out, 0, sizeof(out));
    status = poll_raw(device, event, &iosb, &in, POLL_ONE_SIZE, &out, POLL_ONE_SIZE);
    ok(status == STATUS_SUCCESS, "poll via device -> %08lx", (unsigned long)status);
    ok(out.count == 0, "poll via device count %u", out.count);
    NtClose(device);

    /* The park, satisfied by this thread's own connect: ACCEPT comes up. */
    {
        HANDLE client = NULL;
        in.timeout = AFD_TIMEOUT_INFINITE;
        memset(&out, 0, sizeof(out));
        ResetEvent(event);
        status = poll_raw(listener, event, &iosb, &in, POLL_ONE_SIZE, &out, POLL_ONE_SIZE);
        ok(status == STATUS_PENDING, "park -> %08lx", (unsigned long)status);
        ok(!is_signaled(event), "poll completed with nothing ready");

        status = afd_tcp(&client, FALSE);
        ok(status == STATUS_SUCCESS, "client -> %08lx", (unsigned long)status);
        status = afd_connect_loopback(client, sw16(bound.sin_port));
        ok(status == STATUS_SUCCESS, "connect -> %08lx", (unsigned long)status);

        ok(wait_done(event), "poll never completed");
        ok(iosb.Status == STATUS_SUCCESS, "poll status %08lx", (unsigned long)iosb.Status);
        ok(iosb.Information == POLL_ONE_SIZE, "poll information %lx",
           (unsigned long)iosb.Information);
        ok(out.count == 1, "poll count %u", out.count);
        ok(out.sockets[0].socket == (ULONG_PTR)listener, "poll socket echo");
        ok(out.sockets[0].flags == AFD_POLL_ACCEPT, "poll flags %#x", out.sockets[0].flags);
        ok(out.sockets[0].status == 0, "poll entry status %#x", out.sockets[0].status);

        /* Level-triggered: the same poll answers inline while the
         * connection stays unclaimed. */
        CHECK_POLL(listener, event, ~0, AFD_POLL_ACCEPT);

        /* Masked away, zero timeout: a snapshot that sees nothing. */
        in.timeout = 0;
        in.sockets[0].flags = (~0) & ~AFD_POLL_ACCEPT;
        memset(&out, 0, sizeof(out));
        status = poll_raw(listener, event, &iosb, &in, POLL_ONE_SIZE, &out, POLL_ONE_SIZE);
        ok(status == STATUS_SUCCESS, "masked snapshot -> %08lx", (unsigned long)status);
        ok(out.count == 0, "masked snapshot count %u", out.count);

        /* The connected pair's base state: WRITE|CONNECT on both ends. */
        {
            HANDLE server;
            ULONG accept_handle = 0;
            HANDLE acceptEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            poison_iosb(&iosb);
            status = NtDeviceIoControlFile(listener, acceptEvent, NULL, NULL, &iosb,
                                           IOCTL_AFD_WINE_ACCEPT, NULL, 0, &accept_handle,
                                           sizeof(accept_handle));
            if (status == STATUS_PENDING)
            {
                ok(wait_done(acceptEvent), "accept never completed");
                status = iosb.Status;
            }
            ok(status == STATUS_SUCCESS, "accept -> %08lx", (unsigned long)status);
            CloseHandle(acceptEvent);
            server = (HANDLE)(ULONG_PTR)accept_handle;

            CHECK_POLL(client, event, ~0, AFD_POLL_WRITE | AFD_POLL_CONNECT);
            CHECK_POLL(server, event, ~0, AFD_POLL_WRITE | AFD_POLL_CONNECT);

            /* Data arrival raises READ beside them; the mask narrows. */
            status = afd_send_wait(server, "data", 4, NULL);
            ok(status == STATUS_SUCCESS, "send -> %08lx", (unsigned long)status);
            CHECK_POLL(client, event, AFD_POLL_READ, AFD_POLL_READ);
            CHECK_POLL(client, event, ~0, AFD_POLL_WRITE | AFD_POLL_CONNECT | AFD_POLL_READ);

            /* Draining it lowers READ again. */
            {
                char buffer[8];
                status = afd_recv_wait(client, buffer, sizeof(buffer), NULL);
                ok(status == STATUS_SUCCESS, "drain -> %08lx", (unsigned long)status);
            }
            CHECK_POLL(client, event, ~0, AFD_POLL_WRITE | AFD_POLL_CONNECT);

            /* The peer's send-shutdown raises HUP on this end. */
            {
                int how = 1; /* SD_SEND */
                status = NtDeviceIoControlFile(server, NULL, NULL, NULL, &iosb,
                                               IOCTL_AFD_WINE_SHUTDOWN, &how, sizeof(how), NULL, 0);
                ok(status == STATUS_SUCCESS, "shutdown -> %08lx", (unsigned long)status);
            }
            CHECK_POLL(client, event, AFD_POLL_HUP, AFD_POLL_HUP);
            CHECK_POLL(client, event, ~0, AFD_POLL_WRITE | AFD_POLL_CONNECT | AFD_POLL_HUP);

            NtClose(server);
        }
        NtClose(client);
    }

    CloseHandle(event);
    NtClose(listener);
}

static void test_poll_timeout_expiry(void)
{
    struct afd_poll_params in, out;
    IO_STATUS_BLOCK iosb;
    HANDLE s = NULL, event;
    LARGE_INTEGER now;
    NTSTATUS status;

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    status = afd_tcp(&s, FALSE);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);
    status = afd_bind_loopback(s, 0, NULL);
    ok(status == STATUS_SUCCESS, "bind -> %08lx", (unsigned long)status);

    /* An ABSOLUTE timeout already in the past: the poll pends, then
     * completes STATUS_TIMEOUT with the empty head — the verdict is the
     * SHAPE of the expiry, never how fast it fired. */
    NtQuerySystemTime(&now);
    memset(&in, 0, sizeof(in));
    in.timeout = now.QuadPart;
    in.count = 1;
    in.sockets[0].socket = (ULONG_PTR)s;
    in.sockets[0].flags = ~0;
    memset(&out, 0, sizeof(out));
    ResetEvent(event);
    status = poll_raw(s, event, &iosb, &in, POLL_ONE_SIZE, &out, POLL_ONE_SIZE);
    ok(status == STATUS_PENDING, "expired-absolute poll -> %08lx", (unsigned long)status);
    ok(wait_done(event), "expiry never completed");
    ok(iosb.Status == STATUS_TIMEOUT, "expiry status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == POLL_EMPTY_SIZE, "expiry information %lx",
       (unsigned long)iosb.Information);
    ok(out.count == 0, "expiry count %u", out.count);
    ok(out.timeout == now.QuadPart, "expiry timeout echo");

    CloseHandle(event);
    NtClose(s);
}

static void test_poll_exclusive_displacement(void)
{
    struct afd_poll_params in;
    struct afd_poll_params outFirst, outSecond;
    IO_STATUS_BLOCK first, second;
    HANDLE s = NULL, firstEvent, secondEvent;
    IO_STATUS_BLOCK cancelIosb;
    NTSTATUS status;

    firstEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    secondEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    status = afd_tcp(&s, FALSE);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);

    memset(&in, 0, sizeof(in));
    in.timeout = AFD_TIMEOUT_INFINITE;
    in.count = 1;
    in.sockets[0].socket = (ULONG_PTR)s;
    in.sockets[0].flags = ~0;

    /* An exclusive main poll is displaced by the next exclusive; the new
     * one stays parked. */
    in.exclusive = TRUE;
    status = poll_raw(s, firstEvent, &first, &in, POLL_ONE_SIZE, &outFirst, POLL_ONE_SIZE);
    ok(status == STATUS_PENDING, "first exclusive -> %08lx", (unsigned long)status);
    status = poll_raw(s, secondEvent, &second, &in, POLL_ONE_SIZE, &outSecond, POLL_ONE_SIZE);
    ok(status == STATUS_PENDING, "second exclusive -> %08lx", (unsigned long)status);
    ok(wait_done(firstEvent), "the displaced exclusive never completed");
    ok(!is_signaled(secondEvent), "the displacing exclusive completed too");

    poison_iosb(&cancelIosb);
    status = NtCancelIoFile(s, &cancelIosb);
    ok(status == STATUS_SUCCESS, "cancel -> %08lx", (unsigned long)status);
    ok(wait_done(secondEvent), "cancel never completed the second poll");
    ok(second.Status == STATUS_CANCELLED, "cancelled poll status %08lx",
       (unsigned long)second.Status);

    /* A NON-exclusive main poll is displaced by nothing. */
    in.exclusive = FALSE;
    ResetEvent(firstEvent);
    ResetEvent(secondEvent);
    status = poll_raw(s, firstEvent, &first, &in, POLL_ONE_SIZE, &outFirst, POLL_ONE_SIZE);
    ok(status == STATUS_PENDING, "non-exclusive main -> %08lx", (unsigned long)status);
    in.exclusive = TRUE;
    status = poll_raw(s, secondEvent, &second, &in, POLL_ONE_SIZE, &outSecond, POLL_ONE_SIZE);
    ok(status == STATUS_PENDING, "exclusive follower -> %08lx", (unsigned long)status);
    ok(!is_signaled(firstEvent), "the non-exclusive main was displaced");
    ok(!is_signaled(secondEvent), "the follower completed");

    NtCancelIoFile(s, &cancelIosb);
    ok(wait_done(firstEvent) && wait_done(secondEvent), "cancel never completed the polls");

    CloseHandle(firstEvent);
    CloseHandle(secondEvent);
    NtClose(s);
}

/* The peer's send-shutdown with data still QUEUED does not raise HUP —
 * READ stands alone until the ring drains, and HUP arrives with the
 * drain (the ws2_32:afd test_poll shape around its check_poll_todo:
 * the pinned Wine reports READ|WRITE|CONNECT there, never HUP, and the
 * todo_wine rows make that the spec — Art. 6). */
static void test_halfclose_hup_after_drain(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE client = NULL, server = NULL, event;
    char buffer[8];
    ULONG got = 0;
    NTSTATUS status;

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!tcp_pair(&client, &server))
        return;

    status = afd_send_wait(server, "data", 4, NULL);
    ok(status == STATUS_SUCCESS, "send -> %08lx", (unsigned long)status);
    CHECK_POLL(client, event, AFD_POLL_READ, AFD_POLL_READ);

    {
        int how = 1; /* SD_SEND */
        status = NtDeviceIoControlFile(server, NULL, NULL, NULL, &iosb, IOCTL_AFD_WINE_SHUTDOWN,
                                       &how, sizeof(how), NULL, 0);
        ok(status == STATUS_SUCCESS, "shutdown -> %08lx", (unsigned long)status);
    }

    /* The FIN is behind the data: no HUP while the ring holds bytes. */
    CHECK_POLL(client, event, ~0, AFD_POLL_WRITE | AFD_POLL_CONNECT | AFD_POLL_READ);

    status = afd_recv_wait(client, buffer, sizeof(buffer), &got);
    ok(status == STATUS_SUCCESS && got == 4, "drain -> %08lx/%lu", (unsigned long)status,
       (unsigned long)got);
    CHECK_POLL(client, event, ~0, AFD_POLL_WRITE | AFD_POLL_CONNECT | AFD_POLL_HUP);

    NtClose(client);
    NtClose(server);
    CloseHandle(event);
}

START_TEST(afd_poll)
{
    test_poll_validation();
    test_poll_snapshot_and_levels();
    test_halfclose_hup_after_drain();
    test_poll_timeout_expiry();
    test_poll_exclusive_displacement();
}
