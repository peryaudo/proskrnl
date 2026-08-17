/*
 * sem_net/afd_bind_listen.c — IOCTL_AFD_BIND's validation ladder, the
 * bound name in the OUTPUT buffer, IOCTL_AFD_GETSOCKNAME, and
 * IOCTL_AFD_LISTEN.
 *
 * The ladder is ws2_32:afd test_bind's, transcribed for the AF_INET leg
 * only (the v6 SOCKET surface is staged out of Net-2 — docs/24 §5): a
 * wrong family or a short address is STATUS_INVALID_ADDRESS, cutting
 * into the header itself is STATUS_INVALID_PARAMETER, a short OUTPUT
 * buffer is STATUS_INVALID_PARAMETER, a non-local address completes with
 * STATUS_INVALID_ADDRESS_COMPONENT, a second bind is
 * STATUS_ADDRESS_ALREADY_ASSOCIATED, and a conflicting bind completes
 * with STATUS_SHARING_VIOLATION. On the pinned Wine the well-formed
 * calls answer inline (Windows pends them; test_bind's todo_wine rows) —
 * the helper waits out either shape, and the refusals are pinned as the
 * ioctl's immediate return.
 */
#include "util.h"

#define BIND_IN_SIZE (sizeof(int) + sizeof(struct sockaddr_in))

/* One raw bind call with the given sizes; final status through the event. */
static NTSTATUS bind_raw(HANDLE s, void *params, ULONG in_size, void *out, ULONG out_size,
                         IO_STATUS_BLOCK *iosb)
{
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
    NTSTATUS status;
    poison_iosb(iosb);
    status = NtDeviceIoControlFile(s, event, NULL, NULL, iosb, IOCTL_AFD_BIND, params, in_size, out,
                                   out_size);
    if (status == STATUS_PENDING)
    {
        if (!wait_done(event))
            status = STATUS_IO_TIMEOUT;
        else
            status = iosb->Status;
    }
    CloseHandle(event);
    return status;
}

static void test_bind_validation(void)
{
    struct
    {
        struct afd_bind_params params;
        char space[sizeof(struct sockaddr_in)];
    } in;
    struct sockaddr_in *addr = (struct sockaddr_in *)&in.params.addr;
    struct sockaddr_in out;
    IO_STATUS_BLOCK iosb;
    HANDLE s = NULL;
    NTSTATUS status;

    status = afd_tcp(&s, FALSE);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);

    /* Wrong family. */
    memset(&in, 0, sizeof(in));
    in.params.addr.sa_family = 0xdead & 0xffff;
    status = bind_raw(s, &in.params, BIND_IN_SIZE, &out, sizeof(out), &iosb);
    ok(status == STATUS_INVALID_ADDRESS, "wrong family -> %08lx", (unsigned long)status);

    /* One byte short of a full sockaddr_in. */
    memset(&in, 0, sizeof(in));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = LOOPBACK_BE;
    status = bind_raw(s, &in.params, BIND_IN_SIZE - 1, &out, sizeof(out), &iosb);
    ok(status == STATUS_INVALID_ADDRESS, "short addr -> %08lx", (unsigned long)status);

    /* Down to sa_data: still INVALID_ADDRESS; into the header: INVALID_PARAMETER. */
    status = bind_raw(s, &in.params, sizeof(int) + 2, &out, sizeof(out), &iosb);
    ok(status == STATUS_INVALID_ADDRESS, "header-only addr -> %08lx", (unsigned long)status);
    status = bind_raw(s, &in.params, sizeof(int) + 1, &out, sizeof(out), &iosb);
    ok(status == STATUS_INVALID_PARAMETER, "cut header -> %08lx", (unsigned long)status);

    /* A short output buffer. */
    status = bind_raw(s, &in.params, BIND_IN_SIZE, &out, sizeof(out) - 1, &iosb);
    ok(status == STATUS_INVALID_PARAMETER, "short out -> %08lx", (unsigned long)status);

    /* A non-local address (192.0.2.0, TEST-NET-1) completes with
     * INVALID_ADDRESS_COMPONENT. */
    addr->sin_addr.s_addr = 0x000200c0; /* 192.0.2.0 network order */
    status = bind_raw(s, &in.params, BIND_IN_SIZE, &out, sizeof(out), &iosb);
    ok(status == STATUS_INVALID_ADDRESS_COMPONENT, "non-local -> %08lx", (unsigned long)status);

    NtClose(s);
}

static void test_bind_and_name(void)
{
    struct sockaddr_in bound, name;
    IO_STATUS_BLOCK iosb;
    HANDLE s = NULL, s2 = NULL;
    NTSTATUS status;

    status = afd_tcp(&s, FALSE);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);

    /* GETSOCKNAME before any bind refuses. */
    status = NtDeviceIoControlFile(s, NULL, NULL, NULL, &iosb, IOCTL_AFD_GETSOCKNAME, NULL, 0,
                                   &name, sizeof(name));
    ok(status == STATUS_INVALID_PARAMETER, "unbound name -> %08lx", (unsigned long)status);

    /* Bind to port 0: the OUTPUT carries the materialized name. */
    memset(&bound, 0xcc, sizeof(bound));
    status = afd_bind_loopback(s, 0, &bound);
    ok(status == STATUS_SUCCESS, "bind -> %08lx", (unsigned long)status);
    ok(bound.sin_family == AF_INET, "family %u", bound.sin_family);
    ok(bound.sin_addr.s_addr == LOOPBACK_BE, "address %08lx", (unsigned long)bound.sin_addr.s_addr);
    ok(bound.sin_port != 0, "expected a nonzero port");

    /* GETSOCKNAME answers the same name; a short buffer refuses. */
    memset(&name, 0xcc, sizeof(name));
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(s, NULL, NULL, NULL, &iosb, IOCTL_AFD_GETSOCKNAME, NULL, 0,
                                   &name, sizeof(name));
    ok(status == STATUS_SUCCESS, "sockname -> %08lx", (unsigned long)status);
    ok(iosb.Information == sizeof(name), "sockname info %lx", (unsigned long)iosb.Information);
    ok(memcmp(&name, &bound, sizeof(name)) == 0, "names differ");
    status = NtDeviceIoControlFile(s, NULL, NULL, NULL, &iosb, IOCTL_AFD_GETSOCKNAME, NULL, 0,
                                   &name, sizeof(name) - 1);
    ok(status == STATUS_BUFFER_TOO_SMALL, "short sockname -> %08lx", (unsigned long)status);

    /* A second bind on the same socket. */
    status = afd_bind_loopback(s, 0, NULL);
    ok(status == STATUS_ADDRESS_ALREADY_ASSOCIATED, "rebind -> %08lx", (unsigned long)status);

    /* A conflicting bind from another socket completes with
     * SHARING_VIOLATION. */
    status = afd_tcp(&s2, FALSE);
    ok(status == STATUS_SUCCESS, "second create -> %08lx", (unsigned long)status);
    status = afd_bind_loopback(s2, sw16(bound.sin_port), NULL);
    ok(status == STATUS_SHARING_VIOLATION, "conflicting bind -> %08lx", (unsigned long)status);
    NtClose(s2);
    NtClose(s);
}

static void test_bind_udp(void)
{
    struct sockaddr_in bound, name;
    IO_STATUS_BLOCK iosb;
    HANDLE s = NULL;
    NTSTATUS status;

    status = afd_udp(&s, FALSE);
    ok(status == STATUS_SUCCESS, "udp create -> %08lx", (unsigned long)status);
    memset(&bound, 0xcc, sizeof(bound));
    status = afd_bind_loopback(s, 0, &bound);
    ok(status == STATUS_SUCCESS, "udp bind -> %08lx", (unsigned long)status);
    ok(bound.sin_family == AF_INET && bound.sin_port != 0, "udp name %u:%u", bound.sin_family,
       sw16(bound.sin_port));

    memset(&name, 0xcc, sizeof(name));
    status = NtDeviceIoControlFile(s, NULL, NULL, NULL, &iosb, IOCTL_AFD_GETSOCKNAME, NULL, 0,
                                   &name, sizeof(name));
    ok(status == STATUS_SUCCESS, "udp sockname -> %08lx", (unsigned long)status);
    ok(memcmp(&name, &bound, sizeof(name)) == 0, "udp names differ");
    NtClose(s);
}

static void test_listen(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE s = NULL;
    int value;
    NTSTATUS status;

    status = afd_tcp(&s, FALSE);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);
    status = afd_bind_loopback(s, 0, NULL);
    ok(status == STATUS_SUCCESS, "bind -> %08lx", (unsigned long)status);

    /* Not yet listening. */
    value = 0xcc;
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(s, NULL, NULL, NULL, &iosb, IOCTL_AFD_WINE_GET_SO_ACCEPTCONN,
                                   NULL, 0, &value, sizeof(value));
    ok(status == STATUS_SUCCESS, "acceptconn -> %08lx", (unsigned long)status);
    ok(value == 0, "acceptconn %d before listen", value);

    status = afd_listen(s, 1);
    ok(status == STATUS_SUCCESS, "listen -> %08lx", (unsigned long)status);

    value = 0xcc;
    status = NtDeviceIoControlFile(s, NULL, NULL, NULL, &iosb, IOCTL_AFD_WINE_GET_SO_ACCEPTCONN,
                                   NULL, 0, &value, sizeof(value));
    ok(status == STATUS_SUCCESS, "acceptconn -> %08lx", (unsigned long)status);
    ok(value != 0, "acceptconn %d after listen", value);

    /* Listening again is idempotent at this boundary. */
    status = afd_listen(s, 4);
    ok(status == STATUS_SUCCESS, "re-listen -> %08lx", (unsigned long)status);
    NtClose(s);
}

START_TEST(afd_bind_listen)
{
    test_bind_validation();
    test_bind_and_name();
    test_bind_udp();
    test_listen();
}
