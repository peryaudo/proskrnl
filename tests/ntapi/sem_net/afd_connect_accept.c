/*
 * sem_net/afd_connect_accept.c — IOCTL_AFD_WINE_CONNECT,
 * IOCTL_AFD_WINE_ACCEPT (the ULONG-handle-in-the-output convention),
 * IOCTL_AFD_WINE_ACCEPT_INTO, and IOCTL_AFD_WINE_GETPEERNAME.
 *
 * The property every accept case is really about (the sem_pipe
 * pended_read discipline): the ISSUING THREAD KEEPS RUNNING — the accept
 * pends, the same thread connects the client, and the accept completes
 * with a handle value in the caller's output buffer that IS a working
 * socket (ws2_32's accept() does exactly this dance,
 * dlls/ws2_32/socket.c accept: the output ULONG becomes the SOCKET).
 */
#include "util.h"

static void test_connect(void)
{
    struct sockaddr_in bound, peer;
    IO_STATUS_BLOCK iosb;
    HANDLE listener = NULL, client = NULL;
    NTSTATUS status;

    status = afd_tcp(&listener, FALSE);
    ok(status == STATUS_SUCCESS, "listener -> %08lx", (unsigned long)status);
    status = afd_bind_loopback(listener, 0, &bound);
    ok(status == STATUS_SUCCESS, "bind -> %08lx", (unsigned long)status);
    status = afd_listen(listener, 1);
    ok(status == STATUS_SUCCESS, "listen -> %08lx", (unsigned long)status);

    status = afd_tcp(&client, FALSE);
    ok(status == STATUS_SUCCESS, "client -> %08lx", (unsigned long)status);

    /* GETPEERNAME before the connect refuses. */
    status = NtDeviceIoControlFile(client, NULL, NULL, NULL, &iosb, IOCTL_AFD_WINE_GETPEERNAME,
                                   NULL, 0, &peer, sizeof(peer));
    ok(status == STATUS_INVALID_CONNECTION, "unconnected peername -> %08lx", (unsigned long)status);

    status = afd_connect_loopback(client, sw16(bound.sin_port));
    ok(status == STATUS_SUCCESS, "connect -> %08lx", (unsigned long)status);

    /* The peer name is the listener's bound name. */
    memset(&peer, 0xcc, sizeof(peer));
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(client, NULL, NULL, NULL, &iosb, IOCTL_AFD_WINE_GETPEERNAME,
                                   NULL, 0, &peer, sizeof(peer));
    ok(status == STATUS_SUCCESS, "peername -> %08lx", (unsigned long)status);
    ok(peer.sin_family == AF_INET, "peer family %u", peer.sin_family);
    ok(peer.sin_addr.s_addr == LOOPBACK_BE, "peer address %08lx",
       (unsigned long)peer.sin_addr.s_addr);
    ok(peer.sin_port == bound.sin_port, "peer port %u != %u", sw16(peer.sin_port),
       sw16(bound.sin_port));

    /* A second connect on a connected socket. */
    status = afd_connect_loopback(client, sw16(bound.sin_port));
    ok(status == STATUS_CONNECTION_ACTIVE, "reconnect -> %08lx", (unsigned long)status);

    NtClose(client);
    NtClose(listener);
}

static void test_connect_refused(void)
{
    struct sockaddr_in bound;
    HANDLE probe = NULL, client = NULL;
    NTSTATUS status;

    /* Learn a port that is certainly closed: bind a socket to an
     * ephemeral port and close it without listening. */
    status = afd_tcp(&probe, FALSE);
    ok(status == STATUS_SUCCESS, "probe -> %08lx", (unsigned long)status);
    status = afd_bind_loopback(probe, 0, &bound);
    ok(status == STATUS_SUCCESS, "probe bind -> %08lx", (unsigned long)status);
    NtClose(probe);

    status = afd_tcp(&client, FALSE);
    ok(status == STATUS_SUCCESS, "client -> %08lx", (unsigned long)status);
    status = afd_connect_loopback(client, sw16(bound.sin_port));
    ok(status == STATUS_CONNECTION_REFUSED, "dead-port connect -> %08lx", (unsigned long)status);
    NtClose(client);
}

/* The pended accept: issued on an empty backlog, satisfied by this same
 * thread's client connect, output = a ULONG handle value that works. */
static void test_pended_accept(void)
{
    struct sockaddr_in bound, peer;
    IO_STATUS_BLOCK iosb, peerIosb;
    HANDLE listener = NULL, client = NULL, server, event;
    ULONG accept_handle;
    ULONG got;
    char byte;
    NTSTATUS status;

    status = afd_tcp(&listener, FALSE);
    ok(status == STATUS_SUCCESS, "listener -> %08lx", (unsigned long)status);
    status = afd_bind_loopback(listener, 0, &bound);
    ok(status == STATUS_SUCCESS, "bind -> %08lx", (unsigned long)status);
    status = afd_listen(listener, 1);
    ok(status == STATUS_SUCCESS, "listen -> %08lx", (unsigned long)status);

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    accept_handle = 0xcccccccc;
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(listener, event, NULL, NULL, &iosb, IOCTL_AFD_WINE_ACCEPT, NULL,
                                   0, &accept_handle, sizeof(accept_handle));
    ok(status == STATUS_PENDING, "empty-backlog accept -> %08lx", (unsigned long)status);
    ok(iosb.Status == IOSB_POISON_STATUS, "a pended accept wrote its IOSB: %08lx",
       (unsigned long)iosb.Status);

    /* The whole point: this thread still runs, and it completes the accept. */
    status = afd_tcp(&client, FALSE);
    ok(status == STATUS_SUCCESS, "client -> %08lx", (unsigned long)status);
    status = afd_connect_loopback(client, sw16(bound.sin_port));
    ok(status == STATUS_SUCCESS, "connect -> %08lx", (unsigned long)status);

    ok(wait_done(event), "accept never completed");
    ok(iosb.Status == STATUS_SUCCESS, "accept status %08lx", (unsigned long)iosb.Status);
    /* Information stays 0 — the handle is the output BUFFER's content,
     * not a byte count (measured on the oracle). */
    ok(iosb.Information == 0, "accept information %lx", (unsigned long)iosb.Information);
    ok(accept_handle != 0 && accept_handle != 0xcccccccc, "no handle materialized");
    CloseHandle(event);

    /* The minted handle is a working connected socket: it names its peer
     * and carries a byte in each direction. */
    server = (HANDLE)(ULONG_PTR)accept_handle;
    memset(&peer, 0xcc, sizeof(peer));
    status = NtDeviceIoControlFile(server, NULL, NULL, NULL, &peerIosb, IOCTL_AFD_WINE_GETPEERNAME,
                                   NULL, 0, &peer, sizeof(peer));
    ok(status == STATUS_SUCCESS, "accepted peername -> %08lx", (unsigned long)status);
    ok(peer.sin_addr.s_addr == LOOPBACK_BE, "accepted peer address %08lx",
       (unsigned long)peer.sin_addr.s_addr);

    status = afd_send_wait(server, "S", 1, &got);
    ok(status == STATUS_SUCCESS && got == 1, "server send -> %08lx/%lu", (unsigned long)status,
       (unsigned long)got);
    byte = 0;
    status = afd_recv_wait(client, &byte, 1, &got);
    ok(status == STATUS_SUCCESS && got == 1 && byte == 'S', "client recv -> %08lx/%lu/%c",
       (unsigned long)status, (unsigned long)got, byte);

    status = afd_send_wait(client, "C", 1, &got);
    ok(status == STATUS_SUCCESS && got == 1, "client send -> %08lx/%lu", (unsigned long)status,
       (unsigned long)got);
    byte = 0;
    status = afd_recv_wait(server, &byte, 1, &got);
    ok(status == STATUS_SUCCESS && got == 1 && byte == 'C', "server recv -> %08lx/%lu/%c",
       (unsigned long)status, (unsigned long)got, byte);

    NtClose(server);
    NtClose(client);
    NtClose(listener);
}

/* An accept with the connection already queued completes without pending
 * being required (docs/19 §1: pending is permitted, never required — the
 * discrimination the caller reads is the non-PENDING return). On the
 * pinned Wine even this shape pends and completes at once; both are
 * inside the contract, so the pin is the FINAL status and the handle. */
static void test_ready_accept(void)
{
    struct sockaddr_in bound;
    IO_STATUS_BLOCK iosb;
    HANDLE listener = NULL, client = NULL, event;
    ULONG accept_handle = 0;
    NTSTATUS status;

    status = afd_tcp(&listener, FALSE);
    ok(status == STATUS_SUCCESS, "listener -> %08lx", (unsigned long)status);
    status = afd_bind_loopback(listener, 0, &bound);
    ok(status == STATUS_SUCCESS, "bind -> %08lx", (unsigned long)status);
    status = afd_listen(listener, 1);
    ok(status == STATUS_SUCCESS, "listen -> %08lx", (unsigned long)status);
    status = afd_tcp(&client, FALSE);
    ok(status == STATUS_SUCCESS, "client -> %08lx", (unsigned long)status);
    status = afd_connect_loopback(client, sw16(bound.sin_port));
    ok(status == STATUS_SUCCESS, "connect -> %08lx", (unsigned long)status);

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(listener, event, NULL, NULL, &iosb, IOCTL_AFD_WINE_ACCEPT, NULL,
                                   0, &accept_handle, sizeof(accept_handle));
    if (status == STATUS_PENDING)
    {
        ok(wait_done(event), "ready accept never completed");
        status = iosb.Status;
    }
    ok(status == STATUS_SUCCESS, "ready accept -> %08lx", (unsigned long)status);
    ok(accept_handle != 0, "no handle");
    CloseHandle(event);

    NtClose((HANDLE)(ULONG_PTR)accept_handle);
    NtClose(client);
    NtClose(listener);
}

/* IOCTL_AFD_WINE_ACCEPT_INTO: the AcceptEx substrate — the acceptor is a
 * pre-created bare socket, the listener's ioctl grafts the connection
 * onto it. recv_len 0 keeps the data/address legs out of this pin. */
static void test_accept_into(void)
{
    struct afd_accept_into_params params;
    struct sockaddr_in bound, peer;
    IO_STATUS_BLOCK iosb;
    HANDLE listener = NULL, client = NULL, acceptor = NULL, event;
    char dest[2 * (sizeof(struct sockaddr_in) + 16)];
    NTSTATUS status;

    status = afd_tcp(&listener, FALSE);
    ok(status == STATUS_SUCCESS, "listener -> %08lx", (unsigned long)status);
    status = afd_bind_loopback(listener, 0, &bound);
    ok(status == STATUS_SUCCESS, "bind -> %08lx", (unsigned long)status);
    status = afd_listen(listener, 1);
    ok(status == STATUS_SUCCESS, "listen -> %08lx", (unsigned long)status);
    status = afd_tcp(&acceptor, FALSE);
    ok(status == STATUS_SUCCESS, "acceptor -> %08lx", (unsigned long)status);

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(&params, 0, sizeof(params));
    params.accept_handle = (ULONG)(ULONG_PTR)acceptor;
    params.recv_len = 0;
    params.local_len = sizeof(struct sockaddr_in) + 16;
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(listener, event, NULL, NULL, &iosb, IOCTL_AFD_WINE_ACCEPT_INTO,
                                   &params, sizeof(params), dest, sizeof(dest));
    ok(status == STATUS_PENDING, "accept-into -> %08lx", (unsigned long)status);

    status = afd_tcp(&client, FALSE);
    ok(status == STATUS_SUCCESS, "client -> %08lx", (unsigned long)status);
    status = afd_connect_loopback(client, sw16(bound.sin_port));
    ok(status == STATUS_SUCCESS, "connect -> %08lx", (unsigned long)status);

    ok(wait_done(event), "accept-into never completed");
    ok(iosb.Status == STATUS_SUCCESS, "accept-into status %08lx", (unsigned long)iosb.Status);
    CloseHandle(event);

    /* The acceptor is now the connection. */
    memset(&peer, 0xcc, sizeof(peer));
    status = NtDeviceIoControlFile(acceptor, NULL, NULL, NULL, &iosb, IOCTL_AFD_WINE_GETPEERNAME,
                                   NULL, 0, &peer, sizeof(peer));
    ok(status == STATUS_SUCCESS, "acceptor peername -> %08lx", (unsigned long)status);
    ok(peer.sin_addr.s_addr == LOOPBACK_BE, "acceptor peer %08lx",
       (unsigned long)peer.sin_addr.s_addr);

    NtClose(acceptor);
    NtClose(client);
    NtClose(listener);
}

START_TEST(afd_connect_accept)
{
    test_connect();
    test_connect_refused();
    test_pended_accept();
    test_ready_accept();
    test_accept_into();
}
