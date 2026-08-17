/*
 * sem_net/afd_sendrecv.c — the data path: IOCTL_AFD_RECV's validation and
 * pend/inline discrimination, scatter buffers, capture-at-issue, PEEK,
 * IOCTL_AFD_WINE_SENDMSG/RECVMSG, graceful close, shutdown, FIONREAD,
 * and the UDP datagram rules.
 *
 * Transcribed from ws2_32:afd test_recv, AF_INET/loopback only, with the
 * same-thread completion discipline: every pended recv is satisfied by
 * this thread's own peer send afterwards.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtCancelIoFile(HANDLE, PIO_STATUS_BLOCK);

static void test_recv_validation(void)
{
    struct afd_recv_params params;
    WSABUF wsabuf;
    IO_STATUS_BLOCK iosb;
    HANDLE client = NULL, server = NULL;
    char buffer[8];
    NTSTATUS status;

    if (!tcp_pair(&client, &server))
        return;

    /* NULL params. */
    poison_iosb(&iosb);
    status =
        NtDeviceIoControlFile(client, NULL, NULL, NULL, &iosb, IOCTL_AFD_RECV, NULL, 0, NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "null params -> %08lx", (unsigned long)status);

    /* One byte short. */
    wsabuf.len = sizeof(buffer);
    wsabuf.buf = buffer;
    memset(&params, 0, sizeof(params));
    params.buffers = &wsabuf;
    params.count = 1;
    params.msg_flags = AFD_MSG_NOT_OOB;
    status = NtDeviceIoControlFile(client, NULL, NULL, NULL, &iosb, IOCTL_AFD_RECV, &params,
                                   sizeof(params) - 1, NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "short params -> %08lx", (unsigned long)status);

    /* msg_flags without an OOB disposition, and with both. */
    params.msg_flags = 0;
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(client, NULL, NULL, NULL, &iosb, IOCTL_AFD_RECV, &params,
                                   sizeof(params), NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "no-disposition flags -> %08lx", (unsigned long)status);
    ok(iosb.Status == IOSB_POISON_STATUS, "refusal wrote the IOSB: %08lx",
       (unsigned long)iosb.Status);
    params.msg_flags = AFD_MSG_OOB | AFD_MSG_NOT_OOB;
    status = NtDeviceIoControlFile(client, NULL, NULL, NULL, &iosb, IOCTL_AFD_RECV, &params,
                                   sizeof(params), NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "both-dispositions flags -> %08lx",
       (unsigned long)status);

    NtClose(client);
    NtClose(server);
}

static void test_recv_pend_and_inline(void)
{
    struct afd_recv_params params;
    WSABUF wsabufs[2];
    IO_STATUS_BLOCK iosb;
    HANDLE client = NULL, server = NULL, event;
    char buffer[8];
    ULONG sent;
    NTSTATUS status;

    if (!tcp_pair(&client, &server))
        return;
    event = CreateEventW(NULL, TRUE, FALSE, NULL);

    /* The park: an empty ring pends, the IOSB stays untouched, and the
     * SAME THREAD completes it with the peer's send. */
    wsabufs[0].len = sizeof(buffer);
    wsabufs[0].buf = buffer;
    memset(&params, 0, sizeof(params));
    params.buffers = wsabufs;
    params.count = 1;
    params.msg_flags = AFD_MSG_NOT_OOB;
    memset(buffer, 0xcc, sizeof(buffer));
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(client, event, NULL, NULL, &iosb, IOCTL_AFD_RECV, &params,
                                   sizeof(params), NULL, 0);
    ok(status == STATUS_PENDING, "empty recv -> %08lx", (unsigned long)status);
    ok(iosb.Status == IOSB_POISON_STATUS, "a pended recv wrote its IOSB: %08lx",
       (unsigned long)iosb.Status);

    /* The param block and the WSABUF array need not remain valid once
     * the call returned: everything was captured at issue. */
    memset(&params, 0xcc, sizeof(params));
    memset(wsabufs, 0xcc, sizeof(wsabufs));

    status = afd_send_wait(server, "data", 5, &sent);
    ok(status == STATUS_SUCCESS && sent == 5, "peer send -> %08lx/%lu", (unsigned long)status,
       (unsigned long)sent);

    ok(wait_done(event), "recv never completed");
    ok(iosb.Status == STATUS_SUCCESS, "recv status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 5, "recv information %lx", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "data", 5) == 0, "recv bytes");

    /* Scatter: two buffers with a hole between them. */
    wsabufs[0].len = 2;
    wsabufs[0].buf = buffer;
    wsabufs[1].len = 4;
    wsabufs[1].buf = buffer + 3;
    memset(&params, 0, sizeof(params));
    params.buffers = wsabufs;
    params.count = 2;
    params.msg_flags = AFD_MSG_NOT_OOB;
    memset(buffer, 0xcc, sizeof(buffer));
    ResetEvent(event);
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(client, event, NULL, NULL, &iosb, IOCTL_AFD_RECV, &params,
                                   sizeof(params), NULL, 0);
    ok(status == STATUS_PENDING, "scatter recv -> %08lx", (unsigned long)status);
    status = afd_send_wait(server, "data", 5, &sent);
    ok(status == STATUS_SUCCESS, "peer send -> %08lx", (unsigned long)status);
    ok(wait_done(event), "scatter recv never completed");
    ok(iosb.Status == STATUS_SUCCESS, "scatter status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 5, "scatter information %lx", (unsigned long)iosb.Information);
    ok(memcmp(buffer,
              "da\xcc"
              "ta",
              5) == 0,
       "scatter bytes");

    /* Data already buffered answers inline — the non-PENDING return IS
     * the caller's discrimination (docs/19 §1). */
    status = afd_send_wait(server, "data", 5, &sent);
    ok(status == STATUS_SUCCESS, "peer send -> %08lx", (unsigned long)status);
    status = afd_recv_wait(client, buffer, 1, NULL); /* drain trigger: wait for arrival */
    ok(status == STATUS_SUCCESS, "arrival recv -> %08lx", (unsigned long)status);
    memset(buffer, 0xcc, sizeof(buffer));
    memset(&params, 0, sizeof(params));
    wsabufs[0].len = sizeof(buffer);
    wsabufs[0].buf = buffer;
    params.buffers = wsabufs;
    params.count = 1;
    params.msg_flags = AFD_MSG_NOT_OOB;
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(client, event, NULL, NULL, &iosb, IOCTL_AFD_RECV, &params,
                                   sizeof(params), NULL, 0);
    ok(status == STATUS_SUCCESS, "buffered recv -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "buffered recv iosb %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 4, "buffered recv information %lx", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "ata", 4) == 0, "buffered recv bytes");

    CloseHandle(event);
    NtClose(client);
    NtClose(server);
}

static void test_recv_peek_and_fionread(void)
{
    struct afd_recv_params params;
    WSABUF wsabuf;
    IO_STATUS_BLOCK iosb;
    HANDLE client = NULL, server = NULL;
    char buffer[8];
    int avail;
    ULONG sent;
    NTSTATUS status;

    if (!tcp_pair(&client, &server))
        return;

    status = afd_send_wait(server, "data", 4, &sent);
    ok(status == STATUS_SUCCESS, "send -> %08lx", (unsigned long)status);

    /* Wait for arrival with a 1-byte read, then put it back... no —
     * PEEK is the tool: spin on FIONREAD until the bytes are there (a
     * guest-clocked readiness poll, content-verdict; the bound is
     * wait_done's own 30 s worth of laps). */
    for (int lap = 0; lap < 30000; lap++)
    {
        avail = 0;
        status = NtDeviceIoControlFile(client, NULL, NULL, NULL, &iosb, IOCTL_AFD_WINE_FIONREAD,
                                       NULL, 0, &avail, sizeof(avail));
        ok(status == STATUS_SUCCESS, "fionread -> %08lx", (unsigned long)status);
        if (status != STATUS_SUCCESS || avail >= 4)
            break;
        LARGE_INTEGER interval;
        interval.QuadPart = -10000; /* 1 ms */
        NtDelayExecution(FALSE, &interval);
    }
    ok(avail == 4, "fionread %d", avail);

    /* PEEK does not consume. */
    wsabuf.len = sizeof(buffer);
    wsabuf.buf = buffer;
    memset(&params, 0, sizeof(params));
    params.buffers = &wsabuf;
    params.count = 1;
    params.msg_flags = AFD_MSG_NOT_OOB | AFD_MSG_PEEK;
    memset(buffer, 0xcc, sizeof(buffer));
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(client, NULL, NULL, NULL, &iosb, IOCTL_AFD_RECV, &params,
                                   sizeof(params), NULL, 0);
    ok(status == STATUS_SUCCESS, "peek -> %08lx", (unsigned long)status);
    ok(iosb.Information == 4, "peek information %lx", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "data", 4) == 0, "peek bytes");

    /* Still there: an ordinary recv takes the same bytes. */
    memset(buffer, 0xcc, sizeof(buffer));
    status = afd_recv_wait(client, buffer, sizeof(buffer), &sent);
    ok(status == STATUS_SUCCESS && sent == 4, "post-peek recv -> %08lx/%lu", (unsigned long)status,
       (unsigned long)sent);
    ok(memcmp(buffer, "data", 4) == 0, "post-peek bytes");

    NtClose(client);
    NtClose(server);
}

static void test_recvmsg_sendmsg(void)
{
    /* The WINE_RECVMSG/WINE_SENDMSG shapes ws2_32's WSARecvFrom/WSASendTo
     * issue, over a UDP pair — the address legs are the point. */
    struct afd_recvmsg_params rparams;
    struct afd_sendmsg_params sparams;
    struct sockaddr_in aBound, bBound, from;
    WSABUF wsabuf;
    IO_STATUS_BLOCK iosb;
    HANDLE a = NULL, b = NULL, event;
    char buffer[16];
    unsigned int ws_flags;
    int from_len;
    NTSTATUS status;

    status = afd_udp(&a, FALSE);
    ok(status == STATUS_SUCCESS, "a -> %08lx", (unsigned long)status);
    status = afd_udp(&b, FALSE);
    ok(status == STATUS_SUCCESS, "b -> %08lx", (unsigned long)status);
    status = afd_bind_loopback(a, 0, &aBound);
    ok(status == STATUS_SUCCESS, "a bind -> %08lx", (unsigned long)status);
    status = afd_bind_loopback(b, 0, &bBound);
    ok(status == STATUS_SUCCESS, "b bind -> %08lx", (unsigned long)status);
    event = CreateEventW(NULL, TRUE, FALSE, NULL);

    /* Park a recvmsg on a, with the source-address writeback legs armed. */
    wsabuf.len = sizeof(buffer);
    wsabuf.buf = buffer;
    memset(&from, 0xcc, sizeof(from));
    from_len = sizeof(from);
    ws_flags = 0xcccccccc;
    memset(&rparams, 0, sizeof(rparams));
    rparams.addr_ptr = (ULONG_PTR)&from;
    rparams.addr_len_ptr = (ULONG_PTR)&from_len;
    rparams.ws_flags_ptr = (ULONG_PTR)&ws_flags;
    rparams.count = 1;
    rparams.buffers_ptr = (ULONG_PTR)&wsabuf;
    memset(buffer, 0xcc, sizeof(buffer));
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(a, event, NULL, NULL, &iosb, IOCTL_AFD_WINE_RECVMSG, &rparams,
                                   sizeof(rparams), NULL, 0);
    ok(status == STATUS_PENDING, "recvmsg -> %08lx", (unsigned long)status);

    /* Same thread: sendmsg from b to a's bound name. */
    memset(&sparams, 0, sizeof(sparams));
    sparams.addr_ptr = (ULONG_PTR)&aBound;
    sparams.addr_len = sizeof(aBound);
    sparams.count = 1;
    sparams.buffers_ptr = (ULONG_PTR)&wsabuf;
    {
        WSABUF sendBuf;
        IO_STATUS_BLOCK sendIosb;
        sendBuf.len = 5;
        sendBuf.buf = (char *)"hello";
        sparams.buffers_ptr = (ULONG_PTR)&sendBuf;
        status = NtDeviceIoControlFile(b, NULL, NULL, NULL, &sendIosb, IOCTL_AFD_WINE_SENDMSG,
                                       &sparams, sizeof(sparams), NULL, 0);
        ok(status == STATUS_SUCCESS, "sendmsg -> %08lx", (unsigned long)status);
        ok(sendIosb.Information == 5, "sendmsg information %lx",
           (unsigned long)sendIosb.Information);
    }

    ok(wait_done(event), "recvmsg never completed");
    ok(iosb.Status == STATUS_SUCCESS, "recvmsg status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 5, "recvmsg information %lx", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "hello", 5) == 0, "recvmsg bytes");
    /* The source-address writeback: b's bound name. */
    ok(from.sin_family == AF_INET, "from family %u", from.sin_family);
    ok(from.sin_addr.s_addr == LOOPBACK_BE, "from address %08lx",
       (unsigned long)from.sin_addr.s_addr);
    ok(from.sin_port == bBound.sin_port, "from port %u != %u", sw16(from.sin_port),
       sw16(bBound.sin_port));
    ok(from_len == sizeof(from), "from_len %d", from_len);
    /* ws_flags is written back only when flags come back set (a clean
     * datagram leaves the caller's word alone — measured on the oracle). */
    ok(ws_flags == 0xcccccccc, "ws_flags %#x", ws_flags);

    CloseHandle(event);
    NtClose(a);
    NtClose(b);
}

static void test_udp_short_read(void)
{
    struct sockaddr_in aBound;
    struct afd_sendmsg_params sparams;
    WSABUF sendBuf, wsabuf;
    struct afd_recv_params params;
    IO_STATUS_BLOCK iosb, sendIosb;
    HANDLE a = NULL, b = NULL, event;
    char buffer[6];
    NTSTATUS status;

    status = afd_udp(&a, FALSE);
    ok(status == STATUS_SUCCESS, "a -> %08lx", (unsigned long)status);
    status = afd_udp(&b, FALSE);
    ok(status == STATUS_SUCCESS, "b -> %08lx", (unsigned long)status);
    status = afd_bind_loopback(a, 0, &aBound);
    ok(status == STATUS_SUCCESS, "a bind -> %08lx", (unsigned long)status);
    event = CreateEventW(NULL, TRUE, FALSE, NULL);

    /* Park a short recv, then land a 9-byte datagram on it: the pended
     * completion carries STATUS_BUFFER_OVERFLOW and the truncated
     * length; the datagram's tail is GONE (datagram semantics, not the
     * pipe message-tail rule). */
    wsabuf.len = sizeof(buffer);
    wsabuf.buf = buffer;
    memset(&params, 0, sizeof(params));
    params.buffers = &wsabuf;
    params.count = 1;
    params.msg_flags = AFD_MSG_NOT_OOB;
    memset(buffer, 0xcc, sizeof(buffer));
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(a, event, NULL, NULL, &iosb, IOCTL_AFD_RECV, &params,
                                   sizeof(params), NULL, 0);
    ok(status == STATUS_PENDING, "short udp recv -> %08lx", (unsigned long)status);

    memset(&sparams, 0, sizeof(sparams));
    sparams.addr_ptr = (ULONG_PTR)&aBound;
    sparams.addr_len = sizeof(aBound);
    sparams.count = 1;
    sendBuf.len = 9;
    sendBuf.buf = (char *)"moredata";
    sparams.buffers_ptr = (ULONG_PTR)&sendBuf;
    /* iosb is the parked recv's — the send takes its OWN block, or the
     * send's inline completion races the recv's pended one for the same
     * word (measured: the shared-iosb version passed locally for dozens
     * of runs and lost the race on a CI runner). */
    status = NtDeviceIoControlFile(b, NULL, NULL, NULL, &sendIosb, IOCTL_AFD_WINE_SENDMSG, &sparams,
                                   sizeof(sparams), NULL, 0);
    ok(status == STATUS_SUCCESS || status == STATUS_PENDING, "sendto -> %08lx",
       (unsigned long)status);

    ok(wait_done(event), "short udp recv never completed");
    ok(iosb.Status == STATUS_BUFFER_OVERFLOW, "short udp status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 6, "short udp information %lx", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "moreda", 6) == 0, "short udp bytes");

    CloseHandle(event);
    NtClose(a);
    NtClose(b);
}

static void test_close_and_shutdown(void)
{
    struct afd_recv_params params;
    WSABUF wsabuf;
    IO_STATUS_BLOCK iosb;
    HANDLE client = NULL, server = NULL, event;
    char buffer[8];
    int how;
    NTSTATUS status;

    if (!tcp_pair(&client, &server))
        return;
    event = CreateEventW(NULL, TRUE, FALSE, NULL);

    /* The peer's graceful close completes a pended recv with SUCCESS and
     * zero bytes — nothing else can complete it. */
    wsabuf.len = sizeof(buffer);
    wsabuf.buf = buffer;
    memset(&params, 0, sizeof(params));
    params.buffers = &wsabuf;
    params.count = 1;
    params.msg_flags = AFD_MSG_NOT_OOB;
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(client, event, NULL, NULL, &iosb, IOCTL_AFD_RECV, &params,
                                   sizeof(params), NULL, 0);
    ok(status == STATUS_PENDING, "recv -> %08lx", (unsigned long)status);

    NtClose(server);

    ok(wait_done(event), "recv never completed by the close");
    ok(iosb.Status == STATUS_SUCCESS, "close-completed recv status %08lx",
       (unsigned long)iosb.Status);
    ok(iosb.Information == 0, "close-completed recv information %lx",
       (unsigned long)iosb.Information);

    /* shutdown(SD_RECEIVE), then recv refuses inline. */
    how = 0; /* SD_RECEIVE */
    status = NtDeviceIoControlFile(client, NULL, NULL, NULL, &iosb, IOCTL_AFD_WINE_SHUTDOWN, &how,
                                   sizeof(how), NULL, 0);
    ok(status == STATUS_SUCCESS, "shutdown -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(client, event, NULL, NULL, &iosb, IOCTL_AFD_RECV, &params,
                                   sizeof(params), NULL, 0);
    ok(status == STATUS_PIPE_DISCONNECTED, "post-shutdown recv -> %08lx", (unsigned long)status);

    CloseHandle(event);
    NtClose(client);
}

START_TEST(afd_sendrecv)
{
    test_recv_validation();
    test_recv_pend_and_inline();
    test_recv_peek_and_fionread();
    test_recvmsg_sendmsg();
    test_udp_short_read();
    test_close_and_shutdown();
}
