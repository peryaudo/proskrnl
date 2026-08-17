/*
 * sem_net/afd_nonblock.c — IOCTL_AFD_WINE_FIONBIO, the would-block
 * statuses, and the FIONBIO/event-select interlock.
 *
 * The interlock is ws2_32's own contract (dlls/ws2_32/socket.c FIONBIO:
 * "can't take a socket out of nonblocking mode while WSAAsyncSelect/
 * WSAEventSelect is active"): clearing nonblocking under an active event
 * mask refuses STATUS_INVALID_PARAMETER; an event select forces the
 * socket nonblocking implicitly.
 */
#include "util.h"

struct afd_event_select_params
{
    HANDLE event;
    int mask;
};

static NTSTATUS fionbio(HANDLE s, int on)
{
    IO_STATUS_BLOCK iosb;
    poison_iosb(&iosb);
    return NtDeviceIoControlFile(s, NULL, NULL, NULL, &iosb, IOCTL_AFD_WINE_FIONBIO, &on,
                                 sizeof(on), NULL, 0);
}

static void test_nonblocking_recv(void)
{
    struct afd_recv_params params;
    WSABUF wsabuf;
    IO_STATUS_BLOCK iosb;
    HANDLE client = NULL, server = NULL;
    char buffer[8];
    NTSTATUS status;

    if (!tcp_pair(&client, &server))
        return;

    status = fionbio(client, 1);
    ok(status == STATUS_SUCCESS, "fionbio on -> %08lx", (unsigned long)status);

    /* An empty ring answers the would-block status INLINE, IOSB
     * untouched. */
    wsabuf.len = sizeof(buffer);
    wsabuf.buf = buffer;
    memset(&params, 0, sizeof(params));
    params.buffers = &wsabuf;
    params.count = 1;
    params.msg_flags = AFD_MSG_NOT_OOB;
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(client, NULL, NULL, NULL, &iosb, IOCTL_AFD_RECV, &params,
                                   sizeof(params), NULL, 0);
    ok(status == STATUS_DEVICE_NOT_READY, "nonblocking empty recv -> %08lx", (unsigned long)status);
    ok(iosb.Status == IOSB_POISON_STATUS, "would-block wrote the IOSB: %08lx",
       (unsigned long)iosb.Status);

    /* AFD_RECV_FORCE_ASYNC overrides the nonblocking answer: the request
     * pends like a blocking socket's. */
    params.recv_flags = AFD_RECV_FORCE_ASYNC;
    {
        HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
        memset(buffer, 0xcc, sizeof(buffer));
        poison_iosb(&iosb);
        status = NtDeviceIoControlFile(client, event, NULL, NULL, &iosb, IOCTL_AFD_RECV, &params,
                                       sizeof(params), NULL, 0);
        ok(status == STATUS_PENDING, "forced-async recv -> %08lx", (unsigned long)status);
        status = afd_send_wait(server, "data", 4, NULL);
        ok(status == STATUS_SUCCESS, "peer send -> %08lx", (unsigned long)status);
        ok(wait_done(event), "forced-async recv never completed");
        ok(iosb.Status == STATUS_SUCCESS, "forced-async status %08lx", (unsigned long)iosb.Status);
        ok(iosb.Information == 4, "forced-async information %lx", (unsigned long)iosb.Information);
        CloseHandle(event);
    }

    /* Back to blocking: FIONBIO off works while no event mask is armed. */
    status = fionbio(client, 0);
    ok(status == STATUS_SUCCESS, "fionbio off -> %08lx", (unsigned long)status);

    NtClose(client);
    NtClose(server);
}

static void test_fionbio_event_select_interlock(void)
{
    struct afd_event_select_params select;
    IO_STATUS_BLOCK iosb;
    HANDLE client = NULL, server = NULL, event;
    NTSTATUS status;

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!tcp_pair(&client, &server))
        return;

    select.event = event;
    select.mask = AFD_POLL_READ;
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(client, NULL, NULL, NULL, &iosb, IOCTL_AFD_EVENT_SELECT, &select,
                                   sizeof(select), NULL, 0);
    ok(status == STATUS_SUCCESS, "select -> %08lx", (unsigned long)status);

    /* Setting nonblocking under a mask is fine... */
    status = fionbio(client, 1);
    ok(status == STATUS_SUCCESS, "fionbio on under mask -> %08lx", (unsigned long)status);
    /* ...clearing it is the interlock. */
    status = fionbio(client, 0);
    ok(status == STATUS_INVALID_PARAMETER, "fionbio off under mask -> %08lx",
       (unsigned long)status);

    /* Dropping the selection releases the interlock. */
    select.event = NULL;
    select.mask = 0;
    status = NtDeviceIoControlFile(client, NULL, NULL, NULL, &iosb, IOCTL_AFD_EVENT_SELECT, &select,
                                   sizeof(select), NULL, 0);
    ok(status == STATUS_SUCCESS, "clear select -> %08lx", (unsigned long)status);
    status = fionbio(client, 0);
    ok(status == STATUS_SUCCESS, "fionbio off after clear -> %08lx", (unsigned long)status);

    NtClose(client);
    NtClose(server);
    CloseHandle(event);
}

START_TEST(afd_nonblock)
{
    test_nonblocking_recv();
    test_fionbio_event_select_interlock();
}
