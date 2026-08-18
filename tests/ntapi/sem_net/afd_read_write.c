/*
 * sem_net/afd_read_write.c — NtReadFile/NtWriteFile work on socket
 * handles.
 *
 * From ws2_32:afd test_read_write, the ORACLE's rows (its todo_wine rows
 * — NULL/negative ByteOffset refusals — are Windows-only; the pinned
 * Wine accepts any offset and so does this kernel): an asynchronous
 * handle's read pends and completes like the ioctl path; a synchronous
 * handle's read BLOCKS the caller and answers its final status inline —
 * kernelbase's ReadFile/WriteFile on a SOCK_STREAM handle is how
 * msvcrt-level code does socket I/O without ws2_32.
 */
#include "util.h"

static void test_async_read_write(void)
{
    IO_STATUS_BLOCK readIosb, writeIosb;
    HANDLE client = NULL, server = NULL, event;
    char buffer[8];
    NTSTATUS status;

    if (!tcp_pair(&client, &server))
        return;
    event = CreateEventW(NULL, TRUE, FALSE, NULL);

    /* Write inline (the send window is open). */
    poison_iosb(&writeIosb);
    status = NtWriteFile(client, NULL, NULL, NULL, &writeIosb, "data", 4, NULL, NULL);
    ok(status == STATUS_SUCCESS, "write -> %08lx", (unsigned long)status);
    ok(writeIosb.Status == STATUS_SUCCESS, "write iosb %08lx", (unsigned long)writeIosb.Status);
    ok(writeIosb.Information == 4, "write information %lx", (unsigned long)writeIosb.Information);

    /* Read what arrived (waiting out the pend if the bytes are still in
     * flight), then park a read on the drained ring and complete it from
     * this same thread. */
    memset(buffer, 0xcc, sizeof(buffer));
    poison_iosb(&readIosb);
    status = NtReadFile(server, event, NULL, NULL, &readIosb, buffer, sizeof(buffer), NULL, NULL);
    if (status == STATUS_PENDING)
    {
        ok(wait_done(event), "read never completed");
        status = readIosb.Status;
    }
    ok(status == STATUS_SUCCESS, "read -> %08lx", (unsigned long)status);
    ok(readIosb.Information == 4, "read information %lx", (unsigned long)readIosb.Information);
    ok(memcmp(buffer, "data", 4) == 0, "read bytes");

    ResetEvent(event);
    memset(buffer, 0xcc, sizeof(buffer));
    poison_iosb(&readIosb);
    status = NtReadFile(server, event, NULL, NULL, &readIosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_PENDING, "empty read -> %08lx", (unsigned long)status);
    ok(readIosb.Status == IOSB_POISON_STATUS, "a pended read wrote its IOSB: %08lx",
       (unsigned long)readIosb.Status);

    status = NtWriteFile(client, NULL, NULL, NULL, &writeIosb, "more", 4, NULL, NULL);
    ok(status == STATUS_SUCCESS, "second write -> %08lx", (unsigned long)status);

    ok(wait_done(event), "parked read never completed");
    ok(readIosb.Status == STATUS_SUCCESS, "parked read status %08lx",
       (unsigned long)readIosb.Status);
    ok(readIosb.Information == 4, "parked read information %lx",
       (unsigned long)readIosb.Information);
    ok(memcmp(buffer, "more", 4) == 0, "parked read bytes");

    /* A nonzero ByteOffset is accepted and ignored (the oracle's shape;
     * Windows refuses — test_read_write's todo_wine rows). */
    ResetEvent(event);
    poison_iosb(&readIosb);
    {
        LARGE_INTEGER offset;
        offset.QuadPart = 1;
        memset(buffer, 0xcc, sizeof(buffer));
        status =
            NtReadFile(server, event, NULL, NULL, &readIosb, buffer, sizeof(buffer), &offset, NULL);
        ok(status == STATUS_PENDING, "offset read -> %08lx", (unsigned long)status);
        offset.QuadPart = 2;
        status = NtWriteFile(client, NULL, NULL, NULL, &writeIosb, "data", 4, &offset, NULL);
        ok(status == STATUS_SUCCESS, "offset write -> %08lx", (unsigned long)status);
        ok(wait_done(event), "offset read never completed");
        ok(readIosb.Status == STATUS_SUCCESS, "offset read status %08lx",
           (unsigned long)readIosb.Status);
        ok(memcmp(buffer, "data", 4) == 0, "offset read bytes");
    }

    CloseHandle(event);
    NtClose(client);
    NtClose(server);
}

typedef struct
{
    HANDLE handle;
    IO_STATUS_BLOCK iosb;
    char buffer[8];
    NTSTATUS status;
} SYNC_READ_CTX;

static DWORD WINAPI sync_read_worker(void *arg)
{
    SYNC_READ_CTX *ctx = arg;
    memset(ctx->buffer, 0xcc, sizeof(ctx->buffer));
    poison_iosb(&ctx->iosb);
    ctx->status = NtReadFile(ctx->handle, NULL, NULL, NULL, &ctx->iosb, ctx->buffer,
                             sizeof(ctx->buffer), NULL, NULL);
    return 0;
}

/* A SYNCHRONOUS handle blocks inside NtReadFile and answers its final
 * status — no STATUS_PENDING ever escapes. The block itself is pinned by
 * completion-from-another-thread: the worker cannot finish until this
 * thread writes. */
static void test_sync_read_blocks(void)
{
    struct sockaddr_in bound;
    IO_STATUS_BLOCK iosb;
    HANDLE listener = NULL, client = NULL, server, worker, event;
    ULONG accept_handle = 0;
    ULONG sent = 0;
    NTSTATUS status;
    SYNC_READ_CTX ctx;

    /* The reading end must be a SYNCHRONOUS handle: build the pair by
     * hand with a synchronous client. */
    status = afd_tcp(&listener, FALSE);
    ok(status == STATUS_SUCCESS, "listener -> %08lx", (unsigned long)status);
    status = afd_bind_loopback(listener, 0, &bound);
    ok(status == STATUS_SUCCESS, "bind -> %08lx", (unsigned long)status);
    status = afd_listen(listener, 1);
    ok(status == STATUS_SUCCESS, "listen -> %08lx", (unsigned long)status);
    status = afd_tcp(&client, TRUE); /* FILE_SYNCHRONOUS_IO_NONALERT */
    ok(status == STATUS_SUCCESS, "sync client -> %08lx", (unsigned long)status);
    status = afd_connect_loopback(client, sw16(bound.sin_port));
    ok(status == STATUS_SUCCESS, "connect -> %08lx", (unsigned long)status);
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(listener, event, NULL, NULL, &iosb, IOCTL_AFD_WINE_ACCEPT, NULL,
                                   0, &accept_handle, sizeof(accept_handle));
    if (status == STATUS_PENDING)
    {
        ok(wait_done(event), "accept never completed");
        status = iosb.Status;
    }
    ok(status == STATUS_SUCCESS, "accept -> %08lx", (unsigned long)status);
    CloseHandle(event);
    server = (HANDLE)(ULONG_PTR)accept_handle;

    ctx.handle = client;
    worker = CreateThread(NULL, 0, sync_read_worker, &ctx, 0, NULL);
    ok(worker != NULL, "CreateThread");

    /* This thread is the only writer; the worker joins only after it. */
    status = afd_send_wait(server, "sync", 4, &sent);
    ok(status == STATUS_SUCCESS && sent == 4, "send -> %08lx/%lu", (unsigned long)status,
       (unsigned long)sent);

    ok(WaitForSingleObject(worker, 30000) == WAIT_OBJECT_0, "worker never finished");
    CloseHandle(worker);
    ok(ctx.status == STATUS_SUCCESS, "sync read -> %08lx", (unsigned long)ctx.status);
    ok(ctx.iosb.Information == 4, "sync read information %lx", (unsigned long)ctx.iosb.Information);
    ok(memcmp(ctx.buffer, "sync", 4) == 0, "sync read bytes");

    NtClose(server);
    NtClose(client);
    NtClose(listener);
}

/* An ACCEPTED socket inherits its listener's synchronicity: minted from
 * a synchronous listener, NtReadFile on it blocks — even under FIONBIO
 * nonblocking, which governs the recv verbs, not the file API (the
 * ws2_32:afd test_read_write shape: "NtReadFile always blocks, even
 * when the socket is non-overlapped and nonblocking"). */
static void test_accepted_sync_read_blocks(void)
{
    struct sockaddr_in bound;
    IO_STATUS_BLOCK iosb;
    HANDLE listener = NULL, client = NULL, server, worker, event;
    ULONG accept_handle = 0;
    ULONG sent = 0;
    int nonblocking = 1;
    NTSTATUS status;
    SYNC_READ_CTX ctx;

    status = afd_tcp(&listener, TRUE); /* the SYNCHRONOUS listener */
    ok(status == STATUS_SUCCESS, "sync listener -> %08lx", (unsigned long)status);
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
        ok(wait_done(event), "accept never completed");
        status = iosb.Status;
    }
    ok(status == STATUS_SUCCESS, "accept -> %08lx", (unsigned long)status);
    CloseHandle(event);
    server = (HANDLE)(ULONG_PTR)accept_handle;

    /* Nonblocking mode must not turn NtReadFile into a refusal. */
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(server, NULL, NULL, NULL, &iosb, IOCTL_AFD_WINE_FIONBIO,
                                   &nonblocking, sizeof(nonblocking), NULL, 0);
    ok(status == STATUS_SUCCESS, "fionbio -> %08lx", (unsigned long)status);

    ctx.handle = server;
    worker = CreateThread(NULL, 0, sync_read_worker, &ctx, 0, NULL);
    ok(worker != NULL, "CreateThread");

    status = afd_send_wait(client, "inhr", 4, &sent);
    ok(status == STATUS_SUCCESS && sent == 4, "send -> %08lx/%lu", (unsigned long)status,
       (unsigned long)sent);

    ok(WaitForSingleObject(worker, 30000) == WAIT_OBJECT_0, "worker never finished");
    CloseHandle(worker);
    ok(ctx.status == STATUS_SUCCESS, "accepted sync read -> %08lx", (unsigned long)ctx.status);
    ok(ctx.iosb.Information == 4, "accepted sync read information %lx",
       (unsigned long)ctx.iosb.Information);
    ok(memcmp(ctx.buffer, "inhr", 4) == 0, "accepted sync read bytes");

    NtClose(server);
    NtClose(client);
    NtClose(listener);
}

/* Byte offsets on a socket are ignored, never validated: a negative
 * offset reads/writes exactly like a NULL one (the ws2_32:afd
 * test_read_write rows carry NT's STATUS_INVALID_PARAMETER as
 * todo_wine, so the pinned Wine's accept-anything IS the spec —
 * Art. 6). */
static void test_offsets_ignored(void)
{
    IO_STATUS_BLOCK iosb, iosb2;
    LARGE_INTEGER offset;
    HANDLE client = NULL, server = NULL, event;
    char buffer[8];
    NTSTATUS status;

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!tcp_pair(&client, &server))
        return;

    /* A parked read with offset -1 pends like any other. */
    memset(buffer, 0, sizeof(buffer));
    poison_iosb(&iosb);
    offset.QuadPart = -1;
    status = NtReadFile(server, event, NULL, NULL, &iosb, buffer, sizeof(buffer), &offset, NULL);
    ok(status == STATUS_PENDING, "offset -1 read -> %08lx", (unsigned long)status);

    /* A write with offset -3 lands on the stream. */
    poison_iosb(&iosb2);
    offset.QuadPart = -3;
    status = NtWriteFile(client, NULL, NULL, NULL, &iosb2, "data", 4, &offset, NULL);
    ok(status == STATUS_SUCCESS, "offset -3 write -> %08lx", (unsigned long)status);
    ok(iosb2.Information == 4, "offset -3 write information %lx",
       (unsigned long)iosb2.Information);

    ok(wait_done(event), "offset read never completed");
    ok(iosb.Status == STATUS_SUCCESS, "offset read status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 4, "offset read information %lx", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "data", 4) == 0, "offset read bytes");

    NtClose(client);
    NtClose(server);
    CloseHandle(event);
}

START_TEST(afd_read_write)
{
    test_async_read_write();
    test_sync_read_blocks();
    test_accepted_sync_read_blocks();
    test_offsets_ignored();
}
