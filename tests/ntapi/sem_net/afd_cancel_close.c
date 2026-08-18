/*
 * sem_net/afd_cancel_close.c — every way a parked socket request dies:
 * NtCancelIoFile, NtCancelIoFileEx (targeted, leaving the other request
 * parked), the handle's close, and the issuing thread's exit.
 *
 * The thread-exit row is ws2_32:afd test_async_thread_termination's
 * non-completion-port half, pinned NOT todo there: "asyncs without
 * completion port are always cancelled on thread exit" — an exiting
 * thread's parked socket I/O completes STATUS_CANCELLED, event
 * included. (npfs deliberately does NOT sweep on thread exit — docs/03
 * "CUI-3 SCM notes" — so this is a per-device behavior, pinned per
 * device.)
 */
#include "util.h"

/* One parked recv on `s` through `iosb`/`event`; buffer is the caller's. */
static NTSTATUS park_recv(HANDLE s, HANDLE event, IO_STATUS_BLOCK *iosb, char *buffer, ULONG length)
{
    WSABUF wsabuf;
    struct afd_recv_params params;
    wsabuf.len = length;
    wsabuf.buf = buffer;
    memset(&params, 0, sizeof(params));
    params.buffers = &wsabuf;
    params.count = 1;
    params.msg_flags = AFD_MSG_NOT_OOB;
    poison_iosb(iosb);
    return NtDeviceIoControlFile(s, event, NULL, NULL, iosb, IOCTL_AFD_RECV, &params,
                                 sizeof(params), NULL, 0);
}

static void test_cancel_io_file(void)
{
    IO_STATUS_BLOCK iosb, cancelIosb;
    HANDLE client = NULL, server = NULL, event;
    char buffer[8];
    NTSTATUS status;

    if (!tcp_pair(&client, &server))
        return;
    event = CreateEventW(NULL, TRUE, FALSE, NULL);

    status = park_recv(client, event, &iosb, buffer, sizeof(buffer));
    ok(status == STATUS_PENDING, "recv -> %08lx", (unsigned long)status);

    poison_iosb(&cancelIosb);
    status = NtCancelIoFile(client, &cancelIosb);
    ok(status == STATUS_SUCCESS, "cancel -> %08lx", (unsigned long)status);
    ok(wait_done(event), "cancelled recv never completed");
    ok(iosb.Status == STATUS_CANCELLED, "cancelled recv status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 0, "cancelled recv information %lx", (unsigned long)iosb.Information);

    /* The socket survives its cancel: data still flows. */
    {
        ULONG got = 0;
        status = afd_send_wait(server, "x", 1, NULL);
        ok(status == STATUS_SUCCESS, "post-cancel send -> %08lx", (unsigned long)status);
        status = afd_recv_wait(client, buffer, 1, &got);
        ok(status == STATUS_SUCCESS && got == 1 && buffer[0] == 'x', "post-cancel recv %08lx",
           (unsigned long)status);
    }

    CloseHandle(event);
    NtClose(client);
    NtClose(server);
}

static void test_cancel_targeted(void)
{
    IO_STATUS_BLOCK first, second, cancelIosb;
    HANDLE client = NULL, server = NULL, firstEvent, secondEvent;
    char firstBuffer[4], secondBuffer[4];
    NTSTATUS status;

    if (!tcp_pair(&client, &server))
        return;
    firstEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    secondEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    status = park_recv(client, firstEvent, &first, firstBuffer, sizeof(firstBuffer));
    ok(status == STATUS_PENDING, "first recv -> %08lx", (unsigned long)status);
    status = park_recv(client, secondEvent, &second, secondBuffer, sizeof(secondBuffer));
    ok(status == STATUS_PENDING, "second recv -> %08lx", (unsigned long)status);

    /* Cancel ONLY the first (NtCancelIoFileEx keyed on its IOSB). */
    poison_iosb(&cancelIosb);
    status = NtCancelIoFileEx(client, &first, &cancelIosb);
    ok(status == STATUS_SUCCESS, "targeted cancel -> %08lx", (unsigned long)status);
    ok(wait_done(firstEvent), "first recv never completed");
    ok(first.Status == STATUS_CANCELLED, "first status %08lx", (unsigned long)first.Status);
    ok(second.Status == IOSB_POISON_STATUS, "the targeted cancel took the second too: %08lx",
       (unsigned long)second.Status);

    /* The survivor still works. */
    status = afd_send_wait(server, "AB", 2, NULL);
    ok(status == STATUS_SUCCESS, "send -> %08lx", (unsigned long)status);
    ok(wait_done(secondEvent), "second recv never completed");
    ok(second.Status == STATUS_SUCCESS, "second status %08lx", (unsigned long)second.Status);
    ok(second.Information == 2, "second information %lx", (unsigned long)second.Information);
    ok(memcmp(secondBuffer, "AB", 2) == 0, "second bytes");

    CloseHandle(firstEvent);
    CloseHandle(secondEvent);
    NtClose(client);
    NtClose(server);
}

static void test_close_cancels(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE client = NULL, server = NULL, event;
    char buffer[8];
    NTSTATUS status;

    if (!tcp_pair(&client, &server))
        return;
    event = CreateEventW(NULL, TRUE, FALSE, NULL);

    status = park_recv(client, event, &iosb, buffer, sizeof(buffer));
    ok(status == STATUS_PENDING, "recv -> %08lx", (unsigned long)status);

    NtClose(client);

    ok(wait_done(event), "close never completed the recv");
    /* The close completes it with STATUS_HANDLES_CLOSED (measured on the
     * oracle; real NT answers STATUS_CANCELLED — ws2_32:afd test_recv
     * carries the same divergence as todo_wine, so the Wine answer IS
     * the spec here, Art. 6). */
    ok(iosb.Status == STATUS_HANDLES_CLOSED, "close-cancelled recv status %08lx",
       (unsigned long)iosb.Status);
    ok(iosb.Information == 0, "close-cancelled recv information %lx",
       (unsigned long)iosb.Information);

    CloseHandle(event);
    NtClose(server);
}

typedef struct
{
    HANDLE socket;
    HANDLE event;
    IO_STATUS_BLOCK iosb;
    char buffer[8];
    NTSTATUS status;
} EXIT_CTX;

static DWORD WINAPI exiting_parker(void *arg)
{
    EXIT_CTX *ctx = arg;
    ctx->status = park_recv(ctx->socket, ctx->event, &ctx->iosb, ctx->buffer, sizeof(ctx->buffer));
    return 0; /* the exit is the test */
}

static void test_thread_exit_cancels(void)
{
    HANDLE client = NULL, server = NULL, worker;
    EXIT_CTX ctx;
    NTSTATUS status;

    if (!tcp_pair(&client, &server))
        return;
    ctx.socket = client;
    ctx.event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ctx.status = IOSB_POISON_STATUS;

    worker = CreateThread(NULL, 0, exiting_parker, &ctx, 0, NULL);
    ok(worker != NULL, "CreateThread");
    ok(WaitForSingleObject(worker, 30000) == WAIT_OBJECT_0, "worker never exited");
    CloseHandle(worker);
    ok(ctx.status == STATUS_PENDING, "worker's recv -> %08lx", (unsigned long)ctx.status);

    /* The exit is the cancel: the request completes CANCELLED with the
     * event fired, and nothing this thread does is part of it. */
    ok(wait_done(ctx.event), "thread exit never completed the recv");
    ok(ctx.iosb.Status == STATUS_CANCELLED, "exit-cancelled recv status %08lx",
       (unsigned long)ctx.iosb.Status);

    /* The socket itself survives its issuer. */
    {
        char byte = 0;
        ULONG got = 0;
        status = afd_send_wait(server, "y", 1, NULL);
        ok(status == STATUS_SUCCESS, "post-exit send -> %08lx", (unsigned long)status);
        status = afd_recv_wait(client, &byte, 1, &got);
        ok(status == STATUS_SUCCESS && got == 1 && byte == 'y', "post-exit recv %08lx",
           (unsigned long)status);
    }

    CloseHandle(ctx.event);
    NtClose(client);
    NtClose(server);
}

NTSYSAPI NTSTATUS NTAPI NtSetInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
                                             FILE_INFORMATION_CLASS);
NTSYSAPI NTSTATUS NTAPI NtRemoveIoCompletion(HANDLE, PULONG_PTR, PULONG_PTR, PIO_STATUS_BLOCK,
                                             PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtCreateIoCompletion(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);

typedef struct
{
    HANDLE CompletionPort;
    PVOID CompletionKey;
} TEST_FILE_COMPLETION_INFORMATION;

typedef struct
{
    HANDLE socket;
    IO_STATUS_BLOCK iosb;
    char buffer[8];
    WSABUF wsabuf;
    struct afd_recv_params params;
    NTSTATUS status;
} PORT_EXIT_CTX;

static DWORD WINAPI port_exiting_parker(void *arg)
{
    PORT_EXIT_CTX *ctx = arg;

    ctx->wsabuf.len = sizeof(ctx->buffer);
    ctx->wsabuf.buf = ctx->buffer;
    memset(&ctx->params, 0, sizeof(ctx->params));
    ctx->params.buffers = &ctx->wsabuf;
    ctx->params.count = 1;
    ctx->params.msg_flags = AFD_MSG_NOT_OOB;
    poison_iosb(&ctx->iosb);
    /* NO event, an ApcContext, a port-bound file: the one shape a thread
     * exit does NOT cancel. */
    ctx->status = NtDeviceIoControlFile(ctx->socket, NULL, NULL, (PVOID)(ULONG_PTR)0xfeedf00d,
                                        &ctx->iosb, IOCTL_AFD_RECV, &ctx->params,
                                        sizeof(ctx->params), NULL, 0);
    return 0;
}

static void test_thread_exit_port_exemption(void)
{
    HANDLE client = NULL, server = NULL, worker, port = NULL;
    TEST_FILE_COMPLETION_INFORMATION completion;
    IO_STATUS_BLOCK iosb, packetIosb;
    PORT_EXIT_CTX ctx;
    ULONG_PTR key = 0x11, value = 0x22;
    LARGE_INTEGER zero;
    NTSTATUS status;

    if (!tcp_pair(&client, &server))
        return;

    status = NtCreateIoCompletion(&port, GENERIC_ALL, NULL, 0);
    ok(status == STATUS_SUCCESS, "create port -> %08lx", (unsigned long)status);
    completion.CompletionPort = port;
    completion.CompletionKey = 0;
    status = NtSetInformationFile(client, &iosb, &completion, sizeof(completion),
                                  FileCompletionInformation);
    ok(status == STATUS_SUCCESS, "bind port -> %08lx", (unsigned long)status);

    ctx.socket = client;
    ctx.status = IOSB_POISON_STATUS;
    worker = CreateThread(NULL, 0, port_exiting_parker, &ctx, 0, NULL);
    ok(worker != NULL, "CreateThread");
    ok(WaitForSingleObject(worker, 30000) == WAIT_OBJECT_0, "worker never exited");
    CloseHandle(worker);
    ok(ctx.status == STATUS_PENDING, "worker's recv -> %08lx", (unsigned long)ctx.status);

    /* The exit is NOT the cancel here (the ws2_32:afd
     * test_async_thread_termination rows: "async is not cancelled if
     * there is a completion port, completion key and no event"): no
     * packet arrives and the IOSB stays untouched. */
    zero.QuadPart = 0;
    poison_iosb(&packetIosb);
    status = NtRemoveIoCompletion(port, &key, &value, &packetIosb, &zero);
    ok(status == STATUS_TIMEOUT, "post-exit packet -> %08lx", (unsigned long)status);
    ok(ctx.iosb.Status == IOSB_POISON_STATUS, "post-exit iosb %08lx",
       (unsigned long)ctx.iosb.Status);

    /* An explicit cancel still reaches it, and reports through the port
     * with the request's ApcContext as the packet value. */
    status = NtCancelIoFileEx(client, NULL, &iosb);
    ok(status == STATUS_SUCCESS, "cancel -> %08lx", (unsigned long)status);
    key = 0x11;
    value = 0x22;
    poison_iosb(&packetIosb);
    zero.QuadPart = -300000000LL; /* generous; the packet is already due */
    status = NtRemoveIoCompletion(port, &key, &value, &packetIosb, &zero);
    ok(status == STATUS_SUCCESS, "cancelled packet -> %08lx", (unsigned long)status);
    ok(key == 0, "packet key %lx", (unsigned long)key);
    ok(value == 0xfeedf00d, "packet value %lx", (unsigned long)value);
    ok(packetIosb.Status == STATUS_CANCELLED, "packet status %08lx",
       (unsigned long)packetIosb.Status);
    ok(ctx.iosb.Status == STATUS_CANCELLED, "cancelled iosb %08lx",
       (unsigned long)ctx.iosb.Status);

    NtClose(port);
    NtClose(client);
    NtClose(server);
}

START_TEST(afd_cancel_close)
{
    test_cancel_io_file();
    test_cancel_targeted();
    test_close_cancels();
    test_thread_exit_cancels();
    test_thread_exit_port_exemption();
}
