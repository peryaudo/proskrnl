/*
 * sem_pipe/listen_apc.c — the APC completion leg of FSCTL_PIPE_LISTEN
 * (docs/21 W4a).
 *
 * sem_file/apc_completion.c pins this protocol for a data transfer. This is
 * the same protocol on the IOCTL path, and it is the harder half because the
 * listen PENDS: the APC must survive the syscall's return, and it is queued
 * at completion time — when a client connects, or when the listen is
 * cancelled — to the thread that ISSUED it, not to whoever completes it.
 *
 * What is pinned:
 *   - a listen with an ApcRoutine on an asynchronous handle returns
 *     STATUS_PENDING and does NOT run the routine yet;
 *   - the routine runs at the next ALERTABLE wait after the client attaches,
 *     exactly once, with the caller's ApcContext and the very IOSB it passed;
 *   - the IOSB is already final when the routine runs — that ordering is the
 *     whole point of the leg, since the routine's only argument is a pointer
 *     to it;
 *   - a CANCELLED listen completes the same way: the APC still runs, and the
 *     IOSB carries STATUS_CANCELLED. An implementation that queued the APC
 *     only on the success path would pass everything above and leak the
 *     block here.
 *
 * dlls/ntdll/tests/pipe.c's listen_pipe(..., use_apc = TRUE) is what
 * ntdll:pipe uses, and reaching it is what the pair stops on today.
 */
#include "util.h"

static int apc_calls;
static void *apc_seen_context;
static IO_STATUS_BLOCK *apc_seen_iosb;
static NTSTATUS apc_seen_status;

static void NTAPI listen_apc(PVOID context, PIO_STATUS_BLOCK iosb, ULONG reserved)
{
    apc_calls++;
    apc_seen_context = context;
    apc_seen_iosb = iosb;
    apc_seen_status = iosb->Status;
    (void)reserved;
}

static void reset_apc(void)
{
    apc_calls = 0;
    apc_seen_context = NULL;
    apc_seen_iosb = NULL;
    apc_seen_status = IOSB_POISON_STATUS;
}

/* An alertable sleep: the delivery edge for a queued user APC. */
static void alertable_pause(void)
{
    LARGE_INTEGER timeout;
    timeout.QuadPart = -10 * 10000; /* 10 ms, relative */
    NtDelayExecution(TRUE, &timeout);
}

/* FSCTL_PIPE_LISTEN carrying an ApcRoutine + context. */
static NTSTATUS listen_with_apc(HANDLE handle, void *context, IO_STATUS_BLOCK *iosb)
{
    return NtFsControlFile(handle, NULL, listen_apc, context, iosb, FSCTL_PIPE_LISTEN, NULL, 0,
                           NULL, 0);
}

/* The pended listen, satisfied by a client connect. */
static void test_apc_on_connect(void)
{
    IO_STATUS_BLOCK iosb, clientIosb;
    HANDLE server = NULL, client = NULL;
    int marker = 0;
    NTSTATUS status;

    status = create_pipe_instance_async(&server, W("\\??\\pipe\\prstest_listenapc"), 1, &iosb);
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    reset_apc();
    poison_iosb(&iosb);
    status = listen_with_apc(server, &marker, &iosb);
    ok(status == STATUS_PENDING, "listen with apc -> %08lx", (unsigned long)status);

    /* Not yet: nothing has completed, so an alertable wait must deliver
     * nothing. This is what separates "queued at completion" from "queued at
     * issue". */
    alertable_pause();
    ok(apc_calls == 0, "apc ran before completion (%d)", apc_calls);
    ok(iosb.Status == IOSB_POISON_STATUS, "iosb written before completion %08lx",
       (unsigned long)iosb.Status);

    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_listenapc"), &clientIosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    alertable_pause();
    ok(apc_calls == 1, "apc calls after connect %d", apc_calls);
    ok(apc_seen_context == &marker, "apc context %p want %p", apc_seen_context, (void *)&marker);
    ok(apc_seen_iosb == &iosb, "apc iosb %p want %p", (void *)apc_seen_iosb, (void *)&iosb);
    /* Read INSIDE the routine, so this asserts the ordering and not just the
     * final value. */
    ok(apc_seen_status == STATUS_SUCCESS, "iosb status seen by apc %08lx",
       (unsigned long)apc_seen_status);
    ok(iosb.Status == STATUS_SUCCESS, "iosb status %08lx", (unsigned long)iosb.Status);

    /* Exactly once. */
    alertable_pause();
    ok(apc_calls == 1, "apc ran again (%d)", apc_calls);

    NtClose(client);
    NtClose(server);
}

/* The pended listen, ended by a cancel instead. */
static void test_apc_on_cancel(void)
{
    IO_STATUS_BLOCK iosb, cancelIosb;
    HANDLE server = NULL;
    int marker = 0;
    NTSTATUS status;

    status = create_pipe_instance_async(&server, W("\\??\\pipe\\prstest_listenapc_c"), 1, &iosb);
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    reset_apc();
    poison_iosb(&iosb);
    status = listen_with_apc(server, &marker, &iosb);
    ok(status == STATUS_PENDING, "listen with apc -> %08lx", (unsigned long)status);

    status = NtCancelIoFile(server, &cancelIosb);
    ok(status == STATUS_SUCCESS, "cancel -> %08lx", (unsigned long)status);

    alertable_pause();
    ok(apc_calls == 1, "apc calls after cancel %d", apc_calls);
    ok(apc_seen_context == &marker, "apc context %p want %p", apc_seen_context, (void *)&marker);
    ok(apc_seen_status == STATUS_CANCELLED, "iosb status seen by apc %08lx",
       (unsigned long)apc_seen_status);

    NtClose(server);
}

/* The IMMEDIATE answer, which is a different contract from the pended one
 * and was got wrong first time round. A listen on an ALREADY-CONNECTED
 * instance answers STATUS_PIPE_CONNECTED from the call itself: nothing
 * completed, so the routine must NOT run — the caller already has its
 * status. The oracle frees the async without invoking it (server_ioctl_file,
 * dlls/ntdll/unix/file.c, on any non-pending status).
 *
 * The first cut of the kernel change queued the APC on every inline
 * completion, which passes both cases above and is wrong here. */
static void test_no_apc_when_immediate(void)
{
    IO_STATUS_BLOCK iosb, clientIosb;
    HANDLE server = NULL, client = NULL;
    int marker = 0;
    NTSTATUS status;

    status = create_pipe_instance_async(&server, W("\\??\\pipe\\prstest_listenapc_i"), 1, &iosb);
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_listenapc_i"), &clientIosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    reset_apc();
    poison_iosb(&iosb);
    status = listen_with_apc(server, &marker, &iosb);
    ok(status == STATUS_PIPE_CONNECTED, "listen when connected -> %08lx", (unsigned long)status);
    /* The IOSB is the caller's own poison: an immediate answer writes
     * nothing (dlls/ntdll/tests/pipe.c:412 asserts the same thing). */
    ok(iosb.Status == IOSB_POISON_STATUS, "iosb written on immediate answer %08lx",
       (unsigned long)iosb.Status);

    alertable_pause();
    ok(apc_calls == 0, "apc ran for an immediate answer (%d)", apc_calls);

    /* And the same question for an ioctl that SUCCEEDS inline rather than
     * failing. FSCTL_PIPE_DISCONNECT on a connected server end takes no
     * buffers and completes on the spot. This is the case the two above
     * cannot distinguish: does the APC leg fire for any completion, or only
     * for one that PENDED? Measured, because the answer decides whether
     * kernel/io/ioctl.c queues on the inline path at all. */
    reset_apc();
    poison_iosb(&iosb);
    status = NtFsControlFile(server, NULL, listen_apc, &marker, &iosb, FSCTL_PIPE_DISCONNECT, NULL,
                             0, NULL, 0);
    ok(status == STATUS_SUCCESS, "disconnect with apc -> %08lx", (unsigned long)status);
    alertable_pause();
    ok(apc_calls == 1, "apc calls for an inline SUCCESS %d", apc_calls);

    NtClose(client);
    NtClose(server);
}

START_TEST(listen_apc)
{
    test_apc_on_connect();
    test_apc_on_cancel();
    test_no_apc_when_immediate();
}
