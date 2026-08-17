/*
 * sem_pipe/ioctl_signal.c — what an IOCTL does to the FILE OBJECT's
 * signalled state.
 *
 * sem_pipe/blocking_signal.c pinned this contract for the transfer paths
 * (read, write, flush) and sem_pipe/ioctl_event.c pinned the EVENT half of it
 * for an ioctl. The half left unbuilt was the file object's, and it is the
 * one ntdll:pipe wedges on: test_cancelsynchronousio spins
 *
 *     while ((ret = WaitForSingleObject(ctx.pipe, 0)) == WAIT_OBJECT_0)
 *         Sleep(1);                          (dlls/ntdll/tests/pipe.c:747)
 *
 * waiting for a blocking FSCTL_PIPE_LISTEN to take the pipe HANDLE down
 * before it cancels it.
 *
 * The oracle states the whole rule in three statements, and an ioctl reaches
 * all three through exactly the code a read does — server/async.c:
 *
 *   create_async:     `if (event) reset_event( event );`
 *   queue_async:      `if (!async->is_system) set_fd_signaled( async->fd, 0 );`
 *   async_set_result: `if (async->pending || !NT_ERROR( status )) {
 *                          ...
 *                          if (async->event) set_event( async->event );
 *                          else if (async->fd && !async->is_system)
 *                              set_fd_signaled( async->fd, 1 ); }`
 *
 * What makes the IOCTL a separate measurement from the read is WHERE the
 * verb sits relative to `queue_async`. server/named_pipe.c pipe_server_ioctl's
 * FSCTL_PIPE_LISTEN arm returns STATUS_PIPE_CONNECTED / STATUS_PIPE_CLOSING /
 * STATUS_PIPE_LISTENING *above* the queue and calls `queue_async( &server->
 * listen_q, async )` only in the listening state — whereas pipe_end_read
 * queues unconditionally and lets the reselect satisfy it. So an ioctl has
 * arms a transfer does not: a refusal that never clears the handle, and an
 * inline completion that never clears it either.
 *
 * Every case here puts the parked side in a WORKER and does the release from
 * the main thread behind a bounded poll — so a kernel that never clears the
 * handle FAILS AN ASSERTION rather than costing the leg its timeout (docs/21
 * W10 lesson 2), which is precisely the failure mode of the winetest spin
 * above.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtCancelSynchronousIoFile(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK);

/* How long a state change is given before it is called a failure, and how
 * long the worker is then given to unwind. The first only has to outlast the
 * scheduling of two threads. */
#define STATE_WAIT_MS  2000
#define POLL_MS        5
#define WORKER_WAIT_MS 5000

static BOOLEAN is_signaled(HANDLE handle)
{
    return WaitForSingleObject(handle, 0) == WAIT_OBJECT_0;
}

/* ntdll:pipe:747's own spin, with a deadline bolted on. */
static BOOLEAN wait_until_clear(HANDLE handle)
{
    ULONG waited = 0;
    while (is_signaled(handle))
    {
        if (waited >= STATE_WAIT_MS)
            return FALSE;
        Sleep(POLL_MS);
        waited += POLL_MS;
    }
    return TRUE;
}

/* --- the listening worker --------------------------------------------------
 *
 * One state block per worker, never reused: a listen a broken kernel leaves
 * parked writes its answers whenever it eventually unwinds, and a shared
 * block would report them into the NEXT case's assertion (the lesson
 * sem_pipe/flush_buffers.c paid for).
 */
typedef struct
{
    HANDLE pipe;
    HANDLE event; /* the listen's completion event, or NULL */
    HANDLE thread;
    BOOLEAN wantApc; /* pass a completion routine, and count its calls */
    LONG apcCalls;
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
} LISTENER;

static LISTENER listeners[8];
static unsigned listenerCount;

/* The completion routine's context is the job itself, so one routine serves
 * every case and nothing a broken kernel delivers late can land in another
 * case's counter. */
static VOID NTAPI listener_apc(PVOID ctx, PIO_STATUS_BLOCK iosb, ULONG reserved)
{
    LISTENER *job = ctx;
    (void)iosb;
    (void)reserved;
    job->apcCalls++;
}

static DWORD WINAPI listener_thread(void *param)
{
    LISTENER *job = param;
    LARGE_INTEGER zero;

    job->status =
        NtFsControlFile(job->pipe, job->event, job->wantApc ? listener_apc : NULL,
                        job->wantApc ? job : NULL, &job->iosb, FSCTL_PIPE_LISTEN, NULL, 0, NULL, 0);
    /* The completion routine is a user APC, so it has not run when the
     * syscall returns (sem_pipe/alertable_park.c case 3 pins that ordering);
     * deliver it here so the count is final before the joiner reads it. */
    zero.QuadPart = 0;
    NtDelayExecution(TRUE, &zero);
    return 0;
}

static LISTENER *start_listener_apc(HANDLE pipe, HANDLE event, BOOLEAN wantApc)
{
    LISTENER *job = &listeners[listenerCount++];
    job->pipe = pipe;
    job->event = event;
    job->wantApc = wantApc;
    job->apcCalls = 0;
    job->status = (NTSTATUS)IOSB_POISON_STATUS;
    poison_iosb(&job->iosb);
    job->thread = CreateThread(NULL, 0, listener_thread, job, 0, NULL);
    return job;
}

static LISTENER *start_listener(HANDLE pipe, HANDLE event)
{
    return start_listener_apc(pipe, event, FALSE);
}

static BOOLEAN finish_listener(LISTENER *job)
{
    BOOLEAN done =
        job->thread != NULL && WaitForSingleObject(job->thread, WORKER_WAIT_MS) == WAIT_OBJECT_0;
    if (done)
    {
        CloseHandle(job->thread);
        job->thread = NULL;
    }
    return done;
}

static NTSTATUS make_server(HANDLE *server, const void *wideName)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status =
        create_pipe_instance(server, wideName, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    return status;
}

/* Case 1: a blocking listen with NO event. The handle is down for the whole
 * park and back up at the completion — the FILE OBJECT arm of "exactly one",
 * taken because there is no event to take the other. This is the state
 * ntdll:pipe:747 waits for. */
static void test_blocking_listen_no_event(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    LISTENER *job;
    NTSTATUS status;

    if (!NT_SUCCESS(make_server(&server, W("\\??\\pipe\\prstest_iocsig1"))))
        return;
    ok(is_signaled(server), "the handle is not signalled before any request");

    job = start_listener(server, NULL);
    ok(job->thread != NULL, "CreateThread");
    ok(wait_until_clear(server), "a parked listen never took the handle down");

    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_iocsig1"), &iosb);
    ok(status == STATUS_SUCCESS, "client open -> %08lx", (unsigned long)status);

    ok(finish_listener(job), "the listener finished");
    ok(job->status == STATUS_SUCCESS, "blocking listen -> %08lx", (unsigned long)job->status);
    ok(job->iosb.Status == STATUS_SUCCESS, "listen iosb.Status %08lx",
       (unsigned long)job->iosb.Status);
    ok(is_signaled(server), "the handle is not signalled after the listen completed");

    if (client != NULL)
        NtClose(client);
    NtClose(server);
}

/* Case 2: the same listen with an EVENT, which is the discriminating half.
 * The event is created SIGNALLED so the reset at issue is observable, and the
 * completion takes the EVENT arm — leaving the handle DOWN through its own
 * completion, which reads as a bug and is the contract. */
static void test_blocking_listen_with_event(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL, event;
    LISTENER *job;
    NTSTATUS status;

    if (!NT_SUCCESS(make_server(&server, W("\\??\\pipe\\prstest_iocsig2"))))
        return;

    event = CreateEventW(NULL, TRUE, TRUE, NULL); /* manual reset, born signalled */
    ok(event != NULL, "CreateEventW");

    job = start_listener(server, event);
    ok(job->thread != NULL, "CreateThread");
    ok(wait_until_clear(server), "a parked listen never took the handle down");
    /* Sampled mid-park, which is the only place "reset at issue" is separable
     * from "reset on the way out". */
    ok(!is_signaled(event), "the caller's event was still signalled mid-park");

    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_iocsig2"), &iosb);
    ok(status == STATUS_SUCCESS, "client open -> %08lx", (unsigned long)status);

    ok(finish_listener(job), "the listener finished");
    ok(job->status == STATUS_SUCCESS, "blocking listen -> %08lx", (unsigned long)job->status);
    ok(is_signaled(event), "the event is not signalled after the listen completed");
    ok(!is_signaled(server), "the handle was signalled by a listen that had an event");

    if (client != NULL)
        NtClose(client);
    CloseHandle(event);
    NtClose(server);
}

/* Case 3: a listen REFUSED above the queue. server/named_pipe.c answers
 * STATUS_PIPE_CONNECTED in the connected state and returns before
 * queue_async, so `async->pending` is still 0 and async_set_result's whole
 * signal block is skipped: the handle keeps exactly what it had, while the
 * event has already been reset by create_async one frame up. That split is
 * the point of the case — the two halves of "issue" do not happen in the
 * same place. */
static void test_refused_listen_keeps_the_handle(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL, event;
    NTSTATUS status;

    if (!NT_SUCCESS(make_server(&server, W("\\??\\pipe\\prstest_iocsig3"))))
        return;

    /* Connect before any listen: the instance is CONNECTED, so the listen
     * below is refused rather than parked (sem_pipe/create_pipe.c). */
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_iocsig3"), &iosb);
    ok(status == STATUS_SUCCESS, "client open -> %08lx", (unsigned long)status);

    event = CreateEventW(NULL, TRUE, TRUE, NULL); /* born signalled */
    ok(event != NULL, "CreateEventW");
    ok(is_signaled(server), "the handle is not signalled before the refusal");

    poison_iosb(&iosb);
    status = NtFsControlFile(server, event, NULL, NULL, &iosb, FSCTL_PIPE_LISTEN, NULL, 0, NULL, 0);
    ok(status == STATUS_PIPE_CONNECTED, "listen on a connected pipe -> %08lx",
       (unsigned long)status);
    ok(iosb.Status == (NTSTATUS)IOSB_POISON_STATUS, "a refused listen wrote the IOSB (%08lx)",
       (unsigned long)iosb.Status);
    ok(!is_signaled(event), "a refused listen left the caller's event signalled");
    ok(is_signaled(server), "a listen that never parked left the handle unsignalled");

    CloseHandle(event);
    if (client != NULL)
        NtClose(client);
    NtClose(server);
}

/* Case 4: the same refusal on a handle that is ALREADY DOWN. Case 3 measures
 * it against a fresh handle, which is born signalled — so it cannot tell
 * "leave the handle alone" from "signal the handle", and an implementation
 * that clears at issue and then unconditionally signals on a refusal passes
 * it. Here case 2's rule has left the handle down and the refusal must leave
 * it there. */
static void test_refusal_leaves_a_down_handle_down(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL, event;
    LISTENER *job;
    NTSTATUS status;

    if (!NT_SUCCESS(make_server(&server, W("\\??\\pipe\\prstest_iocsig4"))))
        return;

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(event != NULL, "CreateEventW");

    job = start_listener(server, event);
    ok(job->thread != NULL, "CreateThread");
    ok(wait_until_clear(server), "a parked listen never took the handle down");

    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_iocsig4"), &iosb);
    ok(status == STATUS_SUCCESS, "client open -> %08lx", (unsigned long)status);
    ok(finish_listener(job), "the listener finished");
    ok(job->status == STATUS_SUCCESS, "blocking listen -> %08lx", (unsigned long)job->status);
    ok(!is_signaled(server), "the handle was signalled by a listen that had an event");

    /* Now the refusal, on the down handle. */
    poison_iosb(&iosb);
    status = pipe_fsctl(server, FSCTL_PIPE_LISTEN, &iosb);
    ok(status == STATUS_PIPE_CONNECTED, "listen on a connected pipe -> %08lx",
       (unsigned long)status);
    ok(!is_signaled(server), "a refusal signalled a handle the oracle never touched");

    CloseHandle(event);
    if (client != NULL)
        NtClose(client);
    NtClose(server);
}

/* Case 5: an ioctl that COMPLETES INLINE, which is the arm a transfer does
 * not have. FSCTL_PIPE_PEEK is answered by pipe_end_peek without ever
 * reaching queue_async, so nothing clears the handle — and the completion
 * still runs async_set_result's signal block (`!NT_ERROR( status )` alone
 * satisfies its guard), which takes the EVENT when there is one and the
 * handle otherwise.
 *
 * Both directions are measured because they diverge in opposite ways: with an
 * event on an UP handle, an implementation that clears at issue leaves it
 * DOWN; with no event on a DOWN handle, one that only ever "restores" leaves
 * it down where the oracle puts it up. */
static void test_inline_ioctl_states(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL, event;
    LISTENER *job;
    unsigned char peek[sizeof(SEM_FILE_PIPE_PEEK_BUFFER) + 8];
    NTSTATUS status;

    if (!NT_SUCCESS(make_server(&server, W("\\??\\pipe\\prstest_iocsig5"))))
        return;

    event = CreateEventW(NULL, TRUE, TRUE, NULL); /* born signalled */
    ok(event != NULL, "CreateEventW");

    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_iocsig5"), &iosb);
    ok(status == STATUS_SUCCESS, "client open -> %08lx", (unsigned long)status);
    ok(is_signaled(server), "the handle is not signalled before the peek");

    /* (a) an event, on an UP handle. */
    poison_iosb(&iosb);
    status = NtFsControlFile(server, event, NULL, NULL, &iosb, FSCTL_PIPE_PEEK, NULL, 0, peek,
                             sizeof(peek));
    ok(status == STATUS_SUCCESS, "peek -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "peek iosb.Status %08lx", (unsigned long)iosb.Status);
    ok(is_signaled(event), "an inline ioctl did not signal the caller's event");
    ok(is_signaled(server), "an inline ioctl with an event cleared the handle");

    /* (b) no event, on a DOWN handle. Case 2's rule puts it down: a listen
     * that completed through an event leaves it there. The instance is
     * already connected, so a fresh server end is needed for the listen. */
    NtClose(client);
    client = NULL;
    NtClose(server);
    server = NULL;
    if (!NT_SUCCESS(make_server(&server, W("\\??\\pipe\\prstest_iocsig6"))))
    {
        CloseHandle(event);
        return;
    }
    job = start_listener(server, event);
    ok(job->thread != NULL, "CreateThread");
    ok(wait_until_clear(server), "a parked listen never took the handle down");
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_iocsig6"), &iosb);
    ok(status == STATUS_SUCCESS, "client open -> %08lx", (unsigned long)status);
    ok(finish_listener(job), "the listener finished");
    ok(!is_signaled(server), "the handle was signalled by a listen that had an event");

    poison_iosb(&iosb);
    status = NtFsControlFile(server, NULL, NULL, NULL, &iosb, FSCTL_PIPE_PEEK, NULL, 0, peek,
                             sizeof(peek));
    ok(status == STATUS_SUCCESS, "peek -> %08lx", (unsigned long)status);
    ok(is_signaled(server), "an eventless inline ioctl did not signal the handle");

    CloseHandle(event);
    if (client != NULL)
        NtClose(client);
    NtClose(server);
}

/* Case 6: a listen that PARKED and then FAILED — cancelled by
 * NtCancelSynchronousIoFile, which is ntdll:pipe's own scenario. It was
 * QUEUED, so `async->pending` is 1 and async_set_result's signal block runs
 * even though the status is an error: the handle goes back UP. An
 * implementation that treats every failure as the refusal of case 3 passes
 * that case and leaves this handle down forever.
 *
 * The COMPLETION ROUTINE is measured with it, because it is the third thing
 * inside the same guard: async_set_result queues APC_USER, posts the packet
 * and signals — all under `async->pending || !NT_ERROR( status )` — so the
 * routine's fate is decided by the same question the handle's is, and a
 * refusal that never queued leaves it unrun (sem_pipe/listen_apc.c). */
static void test_cancelled_listen_no_event(void)
{
    IO_STATUS_BLOCK result;
    HANDLE server = NULL;
    LISTENER *job;
    NTSTATUS status;

    if (!NT_SUCCESS(make_server(&server, W("\\??\\pipe\\prstest_iocsig7"))))
        return;

    job = start_listener_apc(server, NULL, TRUE);
    ok(job->thread != NULL, "CreateThread");
    ok(wait_until_clear(server), "a parked listen never took the handle down");

    poison_iosb(&result);
    status = NtCancelSynchronousIoFile(job->thread, NULL, &result);
    ok(status == STATUS_SUCCESS, "cancel a parked listen -> %08lx", (unsigned long)status);

    ok(finish_listener(job), "the listener finished");
    ok(job->status == STATUS_CANCELLED, "cancelled listen -> %08lx", (unsigned long)job->status);
    ok(is_signaled(server), "a parked listen that failed left the handle unsignalled");
    ok(job->apcCalls == 1, "the completion routine ran %ld times for a cancelled listen",
       (long)job->apcCalls);
    /* And it runs with an IOSB nobody wrote: the oracle's async carries the
     * status internally but the client's tail writes the caller's block only
     * for a success, so the routine's only argument still holds the caller's
     * own poison. The first draft asserted STATUS_CANCELLED here and the
     * oracle refuted it — which is also why ntdll:pipe:770 accepts either
     * 0xdeadbabe or STATUS_CANCELLED. */
    ok(job->iosb.Status == (NTSTATUS)IOSB_POISON_STATUS,
       "a cancelled listen wrote the IOSB (%08lx)", (unsigned long)job->iosb.Status);

    NtClose(server);
}

/* Case 7: case 6 with an EVENT — the same queued-and-failed request takes the
 * EVENT arm instead, so a FAILING ioctl signals the caller's event. That is
 * the opposite of what the direct-fd path does (dlls/ntdll/unix/file.c resets
 * the event on a failure), and a pipe never takes that path. */
static void test_cancelled_listen_with_event(void)
{
    IO_STATUS_BLOCK result;
    HANDLE server = NULL, event;
    LISTENER *job;
    NTSTATUS status;

    if (!NT_SUCCESS(make_server(&server, W("\\??\\pipe\\prstest_iocsig8"))))
        return;

    event = CreateEventW(NULL, TRUE, FALSE, NULL); /* born down */
    ok(event != NULL, "CreateEventW");

    job = start_listener(server, event);
    ok(job->thread != NULL, "CreateThread");
    ok(wait_until_clear(server), "a parked listen never took the handle down");

    poison_iosb(&result);
    status = NtCancelSynchronousIoFile(job->thread, NULL, &result);
    ok(status == STATUS_SUCCESS, "cancel a parked listen -> %08lx", (unsigned long)status);

    ok(finish_listener(job), "the listener finished");
    ok(job->status == STATUS_CANCELLED, "cancelled listen -> %08lx", (unsigned long)job->status);
    ok(is_signaled(event), "a failing QUEUED listen did not signal the caller's event");
    ok(!is_signaled(server), "a failing listen with an event signalled the handle too");

    CloseHandle(event);
    NtClose(server);
}

/* Case 8: the PENDED arm. An ASYNCHRONOUS handle answers STATUS_PENDING
 * instead of parking its caller, and owes the handle exactly the same two
 * transitions — which is what makes the pipe handle itself a usable
 * completion signal for an overlapped listen with no event. */
static void test_pended_listen(void)
{
    IO_STATUS_BLOCK iosb, listenIosb;
    HANDLE server = NULL, client = NULL;
    NTSTATUS status;

    status = create_pipe_instance_async(&server, W("\\??\\pipe\\prstest_iocsig9"), 1, &iosb);
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    ok(is_signaled(server), "the handle is not signalled before any request");

    poison_iosb(&listenIosb);
    status =
        NtFsControlFile(server, NULL, NULL, NULL, &listenIosb, FSCTL_PIPE_LISTEN, NULL, 0, NULL, 0);
    ok(status == STATUS_PENDING, "async listen -> %08lx", (unsigned long)status);
    ok(!is_signaled(server), "a pended listen left the handle signalled");

    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_iocsig9"), &iosb);
    ok(status == STATUS_SUCCESS, "client open -> %08lx", (unsigned long)status);

    ok(WaitForSingleObject(server, STATE_WAIT_MS) == WAIT_OBJECT_0,
       "a completed pended listen never signalled the handle");
    ok(listenIosb.Status == STATUS_SUCCESS, "listen iosb.Status %08lx",
       (unsigned long)listenIosb.Status);

    if (client != NULL)
        NtClose(client);
    NtClose(server);
}

START_TEST(ioctl_signal)
{
    test_blocking_listen_no_event();
    test_blocking_listen_with_event();
    test_refused_listen_keeps_the_handle();
    test_refusal_leaves_a_down_handle_down();
    test_inline_ioctl_states();
    test_cancelled_listen_no_event();
    test_cancelled_listen_with_event();
    test_pended_listen();
}
