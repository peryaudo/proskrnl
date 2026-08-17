/*
 * sem_pipe/blocking_signal.c — what a BLOCKING request does to the caller's
 * event and to the FILE OBJECT's signalled state.
 *
 * sem_pipe/pended_read.c pinned the same three rules for a request that
 * answers STATUS_PENDING. They are not rules about pending: the oracle
 * queues a BLOCKING async through exactly the same code, so a synchronous
 * read that parks its caller owes them too.
 *
 *   server/async.c  create_async:  `if (event) reset_event( event );`
 *   server/async.c  queue_async:   `if (!async->is_system)
 *                                       set_fd_signaled( async->fd, 0 );`
 *   server/async.c  async_set_result:
 *                       `if (async->event) set_event( async->event );
 *                        else if (async->fd && !async->is_system)
 *                            set_fd_signaled( async->fd, 1 );`
 *
 * `async->blocking = !is_fd_overlapped( fd )` (create_async) is the ONLY
 * thing a synchronous handle changes, and it decides how the CALLER waits —
 * not whether the fd is cleared. So: the caller's event is reset when the
 * request is issued, the handle goes unsignalled for the duration, and
 * exactly ONE of the two is signalled at the end.
 *
 * A named pipe reaches all of it because its end has no unix fd of its own
 * (server/named_pipe.c pipe_end_get_fd over a pseudo fd), so every read,
 * write and flush on one goes through the server rather than through
 * ntdll's direct-fd path.
 *
 * ntdll:pipe's test_blocking is the winetest consumer (dlls/ntdll/tests/
 * pipe.c:1740/:1742/:1753 sample the states from a helper thread while the
 * main thread is parked, and :1829 is a todo_wine that a kernel which never
 * clears the handle PASSES — i.e. scores a failure for being closer to NT).
 *
 * Every case here samples from a WORKER THREAD behind a bounded wait, and
 * the worker always performs the peer operation that releases the parked
 * main thread — so a kernel that gets this wrong FAILS AN ASSERTION rather
 * than costing the leg its timeout (docs/21 W10 lesson 2).
 */
#include "util.h"

/* How long the parked side is given to settle before the worker samples it,
 * and how long the worker is then given to finish. The first only has to
 * outlast the scheduling of two threads; the second turns a lost wake into
 * an assertion. */
#define PARK_SETTLE_MS 150
#define WORKER_WAIT_MS 5000

static BOOLEAN is_signaled(HANDLE handle)
{
    return WaitForSingleObject(handle, 0) == WAIT_OBJECT_0;
}

/* One state block per worker, never reused: a case whose main-thread request
 * never returns leaves the worker's answers behind, and a shared block would
 * report them into the NEXT case's assertion (the lesson
 * sem_pipe/flush_buffers.c paid for). */
typedef enum
{
    SamplerWrite, /* release a parked READ */
    SamplerRead,  /* release a parked FLUSH */
    SamplerClose  /* break the pipe under a parked read */
} SAMPLER_ACTION;

typedef struct
{
    HANDLE peer;    /* the end the worker operates on */
    HANDLE watched; /* the end the parked request was issued on */
    HANDLE event;   /* the parked request's event, or NULL */
    HANDLE thread;
    SAMPLER_ACTION action;
    BOOLEAN sawWatchedSignaled;
    BOOLEAN sawEventSignaled;
    NTSTATUS peerStatus;
} SAMPLER;

static SAMPLER samplers[8];
static unsigned samplerCount;

static DWORD WINAPI sampler_thread(void *param)
{
    SAMPLER *job = param;
    IO_STATUS_BLOCK iosb;
    char buffer[16];

    Sleep(PARK_SETTLE_MS);
    job->sawWatchedSignaled = is_signaled(job->watched);
    if (job->event != NULL)
        job->sawEventSignaled = is_signaled(job->event);
    switch (job->action)
    {
    case SamplerWrite:
        job->peerStatus = pipe_write(job->peer, "x", 1, &iosb);
        break;
    case SamplerRead:
        job->peerStatus = pipe_read(job->peer, buffer, 1, &iosb);
        break;
    case SamplerClose:
        job->peerStatus = NtClose(job->peer);
        break;
    }
    return 0;
}

static SAMPLER *start_sampler(HANDLE peer, HANDLE watched, HANDLE event, SAMPLER_ACTION action)
{
    SAMPLER *job = &samplers[samplerCount++];
    job->peer = peer;
    job->watched = watched;
    job->event = event;
    job->action = action;
    job->sawWatchedSignaled = TRUE;
    job->sawEventSignaled = TRUE;
    job->peerStatus = (NTSTATUS)IOSB_POISON_STATUS;
    job->thread = CreateThread(NULL, 0, sampler_thread, job, 0, NULL);
    return job;
}

static BOOLEAN finish_sampler(SAMPLER *job)
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

/* server (synchronous) + client (synchronous), connected. Both ends
 * synchronous, because the whole subject is the request that BLOCKS. */
static BOOLEAN make_pair(const void *wideName, HANDLE *server, HANDLE *client)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status =
        create_pipe_instance(server, wideName, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return FALSE;
    status = open_pipe_client(client, wideName, &iosb);
    ok(status == STATUS_SUCCESS, "client open -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(*server);
        return FALSE;
    }
    return TRUE;
}

/* Case 1: a blocking read with no event. The handle is down for the whole
 * park and back up at the completion — the FILE OBJECT arm of "exactly one",
 * taken because there is no event to take the other. */
static void test_blocking_read_no_event(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    SAMPLER *job;
    char buffer[16];
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_blksig1"), &server, &client))
        return;

    ok(is_signaled(client), "the handle is not signalled before any request");

    job = start_sampler(server, client, NULL, SamplerWrite);
    ok(job->thread != NULL, "CreateThread");

    poison_iosb(&iosb);
    status = pipe_read(client, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_SUCCESS, "blocking read -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "read iosb.Status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 1, "read iosb.Information %llx", (unsigned long long)iosb.Information);
    ok(is_signaled(client), "the handle is not signalled after the read completed");

    ok(finish_sampler(job), "the sampler finished");
    ok(!job->sawWatchedSignaled, "the handle was signalled while a blocking read was parked");

    NtClose(client);
    NtClose(server);
}

/* Case 2: the same read with an EVENT, which is the discriminating half.
 * The event is created SIGNALLED so the reset at issue is observable, and
 * the completion takes the EVENT arm — leaving the handle down through its
 * own completion, which reads as a bug and is the contract. */
static void test_blocking_read_with_event(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL, event;
    SAMPLER *job;
    char buffer[16];
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_blksig2"), &server, &client))
        return;

    event = CreateEventW(NULL, TRUE, TRUE, NULL); /* manual reset, born signalled */
    ok(event != NULL, "CreateEventW");
    ok(is_signaled(event), "the event is not signalled before the request");

    job = start_sampler(server, client, event, SamplerWrite);
    ok(job->thread != NULL, "CreateThread");

    poison_iosb(&iosb);
    status = NtReadFile(client, event, NULL, NULL, &iosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_SUCCESS, "blocking read -> %08lx", (unsigned long)status);
    ok(iosb.Information == 1, "read iosb.Information %llx", (unsigned long long)iosb.Information);
    ok(is_signaled(event), "the event is not signalled after the read completed");
    ok(!is_signaled(client), "the handle was signalled by a read that had an event");

    ok(finish_sampler(job), "the sampler finished");
    ok(!job->sawEventSignaled, "the event was signalled while the read was parked");
    ok(!job->sawWatchedSignaled, "the handle was signalled while a blocking read was parked");

    CloseHandle(event);
    NtClose(client);
    NtClose(server);
}

/* Case 3: the handle comes back up on the NEXT request that completes on it,
 * with no event — nothing else does, and case 2 left it down. This is the
 * rule ntdll:pipe:1678 measures one shape over (a write on the end whose own
 * read is still parked). */
static void test_a_later_completion_signals_the_handle(void)
{
    IO_STATUS_BLOCK iosb, writeIosb;
    HANDLE server = NULL, client = NULL, event;
    char buffer[16];
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_blksig3"), &server, &client))
        return;

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(event != NULL, "CreateEventW");

    status = pipe_write(server, "q", 1, &writeIosb);
    ok(status == STATUS_SUCCESS, "peer write -> %08lx", (unsigned long)status);

    /* Satisfiable at once, so nothing parks — the event still takes the
     * completion and the handle is still left down. */
    poison_iosb(&iosb);
    status = NtReadFile(client, event, NULL, NULL, &iosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_SUCCESS, "inline read -> %08lx", (unsigned long)status);
    ok(is_signaled(event), "the event is not signalled after an inline read");
    ok(!is_signaled(client), "the handle was signalled by a read that had an event");

    /* A request with no event on the same handle puts it back up. */
    status = pipe_write(client, "z", 1, &writeIosb);
    ok(status == STATUS_SUCCESS, "write -> %08lx", (unsigned long)status);
    ok(is_signaled(client), "an eventless completion did not signal the handle");

    CloseHandle(event);
    NtClose(client);
    NtClose(server);
}

/* Case 4: a blocking FLUSH. It has no event parameter at all, so it can only
 * ever take the file-object arm — and it parks for as long as the peer has
 * not consumed what this end wrote (sem_pipe/flush_buffers.c pins the wait
 * itself). ntdll:pipe:1753 is exactly this sample. */
static void test_blocking_flush(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    SAMPLER *job;
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_blksig4"), &server, &client))
        return;

    status = pipe_write(client, "f", 1, &iosb);
    ok(status == STATUS_SUCCESS, "client write -> %08lx", (unsigned long)status);
    ok(is_signaled(client), "the handle is not signalled before the flush");

    job = start_sampler(server, client, NULL, SamplerRead);
    ok(job->thread != NULL, "CreateThread");

    poison_iosb(&iosb);
    status = NtFlushBuffersFile(client, &iosb);
    ok(status == STATUS_SUCCESS, "blocking flush -> %08lx", (unsigned long)status);
    ok(is_signaled(client), "the handle is not signalled after the flush completed");

    ok(finish_sampler(job), "the sampler finished");
    ok(job->peerStatus == STATUS_SUCCESS, "peer read -> %08lx", (unsigned long)job->peerStatus);
    ok(!job->sawWatchedSignaled, "the handle was signalled while a blocking flush was parked");

    NtClose(client);
    NtClose(server);
}

/* Case 5: a request that fails WITHOUT EVER PARKING. The oracle refuses this
 * one inside pipe_end_read (server/named_pipe.c, the CLOSING state with an
 * empty queue), which is above queue_async — so the handle is never cleared,
 * while the event has already been reset by create_async one frame up. That
 * split is the whole point of the case: the two halves of "issue" do NOT
 * happen at the same place, and an implementation that clears the handle
 * where it resets the event diverges exactly here. */
static void test_failed_read_states(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL, event;
    char buffer[16];
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_blksig5"), &server, &client))
        return;

    event = CreateEventW(NULL, TRUE, TRUE, NULL); /* born signalled */
    ok(event != NULL, "CreateEventW");

    NtClose(server); /* the peer is gone: the next read cannot be served */

    poison_iosb(&iosb);
    status = NtReadFile(client, event, NULL, NULL, &iosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_PIPE_BROKEN, "read on a broken pipe -> %08lx", (unsigned long)status);
    ok(iosb.Status == (NTSTATUS)IOSB_POISON_STATUS, "a failed read wrote the IOSB (%08lx)",
       (unsigned long)iosb.Status);
    ok(!is_signaled(event), "a failed read left the caller's event signalled");
    ok(is_signaled(client), "a read that never parked left the handle unsignalled");

    CloseHandle(event);
    NtClose(client);
}

/* The completion routine of the case below. Its context is a counter of its
 * own, because a request a broken kernel leaves parked can deliver late. */
static volatile LONG failedReadApcCalls;
static VOID NTAPI failed_read_apc(PVOID ctx, PIO_STATUS_BLOCK iosb, ULONG reserved)
{
    (void)ctx;
    (void)iosb;
    (void)reserved;
    failedReadApcCalls++;
}

/* Case 6: a request that PARKS and then fails — the peer closes under it.
 * Here the handle really was cleared, so what the failing completion does
 * with it is a second, independent measurement from case 5's.
 *
 * The COMPLETION ROUTINE is the third thing inside the same guard and is
 * measured here for that reason: async_set_result queues APC_USER, posts the
 * packet and signals all under `async->pending || !NT_ERROR( status )`
 * (server/async.c), so a QUEUED request that FAILS runs the routine — with an
 * IOSB nobody wrote, since the failing tail leaves the caller's block alone.
 * A request refused above the queue runs nothing (sem_pipe/listen_apc.c), so
 * the two arms of a failure differ and only a case can say which is which. */
static void test_parked_then_failed_read(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    SAMPLER *job;
    static char buffer[16];
    LARGE_INTEGER zero;
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_blksig6"), &server, &client))
        return;

    job = start_sampler(server, client, NULL, SamplerClose);
    ok(job->thread != NULL, "CreateThread");

    failedReadApcCalls = 0;
    poison_iosb(&iosb);
    status =
        NtReadFile(client, NULL, failed_read_apc, NULL, &iosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_PIPE_BROKEN, "parked read broken by the peer -> %08lx",
       (unsigned long)status);
    ok(iosb.Status == (NTSTATUS)IOSB_POISON_STATUS, "a failed read wrote the IOSB (%08lx)",
       (unsigned long)iosb.Status);
    ok(is_signaled(client), "a parked read that failed left the handle unsignalled");

    /* The routine is a user APC, so it has not run when the syscall returns
     * (the ordering sem_pipe/alertable_park.c case 3 pins); this is the next
     * alertable point. */
    ok(failedReadApcCalls == 0, "the completion routine ran before an alertable point (%ld)",
       (long)failedReadApcCalls);
    zero.QuadPart = 0;
    NtDelayExecution(TRUE, &zero);
    ok(failedReadApcCalls == 1, "the completion routine ran %ld times for a failed parked read",
       (long)failedReadApcCalls);

    ok(finish_sampler(job), "the sampler finished");
    ok(!job->sawWatchedSignaled, "the handle was signalled while a blocking read was parked");

    NtClose(client);
}

/* Case 7: case 6 with an EVENT, which is the corner where the two failure
 * shapes stop agreeing. Case 5's refusal never reaches the signal block at
 * all; a request that was QUEUED does reach it even when it fails
 * (`async->pending || !NT_ERROR( status )`), and there it takes the SAME
 * event-or-handle arm a success takes. So a failing read can signal the
 * caller's event — which is the opposite of what the direct-fd path does
 * (dlls/ntdll/unix/file.c's `if (status != STATUS_PENDING && event)
 * NtResetEvent`), and a pipe never takes that path. */
static void test_parked_then_failed_read_with_event(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL, event;
    SAMPLER *job;
    char buffer[16];
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_blksig7"), &server, &client))
        return;

    event = CreateEventW(NULL, TRUE, TRUE, NULL); /* born signalled */
    ok(event != NULL, "CreateEventW");

    job = start_sampler(server, client, event, SamplerClose);
    ok(job->thread != NULL, "CreateThread");

    poison_iosb(&iosb);
    status = NtReadFile(client, event, NULL, NULL, &iosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_PIPE_BROKEN, "parked read broken by the peer -> %08lx",
       (unsigned long)status);
    ok(is_signaled(event), "a failing QUEUED read did not signal the caller's event");
    ok(!is_signaled(client), "a failing read with an event signalled the handle too");

    ok(finish_sampler(job), "the sampler finished");
    ok(!job->sawEventSignaled, "the event was signalled while the read was parked");
    ok(!job->sawWatchedSignaled, "the handle was signalled while a blocking read was parked");

    CloseHandle(event);
    NtClose(client);
}

/* Case 8: a refusal on a handle that is ALREADY DOWN. Case 5 measures the
 * refusal against a fresh handle, which is born signalled — so it cannot tell
 * "leave the handle alone" from "signal the handle", and an implementation
 * that clears at issue and then unconditionally signals on a refusal passes
 * it. Here the previous read completed through an EVENT and left the handle
 * down (case 2's rule), and the refusal must leave it down. */
static void test_refusal_leaves_a_down_handle_down(void)
{
    IO_STATUS_BLOCK iosb, writeIosb;
    HANDLE server = NULL, client = NULL, event;
    char buffer[16];
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_blksig8"), &server, &client))
        return;

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(event != NULL, "CreateEventW");

    status = pipe_write(server, "d", 1, &writeIosb);
    ok(status == STATUS_SUCCESS, "peer write -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    status = NtReadFile(client, event, NULL, NULL, &iosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_SUCCESS, "inline read -> %08lx", (unsigned long)status);
    ok(!is_signaled(client), "the handle was signalled by a read that had an event");

    NtClose(server); /* the peer is gone: the next read is refused above the queue */

    poison_iosb(&iosb);
    status = pipe_read(client, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_PIPE_BROKEN, "read on a broken pipe -> %08lx", (unsigned long)status);
    ok(!is_signaled(client), "a refusal signalled a handle the oracle never touched");

    CloseHandle(event);
    NtClose(client);
}

/* Case 9: the WRITE direction of case 7, because the two directions carry the
 * same rule through different code and only a case can say they agree. The
 * write fills the end's 4 KiB quota and parks; the peer then closes under it.
 * A queued write that fails signals the caller's event exactly as a read
 * does — and an implementation whose failure path resets the event after the
 * engine set it passes every read case and fails this one. */
static void test_parked_then_failed_write_with_event(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL, event;
    static char bulk[4096];
    SAMPLER *job;
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_blksig9"), &server, &client))
        return;

    event = CreateEventW(NULL, TRUE, TRUE, NULL); /* born signalled */
    ok(event != NULL, "CreateEventW");

    /* Fill the outgoing quota so the next write has nowhere to go. */
    status = pipe_write(client, bulk, sizeof(bulk), &iosb);
    ok(status == STATUS_SUCCESS, "quota-filling write -> %08lx", (unsigned long)status);

    job = start_sampler(server, client, event, SamplerClose);
    ok(job->thread != NULL, "CreateThread");

    poison_iosb(&iosb);
    status = NtWriteFile(client, event, NULL, NULL, &iosb, bulk, sizeof(bulk), NULL, NULL);
    ok(!NT_SUCCESS(status), "parked write broken by the peer -> %08lx", (unsigned long)status);
    ok(is_signaled(event), "a failing QUEUED write did not signal the caller's event");

    ok(finish_sampler(job), "the sampler finished");
    ok(!job->sawEventSignaled, "the event was signalled while the write was parked");
    ok(!job->sawWatchedSignaled, "the handle was signalled while a blocking write was parked");

    CloseHandle(event);
    NtClose(client);
}

START_TEST(blocking_signal)
{
    test_blocking_read_no_event();
    test_blocking_read_with_event();
    test_a_later_completion_signals_the_handle();
    test_blocking_flush();
    test_failed_read_states();
    test_parked_then_failed_read();
    test_parked_then_failed_read_with_event();
    test_refusal_leaves_a_down_handle_down();
    test_parked_then_failed_write_with_event();
}
