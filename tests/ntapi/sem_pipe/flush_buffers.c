/*
 * sem_pipe/flush_buffers.c — NtFlushBuffersFile on a named-pipe end (M9).
 *
 * A pipe's flush is not a writeback. It PARKS until the peer has consumed
 * everything this end wrote (wine server/named_pipe.c pipe_end_flush: the
 * guard is `pipe_end->connection && !list_empty(&connection->message_queue)`,
 * and what wakes it is the drain — reselect_read_queue's
 * `fd_async_wake_up(pipe_end->connection->fd, ASYNC_TYPE_WAIT,
 * STATUS_SUCCESS)` when the queue it just read from goes empty).
 *
 * That ordering is what the FlushFileBuffers-then-DisconnectNamedPipe idiom
 * rests on: a disconnect DISCARDS whatever the peer has not read, so a flush
 * that answers a plausible no-op success loses the reply.
 *
 * Every case here runs the flush on a WORKER THREAD behind a bounded wait,
 * so a kernel that loses the wake FAILS AN ASSERTION rather than costing the
 * leg its timeout (docs/21 W10 lesson 2).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtCancelSynchronousIoFile(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK);

/* How long a flush is given to prove it is still parked, and how long it is
 * then given to finish. The first is a lower bound on nothing — it only has
 * to outlast a wrong kernel's immediate return; the second is a ceiling that
 * turns a lost wake into an assertion. */
#define PARK_SETTLE_MS 150
#define FLUSH_WAIT_MS  5000

/* One state block per flush, never reused. A case whose flush never returns
 * leaves a thread parked in the KERNEL, and that thread writes its answer
 * whenever it finally wakes — measured: an earlier draft shared one set of
 * globals, and a stuck flush from one case reported STATUS_PIPE_BROKEN into
 * the next case's assertion, so the failure named the wrong subject. A test
 * whose failure path lies is worse than one that fails. */
typedef struct
{
    HANDLE target;
    HANDLE thread;
    volatile LONG done;
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
} FLUSH_JOB;

static FLUSH_JOB flush_jobs[16];
static unsigned flush_job_count;

static FLUSH_JOB *new_flush_job(HANDLE target)
{
    FLUSH_JOB *job = &flush_jobs[flush_job_count++];
    job->target = target;
    job->thread = NULL;
    job->status = (NTSTATUS)IOSB_POISON_STATUS;
    poison_iosb(&job->iosb);
    job->done = 0;
    return job;
}

static DWORD WINAPI flush_thread(void *param)
{
    FLUSH_JOB *job = param;
    job->status = NtFlushBuffersFile(job->target, &job->iosb);
    job->done = 1;
    return 0;
}

static FLUSH_JOB *start_flush(HANDLE target)
{
    FLUSH_JOB *job = new_flush_job(target);
    job->thread = CreateThread(NULL, 0, flush_thread, job, 0, NULL);
    return job;
}

static BOOL finish_flush(FLUSH_JOB *job)
{
    BOOL done = job->thread != NULL && WaitForSingleObject(job->thread, FLUSH_WAIT_MS) == WAIT_OBJECT_0;
    if (done)
    {
        CloseHandle(job->thread);
        job->thread = NULL;
    }
    return done;
}

static void sleep_ms(DWORD ms)
{
    Sleep(ms);
}

/* test_flush_after_a_cancelled_read's worker: one thread that takes a
 * cancelled read and then a flush, because the whole question is whether the
 * first leaves anything behind for the second. */
static HANDLE stale_read_end;
static volatile NTSTATUS stale_read_status;

static DWORD WINAPI read_then_flush_thread(void *param)
{
    FLUSH_JOB *job = param;
    IO_STATUS_BLOCK iosb;
    char buffer[16];

    stale_read_status = pipe_read(stale_read_end, buffer, sizeof(buffer), &iosb);
    pipe_write(job->target, "abcd", 4, &iosb);
    job->status = NtFlushBuffersFile(job->target, &job->iosb);
    job->done = 1;
    return 0;
}

/* Nothing queued: the guard's second half is false, so the flush answers at
 * once. Both ends, because the rule is per END and not per role. */
static void test_flush_nothing_queued(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    FLUSH_JOB *job;
    NTSTATUS status;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_flushidle"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_flushidle"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    job = start_flush(server);
    ok(job->thread != NULL, "CreateThread");
    ok(finish_flush(job), "idle server flush finished");
    ok(job->status == STATUS_SUCCESS, "idle server flush -> %08lx", (unsigned long)job->status);
    ok(job->iosb.Status == STATUS_SUCCESS, "idle server flush iosb.Status %08lx",
       (unsigned long)job->iosb.Status);
    ok(job->iosb.Information == 0, "idle server flush iosb.Information %llx",
       (unsigned long long)job->iosb.Information);

    job = start_flush(client);
    ok(job->thread != NULL, "CreateThread");
    ok(finish_flush(job), "idle client flush finished");
    ok(job->status == STATUS_SUCCESS, "idle client flush -> %08lx", (unsigned long)job->status);

    NtClose(client);
    NtClose(server);
}

/* A LISTENING instance has no peer at all, so there is nothing to wait for:
 * the flush is a success, not the STATUS_PIPE_LISTENING every data verb on
 * the same handle answers. */
static void test_flush_listening(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL;
    FLUSH_JOB *job;
    NTSTATUS status;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_flushlisten"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);

    job = start_flush(server);
    ok(job->thread != NULL, "CreateThread");
    ok(finish_flush(job), "listening flush finished");
    ok(job->status == STATUS_SUCCESS, "listening flush -> %08lx", (unsigned long)job->status);

    NtClose(server);
}

/* The item itself: the flush parks while the peer has unread bytes and
 * returns only when the LAST of them is gone. The two-step drain is the
 * discriminating half — an implementation that returns on the first wake
 * without re-checking the queue passes a single-read version of this case. */
static void test_flush_waits_for_drain(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    FLUSH_JOB *job;
    char buffer[8];
    NTSTATUS status;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_flushdrain"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_flushdrain"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    status = pipe_write(server, "abcdefgh", 8, &iosb);
    ok(status == STATUS_SUCCESS, "server write -> %08lx", (unsigned long)status);

    job = start_flush(server);
    ok(job->thread != NULL, "CreateThread");
    sleep_ms(PARK_SETTLE_MS);
    ok(job->done == 0, "flush returned with 8 bytes unread (status %08lx)",
       (unsigned long)job->status);

    status = pipe_read(client, buffer, 4, &iosb);
    ok(status == STATUS_SUCCESS, "client first read -> %08lx", (unsigned long)status);
    ok(iosb.Information == 4, "client first read length %llx",
       (unsigned long long)iosb.Information);
    sleep_ms(PARK_SETTLE_MS);
    ok(job->done == 0, "flush returned with 4 bytes still unread (status %08lx)",
       (unsigned long)job->status);

    status = pipe_read(client, buffer, 4, &iosb);
    ok(status == STATUS_SUCCESS, "client second read -> %08lx", (unsigned long)status);
    ok(finish_flush(job), "flush finished after the drain");
    ok(job->status == STATUS_SUCCESS, "drained flush -> %08lx", (unsigned long)job->status);
    ok(job->iosb.Status == STATUS_SUCCESS, "drained flush iosb.Status %08lx",
       (unsigned long)job->iosb.Status);

    NtClose(client);
    NtClose(server);
}

/* The drain and the peer's CLOSE, in that order, before the flusher has been
 * scheduled again — which is not a corner but the ordinary echo-server shape
 * (dlls/kernel32/tests/pipe.c exerciseServer reads and closes back to back).
 * The answer is the DRAIN's: a flush's status is decided at the transition
 * that satisfies it, so nothing that happens afterwards can change it. An
 * implementation whose parked flush re-reads the pipe's state instead reports
 * STATUS_PIPE_BROKEN here and passes every other case in this file. */
static void test_flush_drain_then_peer_close(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    FLUSH_JOB *job;
    char buffer[8];
    NTSTATUS status;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_flushrace"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_flushrace"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    status = pipe_write(server, "abcd", 4, &iosb);
    ok(status == STATUS_SUCCESS, "server write -> %08lx", (unsigned long)status);

    job = start_flush(server);
    ok(job->thread != NULL, "CreateThread");
    sleep_ms(PARK_SETTLE_MS);
    ok(job->done == 0, "flush returned with 4 bytes unread (status %08lx)",
       (unsigned long)job->status);

    status = pipe_read(client, buffer, 4, &iosb);
    ok(status == STATUS_SUCCESS, "client read -> %08lx", (unsigned long)status);
    NtClose(client);

    ok(finish_flush(job), "flush finished after the drain");
    ok(job->status == STATUS_SUCCESS, "drain-then-close flush -> %08lx",
       (unsigned long)job->status);

    NtClose(server);
}

/* The peer is GONE rather than slow: its handle closed with the bytes still
 * queued. There is no connection left to drain them, so the flush answers at
 * once. An implementation that waits on the QUEUE alone hangs here forever. */
static void test_flush_peer_closed(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    FLUSH_JOB *job;
    NTSTATUS status;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_flushclosed"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_flushclosed"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    status = pipe_write(server, "abcd", 4, &iosb);
    ok(status == STATUS_SUCCESS, "server write -> %08lx", (unsigned long)status);
    NtClose(client);

    job = start_flush(server);
    ok(job->thread != NULL, "CreateThread");
    ok(finish_flush(job), "flush finished with the peer closed");
    ok(job->status == STATUS_SUCCESS, "peer-closed flush -> %08lx", (unsigned long)job->status);

    NtClose(server);
}

/* After the server's own FSCTL_PIPE_DISCONNECT the two ends do NOT answer
 * alike, and that asymmetry is the discriminating case: the disconnect
 * clears the CLIENT's pipe pointer (wine server/named_pipe.c
 * pipe_server_ioctl: `server->pipe_end.connection->pipe = NULL`), so the
 * client's flush is STATUS_PIPE_DISCONNECTED while the server — which keeps
 * its own pipe and simply has no connection — is a success. An
 * implementation that asks one "is this end disconnected" question answers
 * both the same way.
 */
static void test_flush_after_disconnect(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    FLUSH_JOB *job;
    NTSTATUS status;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_flushdisc"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_flushdisc"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    status = pipe_fsctl(server, FSCTL_PIPE_DISCONNECT, &iosb);
    ok(status == STATUS_SUCCESS, "disconnect -> %08lx", (unsigned long)status);

    job = start_flush(client);
    ok(job->thread != NULL, "CreateThread");
    ok(finish_flush(job), "disconnected client flush finished");
    ok(job->status == STATUS_PIPE_DISCONNECTED, "disconnected client flush -> %08lx",
       (unsigned long)job->status);
    /* A refused flush leaves the caller's block alone. */
    ok(job->iosb.Status == (NTSTATUS)IOSB_POISON_STATUS,
       "refused client flush wrote iosb.Status %08lx", (unsigned long)job->iosb.Status);

    job = start_flush(server);
    ok(job->thread != NULL, "CreateThread");
    ok(finish_flush(job), "disconnected server flush finished");
    ok(job->status == STATUS_SUCCESS, "disconnected server flush -> %08lx",
       (unsigned long)job->status);

    NtClose(client);
    NtClose(server);
}

/* A flush that is ALREADY PARKED does not get the resting answer when the
 * pipe comes apart under it — the disconnect wakes the fd's wait queue with
 * its own status (pipe_end_disconnect's `fd_async_wake_up(pipe_end->fd,
 * ASYNC_TYPE_WAIT, status)`), so the same server end that answers
 * STATUS_SUCCESS to a flush issued after the disconnect answers
 * STATUS_PIPE_DISCONNECTED to one that was waiting when it happened. */
static void test_flush_parked_then_disconnect(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    FLUSH_JOB *job;
    NTSTATUS status;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_flushpark"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_flushpark"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    status = pipe_write(server, "abcd", 4, &iosb);
    ok(status == STATUS_SUCCESS, "server write -> %08lx", (unsigned long)status);

    job = start_flush(server);
    ok(job->thread != NULL, "CreateThread");
    sleep_ms(PARK_SETTLE_MS);
    ok(job->done == 0, "flush returned with 4 bytes unread (status %08lx)",
       (unsigned long)job->status);

    status = pipe_fsctl(server, FSCTL_PIPE_DISCONNECT, &iosb);
    ok(status == STATUS_SUCCESS, "disconnect under a parked flush -> %08lx", (unsigned long)status);
    ok(finish_flush(job), "parked flush finished at the disconnect");
    ok(job->status == STATUS_PIPE_DISCONNECTED, "parked flush -> %08lx",
       (unsigned long)job->status);
    /* And it still writes NOTHING into the caller's block — which is the
     * measurement, not the guess: this pair first asserted {status, 0} on the
     * reasoning that a flush which PENDED reports through the IOSB the way
     * every other completed async does, and the oracle refuted it. A failing
     * flush leaves the block alone whether it parked or not. */
    ok(job->iosb.Status == (NTSTATUS)IOSB_POISON_STATUS, "parked flush wrote iosb.Status %08lx",
       (unsigned long)job->iosb.Status);
    ok(job->iosb.Information == (ULONG_PTR)~0ULL, "parked flush wrote iosb.Information %llx",
       (unsigned long long)job->iosb.Information);

    NtClose(client);
    NtClose(server);
}

/* The same shape with the peer CLOSING instead: the wake carries
 * STATUS_PIPE_BROKEN (pipe_end_destroy's own disconnect status), which is a
 * third answer for a handle whose resting answer is STATUS_SUCCESS. */
static void test_flush_parked_then_peer_close(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    FLUSH_JOB *job;
    NTSTATUS status;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_flushbroke"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_flushbroke"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    status = pipe_write(server, "abcd", 4, &iosb);
    ok(status == STATUS_SUCCESS, "server write -> %08lx", (unsigned long)status);

    job = start_flush(server);
    ok(job->thread != NULL, "CreateThread");
    sleep_ms(PARK_SETTLE_MS);
    ok(job->done == 0, "flush returned with 4 bytes unread (status %08lx)",
       (unsigned long)job->status);

    NtClose(client);
    ok(finish_flush(job), "parked flush finished at the peer's close");
    ok(job->status == STATUS_PIPE_BROKEN, "parked flush at peer close -> %08lx",
       (unsigned long)job->status);
    ok(job->iosb.Status == (NTSTATUS)IOSB_POISON_STATUS, "parked flush wrote iosb.Status %08lx",
       (unsigned long)job->iosb.Status);
    ok(job->iosb.Information == (ULONG_PTR)~0ULL, "parked flush wrote iosb.Information %llx",
       (unsigned long long)job->iosb.Information);

    NtClose(server);
}

/* A parked flush is CANCELLABLE, the same way a parked read is: the oracle's
 * flush async is created blocking (server/fd.c DECL_HANDLER(flush) ->
 * async_handoff(async, NULL, 1)) and cancel_sync matches every blocking async
 * of the target thread (server/async.c). Nothing in sem_pipe/cancel_sync.c
 * reaches a flush. */
static void test_cancel_a_parked_flush(void)
{
    IO_STATUS_BLOCK iosb, result;
    HANDLE server = NULL, client = NULL;
    FLUSH_JOB *job;
    NTSTATUS status;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_flushcancel"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_flushcancel"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    status = pipe_write(server, "abcd", 4, &iosb);
    ok(status == STATUS_SUCCESS, "server write -> %08lx", (unsigned long)status);

    job = start_flush(server);
    ok(job->thread != NULL, "CreateThread");
    sleep_ms(PARK_SETTLE_MS);
    ok(job->done == 0, "flush returned with 4 bytes unread (status %08lx)",
       (unsigned long)job->status);

    poison_iosb(&result);
    status = NtCancelSynchronousIoFile(job->thread, NULL, &result);
    ok(status == STATUS_SUCCESS, "cancel a parked flush -> %08lx", (unsigned long)status);
    ok(finish_flush(job), "cancelled flush finished");
    ok(job->status == STATUS_CANCELLED, "cancelled flush -> %08lx", (unsigned long)job->status);

    NtClose(client);
    NtClose(server);
}

/* And a cancel does not OUTLIVE the request it cancelled. The same thread
 * whose blocking read was just cancelled must be able to park in a flush
 * straight afterwards — obvious on a per-request async model and not at all
 * obvious on a per-THREAD cancel flag, which is what proskrnl carries
 * (kernel/ke/ke.h KTHREAD.syncIoCancelled). The flush is the first blocking
 * pipe operation whose Io-layer wrapper had no synchronous-I/O span around
 * it, so it read a flag nobody had reset and answered STATUS_CANCELLED to a
 * caller that had asked for nothing of the kind. */
static void test_flush_after_a_cancelled_read(void)
{
    IO_STATUS_BLOCK iosb, result;
    HANDLE server = NULL, client = NULL;
    FLUSH_JOB *job;
    char buffer[8];
    NTSTATUS status;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_flushstale"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_flushstale"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    /* Park the worker in a read on the empty pipe and cancel it. */
    stale_read_end = server;
    stale_read_status = STATUS_PENDING;
    job = new_flush_job(server);
    job->thread = CreateThread(NULL, 0, read_then_flush_thread, job, 0, NULL);
    ok(job->thread != NULL, "CreateThread");
    sleep_ms(PARK_SETTLE_MS);
    poison_iosb(&result);
    status = NtCancelSynchronousIoFile(job->thread, NULL, &result);
    ok(status == STATUS_SUCCESS, "cancel the blocked read -> %08lx", (unsigned long)status);

    /* The worker then writes 4 bytes and flushes. That flush must PARK. */
    sleep_ms(PARK_SETTLE_MS);
    ok(stale_read_status == STATUS_CANCELLED, "cancelled read -> %08lx",
       (unsigned long)stale_read_status);
    ok(job->done == 0, "the flush inherited the read's cancel (status %08lx)",
       (unsigned long)job->status);

    status = pipe_read(client, buffer, 4, &iosb);
    ok(status == STATUS_SUCCESS, "client read -> %08lx", (unsigned long)status);
    ok(finish_flush(job), "flush finished after the drain");
    ok(job->status == STATUS_SUCCESS, "flush after a cancelled read -> %08lx",
       (unsigned long)job->status);

    NtClose(client);
    NtClose(server);
}

START_TEST(flush_buffers)
{
    test_flush_nothing_queued();
    test_flush_listening();
    test_flush_waits_for_drain();
    test_flush_drain_then_peer_close();
    test_flush_peer_closed();
    test_flush_after_disconnect();
    test_flush_parked_then_disconnect();
    test_flush_parked_then_peer_close();
    test_cancel_a_parked_flush();
    test_flush_after_a_cancelled_read();
}
