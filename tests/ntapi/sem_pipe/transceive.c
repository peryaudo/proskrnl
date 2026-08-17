/*
 * sem_pipe/transceive.c — FSCTL_PIPE_TRANSCEIVE: one write and one read, in
 * one verb, on one end.
 *
 * docs/21 W11, the transceive cluster in ntdll:pipe (dlls/ntdll/tests/pipe.c
 * test_pipe_state :2069 x8 and test_transceive :1450/:1456/:1457/:1458). The
 * whole verb is server/named_pipe.c pipe_end_transceive, reached through
 * pipe_end_ioctl from both ends' ioctl handlers — so unlike LISTEN and
 * DISCONNECT it is a verb BOTH ends have.
 *
 * Five things it does that neither half of its name predicts:
 *
 *   - THE STATE QUESTION IS "IS THERE A CONNECTION", AND ITS TWO ANSWERS
 *     SPLIT THE ENDS:
 *
 *         if (!pipe_end->connection)
 *         { set_error( pipe_end->pipe ? STATUS_INVALID_PIPE_STATE
 *                                     : STATUS_PIPE_DISCONNECTED ); return; }
 *
 *     `connection` is NULL in every state but CONNECTED, so LISTENING,
 *     CLOSING and a DISCONNECTED *server* all report the STATE, while the
 *     client the server disconnected out from under reports the
 *     DISCONNECTION — it is the only end that lost its `pipe`. §1 measures
 *     all four rows; §2 measures the ORDER against the read-mode rule below.
 *
 *   - IT REFUSES A BYTE-MODE READER, and that is a mode of the END rather
 *     than a type of the pipe: `pipe_end->flags & NAMED_PIPE_MESSAGE_STREAM_READ`
 *     is what FilePipeInformation writes. A byte-TYPE pipe can never carry
 *     that flag (create_named_pipe refuses the combination), so on one it is
 *     STATUS_INVALID_READ_MODE forever, while on a message-type pipe it
 *     depends on the end's current mode and moves under a SET (§2).
 *
 *   - IT REFUSES A READER THAT ALREADY HAS DATA — `if (!list_empty(
 *     &pipe_end->message_queue )) set_error( STATUS_PIPE_BUSY )` — which is
 *     the one refusal here that is about the STREAM rather than about the
 *     handle, and the one an implementation built as "write, then read" never
 *     makes: such an implementation would happily answer out of the buffered
 *     bytes (§3).
 *
 *   - THE WRITE HALF NEVER BLOCKS. The oracle says so in a comment —
 *     "transaction never blocks on write, so just queue a message without
 *     async" — and it is a real difference, not a note: an ordinary
 *     NtWriteFile past the peer's quota parks its caller, and a transceive of
 *     the same bytes over the same full queue is accepted on the spot (§5).
 *
 *   - AND THE READ HALF IS THE END'S ORDINARY READ QUEUE
 *     (`queue_async( &pipe_end->read_q, async )`), so a transceive and an
 *     NtReadFile issued after it are served in ISSUE order out of one queue
 *     (§7) — but it is NOT pipe_end_read: that function's
 *     `NAMED_PIPE_NONBLOCKING_MODE` arm, which answers STATUS_PIPE_EMPTY
 *     rather than waiting, has no counterpart in pipe_end_transceive. A
 *     NOWAIT-mode end therefore PENDS a transceive and refuses a read (§6),
 *     which is the case an implementation that tail-calls its own read path
 *     gets wrong. What that mode arm asks about is BUFFERED DATA and not
 *     outstanding requests, which the oracle had to say: §6's first draft
 *     expected the read behind a parked transceive to pend and it is refused
 *     exactly as it would be with nothing outstanding.
 *
 * What is deliberately NOT measured here: the verb's embedded access. The
 * oracle's DECL_HANDLER(ioctl) demands `(code >> 14) & (FILE_READ_DATA |
 * FILE_WRITE_DATA)` on the handle, which for this code is both bits, but
 * proskrnl's ioctl engine asks Ob for no access at all on any verb
 * (kernel/io/ioctl.c) — so that is one rule about the ENGINE, owed by every
 * verb including FSCTL_PIPE_PEEK's FILE_READ_DATA, and it is not this item's
 * to pin half of.
 */
#include "util.h"

#ifndef FSCTL_PIPE_TRANSCEIVE
#define FSCTL_PIPE_TRANSCEIVE                                                                      \
    CTL_CODE(FILE_DEVICE_NAMED_PIPE, 5, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)
#endif
#ifndef FilePipeInformation
#define FilePipeInformation 23
#endif

static BOOLEAN is_signaled(HANDLE handle)
{
    return WaitForSingleObject(handle, 0) == WAIT_OBJECT_0;
}

/* One transceive: `input` bytes out, up to `outputLength` bytes back. */
static NTSTATUS transceive(HANDLE handle, HANDLE event, const void *input, ULONG inputLength,
                           void *output, ULONG outputLength, IO_STATUS_BLOCK *iosb)
{
    poison_iosb(iosb);
    return NtFsControlFile(handle, event, NULL, NULL, iosb, FSCTL_PIPE_TRANSCEIVE, (PVOID)input,
                           inputLength, output, outputLength);
}

static NTSTATUS set_pipe_mode(HANDLE handle, ULONG readMode, ULONG completionMode)
{
    SEM_FILE_PIPE_INFORMATION info;
    IO_STATUS_BLOCK iosb;

    info.ReadMode = readMode;
    info.CompletionMode = completionMode;
    return NtSetInformationFile(handle, &iosb, &info, sizeof(info), FilePipeInformation);
}

/* A SYNCHRONOUS message-type server end in message read mode — the shape
 * every refusal case below wants, since a refusal never parks and so never
 * needs the asynchronous handle the happy path does. */
static NTSTATUS create_sync_server(HANDLE *handle, const void *wideName, ULONG type, ULONG readMode,
                                   ULONG quota)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    LARGE_INTEGER timeout;
    IO_STATUS_BLOCK iosb;

    init_ustr(&name, wideName);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    timeout.QuadPart = -100 * 10000; /* 100 ms, relative */
    *handle = NULL;
    return NtCreateNamedPipeFile(handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr, &iosb,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE,
                                 FILE_SYNCHRONOUS_IO_NONALERT, type, readMode,
                                 FILE_PIPE_QUEUE_OPERATION, 1, quota, quota, &timeout);
}

/* The same instance on an ASYNCHRONOUS handle: no FILE_SYNCHRONOUS_IO_* bit,
 * so a transceive that parks answers STATUS_PENDING and this thread carries
 * on to satisfy it (the pended_read.c arrangement, and the reason no case
 * here needs a worker thread). */
static NTSTATUS create_async_server(HANDLE *handle, const void *wideName, ULONG type,
                                    ULONG readMode, ULONG quota)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    LARGE_INTEGER timeout;
    IO_STATUS_BLOCK iosb;

    init_ustr(&name, wideName);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    timeout.QuadPart = -100 * 10000; /* 100 ms, relative */
    *handle = NULL;
    return NtCreateNamedPipeFile(handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr, &iosb,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, type, readMode,
                                 FILE_PIPE_QUEUE_OPERATION, 1, quota, quota, &timeout);
}

/* §1 — the state ladder: the four rows ntdll:pipe's test_pipe_state asks for.
 *
 * Every one of them is asked through a MESSAGE-type end in MESSAGE read mode,
 * so the read-mode refusal below cannot be what answers — that ordering is
 * §2's subject and this section must not depend on it. */
static void test_state_ladder(void)
{
    char in[4] = "req";
    char out[16];
    HANDLE server = NULL, client = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    status = create_sync_server(&server, W("\\??\\pipe\\prstest_tvst"), FILE_PIPE_TYPE_MESSAGE,
                                FILE_PIPE_MESSAGE_MODE, 4096);
    ok(status == STATUS_SUCCESS, "state-ladder server -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* LISTENING: no connection, and the pipe is still this end's. */
    status = transceive(server, NULL, in, 3, out, sizeof(out), &iosb);
    ok(status == STATUS_INVALID_PIPE_STATE, "transceive while listening -> %08lx",
       (unsigned long)status);

    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_tvst"), &iosb);
    ok(status == STATUS_SUCCESS, "state-ladder client -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    /* DISCONNECTED splits the two ends, exactly as FSCTL_PIPE_PEEK's ladder
     * does and for the same reason: the server keeps `pipe`, its client does
     * not. */
    status = pipe_fsctl(server, FSCTL_PIPE_DISCONNECT, &iosb);
    ok(status == STATUS_SUCCESS, "disconnect -> %08lx", (unsigned long)status);

    status = transceive(server, NULL, in, 3, out, sizeof(out), &iosb);
    ok(status == STATUS_INVALID_PIPE_STATE, "transceive on the disconnecting SERVER -> %08lx",
       (unsigned long)status);
    status = transceive(client, NULL, in, 3, out, sizeof(out), &iosb);
    ok(status == STATUS_PIPE_DISCONNECTED, "transceive on the disconnected CLIENT -> %08lx",
       (unsigned long)status);

    NtClose(client);
    NtClose(server);

    /* CLOSING — the peer closed its handle. `connection` is gone but the
     * pipe is not, so this is the STATE row again and not the disconnection
     * one, which is what separates "the peer left" from "the server threw the
     * client out". */
    status = create_sync_server(&server, W("\\??\\pipe\\prstest_tvcl"), FILE_PIPE_TYPE_MESSAGE,
                                FILE_PIPE_MESSAGE_MODE, 4096);
    ok(status == STATUS_SUCCESS, "closing server -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_tvcl"), &iosb);
    ok(status == STATUS_SUCCESS, "closing client -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }
    NtClose(client);

    status = transceive(server, NULL, in, 3, out, sizeof(out), &iosb);
    ok(status == STATUS_INVALID_PIPE_STATE, "transceive while closing -> %08lx",
       (unsigned long)status);

    NtClose(server);
}

/* §2 — the read-mode refusal, and the ORDER of the three guards.
 *
 * A byte-TYPE pipe cannot be read in message mode at all, so it is the
 * cheapest statement of "this verb needs a message reader"; a message-type
 * end whose mode is SET back to byte gives the same status, which is what
 * says the rule reads the END and not the pipe. And the guard sits BELOW the
 * state question and ABOVE the busy one: a LISTENING byte-mode end reports
 * its state, a connected byte-mode end with data queued reports its mode. */
static void test_read_mode(void)
{
    char in[4] = "req";
    char out[16];
    char reply[8] = "hi";
    HANDLE server = NULL, client = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    /* A byte-TYPE pipe: byte read mode is the only mode it has. */
    status = create_sync_server(&server, W("\\??\\pipe\\prstest_tvby"), FILE_PIPE_TYPE_BYTE,
                                FILE_PIPE_BYTE_STREAM_MODE, 4096);
    ok(status == STATUS_SUCCESS, "byte-type server -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* Listening AND byte-mode: the state is what comes back. */
    status = transceive(server, NULL, in, 3, out, sizeof(out), &iosb);
    ok(status == STATUS_INVALID_PIPE_STATE, "listening byte-mode transceive -> %08lx",
       (unsigned long)status);

    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_tvby"), &iosb);
    ok(status == STATUS_SUCCESS, "byte-type client -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    status = transceive(server, NULL, in, 3, out, sizeof(out), &iosb);
    ok(status == STATUS_INVALID_READ_MODE, "connected byte-mode transceive -> %08lx",
       (unsigned long)status);

    /* Data queued as well: the MODE still answers, so the mode guard is above
     * the busy guard. */
    status = pipe_write(client, reply, 2, &iosb);
    ok(status == STATUS_SUCCESS, "byte-type seed -> %08lx", (unsigned long)status);
    status = transceive(server, NULL, in, 3, out, sizeof(out), &iosb);
    ok(status == STATUS_INVALID_READ_MODE, "byte-mode transceive with data queued -> %08lx",
       (unsigned long)status);

    NtClose(client);
    NtClose(server);

    /* A MESSAGE-type end, created in message mode and SET back to byte: the
     * same refusal, from a pipe whose type never changed. */
    status = create_sync_server(&server, W("\\??\\pipe\\prstest_tvmo"), FILE_PIPE_TYPE_MESSAGE,
                                FILE_PIPE_MESSAGE_MODE, 4096);
    ok(status == STATUS_SUCCESS, "mode-switch server -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_tvmo"), &iosb);
    ok(status == STATUS_SUCCESS, "mode-switch client -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    status = set_pipe_mode(server, FILE_PIPE_BYTE_STREAM_MODE, FILE_PIPE_QUEUE_OPERATION);
    ok(status == STATUS_SUCCESS, "set byte read mode -> %08lx", (unsigned long)status);
    status = transceive(server, NULL, in, 3, out, sizeof(out), &iosb);
    ok(status == STATUS_INVALID_READ_MODE, "message-type end read in byte mode -> %08lx",
       (unsigned long)status);

    NtClose(client);
    NtClose(server);
}

/* §3 — STATUS_PIPE_BUSY: a reader that already has data cannot transceive.
 *
 * The refusal is total, not a preference — the input is NOT written, which is
 * the part a caller depends on and the part an implementation that writes
 * first and then discovers the buffered bytes gets wrong. Measured by
 * draining the peer afterwards: the only message it ever sees is its own
 * seed coming back to it, never the transceive's payload. */
static void test_busy_reader(void)
{
    char in[8] = "payload";
    char out[16];
    char drain[16];
    HANDLE server = NULL, client = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    status = create_sync_server(&server, W("\\??\\pipe\\prstest_tvbz"), FILE_PIPE_TYPE_MESSAGE,
                                FILE_PIPE_MESSAGE_MODE, 4096);
    ok(status == STATUS_SUCCESS, "busy server -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_tvbz"), &iosb);
    ok(status == STATUS_SUCCESS, "busy client -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    status = pipe_write(client, "abc", 3, &iosb);
    ok(status == STATUS_SUCCESS, "busy seed -> %08lx", (unsigned long)status);

    status = transceive(server, NULL, in, 7, out, sizeof(out), &iosb);
    ok(status == STATUS_PIPE_BUSY, "transceive with data buffered -> %08lx", (unsigned long)status);
    ok(iosb.Status == IOSB_POISON_STATUS, "a refused transceive wrote its IOSB: %08lx",
       (unsigned long)iosb.Status);

    /* Nothing was written: the client's incoming queue is empty, so a
     * COMPLETE_OPERATION read there says so rather than handing back
     * "payload". */
    status = set_pipe_mode(client, FILE_PIPE_MESSAGE_MODE, FILE_PIPE_COMPLETE_OPERATION);
    ok(status == STATUS_SUCCESS, "client to NOWAIT -> %08lx", (unsigned long)status);
    status = pipe_read(client, drain, sizeof(drain), &iosb);
    ok(status == STATUS_PIPE_EMPTY, "the refused transceive wrote its input -> %08lx",
       (unsigned long)status);

    /* And the server's own buffered message is still there, unconsumed. */
    status = pipe_read(server, drain, sizeof(drain), &iosb);
    ok(status == STATUS_SUCCESS, "drain the server -> %08lx", (unsigned long)status);
    ok(iosb.Information == 3, "drained %llu", (unsigned long long)iosb.Information);

    NtClose(client);
    NtClose(server);
}

/* §4 — the whole verb, on an asynchronous handle: it PENDS, the peer sees the
 * input as one message, and the peer's reply is what completes it.
 *
 * The event is created SIGNALLED so the reset at issue is observable, and
 * everything after the transceive runs on THIS thread — a kernel that parks
 * the caller inside the fsctl never reaches the second statement. Second
 * half: the reply is framed as a MESSAGE, so a reply longer than the output
 * buffer completes STATUS_BUFFER_OVERFLOW with the tail still queued. */
static void test_transceive_round_trip(void)
{
    char out[16];
    char drain[32];
    HANDLE server = NULL, client = NULL, event;
    IO_STATUS_BLOCK iosb, peerIosb;
    NTSTATUS status;

    status = create_async_server(&server, W("\\??\\pipe\\prstest_tvrt"), FILE_PIPE_TYPE_MESSAGE,
                                 FILE_PIPE_MESSAGE_MODE, 4096);
    ok(status == STATUS_SUCCESS, "round-trip server -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_tvrt"), &peerIosb);
    ok(status == STATUS_SUCCESS, "round-trip client -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }
    status = set_pipe_mode(client, FILE_PIPE_MESSAGE_MODE, FILE_PIPE_QUEUE_OPERATION);
    ok(status == STATUS_SUCCESS, "client read mode -> %08lx", (unsigned long)status);

    event = CreateEventW(NULL, TRUE, TRUE, NULL); /* manual reset, SIGNALLED */
    ok(event != NULL, "CreateEventW");
    ok(is_signaled(server), "the server handle is not signalled before any request");

    memset(out, 0, sizeof(out));
    status = transceive(server, event, "question", 8, out, sizeof(out), &iosb);
    ok(status == STATUS_PENDING, "transceive on an empty async pipe -> %08lx",
       (unsigned long)status);
    ok(iosb.Status == IOSB_POISON_STATUS, "a pended transceive wrote its IOSB: %08lx",
       (unsigned long)iosb.Status);
    ok(!is_signaled(event), "the event was not reset when the transceive was issued");
    ok(!is_signaled(server), "the handle is still signalled with a transceive outstanding");

    /* The write half already happened, even though the verb has not
     * completed: the peer can read the payload now. */
    status = pipe_read(client, drain, sizeof(drain), &peerIosb);
    ok(status == STATUS_SUCCESS, "peer read of the transceived message -> %08lx",
       (unsigned long)status);
    ok(peerIosb.Information == 8, "peer read %llu bytes", (unsigned long long)peerIosb.Information);
    ok(memcmp(drain, "question", 8) == 0, "the transceive wrote the wrong bytes");

    /* And the reply completes it, from this same thread. */
    status = pipe_write(client, "answer", 6, &peerIosb);
    ok(status == STATUS_SUCCESS, "peer reply -> %08lx", (unsigned long)status);

    ok(iosb.Status == STATUS_SUCCESS, "completed transceive status %08lx",
       (unsigned long)iosb.Status);
    ok(iosb.Information == 6, "completed transceive information %llu",
       (unsigned long long)iosb.Information);
    ok(memcmp(out, "answer", 6) == 0, "the reply was not placed in the output buffer");
    ok(is_signaled(event), "the event was not signalled at completion");
    ok(!is_signaled(server), "the handle was signalled although the transceive carried an event");

    /* The reply is a MESSAGE: a second transceive with room for two of the
     * five bytes coming back overflows and leaves the tail queued. */
    memset(out, 0, sizeof(out));
    status = transceive(server, event, "again", 5, out, 2, &iosb);
    ok(status == STATUS_PENDING, "second transceive -> %08lx", (unsigned long)status);
    status = pipe_read(client, drain, sizeof(drain), &peerIosb);
    ok(status == STATUS_SUCCESS, "peer read of the second message -> %08lx", (unsigned long)status);
    status = pipe_write(client, "12345", 5, &peerIosb);
    ok(status == STATUS_SUCCESS, "peer long reply -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_BUFFER_OVERFLOW, "truncated reply status %08lx",
       (unsigned long)iosb.Status);
    ok(iosb.Information == 2, "truncated reply information %llu",
       (unsigned long long)iosb.Information);
    ok(memcmp(out, "12", 2) == 0, "the truncated reply placed the wrong bytes");

    /* The tail is the SAME message, still queued — a plain read picks it up. */
    status = pipe_read(server, drain, sizeof(drain), &iosb);
    ok(status == STATUS_SUCCESS, "read the overflow tail -> %08lx", (unsigned long)status);
    ok(iosb.Information == 3, "overflow tail information %llu",
       (unsigned long long)iosb.Information);
    ok(memcmp(drain, "345", 3) == 0, "the overflow tail is the wrong bytes");

    CloseHandle(event);
    NtClose(client);
    NtClose(server);
}

/* §5 — the write half never blocks on the peer's quota.
 *
 * The end's outgoing queue is filled to its quota by an ordinary write first,
 * so a SECOND ordinary write would park; the transceive of the same size is
 * accepted immediately and pends for its REPLY instead. That distinction is
 * what "just queue a message without async" means, and an implementation that
 * routes the write half through its own NtWriteFile path hangs here rather
 * than failing an assertion — which is why this case runs on an asynchronous
 * handle and asserts STATUS_PENDING, the one answer a parked writer cannot
 * give.
 */
static void test_write_half_ignores_quota(void)
{
    char fill[64];
    char out[16];
    char drain[128];
    HANDLE server = NULL, client = NULL;
    IO_STATUS_BLOCK iosb, peerIosb;
    NTSTATUS status;

    /* 64-byte quotas: one 64-byte message fills the outbound direction. */
    status = create_async_server(&server, W("\\??\\pipe\\prstest_tvqt"), FILE_PIPE_TYPE_MESSAGE,
                                 FILE_PIPE_MESSAGE_MODE, 64);
    ok(status == STATUS_SUCCESS, "quota server -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_tvqt"), &peerIosb);
    ok(status == STATUS_SUCCESS, "quota client -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }
    status = set_pipe_mode(client, FILE_PIPE_MESSAGE_MODE, FILE_PIPE_QUEUE_OPERATION);
    ok(status == STATUS_SUCCESS, "quota client read mode -> %08lx", (unsigned long)status);

    memset(fill, 'f', sizeof(fill));
    status = pipe_write(server, fill, sizeof(fill), &iosb);
    ok(status == STATUS_SUCCESS, "fill the outbound quota -> %08lx", (unsigned long)status);
    ok(iosb.Information == sizeof(fill), "filled %llu", (unsigned long long)iosb.Information);

    memset(out, 0, sizeof(out));
    status = transceive(server, NULL, "over", 4, out, sizeof(out), &iosb);
    ok(status == STATUS_PENDING, "transceive over a full queue -> %08lx", (unsigned long)status);

    /* Both messages are there, in order, so the transceive's payload really
     * was queued rather than dropped or deferred. */
    status = pipe_read(client, drain, sizeof(drain), &peerIosb);
    ok(status == STATUS_SUCCESS, "peer read of the fill -> %08lx", (unsigned long)status);
    ok(peerIosb.Information == sizeof(fill), "peer read %llu of the fill",
       (unsigned long long)peerIosb.Information);
    status = pipe_read(client, drain, sizeof(drain), &peerIosb);
    ok(status == STATUS_SUCCESS, "peer read of the transceived message -> %08lx",
       (unsigned long)status);
    ok(peerIosb.Information == 4, "peer read %llu of the transceive",
       (unsigned long long)peerIosb.Information);
    ok(memcmp(drain, "over", 4) == 0, "the over-quota transceive wrote the wrong bytes");

    status = pipe_write(client, "ok", 2, &peerIosb);
    ok(status == STATUS_SUCCESS, "peer reply -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "over-quota transceive status %08lx",
       (unsigned long)iosb.Status);
    ok(iosb.Information == 2, "over-quota transceive information %llu",
       (unsigned long long)iosb.Information);

    NtClose(client);
    NtClose(server);
}

/* §6 — NOWAIT mode: a READ refuses, and a transceive on the same handle in
 * the same state PENDS.
 *
 * FILE_PIPE_COMPLETE_OPERATION is pipe_end_read's rule
 * (`(flags & NAMED_PIPE_NONBLOCKING_MODE) && list_empty(...)` ->
 * STATUS_PIPE_EMPTY) and pipe_end_transceive does not have it. The two calls
 * are back to back against one unchanged handle, which is the only
 * arrangement that shows it is the VERB and not the state that differs.
 *
 * THE FIRST DRAFT ALSO CLAIMED HERE that a plain read issued behind the
 * parked transceive would pend "because the transceive is ahead of it", and
 * THE ORACLE REFUTED IT: the read still answers STATUS_PIPE_EMPTY. The mode's
 * arm asks `list_empty( &pipe_end->message_queue )` — the queue of BUFFERED
 * DATA — and a parked request of any kind puts nothing in it. So NOWAIT is
 * decided by what is readable, never by what is outstanding, and the queue
 * order is §7's subject on a handle where nothing refuses. */
static void test_nowait_ignored_by_transceive(void)
{
    char out[16];
    char drain[32];
    HANDLE server = NULL, client = NULL;
    IO_STATUS_BLOCK iosb, readIosb, peerIosb;
    NTSTATUS status;

    status = create_async_server(&server, W("\\??\\pipe\\prstest_tvnw"), FILE_PIPE_TYPE_MESSAGE,
                                 FILE_PIPE_MESSAGE_MODE, 4096);
    ok(status == STATUS_SUCCESS, "nowait server -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_tvnw"), &peerIosb);
    ok(status == STATUS_SUCCESS, "nowait client -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }
    status = set_pipe_mode(client, FILE_PIPE_MESSAGE_MODE, FILE_PIPE_QUEUE_OPERATION);
    ok(status == STATUS_SUCCESS, "nowait client read mode -> %08lx", (unsigned long)status);

    status = set_pipe_mode(server, FILE_PIPE_MESSAGE_MODE, FILE_PIPE_COMPLETE_OPERATION);
    ok(status == STATUS_SUCCESS, "server to NOWAIT -> %08lx", (unsigned long)status);

    status = pipe_read(server, drain, sizeof(drain), &readIosb);
    ok(status == STATUS_PIPE_EMPTY, "NOWAIT read on an empty pipe -> %08lx", (unsigned long)status);

    memset(out, 0, sizeof(out));
    status = transceive(server, NULL, "one", 3, out, sizeof(out), &iosb);
    ok(status == STATUS_PENDING, "NOWAIT transceive on an empty pipe -> %08lx",
       (unsigned long)status);

    /* Still refused with the transceive parked: the mode reads the DATA queue,
     * not the request queue. */
    status = pipe_read(server, drain, sizeof(drain), &readIosb);
    ok(status == STATUS_PIPE_EMPTY, "NOWAIT read behind a parked transceive -> %08lx",
       (unsigned long)status);

    status = pipe_read(client, drain, sizeof(drain), &peerIosb);
    ok(status == STATUS_SUCCESS, "peer read -> %08lx", (unsigned long)status);
    status = pipe_write(client, "first", 5, &peerIosb);
    ok(status == STATUS_SUCCESS, "reply -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "NOWAIT transceive completion %08lx",
       (unsigned long)iosb.Status);
    ok(memcmp(out, "first", 5) == 0, "the NOWAIT transceive took the wrong reply");

    NtClose(client);
    NtClose(server);
}

/* §7 — the read half is the END'S OWN READ QUEUE, so a transceive and a plain
 * read are served in ISSUE order out of one queue
 * (`queue_async( &pipe_end->read_q, async )` is what both reach). Two replies,
 * oldest request first — and the read must not be able to take the first one,
 * which is the half that says the transceive is really queued rather than
 * merely remembered somewhere else. */
static void test_queue_order(void)
{
    char out[16];
    char second[16];
    char drain[32];
    HANDLE server = NULL, client = NULL;
    IO_STATUS_BLOCK iosb, readIosb, peerIosb;
    NTSTATUS status;

    status = create_async_server(&server, W("\\??\\pipe\\prstest_tvqo"), FILE_PIPE_TYPE_MESSAGE,
                                 FILE_PIPE_MESSAGE_MODE, 4096);
    ok(status == STATUS_SUCCESS, "queue-order server -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_tvqo"), &peerIosb);
    ok(status == STATUS_SUCCESS, "queue-order client -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }
    status = set_pipe_mode(client, FILE_PIPE_MESSAGE_MODE, FILE_PIPE_QUEUE_OPERATION);
    ok(status == STATUS_SUCCESS, "queue-order client read mode -> %08lx", (unsigned long)status);

    memset(out, 0, sizeof(out));
    status = transceive(server, NULL, "one", 3, out, sizeof(out), &iosb);
    ok(status == STATUS_PENDING, "queue-order transceive -> %08lx", (unsigned long)status);

    memset(second, 0, sizeof(second));
    poison_iosb(&readIosb);
    status = NtReadFile(server, NULL, NULL, NULL, &readIosb, second, sizeof(second), NULL, NULL);
    ok(status == STATUS_PENDING, "read queued behind a transceive -> %08lx", (unsigned long)status);

    status = pipe_read(client, drain, sizeof(drain), &peerIosb);
    ok(status == STATUS_SUCCESS, "peer read -> %08lx", (unsigned long)status);

    status = pipe_write(client, "first", 5, &peerIosb);
    ok(status == STATUS_SUCCESS, "first reply -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "transceive took the first reply: %08lx",
       (unsigned long)iosb.Status);
    ok(memcmp(out, "first", 5) == 0, "the transceive took the wrong reply");
    ok(readIosb.Status == IOSB_POISON_STATUS, "the queued read overtook the transceive: %08lx",
       (unsigned long)readIosb.Status);

    status = pipe_write(client, "sec", 3, &peerIosb);
    ok(status == STATUS_SUCCESS, "second reply -> %08lx", (unsigned long)status);
    ok(readIosb.Status == STATUS_SUCCESS, "queued read status %08lx",
       (unsigned long)readIosb.Status);
    ok(readIosb.Information == 3, "queued read information %llu",
       (unsigned long long)readIosb.Information);
    ok(memcmp(second, "sec", 3) == 0, "the queued read took the wrong reply");

    NtClose(client);
    NtClose(server);
}

START_TEST(transceive)
{
    test_state_ladder();
    test_read_mode();
    test_busy_reader();
    test_transceive_round_trip();
    test_write_half_ignores_quota();
    test_nowait_ignored_by_transceive();
    test_queue_order();
}
