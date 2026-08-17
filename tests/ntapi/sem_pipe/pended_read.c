/*
 * sem_pipe/pended_read.c — a DATA read on an ASYNCHRONOUS pipe handle PENDS.
 *
 * Every other pended verb pinned so far is a control operation
 * (FSCTL_PIPE_LISTEN, NtNotifyChangeDirectoryFile). This file pins the data
 * leg, and the property it is really about is that the ISSUING THREAD KEEPS
 * RUNNING: every case below satisfies its own read afterwards, from the same
 * thread, with no helper. A kernel that parks the caller inside NtReadFile
 * instead of answering STATUS_PENDING passes nothing here — it never reaches
 * the second statement.
 *
 * That is not a hypothetical shape. ntdll:pipe's test_completion does exactly
 * it (dlls/ntdll/tests/pipe.c:1578 issues the read on an empty overlapped
 * pipe, :1583 writes from the same thread), and so does kernel32:virtual's
 * test_write_watch and kernel32:pipe's overlapped server.
 *
 * The oracle's rules, transcribed from the pinned tree so the ORDER and the
 * exclusivity are visible rather than inferred:
 *
 *   server/async.c  create_async:  `if (event) reset_event( event );`
 *   server/async.c  queue_async:   `set_fd_signaled( async->fd, 0 );`
 *   server/async.c  async_set_result:
 *                       `if (async->event) set_event( async->event );
 *                        else if (async->fd) set_fd_signaled( async->fd, 1 );`
 *
 * — so the caller's event is RESET when the request is issued, the FILE
 * OBJECT goes unsignalled when it actually parks, and exactly ONE of the two
 * is signalled at completion. A handle whose read pended with an event
 * supplied stays unsignalled through the completion, which is the half an
 * implementation gets wrong (and which ntdll:pipe:1611-:1617 measures).
 */
#include "util.h"

/* The pipe surface these cases need beyond util.h. Values as
 * wine/include/winternl.h spells them (FILE_INFORMATION_CLASS members
 * FilePipeInformation and FileIoCompletionNotificationInformation, and the
 * FILE_SKIP_* block) — the oracle run validates each, since a wrong class
 * number or flag bit would answer differently on the real ntdll. */
#ifndef FilePipeInformation
#define FilePipeInformation 23
#endif
#ifndef FileIoCompletionNotificationInformation
#define FileIoCompletionNotificationInformation 41
#endif
#ifndef FILE_SKIP_SET_EVENT_ON_HANDLE
#define FILE_SKIP_SET_EVENT_ON_HANDLE 0x2
#endif

typedef struct
{
    ULONG Flags;
} SEM_FILE_IO_COMPLETION_NOTIFICATION_INFORMATION;

static BOOLEAN is_signaled(HANDLE handle)
{
    return WaitForSingleObject(handle, 0) == WAIT_OBJECT_0;
}

/* One ASYNCHRONOUS server-end instance, with the pipe type and read mode as
 * arguments (util.h's create_pipe_instance_async fixes them at byte mode).
 * The reader in every case below is this end, so that the WRITER can be an
 * ordinary synchronous handle and the completion arrives from a plain
 * NtWriteFile rather than from a helper thread. */
static NTSTATUS create_async_server(HANDLE *handle, const void *wide_name, ULONG type,
                                    ULONG read_mode)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    LARGE_INTEGER timeout;
    IO_STATUS_BLOCK iosb;

    init_ustr(&name, wide_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    timeout.QuadPart = -100 * 10000; /* 100 ms, relative */
    *handle = NULL;
    return NtCreateNamedPipeFile(handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr, &iosb,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, 0, type,
                                 read_mode, FILE_PIPE_QUEUE_OPERATION, 1, 4096, 4096, &timeout);
}

/* server (async, the reader) + client (synchronous, the writer), connected. */
static BOOLEAN make_pair(const void *wide_name, ULONG type, ULONG read_mode, HANDLE *server,
                         HANDLE *client)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status = create_async_server(server, wide_name, type, read_mode);
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return FALSE;
    status = open_pipe_client(client, wide_name, &iosb);
    ok(status == STATUS_SUCCESS, "client open -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(*server);
        return FALSE;
    }
    return TRUE;
}

/* Case 1: the park, and the EVENT leg of the completion.
 *
 * The event is created SIGNALLED so the reset at issue is observable: the
 * oracle resets it in create_async, before the request can pend, which a
 * caller that reads the event and the IOSB together depends on. */
static void test_pended_read_with_event(void)
{
    IO_STATUS_BLOCK iosb, writeIosb;
    HANDLE server = NULL, client = NULL, event;
    char buffer[16];
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_rdev"), FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
                   &server, &client))
        return;

    event = CreateEventW(NULL, TRUE, TRUE, NULL); /* manual reset, SIGNALLED */
    ok(event != NULL, "CreateEventW");
    ok(is_signaled(server), "the server handle is not signalled before any request");

    memset(buffer, 0, sizeof(buffer));
    poison_iosb(&iosb);
    status = NtReadFile(server, event, NULL, &iosb, &iosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_PENDING, "read on an EMPTY async pipe -> %08lx", (unsigned long)status);
    ok(iosb.Status == IOSB_POISON_STATUS, "a pended read wrote its IOSB: %08lx",
       (unsigned long)iosb.Status);
    ok(!is_signaled(event), "the event was not reset when the read was issued");
    ok(!is_signaled(server), "the server handle is still signalled with a read outstanding");

    /* The whole point: this thread is still running, and it is the one that
     * completes the read. */
    status = pipe_write(client, "hello", 5, &writeIosb);
    ok(status == STATUS_SUCCESS, "peer write -> %08lx", (unsigned long)status);

    ok(iosb.Status == STATUS_SUCCESS, "completed read status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 5, "completed read information %llx",
       (unsigned long long)iosb.Information);
    ok(memcmp(buffer, "hello", 5) == 0, "the pended read placed no bytes in the caller's buffer");
    ok(is_signaled(event), "the event was not signalled at completion");
    /* Exactly one of the two: an event was supplied, so the FILE OBJECT is
     * left alone (async_set_result's `else if`). */
    ok(!is_signaled(server), "the handle was signalled although the read carried an event");

    CloseHandle(event);
    NtClose(client);
    NtClose(server);
}

/* Case 2: no event — then the FILE OBJECT is the completion signal, and it is
 * the only one. This is the leg ntdll:pipe:1607-:1617 drives. */
static void test_pended_read_signals_the_handle(void)
{
    IO_STATUS_BLOCK iosb, writeIosb;
    HANDLE server = NULL, client = NULL;
    char buffer[16];
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_rdhnd"), FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
                   &server, &client))
        return;

    ok(is_signaled(server), "the server handle is not signalled before any request");

    memset(buffer, 0, sizeof(buffer));
    poison_iosb(&iosb);
    status = NtReadFile(server, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_PENDING, "read with no event -> %08lx", (unsigned long)status);
    ok(!is_signaled(server), "the handle is still signalled with a read outstanding");
    ok(iosb.Status == IOSB_POISON_STATUS, "a pended read wrote its IOSB: %08lx",
       (unsigned long)iosb.Status);

    status = pipe_write(client, "abcd", 4, &writeIosb);
    ok(status == STATUS_SUCCESS, "peer write -> %08lx", (unsigned long)status);

    ok(is_signaled(server), "the handle was not signalled at completion");
    ok(iosb.Status == STATUS_SUCCESS, "completed read status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 4, "completed read information %llx",
       (unsigned long long)iosb.Information);
    ok(memcmp(buffer, "abcd", 4) == 0, "the pended read placed no bytes in the caller's buffer");

    NtClose(client);
    NtClose(server);
}

/* Case 3: a read that CAN be served does NOT pend — it answers its own final
 * status inline, on the very same asynchronous handle. Pending is permitted
 * and never required (docs/19 §1), so this is the discrimination the caller
 * actually reads: a non-PENDING return means the IOSB is already final. */
static void test_satisfiable_read_completes_inline(void)
{
    IO_STATUS_BLOCK iosb, writeIosb;
    HANDLE server = NULL, client = NULL;
    char buffer[16];
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_rdinl"), FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
                   &server, &client))
        return;

    status = pipe_write(client, "xy", 2, &writeIosb);
    ok(status == STATUS_SUCCESS, "peer write -> %08lx", (unsigned long)status);

    memset(buffer, 0, sizeof(buffer));
    poison_iosb(&iosb);
    status = NtReadFile(server, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_SUCCESS, "read with data available -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "inline read iosb status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 2, "inline read information %llx", (unsigned long long)iosb.Information);
    ok(memcmp(buffer, "xy", 2) == 0, "inline read bytes");

    NtClose(client);
    NtClose(server);
}

/* Case 4: the message-mode short-buffer rule survives the park. A pended read
 * whose buffer cannot hold the message the writer later sends completes with
 * STATUS_BUFFER_OVERFLOW in the IOSB and keeps the tail as the SAME message —
 * the same contract sem_pipe/message_mode.c pins for an inline read, reached
 * through a completion that runs in the writer's call rather than the
 * reader's. */
static void test_pended_read_message_overflow(void)
{
    IO_STATUS_BLOCK iosb, writeIosb;
    HANDLE server = NULL, client = NULL;
    char buffer[16];
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_rdmsg"), FILE_PIPE_TYPE_MESSAGE, FILE_PIPE_MESSAGE_MODE,
                   &server, &client))
        return;

    memset(buffer, 0, sizeof(buffer));
    poison_iosb(&iosb);
    status = NtReadFile(server, NULL, NULL, NULL, &iosb, buffer, 2, NULL, NULL);
    ok(status == STATUS_PENDING, "short read on an empty message pipe -> %08lx",
       (unsigned long)status);

    status = pipe_write(client, "12345678", 8, &writeIosb);
    ok(status == STATUS_SUCCESS, "peer write -> %08lx", (unsigned long)status);

    ok(iosb.Status == STATUS_BUFFER_OVERFLOW, "completed short read status %08lx",
       (unsigned long)iosb.Status);
    ok(iosb.Information == 2, "completed short read information %llx",
       (unsigned long long)iosb.Information);
    ok(memcmp(buffer, "12", 2) == 0, "the pended short read placed no bytes");

    /* The rest of the SAME message is still there. */
    memset(buffer, 0, sizeof(buffer));
    poison_iosb(&iosb);
    status = NtReadFile(server, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_SUCCESS, "read of the message tail -> %08lx", (unsigned long)status);
    ok(iosb.Information == 6, "message tail information %llx",
       (unsigned long long)iosb.Information);
    ok(memcmp(buffer, "345678", 6) == 0, "message tail bytes");

    NtClose(client);
    NtClose(server);
}

/* Case 5: NtCancelIoFile reaches a pended READ, not only a pended listen. The
 * IOSB carries STATUS_CANCELLED and the event fires — a cancelled request is
 * still a completed one, and the caller has nothing else to wait on. */
static void test_cancel_a_pended_read(void)
{
    IO_STATUS_BLOCK iosb, cancelIosb;
    HANDLE server = NULL, client = NULL, event;
    char buffer[16];
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_rdcan"), FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
                   &server, &client))
        return;

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(event != NULL, "CreateEventW");

    poison_iosb(&iosb);
    status = NtReadFile(server, event, NULL, &iosb, &iosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_PENDING, "read -> %08lx", (unsigned long)status);

    poison_iosb(&cancelIosb);
    status = NtCancelIoFile(server, &cancelIosb);
    ok(status == STATUS_SUCCESS, "cancel -> %08lx", (unsigned long)status);

    ok(iosb.Status == STATUS_CANCELLED, "cancelled read status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 0, "cancelled read information %llx",
       (unsigned long long)iosb.Information);
    ok(is_signaled(event), "a cancelled read did not signal the event");

    CloseHandle(event);
    NtClose(client);
    NtClose(server);
}

/* Case 6: the peer CLOSING completes a pended read. Nothing else can — the
 * writer is gone — so a kernel that leaves the request parked hands the
 * caller a wait that never ends. */
static void test_peer_close_completes_a_pended_read(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    char buffer[16];
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_rdclo"), FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
                   &server, &client))
        return;

    poison_iosb(&iosb);
    status = NtReadFile(server, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_PENDING, "read -> %08lx", (unsigned long)status);

    NtClose(client);

    ok(iosb.Status == STATUS_PIPE_BROKEN, "read completed by the peer's close -> %08lx",
       (unsigned long)iosb.Status);
    ok(iosb.Information == 0, "information %llx", (unsigned long long)iosb.Information);
    ok(is_signaled(server), "the handle was not signalled when the peer closed");

    NtClose(server);
}

/* Case 7: two pended reads are served in ISSUE order, and one write satisfies
 * only as many as its bytes reach. The queue is observable — a kernel holding
 * one slot per handle, or serving the newest first, answers this differently. */
static void test_pended_reads_are_served_in_order(void)
{
    IO_STATUS_BLOCK first, second, writeIosb;
    HANDLE server = NULL, client = NULL;
    char firstBuffer[4], secondBuffer[4];
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_rdfifo"), FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
                   &server, &client))
        return;

    memset(firstBuffer, 0, sizeof(firstBuffer));
    memset(secondBuffer, 0, sizeof(secondBuffer));
    poison_iosb(&first);
    poison_iosb(&second);
    status = NtReadFile(server, NULL, NULL, NULL, &first, firstBuffer, 2, NULL, NULL);
    ok(status == STATUS_PENDING, "first read -> %08lx", (unsigned long)status);
    status = NtReadFile(server, NULL, NULL, NULL, &second, secondBuffer, 2, NULL, NULL);
    ok(status == STATUS_PENDING, "second read -> %08lx", (unsigned long)status);

    status = pipe_write(client, "AB", 2, &writeIosb);
    ok(status == STATUS_SUCCESS, "peer write -> %08lx", (unsigned long)status);

    ok(first.Status == STATUS_SUCCESS, "first read status %08lx", (unsigned long)first.Status);
    ok(first.Information == 2, "first read information %llx",
       (unsigned long long)first.Information);
    ok(memcmp(firstBuffer, "AB", 2) == 0, "the first read took the bytes");
    ok(second.Status == IOSB_POISON_STATUS, "the second read completed out of order: %08lx",
       (unsigned long)second.Status);

    status = pipe_write(client, "CD", 2, &writeIosb);
    ok(status == STATUS_SUCCESS, "second peer write -> %08lx", (unsigned long)status);
    ok(second.Status == STATUS_SUCCESS, "second read status %08lx", (unsigned long)second.Status);
    ok(second.Information == 2, "second read information %llx",
       (unsigned long long)second.Information);
    ok(memcmp(secondBuffer, "CD", 2) == 0, "the second read took the later bytes");

    NtClose(client);
    NtClose(server);
}

/* Case 8: FILE_PIPE_COMPLETE_OPERATION (PIPE_NOWAIT) refuses instead of
 * pending, even on an asynchronous handle. The completion mode is a property
 * of the END and it is checked before the handle's synchronicity, so an
 * implementation that keys the pend on the handle alone answers PENDING here
 * and never completes. */
static void test_nowait_mode_refuses_rather_than_pends(void)
{
    SEM_FILE_PIPE_INFORMATION mode;
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    char buffer[16];
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_rdnw"), FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
                   &server, &client))
        return;

    mode.ReadMode = FILE_PIPE_BYTE_STREAM_MODE;
    mode.CompletionMode = FILE_PIPE_COMPLETE_OPERATION;
    status = NtSetInformationFile(server, &iosb, &mode, sizeof(mode), FilePipeInformation);
    ok(status == STATUS_SUCCESS, "set nowait -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    status = NtReadFile(server, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_PIPE_EMPTY, "nowait read on an empty pipe -> %08lx", (unsigned long)status);

    NtClose(client);
    NtClose(server);
}

/* Case 9: a write on the SAME handle does not touch a read parked on it.
 * The two directions are independent, so this pins the boundary between
 * them — and it is the case a queue keyed on the HANDLE rather than on the
 * pipe END would get wrong by completing the read with the writer's bytes.
 *
 * The last assertion used to be the ONE divergence this item accepted, and
 * it is a plain assertion now. NT re-signals the FILE OBJECT on ANY
 * completion (it counts no outstanding requests — `async_set_result`'s
 * `else if (async->fd) set_fd_signaled( async->fd, 1 )`), and proskrnl did
 * not, because condrv borrows the file object as its own readiness signal
 * and a completion-side re-signal spins conhost's poll loop. The borrowing
 * is now DECLARED (io.h deviceManagedSignal) instead of paid for by every
 * other device, so the write below takes the ordinary blocking-request
 * completion path and puts the handle back up with the read still parked —
 * which is exactly what ntdll:pipe:1678 asks for. The todo_proskrnl tag
 * reported "unexpectedly passed" the moment that landed, which is the whole
 * reason it was a tag rather than a dropped case. */
static void test_a_write_does_not_disturb_a_parked_read(void)
{
    IO_STATUS_BLOCK readIosb, writeIosb;
    HANDLE server = NULL, client = NULL;
    char buffer[16];
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_rdinls"), FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
                   &server, &client))
        return;

    poison_iosb(&readIosb);
    status = NtReadFile(server, NULL, NULL, NULL, &readIosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_PENDING, "read -> %08lx", (unsigned long)status);
    ok(!is_signaled(server), "the handle is still signalled with a read outstanding");

    /* The other DIRECTION, so this write cannot satisfy the read above. */
    poison_iosb(&writeIosb);
    status = pipe_write(server, "z", 1, &writeIosb);
    ok(status == STATUS_SUCCESS, "write on the same handle -> %08lx", (unsigned long)status);
    ok(writeIosb.Information == 1, "write information %llx",
       (unsigned long long)writeIosb.Information);
    ok(readIosb.Status == IOSB_POISON_STATUS, "the parked read was completed by the write: %08lx",
       (unsigned long)readIosb.Status);
    ok(is_signaled(server), "an inline completion did not re-signal the handle");

    NtClose(client);
    NtClose(server);
}

/* Case 10: FILE_SKIP_SET_EVENT_ON_HANDLE FREEZES the handle's signalled
 * state — in both directions and forever, which is more than its name says.
 *
 * The oracle puts the guard inside the transition itself (`set_fd_signaled`
 * returns immediately when the bit is set, server/fd.c) and clears the
 * handle BEFORE recording the bit (`set_fd_completion_mode`). So the order
 * is the content: the one clear that ever happens is the one at set time,
 * and every later completion — pended or inline — leaves the handle alone.
 * A caller's own EVENT is untouched by any of it. ntdll:pipe drives the
 * whole rule at pipe.c:1680-:1702.
 *
 * The two "did not re-signal" assertions below are weaker on proskrnl than
 * they look, and the comment says so rather than letting a green run imply
 * more: nothing re-signals a file object on an inline completion there at
 * all (case 9), so those two pass whether or not the freeze works. What
 * carries the case is the CLEAR at set time, which nothing else does. */
static void test_skip_set_event_on_handle_freezes_it(void)
{
    SEM_FILE_IO_COMPLETION_NOTIFICATION_INFORMATION modes;
    IO_STATUS_BLOCK iosb, writeIosb;
    HANDLE server = NULL, client = NULL;
    char buffer[16];
    NTSTATUS status;

    if (!make_pair(W("\\??\\pipe\\prstest_rdfrz"), FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
                   &server, &client))
        return;

    ok(is_signaled(server), "the handle is not signalled before any request");

    modes.Flags = FILE_SKIP_SET_EVENT_ON_HANDLE;
    status = NtSetInformationFile(server, &iosb, &modes, sizeof(modes),
                                  FileIoCompletionNotificationInformation);
    ok(status == STATUS_SUCCESS, "set skip-event -> %08lx", (unsigned long)status);
    /* The set itself is what takes the handle down, once. */
    ok(!is_signaled(server), "setting the flag did not clear the handle");

    /* An inline completion does not put it back. */
    status = pipe_write(server, "z", 1, &writeIosb);
    ok(status == STATUS_SUCCESS, "write -> %08lx", (unsigned long)status);
    ok(!is_signaled(server), "an inline completion re-signalled a frozen handle");

    /* Nor does a pended one — and the read still completes normally. */
    poison_iosb(&iosb);
    status = NtReadFile(server, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_PENDING, "read -> %08lx", (unsigned long)status);
    status = pipe_write(client, "wx", 2, &writeIosb);
    ok(status == STATUS_SUCCESS, "peer write -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "completed read status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 2, "completed read information %llx",
       (unsigned long long)iosb.Information);
    ok(!is_signaled(server), "a pended completion re-signalled a frozen handle");

    NtClose(client);
    NtClose(server);
}

START_TEST(pended_read)
{
    test_pended_read_with_event();
    test_pended_read_signals_the_handle();
    test_satisfiable_read_completes_inline();
    test_pended_read_message_overflow();
    test_cancel_a_pended_read();
    test_peer_close_completes_a_pended_read();
    test_pended_reads_are_served_in_order();
    test_nowait_mode_refuses_rather_than_pends();
    test_a_write_does_not_disturb_a_parked_read();
    test_skip_set_event_on_handle_freezes_it();
}
