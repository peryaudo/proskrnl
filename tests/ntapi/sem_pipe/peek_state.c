/*
 * sem_pipe/peek_state.c — FSCTL_PIPE_PEEK's STATE LADDER, and the axis its
 * STATUS_BUFFER_OVERFLOW is keyed on.
 *
 * docs/21 W11, the peek cluster in ntdll:pipe (dlls/ntdll/tests/pipe.c
 * test_pipe_state :2055, test_pipe_with_data_state :2205, read_pipe_test
 * :1197/:1199).
 *
 * The whole verb is server/named_pipe.c pipe_end_peek, and the four things
 * this file measures are the four an implementation that "reports what is
 * buffered" gets wrong:
 *
 *   - THE LENGTH FLOOR IS FIRST, above the state:
 *
 *         if (reply_size < offsetof( FILE_PIPE_PEEK_BUFFER, Data ))
 *             { set_error( STATUS_INFO_LENGTH_MISMATCH ); return; }
 *
 *     so a too-short buffer on a LISTENING pipe reports the LENGTH, not the
 *     state. §2.
 *
 *   - THE STATE LADDER HAS FOUR ARMS AND THE CLOSING ONE ASKS ABOUT DATA:
 *
 *         case FILE_PIPE_CONNECTED_STATE: break;
 *         case FILE_PIPE_CLOSING_STATE:
 *             if (!list_empty( &pipe_end->message_queue )) break;
 *             set_error( STATUS_PIPE_BROKEN ); return;
 *         default:
 *             set_error( pipe_end->pipe ? STATUS_INVALID_PIPE_STATE
 *                                       : STATUS_PIPE_DISCONNECTED ); return;
 *
 *     Two of those are not guessable. A peer that closed with bytes still
 *     buffered is PEEKABLE — CLOSING is not "broken" until the queue runs
 *     out — and §1 measures both halves through ONE handle, draining it
 *     between the two so nothing but the queue moved. And a DISCONNECTED
 *     SERVER answers STATUS_INVALID_PIPE_STATE, not the
 *     STATUS_PIPE_DISCONNECTED its own client gets: `pipe_end->pipe` is the
 *     named pipe this end still holds, and FSCTL_PIPE_DISCONNECT drops it
 *     for the CLIENT only (the arm in pipe_server_ioctl:
 *     `release_object( ...connection->pipe ); ...connection->pipe = NULL`).
 *     An implementation that reads the INSTANCE's state answers
 *     "disconnected" at both ends and fails at exactly one of them.
 *
 *   - THE OVERFLOW IS THE PIPE'S TYPE, NOT THE END'S READ MODE:
 *
 *         if (avail && pipe_end->pipe->message_mode) { message_length = ...;
 *             reply_size = min( reply_size, message_length ); }
 *         ...
 *         if (message_length > reply_size) set_error( STATUS_BUFFER_OVERFLOW );
 *
 *     `message_mode` is the pipe's FILE_PIPE_TYPE_MESSAGE, decided at
 *     create; the end's FILE_PIPE_*_MODE read mode does not appear in this
 *     function at all. §3 peeks a MESSAGE-type pipe through an end in BYTE
 *     read mode, which is what read_pipe_test does — and it is also why the
 *     reply STOPS at the first message even when the caller's buffer would
 *     hold two. A byte-type pipe never overflows however much it leaves
 *     behind (sem_pipe/byte_mode.c pins that side; here it is the
 *     MessageLength zero beside it).
 *
 *   - AND THE OVERFLOW IS ABOUT THE FIRST MESSAGE, NOT ABOUT `avail`. With
 *     two messages queued and room for both, the answer is SUCCESS carrying
 *     ONE message; with room for none of the first it is an overflow even
 *     though the fixed part fitted.
 *
 * NumberOfMessages is a literal 0 in every reply, under a FIXME of the
 * oracle's own — pinned rather than left open because the oracle is the spec
 * wherever it answers at all (Art. 6), the same trade
 * FileStandardInformation's DeletePending records in
 * sem_pipe/pipe_file_info.c. Nothing on the boundary reads it: PeekNamedPipe
 * hands back MessageLength and drops this field.
 */
#include "util.h"

/* Distinct quotas so a swapped field cannot pass, and a distinct name per
 * sub-case so one leaked instance cannot make a later create fail as
 * INSTANCE_NOT_AVAILABLE and blame the wrong rule (create_refusals.c). */
#define IN_QUOTA  512
#define OUT_QUOTA 256

#define PEEK_FIXED ((ULONG) __builtin_offsetof(SEM_FILE_PIPE_PEEK_BUFFER, Data))

static unsigned short NameBuffer[64];
static const void *pipe_name(unsigned index)
{
    static const unsigned short base[] = {'\\', '?', '?', '\\', 'p', 'i', 'p', 'e',
                                          '\\', 'p', 'r', 's',  't', 'e', 's', 't',
                                          '_',  'p', 'e', 'e',  'k', '_', 0};
    unsigned i = 0;
    while (base[i] != 0)
    {
        NameBuffer[i] = base[i];
        i++;
    }
    NameBuffer[i++] = (unsigned short)('a' + (index / 10));
    NameBuffer[i++] = (unsigned short)('0' + (index % 10));
    NameBuffer[i] = 0;
    return NameBuffer;
}

static NTSTATUS create_server(HANDLE *handle, const void *wideName, ULONG type, ULONG readMode,
                              IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    LARGE_INTEGER timeout;

    init_ustr(&name, wideName);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    timeout.QuadPart = -100 * 10000; /* 100 ms, relative */
    *handle = NULL;
    return NtCreateNamedPipeFile(handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr, iosb,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE,
                                 FILE_SYNCHRONOUS_IO_NONALERT, type, readMode,
                                 FILE_PIPE_QUEUE_OPERATION, 1, IN_QUOTA, OUT_QUOTA, &timeout);
}

/* One peek into `reply`, asking for `dataCapacity` bytes of payload on top of
 * the fixed part. The reply buffer is poisoned first so an untouched field
 * cannot read as a zero somebody wrote. */
static NTSTATUS peek(HANDLE handle, void *reply, ULONG replyLength, IO_STATUS_BLOCK *iosb)
{
    memset(reply, 0xcc, replyLength);
    poison_iosb(iosb);
    return NtFsControlFile(handle, NULL, NULL, NULL, iosb, FSCTL_PIPE_PEEK, NULL, 0, reply,
                           replyLength);
}

/* §1 — the state ladder, on a BYTE-type pipe so no arm of it can be reached
 * or missed through the overflow rule §3 is about. */
static void test_state_ladder(void)
{
    unsigned char reply[64];
    SEM_FILE_PIPE_PEEK_BUFFER *view = (SEM_FILE_PIPE_PEEK_BUFFER *)reply;
    unsigned char drain[64];
    HANDLE server = NULL, client = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    status = create_server(&server, pipe_name(0), FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
                           &iosb);
    ok(status == STATUS_SUCCESS, "listening server -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* LISTENING: no connection, so nothing to peek — and the pipe is still
     * this end's, so it is a STATE complaint rather than a disconnection. */
    status = peek(server, reply, sizeof(reply), &iosb);
    ok(status == STATUS_INVALID_PIPE_STATE, "peek while listening -> %08lx", (unsigned long)status);

    status = open_pipe_client(&client, pipe_name(0), &iosb);
    ok(status == STATUS_SUCCESS, "client open -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    /* CONNECTED and empty: a success that carries the fixed part alone. */
    status = peek(server, reply, sizeof(reply), &iosb);
    ok(status == STATUS_SUCCESS, "peek while connected -> %08lx", (unsigned long)status);
    ok(iosb.Status == status, "connected peek iosb.Status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == PEEK_FIXED, "connected peek information %llu",
       (unsigned long long)iosb.Information);
    ok(view->NamedPipeState == FILE_PIPE_CONNECTED_STATE, "connected peek state %lu",
       (unsigned long)view->NamedPipeState);
    ok(view->ReadDataAvailable == 0, "connected peek avail %lu",
       (unsigned long)view->ReadDataAvailable);
    ok(view->MessageLength == 0, "connected peek message length %lu",
       (unsigned long)view->MessageLength);

    status = peek(client, reply, sizeof(reply), &iosb);
    ok(status == STATUS_SUCCESS, "client peek while connected -> %08lx", (unsigned long)status);
    ok(view->NamedPipeState == FILE_PIPE_CONNECTED_STATE, "client peek state %lu",
       (unsigned long)view->NamedPipeState);

    status = pipe_write(client, "abcdefgh", 8, &iosb);
    ok(status == STATUS_SUCCESS, "seed the pipe -> %08lx", (unsigned long)status);

    /* The peer CLOSES with those eight bytes still queued. CLOSING is not
     * broken while there is something to read: the same handle answers
     * SUCCESS now and STATUS_PIPE_BROKEN below, with nothing between them
     * but the read that empties the queue. */
    NtClose(client);
    client = NULL;

    status = peek(server, reply, sizeof(reply), &iosb);
    ok(status == STATUS_SUCCESS, "peek while closing with data -> %08lx", (unsigned long)status);
    ok(view->NamedPipeState == FILE_PIPE_CLOSING_STATE, "closing peek state %lu",
       (unsigned long)view->NamedPipeState);
    ok(view->ReadDataAvailable == 8, "closing peek avail %lu",
       (unsigned long)view->ReadDataAvailable);
    ok(iosb.Information == PEEK_FIXED + 8, "closing peek information %llu",
       (unsigned long long)iosb.Information);

    status = pipe_read(server, drain, sizeof(drain), &iosb);
    ok(status == STATUS_SUCCESS, "drain the closing pipe -> %08lx", (unsigned long)status);
    ok(iosb.Information == 8, "drained %llu", (unsigned long long)iosb.Information);

    status = peek(server, reply, sizeof(reply), &iosb);
    ok(status == STATUS_PIPE_BROKEN, "peek while closing and empty -> %08lx",
       (unsigned long)status);

    NtClose(server);
}

/* §1b — DISCONNECT splits the two ends: the server keeps the pipe and
 * complains about the STATE, its client lost it and is DISCONNECTED. */
static void test_disconnect_splits_the_ends(void)
{
    unsigned char reply[64];
    HANDLE server = NULL, client = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    status = create_server(&server, pipe_name(1), FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
                           &iosb);
    ok(status == STATUS_SUCCESS, "disconnect server -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, pipe_name(1), &iosb);
    ok(status == STATUS_SUCCESS, "disconnect client -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    poison_iosb(&iosb);
    status = pipe_fsctl(server, FSCTL_PIPE_DISCONNECT, &iosb);
    ok(status == STATUS_SUCCESS, "disconnect -> %08lx", (unsigned long)status);

    status = peek(server, reply, sizeof(reply), &iosb);
    ok(status == STATUS_INVALID_PIPE_STATE, "peek on the disconnecting SERVER -> %08lx",
       (unsigned long)status);

    status = peek(client, reply, sizeof(reply), &iosb);
    ok(status == STATUS_PIPE_DISCONNECTED, "peek on the disconnected CLIENT -> %08lx",
       (unsigned long)status);

    NtClose(client);
    NtClose(server);
}

/* §2 — the length floor is decided above the state. */
static void test_length_floor(void)
{
    unsigned char reply[64];
    HANDLE server = NULL, client = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    status = create_server(&server, pipe_name(2), FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
                           &iosb);
    ok(status == STATUS_SUCCESS, "length-floor server -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* LISTENING would be STATUS_INVALID_PIPE_STATE with room for the reply;
     * with four bytes it is the length that is reported. */
    status = peek(server, reply, 4, &iosb);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short peek while listening -> %08lx",
       (unsigned long)status);
    status = peek(server, reply, 0, &iosb);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "zero-length peek while listening -> %08lx",
       (unsigned long)status);

    status = open_pipe_client(&client, pipe_name(2), &iosb);
    ok(status == STATUS_SUCCESS, "length-floor client -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    /* Exactly the fixed part is enough: the floor is the header, not a
     * byte of payload. */
    status = peek(server, reply, PEEK_FIXED, &iosb);
    ok(status == STATUS_SUCCESS, "peek with room for the header alone -> %08lx",
       (unsigned long)status);
    ok(iosb.Information == PEEK_FIXED, "header-only peek information %llu",
       (unsigned long long)iosb.Information);

    NtClose(client);
    NtClose(server);
}

/* §3 — the overflow axis: the PIPE's type, and the FIRST message. */
static void test_message_overflow(void)
{
    unsigned char reply[64];
    SEM_FILE_PIPE_PEEK_BUFFER *view = (SEM_FILE_PIPE_PEEK_BUFFER *)reply;
    HANDLE server = NULL, client = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    /* A MESSAGE-type pipe read through an end in BYTE read mode — the shape
     * read_pipe_test uses, and the one that separates the two axes. */
    status = create_server(&server, pipe_name(3), FILE_PIPE_TYPE_MESSAGE,
                           FILE_PIPE_BYTE_STREAM_MODE, &iosb);
    ok(status == STATUS_SUCCESS, "message-type server -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, pipe_name(3), &iosb);
    ok(status == STATUS_SUCCESS, "message-type client -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    status = pipe_write(client, "0123456789", 10, &iosb);
    ok(status == STATUS_SUCCESS, "first message -> %08lx", (unsigned long)status);

    /* Room for four of the ten: a TRUNCATED message overflows, whatever the
     * reading end's mode is. */
    status = peek(server, reply, PEEK_FIXED + 4, &iosb);
    ok(status == STATUS_BUFFER_OVERFLOW, "truncated message peek -> %08lx", (unsigned long)status);
    ok(iosb.Information == PEEK_FIXED + 4, "truncated peek information %llu",
       (unsigned long long)iosb.Information);
    ok(view->ReadDataAvailable == 10, "truncated peek avail %lu",
       (unsigned long)view->ReadDataAvailable);
    ok(view->MessageLength == 10, "truncated peek message length %lu",
       (unsigned long)view->MessageLength);

    /* Room for the header alone, with a message queued, is the same
     * complaint: the fixed part fitting is not the question. */
    status = peek(server, reply, PEEK_FIXED, &iosb);
    ok(status == STATUS_BUFFER_OVERFLOW, "header-only peek with a message queued -> %08lx",
       (unsigned long)status);
    ok(iosb.Information == PEEK_FIXED, "header-only overflow information %llu",
       (unsigned long long)iosb.Information);

    /* Room for all ten: no overflow. */
    status = peek(server, reply, PEEK_FIXED + 16, &iosb);
    ok(status == STATUS_SUCCESS, "whole message peek -> %08lx", (unsigned long)status);
    ok(iosb.Information == PEEK_FIXED + 10, "whole message information %llu",
       (unsigned long long)iosb.Information);

    /* A SECOND message, and room for both: the reply still stops at the
     * first. An implementation that copies across the queue up to the
     * caller's capacity — which is right for a byte pipe — answers 20 here. */
    status = pipe_write(client, "abcdefghij", 10, &iosb);
    ok(status == STATUS_SUCCESS, "second message -> %08lx", (unsigned long)status);

    status = peek(server, reply, PEEK_FIXED + 32, &iosb);
    ok(status == STATUS_SUCCESS, "two-message peek -> %08lx", (unsigned long)status);
    ok(iosb.Information == PEEK_FIXED + 10, "two-message information %llu",
       (unsigned long long)iosb.Information);
    ok(view->ReadDataAvailable == 20, "two-message avail %lu",
       (unsigned long)view->ReadDataAvailable);
    ok(view->MessageLength == 10, "two-message message length %lu",
       (unsigned long)view->MessageLength);
    /* Two messages queued is where a real count would show. */
    ok(view->NumberOfMessages == 0, "two-message message count %lu",
       (unsigned long)view->NumberOfMessages);

    NtClose(client);
    NtClose(server);
}

/* §3b — the byte-type half of the same axis. byte_mode.c pins the status;
 * what belongs here is the MessageLength beside it, which is what says the
 * kernel never framed a message it was not asked to. */
static void test_byte_type_never_overflows(void)
{
    unsigned char reply[64];
    SEM_FILE_PIPE_PEEK_BUFFER *view = (SEM_FILE_PIPE_PEEK_BUFFER *)reply;
    HANDLE server = NULL, client = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    status = create_server(&server, pipe_name(4), FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
                           &iosb);
    ok(status == STATUS_SUCCESS, "byte-type server -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, pipe_name(4), &iosb);
    ok(status == STATUS_SUCCESS, "byte-type client -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    status = pipe_write(client, "01234567", 8, &iosb);
    ok(status == STATUS_SUCCESS, "byte-type seed -> %08lx", (unsigned long)status);

    status = peek(server, reply, PEEK_FIXED + 4, &iosb);
    ok(status == STATUS_SUCCESS, "short peek on a byte pipe -> %08lx", (unsigned long)status);
    ok(iosb.Information == PEEK_FIXED + 4, "byte-type peek information %llu",
       (unsigned long long)iosb.Information);
    ok(view->ReadDataAvailable == 8, "byte-type peek avail %lu",
       (unsigned long)view->ReadDataAvailable);
    ok(view->MessageLength == 0, "byte-type peek message length %lu",
       (unsigned long)view->MessageLength);

    NtClose(client);
    NtClose(server);
}

/* §4 — a CLIENT that outlived its server still knows its pipe's TYPE.
 *
 * The oracle's client holds its own reference to the named pipe until it is
 * destroyed (server/named_pipe.c pipe_end_destroy's `if (pipe_end->pipe)
 * release_object`), so the message-type overflow rule survives the server's
 * close. proskrnl drops NPFS_INSTANCE.pipe when the SERVER's handle goes —
 * the same older lifetime gap sem_pipe/pipe_file_info.c tags on
 * AllocationSize, and the only one of ntdll:pipe's peek assertions this
 * file's rules cannot reach (docs/03 "A pipe end's own file information").
 */
static void test_closing_client_keeps_the_type(void)
{
    unsigned char reply[64];
    SEM_FILE_PIPE_PEEK_BUFFER *view = (SEM_FILE_PIPE_PEEK_BUFFER *)reply;
    HANDLE server = NULL, client = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    status = create_server(&server, pipe_name(5), FILE_PIPE_TYPE_MESSAGE,
                           FILE_PIPE_BYTE_STREAM_MODE, &iosb);
    ok(status == STATUS_SUCCESS, "closing-client server -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, pipe_name(5), &iosb);
    ok(status == STATUS_SUCCESS, "closing-client client -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    status = pipe_write(server, "0123456789", 10, &iosb);
    ok(status == STATUS_SUCCESS, "server message -> %08lx", (unsigned long)status);
    NtClose(server);
    server = NULL;

    /* CLOSING with data: the ladder lets it through at both runners. What
     * only the oracle still knows is that the pipe was message-type. */
    status = peek(client, reply, PEEK_FIXED + 4, &iosb);
    ok(view->NamedPipeState == FILE_PIPE_CLOSING_STATE, "closing-client peek state %lu",
       (unsigned long)view->NamedPipeState);
    ok(view->ReadDataAvailable == 10, "closing-client peek avail %lu",
       (unsigned long)view->ReadDataAvailable);
    todo_proskrnl
    {
        ok(status == STATUS_BUFFER_OVERFLOW, "closing-client truncated peek -> %08lx",
           (unsigned long)status);
        ok(view->MessageLength == 10, "closing-client peek message length %lu",
           (unsigned long)view->MessageLength);
    }

    NtClose(client);
}

START_TEST(peek_state)
{
    test_state_ladder();
    test_disconnect_splits_the_ends();
    test_length_floor();
    test_message_overflow();
    test_byte_type_never_overflows();
    test_closing_client_keeps_the_type();
}
