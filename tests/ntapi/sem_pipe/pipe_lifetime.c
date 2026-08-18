/*
 * sem_pipe/pipe_lifetime.c — how long a pipe's FACTS outlive its NAME, and
 * which end owns which.
 *
 * docs/21 W11, the test_pipe_local_info cluster in ntdll:pipe
 * (dlls/ntdll/tests/pipe.c :2356/:2357/:2359/:2366/:2369) and the last
 * assertion of test_pipe_with_data_state (:2205, `in client state 4`).
 *
 * The oracle keeps the two questions apart, and every case below is about a
 * pair that an implementation with ONE lifetime gets wrong:
 *
 *   - EVERY END HOLDS ITS OWN REFERENCE to the named pipe
 *     (server/named_pipe.c init_pipe_end: `pipe_end->pipe =
 *     (struct named_pipe *)grab_object( pipe )`, released in
 *     pipe_end_destroy). So a CLIENT that outlives its server still describes
 *     the pipe it belongs to — its type, its configuration, its instance
 *     limit and its two quotas — because the object is still there.
 *   - THE NAME GOES WITH THE LAST INSTANCE, not with the object.
 *     pipe_server_destroy is `if (!--pipe->instances) unlink_named_object(
 *     &pipe->obj )`, and an unlinked object has no name: get_object_name
 *     answers NULL, which is the second disjunct of the FileNameInformation
 *     arm's `if (!pipe || !(name = get_object_name( &pipe->obj, &name_len )))
 *     { set_error( STATUS_PIPE_DISCONNECTED ); return; }`. So the SAME handle
 *     that still reports the quotas refuses to report the name.
 *   - THE COUNT IS THE INSTANCES', not the references'. `CurrentInstances =
 *     pipe->instances` reads 0 through a client whose only server has gone,
 *     while the five fields beside it read the pipe's real values — §1 asks
 *     for both in one query because an implementation that keyed all six on
 *     one liveness bit answers all six the same way.
 *   - A DISCONNECT IS NOT A CLOSE. FSCTL_PIPE_DISCONNECT drops the CLIENT's
 *     reference outright (`release_object( server->pipe_end.connection->pipe
 *     ); server->pipe_end.connection->pipe = NULL`), and then every arm of
 *     pipe_end_get_file_info refuses that end with STATUS_PIPE_DISCONNECTED.
 *     §4 puts the two endings side by side on the same handle shape: the
 *     server merely closing leaves the client describing the pipe, the server
 *     disconnecting leaves it describing nothing.
 *
 * §3 is the case no failing winetest assertion asks for and the one that
 * decides the implementation's shape: with a SECOND instance still open, the
 * name does NOT leave the namespace when the first server closes, and the
 * client of that first instance reports CurrentInstances 1 and its own name.
 * An implementation that unlinked on "a server end closed" rather than on
 * "the instance count reached zero" passes every other case here.
 */
#include "util.h"

/* Distinct from 4096 in both directions, and from each other: AllocationSize
 * is the SUM, so equal quotas would let a swapped field pass and a round
 * number would let a hardwired one. */
#define IN_QUOTA  100
#define OUT_QUOTA 200

#define PEEK_FIXED ((ULONG) __builtin_offsetof(SEM_FILE_PIPE_PEEK_BUFFER, Data))

/* A distinct pipe name per sub-case — one leaked instance turns a later
 * create into INSTANCE_NOT_AVAILABLE and the failure names the wrong rule. */
static unsigned short NameBuffer[64];
static const void *pipe_name(unsigned index)
{
    static const unsigned short base[] = {'\\', '?', '?', '\\', 'p', 'i', 'p', 'e',
                                          '\\', 'p', 'r', 's',  't', 'e', 's', 't',
                                          '_',  'l', 'i', 'f',  'e', '_', 0};
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

static NTSTATUS create_server(HANDLE *handle, const void *wideName, ULONG type, ULONG maxInstances,
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
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                                 FILE_SYNCHRONOUS_IO_NONALERT, type, FILE_PIPE_BYTE_STREAM_MODE,
                                 FILE_PIPE_QUEUE_OPERATION, maxInstances, IN_QUOTA, OUT_QUOTA,
                                 &timeout);
}

/* FileNameInformation's answer is discarded — this file asks it only for its
 * STATUS, which is where it parts from the class beside it. */
static NTSTATUS query_name(HANDLE handle)
{
    IO_STATUS_BLOCK iosb;
    unsigned char buffer[128];

    memset(buffer, 0xcc, sizeof(buffer));
    poison_iosb(&iosb);
    return NtQueryInformationFile(handle, &iosb, buffer, sizeof(buffer), FileNameInformation);
}

static NTSTATUS query_standard(HANDLE handle, FILE_STANDARD_INFORMATION *info)
{
    IO_STATUS_BLOCK iosb;

    memset(info, 0xcc, sizeof(*info));
    poison_iosb(&iosb);
    return NtQueryInformationFile(handle, &iosb, info, sizeof(*info), FileStandardInformation);
}

static NTSTATUS peek(HANDLE handle, void *reply, ULONG replyLength, IO_STATUS_BLOCK *iosb)
{
    memset(reply, 0xcc, replyLength);
    poison_iosb(iosb);
    return NtFsControlFile(handle, NULL, NULL, NULL, iosb, FSCTL_PIPE_PEEK, NULL, 0, reply,
                           replyLength);
}

/* §1 — a CLIENT whose server merely CLOSED still describes the pipe.
 *
 * Six fields in one query, five of them the pipe's own and the sixth the
 * instance count that really did fall to zero. The message-type peek is the
 * same fact asked through a different verb: the overflow rule reads
 * `pipe_end->pipe->message_mode`, so an end that lost its pipe answers a byte
 * pipe's STATUS_SUCCESS where a message pipe owes STATUS_BUFFER_OVERFLOW. */
static void test_client_outlives_its_server(void)
{
    IO_STATUS_BLOCK iosb;
    FILE_PIPE_LOCAL_INFORMATION local;
    FILE_STANDARD_INFORMATION std;
    unsigned char reply[64];
    SEM_FILE_PIPE_PEEK_BUFFER *view = (SEM_FILE_PIPE_PEEK_BUFFER *)reply;
    HANDLE server = NULL, client = NULL;
    NTSTATUS status;

    status = create_server(&server, pipe_name(0), FILE_PIPE_TYPE_MESSAGE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, pipe_name(0), &iosb);
    ok(status == STATUS_SUCCESS, "client open -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    status = pipe_write(server, "0123456789", 10, &iosb);
    ok(status == STATUS_SUCCESS, "server message -> %08lx", (unsigned long)status);
    NtClose(server);
    server = NULL;

    status = query_pipe_local(client, &local);
    ok(status == STATUS_SUCCESS, "closing-client local info -> %08lx", (unsigned long)status);
    ok(local.NamedPipeType == FILE_PIPE_TYPE_MESSAGE, "closing-client NamedPipeType %lu",
       (unsigned long)local.NamedPipeType);
    ok(local.NamedPipeConfiguration == FILE_PIPE_FULL_DUPLEX,
       "closing-client NamedPipeConfiguration %lu", (unsigned long)local.NamedPipeConfiguration);
    ok(local.MaximumInstances == 1, "closing-client MaximumInstances %lu",
       (unsigned long)local.MaximumInstances);
    /* The one field that DID move: the instance is gone, and the object it
     * belonged to is not. */
    ok(local.CurrentInstances == 0, "closing-client CurrentInstances %lu",
       (unsigned long)local.CurrentInstances);
    ok(local.InboundQuota == IN_QUOTA, "closing-client InboundQuota %lu",
       (unsigned long)local.InboundQuota);
    ok(local.OutboundQuota == OUT_QUOTA, "closing-client OutboundQuota %lu",
       (unsigned long)local.OutboundQuota);
    ok(local.NamedPipeState == FILE_PIPE_CLOSING_STATE, "closing-client NamedPipeState %lu",
       (unsigned long)local.NamedPipeState);
    ok(local.NamedPipeEnd == FILE_PIPE_CLIENT_END, "closing-client NamedPipeEnd %lu",
       (unsigned long)local.NamedPipeEnd);

    /* AllocationSize is the pipe's pair of quotas, so it is the same fact one
     * class over — and it is 0 for an end that forgot its pipe. */
    status = query_standard(client, &std);
    ok(status == STATUS_SUCCESS, "closing-client standard info -> %08lx", (unsigned long)status);
    ok(std.AllocationSize.QuadPart == (LONGLONG)(IN_QUOTA + OUT_QUOTA),
       "closing-client AllocationSize %llu", (unsigned long long)std.AllocationSize.QuadPart);
    ok(std.EndOfFile.QuadPart == 10, "closing-client EndOfFile %llu",
       (unsigned long long)std.EndOfFile.QuadPart);

    /* And the pipe's TYPE, asked through the peek ladder: 4 bytes of room for
     * a 10-byte message on a MESSAGE-type pipe. */
    status = peek(client, reply, PEEK_FIXED + 4, &iosb);
    ok(status == STATUS_BUFFER_OVERFLOW, "closing-client truncated peek -> %08lx",
       (unsigned long)status);
    ok(view->NamedPipeState == FILE_PIPE_CLOSING_STATE, "closing-client peek state %lu",
       (unsigned long)view->NamedPipeState);
    ok(view->ReadDataAvailable == 10, "closing-client peek avail %lu",
       (unsigned long)view->ReadDataAvailable);
    ok(view->MessageLength == 10, "closing-client peek message length %lu",
       (unsigned long)view->MessageLength);

    NtClose(client);
}

/* §2 — the NAME left with the last instance, and the facts did not.
 *
 * Three ways of asking, on the same pipe, in the same state: the handle that
 * still reports the quotas refuses to report the name; a client open by that
 * name finds nothing; and a CREATE of that name mints a brand-new pipe, which
 * the surviving client is not part of. The last one is what separates "the
 * object is still referenced" from "the object is still findable" — an
 * implementation that merely stopped freeing the pipe would hand the new
 * client the old one. */
static void test_the_name_goes_with_the_last_instance(void)
{
    IO_STATUS_BLOCK iosb;
    FILE_PIPE_LOCAL_INFORMATION local, fresh;
    HANDLE server = NULL, client = NULL, stranger = NULL, reborn = NULL;
    NTSTATUS status;

    status = create_server(&server, pipe_name(1), FILE_PIPE_TYPE_BYTE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "named-pipe server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, pipe_name(1), &iosb);
    ok(status == STATUS_SUCCESS, "named-pipe client open -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    /* Connected, the name is there through this very handle. */
    status = query_name(client);
    ok(status == STATUS_SUCCESS, "connected client name -> %08lx", (unsigned long)status);

    NtClose(server);
    server = NULL;

    /* The one assertion in this file that is a TRADE rather than a rule. The
     * oracle refuses under a FIXME of its own — "We should be able to return
     * on unlinked pipe", server/named_pipe.c above that guard — and
     * ntdll:pipe:2185 wraps the STATUS_SUCCESS assertion in todo_wine_if
     * because real NT reports the name. Pinned to the oracle anyway: where the
     * oracle answers it is the spec (Art. 6, the same call docs/03 makes for
     * DeletePending), and the other answer is un-pinnable — no G5 case can be
     * oracle-green on it, and beyond_oracle is barred for behaviour Wine DOES
     * implement. docs/03 carries the trade. */
    status = query_name(client);
    ok(status == STATUS_PIPE_DISCONNECTED, "unlinked client name -> %08lx", (unsigned long)status);
    status = query_pipe_local(client, &local);
    ok(status == STATUS_SUCCESS, "unlinked client local info -> %08lx", (unsigned long)status);
    ok(local.InboundQuota == IN_QUOTA && local.OutboundQuota == OUT_QUOTA,
       "unlinked client quotas %lu/%lu", (unsigned long)local.InboundQuota,
       (unsigned long)local.OutboundQuota);

    status = open_pipe_client(&stranger, pipe_name(1), &iosb);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "open of the unlinked name -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(stranger);

    /* A create of the same name is a NEW pipe: it may name a different
     * instance limit, and the old client is not describing it. */
    status = create_server(&reborn, pipe_name(1), FILE_PIPE_TYPE_BYTE, 3, &iosb);
    ok(status == STATUS_SUCCESS, "re-create of the unlinked name -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = query_pipe_local(reborn, &fresh);
        ok(status == STATUS_SUCCESS, "reborn server local info -> %08lx", (unsigned long)status);
        ok(fresh.MaximumInstances == 3 && fresh.CurrentInstances == 1,
           "reborn server instances %lu/%lu", (unsigned long)fresh.CurrentInstances,
           (unsigned long)fresh.MaximumInstances);
        status = query_pipe_local(client, &local);
        ok(status == STATUS_SUCCESS, "old client local info after the re-create -> %08lx",
           (unsigned long)status);
        ok(local.MaximumInstances == 1 && local.CurrentInstances == 0,
           "old client instances %lu/%lu", (unsigned long)local.CurrentInstances,
           (unsigned long)local.MaximumInstances);
        NtClose(reborn);
    }

    NtClose(client);
}

/* §3 — the unlink is keyed on the INSTANCE COUNT, not on "a server closed".
 *
 * Two instances; the client is attached to the first, which then closes. The
 * pipe still has an instance, so it keeps its name: the client of the DEAD
 * instance reports CurrentInstances 1 and its own name, and a second client
 * finds the name and connects to the survivor. */
static void test_a_second_instance_keeps_the_name(void)
{
    IO_STATUS_BLOCK iosb;
    FILE_PIPE_LOCAL_INFORMATION local;
    HANDLE first = NULL, second = NULL, client = NULL, stranger = NULL;
    NTSTATUS status;

    status = create_server(&first, pipe_name(2), FILE_PIPE_TYPE_BYTE, 2, &iosb);
    ok(status == STATUS_SUCCESS, "first instance -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    /* The client attaches to the only listening instance, so which one it
     * lands on is decided rather than raced. */
    status = open_pipe_client(&client, pipe_name(2), &iosb);
    ok(status == STATUS_SUCCESS, "client of the first instance -> %08lx", (unsigned long)status);
    status = create_server(&second, pipe_name(2), FILE_PIPE_TYPE_BYTE, 2, &iosb);
    ok(status == STATUS_SUCCESS, "second instance -> %08lx", (unsigned long)status);
    if (client == NULL || second == NULL)
    {
        NtClose(first);
        return;
    }

    NtClose(first);
    first = NULL;

    status = query_pipe_local(client, &local);
    ok(status == STATUS_SUCCESS, "orphaned-instance client local info -> %08lx",
       (unsigned long)status);
    ok(local.CurrentInstances == 1, "one instance still open, CurrentInstances %lu",
       (unsigned long)local.CurrentInstances);
    ok(local.NamedPipeState == FILE_PIPE_CLOSING_STATE, "orphaned-instance client state %lu",
       (unsigned long)local.NamedPipeState);
    status = query_name(client);
    ok(status == STATUS_SUCCESS, "still-linked client name -> %08lx", (unsigned long)status);

    status = open_pipe_client(&stranger, pipe_name(2), &iosb);
    ok(status == STATUS_SUCCESS, "open of the still-linked name -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(stranger);

    NtClose(client);
    NtClose(second);
}

/* §4 — a DISCONNECT is not a close, and the difference is the client's whole
 * answer.
 *
 * Same pipe shape as §1 and the same client handle; the server ends the
 * connection with FSCTL_PIPE_DISCONNECT instead of by closing. That takes the
 * client's own reference away, so the three classes §1 answered all refuse —
 * while the SERVER, which kept its reference, still reports the pipe. */
static void test_disconnect_is_not_a_close(void)
{
    IO_STATUS_BLOCK iosb;
    FILE_PIPE_LOCAL_INFORMATION local;
    FILE_STANDARD_INFORMATION std;
    HANDLE server = NULL, client = NULL;
    NTSTATUS status;

    status = create_server(&server, pipe_name(3), FILE_PIPE_TYPE_BYTE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "disconnect server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, pipe_name(3), &iosb);
    ok(status == STATUS_SUCCESS, "disconnect client open -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    status = pipe_fsctl(server, FSCTL_PIPE_DISCONNECT, &iosb);
    ok(status == STATUS_SUCCESS, "disconnect -> %08lx", (unsigned long)status);

    status = query_pipe_local(client, &local);
    ok(status == STATUS_PIPE_DISCONNECTED, "disconnected client local info -> %08lx",
       (unsigned long)status);
    status = query_standard(client, &std);
    ok(status == STATUS_PIPE_DISCONNECTED, "disconnected client standard info -> %08lx",
       (unsigned long)status);
    status = query_name(client);
    ok(status == STATUS_PIPE_DISCONNECTED, "disconnected client name -> %08lx",
       (unsigned long)status);

    /* The end that did the disconnecting kept everything. */
    status = query_pipe_local(server, &local);
    ok(status == STATUS_SUCCESS, "disconnecting server local info -> %08lx", (unsigned long)status);
    ok(local.InboundQuota == IN_QUOTA && local.OutboundQuota == OUT_QUOTA,
       "disconnecting server quotas %lu/%lu", (unsigned long)local.InboundQuota,
       (unsigned long)local.OutboundQuota);
    ok(local.NamedPipeState == FILE_PIPE_DISCONNECTED_STATE, "disconnecting server state %lu",
       (unsigned long)local.NamedPipeState);
    status = query_name(server);
    ok(status == STATUS_SUCCESS, "disconnecting server name -> %08lx", (unsigned long)status);

    NtClose(client);
    NtClose(server);
}

START_TEST(pipe_lifetime)
{
    test_client_outlives_its_server();
    test_the_name_goes_with_the_last_instance();
    test_a_second_instance_keeps_the_name();
    test_disconnect_is_not_a_close();
}
