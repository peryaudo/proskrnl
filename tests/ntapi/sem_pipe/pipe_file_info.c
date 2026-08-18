/*
 * sem_pipe/pipe_file_info.c — what a PIPE END answers through the universal
 * file-information classes: FileStandardInformation's four numbers, and the
 * refusal an end whose pipe was taken away owes both it and
 * FileNameInformation.
 *
 * docs/21 W11, the FileStandardInformation cluster in ntdll:pipe
 * (dlls/ntdll/tests/pipe.c test_pipe_with_data_state :2151/:2160/:2163,
 * _test_file_name_fail at :2447 and :2181).
 *
 * A pipe end has no unix fd — the server hands it an `alloc_pseudo_fd`, so
 * `server_get_unix_fd` answers STATUS_BAD_DEVICE_TYPE and ntdll routes the
 * WHOLE class to the server (dlls/ntdll/unix/file.c NtQueryInformationFile,
 * the `if (status != STATUS_BAD_DEVICE_TYPE) ... server_get_file_info` arm).
 * There it lands in server/named_pipe.c pipe_end_get_file_info, whose
 * FileStandardInformation arm is
 *
 *     if (!(get_handle_access( current->process, handle ) & FILE_READ_ATTRIBUTES))
 *         { set_error( STATUS_ACCESS_DENIED ); return; }
 *     if (get_reply_max_size() < sizeof(*std_info)) ...INFO_LENGTH_MISMATCH...
 *     if (!pipe) { set_error( STATUS_PIPE_DISCONNECTED ); return; }
 *     std_info->AllocationSize.QuadPart = pipe->outsize + pipe->insize;
 *     std_info->EndOfFile.QuadPart      = pipe_end_get_avail( pipe_end );
 *     std_info->NumberOfLinks           = 1;
 *     std_info->DeletePending           = 0;
 *     std_info->Directory               = 0;
 *
 * Four things in that are not guessable from the class name, and each is a
 * way an implementation that "reports the file's size" diverges:
 *
 *   - ALLOCATIONSIZE IS THE PIPE'S, ENDOFFILE IS THIS END'S. The first is
 *     both quotas added together and is the same number at both ends; the
 *     second is what THIS end can read right now, so the two ends of one
 *     pipe disagree about it whenever either has written. §1 gives the two
 *     quotas different values so a swap shows, and writes in one direction
 *     only so the ends must disagree.
 *   - ALLOCATIONSIZE IS A CAPACITY, NOT A USAGE. It does not move when data
 *     arrives, which an implementation summing buffered bytes gets wrong in
 *     exactly the state the winetest asks about.
 *   - THE CLASS DEMANDS FILE_READ_ATTRIBUTES OF THE HANDLE, which no other
 *     universal class here does and which FileNameInformation — the arm
 *     directly above it in the same handler — does not. §2 measures both
 *     through one weakened handle, because an implementation that puts the
 *     demand on the CLASS refuses the name too, and one that puts it on the
 *     DEVICE refuses neither.
 *   - AN ORPHANED END REFUSES BOTH. `pipe_end->pipe` is dropped for the
 *     CLIENT when the server disconnects (server/named_pipe.c, the
 *     FSCTL_PIPE_DISCONNECT arm: `release_object( ...connection->pipe );
 *     ...connection->pipe = NULL`), and the disconnecting SERVER keeps its
 *     own — so the refusal is one end's, not the pipe's. §3.
 *
 * DeletePending is 0 and NumberOfLinks is 1 for every pipe end. Both carry a
 * FIXME in the oracle and NT is documented to report DeletePending set on a
 * pipe (the winetest wraps that assertion in todo_wine), but the oracle is
 * the spec here (Art. 6) and this is what it answers.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG,
                                          ULONG);
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0) /* wine/include/winternl.h */

/* The two quotas are DIFFERENT and neither is the 4 KiB util.h's helper uses:
 * AllocationSize is their sum, so equal quotas would let a wrong field pass,
 * and a round number would let a hardwired one. */
#define IN_QUOTA  100
#define OUT_QUOTA 200

/* A distinct pipe name per sub-case — one leaked instance turns a later
 * create into INSTANCE_NOT_AVAILABLE and the failure names the wrong rule
 * (the argument create_refusals.c makes). */
static unsigned short NameBuffer[64];
static const void *pipe_name(unsigned index)
{
    static const unsigned short base[] = {'\\', '?', '?', '\\', 'p', 'i', 'p', 'e', '\\', 'p', 'r',
                                          's',  't', 'e', 's',  't', '_', 's', 't', 'd',  '_', 0};
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

static NTSTATUS create_server(HANDLE *handle, const void *wideName, ULONG access,
                              IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    LARGE_INTEGER timeout;

    init_ustr(&name, wideName);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    timeout.QuadPart = -100 * 10000; /* 100 ms, relative */
    *handle = NULL;
    return NtCreateNamedPipeFile(handle, access, &attr, iosb, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_PIPE_TYPE_BYTE,
                                 FILE_PIPE_BYTE_STREAM_MODE, FILE_PIPE_QUEUE_OPERATION, 1, IN_QUOTA,
                                 OUT_QUOTA, &timeout);
}

static NTSTATUS open_client(HANDLE *handle, const void *wideName, ULONG access,
                            IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    init_ustr(&name, wideName);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    *handle = NULL;
    return NtCreateFile(handle, access | SYNCHRONIZE, &attr, iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
                        FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

static NTSTATUS query_standard(HANDLE handle, FILE_STANDARD_INFORMATION *info,
                               IO_STATUS_BLOCK *iosb)
{
    memset(info, 0xcc, sizeof(*info));
    poison_iosb(iosb);
    return NtQueryInformationFile(handle, iosb, info, sizeof(*info), FileStandardInformation);
}

/* FileNameInformation's answer, discarded — this file asks it only for its
 * STATUS, which is where it differs from the class beside it. */
static NTSTATUS query_name(HANDLE handle, IO_STATUS_BLOCK *iosb)
{
    unsigned char buffer[128];

    memset(buffer, 0xcc, sizeof(buffer));
    poison_iosb(iosb);
    return NtQueryInformationFile(handle, iosb, buffer, sizeof(buffer), FileNameInformation);
}

/* §1 — the four numbers, at both ends, before and after data. */
static void test_fields(void)
{
    IO_STATUS_BLOCK iosb;
    FILE_PIPE_LOCAL_INFORMATION local;
    FILE_STANDARD_INFORMATION std;
    HANDLE server = NULL, client = NULL;
    unsigned char data[10] = {0};
    unsigned char sink[10];
    NTSTATUS status;

    status =
        create_server(&server, pipe_name(0),
                      GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_client(&client, pipe_name(0), GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES,
                         &iosb);
    ok(status == STATUS_SUCCESS, "client open -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    /* The quotas the create asked for, read back through the class that owns
     * them — so §1 measures the RELATION the winetest asserts and not a
     * number this file wrote down twice. */
    status = query_pipe_local(server, &local);
    ok(status == STATUS_SUCCESS, "server local info -> %08lx", (unsigned long)status);
    ok(local.InboundQuota == IN_QUOTA && local.OutboundQuota == OUT_QUOTA, "server quotas %lu/%lu",
       (unsigned long)local.InboundQuota, (unsigned long)local.OutboundQuota);

    status = query_standard(server, &std, &iosb);
    ok(status == STATUS_SUCCESS, "server standard info -> %08lx", (unsigned long)status);
    ok(std.AllocationSize.QuadPart == (LONGLONG)(local.InboundQuota + local.OutboundQuota),
       "server AllocationSize %llu, wanted %llu", (unsigned long long)std.AllocationSize.QuadPart,
       (unsigned long long)(local.InboundQuota + local.OutboundQuota));
    ok(std.EndOfFile.QuadPart == 0, "server EndOfFile on an empty pipe %llu",
       (unsigned long long)std.EndOfFile.QuadPart);
    ok(std.NumberOfLinks == 1, "server NumberOfLinks %lu", (unsigned long)std.NumberOfLinks);
    ok(std.DeletePending == 0, "server DeletePending %d", (int)std.DeletePending);
    ok(std.Directory == 0, "server Directory %d", (int)std.Directory);
    ok(iosb.Status == STATUS_SUCCESS, "server IOSB.Status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == sizeof(std), "server IOSB.Information %llu",
       (unsigned long long)iosb.Information);

    /* Both ends see the SAME capacity: it is the pipe's pair of quotas, not
     * "the buffer I write into". */
    status = query_standard(client, &std, &iosb);
    ok(status == STATUS_SUCCESS, "client standard info -> %08lx", (unsigned long)status);
    ok(std.AllocationSize.QuadPart == (LONGLONG)(IN_QUOTA + OUT_QUOTA),
       "client AllocationSize %llu", (unsigned long long)std.AllocationSize.QuadPart);

    /* One direction only, so the two ends MUST disagree about EndOfFile. */
    status = pipe_write(client, data, sizeof(data), &iosb);
    ok(status == STATUS_SUCCESS, "client write -> %08lx", (unsigned long)status);

    status = query_pipe_local(server, &local);
    ok(status == STATUS_SUCCESS, "server local info after the write -> %08lx",
       (unsigned long)status);
    ok(local.ReadDataAvailable == sizeof(data), "server ReadDataAvailable %lu",
       (unsigned long)local.ReadDataAvailable);

    status = query_standard(server, &std, &iosb);
    ok(status == STATUS_SUCCESS, "server standard info after the write -> %08lx",
       (unsigned long)status);
    ok(std.EndOfFile.QuadPart == (LONGLONG)local.ReadDataAvailable,
       "server EndOfFile %llu, wanted ReadDataAvailable %lu",
       (unsigned long long)std.EndOfFile.QuadPart, (unsigned long)local.ReadDataAvailable);
    /* A capacity, not a usage. */
    ok(std.AllocationSize.QuadPart == (LONGLONG)(IN_QUOTA + OUT_QUOTA),
       "server AllocationSize moved with the data: %llu",
       (unsigned long long)std.AllocationSize.QuadPart);

    status = query_standard(client, &std, &iosb);
    ok(status == STATUS_SUCCESS, "client standard info after the write -> %08lx",
       (unsigned long)status);
    ok(std.EndOfFile.QuadPart == 0, "client EndOfFile after ITS OWN write %llu",
       (unsigned long long)std.EndOfFile.QuadPart);

    /* And it falls back once the data is consumed. */
    status = pipe_read(server, sink, sizeof(sink), &iosb);
    ok(status == STATUS_SUCCESS, "server read -> %08lx", (unsigned long)status);
    status = query_standard(server, &std, &iosb);
    ok(status == STATUS_SUCCESS, "server standard info after the read -> %08lx",
       (unsigned long)status);
    ok(std.EndOfFile.QuadPart == 0, "server EndOfFile after the read %llu",
       (unsigned long long)std.EndOfFile.QuadPart);

    NtClose(client);
    NtClose(server);
}

/* §2 — the access the class demands, and the class beside it that demands
 * none. Both asked of the SAME handle, twice over: an end opened weak, and a
 * weakened DUPLICATE of a strong one, because only the second separates the
 * handle entry's word from the open's. */
static void test_read_attributes(void)
{
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION std;
    HANDLE server = NULL, client = NULL, weak = NULL;
    NTSTATUS status;

    status =
        create_server(&server, pipe_name(1),
                      GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* A client that never asked for the bit. */
    status = open_client(&client, pipe_name(1), 0, &iosb);
    ok(status == STATUS_SUCCESS, "SYNCHRONIZE-only client open -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = query_standard(client, &std, &iosb);
        ok(status == STATUS_ACCESS_DENIED, "standard info on a SYNCHRONIZE-only end -> %08lx",
           (unsigned long)status);
        /* The name class one arm up has no access guard at all. */
        status = query_name(client, &iosb);
        ok(status == STATUS_SUCCESS, "name info on a SYNCHRONIZE-only end -> %08lx",
           (unsigned long)status);
    }

    /* The same file object through a handle the duplicate weakened: the
     * value read is `get_handle_access( current->process, handle )`, the
     * handle table's own word, not FILE_OBJECT's grant at open. */
    status =
        NtDuplicateObject(NtCurrentProcess(), server, NtCurrentProcess(), &weak, SYNCHRONIZE, 0, 0);
    ok(status == STATUS_SUCCESS, "duplicate -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = query_standard(weak, &std, &iosb);
        ok(status == STATUS_ACCESS_DENIED, "standard info through a weakened duplicate -> %08lx",
           (unsigned long)status);
        /* The strong handle to the same end still answers. */
        status = query_standard(server, &std, &iosb);
        ok(status == STATUS_SUCCESS, "standard info through the strong handle -> %08lx",
           (unsigned long)status);
        NtClose(weak);
    }

    if (client != NULL)
        NtClose(client);
    NtClose(server);
}

/* §2b — and the demand belongs to a pipe END, not to the pipe DEVICE. The
 * `\Device\NamedPipe` root is reached through the same device, but on the
 * oracle it is a named_pipe_device_file whose fd ops are
 * default_fd_get_file_info (server/fd.c) — which has no access guard, and no
 * arm for this class at all.
 *
 * So the root's ANSWER cannot be pinned: the oracle is unbuilt there and an
 * unbuilt oracle is not authoritative (Art. 12), which is also why naming its
 * status here would be forbidden. What IS pinnable, and is exactly what
 * separates a check keyed on the device from one keyed on the end, is that
 * the answer does not depend on FILE_READ_ATTRIBUTES: an entitled root handle
 * and an unentitled one must agree, whatever they agree on. */
static void test_device_root(void)
{
    static const unsigned short rootName[] = {'\\', '?', '?', '\\', 'p', 'i', 'p', 'e', 0};
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION std;
    HANDLE strong = NULL, weak = NULL;
    NTSTATUS strongStatus, weakStatus, status;

    init_ustr(&name, rootName);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status =
        NtCreateFile(&strong, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attr, &iosb, NULL,
                     FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ok(status == STATUS_SUCCESS, "entitled root open -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    init_ustr(&name, rootName);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateFile(&weak, SYNCHRONIZE, &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
                          FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ok(status == STATUS_SUCCESS, "unentitled root open -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        strongStatus = query_standard(strong, &std, &iosb);
        weakStatus = query_standard(weak, &std, &iosb);
        ok(strongStatus == weakStatus,
           "the root's standard info depends on FILE_READ_ATTRIBUTES: %08lx vs %08lx",
           (unsigned long)strongStatus, (unsigned long)weakStatus);
        NtClose(weak);
    }
    NtClose(strong);
}

/* §3 — the end whose pipe was taken away, and the order between the two
 * refusals it can owe. */
static void test_orphaned_end(void)
{
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION std;
    HANDLE server = NULL, client = NULL, weakClient = NULL;
    NTSTATUS status;

    status =
        create_server(&server, pipe_name(2),
                      GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_client(&client, pipe_name(2), FILE_READ_ATTRIBUTES, &iosb);
    ok(status == STATUS_SUCCESS, "client open -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    status = pipe_fsctl(server, FSCTL_PIPE_DISCONNECT, &iosb);
    ok(status == STATUS_SUCCESS, "disconnect -> %08lx", (unsigned long)status);

    status = query_standard(client, &std, &iosb);
    ok(status == STATUS_PIPE_DISCONNECTED, "standard info on a disconnected client -> %08lx",
       (unsigned long)status);
    status = query_name(client, &iosb);
    ok(status == STATUS_PIPE_DISCONNECTED, "name info on a disconnected client -> %08lx",
       (unsigned long)status);

    /* The end that DID the disconnecting keeps its pipe, so it keeps its
     * numbers — the refusal belongs to one end, not to the pipe. */
    status = query_standard(server, &std, &iosb);
    ok(status == STATUS_SUCCESS, "standard info on the disconnecting server -> %08lx",
       (unsigned long)status);
    ok(std.AllocationSize.QuadPart == (LONGLONG)(IN_QUOTA + OUT_QUOTA),
       "disconnecting server AllocationSize %llu", (unsigned long long)std.AllocationSize.QuadPart);

    NtClose(client);
    NtClose(server);

    /* ACCESS BEFORE THE DISCONNECT. Same shape one instance over: a client
     * with no FILE_READ_ATTRIBUTES, orphaned, still reports the ACCESS
     * failure — the guard sits above `if (!pipe)` in the handler, so an
     * implementation that answers the disconnect first passes every case
     * above and fails this one. */
    server = NULL;
    status =
        create_server(&server, pipe_name(3),
                      GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &iosb);
    ok(status == STATUS_SUCCESS, "second server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_client(&weakClient, pipe_name(3), 0, &iosb);
    ok(status == STATUS_SUCCESS, "weak client open -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = pipe_fsctl(server, FSCTL_PIPE_DISCONNECT, &iosb);
        ok(status == STATUS_SUCCESS, "second disconnect -> %08lx", (unsigned long)status);
        status = query_standard(weakClient, &std, &iosb);
        ok(status == STATUS_ACCESS_DENIED,
           "standard info on a disconnected SYNCHRONIZE-only client -> %08lx",
           (unsigned long)status);
        /* The name class, which has no access guard, reports the disconnect
         * through that same handle. */
        status = query_name(weakClient, &iosb);
        ok(status == STATUS_PIPE_DISCONNECTED,
           "name info on a disconnected SYNCHRONIZE-only client -> %08lx", (unsigned long)status);
        NtClose(weakClient);
    }
    NtClose(server);
}

/* §4 — a CLIENT whose server merely CLOSED (no disconnect) is not orphaned:
 * its pipe object is still there, so it still reports the pipe's capacity.
 * The lifetime that makes that true — and the NAME the same close takes away
 * — is sem_pipe/pipe_lifetime.c; the case is here because AllocationSize is
 * this file's field. */
static void test_closing_client(void)
{
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION std;
    HANDLE server = NULL, client = NULL;
    NTSTATUS status;

    status =
        create_server(&server, pipe_name(4),
                      GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_client(&client, pipe_name(4), GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES,
                         &iosb);
    ok(status == STATUS_SUCCESS, "client open -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }
    NtClose(server);

    status = query_standard(client, &std, &iosb);
    ok(status == STATUS_SUCCESS, "standard info on a closing client -> %08lx",
       (unsigned long)status);
    ok(std.AllocationSize.QuadPart == (LONGLONG)(IN_QUOTA + OUT_QUOTA),
       "closing-client AllocationSize %llu", (unsigned long long)std.AllocationSize.QuadPart);
    NtClose(client);
}

START_TEST(pipe_file_info)
{
    test_fields();
    test_read_attributes();
    test_device_root();
    test_orphaned_end();
    test_closing_client();
}
