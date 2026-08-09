/*
 * sem_pipe/create_refusals.c — the refusals npfs owes on create, on the
 * client open, on FSCTL_PIPE_LISTEN and on the pipe info classes.
 *
 * docs/21 W11. Each case pins a SPECIFIC NT failure, which is an
 * implementation and not a stub (Art. 12), and each transcribes one guard in
 * the pinned oracle, cited above the case:
 *
 *   third_party/wine server/named_pipe.c
 *     DECL_HANDLER(create_named_pipe)  the create guard block, in its order
 *     named_pipe_open_file             the client's access vs the pipe sharing
 *     pipe_client_ioctl                FSCTL_PIPE_LISTEN on the client end
 *     pipe_end_get_file_info           FILE_READ_ATTRIBUTES on the pipe classes
 *
 * The order matters as much as the values: the oracle validates the sharing
 * word before the access word, and tests the instance limit before the
 * FILE_CREATE/sharing collision, so a pipe at its limit answers
 * INSTANCE_NOT_AVAILABLE rather than ACCESS_DENIED.
 */
#include "util.h"

/* NtCreateNamedPipeFile with every knob the refusal block reads. */
static NTSTATUS create_pipe_ex(HANDLE *handle, const void *wide_name, ULONG access, ULONG sharing,
                               ULONG disposition, ULONG type, ULONG read_mode, ULONG max_instances,
                               IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    LARGE_INTEGER timeout;

    init_ustr(&name, wide_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    timeout.QuadPart = -100 * 10000; /* 100 ms, relative */
    *handle = NULL;
    return NtCreateNamedPipeFile(handle, access, &attr, iosb, sharing, disposition,
                                 FILE_SYNCHRONOUS_IO_NONALERT, type, read_mode,
                                 FILE_PIPE_QUEUE_OPERATION, max_instances, 4096, 4096, &timeout);
}

/* The client open with a chosen desired access. SYNCHRONIZE is always in it
 * because FILE_SYNCHRONOUS_IO_NONALERT requires it — the same thing
 * CreateFileW does, which is how dlls/ntdll/tests/pipe.c reaches this. */
static NTSTATUS open_pipe_client_access(HANDLE *handle, const void *wide_name, ULONG access,
                                        IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    init_ustr(&name, wide_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    *handle = NULL;
    return NtCreateFile(handle, access | SYNCHRONIZE, &attr, iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
                        FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

/* A distinct pipe name per sub-case. The sharing/access sweep would otherwise
 * reuse one name across sixteen create/close rounds, where a single leaked
 * instance turns every later round into PIPE_NOT_AVAILABLE and the failure
 * names the wrong rule. Built by hand rather than with a literal because the
 * harness has no wide sprintf. */
static unsigned short NameBuffer[64];
static const void *pipe_name(unsigned index)
{
    static const unsigned short base[] = {'\\', '?', '?', '\\', 'p', 'i', 'p', 'e', '\\', 'p', 'r',
                                          's',  't', 'e', 's',  't', '_', 'r', 'e', 'f',  '_', 0};
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

/* server/named_pipe.c pipe_client_ioctl: the CLIENT end answers
 * STATUS_ILLEGAL_FUNCTION to FSCTL_PIPE_LISTEN. Not INVALID_PARAMETER —
 * listening is a verb the client end does not HAVE, which is what
 * ILLEGAL_FUNCTION says. dlls/ntdll/tests/pipe.c:344 asserts it twelve times,
 * once per sharing/access combination its matrix opens a client for. */
static void test_listen_on_client_end(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    NTSTATUS status;

    status = create_pipe_instance(&server, pipe_name(0), FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, pipe_name(0), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    status = pipe_fsctl(client, FSCTL_PIPE_LISTEN, &iosb);
    ok(status == STATUS_ILLEGAL_FUNCTION, "listen on client end -> %08lx", (unsigned long)status);

    NtClose(client);
    NtClose(server);
}

/* server/named_pipe.c named_pipe_open_file:
 *
 *     if (((access & GENERIC_READ)  && !(pipe_sharing & FILE_SHARE_READ)) ||
 *         ((access & GENERIC_WRITE) && !(pipe_sharing & FILE_SHARE_WRITE)))
 *         set_error( STATUS_ACCESS_DENIED );
 *
 * The pipe's SHARING (fixed at create) is what bounds the client's access —
 * the inverse of the usual share-mode reading, where sharing bounds what
 * OTHERS may do. A FILE_SHARE_READ pipe is FILE_PIPE_OUTBOUND: the client may
 * read it and may not write it. An access of 0 asks for neither and is always
 * allowed. */
static void test_client_access_vs_sharing(void)
{
    static const ULONG sharing[] = {FILE_SHARE_READ, FILE_SHARE_WRITE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE};
    static const ULONG access[] = {0, GENERIC_READ, GENERIC_WRITE, GENERIC_READ | GENERIC_WRITE};
    unsigned j, k, index = 10;

    for (j = 0; j < 3; j++)
    {
        for (k = 0; k < 4; k++)
        {
            IO_STATUS_BLOCK iosb;
            HANDLE server = NULL, client = NULL;
            NTSTATUS status, expected;
            const void *name = pipe_name(index++);

            status = create_pipe_instance(&server, name, sharing[j], FILE_PIPE_TYPE_BYTE,
                                          FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
            ok(status == STATUS_SUCCESS, "server create (sharing %lx) -> %08lx",
               (unsigned long)sharing[j], (unsigned long)status);
            if (!NT_SUCCESS(status))
                continue;

            expected = STATUS_SUCCESS;
            if (((access[k] & GENERIC_READ) && !(sharing[j] & FILE_SHARE_READ)) ||
                ((access[k] & GENERIC_WRITE) && !(sharing[j] & FILE_SHARE_WRITE)))
                expected = STATUS_ACCESS_DENIED;

            status = open_pipe_client_access(&client, name, access[k], &iosb);
            ok(status == expected, "client open (sharing %lx access %lx) -> %08lx, want %08lx",
               (unsigned long)sharing[j], (unsigned long)access[k], (unsigned long)status,
               (unsigned long)expected);
            if (NT_SUCCESS(status))
                NtClose(client);
            NtClose(server);
        }
    }
}

/* WHICH refusal wins when a client open is disqualified twice over. Both of
 * these were caught by review as ordering the guard could get wrong, and
 * both are measured here rather than argued:
 *
 *   - no listening instance AND a disallowed access. The oracle tests the
 *     listener list FIRST (server/named_pipe.c named_pipe_open_file: the
 *     list_empty(&pipe->listeners) -> STATUS_PIPE_NOT_AVAILABLE arm precedes
 *     the sharing guard), and the difference is not cosmetic — PIPE_BUSY is
 *     what drives a WaitNamedPipe-and-retry loop, where ACCESS_DENIED ends
 *     it.
 *
 *   - MAXIMUM_ALLOWED / GENERIC_ALL, which name no direction explicitly but
 *     which an access MAPPING expands to include both. */
static void test_client_open_precedence(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL, second = NULL;
    NTSTATUS status;

    /* One instance, already taken: no listener left. The second open also
     * asks for GENERIC_WRITE, which this OUTBOUND pipe would refuse. */
    status = create_pipe_instance(&server, pipe_name(60), FILE_SHARE_READ, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "outbound server create -> %08lx", (unsigned long)status);
    status = open_pipe_client_access(&client, pipe_name(60), GENERIC_READ, &iosb);
    ok(status == STATUS_SUCCESS, "first client -> %08lx", (unsigned long)status);

    status = open_pipe_client_access(&second, pipe_name(60), GENERIC_WRITE, &iosb);
    ok(status == STATUS_PIPE_NOT_AVAILABLE, "no listener beats bad access -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(second);
    NtClose(client);
    NtClose(server);

    /* A generic wish that names no direction, against an OUTBOUND pipe. */
    status = create_pipe_instance(&server, pipe_name(61), FILE_SHARE_READ, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "outbound server create -> %08lx", (unsigned long)status);
    status = open_pipe_client_access(&client, pipe_name(61), MAXIMUM_ALLOWED, &iosb);
    ok(status == STATUS_SUCCESS, "MAXIMUM_ALLOWED on OUTBOUND pipe -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(client);
    NtClose(server);

    status = create_pipe_instance(&server, pipe_name(62), FILE_SHARE_READ, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "outbound server create -> %08lx", (unsigned long)status);
    status = open_pipe_client_access(&client, pipe_name(62), GENERIC_ALL, &iosb);
    ok(status == STATUS_SUCCESS, "GENERIC_ALL on OUTBOUND pipe -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(client);
    NtClose(server);
}

/* server/named_pipe.c DECL_HANDLER(create_named_pipe), the first guard:
 *
 *     if (!req->sharing || (req->sharing & ~(FILE_SHARE_READ | FILE_SHARE_WRITE)) ||
 *         (!(flags & MESSAGE_STREAM_WRITE) && (flags & MESSAGE_STREAM_READ)))
 *         set_error( STATUS_INVALID_PARAMETER );
 *     if (!req->access) set_error( STATUS_ACCESS_DENIED );
 *
 * A pipe MUST name a direction: zero sharing is not "share nothing", it is a
 * malformed request. dlls/ntdll/tests/pipe.c:281 pins the zero case and :291
 * the access case's neighbour. */
static void test_create_sharing_and_access(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE handle = NULL;
    NTSTATUS status;

    status = create_pipe_ex(&handle, pipe_name(30), GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0,
                            FILE_CREATE, FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_INVALID_PARAMETER, "create sharing 0 -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(handle);

    /* A bit outside {READ, WRITE} is refused even alongside a legal one. */
    status = create_pipe_ex(&handle, pipe_name(31), GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                            FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_CREATE, FILE_PIPE_TYPE_BYTE,
                            FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_INVALID_PARAMETER, "create sharing R|DELETE -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(handle);

    /* A BYTE-type pipe may not be born in message READ mode. */
    status = create_pipe_ex(&handle, pipe_name(32), GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, FILE_PIPE_TYPE_BYTE,
                            FILE_PIPE_MESSAGE_MODE, 1, &iosb);
    ok(status == STATUS_INVALID_PARAMETER, "create byte pipe in message read mode -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(handle);

    /* Zero desired access is ACCESS_DENIED, and it is checked AFTER the
     * sharing word — a request wrong in both ways reports the sharing. */
    status = create_pipe_ex(&handle, pipe_name(33), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            FILE_CREATE, FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_ACCESS_DENIED, "create access 0 -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(handle);

    status = create_pipe_ex(&handle, pipe_name(34), 0, 0, FILE_CREATE, FILE_PIPE_TYPE_BYTE,
                            FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_INVALID_PARAMETER, "create access 0 AND sharing 0 -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(handle);

    /* And the guard block runs BEFORE the disposition is looked at: the
     * oracle validates sharing and access up front and only then switches on
     * the disposition, so a request wrong in the access AND carrying a
     * disposition no pipe accepts reports the ACCESS. */
    status =
        create_pipe_ex(&handle, pipe_name(35), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       FILE_SUPERSEDE, FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_ACCESS_DENIED, "access 0 with a bad disposition -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(handle);
}

/* server/named_pipe.c DECL_HANDLER(create_named_pipe), the existing-pipe arm:
 *
 *     if (pipe->maxinstances <= pipe->instances) STATUS_INSTANCE_NOT_AVAILABLE;
 *     if (pipe->sharing != req->sharing || req->disposition == FILE_CREATE)
 *         STATUS_ACCESS_DENIED;
 *
 * So a second instance must agree with the FIRST instance's sharing, and
 * FILE_CREATE never opens an existing pipe — it does not answer
 * OBJECT_NAME_COLLISION the way a file create does. dlls/ntdll/tests/pipe.c:296
 * pins the FILE_CREATE case. FILE_OPEN of a pipe that does not exist is
 * OBJECT_NAME_NOT_FOUND: only FILE_CREATE and FILE_OPEN_IF may mint one. */
static void test_create_on_existing(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE first = NULL, second = NULL;
    const ULONG full = GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE;
    NTSTATUS status;

    status = create_pipe_ex(&first, pipe_name(40), full, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            FILE_CREATE, FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, 4, &iosb);
    ok(status == STATUS_SUCCESS, "first instance -> %08lx", (unsigned long)status);
    ok(iosb.Information == FILE_CREATED, "first iosb.Information %lu",
       (unsigned long)iosb.Information);

    /* Same sharing, FILE_OPEN_IF: a further instance, and it is OPENED. */
    poison_iosb(&iosb);
    status =
        create_pipe_ex(&second, pipe_name(40), full, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       FILE_OPEN_IF, FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, 4, &iosb);
    ok(status == STATUS_SUCCESS, "second instance -> %08lx", (unsigned long)status);
    ok(iosb.Information == FILE_OPENED, "second iosb.Information %lu",
       (unsigned long)iosb.Information);
    if (NT_SUCCESS(status))
        NtClose(second);

    /* FILE_CREATE on a name that already exists. */
    status = create_pipe_ex(&second, pipe_name(40), full, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            FILE_CREATE, FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, 4, &iosb);
    ok(status == STATUS_ACCESS_DENIED, "FILE_CREATE on existing -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(second);

    /* A second instance that disagrees about the direction. */
    status = create_pipe_ex(&second, pipe_name(40), full, FILE_SHARE_READ, FILE_OPEN_IF,
                            FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, 4, &iosb);
    ok(status == STATUS_ACCESS_DENIED, "second instance, other sharing -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(second);

    /* FILE_OPEN of an existing pipe is a further instance too. */
    status = create_pipe_ex(&second, pipe_name(40), full, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            FILE_OPEN, FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, 4, &iosb);
    ok(status == STATUS_SUCCESS, "FILE_OPEN on existing -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(second);

    NtClose(first);

    /* FILE_OPEN of a name with no pipe behind it mints nothing. */
    status = create_pipe_ex(&second, pipe_name(41), full, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            FILE_OPEN, FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, 4, &iosb);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "FILE_OPEN of missing pipe -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(second);
}

/* server/named_pipe.c pipe_end_get_file_info, the FilePipeInformation and
 * FilePipeLocalInformation arms:
 *
 *     if (!(get_handle_access( current->process, handle ) & FILE_READ_ATTRIBUTES))
 *         set_error( STATUS_ACCESS_DENIED );
 *
 * dlls/ntdll/tests/pipe.c:291 opens a SYNCHRONIZE-only server end for exactly
 * this. The access is the HANDLE's, so a class whose value needs no
 * privileged state still owes the check.
 *
 * The BUFFER LENGTH is checked first, and that ordering was measured, not
 * guessed: this case originally asserted that a short buffer on an unentitled
 * handle still reported ACCESS_DENIED, and the oracle answered
 * STATUS_INFO_LENGTH_MISMATCH. The server guard above is not the first thing
 * in the path — NtQueryInformationFile validates the class's fixed size
 * before it ever reaches the pipe object (the oracle's own table,
 * dlls/ntdll/unix/file.c info_sizes[]: sizeof(FILE_PIPE_INFORMATION) and
 * sizeof(FILE_PIPE_LOCAL_INFORMATION)). So length, then access. */
static void test_pipe_info_requires_read_attributes(void)
{
    IO_STATUS_BLOCK iosb;
    FILE_PIPE_LOCAL_INFORMATION local;
    SEM_FILE_PIPE_INFORMATION mode;
    HANDLE weak = NULL, strong = NULL;
    NTSTATUS status;

    status = create_pipe_ex(&weak, pipe_name(50), SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            FILE_CREATE, FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, 2, &iosb);
    ok(status == STATUS_SUCCESS, "weak-handle create -> %08lx", (unsigned long)status);

    status = NtQueryInformationFile(weak, &iosb, &local, sizeof(local), FilePipeLocalInformation);
    ok(status == STATUS_ACCESS_DENIED, "local info on SYNCHRONIZE handle -> %08lx",
       (unsigned long)status);

    status = NtQueryInformationFile(weak, &iosb, &mode, sizeof(mode), FilePipeInformation);
    ok(status == STATUS_ACCESS_DENIED, "pipe info on SYNCHRONIZE handle -> %08lx",
       (unsigned long)status);

    /* Length before access: the same unentitled handle reports the LENGTH
     * when the buffer is short, so the class-size check sits in front of the
     * pipe object entirely. */
    status = NtQueryInformationFile(weak, &iosb, &local, 4, FilePipeLocalInformation);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short buffer on SYNCHRONIZE handle -> %08lx",
       (unsigned long)status);

    /* FILE_READ_ATTRIBUTES alone is enough — no data access needed. */
    status = create_pipe_ex(&strong, pipe_name(50), FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_PIPE_TYPE_BYTE,
                            FILE_PIPE_BYTE_STREAM_MODE, 2, &iosb);
    ok(status == STATUS_SUCCESS, "strong-handle create -> %08lx", (unsigned long)status);

    status = NtQueryInformationFile(strong, &iosb, &local, sizeof(local), FilePipeLocalInformation);
    ok(status == STATUS_SUCCESS, "local info with READ_ATTRIBUTES -> %08lx", (unsigned long)status);
    ok(local.NamedPipeEnd == FILE_PIPE_SERVER_END, "end %lu", (unsigned long)local.NamedPipeEnd);

    NtClose(strong);
    NtClose(weak);
}

START_TEST(create_refusals)
{
    test_listen_on_client_end();
    test_client_access_vs_sharing();
    test_client_open_precedence();
    test_create_sharing_and_access();
    test_create_on_existing();
    test_pipe_info_requires_read_attributes();
}
