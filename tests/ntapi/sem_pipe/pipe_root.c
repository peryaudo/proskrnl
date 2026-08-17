/*
 * sem_pipe/pipe_root.c — what ROOT a named-pipe create and a pipe-relative
 * open accept, and what an UNNAMED pipe is.
 *
 * docs/21 W11, the 25-assertion cluster in dlls/ntdll/tests/pipe.c
 * test_empty_name (:2842-:2936). Two rules, both read off the pinned oracle:
 *
 *   third_party/wine server/named_pipe.c
 *     named_pipe_link_name    a pipe's NAME lives in the DEVICE's flat
 *                             namespace; the only parent that reaches it is
 *                             the device object (the device's root DIRECTORY
 *                             is folded onto it), and every other parent is
 *                             STATUS_OBJECT_NAME_INVALID
 *     pipe_server_lookup_name a SERVER END is a lookup root: an empty name
 *                             resolves to the end itself, a non-empty one is
 *                             STATUS_OBJECT_NAME_INVALID
 *     pipe_server_open_file   ...and opening that resolved end IS the client
 *                             open (it tail-calls named_pipe_open_file on the
 *                             end's pipe), which is how a pipe with no name
 *                             is reachable at all
 *   third_party/wine server/object.c
 *     create_named_object     an EMPTY name allocates an UNLINKED object and
 *                             never touches the parent — so an unnamed create
 *                             accepts ANY root
 *     open_named_object       ...and FILE_OPEN of an empty name resolves to
 *                             the ROOT, whose type is never named_pipe_ops,
 *                             so it is STATUS_OBJECT_TYPE_MISMATCH
 *   third_party/wine server/named_pipe.c DECL_HANDLER(create_named_pipe)
 *                             "pipes need a root directory even without a
 *                             name": an empty name with no root at all is
 *                             STATUS_OBJECT_PATH_SYNTAX_BAD
 *
 * Four things an implementation reaching for the obvious guard gets wrong,
 * and each has its own case below:
 *
 *   - THE EMPTY NAME IGNORES THE ROOT'S TYPE ENTIRELY. The root is resolved
 *     with `get_handle_obj( process, rootdir, 0, NULL )` — any type, no
 *     access — and then dropped unused. An event handle is a legal root for
 *     an unnamed pipe; only a root that names NOTHING is refused, and its
 *     answer is STATUS_INVALID_HANDLE rather than a name error (§1).
 *   - A NAMED create's root is the OPPOSITE: it must reach the pipe device's
 *     own namespace. A File on another device, a pipe END and an event all
 *     answer STATUS_OBJECT_NAME_INVALID, which is the link's refusal and not
 *     the lookup's (§4).
 *   - THE PIPE NAMESPACE IS FLAT, so a name carrying a component separator is
 *     one key rather than a path. `prstest_root_a2\sub` created relative to
 *     the device root is openable by its absolute name (§4).
 *   - ...AND THE THREE REFUSALS ARE ORDERED. The handle is resolved first
 *     (server/request.c get_req_object_attributes), then `lookup_named_object`
 *     refuses an ABSOLUTE name under ANY root that resolved, and only then does
 *     the link ask whether this root reaches the pipe namespace. A ladder that
 *     asks about the root first answers STATUS_OBJECT_NAME_INVALID where the
 *     oracle answers STATUS_OBJECT_PATH_SYNTAX_BAD, and passes every row where
 *     the root IS the pipe device (§4's last block).
 *   - AN UNNAMED PIPE'S CLIENT END IS OPENED THROUGH ITS SERVER END'S HANDLE,
 *     with an empty name — and the SECOND such open answers
 *     STATUS_PIPE_NOT_AVAILABLE exactly as a by-name open of a pipe whose
 *     instances are all taken does, because it lands in the same function
 *     (§3). The client end is NOT a root in turn: pipe_client_ops carries
 *     no_lookup_name, so an empty name there is STATUS_OBJECT_TYPE_MISMATCH
 *     and a non-empty one is STATUS_OBJECT_NAME_NOT_FOUND — the two halves of
 *     open_named_object's own ladder.
 *
 * What this file deliberately does NOT pin, because proskrnl cannot yet tell
 * the device from its root directory (docs/21 W7's parser question, the same
 * one `\??\C:` vs `\??\C:\` asks): the winetest's :2810, where the same named
 * create relative to a handle on `\Device\NamedPipe` — no trailing separator,
 * so the DEVICE FILE rather than the directory — must be
 * STATUS_OBJECT_NAME_INVALID. Every root here is spelled with the trailing
 * separator for that reason.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN);

/* A distinct pipe name per sub-case — one leaked instance turns a later
 * create into INSTANCE_NOT_AVAILABLE and the failure names the wrong rule
 * (the argument create_refusals.c makes). */
static unsigned short NameBuffer[64];
static const void *pipe_name(unsigned index, const void *wideSuffix)
{
    static const unsigned short base[] = {'p', 'r', 's', 't', 'e', 's', 't',
                                          '_', 'r', 'o', 'o', 't', '_', 0};
    const unsigned short *suffix = (const unsigned short *)wideSuffix;
    unsigned i = 0;
    while (base[i] != 0)
    {
        NameBuffer[i] = base[i];
        i++;
    }
    NameBuffer[i++] = (unsigned short)('a' + (index / 10));
    NameBuffer[i++] = (unsigned short)('0' + (index % 10));
    while (suffix != NULL && *suffix != 0)
    {
        NameBuffer[i++] = *suffix++;
    }
    NameBuffer[i] = 0;
    return NameBuffer;
}

/* The same name with the `\??\pipe\` prefix, for an ABSOLUTE open. A second
 * buffer so a caller can hold both at once. */
static unsigned short AbsBuffer[80];
static const void *absolute_name(const void *wideRelative)
{
    static const unsigned short prefix[] = {'\\', '?', '?', '\\', 'p', 'i', 'p', 'e', '\\', 0};
    const unsigned short *rel = (const unsigned short *)wideRelative;
    unsigned i = 0;
    while (prefix[i] != 0)
    {
        AbsBuffer[i] = prefix[i];
        i++;
    }
    unsigned j = 0;
    while (rel[j] != 0)
    {
        AbsBuffer[i + j] = rel[j];
        j++;
    }
    AbsBuffer[i + j] = 0;
    return AbsBuffer;
}

/* NtCreateNamedPipeFile relative to `root`. `wideName == NULL` is the EMPTY
 * name — a present UNICODE_STRING of length zero, which is what the winetest
 * passes and what the server reads as "unnamed", NOT a NULL ObjectName. */
static NTSTATUS create_pipe_at(HANDLE *handle, HANDLE root, const void *wideName, ULONG disposition,
                               IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    LARGE_INTEGER timeout;

    name.Length = 0;
    name.MaximumLength = 0;
    name.Buffer = NULL;
    if (wideName != NULL)
    {
        init_ustr(&name, wideName);
    }
    init_attr(&attr, root, &name, OBJ_CASE_INSENSITIVE);
    timeout.QuadPart = -100 * 10000; /* 100 ms, relative */
    *handle = NULL;
    poison_iosb(iosb);
    return NtCreateNamedPipeFile(
        handle, GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attr, iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE, disposition, FILE_SYNCHRONOUS_IO_NONALERT,
        FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, FILE_PIPE_QUEUE_OPERATION, 3, 4096, 4096,
        &timeout);
}

/* NtCreateFile relative to `root`, same empty-name convention. */
static NTSTATUS open_at(HANDLE *handle, HANDLE root, const void *wideName, ACCESS_MASK access,
                        ULONG options, IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    name.Length = 0;
    name.MaximumLength = 0;
    name.Buffer = NULL;
    if (wideName != NULL)
    {
        init_ustr(&name, wideName);
    }
    init_attr(&attr, root, &name, OBJ_CASE_INSENSITIVE);
    *handle = NULL;
    poison_iosb(iosb);
    return NtCreateFile(handle, access | SYNCHRONIZE, &attr, iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, options, NULL, 0);
}

/* The pipe device's ROOT DIRECTORY: "\??\pipe\", WITH the trailing separator
 * (the shape kernelbase's WaitNamedPipeW opens, dlls/kernelbase/sync.c). */
static HANDLE open_pipe_root(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE root = NULL;
    NTSTATUS status =
        open_at(&root, NULL, W("\\??\\pipe\\"), GENERIC_READ | GENERIC_WRITE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "open \\??\\pipe\\ -> %08lx", (unsigned long)status);
    return NT_SUCCESS(status) ? root : NULL;
}

/* A root of a completely different kind: the shared test directory on C:.
 * Its device is not the pipe device, which is what §4 needs. */
static HANDLE open_disk_root(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE dir = NULL;
    NTSTATUS status;

    init_ustr(&name, W("\\??\\C:\\prstest"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status =
        NtCreateFile(&dir, FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE, &attr, &iosb, NULL,
                     FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                     FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ok(status == STATUS_SUCCESS, "open \\??\\C:\\prstest -> %08lx", (unsigned long)status);
    return NT_SUCCESS(status) ? dir : NULL;
}

/* FileNameInformation's status and the name it reports. */
static NTSTATUS query_name(HANDLE handle, unsigned short *out, unsigned outUnits)
{
    IO_STATUS_BLOCK iosb;
    unsigned char buffer[256];
    ULONG nameBytes;
    unsigned i;
    NTSTATUS status;

    memset(buffer, 0, sizeof(buffer));
    poison_iosb(&iosb);
    out[0] = 0;
    status = NtQueryInformationFile(handle, &iosb, buffer, sizeof(buffer), FileNameInformation);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    memcpy(&nameBytes, buffer, sizeof(nameBytes));
    for (i = 0; i < nameBytes / 2 && i + 1 < outUnits; i++)
    {
        memcpy(&out[i], buffer + 4 + i * 2, 2);
    }
    out[i] = 0;
    return status;
}

static int names_equal(const unsigned short *a, const void *wideB)
{
    const unsigned short *b = (const unsigned short *)wideB;
    unsigned i = 0;
    while (a[i] != 0 && b[i] != 0 && a[i] == b[i])
    {
        i++;
    }
    return a[i] == 0 && b[i] == 0;
}

/* §1 — an EMPTY name makes an UNNAMED pipe, and the root only has to exist.
 *
 * server/object.c create_named_object's first arm allocates the object with
 * `alloc_object( ops )` and never looks at `parent`, so the root's TYPE is
 * unread. What the handler does check is that a root was supplied at all
 * ("pipes need a root directory even without a name") and that it resolves. */
static void test_empty_name_root(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE root = NULL, pipe = NULL, event = NULL, stale = NULL;
    NTSTATUS status;

    /* No root at all — a path with neither an absolute name nor a place to
     * hang a relative one. */
    status = create_pipe_at(&pipe, NULL, NULL, FILE_CREATE, &iosb);
    ok(status == STATUS_OBJECT_PATH_SYNTAX_BAD, "unnamed, no root -> %08lx", (unsigned long)status);

    /* A root that names nothing: the HANDLE is at fault, not the name. */
    status = NtCreateEvent(&stale, EVENT_ALL_ACCESS, NULL, 0 /* NotificationEvent */, FALSE);
    ok(status == STATUS_SUCCESS, "event create -> %08lx", (unsigned long)status);
    NtClose(stale);
    status = create_pipe_at(&pipe, stale, NULL, FILE_CREATE, &iosb);
    ok(status == STATUS_INVALID_HANDLE, "unnamed, dead root -> %08lx", (unsigned long)status);

    /* An EVENT is a legal root for an unnamed pipe. This is the case that
     * separates "the root is resolved and dropped" from "the root selects the
     * namespace": an implementation that demanded a File here refuses it. */
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, 0, FALSE);
    ok(status == STATUS_SUCCESS, "event create -> %08lx", (unsigned long)status);
    status = create_pipe_at(&pipe, event, NULL, FILE_CREATE, &iosb);
    ok(status == STATUS_SUCCESS, "unnamed under an event -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ok(iosb.Information == FILE_CREATED, "unnamed information %llx",
           (unsigned long long)iosb.Information);
        NtClose(pipe);
    }
    NtClose(event);

    root = open_pipe_root();
    if (root == NULL)
    {
        return;
    }

    /* The ordinary shape: unnamed under the pipe device's own root. */
    status = create_pipe_at(&pipe, root, NULL, FILE_CREATE, &iosb);
    ok(status == STATUS_SUCCESS, "unnamed under the pipe root -> %08lx", (unsigned long)status);

    /* FILE_OPEN of an empty name resolves to the ROOT ITSELF and then
     * type-checks it — and a root is never a named_pipe. So the disposition
     * that would "open the unnamed pipe" cannot exist, whatever the root is.
     * open_named_object's `ops && obj->ops != ops` arm. */
    if (NT_SUCCESS(status))
    {
        HANDLE reopen = NULL;
        status = create_pipe_at(&reopen, root, NULL, FILE_OPEN, &iosb);
        ok(status == STATUS_OBJECT_TYPE_MISMATCH, "unnamed FILE_OPEN under the root -> %08lx",
           (unsigned long)status);

        status = create_pipe_at(&reopen, pipe, NULL, FILE_OPEN, &iosb);
        ok(status == STATUS_OBJECT_TYPE_MISMATCH, "unnamed FILE_OPEN under a pipe end -> %08lx",
           (unsigned long)status);

        /* A pipe END is a legal root for another unnamed pipe, for the same
         * reason the event was: the root goes unread. */
        status = create_pipe_at(&reopen, pipe, NULL, FILE_CREATE, &iosb);
        ok(status == STATUS_SUCCESS, "unnamed under a pipe end -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            NtClose(reopen);
        }
        NtClose(pipe);
    }
    NtClose(root);
}

/* §2 — an unnamed pipe end has no name to report, and says so. The oracle's
 * FileNameInformation arm is
 *
 *     if (!pipe || !(name = get_object_name( &pipe->obj, &name_len )))
 *         { set_error( STATUS_PIPE_DISCONNECTED ); return; }
 *
 * (server/named_pipe.c pipe_end_get_file_info) — the SAME refusal an orphaned
 * end gets, because the two conditions share one guard. A named pipe created
 * through the same root is the positive control: it reports "\<name>", so the
 * refusal is about the missing name and not about the root. */
static void test_unnamed_has_no_name(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE root = NULL, unnamed = NULL, named = NULL;
    unsigned short reported[64];
    NTSTATUS status;

    root = open_pipe_root();
    if (root == NULL)
    {
        return;
    }

    status = create_pipe_at(&unnamed, root, NULL, FILE_CREATE, &iosb);
    ok(status == STATUS_SUCCESS, "unnamed create -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = query_name(unnamed, reported, 64);
        ok(status == STATUS_PIPE_DISCONNECTED, "unnamed FileNameInformation -> %08lx",
           (unsigned long)status);
        NtClose(unnamed);
    }

    status = create_pipe_at(&named, root, pipe_name(0, NULL), FILE_CREATE, &iosb);
    ok(status == STATUS_SUCCESS, "named create under the root -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = query_name(named, reported, 64);
        ok(status == STATUS_SUCCESS, "named FileNameInformation -> %08lx", (unsigned long)status);
        ok(names_equal(reported, W("\\prstest_root_a0")), "named reports %04x%04x",
           (unsigned)reported[0], (unsigned)reported[1]);
        NtClose(named);
    }
    NtClose(root);
}

/* §3 — the client end of an unnamed pipe is opened through the SERVER END's
 * handle with an empty name, and the ladder around that. */
static void test_open_relative_to_end(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE root = NULL, server = NULL, client = NULL, other = NULL;
    unsigned char data[4] = {0xde, 0xad, 0xbe, 0xef};
    unsigned char sink[4] = {0};
    NTSTATUS status;

    root = open_pipe_root();
    if (root == NULL)
    {
        return;
    }
    status = create_pipe_at(&server, root, NULL, FILE_CREATE, &iosb);
    ok(status == STATUS_SUCCESS, "unnamed create -> %08lx", (unsigned long)status);
    NtClose(root);
    if (!NT_SUCCESS(status))
    {
        return;
    }

    /* pipe_server_lookup_name: a NON-EMPTY name under a server end is the
     * name's fault — the end has no namespace to hold it. */
    status = open_at(&other, server, W("a"), GENERIC_WRITE, FILE_SYNCHRONOUS_IO_NONALERT, &iosb);
    ok(status == STATUS_OBJECT_NAME_INVALID, "named open under a server end -> %08lx",
       (unsigned long)status);

    /* ...and an EMPTY name resolves to the end, whose open_file is the client
     * open. */
    status = open_at(&client, server, NULL, GENERIC_WRITE | FILE_WRITE_ATTRIBUTES,
                     FILE_SYNCHRONOUS_IO_NONALERT, &iosb);
    ok(status == STATUS_SUCCESS, "client open under a server end -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    /* The instance is taken now, and the second open lands in the same
     * function a by-name open would: PIPE_NOT_AVAILABLE, not a name error. */
    status = open_at(&other, server, NULL, GENERIC_WRITE, FILE_SYNCHRONOUS_IO_NONALERT, &iosb);
    ok(status == STATUS_PIPE_NOT_AVAILABLE, "second client open -> %08lx", (unsigned long)status);

    /* The CLIENT end is not a root in turn — pipe_client_ops carries
     * no_lookup_name, whose two arms differ: a NULL name sets the type
     * mismatch itself, and a non-empty one leaves the lookup at the client
     * with the name unconsumed, which open_named_object reports as a missing
     * NAME. Two statuses out of one function. */
    status = open_at(&other, client, NULL, GENERIC_READ, FILE_SYNCHRONOUS_IO_NONALERT, &iosb);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "empty open under a client end -> %08lx",
       (unsigned long)status);
    status = open_at(&other, client, W("x"), GENERIC_READ, FILE_SYNCHRONOUS_IO_NONALERT, &iosb);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "named open under a client end -> %08lx",
       (unsigned long)status);

    /* The two ends really are one pipe. */
    status = pipe_write(client, data, sizeof(data), &iosb);
    ok(status == STATUS_SUCCESS, "write -> %08lx", (unsigned long)status);
    status = pipe_read(server, sink, sizeof(sink), &iosb);
    ok(status == STATUS_SUCCESS, "read -> %08lx", (unsigned long)status);
    ok(iosb.Information == sizeof(data), "read %llx", (unsigned long long)iosb.Information);
    ok(memcmp(sink, data, sizeof(data)) == 0, "read %02x%02x%02x%02x", sink[0], sink[1], sink[2],
       sink[3]);

    NtClose(client);
    NtClose(server);
}

/* §4 — a NAMED create's root must reach the pipe device's own namespace.
 *
 * named_pipe_link_name folds the device's root DIRECTORY onto the device and
 * refuses every other parent with STATUS_OBJECT_NAME_INVALID. That the name
 * lands in the DEVICE's namespace rather than under the root is measurable:
 * the pipe is then openable by its absolute path. */
static void test_named_create_root(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE root = NULL, disk = NULL, event = NULL, pipe = NULL, client = NULL, end = NULL;
    const void *relative;
    NTSTATUS status;

    root = open_pipe_root();
    if (root == NULL)
    {
        return;
    }

    /* Accepted: the device's root directory. */
    status = create_pipe_at(&pipe, root, pipe_name(1, NULL), FILE_CREATE, &iosb);
    ok(status == STATUS_SUCCESS, "named create under the pipe root -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ok(iosb.Information == FILE_CREATED, "named information %llx",
           (unsigned long long)iosb.Information);
        /* It went into the DEVICE's namespace, not under the root handle. */
        status = open_pipe_client(&client, absolute_name(pipe_name(1, NULL)), &iosb);
        ok(status == STATUS_SUCCESS, "absolute open of the relative create -> %08lx",
           (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            NtClose(client);
        }
        NtClose(pipe);
    }

    /* The namespace is FLAT: a separator in the name is a character, not a
     * path. This is the winetest's own "test3\pipe" (pipe.c:2932). */
    relative = pipe_name(2, W("\\sub"));
    status = create_pipe_at(&pipe, root, relative, FILE_CREATE, &iosb);
    ok(status == STATUS_SUCCESS, "named create with a separator -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = open_pipe_client(&client, absolute_name(pipe_name(2, W("\\sub"))), &iosb);
        ok(status == STATUS_SUCCESS, "absolute open of the separated name -> %08lx",
           (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            NtClose(client);
        }
        NtClose(pipe);
    }

    /* Refused: a File on ANOTHER device. */
    disk = open_disk_root();
    if (disk != NULL)
    {
        status = create_pipe_at(&pipe, disk, pipe_name(3, NULL), FILE_CREATE, &iosb);
        ok(status == STATUS_OBJECT_NAME_INVALID, "named create under a disk directory -> %08lx",
           (unsigned long)status);
    }

    /* Refused: an object that is not a File at all. */
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, 0, FALSE);
    ok(status == STATUS_SUCCESS, "event create -> %08lx", (unsigned long)status);

    /* Refused: a pipe END. pipe_server_lookup_name sets the same status one
     * frame earlier, so the two roots agree by two different routes. */
    status = create_pipe_at(&end, root, pipe_name(5, NULL), FILE_CREATE, &iosb);
    ok(status == STATUS_SUCCESS, "named create for the end-root case -> %08lx",
       (unsigned long)status);
    if (end != NULL)
    {
        status = create_pipe_at(&pipe, end, pipe_name(6, NULL), FILE_CREATE, &iosb);
        ok(status == STATUS_OBJECT_NAME_INVALID, "named create under a pipe end -> %08lx",
           (unsigned long)status);
    }

    /* THE ORDER of the three refusals, which is separable from all three and
     * is what a ladder built root-first gets wrong.
     *
     * An ABSOLUTE name under a root is `lookup_named_object`'s FIRST guard
     * (server/object.c: `if (root) { if (name_tmp.len && name_tmp.str[0] ==
     * '\\') set_error( STATUS_OBJECT_PATH_SYNTAX_BAD ); }`), so it fires
     * before `lookup_name` and before `named_pipe_link_name` — i.e. the same
     * absolute name answers the SYNTAX error under EVERY root that resolves,
     * including the three this test has just seen refuse a relative name.
     * An implementation that asked "does this root reach the pipe namespace"
     * first passes the pipe-root row below and answers
     * STATUS_OBJECT_NAME_INVALID for the other three.
     *
     * It is also a SYNTAX error rather than the STATUS_INVALID_PARAMETER
     * NtCreateFile gives for the identical mistake — that one is ntdll's own
     * check on a path this call never goes through. */
    status = create_pipe_at(&pipe, root, W("\\prstest_root_abs"), FILE_CREATE, &iosb);
    ok(status == STATUS_OBJECT_PATH_SYNTAX_BAD, "absolute name under the pipe root -> %08lx",
       (unsigned long)status);
    if (disk != NULL)
    {
        status = create_pipe_at(&pipe, disk, W("\\prstest_root_abs"), FILE_CREATE, &iosb);
        ok(status == STATUS_OBJECT_PATH_SYNTAX_BAD, "absolute name under a disk directory -> %08lx",
           (unsigned long)status);
    }
    if (event != NULL)
    {
        status = create_pipe_at(&pipe, event, W("\\prstest_root_abs"), FILE_CREATE, &iosb);
        ok(status == STATUS_OBJECT_PATH_SYNTAX_BAD, "absolute name under an event -> %08lx",
           (unsigned long)status);
    }

    /* ...but the HANDLE is resolved above all of it
     * (server/request.c get_req_object_attributes, whose `get_handle_obj`
     * failure returns before create_named_object is called), so a root that
     * names nothing reports the handle even with an absolute name. */
    status =
        create_pipe_at(&pipe, (HANDLE)(ULONG_PTR)0x1234, pipe_name(7, NULL), FILE_CREATE, &iosb);
    ok(status == STATUS_INVALID_HANDLE, "named create under a dead root -> %08lx",
       (unsigned long)status);
    status = create_pipe_at(&pipe, (HANDLE)(ULONG_PTR)0x1234, W("\\prstest_root_abs"), FILE_CREATE,
                            &iosb);
    ok(status == STATUS_INVALID_HANDLE, "absolute name under a dead root -> %08lx",
       (unsigned long)status);

    if (end != NULL)
    {
        NtClose(end);
    }
    if (event != NULL)
    {
        NtClose(event);
    }
    if (disk != NULL)
    {
        NtClose(disk);
    }
    NtClose(root);
}

/* §5 — NtCreateFile with an EMPTY name relative to the device root handle.
 *
 * The lookup resolves to the root object itself and then asks it to open a
 * file; named_pipe_dir_open_file's own guard is `if (dir->fd) return
 * no_open_file(...)` — the root has already been turned into a file object,
 * so it refuses. A second root handle is NOT what this produces. */
static void test_open_empty_under_root(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE root = NULL, again = NULL;
    NTSTATUS status;

    root = open_pipe_root();
    if (root == NULL)
    {
        return;
    }
    status = open_at(&again, root, NULL, GENERIC_READ, 0, &iosb);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "empty open under the pipe root -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        NtClose(again);
    }
    NtClose(root);
}

START_TEST(pipe_root)
{
    test_empty_name_root();
    test_unnamed_has_no_name();
    test_open_relative_to_end();
    test_named_create_root();
    test_open_empty_under_root();
}
