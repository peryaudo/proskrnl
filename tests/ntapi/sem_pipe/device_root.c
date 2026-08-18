/*
 * sem_pipe/device_root.c — `\Device\NamedPipe` is not `\Device\NamedPipe\`.
 *
 * docs/21 W7's parser question, and the last two failing assertions of
 * dlls/ntdll/tests/pipe.c test_empty_name: :2787 (FSCTL_PIPE_WAIT on the
 * DEVICE is STATUS_ILLEGAL_FUNCTION, where on the root DIRECTORY it is the
 * name lookup) and :2810 (a NAMED create relative to a handle on the DEVICE
 * is STATUS_OBJECT_NAME_INVALID, where relative to the DIRECTORY the same
 * call succeeds — the winetest's own :2932).
 *
 * THE WHOLE DISTINCTION IS ONE `if` IN THE ORACLE, and it is about the
 * REMAINING NAME rather than about anything the device stores
 * (third_party/wine server/named_pipe.c named_pipe_device_lookup_name):
 *
 *     if (!name) return NULL;                  // open the device itself
 *     if (!name->len && name->str) { ... }     // open the root directory
 *
 * `name == NULL` is server/object.c lookup_named_object's `if (!name_tmp.len)
 * ptr = NULL` — the walk consumed the whole path — while a name that is
 * present and EMPTY is what a trailing separator leaves behind. So the two
 * spellings differ only in a pointer, and everything below follows from which
 * of the oracle's two objects the open produced:
 *
 *   `\Device\NamedPipe`   a named_pipe_device_file: no_lookup_name,
 *                         no_link_name, named_pipe_device_ioctl,
 *                         named_pipe_device_file_get_full_name;
 *   `\Device\NamedPipe\`  a named_pipe_dir: named_pipe_dir_lookup_name (which
 *                         forwards to the device's flat namespace),
 *                         named_pipe_dir_ioctl (FSCTL_PIPE_WAIT, then a tail
 *                         call onto the device's ladder),
 *                         named_pipe_dir_get_full_name (the device's name plus
 *                         a separator).
 *
 * Four things an implementation that special-cases the winetest's two
 * assertions gets wrong, and each has its own section:
 *
 *   - THE DEVICE'S REFUSAL PRECEDES THE VERB'S ARGUMENTS AND ITS LOOKUP.
 *     named_pipe_device_ioctl answers FSCTL_PIPE_WAIT above everything, so a
 *     wait for a pipe that EXISTS and is listening is still
 *     STATUS_ILLEGAL_FUNCTION, and so is one whose input buffer is too short
 *     to hold the name it claims — the very check the DIRECTORY makes first
 *     (§2).
 *   - THE CREATE AND THE OPEN REFUSE DIFFERENTLY. A named create dies in
 *     named_pipe_link_name (STATUS_OBJECT_NAME_INVALID: this parent does not
 *     reach the pipe namespace); a named OPEN dies in open_named_object, whose
 *     complaint is that no_lookup_name left the name unconsumed
 *     (STATUS_OBJECT_NAME_NOT_FOUND). One fact, two statuses, and only the
 *     open path can see the second (§3, §4).
 *   - THE EMPTY NAME IS BLIND TO WHICH ROOT IT IS. create_named_object's
 *     empty-name arm allocates an UNLINKED pipe and never looks at the parent
 *     (server/object.c), so an unnamed create succeeds through BOTH handles —
 *     which the winetest marks todo_wine at :2800, i.e. NT refuses it and the
 *     pinned oracle does not. Art. 6: the oracle is the spec, so this is
 *     pinned as measured and NOT "fixed" toward NT (§5).
 *   - AND THE SPLIT IS NARROW. Every other pipe FSCTL answers identically
 *     through both handles (sem_pipe/device_ioctl.c §4 measures the whole
 *     eight-row matrix twice), because named_pipe_dir_ioctl's default arm is a
 *     tail call. FSCTL_PIPE_WAIT is the one arm that parts.
 *
 * Every pipe here is named prstest_droot_* so the buckets cannot collide in
 * the oracle's shared wineserver namespace.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryObject(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN);

/* Open one of the two spellings, exactly as the winetest opens them: a plain
 * FILE_OPEN with no options, so nothing but the NAME can decide which object
 * comes back. */
static NTSTATUS open_root(HANDLE *handle, const void *wideName)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;

    init_ustr(&name, wideName);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    *handle = NULL;
    poison_iosb(&iosb);
    return NtCreateFile(handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr, &iosb, NULL,
                        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0,
                        NULL, 0);
}

/* FSCTL_PIPE_WAIT for `name` (relative to the device, as WaitNamedPipeW sends
 * it). `shortBuffer` sends a length that stops inside the name — the
 * DIRECTORY's first check, and the thing the DEVICE must answer above. */
static NTSTATUS wait_for(HANDLE root, const void *wideName, int timeoutMs, int shortBuffer,
                         IO_STATUS_BLOCK *iosb)
{
    unsigned char raw[sizeof(SEM_PIPE_WAIT_FOR_BUFFER) + 64 * sizeof(WCHAR)];
    SEM_PIPE_WAIT_FOR_BUFFER *wait = (SEM_PIPE_WAIT_FOR_BUFFER *)raw;
    const unsigned short *p = (const unsigned short *)wideName;
    ULONG len = 0;

    while (p[len])
        len++;
    wait->Timeout.QuadPart = -(LONGLONG)timeoutMs * 10000;
    wait->TimeoutSpecified = TRUE;
    wait->NameLength = len * sizeof(WCHAR);
    memcpy(wait->Name, p, len * sizeof(WCHAR));
    poison_iosb(iosb);
    return NtFsControlFile(root, NULL, NULL, NULL, iosb, FSCTL_PIPE_WAIT, wait,
                           shortBuffer ? (ULONG)sizeof(SEM_PIPE_WAIT_FOR_BUFFER)
                                       : (ULONG)offsetof(SEM_PIPE_WAIT_FOR_BUFFER, Name[len]),
                           NULL, 0);
}

/* NtCreateNamedPipeFile relative to `root`. `wideName == NULL` is the EMPTY
 * name — a present UNICODE_STRING of length zero, which is what the winetest
 * passes and what the server reads as "unnamed". */
static NTSTATUS create_pipe_at(HANDLE *handle, HANDLE root, const void *wideName,
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
        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT,
        FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, FILE_PIPE_QUEUE_OPERATION, 3, 4096, 4096,
        &timeout);
}

/* NtCreateFile(FILE_OPEN) relative to `root`, same empty-name convention. */
static NTSTATUS open_at(HANDLE *handle, HANDLE root, const void *wideName, IO_STATUS_BLOCK *iosb)
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
    return NtCreateFile(handle, GENERIC_READ | SYNCHRONIZE, &attr, iosb, NULL,
                        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

static WCHAR ReportedName[512];

/* ObjectNameInformation, copied out NUL-terminated. */
static NTSTATUS query_object_name(HANDLE handle, WCHAR *out, ULONG outUnits)
{
    BYTE raw[1024];
    ULONG used = 0;
    UNICODE_STRING *reported = (UNICODE_STRING *)raw;
    ULONG units;
    NTSTATUS status;

    memset(raw, 0, sizeof(raw));
    out[0] = 0;
    status = NtQueryObject(handle, ObjectNameInformation, raw, sizeof(raw), &used);
    if (!NT_SUCCESS(status))
        return status;
    units = reported->Length / (ULONG)sizeof(WCHAR);
    if (units >= outUnits)
        units = outUnits - 1;
    memcpy(out, reported->Buffer, units * sizeof(WCHAR));
    out[units] = 0;
    return status;
}

static WCHAR lower(WCHAR c)
{
    return (c >= 'A' && c <= 'Z') ? (WCHAR)(c - 'A' + 'a') : c;
}

static int wide_equal(const WCHAR *a, const void *wideB)
{
    const unsigned short *b = (const unsigned short *)wideB;
    ULONG i = 0;
    while (a[i] != 0 && b[i] != 0 && lower(a[i]) == lower((WCHAR)b[i]))
        i++;
    return a[i] == 0 && b[i] == 0;
}

START_TEST(device_root)
{
    IO_STATUS_BLOCK iosb;
    HANDLE device = NULL, dir = NULL;
    HANDLE listener = NULL, pipe = NULL, opened = NULL, unnamed = NULL, event = NULL;
    NTSTATUS status;

    /* --- §1 both spellings open, and they are two different objects ------ */

    status = open_root(&device, W("\\Device\\NamedPipe"));
    ok(status == STATUS_SUCCESS, "open \\Device\\NamedPipe -> %08lx", (unsigned long)status);
    status = open_root(&dir, W("\\Device\\NamedPipe\\"));
    ok(status == STATUS_SUCCESS, "open \\Device\\NamedPipe\\ -> %08lx", (unsigned long)status);
    if (device == NULL || dir == NULL)
    {
        skip("no named-pipe device root");
        return;
    }

    /* A listening instance for §2 to ask both handles about. */
    status = create_pipe_instance(&listener, W("\\??\\pipe\\prstest_droot_wait"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 3, &iosb);
    ok(status == STATUS_SUCCESS, "listener create -> %08lx", (unsigned long)status);

    /* --- §2 FSCTL_PIPE_WAIT is the one verb the two ladders disagree on -- */

    /* The DIRECTORY serves it: an absent name is the lookup's own answer, a
     * listening one is immediate success (sem_pipe/pipe_wait.c pins the rest
     * of that ladder — the two rows here exist to be compared with the four
     * below). */
    status = wait_for(dir, W("prstest_droot_absent"), 50, 0, &iosb);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "dir wait for an absent name -> %08lx",
       (unsigned long)status);
    status = wait_for(dir, W("prstest_droot_wait"), 5000, 0, &iosb);
    ok(status == STATUS_SUCCESS, "dir wait for a listener -> %08lx", (unsigned long)status);

    /* The DEVICE does not have the verb at all, and says so ABOVE both the
     * lookup and the argument check: the same three calls the directory
     * answers three different ways are one answer here. The listening row is
     * what separates "refuses the verb" from "refuses because the name is
     * absent" — an implementation that put the ILLEGAL_FUNCTION after the
     * lookup passes the absent row and fails this one. */
    status = wait_for(device, W("prstest_droot_absent"), 50, 0, &iosb);
    ok(status == STATUS_ILLEGAL_FUNCTION, "device wait for an absent name -> %08lx",
       (unsigned long)status);
    status = wait_for(device, W("prstest_droot_wait"), 5000, 0, &iosb);
    ok(status == STATUS_ILLEGAL_FUNCTION, "device wait for a listener -> %08lx",
       (unsigned long)status);
    status = wait_for(device, W("prstest_droot_wait"), 50, 1, &iosb);
    ok(status == STATUS_ILLEGAL_FUNCTION, "device wait with a short buffer -> %08lx",
       (unsigned long)status);
    /* ...and the directory's own first check is that same short buffer, which
     * is what makes the ordering above measurable rather than incidental. */
    status = wait_for(dir, W("prstest_droot_wait"), 50, 1, &iosb);
    ok(status == STATUS_INVALID_PARAMETER, "dir wait with a short buffer -> %08lx",
       (unsigned long)status);

    /* --- §3 a NAMED create: the directory reaches the namespace, the
     *         device does not ---------------------------------------------- */

    status = create_pipe_at(&pipe, dir, W("prstest_droot_a0"), &iosb);
    ok(status == STATUS_SUCCESS, "named create under the directory -> %08lx",
       (unsigned long)status);
    if (pipe != NULL)
        NtClose(pipe);

    status = create_pipe_at(&pipe, device, W("prstest_droot_a1"), &iosb);
    ok(status == STATUS_OBJECT_NAME_INVALID, "named create under the device -> %08lx",
       (unsigned long)status);
    ok(pipe == NULL, "a refused create left the handle slot alone");
    if (pipe != NULL)
        NtClose(pipe);

    /* The winetest's :2810 and :2932 verbatim: the SAME name carrying a
     * component separator, which the flat pipe namespace reads as one key
     * rather than a path. The device refuses it for being under the wrong
     * parent, not for its punctuation. */
    status = create_pipe_at(&pipe, device, W("prstest_droot_a2\\sub"), &iosb);
    ok(status == STATUS_OBJECT_NAME_INVALID, "separated name under the device -> %08lx",
       (unsigned long)status);
    if (pipe != NULL)
        NtClose(pipe);
    status = create_pipe_at(&pipe, dir, W("prstest_droot_a2\\sub"), &iosb);
    ok(status == STATUS_SUCCESS, "separated name under the directory -> %08lx",
       (unsigned long)status);
    if (pipe != NULL)
        NtClose(pipe);

    /* An ABSOLUTE name under either root is refused a frame ABOVE the link,
     * by lookup_named_object's first guard — so the device answers the syntax
     * error here and not the name error it gives every relative name. */
    status = create_pipe_at(&pipe, device, W("\\??\\pipe\\prstest_droot_a3"), &iosb);
    ok(status == STATUS_OBJECT_PATH_SYNTAX_BAD, "absolute name under the device -> %08lx",
       (unsigned long)status);
    if (pipe != NULL)
        NtClose(pipe);

    /* --- §4 a NAMED open refuses with the OTHER status -------------------- */

    status = create_pipe_instance(&pipe, W("\\??\\pipe\\prstest_droot_open"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 3, &iosb);
    ok(status == STATUS_SUCCESS, "open-target create -> %08lx", (unsigned long)status);

    status = open_at(&opened, dir, W("prstest_droot_open"), &iosb);
    ok(status == STATUS_SUCCESS, "named open under the directory -> %08lx", (unsigned long)status);
    if (opened != NULL)
        NtClose(opened);

    /* The pipe EXISTS; the device is simply not a parent the name can be
     * looked up under, and open_named_object reports the unconsumed name
     * rather than the missing object. */
    opened = NULL;
    status = open_at(&opened, device, W("prstest_droot_open"), &iosb);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "named open under the device -> %08lx",
       (unsigned long)status);
    ok(opened == NULL, "a refused open left the handle slot alone");
    if (opened != NULL)
        NtClose(opened);

    /* An EMPTY name resolves to the root itself, which is already open — both
     * spellings say so, and they reach it by different routes
     * (no_lookup_name's own NULL arm for the device; named_pipe_dir_open_file's
     * `if (dir->fd)` for the directory). */
    opened = NULL;
    status = open_at(&opened, device, NULL, &iosb);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "empty open under the device -> %08lx",
       (unsigned long)status);
    if (opened != NULL)
        NtClose(opened);
    opened = NULL;
    status = open_at(&opened, dir, NULL, &iosb);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "empty open under the directory -> %08lx",
       (unsigned long)status);
    if (opened != NULL)
        NtClose(opened);

    /* --- §5 the UNNAMED create ignores which root it is ------------------- */

    status = create_pipe_at(&unnamed, dir, NULL, &iosb);
    ok(status == STATUS_SUCCESS, "unnamed create under the directory -> %08lx",
       (unsigned long)status);
    if (unnamed != NULL)
        NtClose(unnamed);
    unnamed = NULL;
    status = create_pipe_at(&unnamed, device, NULL, &iosb);
    ok(status == STATUS_SUCCESS, "unnamed create under the device -> %08lx", (unsigned long)status);
    if (unnamed != NULL)
        NtClose(unnamed);

    /* ...and it is blind to the root's TYPE entirely, not merely to which of
     * the two pipe roots it is: an EVENT is a legal parent for an unnamed
     * pipe (sem_pipe/pipe_root.c §1 has the rest of that ladder). Repeated
     * here because it is what stops "the device refuses named creates" from
     * being implemented as "the device refuses creates". */
    unnamed = NULL;
    status = NtCreateEvent(&event, GENERIC_ALL, NULL, 0 /* NotificationEvent */, FALSE);
    ok(status == STATUS_SUCCESS, "scratch event -> %08lx", (unsigned long)status);
    status = create_pipe_at(&unnamed, event, NULL, &iosb);
    ok(status == STATUS_SUCCESS, "unnamed create under an event -> %08lx", (unsigned long)status);
    if (unnamed != NULL)
        NtClose(unnamed);
    if (event != NULL)
        NtClose(event);

    /* --- §6 what each root is CALLED -------------------------------------- */

    /* named_pipe_device_file_get_full_name is the device's own name;
     * named_pipe_dir_get_full_name is that name with a separator appended.
     * The separator is the whole difference, and it is the only place the
     * distinction is visible to a caller holding just one of the handles. */
    status = query_object_name(device, ReportedName, 512);
    ok(status == STATUS_SUCCESS, "device object name -> %08lx", (unsigned long)status);
    ok(wide_equal(ReportedName, W("\\Device\\NamedPipe")),
       "the device reports its own name, with no separator");
    status = query_object_name(dir, ReportedName, 512);
    ok(status == STATUS_SUCCESS, "directory object name -> %08lx", (unsigned long)status);
    ok(wide_equal(ReportedName, W("\\Device\\NamedPipe\\")),
       "the root directory reports the device plus a separator");

    if (listener != NULL)
        NtClose(listener);
    if (pipe != NULL)
        NtClose(pipe);
    NtClose(dir);
    NtClose(device);
}
