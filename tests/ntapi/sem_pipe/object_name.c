/*
 * sem_pipe/object_name.c — what NtQueryObject(ObjectNameInformation) says
 * about a FILE handle.
 *
 * docs/21 W11's last small item: dlls/ntdll/tests/pipe.c :2849 and :2881 ask
 * this question of an UNNAMED pipe's two ends and want STATUS_OBJECT_PATH_
 * INVALID. The subject is wider than the assertions, which is why this file
 * covers named pipes, the pipe device's root directory and ordinary disk
 * files too: NtQueryObject answers off the object TYPE, so one hook decides
 * what EVERY file handle reports.
 *
 * The oracle's shape, and it is per object type rather than one walk
 * (third_party/wine):
 *
 *   server/object.c   default_get_full_name    walks name->parent to the root
 *                                              and returns NULL for an object
 *                                              that was never linked
 *   server/named_pipe.c
 *     named_pipe_get_full_name                 that walk, and NULL becomes
 *                                              STATUS_OBJECT_PATH_INVALID
 *     pipe_end_get_full_name                   an END defers to its PIPE, so
 *                                              both ends report one name
 *     named_pipe_dir_get_full_name             the device's name plus a '\'
 *   server/fd.c       default_fd_get_full_name the fd's captured nt_name
 *   server/handle.c   DECL_HANDLER(get_object_name)
 *                                              a NULL name with no error set
 *                                              is SUCCESS with an EMPTY name,
 *                                              which is what every
 *                                              no_get_full_name type (the
 *                                              console objects) answers
 *
 * Three things an implementation gets wrong by reaching for the obvious, and
 * each has its own section below:
 *
 *   - AN EMPTY NAME IS NOT THE ANSWER FOR "I HAVE NO NAME FOR THIS". A pipe
 *     with no name REFUSES; only a type that is nameless as a CLASS succeeds
 *     with nothing. Reporting the empty string for a named pipe is Art. 12's
 *     fabricated-plausible answer with no stub in it — the caller cannot tell
 *     two pipes apart and is not told that it cannot.
 *   - THE NAME BELONGS TO THE PIPE, NOT TO THE END OR THE HANDLE, and it
 *     lives exactly as long as the pipe's NAME does — which is the last
 *     INSTANCE, not the last handle (sem_pipe/pipe_lifetime.c's rule, asked
 *     here through a different syscall). A surviving client reports the name
 *     while a second instance is open and refuses once the last one goes.
 *   - THE TOO-SHORT ANSWER IS STATUS_BUFFER_OVERFLOW, not the
 *     STATUS_INFO_LENGTH_MISMATCH a registry key gets for the same mistake
 *     (sem_reg/key_object_name.c). Both file-ish get_full_name arms set it
 *     explicitly; the generic walk does not. Only a buffer between
 *     sizeof(OBJECT_NAME_INFORMATION) and the full size can see the
 *     difference — shorter than the struct is INFO_LENGTH_MISMATCH on both,
 *     forced one layer up (dlls/ntdll/unix/file.c NtQueryObject).
 *
 * WHAT THE TWO RUNNERS ARE ALLOWED TO DISAGREE ABOUT, measured rather than
 * assumed: the PREFIX of a disk file's name. The oracle reports the name its
 * fd captured at open — `\??\C:\prstest\objname.txt`, the DOS-device spelling
 * the caller used — because Wine's C: is a host directory and the server has
 * nothing else to report. proskrnl composes its volume DEVICE object's name
 * with the volume-relative path, `\Device\HarddiskVolume1\prstest\
 * objname.txt`, which is what NT answers. So §6 pins what is the same on both
 * — that the name ENDS with the file's path, that the directory's name is the
 * file's name minus its last component, and the whole length protocol — and
 * not the prefix. docs/03 "What a FILE handle is called in the object
 * namespace" carries the trade.
 *
 * ReturnLength on a REFUSAL is deliberately not asserted: the oracle zeroes it
 * at NtQueryObject's entry and proskrnl leaves the caller's value alone, and
 * nothing here is building that.
 *
 * §7 is the one block the oracle cannot be the spec for, and its comment says
 * why in the terms Art. 5 asks for: a name too long to fit the answer's own
 * UNICODE_STRING.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryObject(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

/* §7's over-long pipe name, and what a full answer for it would need:
 * `\Device\NamedPipe` (17) + `\` + 32760 characters, times two bytes, plus the
 * fixed struct and the terminator. Spelled as arithmetic so a reader can check
 * the 65574 the assertion wants against the name it is built from. */
#define LONG_NAME_UNITS  32760u
#define LONG_NAME_BYTES  ((17u + 1u + LONG_NAME_UNITS) * (ULONG)sizeof(WCHAR))
#define LONG_NAME_NEEDED ((ULONG)sizeof(UNICODE_STRING) + LONG_NAME_BYTES + (ULONG)sizeof(WCHAR))

/* The reported name, copied out of the query's buffer so a later query can
 * reuse it. Two slots, because §2 and §6 both compare two handles' answers. */
static WCHAR NameA[512];
static WCHAR NameB[512];

static ULONG wide_len(const WCHAR *s)
{
    ULONG n = 0;
    while (s[n] != 0)
        n++;
    return n;
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

/* Does `name` end with the wide literal `suffix`? */
static int ends_with(const WCHAR *name, const void *wideSuffix)
{
    const unsigned short *suffix = (const unsigned short *)wideSuffix;
    ULONG nameUnits = wide_len(name);
    ULONG suffixUnits = 0, i;

    while (suffix[suffixUnits] != 0)
        suffixUnits++;
    if (suffixUnits > nameUnits)
        return 0;
    for (i = 0; i < suffixUnits; i++)
    {
        if (lower(name[nameUnits - suffixUnits + i]) != lower((WCHAR)suffix[i]))
            return 0;
    }
    return 1;
}

/* Is `name` exactly `prefix` followed by the wide literal `tail`? */
static int equals_join(const WCHAR *name, const WCHAR *prefix, const void *wideTail)
{
    const unsigned short *tail = (const unsigned short *)wideTail;
    ULONG prefixUnits = wide_len(prefix);
    ULONG i = 0;

    while (i < prefixUnits)
    {
        if (name[i] == 0 || lower(name[i]) != lower(prefix[i]))
            return 0;
        i++;
    }
    while (tail[i - prefixUnits] != 0)
    {
        if (lower(name[i]) != lower((WCHAR)tail[i - prefixUnits]))
            return 0;
        i++;
    }
    return name[i] == 0;
}

/* ObjectNameInformation into `out`; *usedOut carries ReturnLength. Returns the
 * status. On success `out` holds the reported name, NUL-terminated by the
 * query itself (asserted here, since the terminator is part of the contract). */
static NTSTATUS query_object_name(HANDLE handle, WCHAR *out, ULONG outUnits, ULONG *usedOut)
{
    BYTE raw[1024];
    ULONG used = 0;
    NTSTATUS status;
    UNICODE_STRING *reported = (UNICODE_STRING *)raw;
    ULONG units;

    memset(raw, 0, sizeof(raw));
    out[0] = 0;
    status = NtQueryObject(handle, ObjectNameInformation, raw, sizeof(raw), &used);
    *usedOut = used;
    if (!NT_SUCCESS(status))
        return status;

    units = reported->Length / (ULONG)sizeof(WCHAR);
    ok(units < outUnits, "reported name fits (%lu units)", (unsigned long)units);
    if (units >= outUnits)
        units = outUnits - 1;
    memcpy(out, reported->Buffer, units * sizeof(WCHAR));
    out[units] = 0;
    ok(reported->Buffer == (WCHAR *)(raw + sizeof(UNICODE_STRING)),
       "Name.Buffer points just past the struct");
    ok(reported->MaximumLength == reported->Length + sizeof(WCHAR),
       "MaximumLength %u covers the terminator of a %u-byte name",
       (unsigned)reported->MaximumLength, (unsigned)reported->Length);
    ok(reported->Buffer[reported->Length / sizeof(WCHAR)] == 0, "reported name is NUL-terminated");
    ok(used == sizeof(UNICODE_STRING) + reported->Length + sizeof(WCHAR),
       "ReturnLength %lu for a %u-byte name", (unsigned long)used, (unsigned)reported->Length);
    return status;
}

/* The same query with a caller-chosen buffer size, for §3. */
static NTSTATUS query_object_name_sized(HANDLE handle, ULONG length, ULONG *usedOut)
{
    BYTE raw[1024];
    ULONG used = 0;
    NTSTATUS status;

    memset(raw, 0, sizeof(raw));
    status = NtQueryObject(handle, ObjectNameInformation, raw, length, &used);
    *usedOut = used;
    return status;
}

/* The pipe device's ROOT DIRECTORY: "\??\pipe\", WITH the trailing separator.
 * The spelling without it is the DEVICE FILE, which proskrnl cannot yet tell
 * from the directory (docs/21 W7's parser item, the same one `\??\C:` vs
 * `\??\C:\` asks) — so this file never uses it. */
static HANDLE open_pipe_root(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE root = NULL;
    NTSTATUS status;

    init_ustr(&name, W("\\??\\pipe\\"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    poison_iosb(&iosb);
    status =
        NtCreateFile(&root, GENERIC_READ | SYNCHRONIZE, &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                     FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, NULL, 0);
    ok(status == STATUS_SUCCESS, "open \\??\\pipe\\ -> %08lx", (unsigned long)status);
    return NT_SUCCESS(status) ? root : NULL;
}

/* An UNNAMED pipe: a PRESENT, zero-length ObjectName relative to a root,
 * which is what dlls/ntdll/tests/pipe.c test_empty_name passes. */
static NTSTATUS create_unnamed_pipe(HANDLE *handle, HANDLE root, IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    LARGE_INTEGER timeout;

    name.Length = 0;
    name.MaximumLength = 0;
    name.Buffer = NULL;
    init_attr(&attr, root, &name, OBJ_CASE_INSENSITIVE);
    timeout.QuadPart = -100 * 10000; /* 100 ms, relative */
    *handle = NULL;
    poison_iosb(iosb);
    return NtCreateNamedPipeFile(handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr, iosb,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE,
                                 FILE_SYNCHRONOUS_IO_NONALERT, FILE_PIPE_TYPE_BYTE,
                                 FILE_PIPE_BYTE_STREAM_MODE, FILE_PIPE_QUEUE_OPERATION, 3, 4096,
                                 4096, &timeout);
}

/* The client end of an unnamed pipe: an empty name relative to the SERVER
 * END's handle (server/named_pipe.c pipe_server_lookup_name, whose
 * pipe_server_open_file tail-calls the by-name client open). */
static NTSTATUS open_unnamed_client(HANDLE *handle, HANDLE server, IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    name.Length = 0;
    name.MaximumLength = 0;
    name.Buffer = NULL;
    init_attr(&attr, server, &name, OBJ_CASE_INSENSITIVE);
    *handle = NULL;
    poison_iosb(iosb);
    return NtCreateFile(handle, GENERIC_WRITE | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE, &attr, iosb,
                        NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

static HANDLE open_disk_file(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE file = NULL;
    NTSTATUS status;

    init_ustr(&name, W("\\??\\C:\\prstest\\objname.txt"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    poison_iosb(&iosb);
    status = NtCreateFile(&file, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr, &iosb, NULL,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                          FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ok(status == STATUS_SUCCESS, "create objname.txt -> %08lx", (unsigned long)status);
    return NT_SUCCESS(status) ? file : NULL;
}

static HANDLE open_disk_dir(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE dir = NULL;
    NTSTATUS status;

    init_ustr(&name, W("\\??\\C:\\prstest"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    poison_iosb(&iosb);
    status = NtCreateFile(&dir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attr, &iosb, NULL,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                          FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ok(status == STATUS_SUCCESS, "open \\??\\C:\\prstest -> %08lx", (unsigned long)status);
    return NT_SUCCESS(status) ? dir : NULL;
}

START_TEST(object_name)
{
    IO_STATUS_BLOCK iosb;
    HANDLE root = NULL, unnamed = NULL, unnamedClient = NULL;
    HANDLE server = NULL, client = NULL, server2 = NULL;
    HANDLE file = NULL, dir = NULL;
    NTSTATUS status;
    ULONG used = 0, needed = 0;

    /* --- §1 the pipe device's ROOT DIRECTORY names the device ----------- */

    root = open_pipe_root();
    if (root == NULL)
        return;
    status = query_object_name(root, NameA, 512, &used);
    ok(status == STATUS_SUCCESS, "root dir name -> %08lx", (unsigned long)status);
    ok(wide_equal(NameA, W("\\Device\\NamedPipe\\")), "root dir is the device plus a separator");

    /* --- §2 a NAMED pipe: the name is the PIPE's, and both ends have it - */

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_objname"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 3, &iosb);
    ok(status == STATUS_SUCCESS, "named pipe -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    status = query_object_name(server, NameA, 512, &used);
    ok(status == STATUS_SUCCESS, "named server name -> %08lx", (unsigned long)status);
    ok(wide_equal(NameA, W("\\Device\\NamedPipe\\prstest_objname")),
       "the server end reports the pipe's full path");
    needed = used;

    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_objname"), &iosb);
    ok(status == STATUS_SUCCESS, "named client -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = query_object_name(client, NameB, 512, &used);
        ok(status == STATUS_SUCCESS, "named client name -> %08lx", (unsigned long)status);
        /* The CLIENT end was never named itself — it defers to the pipe — so
         * an implementation that reported the name the OPEN used would pass
         * this and fail §5, where the pipe loses its name under a live
         * handle. */
        ok(wide_equal(NameB, W("\\Device\\NamedPipe\\prstest_objname")),
           "both ends of one pipe report one name");
    }

    /* --- §3 the length protocol ----------------------------------------- */

    /* Shorter than the fixed struct is INFO_LENGTH_MISMATCH, and that arm is
     * one layer above the object type (dlls/ntdll/unix/file.c NtQueryObject
     * forces it whatever the name query answered). */
    status = query_object_name_sized(server, 0, &used);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "zero-length buffer -> %08lx", (unsigned long)status);
    status = query_object_name_sized(server, sizeof(UNICODE_STRING) - 1, &used);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "buffer one byte short of the struct -> %08lx",
       (unsigned long)status);

    /* From the struct's own size up to the full size is BUFFER_OVERFLOW —
     * where a registry key answers INFO_LENGTH_MISMATCH for exactly the same
     * mistake (sem_reg/key_object_name.c) — and ReturnLength is the FULL size
     * however short the buffer was. */
    used = 0;
    status = query_object_name_sized(server, sizeof(UNICODE_STRING), &used);
    ok(status == STATUS_BUFFER_OVERFLOW, "struct-sized buffer -> %08lx", (unsigned long)status);
    ok(used == needed, "ReturnLength %lu is the full size %lu", (unsigned long)used,
       (unsigned long)needed);
    used = 0;
    status = query_object_name_sized(server, needed - 1, &used);
    ok(status == STATUS_BUFFER_OVERFLOW, "one byte short of the name -> %08lx",
       (unsigned long)status);
    ok(used == needed, "ReturnLength %lu on the one-byte-short buffer", (unsigned long)used);
    used = 0;
    status = query_object_name_sized(server, needed, &used);
    ok(status == STATUS_SUCCESS, "the exact size -> %08lx", (unsigned long)status);
    ok(used == needed, "ReturnLength %lu on the exact buffer", (unsigned long)used);

    /* --- §4 an UNNAMED pipe REFUSES, before any sizing ------------------ */

    status = create_unnamed_pipe(&unnamed, root, &iosb);
    ok(status == STATUS_SUCCESS, "unnamed pipe -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = query_object_name_sized(unnamed, 1024, &used);
        ok(status == STATUS_OBJECT_PATH_INVALID, "unnamed server end -> %08lx",
           (unsigned long)status);
        /* No buffer is big enough and none is too small: an implementation
         * that sized first answers a length error here and passes the line
         * above. (pipe.c:2849's own shape, with the winetest's big buffer.) */
        status = query_object_name_sized(unnamed, 0, &used);
        ok(status == STATUS_OBJECT_PATH_INVALID, "unnamed server end, zero-length buffer -> %08lx",
           (unsigned long)status);

        status = open_unnamed_client(&unnamedClient, unnamed, &iosb);
        ok(status == STATUS_SUCCESS, "unnamed client -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            status = query_object_name_sized(unnamedClient, 1024, &used);
            ok(status == STATUS_OBJECT_PATH_INVALID, "unnamed client end -> %08lx",
               (unsigned long)status);
        }
    }

    /* --- §5 the name lives as long as the pipe's NAME does -------------- */

    status = create_pipe_instance(&server2, W("\\??\\pipe\\prstest_objname"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 3, &iosb);
    ok(status == STATUS_SUCCESS, "second instance -> %08lx", (unsigned long)status);
    NtClose(server);
    server = NULL;
    if (client != NULL)
    {
        /* One instance left: the pipe is still in the device's namespace, so
         * the client of the CLOSED instance still reports the name. */
        status = query_object_name(client, NameA, 512, &used);
        ok(status == STATUS_SUCCESS, "client name, one instance left -> %08lx",
           (unsigned long)status);
        ok(wide_equal(NameA, W("\\Device\\NamedPipe\\prstest_objname")),
           "the name survives its own instance");
    }
    if (server2 != NULL)
    {
        NtClose(server2);
        server2 = NULL;
    }
    if (client != NULL)
    {
        /* The last instance is gone, so the pipe was unlinked — and this
         * handle, which never changed, now has no path. */
        status = query_object_name_sized(client, 1024, &used);
        ok(status == STATUS_OBJECT_PATH_INVALID, "client name, no instances left -> %08lx",
           (unsigned long)status);
        NtClose(client);
        client = NULL;
    }

    /* --- §6 a disk file and its directory ------------------------------- */

    /* The directory first: its FILE_OPEN_IF is what CREATES the shared test
     * directory on a fresh image, and the file below lives inside it. */
    dir = open_disk_dir();
    file = open_disk_file();
    if (file != NULL && dir != NULL)
    {
        status = query_object_name(file, NameA, 512, &used);
        ok(status == STATUS_SUCCESS, "disk file name -> %08lx", (unsigned long)status);
        needed = used;
        ok(ends_with(NameA, W("\\prstest\\objname.txt")), "the name ends with the file's path");

        status = query_object_name(dir, NameB, 512, &used);
        ok(status == STATUS_SUCCESS, "disk dir name -> %08lx", (unsigned long)status);
        /* The two answers agree about everything but the last component,
         * whatever the runner spells the volume as — which is the part of a
         * composed name an implementation can get wrong without any single
         * name looking wrong. */
        ok(equals_join(NameA, NameB, W("\\objname.txt")),
           "the file's name is the directory's plus its own component");

        used = 0;
        status = query_object_name_sized(file, sizeof(UNICODE_STRING), &used);
        ok(status == STATUS_BUFFER_OVERFLOW, "disk file, struct-sized buffer -> %08lx",
           (unsigned long)status);
        ok(used == needed, "disk file ReturnLength %lu is the full size %lu", (unsigned long)used,
           (unsigned long)needed);
    }

    /* --- §7 a name too long to be REPORTED ------------------------------ */

    /* A pipe's name is the caller's ObjectName, bounded only by
     * UNICODE_STRING's own USHORT — so a 32760-character name under
     * `\Device\NamedPipe` composes to 65556 bytes, which the answer's OWN
     * UNICODE_STRING cannot describe. Both runners accept the create. */
    {
        static WCHAR longName[LONG_NAME_UNITS + 1];
        static BYTE hugeBuffer[LONG_NAME_NEEDED + 64];
        UNICODE_STRING longAttr;
        OBJECT_ATTRIBUTES attr;
        LARGE_INTEGER timeout;
        HANDLE longPipe = NULL;
        ULONG i;

        for (i = 0; i < LONG_NAME_UNITS; i++)
            longName[i] = 'a';
        longName[LONG_NAME_UNITS] = 0;
        longAttr.Length = (USHORT)(LONG_NAME_UNITS * sizeof(WCHAR));
        longAttr.MaximumLength = longAttr.Length;
        longAttr.Buffer = longName;
        init_attr(&attr, root, &longAttr, OBJ_CASE_INSENSITIVE);
        timeout.QuadPart = -100 * 10000; /* 100 ms, relative */
        poison_iosb(&iosb);
        status = NtCreateNamedPipeFile(&longPipe, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr,
                                       &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE,
                                       FILE_SYNCHRONOUS_IO_NONALERT, FILE_PIPE_TYPE_BYTE,
                                       FILE_PIPE_BYTE_STREAM_MODE, FILE_PIPE_QUEUE_OPERATION, 3,
                                       4096, 4096, &timeout);
        ok(status == STATUS_SUCCESS, "32760-character pipe name -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            /* A SHORT buffer is answered normally, and this is the case the
             * oracle can still be the spec for: the length error carries the
             * whole 65574 an answer would need. So the refusal below must sit
             * BELOW the size protocol, not in front of it. */
            used = 0;
            status = query_object_name_sized(longPipe, sizeof(UNICODE_STRING), &used);
            ok(status == STATUS_BUFFER_OVERFLOW, "long name, struct-sized buffer -> %08lx",
               (unsigned long)status);
            ok(used == LONG_NAME_NEEDED, "long name ReturnLength %lu", (unsigned long)used);

            /* And with a buffer that IS big enough, the answer does not exist:
             * OBJECT_NAME_INFORMATION reports a UNICODE_STRING, whose Length
             * and MaximumLength are USHORTs (Microsoft, "OBJECT_NAME_INFORMATION
             * structure", learn.microsoft.com/windows/win32/api/winternl/
             * ns-winternl-object_name_information, and UNICODE_STRING beside
             * it), so 65556 bytes cannot be described at all.
             *
             * beyond_oracle because the oracle has no VALID answer here rather
             * than a different one — measured, not inferred: it returns SUCCESS
             * reporting Length 20 and MaximumLength 22, which is 65556 truncated
             * into the USHORT by `p->Name.Length = res` (dlls/ntdll/unix/file.c
             * NtQueryObject). That names a DIFFERENT object, so repeating it
             * would be the fabricated-plausible answer Art. 12 forbids. */
            beyond_oracle
            {
                ULONG hugeUsed = 0;
                memset(hugeBuffer, 0, sizeof(hugeBuffer));
                status = NtQueryObject(longPipe, ObjectNameInformation, hugeBuffer,
                                       sizeof(hugeBuffer), &hugeUsed);
                ok(status == STATUS_NAME_TOO_LONG, "long name, ample buffer -> %08lx",
                   (unsigned long)status);
            }
            NtClose(longPipe);
        }
    }

    if (file != NULL)
        NtClose(file);
    if (dir != NULL)
        NtClose(dir);
    if (unnamedClient != NULL)
        NtClose(unnamedClient);
    if (unnamed != NULL)
        NtClose(unnamed);
    NtClose(root);
}
