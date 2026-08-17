/*
 * sem_file/access_info.c — NtQueryInformationFile(FileAccessInformation),
 * class 8: what it reports, and the ladder it reports it through.
 *
 * docs/21 W11, the last item inside ntdll:pipe's measured prefix. The pair
 * PANICS on this class (dlls/ntdll/tests/pipe.c :1015, `_test_file_access`
 * on a SYNCHRONIZE-only client end), so nothing behind it has ever run.
 *
 * The class is one ACCESS_MASK and both halves of it are easy to get wrong.
 *
 *   THE VALUE is the access of the HANDLE IN THE CALLER'S HAND, not the
 *   access the OPEN was granted: `info.AccessFlags = get_handle_access(
 *   current->process, handle )` (server/fd.c default_fd_get_file_info), which
 *   reads `entry->access` — the handle table's word. Several handles can name
 *   one file object and NtDuplicateObject grants specific bits verbatim, so
 *   the two quantities are separable, and only a duplicate separates them.
 *   docs/21 predicted this class was "the granted access of the handle, which
 *   FILE_OBJECT.grantedAccess already holds"; the second clause is false and
 *   §1 below is what says so.
 *
 *   THE ORDER is the inverse of every table-driven class.
 *   info_sizes[FileAccessInformation] is 0 (dlls/ntdll/unix/file.c
 *   NtQueryInformationFile), so ntdll makes NO length check and hands the
 *   call straight to server_get_file_info. The HANDLE is resolved first
 *   (server/fd.c DECL_HANDLER(get_file_info): get_handle_fd_obj(..., 0)) and
 *   the length is checked afterwards, inside the fd op. FilePipeInformation
 *   through the same junk handle with the same too-short buffer reports the
 *   LENGTH, because its info_sizes[] entry is non-zero and that check sits in
 *   ntdll above the server call. §4 measures both in one place: an
 *   implementation with a single length gate ahead of a single handle gate
 *   cannot answer them both.
 *
 * The access the CLASS itself demands is nothing at all — get_handle_fd_obj
 * is called with an access mask of 0 — which is what makes the winetest's
 * SYNCHRONIZE-only handle (§3) a success rather than an ACCESS_DENIED, and
 * separates this class from the two pipe classes one function over
 * (FILE_READ_ATTRIBUTES, pinned by sem_pipe/create_refusals.c).
 *
 * Not pinned here: whether a FAILING NtQueryInformationFile writes the
 * caller's IOSB. The oracle writes io->Status on nearly every return from the
 * syscall (`return io->Status = ...`) and proskrnl writes it only on success;
 * that is a whole-syscall convention with a dozen classes in it, not this
 * class's rule, and picking it up for class 8 alone would make the syscall
 * answer two ways. Information on SUCCESS is this class's business and is
 * pinned (§5).
 */
#include "util.h"

/* Prototypes mingw's winternl.h omits (as wine/include/winternl.h). */
NTSYSAPI NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG,
                                          ULONG);
NTSYSAPI NTSTATUS NTAPI NtCreateNamedPipeFile(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                              ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG,
                                              ULONG, ULONG, PLARGE_INTEGER);
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0) /* wine/include/winternl.h */

/* wine/include/winternl.h FILE_PIPE_INFORMATION; mingw's winternl.h carries
 * only FILE_PIPE_LOCAL_INFORMATION, and sem_pipe/util.h's copy is in the
 * other bucket. Used by §4 as the class whose length check runs EARLIER. */
typedef struct
{
    ULONG ReadMode;
    ULONG CompletionMode;
} SEM_FILE_PIPE_INFORMATION;

/* The buffer is a struct with a tail so "wrote exactly four bytes" is
 * observable, and every byte of it is poisoned so an untouched field reads
 * back as the poison rather than as a plausible zero. */
typedef struct
{
    FILE_ACCESS_INFORMATION info;
    ULONG tail;
} ACCESS_BUFFER;

#define BUFFER_POISON 0x55555555u

static NTSTATUS query_access_len(HANDLE handle, ULONG length, ACCESS_BUFFER *buffer,
                                 IO_STATUS_BLOCK *iosb)
{
    memset(buffer, 0x55, sizeof(*buffer));
    poison_iosb(iosb);
    return NtQueryInformationFile(handle, iosb, buffer, length, FileAccessInformation);
}

/* One well-formed query; returns the reported mask through *flagsOut. */
static NTSTATUS query_access(HANDLE handle, ACCESS_MASK *flagsOut)
{
    ACCESS_BUFFER buffer;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status =
        query_access_len(handle, (ULONG)sizeof(FILE_ACCESS_INFORMATION), &buffer, &iosb);

    *flagsOut = buffer.info.AccessFlags;
    return status;
}

/* Assert one handle's reported access, naming the case. */
static void check_access(int line, HANDLE handle, ACCESS_MASK expected, const char *what)
{
    ACCESS_MASK flags = BUFFER_POISON;
    NTSTATUS status = query_access(handle, &flags);

    ntapi_okv(status == STATUS_SUCCESS, __FILE__, line, "%s: query -> %08lx", what,
              (unsigned long)status);
    ntapi_okv(flags == expected, __FILE__, line, "%s: AccessFlags %08lx, wanted %08lx", what,
              (unsigned long)flags, (unsigned long)expected);
}
#define CHECK_ACCESS(h, e, what) check_access(__LINE__, (h), (e), (what))

/* --- §1 the value belongs to the HANDLE, not to the open ------------------ */

/* The discriminating case of the whole file. Both handles below name ONE file
 * object; a kernel that answers from the file object's own granted access
 * reports the create's mask through the weakened duplicate and passes every
 * other case here. */
static void test_value_is_the_handles_access(HANDLE dir)
{
    static const ACCESS_MASK opened =
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    static const ACCESS_MASK weakened = FILE_READ_DATA | SYNCHRONIZE;
    IO_STATUS_BLOCK iosb;
    HANDLE file = NULL, weak = NULL, empty = NULL;
    NTSTATUS status;

    scrub_file(dir, W("access.bin"));
    status = open_file(&file, dir, W("access.bin"), opened, 0, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create access.bin -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    CHECK_ACCESS(file, opened, "the opened handle");

    status = NtDuplicateObject(NtCurrentProcess(), file, NtCurrentProcess(), &weak, weakened, 0, 0);
    ok(status == STATUS_SUCCESS, "duplicate without FILE_WRITE_DATA -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        CHECK_ACCESS(weak, weakened, "the weakened duplicate");
        CHECK_ACCESS(file, opened, "the original, after the duplicate");
        NtClose(weak);
    }

    /* An access word of ZERO is a legal handle and a legal answer. Nothing in
     * dup_handle refuses it (server/handle.c: the mapped access is stored as
     * it comes, and only open_object's `if (!(access = ...))` guard rejects an
     * empty mask), and the class demands no access, so the query succeeds and
     * reports the empty word. An implementation that treated 0 as "unknown,
     * fall back to the file object" answers `opened` here. */
    status = NtDuplicateObject(NtCurrentProcess(), file, NtCurrentProcess(), &empty, 0, 0, 0);
    ok(status == STATUS_SUCCESS, "duplicate with an empty mask -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        CHECK_ACCESS(empty, 0, "the zero-access duplicate");
        NtClose(empty);
    }

    NtClose(file);
    scrub_file(dir, W("access.bin"));
}

/* --- §2 the generic bits are resolved at the OPEN ------------------------- */

/* map_access runs when the handle is created, so no GENERIC_* or
 * MAXIMUM_ALLOWED bit can ever appear in the answer: what comes back is the
 * specific rights the mapping produced. */
static void test_generic_bits_are_resolved(HANDLE dir)
{
    static const ACCESS_MASK generics =
        GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL;
    IO_STATUS_BLOCK iosb;
    HANDLE file = NULL;
    ACCESS_MASK flags = BUFFER_POISON;
    NTSTATUS status;

    scrub_file(dir, W("generic.bin"));
    status = open_file(&file, dir, W("generic.bin"), GENERIC_READ, 0, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create generic.bin -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* The file type's mapping is { FILE_GENERIC_READ, FILE_GENERIC_WRITE,
     * FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS } (server/file.c file_map_access),
     * and FILE_GENERIC_READ already carries SYNCHRONIZE — so the whole word is
     * predictable and asserted, not merely bit-tested. */
    CHECK_ACCESS(file, FILE_GENERIC_READ, "a GENERIC_READ open");
    NtClose(file);

    /* MAXIMUM_ALLOWED resolves to whatever the descriptor grants, which is a
     * property of the volume rather than of the boundary — so the RULE is
     * asserted (no generic bit survives, and something concrete was granted)
     * and the exact word is not. */
    file = NULL;
    status = open_file(&file, dir, W("generic.bin"), MAXIMUM_ALLOWED, 0, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "open generic.bin MAXIMUM_ALLOWED -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = query_access(file, &flags);
        ok(status == STATUS_SUCCESS, "MAXIMUM_ALLOWED: query -> %08lx", (unsigned long)status);
        ok((flags & (generics | MAXIMUM_ALLOWED)) == 0,
           "MAXIMUM_ALLOWED: no unmapped bit survives (%08lx)", (unsigned long)flags);
        ok((flags & FILE_READ_DATA) != 0, "MAXIMUM_ALLOWED: FILE_READ_DATA granted (%08lx)",
           (unsigned long)flags);
        NtClose(file);
    }

    scrub_file(dir, W("generic.bin"));
}

/* --- §3 the class demands no access at all -------------------------------- */

/* The winetest's own shape, twice: `_test_file_access(hClient, SYNCHRONIZE)`
 * asks a handle with no read, no write and no attribute rights for its own
 * access word and expects SYNCHRONIZE back. The pipe case is the one
 * ntdll:pipe:1015 runs; the plain-file case says the rule is the class's and
 * not npfs's. */
static void test_no_access_required(HANDLE dir)
{
    IO_STATUS_BLOCK iosb;
    HANDLE file = NULL, server = NULL, client = NULL;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    LARGE_INTEGER timeout;
    NTSTATUS status;

    scrub_file(dir, W("sync.bin"));
    status = open_file(&file, dir, W("sync.bin"), SYNCHRONIZE, 0, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create sync.bin with SYNCHRONIZE only -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        CHECK_ACCESS(file, SYNCHRONIZE, "a SYNCHRONIZE-only file handle");
        NtClose(file);
    }
    scrub_file(dir, W("sync.bin"));

    /* dlls/ntdll/tests/pipe.c :1006-:1015, transcribed: a server end created
     * with READ_DATA|READ_ATTRIBUTES|WRITE_ATTRIBUTES|SYNCHRONIZE, and a
     * client opened with SYNCHRONIZE and nothing else. */
    init_ustr(&name, W("\\??\\pipe\\prstest_access"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    timeout.QuadPart = -100 * 10000; /* 100 ms, relative */
    status = NtCreateNamedPipeFile(
        &server, FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE, &attr,
        &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, 1, 1, 0, 0xFFFFFFFF, 500, 500,
        &timeout);
    ok(status == STATUS_SUCCESS, "create the pipe server end -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    status = NtCreateFile(&client, SYNCHRONIZE, &attr, &iosb, NULL, 0,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, NULL, 0);
    ok(status == STATUS_SUCCESS, "open the pipe client end -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        CHECK_ACCESS(client, SYNCHRONIZE, "a SYNCHRONIZE-only pipe client");
        NtClose(client);
    }

    CHECK_ACCESS(server,
                 FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                 "the pipe server end");
    NtClose(server);
}

/* --- §4 the HANDLE is resolved before the length is checked --------------- */

/* Every case here uses a buffer too short for the class, so a kernel that
 * checks the length first answers STATUS_INFO_LENGTH_MISMATCH to all of them.
 *
 * INVALID_HANDLE_VALUE is the current PROCESS pseudo-handle, which resolves
 * to an object with no fd at all (server/process.c has no get_fd), so
 * get_handle_fd_obj leaves on the type. A value naming nothing is
 * STATUS_INVALID_HANDLE from the same lookup one step earlier. */
static void test_handle_precedes_length(void)
{
    static const ULONG shortLength = (ULONG)sizeof(FILE_ACCESS_INFORMATION) - 1;
    HANDLE junk = (HANDLE)(ULONG_PTR)0x00fffffc;
    ACCESS_BUFFER buffer;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    status = query_access_len(INVALID_HANDLE_VALUE, (ULONG)sizeof(FILE_ACCESS_INFORMATION), &buffer,
                              &iosb);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "well-formed query on a process handle -> %08lx",
       (unsigned long)status);
    status = query_access_len(INVALID_HANDLE_VALUE, shortLength, &buffer, &iosb);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "short query on a process handle -> %08lx",
       (unsigned long)status);

    status = query_access_len(junk, (ULONG)sizeof(FILE_ACCESS_INFORMATION), &buffer, &iosb);
    ok(status == STATUS_INVALID_HANDLE, "well-formed query on a junk handle -> %08lx",
       (unsigned long)status);
    status = query_access_len(junk, shortLength, &buffer, &iosb);
    ok(status == STATUS_INVALID_HANDLE, "short query on a junk handle -> %08lx",
       (unsigned long)status);

    /* The contrast that makes the ordering a finding rather than a detail:
     * FilePipeInformation's info_sizes[] entry is non-zero, so ITS length
     * check runs in ntdll above the server call and beats the same junk
     * handle. Two classes of one syscall, two orders. */
    {
        SEM_FILE_PIPE_INFORMATION pipeInfo;

        poison_iosb(&iosb);
        memset(&pipeInfo, 0x55, sizeof(pipeInfo));
        status = NtQueryInformationFile(junk, &iosb, &pipeInfo, sizeof(pipeInfo) - 1,
                                        FilePipeInformation);
        ok(status == STATUS_INFO_LENGTH_MISMATCH,
           "short FilePipeInformation on the same junk handle -> %08lx", (unsigned long)status);
    }
}

/* --- §5 the length rule, and what the reply is -------------------------- */

static void test_length_and_reply(HANDLE dir)
{
    IO_STATUS_BLOCK iosb;
    ACCESS_BUFFER buffer;
    HANDLE file = NULL;
    NTSTATUS status;

    scrub_file(dir, W("length.bin"));
    status = open_file(&file, dir, W("length.bin"), FILE_GENERIC_READ, 0, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create length.bin -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* Short of the class's size is STATUS_INFO_LENGTH_MISMATCH and the
     * caller's buffer is left alone — the guard sits above set_reply_data. */
    status = query_access_len(file, (ULONG)sizeof(FILE_ACCESS_INFORMATION) - 1, &buffer, &iosb);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "one byte short -> %08lx", (unsigned long)status);
    ok(buffer.info.AccessFlags == BUFFER_POISON, "one byte short: buffer untouched (%08lx)",
       (unsigned long)buffer.info.AccessFlags);
    status = query_access_len(file, 0, &buffer, &iosb);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "zero length -> %08lx", (unsigned long)status);

    /* Longer than the class is fine and reports the CLASS's size, not the
     * buffer's: the reply is `set_reply_data( &info, sizeof(info) )`, so the
     * bytes past it stay the caller's. */
    status = query_access_len(file, (ULONG)sizeof(ACCESS_BUFFER), &buffer, &iosb);
    ok(status == STATUS_SUCCESS, "oversized buffer -> %08lx", (unsigned long)status);
    ok(buffer.info.AccessFlags == FILE_GENERIC_READ, "oversized buffer: AccessFlags %08lx",
       (unsigned long)buffer.info.AccessFlags);
    ok(iosb.Information == sizeof(FILE_ACCESS_INFORMATION),
       "oversized buffer: Information %lu, wanted %lu", (unsigned long)iosb.Information,
       (unsigned long)sizeof(FILE_ACCESS_INFORMATION));
    ok(buffer.tail == BUFFER_POISON, "oversized buffer: the tail is untouched (%08lx)",
       (unsigned long)buffer.tail);

    NtClose(file);
    scrub_file(dir, W("length.bin"));
}

/* --- §6 the class is not a regular-file class ---------------------------- */

/* default_fd_get_file_info is the fd op every backing shares, so a DIRECTORY
 * handle answers it exactly as a file does — there is no stat, no read and no
 * device round trip in this class at all. */
static void test_directory_handle(HANDLE dir)
{
    static const ACCESS_MASK opened =
        FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_TRAVERSE | SYNCHRONIZE;

    CHECK_ACCESS(dir, opened, "the test directory handle");
}

/* --- §7 FileAllInformation carries the same word ------------------------- */

/* beyond_oracle, and this is what the tag is for. The pinned Wine fills
 * FILE_ALL_INFORMATION's AccessInformation with a hardwired zero and a FIXME
 * (dlls/ntdll/unix/file.c: `info->AccessInformation.AccessFlags = 0;` followed
 * by a FIXME), exactly as it does the ModeInformation beside it — a placeholder, not an
 * implemented behaviour, so the oracle has nothing to say and asserting its
 * zero would be pinning a gap. Microsoft documents the field's contract:
 * FILE_ACCESS_INFORMATION's AccessFlags is "the access rights that are granted
 * for this handle" (learn.microsoft.com, "FILE_ACCESS_INFORMATION structure
 * (ntddk.h)"), and FILE_ALL_INFORMATION's AccessInformation member is that
 * same structure ("FILE_ALL_INFORMATION structure (ntifs.h)"). One question,
 * so one answer — and the case that can tell one answer from two is again the
 * weakened DUPLICATE, because through the original open every implementation
 * of either rule agrees. */
static void test_all_information_agrees(HANDLE dir)
{
    static const ACCESS_MASK opened =
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    static const ACCESS_MASK weakened = FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    IO_STATUS_BLOCK iosb;
    HANDLE file = NULL, weak = NULL;
    NTSTATUS status;

    scrub_file(dir, W("agree.bin"));
    status = open_file(&file, dir, W("agree.bin"), opened, 0, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create agree.bin -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    status = NtDuplicateObject(NtCurrentProcess(), file, NtCurrentProcess(), &weak, weakened, 0, 0);
    ok(status == STATUS_SUCCESS, "duplicate for FileAllInformation -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        beyond_oracle
        {
            struct
            {
                FILE_ALL_INFORMATION info;
                WCHAR pad[260];
            } all;
            ACCESS_MASK direct = BUFFER_POISON;

            memset(&all, 0x55, sizeof(all));
            poison_iosb(&iosb);
            status = NtQueryInformationFile(weak, &iosb, &all, sizeof(all), FileAllInformation);
            ok(status == STATUS_SUCCESS, "FileAllInformation through the duplicate -> %08lx",
               (unsigned long)status);
            ok(all.info.AccessInformation.AccessFlags == weakened,
               "FileAllInformation: AccessFlags %08lx, wanted the duplicate's %08lx",
               (unsigned long)all.info.AccessInformation.AccessFlags, (unsigned long)weakened);

            status = query_access(weak, &direct);
            ok(status == STATUS_SUCCESS, "class 8 through the duplicate -> %08lx",
               (unsigned long)status);
            ok(all.info.AccessInformation.AccessFlags == direct,
               "the two directions agree (%08lx vs %08lx)",
               (unsigned long)all.info.AccessInformation.AccessFlags, (unsigned long)direct);
        }
        NtClose(weak);
    }

    NtClose(file);
    scrub_file(dir, W("agree.bin"));
}

START_TEST(access_info)
{
    HANDLE dir = open_test_dir(W("\\??\\C:\\prstest\\access"));

    if (dir == NULL)
        return;

    test_value_is_the_handles_access(dir);
    test_generic_bits_are_resolved(dir);
    test_no_access_required(dir);
    test_handle_precedes_length();
    test_length_and_reply(dir);
    test_directory_handle(dir);
    test_all_information_agrees(dir);

    NtClose(dir);
}
