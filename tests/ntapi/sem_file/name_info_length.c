/*
 * sem_file/name_info_length.c — the LENGTH FLOOR of
 * NtQueryInformationFile(FileNameInformation), class 9.
 *
 * docs/21 W11, ntdll:pipe:1987 (dlls/ntdll/tests/pipe.c `_test_file_name`,
 * which asks the class of a connected pipe end with a FOUR-byte buffer and
 * wants STATUS_INFO_LENGTH_MISMATCH).
 *
 * The floor is stated once, in ntdll's table, above every device:
 *
 *     dlls/ntdll/unix/file.c  NtQueryInformationFile
 *         static const size_t info_sizes[] = { ...
 *             sizeof(FILE_NAME_INFORMATION),   // the FileNameInformation row
 *         ... };
 *         if (len < info_sizes[class]) return io->Status = STATUS_INFO_LENGTH_MISMATCH;
 *
 * and `sizeof(FILE_NAME_INFORMATION)` is the WHOLE struct — the ULONG count
 * plus its `WCHAR FileName[1]` tail, padded to 8 — not the offset of the
 * tail. The two spellings differ for exactly the buffers 4..7 bytes long, and
 * they answer with two different statuses there: a floor written as
 * `offsetof(FILE_NAME_INFORMATION, FileName)` accepts a four-byte buffer,
 * writes the count into it and reports STATUS_BUFFER_OVERFLOW.
 *
 * Which is why this is pinned on a REGULAR FILE and on a PIPE in one place:
 * the winetest sees it on a pipe, but the check runs before the handle is
 * resolved, so it cannot be a pipe rule. Nothing about the answer changes
 * with the backend.
 */
#include "util.h"

/* Prototypes mingw's winternl.h omits (as wine/include/winternl.h). */
NTSYSAPI NTSTATUS NTAPI NtCreateNamedPipeFile(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                              ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG,
                                              ULONG, ULONG, PLARGE_INTEGER);

/* Ask the class into `buffer` with a caller-chosen length; the IOSB is
 * poisoned first so "did it write one" is separable from "what did it say". */
static NTSTATUS query_name(HANDLE handle, void *buffer, ULONG length, IO_STATUS_BLOCK *iosb)
{
    poison_iosb(iosb);
    memset(buffer, 0xaa, 64);
    return NtQueryInformationFile(handle, iosb, buffer, length, FileNameInformation);
}

/* The ladder, asked of one handle. `what` names the backend so a failure
 * says which of the two ran it. */
static void check_floor(HANDLE handle, const char *what)
{
    unsigned char buffer[64];
    FILE_NAME_INFORMATION *name = (FILE_NAME_INFORMATION *)(void *)buffer;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    ULONG full;

    /* What the whole name is, so the short-buffer cases below can assert the
     * count is reported in full rather than cut with the data. */
    status = query_name(handle, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_SUCCESS, "%s: full query -> %08lx", what, (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return;
    full = name->FileNameLength;
    ok(full >= sizeof(WCHAR), "%s: FileNameLength %lu", what, (unsigned long)full);

    status = query_name(handle, buffer, 0, &iosb);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "%s: length 0 -> %08lx", what, (unsigned long)status);

    /* THE FLOOR. offsetof(FILE_NAME_INFORMATION, FileName) is 4 and
     * sizeof(FILE_NAME_INFORMATION) is 8; only the second is the rule. */
    status = query_name(handle, buffer, 4, &iosb);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "%s: length 4 -> %08lx", what, (unsigned long)status);
    /* The caller's BUFFER is untouched by the refusal, which is a separate
     * promise from the status and the one an `offsetof` floor breaks: that
     * floor accepts the four bytes and writes the count into them.
     *
     * The caller's IOSB is NOT asserted here. The oracle writes it on this
     * refusal (`return io->Status = STATUS_INFO_LENGTH_MISMATCH`) and
     * proskrnl writes the IOSB only on success — a whole-syscall convention
     * with a dozen classes in it, not this class's rule, and picking it up
     * for class 9 alone would make the syscall answer two ways. Measured on
     * the oracle, and declined for exactly the reason sem_file/access_info.c
     * declines it. */
    ok(name->FileNameLength == 0xaaaaaaaa, "%s: length 4 wrote the buffer (%08lx)", what,
       (unsigned long)name->FileNameLength);

    /* One byte short of the struct is still short: the floor is the struct's
     * SIZE, so it does not fall on the tail's offset or on any partial WCHAR. */
    status = query_name(handle, buffer, 7, &iosb);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "%s: length 7 -> %08lx", what, (unsigned long)status);

    /* And at the floor exactly the class SUCCEEDS its way into an overflow:
     * the count is written in full, one WCHAR of name fits, and Information
     * counts what was consumed rather than what was owed. */
    status = query_name(handle, buffer, 8, &iosb);
    ok(status == STATUS_BUFFER_OVERFLOW, "%s: length 8 -> %08lx", what, (unsigned long)status);
    ok(name->FileNameLength == full, "%s: length 8 reported %lu, wanted %lu", what,
       (unsigned long)name->FileNameLength, (unsigned long)full);
    ok(iosb.Status == STATUS_BUFFER_OVERFLOW, "%s: length 8 IOSB.Status %08lx", what,
       (unsigned long)iosb.Status);
    ok(iosb.Information == 8, "%s: length 8 Information %llu", what,
       (unsigned long long)iosb.Information);
}

static void test_regular_file(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE dir, file = NULL;
    NTSTATUS status;

    dir = open_test_dir(W("\\??\\C:\\prstest\\nameinfo"));
    if (dir == NULL)
        return;

    status = open_file(&file, dir, W("n.txt"), GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OVERWRITE_IF, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create n.txt -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        check_floor(file, "file");
        NtClose(file);
    }
    NtClose(dir);
}

/* The winetest's own subject. A pipe end resolves to a different backend and
 * a different in-server handler, and answers the ladder identically — which
 * is the point: the floor is above both. */
static void test_pipe_end(void)
{
    static const unsigned short pipeName[] = {'\\', '?', '?', '\\', 'p', 'i', 'p', 'e', '\\',
                                              'p',  'r', 's', 't',  'e', 's', 't', '_', 'n',
                                              'a',  'm', 'e', 'l',  'e', 'n', 0};
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER timeout;
    HANDLE server = NULL;
    NTSTATUS status;

    init_ustr(&name, pipeName);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    timeout.QuadPart = -100 * 10000; /* 100 ms, relative */
    status = NtCreateNamedPipeFile(&server, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr,
                                   &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE,
                                   FILE_SYNCHRONOUS_IO_NONALERT, 0, 0, 0, 1, 4096, 4096, &timeout);
    ok(status == STATUS_SUCCESS, "pipe create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    check_floor(server, "pipe");
    NtClose(server);
}

START_TEST(name_info_length)
{
    test_regular_file();
    test_pipe_end();
}
