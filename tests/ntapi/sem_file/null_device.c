/*
 * sem_file/null_device.c — \Device\Null and its \??\NUL DOS name.
 *
 * Convicted by the winetest gate: ucrtbase:file's test_std_stream_open does
 *
 *     f = fopen("nul", "r");
 *     ok(f != stdin, ...);
 *     ok(_fileno(f) == STDIN_FILENO, ...);
 *
 * and on proskrnl the open returned NULL, so _fileno(NULL) faulted on
 * 0x18(%rbx) — the whole subtest died at its third assertion with
 * c0000005 and printed nothing. NUL is a device real NT has always had, so
 * this is a gap, not a boundary question (Art. 2 does not apply: nothing is
 * being invented here).
 *
 * Oracle-first (G5). Every expectation below is the pinned Wine's answer
 * for \??\NUL, which is where the shape comes from — a sink that swallows
 * writes and reads back end-of-file, openable many times over.
 */
#include "util.h"

static NTSTATUS open_nul(HANDLE *handle, ACCESS_MASK access, ULONG share, ULONG disposition,
                         IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    init_ustr(&name, W("\\??\\NUL"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    *handle = NULL;
    return NtCreateFile(handle, access, &attr, iosb, NULL, FILE_ATTRIBUTE_NORMAL, share,
                        disposition, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

START_TEST(null_device)
{
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    HANDLE handle, second;
    char buffer[16];

    /* --- it opens, by its DOS name, for read and for write --------------- */
    poison_iosb(&iosb);
    status = open_nul(&handle, FILE_GENERIC_READ | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      FILE_OPEN, &iosb);
    ok(status == STATUS_SUCCESS, "open \\??\\NUL for read -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    ok(iosb.Information == FILE_OPENED, "open information %lu", (unsigned long)iosb.Information);

    /* --- a read reads nothing and says so -------------------------------- */
    poison_iosb(&iosb);
    memset(buffer, 'x', sizeof(buffer));
    status = NtReadFile(handle, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_END_OF_FILE, "read NUL -> %08lx", (unsigned long)status);

    /* --- a second open succeeds (it is not an exclusive stream) ----------- */
    status = open_nul(&second, FILE_GENERIC_WRITE | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      FILE_OPEN, &iosb);
    ok(status == STATUS_SUCCESS, "second open -> %08lx", (unsigned long)status);

    /* --- a write is swallowed whole --------------------------------------- */
    if (NT_SUCCESS(status))
    {
        poison_iosb(&iosb);
        status = NtWriteFile(second, NULL, NULL, NULL, &iosb, "hello", 5, NULL, NULL);
        ok(status == STATUS_SUCCESS, "write NUL -> %08lx", (unsigned long)status);
        ok(iosb.Information == 5, "write consumed %lu of 5", (unsigned long)iosb.Information);
        NtClose(second);
    }

    /* --- it reports itself as a zero-length file --------------------------- */
    FILE_STANDARD_INFORMATION standard;
    memset(&standard, 0xcc, sizeof(standard));
    status =
        NtQueryInformationFile(handle, &iosb, &standard, sizeof(standard), FileStandardInformation);
    ok(status == STATUS_SUCCESS, "query standard -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ok(standard.EndOfFile.QuadPart == 0, "NUL size %ld", (long)standard.EndOfFile.QuadPart);
        ok(standard.Directory == FALSE, "NUL is a directory");
    }

    NtClose(handle);
}
