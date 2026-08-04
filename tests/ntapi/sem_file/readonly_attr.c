/*
 * sem_file/readonly_attr.c — the FILE_ATTRIBUTE_READONLY lifecycle.
 *
 * Convicted by the winetest gate: msvcrt:file's test__creat leaves a
 * read-only "_creat.tst" behind, clears the bit with SetFileAttributes,
 * deletes it, and creates it again — and on proskrnl every step after the
 * clear failed (file.c:2921 "_creat failed", 2934 "expected rw file", and
 * test_lseek's own _creat at 2952 behind them). That is four Nt* rules in a
 * row, so they are pinned here as one sequence rather than inferred from
 * the CRT's aggregate:
 *
 *   1. a create with FILE_ATTRIBUTE_READONLY reports the bit back,
 *   2. a delete of a read-only file is STATUS_CANNOT_DELETE,
 *   3. FileBasicInformation with FILE_ATTRIBUTE_NORMAL CLEARS the bit
 *      (this is the step msvcrt:file depends on and the one a
 *      keep-what-you-had implementation gets wrong), and
 *   4. FILE_OVERWRITE_IF onto a read-only file is STATUS_ACCESS_DENIED —
 *      the status _creat surfaces as its failure.
 *
 * Oracle-first (G5): every expectation here is the pinned Wine's, and the
 * winetest pair is the differential gate above it.
 */
#include "util.h"

/* Create/open a file with an explicit access mask AND attribute set
 * (open_file fixes both, and both are the point here). */
static NTSTATUS create_access(HANDLE *handle, HANDLE root, const void *wideName, ACCESS_MASK access,
                              ULONG attributes, ULONG disposition, IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    init_ustr(&name, wideName);
    init_attr(&attr, root, &name, OBJ_CASE_INSENSITIVE);
    *handle = NULL;
    /* FILE_SHARE_DELETE as well: this test keeps a DELETE-access handle open
     * while probing the same file, and an opener that does not permit
     * delete-sharing is refused for THAT reason (STATUS_SHARING_VIOLATION)
     * before the read-only rule under test is ever reached. */
    return NtCreateFile(handle, access, &attr, iosb, NULL, attributes,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, disposition,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

/* The common case: full read/write/delete access. */
static NTSTATUS create_with_attributes(HANDLE *handle, HANDLE root, const void *wideName,
                                       ULONG attributes, ULONG disposition, IO_STATUS_BLOCK *iosb)
{
    return create_access(handle, root, wideName,
                         FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | SYNCHRONIZE, attributes,
                         disposition, iosb);
}

static ULONG query_attributes(HANDLE handle)
{
    FILE_BASIC_INFORMATION basic;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    memset(&basic, 0, sizeof(basic));
    status = NtQueryInformationFile(handle, &iosb, &basic, sizeof(basic), FileBasicInformation);
    ok(status == STATUS_SUCCESS, "query basic -> %08lx", (unsigned long)status);
    return NT_SUCCESS(status) ? basic.FileAttributes : 0;
}

static NTSTATUS set_attributes(HANDLE handle, ULONG attributes)
{
    FILE_BASIC_INFORMATION basic;
    IO_STATUS_BLOCK iosb;

    memset(&basic, 0, sizeof(basic));
    basic.FileAttributes = attributes;
    return NtSetInformationFile(handle, &iosb, &basic, sizeof(basic), FileBasicInformation);
}

static NTSTATUS set_disposition(HANDLE handle, BOOLEAN deleteFile)
{
    FILE_DISPOSITION_INFORMATION disposition;
    IO_STATUS_BLOCK iosb;

    disposition.DoDeleteFile = deleteFile;
    return NtSetInformationFile(handle, &iosb, &disposition, sizeof(disposition),
                                FileDispositionInformation);
}

START_TEST(readonly_attr)
{
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    HANDLE dir, handle;
    ULONG attributes;

    dir = open_test_dir(W("\\??\\C:\\prstest\\roattr"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;

    /* --- 1. the bit survives creation and comes back on query ------------- */
    scrub_file(dir, W("ro.txt"));
    status = create_with_attributes(&handle, dir, W("ro.txt"), FILE_ATTRIBUTE_READONLY,
                                    FILE_OVERWRITE_IF, &iosb);
    ok(status == STATUS_SUCCESS, "create read-only -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(dir);
        return;
    }
    attributes = query_attributes(handle);
    ok((attributes & FILE_ATTRIBUTE_READONLY) != 0, "created read-only, attributes %08lx",
       (unsigned long)attributes);

    /* --- 2. a read-only file refuses to be deleted ------------------------ */
    status = set_disposition(handle, TRUE);
    ok(status == STATUS_CANNOT_DELETE, "delete read-only -> %08lx", (unsigned long)status);

    /* --- 3. FILE_ATTRIBUTE_NORMAL clears it ------------------------------- */
    status = set_attributes(handle, FILE_ATTRIBUTE_NORMAL);
    ok(status == STATUS_SUCCESS, "set NORMAL -> %08lx", (unsigned long)status);
    attributes = query_attributes(handle);
    ok((attributes & FILE_ATTRIBUTE_READONLY) == 0, "NORMAL left read-only set, attributes %08lx",
       (unsigned long)attributes);

    /* ...and the delete the bit was refusing now goes through. */
    status = set_disposition(handle, TRUE);
    ok(status == STATUS_SUCCESS, "delete after clear -> %08lx", (unsigned long)status);
    NtClose(handle);
    status = open_file(&handle, dir, W("ro.txt"), FILE_GENERIC_READ | SYNCHRONIZE, 0, FILE_OPEN,
                       FILE_NON_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "deleted file still opens -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(handle);

    /* The name is free again — _creat's next call in msvcrt:file. */
    status = create_with_attributes(&handle, dir, W("ro.txt"), FILE_ATTRIBUTE_NORMAL,
                                    FILE_OVERWRITE_IF, &iosb);
    ok(status == STATUS_SUCCESS, "recreate after delete -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        attributes = query_attributes(handle);
        ok((attributes & FILE_ATTRIBUTE_READONLY) == 0, "recreated read-only, attributes %08lx",
           (unsigned long)attributes);
        (void)set_disposition(handle, TRUE);
        NtClose(handle);
    }

    /* --- 4. what a read-only file refuses on OPEN ------------------------
     * The creating handle is kept for the whole block and does the cleanup:
     * every access below is refused once the file exists read-only, so a
     * test that closed it first could not tidy up after itself. */
    scrub_file(dir, W("ro2.txt"));
    status = create_with_attributes(&handle, dir, W("ro2.txt"), FILE_ATTRIBUTE_READONLY,
                                    FILE_OVERWRITE_IF, &iosb);
    ok(status == STATUS_SUCCESS, "create ro2 -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        HANDLE probe;

        /* FILE_OVERWRITE_IF onto it — the status msvcrt:file's _creat
         * surfaces as its failure. */
        status = create_access(&probe, dir, W("ro2.txt"),
                               FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE,
                               FILE_ATTRIBUTE_NORMAL, FILE_OVERWRITE_IF, &iosb);
        ok(status == STATUS_ACCESS_DENIED, "overwrite read-only -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(probe);

        /* ...and a plain open for write data. */
        status = create_access(&probe, dir, W("ro2.txt"), FILE_GENERIC_WRITE | SYNCHRONIZE, 0,
                               FILE_OPEN, &iosb);
        ok(status == STATUS_ACCESS_DENIED, "open read-only for write -> %08lx",
           (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(probe);

        /* Reading it is fine — the bit denies writers, not readers. */
        status = create_access(&probe, dir, W("ro2.txt"), FILE_GENERIC_READ | SYNCHRONIZE, 0,
                               FILE_OPEN, &iosb);
        ok(status == STATUS_SUCCESS, "open read-only for read -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(probe);

        /* Cleanup through the creating handle, which was granted its access
         * before the attribute existed. */
        status = set_attributes(handle, FILE_ATTRIBUTE_NORMAL);
        ok(status == STATUS_SUCCESS, "clear ro2 -> %08lx", (unsigned long)status);
        status = set_disposition(handle, TRUE);
        ok(status == STATUS_SUCCESS, "delete ro2 -> %08lx", (unsigned long)status);
        NtClose(handle);
    }

    NtClose(dir);
}
