/*
 * sem_file/internal_info.c — NtQueryInformationFile(FileInternalInformation):
 * the per-file identity (IndexNumber) win32u's font backend keys its
 * file-mapping cache on (user/wine/win32u/font_unix.c fstat -> st_ino).
 *
 * The contract (Wine dlls/ntdll/unix/file.c fill_file_info: IndexNumber =
 * st_ino) pins only the identity semantics, never the values: nonzero for a
 * regular file, equal across handles to the same file — including a
 * close-and-reopen — different for different files, and served identically
 * through FileAllInformation.InternalInformation. Without this class every
 * font file looked like the same file to win32u and all TrueType faces
 * realized as the first-mapped bitmap font (the GUI-4 "close button says r"
 * bug).
 */
#include "util.h"

START_TEST(internal_info)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, a, a2, b;
    FILE_INTERNAL_INFORMATION ia, ia2, ib;
    FILE_ALL_INFORMATION all;
    LONGLONG first_id;

    dir = open_test_dir(W("\\??\\C:\\prstest\\internal"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("ia.bin"));
    scrub_file(dir, W("ib.bin"));

    status = open_file(&a, dir, W("ia.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create ia.bin -> %08lx", (unsigned long)status);
    status = open_file(&b, dir, W("ib.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create ib.bin -> %08lx", (unsigned long)status);

    /* --- the class answers, with the documented shape ----------------------- */
    poison_iosb(&iosb);
    memset(&ia, 0, sizeof(ia));
    status = NtQueryInformationFile(a, &iosb, &ia, sizeof(ia), FileInternalInformation);
    ok(status == STATUS_SUCCESS, "query internal -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "iosb.Status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == sizeof(ia), "Information %lu", (unsigned long)iosb.Information);
    ok(ia.IndexNumber.QuadPart != 0, "IndexNumber is nonzero for a regular file");

    /* --- identity: same file == same number, however reached ---------------- */
    status = open_file(&a2, dir, W("ia.bin"), FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "reopen ia.bin -> %08lx", (unsigned long)status);
    memset(&ia2, 0, sizeof(ia2));
    status = NtQueryInformationFile(a2, &iosb, &ia2, sizeof(ia2), FileInternalInformation);
    ok(status == STATUS_SUCCESS, "query second handle -> %08lx", (unsigned long)status);
    ok(ia2.IndexNumber.QuadPart == ia.IndexNumber.QuadPart,
       "two handles to one file agree (%llx vs %llx)", (unsigned long long)ia2.IndexNumber.QuadPart,
       (unsigned long long)ia.IndexNumber.QuadPart);
    NtClose(a2);

    /* --- identity: different files are distinguishable ---------------------- */
    memset(&ib, 0, sizeof(ib));
    status = NtQueryInformationFile(b, &iosb, &ib, sizeof(ib), FileInternalInformation);
    ok(status == STATUS_SUCCESS, "query ib.bin -> %08lx", (unsigned long)status);
    ok(ib.IndexNumber.QuadPart != ia.IndexNumber.QuadPart,
       "two files differ (%llx vs %llx) — a shared id collapses win32u's font-mapping cache",
       (unsigned long long)ib.IndexNumber.QuadPart, (unsigned long long)ia.IndexNumber.QuadPart);

    /* --- FileAllInformation serves the same number, not a fabricated zero --- */
    memset(&all, 0, sizeof(all));
    status = NtQueryInformationFile(a, &iosb, &all, sizeof(all), FileAllInformation);
    ok(status == STATUS_SUCCESS || status == STATUS_BUFFER_OVERFLOW, "query all -> %08lx",
       (unsigned long)status);
    ok(all.InternalInformation.IndexNumber.QuadPart == ia.IndexNumber.QuadPart,
       "FileAllInformation agrees (%llx vs %llx)",
       (unsigned long long)all.InternalInformation.IndexNumber.QuadPart,
       (unsigned long long)ia.IndexNumber.QuadPart);

    /* --- stability: the id names the on-disk file, not the open ------------- */
    first_id = ia.IndexNumber.QuadPart;
    NtClose(a);
    status = open_file(&a, dir, W("ia.bin"), FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "reopen after close -> %08lx", (unsigned long)status);
    memset(&ia, 0, sizeof(ia));
    status = NtQueryInformationFile(a, &iosb, &ia, sizeof(ia), FileInternalInformation);
    ok(status == STATUS_SUCCESS, "query reopened -> %08lx", (unsigned long)status);
    ok(ia.IndexNumber.QuadPart == first_id, "id survives close+reopen (%llx vs %llx)",
       (unsigned long long)ia.IndexNumber.QuadPart, (unsigned long long)first_id);

    /* --- a directory handle answers too (no value pinned) ------------------- */
    memset(&ia2, 0, sizeof(ia2));
    status = NtQueryInformationFile(dir, &iosb, &ia2, sizeof(ia2), FileInternalInformation);
    ok(status == STATUS_SUCCESS, "query directory -> %08lx", (unsigned long)status);

    /* --- the short-buffer convention ---------------------------------------- */
    status = NtQueryInformationFile(a, &iosb, &ia, sizeof(ia) - 1, FileInternalInformation);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short buffer -> %08lx", (unsigned long)status);

    /* cleanup */
    NtClose(a);
    NtClose(b);
    scrub_file(dir, W("ia.bin"));
    scrub_file(dir, W("ib.bin"));
    NtClose(dir);
}
