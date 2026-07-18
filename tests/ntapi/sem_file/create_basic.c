/*
 * sem_file/create_basic.c — NtCreateFile create/open fundamentals (M6).
 *
 * Pins the create-disposition matrix (FILE_CREATE/OPEN/OPEN_IF/OVERWRITE_IF),
 * the IOSB Information verdicts (FILE_CREATED/OPENED/OVERWRITTEN), the
 * namespace statuses for missing leaves and paths, directory-vs-file typing
 * (FILE_DIRECTORY_FILE / FILE_NON_DIRECTORY_FILE), relative opens via
 * OBJECT_ATTRIBUTES.RootDirectory, and case-insensitive lookup — the NT file
 * semantics FAT32 must reproduce (docs/02 M6).
 */
#include "util.h"

START_TEST(create_basic)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, h1, h2;

    dir = open_test_dir(W("\\??\\C:\\prstest\\create"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("new.txt"));
    scrub_file(dir, W("CaseFile.txt"));

    /* --- FILE_CREATE: new file -> FILE_CREATED; again -> collision. ------- */
    poison_iosb(&iosb);
    status = open_file(&h1, dir, W("new.txt"), FILE_GENERIC_WRITE, 0, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "FILE_CREATE new -> %08lx", (unsigned long)status);
    ok(iosb.Information == FILE_CREATED, "FILE_CREATE new: Information %lx",
       (unsigned long)iosb.Information);
    ok(iosb.Status == STATUS_SUCCESS, "FILE_CREATE new: iosb.Status %08lx",
       (unsigned long)iosb.Status);
    NtClose(h1);

    poison_iosb(&iosb);
    status = open_file(&h1, dir, W("new.txt"), FILE_GENERIC_WRITE, 0, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_OBJECT_NAME_COLLISION, "FILE_CREATE existing -> %08lx",
       (unsigned long)status);

    /* --- FILE_OPEN: existing opens, missing fails. ------------------------ */
    poison_iosb(&iosb);
    status =
        open_file(&h1, dir, W("new.txt"), FILE_GENERIC_READ, FILE_SHARE_READ, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "FILE_OPEN existing -> %08lx", (unsigned long)status);
    ok(iosb.Information == FILE_OPENED, "FILE_OPEN existing: Information %lx",
       (unsigned long)iosb.Information);
    NtClose(h1);

    poison_iosb(&iosb);
    status = open_file(&h1, dir, W("missing.txt"), FILE_GENERIC_READ, FILE_SHARE_READ, FILE_OPEN, 0,
                       &iosb);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "FILE_OPEN missing -> %08lx", (unsigned long)status);
    /* The failing status is written into the IOSB too (pinned Wine). */
    ok(iosb.Status == STATUS_OBJECT_NAME_NOT_FOUND, "FILE_OPEN missing: iosb.Status %08lx",
       (unsigned long)iosb.Status);

    /* --- FILE_OPEN_IF: missing creates, existing opens. ------------------- */
    scrub_file(dir, W("openif.txt"));
    poison_iosb(&iosb);
    status = open_file(&h1, dir, W("openif.txt"), FILE_GENERIC_WRITE, 0, FILE_OPEN_IF, 0, &iosb);
    ok(status == STATUS_SUCCESS, "FILE_OPEN_IF missing -> %08lx", (unsigned long)status);
    ok(iosb.Information == FILE_CREATED, "FILE_OPEN_IF missing: Information %lx",
       (unsigned long)iosb.Information);
    NtClose(h1);
    poison_iosb(&iosb);
    status = open_file(&h1, dir, W("openif.txt"), FILE_GENERIC_WRITE, 0, FILE_OPEN_IF, 0, &iosb);
    ok(status == STATUS_SUCCESS, "FILE_OPEN_IF existing -> %08lx", (unsigned long)status);
    ok(iosb.Information == FILE_OPENED, "FILE_OPEN_IF existing: Information %lx",
       (unsigned long)iosb.Information);
    NtClose(h1);

    /* --- FILE_OVERWRITE_IF truncates an existing file. -------------------- */
    status = open_file(&h1, dir, W("openif.txt"), FILE_GENERIC_WRITE, 0, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "reopen for write -> %08lx", (unsigned long)status);
    static const char payload[] = "sixteen bytes!!";
    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    poison_iosb(&iosb);
    status = NtWriteFile(h1, NULL, NULL, NULL, &iosb, payload, sizeof(payload), &offset, NULL);
    ok(status == STATUS_SUCCESS, "write payload -> %08lx", (unsigned long)status);
    ok(iosb.Information == sizeof(payload), "write payload: Information %lx",
       (unsigned long)iosb.Information);
    NtClose(h1);

    poison_iosb(&iosb);
    status =
        open_file(&h1, dir, W("openif.txt"), FILE_GENERIC_WRITE, 0, FILE_OVERWRITE_IF, 0, &iosb);
    ok(status == STATUS_SUCCESS, "FILE_OVERWRITE_IF existing -> %08lx", (unsigned long)status);
    ok(iosb.Information == FILE_OVERWRITTEN, "FILE_OVERWRITE_IF existing: Information %lx",
       (unsigned long)iosb.Information);
    FILE_STANDARD_INFORMATION std;
    poison_iosb(&iosb);
    status = NtQueryInformationFile(h1, &iosb, &std, sizeof(std), FileStandardInformation);
    ok(status == STATUS_SUCCESS, "query standard -> %08lx", (unsigned long)status);
    ok(std.EndOfFile.QuadPart == 0, "overwrite did not truncate (EOF %ld)",
       (long)std.EndOfFile.QuadPart);
    NtClose(h1);

    /* --- FILE_OVERWRITE on a missing file fails. -------------------------- */
    scrub_file(dir, W("gone.txt"));
    status = open_file(&h1, dir, W("gone.txt"), FILE_GENERIC_WRITE, 0, FILE_OVERWRITE, 0, &iosb);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "FILE_OVERWRITE missing -> %08lx",
       (unsigned long)status);

    /* --- a missing intermediate component is a PATH error. ---------------- */
    status = open_file(&h1, dir, W("nodir\\leaf.txt"), FILE_GENERIC_READ, FILE_SHARE_READ,
                       FILE_OPEN, 0, &iosb);
    ok(status == STATUS_OBJECT_PATH_NOT_FOUND, "missing intermediate -> %08lx",
       (unsigned long)status);

    /* --- directory/file typing. ------------------------------------------- */
    status =
        open_file(&h1, dir, W("adir"), FILE_LIST_DIRECTORY | SYNCHRONIZE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "create subdir -> %08lx", (unsigned long)status);
    NtClose(h1);

    /* Opening a directory with FILE_NON_DIRECTORY_FILE is refused... */
    status = open_file(&h1, dir, W("adir"), FILE_GENERIC_READ, FILE_SHARE_READ, FILE_OPEN,
                       FILE_NON_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_FILE_IS_A_DIRECTORY, "dir as non-directory -> %08lx",
       (unsigned long)status);
    /* ...and a data file with FILE_DIRECTORY_FILE is too. */
    status = open_file(&h1, dir, W("new.txt"), FILE_GENERIC_READ, FILE_SHARE_READ, FILE_OPEN,
                       FILE_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_NOT_A_DIRECTORY, "file as directory -> %08lx", (unsigned long)status);

    /* FILE_CREATE of a data file over an existing directory name collides. */
    status = open_file(&h1, dir, W("adir"), FILE_GENERIC_WRITE, 0, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_OBJECT_NAME_COLLISION, "create over dir -> %08lx", (unsigned long)status);

    /* --- relative create/open via RootDirectory. --------------------------- */
    status = open_file(&h2, dir, W("adir"), FILE_LIST_DIRECTORY | FILE_ADD_FILE | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "reopen subdir -> %08lx", (unsigned long)status);
    scrub_file(h2, W("rel.txt"));
    poison_iosb(&iosb);
    status = open_file(&h1, h2, W("rel.txt"), FILE_GENERIC_WRITE, 0, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "relative create -> %08lx", (unsigned long)status);
    ok(iosb.Information == FILE_CREATED, "relative create: Information %lx",
       (unsigned long)iosb.Information);
    NtClose(h1);
    /* The file is reachable by absolute path too. */
    status = open_file(&h1, NULL, W("\\??\\C:\\prstest\\create\\adir\\rel.txt"), FILE_GENERIC_READ,
                       FILE_SHARE_READ, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "absolute reopen of relative create -> %08lx",
       (unsigned long)status);
    NtClose(h1);
    scrub_file(h2, W("rel.txt"));
    NtClose(h2);

    /* --- case-insensitive lookup (OBJ_CASE_INSENSITIVE). ------------------- */
    status = open_file(&h1, dir, W("CaseFile.txt"), FILE_GENERIC_WRITE, 0, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create CaseFile.txt -> %08lx", (unsigned long)status);
    NtClose(h1);
    status = open_file(&h1, dir, W("cAsEfIlE.TXT"), FILE_GENERIC_READ, FILE_SHARE_READ, FILE_OPEN,
                       0, &iosb);
    ok(status == STATUS_SUCCESS, "case-insensitive open -> %08lx", (unsigned long)status);
    NtClose(h1);
    /* Creating the same name in a different case still collides. */
    status = open_file(&h1, dir, W("CASEFILE.txt"), FILE_GENERIC_WRITE, 0, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_OBJECT_NAME_COLLISION, "case-insensitive collision -> %08lx",
       (unsigned long)status);

    /* --- an invalid disposition is rejected. -------------------------------- */
    status = open_file(&h1, dir, W("new.txt"), FILE_GENERIC_READ, FILE_SHARE_READ,
                       FILE_MAXIMUM_DISPOSITION + 1, 0, &iosb);
    ok(status == STATUS_INVALID_PARAMETER, "bad disposition -> %08lx", (unsigned long)status);

    scrub_file(dir, W("new.txt"));
    scrub_file(dir, W("openif.txt"));
    scrub_file(dir, W("CaseFile.txt"));
    NtClose(dir);
}
