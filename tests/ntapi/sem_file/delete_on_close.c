/*
 * sem_file/delete_on_close.c — delete-on-close and FileDispositionInformation
 * (M6): the two NT deletion paths, DeletePending visibility, the
 * STATUS_DELETE_PENDING window, cancelling a pending delete, directory
 * deletion, and the read-only-attribute guard.
 */
#include "util.h"

START_TEST(delete_on_close)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, h1, h2;
    FILE_DISPOSITION_INFORMATION disposition;
    FILE_STANDARD_INFORMATION std;
    FILE_BASIC_INFORMATION basic;

    dir = open_test_dir(W("\\??\\C:\\prstest\\del"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("doc.txt"));
    scrub_file(dir, W("disp.txt"));
    scrub_file(dir, W("ro.txt"));

    /* --- FILE_DELETE_ON_CLOSE at create: the file dies with the handle. ---- */
    status = open_file(&h1, dir, W("doc.txt"), FILE_GENERIC_WRITE | DELETE, 0, FILE_CREATE,
                       FILE_DELETE_ON_CLOSE, &iosb);
    ok(status == STATUS_SUCCESS, "create delete-on-close -> %08lx", (unsigned long)status);
    NtClose(h1);
    status =
        open_file(&h1, dir, W("doc.txt"), FILE_GENERIC_READ, FILE_SHARE_READ, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "reopen after delete-on-close -> %08lx",
       (unsigned long)status);

    /* --- FileDispositionInformation needs DELETE access. ------------------- */
    status = open_file(&h1, dir, W("disp.txt"), FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_CREATE, 0,
                       &iosb);
    ok(status == STATUS_SUCCESS, "create disp.txt -> %08lx", (unsigned long)status);
    disposition.DoDeleteFile = TRUE;
    status = NtSetInformationFile(h1, &iosb, &disposition, sizeof(disposition),
                                  FileDispositionInformation);
    ok(status == STATUS_ACCESS_DENIED, "set disposition without DELETE -> %08lx",
       (unsigned long)status);
    NtClose(h1);

    /* --- set disposition, watch DeletePending, see the delete window. ------ */
    status = open_file(&h1, dir, W("disp.txt"), FILE_GENERIC_READ | DELETE,
                       FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "open with DELETE -> %08lx", (unsigned long)status);

    status = NtQueryInformationFile(h1, &iosb, &std, sizeof(std), FileStandardInformation);
    ok(status == STATUS_SUCCESS && std.DeletePending == FALSE, "DeletePending starts FALSE (%d)",
       (int)std.DeletePending);

    disposition.DoDeleteFile = TRUE;
    status = NtSetInformationFile(h1, &iosb, &disposition, sizeof(disposition),
                                  FileDispositionInformation);
    ok(status == STATUS_SUCCESS, "set disposition -> %08lx", (unsigned long)status);
    /* (Real NT would now report DeletePending and refuse new opens with
     * STATUS_DELETE_PENDING; the pinned Wine's unix backend does neither, so
     * neither corner is asserted — the query itself must still succeed.) */
    status = NtQueryInformationFile(h1, &iosb, &std, sizeof(std), FileStandardInformation);
    ok(status == STATUS_SUCCESS, "query standard during disposition -> %08lx",
       (unsigned long)status);
    status = open_file(&h2, dir, W("disp.txt"), FILE_GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_OPEN, 0, &iosb);
    if (NT_SUCCESS(status))
        NtClose(h2);

    /* --- cancelling the disposition keeps the file alive. ------------------ */
    disposition.DoDeleteFile = FALSE;
    status = NtSetInformationFile(h1, &iosb, &disposition, sizeof(disposition),
                                  FileDispositionInformation);
    ok(status == STATUS_SUCCESS, "cancel disposition -> %08lx", (unsigned long)status);
    NtClose(h1);
    status = open_file(&h1, dir, W("disp.txt"), FILE_GENERIC_READ | DELETE, FILE_SHARE_READ,
                       FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "file survived a cancelled delete -> %08lx",
       (unsigned long)status);

    /* --- and with the disposition re-set, close really deletes. ------------ */
    disposition.DoDeleteFile = TRUE;
    status = NtSetInformationFile(h1, &iosb, &disposition, sizeof(disposition),
                                  FileDispositionInformation);
    ok(status == STATUS_SUCCESS, "re-set disposition -> %08lx", (unsigned long)status);
    NtClose(h1);
    status =
        open_file(&h1, dir, W("disp.txt"), FILE_GENERIC_READ, FILE_SHARE_READ, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "file gone after close -> %08lx",
       (unsigned long)status);

    /* --- read-only attribute blocks deletion. ------------------------------ */
    status =
        open_file(&h1, dir, W("ro.txt"), FILE_GENERIC_WRITE | DELETE, 0, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create ro.txt -> %08lx", (unsigned long)status);
    memset(&basic, 0, sizeof(basic));
    basic.FileAttributes = FILE_ATTRIBUTE_READONLY;
    status = NtSetInformationFile(h1, &iosb, &basic, sizeof(basic), FileBasicInformation);
    ok(status == STATUS_SUCCESS, "set read-only -> %08lx", (unsigned long)status);
    disposition.DoDeleteFile = TRUE;
    status = NtSetInformationFile(h1, &iosb, &disposition, sizeof(disposition),
                                  FileDispositionInformation);
    ok(status == STATUS_CANNOT_DELETE, "delete read-only -> %08lx", (unsigned long)status);
    /* Clear the attribute so the scrub path can remove it. */
    basic.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    status = NtSetInformationFile(h1, &iosb, &basic, sizeof(basic), FileBasicInformation);
    ok(status == STATUS_SUCCESS, "clear read-only -> %08lx", (unsigned long)status);
    NtClose(h1);
    scrub_file(dir, W("ro.txt"));

    /* --- FILE_DELETE_ON_CLOSE needs the delete to be shared by others. ----- */
    status = open_file(&h1, dir, W("doc.txt"), FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_CREATE, 0,
                       &iosb);
    ok(status == STATUS_SUCCESS, "recreate doc.txt -> %08lx", (unsigned long)status);
    status = open_file(&h2, dir, W("doc.txt"), FILE_GENERIC_READ | DELETE, FILE_SHARE_READ,
                       FILE_OPEN, FILE_DELETE_ON_CLOSE, &iosb);
    ok(status == STATUS_SHARING_VIOLATION, "delete-on-close without share-delete -> %08lx",
       (unsigned long)status);
    NtClose(h1);
    scrub_file(dir, W("doc.txt"));

    /* --- directories: delete-on-close works, but only when empty. ---------- */
    status =
        open_file(&h1, dir, W("subdir"), FILE_LIST_DIRECTORY | FILE_ADD_FILE | SYNCHRONIZE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "create subdir -> %08lx", (unsigned long)status);
    /* Put a file inside; deleting the non-empty directory must fail. */
    status = open_file(&h2, h1, W("inner.txt"), FILE_GENERIC_WRITE, 0, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create inner.txt -> %08lx", (unsigned long)status);
    NtClose(h2);
    NtClose(h1);

    status = open_file(&h1, dir, W("subdir"), DELETE | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
                       FILE_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "open subdir for delete -> %08lx", (unsigned long)status);
    disposition.DoDeleteFile = TRUE;
    status = NtSetInformationFile(h1, &iosb, &disposition, sizeof(disposition),
                                  FileDispositionInformation);
    ok(status == STATUS_DIRECTORY_NOT_EMPTY, "delete non-empty dir -> %08lx",
       (unsigned long)status);
    NtClose(h1);

    /* Empty it, then delete-on-close removes it. */
    status = open_file(&h1, dir, W("subdir"), FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "reopen subdir -> %08lx", (unsigned long)status);
    scrub_file(h1, W("inner.txt"));
    NtClose(h1);

    status = open_file(&h1, dir, W("subdir"), DELETE | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
                       FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, &iosb);
    ok(status == STATUS_SUCCESS, "open empty subdir delete-on-close -> %08lx",
       (unsigned long)status);
    NtClose(h1);
    status = open_file(&h1, dir, W("subdir"), FILE_LIST_DIRECTORY | SYNCHRONIZE, FILE_SHARE_READ,
                       FILE_OPEN, FILE_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "subdir gone -> %08lx", (unsigned long)status);

    NtClose(dir);
}
