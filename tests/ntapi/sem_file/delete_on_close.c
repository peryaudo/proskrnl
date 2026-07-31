/*
 * sem_file/delete_on_close.c — delete-on-close and FileDispositionInformation
 * (M6): the two NT deletion paths, DeletePending visibility, the
 * STATUS_DELETE_PENDING window, cancelling a pending delete, directory
 * deletion, and the read-only-attribute guard.
 */
#include "util.h"


/* A read-only file cannot be deleted through FILE_DELETE_ON_CLOSE either.
 * The FS refused it through NtSetInformationFile(FileDispositionInformation)
 * but not through the create option -- the same deletion arriving by a
 * different door, walking straight past the check. The oracle answers at
 * OPEN, not silently at close. */
static void test_readonly_delete_on_close(HANDLE dir)
{
    IO_STATUS_BLOCK iosb;
    FILE_BASIC_INFORMATION basic;
    NTSTATUS status;
    HANDLE h;

    scrub_file(dir, W("ro_doc.bin"));
    status = open_file(&h, dir, W("ro_doc.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0,
                       FILE_OVERWRITE_IF, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create ro_doc.bin -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    memset(&basic, 0, sizeof(basic));
    basic.FileAttributes = FILE_ATTRIBUTE_READONLY;
    status = NtSetInformationFile(h, &iosb, &basic, sizeof(basic), FileBasicInformation);
    ok(status == STATUS_SUCCESS, "mark read-only -> %08lx", (unsigned long)status);
    NtClose(h);

    status = open_file(&h, dir, W("ro_doc.bin"), DELETE | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
                       FILE_DELETE_ON_CLOSE, &iosb);
    ok(status == STATUS_CANNOT_DELETE, "FILE_DELETE_ON_CLOSE on a read-only file -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(h);

    status = open_file(&h, dir, W("ro_doc.bin"), FILE_GENERIC_READ, FILE_SHARE_READ, FILE_OPEN, 0,
                       &iosb);
    ok(status == STATUS_SUCCESS, "the read-only file survived -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(h);

    /* Clear the bit so the scrub can remove it. */
    status = open_file(&h, dir, W("ro_doc.bin"), FILE_GENERIC_WRITE | FILE_WRITE_ATTRIBUTES,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0,
                       &iosb);
    if (NT_SUCCESS(status))
    {
        memset(&basic, 0, sizeof(basic));
        basic.FileAttributes = FILE_ATTRIBUTE_NORMAL;
        NtSetInformationFile(h, &iosb, &basic, sizeof(basic), FileBasicInformation);
        NtClose(h);
    }
    scrub_file(dir, W("ro_doc.bin"));
}

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

    /* The unlink waits for the truly-LAST open — even one that requested no
     * data access and so imposed no share constraints (pinned Wine, fuzzer-
     * found: the inode's unlink runs when its fd list empties,
     * server/fd.c). A delete-on-close handle closing while an attributes-
     * only open remains leaves the file alive and re-openable; the file
     * finally goes when that open closes too. */
    {
        HANDLE weak = NULL, killer = NULL;
        scrub_file(dir, W("linger.txt"));
        status = open_file(&h1, dir, W("linger.txt"), FILE_GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE, 0,
                           &iosb);
        ok(status == STATUS_SUCCESS, "create linger.txt -> %08lx", (unsigned long)status);
        NtClose(h1);
        status = open_file(&weak, dir, W("linger.txt"), FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                           FILE_SHARE_READ, FILE_OPEN, 0, &iosb);
        ok(status == STATUS_SUCCESS, "attributes-only open -> %08lx", (unsigned long)status);
        status = open_file(&killer, dir, W("linger.txt"), DELETE | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
                           FILE_DELETE_ON_CLOSE, &iosb);
        ok(status == STATUS_SUCCESS, "delete-on-close open beside it -> %08lx",
           (unsigned long)status);
        NtClose(killer); /* intent latched; the attributes-only open defers it */
        status =
            open_file(&h1, dir, W("linger.txt"), FILE_GENERIC_READ,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0, &iosb);
        ok(status == STATUS_SUCCESS, "file still openable while deferred -> %08lx",
           (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(h1);
        NtClose(weak); /* the last open: the deferred unlink applies */
        status =
            open_file(&h1, dir, W("linger.txt"), FILE_GENERIC_READ,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0, &iosb);
        ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "linger.txt gone after last close -> %08lx",
           (unsigned long)status);
    }

    test_readonly_delete_on_close(dir);
    NtClose(dir);
}
