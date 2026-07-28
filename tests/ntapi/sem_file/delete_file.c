/*
 * sem_file/delete_file.c — NtDeleteFile (CUI-5).
 *
 * The by-name delete. No PE-side kernelbase caller exists (DeleteFileW
 * opens FILE_DELETE_ON_CLOSE instead), so this is API completeness with an
 * exact contract: the pinned Wine's NtDeleteFile (dlls/ntdll/unix/file.c)
 * is an open with GENERIC_READ|GENERIC_WRITE|DELETE, full sharing,
 * FILE_OPEN + FILE_DELETE_ON_CLOSE, then a close — so its error shape is
 * the open's error shape (name/path resolution, sharing, read-only), and
 * its success shape is delete-on-close semantics (deferred past other
 * opens of the same file).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtDeleteFile(POBJECT_ATTRIBUTES);

static void make_file(HANDLE root, const void *name)
{
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    NTSTATUS status = open_file(&handle, root, name, FILE_GENERIC_WRITE | SYNCHRONIZE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OVERWRITE_IF, 0, &iosb);
    ok(status == STATUS_SUCCESS, "make_file -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        NtWriteFile(handle, NULL, NULL, NULL, &iosb, "x", 1, NULL, NULL);
        NtClose(handle);
    }
}

static NTSTATUS delete_by_name(const void *path)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    init_ustr(&name, path);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    return NtDeleteFile(&attr);
}

START_TEST(delete_file)
{
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    HANDLE dir, other;

    dir = open_test_dir(W("\\??\\C:\\prstest\\delfile"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("plain.txt"));
    scrub_file(dir, W("busy.txt"));
    scrub_file(dir, W("shared.txt"));

    /* --- a plain file is deleted ------------------------------------------- */
    make_file(dir, W("plain.txt"));
    status = delete_by_name(W("\\??\\C:\\prstest\\delfile\\plain.txt"));
    ok(status == STATUS_SUCCESS, "delete plain -> %08lx", (unsigned long)status);
    status = open_file(&other, dir, W("plain.txt"), FILE_GENERIC_READ | SYNCHRONIZE, 0, FILE_OPEN,
                       0, &iosb);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "deleted file still opens -> %08lx",
       (unsigned long)status);

    /* --- error shapes are the open's --------------------------------------- */
    status = delete_by_name(W("\\??\\C:\\prstest\\delfile\\absent.txt"));
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "missing file -> %08lx", (unsigned long)status);
    status = delete_by_name(W("\\??\\C:\\prstest\\delfile\\nosuchdir\\x.txt"));
    ok(status == STATUS_OBJECT_PATH_NOT_FOUND, "missing parent -> %08lx", (unsigned long)status);

    /* An existing open without FILE_SHARE_DELETE collides with the
     * GENERIC_READ|GENERIC_WRITE|DELETE open NtDeleteFile issues. */
    make_file(dir, W("busy.txt"));
    status = open_file(&other, dir, W("busy.txt"), FILE_GENERIC_READ | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "open busy -> %08lx", (unsigned long)status);
    status = delete_by_name(W("\\??\\C:\\prstest\\delfile\\busy.txt"));
    ok(status == STATUS_SHARING_VIOLATION, "delete busy -> %08lx", (unsigned long)status);
    NtClose(other);
    scrub_file(dir, W("busy.txt"));

    /* --- deferral past another open of the same file ------------------------ */
    make_file(dir, W("shared.txt"));
    status = open_file(&other, dir, W("shared.txt"), FILE_GENERIC_READ | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "open shared -> %08lx", (unsigned long)status);
    status = delete_by_name(W("\\??\\C:\\prstest\\delfile\\shared.txt"));
    ok(status == STATUS_SUCCESS, "delete shared -> %08lx", (unsigned long)status);
    /* The unlink applies when the last open leaves (the pinned Wine defers
     * it past every fd of the inode — server/fd.c). */
    NtClose(other);
    status = open_file(&other, dir, W("shared.txt"), FILE_GENERIC_READ | SYNCHRONIZE, 0, FILE_OPEN,
                       0, &iosb);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "shared file survived last close -> %08lx",
       (unsigned long)status);

    NtClose(dir);
}
