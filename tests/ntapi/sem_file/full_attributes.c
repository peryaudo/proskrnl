/*
 * sem_file/full_attributes.c — NtQueryFullAttributesFile (M10).
 *
 * kernelbase's GetFileAttributesExW is a straight call to
 * NtQueryFullAttributesFile (third_party/wine dlls/kernelbase/file.c), and
 * msvcrt's stat family reaches it the same way — cmd.exe probes every
 * command candidate with it. The contract (Wine dlls/ntdll/unix/file.c
 * NtQueryFullAttributesFile): a by-name query filling
 * FILE_NETWORK_OPEN_INFORMATION — times, sizes, attributes — with the same
 * name resolution and error shape as NtQueryAttributesFile.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryFullAttributesFile(const OBJECT_ATTRIBUTES *,
                                                  FILE_NETWORK_OPEN_INFORMATION *);

START_TEST(full_attributes)
{
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    HANDLE dir, file;

    dir = open_test_dir(W("\\??\\C:\\prstest\\fullattr"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("fa.txt"));

    /* A five-byte file. */
    status = open_file(&file, dir, W("fa.txt"), FILE_GENERIC_WRITE, 0, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create fa.txt -> %08lx", (unsigned long)status);
    status = NtWriteFile(file, NULL, NULL, NULL, &iosb, "hello", 5, NULL, NULL);
    ok(status == STATUS_SUCCESS, "write -> %08lx", (unsigned long)status);
    NtClose(file);

    /* --- the file ---------------------------------------------------------- */
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    init_ustr(&name, W("\\??\\C:\\prstest\\fullattr\\fa.txt"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);

    FILE_NETWORK_OPEN_INFORMATION full;
    memset(&full, 0xcc, sizeof(full));
    status = NtQueryFullAttributesFile(&attr, &full);
    ok(status == STATUS_SUCCESS, "full attributes -> %08lx", (unsigned long)status);
    ok(full.EndOfFile.QuadPart == 5, "EndOfFile %lld", (long long)full.EndOfFile.QuadPart);
    ok(full.AllocationSize.QuadPart >= 5, "AllocationSize %lld",
       (long long)full.AllocationSize.QuadPart);
    ok(!(full.FileAttributes & FILE_ATTRIBUTE_DIRECTORY), "file marked directory (%08lx)",
       (unsigned long)full.FileAttributes);
    ok(full.LastWriteTime.QuadPart != 0, "LastWriteTime zero");

    /* Agreement with NtQueryAttributesFile on the shared fields. */
    FILE_BASIC_INFORMATION basic;
    memset(&basic, 0xcc, sizeof(basic));
    status = NtQueryAttributesFile(&attr, &basic);
    ok(status == STATUS_SUCCESS, "basic attributes -> %08lx", (unsigned long)status);
    ok(basic.FileAttributes == full.FileAttributes, "attributes disagree (%08lx vs %08lx)",
       (unsigned long)basic.FileAttributes, (unsigned long)full.FileAttributes);
    ok(basic.LastWriteTime.QuadPart == full.LastWriteTime.QuadPart,
       "LastWriteTime disagrees (%lld vs %lld)", (long long)basic.LastWriteTime.QuadPart,
       (long long)full.LastWriteTime.QuadPart);

    /* --- a directory ------------------------------------------------------- */
    init_ustr(&name, W("\\??\\C:\\prstest\\fullattr"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    memset(&full, 0xcc, sizeof(full));
    status = NtQueryFullAttributesFile(&attr, &full);
    ok(status == STATUS_SUCCESS, "directory full attributes -> %08lx", (unsigned long)status);
    ok(full.FileAttributes & FILE_ATTRIBUTE_DIRECTORY, "directory not marked (%08lx)",
       (unsigned long)full.FileAttributes);

    /* --- a missing name ---------------------------------------------------- */
    init_ustr(&name, W("\\??\\C:\\prstest\\fullattr\\absent.txt"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtQueryFullAttributesFile(&attr, &full);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "missing file -> %08lx", (unsigned long)status);

    scrub_file(dir, W("fa.txt"));
    NtClose(dir);
}
