/*
 * sem_file/append.c — FILE_APPEND_DATA write semantics (CUI-3). The
 * consumer that convicts them: a service binary appending its proof to a
 * log with CreateFileW(FILE_APPEND_DATA) + WriteFile — kernelbase passes a
 * NULL ByteOffset, and NT serves the write at END OF FILE because the
 * handle is append-only (no FILE_WRITE_DATA). The explicit
 * FILE_WRITE_TO_END_OF_FILE sentinel (ByteOffset.QuadPart == -1) does the
 * same on a normal write handle. A kernel that demands FILE_WRITE_DATA
 * unconditionally fails every append-mode logger silently.
 */
#include "util.h"

static void read_back(HANDLE dir, const void *name, char *buffer, ULONG capacity, ULONG *lengthOut)
{
    IO_STATUS_BLOCK iosb;
    HANDLE handle = NULL;
    LARGE_INTEGER zero;
    NTSTATUS status =
        open_file(&handle, dir, name, FILE_READ_DATA | SYNCHRONIZE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "read-back open -> %08lx", (unsigned long)status);
    zero.QuadPart = 0;
    status = NtReadFile(handle, NULL, NULL, NULL, &iosb, buffer, capacity, &zero, NULL);
    ok(status == STATUS_SUCCESS || status == STATUS_END_OF_FILE, "read-back -> %08lx",
       (unsigned long)status);
    *lengthOut = status == STATUS_SUCCESS ? (ULONG)iosb.Information : 0;
    NtClose(handle);
}

START_TEST(append)
{
    IO_STATUS_BLOCK iosb;
    HANDLE dir, handle = NULL;
    char buffer[64];
    ULONG length;
    NTSTATUS status;

    dir = open_test_dir(W("\\??\\C:\\prstest\\append"));
    if (dir == NULL)
        return;
    scrub_file(dir, W("log.txt"));

    /* Seed four bytes through a normal write handle. */
    status =
        open_file(&handle, dir, W("log.txt"), FILE_WRITE_DATA | SYNCHRONIZE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, FILE_NON_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "seed create -> %08lx", (unsigned long)status);
    status = NtWriteFile(handle, NULL, NULL, NULL, &iosb, "AAAA", 4, NULL, NULL);
    ok(status == STATUS_SUCCESS, "seed write -> %08lx", (unsigned long)status);

    /* FILE_WRITE_TO_END_OF_FILE (-1) on the same write handle lands at EOF,
     * wherever the position points. */
    LARGE_INTEGER toEnd;
    toEnd.QuadPart = -1;
    status = NtWriteFile(handle, NULL, NULL, NULL, &iosb, "BB", 2, &toEnd, NULL);
    ok(status == STATUS_SUCCESS, "write-to-end -> %08lx", (unsigned long)status);
    ok(iosb.Information == 2, "write-to-end length %lu", (unsigned long)iosb.Information);
    NtClose(handle);
    read_back(dir, W("log.txt"), buffer, sizeof(buffer), &length);
    ok(length == 6 && memcmp(buffer, "AAAABB", 6) == 0, "after write-to-end: %lu bytes",
       (unsigned long)length);

    /* An APPEND-ONLY handle (FILE_APPEND_DATA, no FILE_WRITE_DATA): the
     * kernelbase WriteFile shape — NULL ByteOffset — appends at EOF. */
    status =
        open_file(&handle, dir, W("log.txt"), FILE_APPEND_DATA | SYNCHRONIZE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "append open -> %08lx", (unsigned long)status);
    status = NtWriteFile(handle, NULL, NULL, NULL, &iosb, "CC", 2, NULL, NULL);
    ok(status == STATUS_SUCCESS, "append write -> %08lx", (unsigned long)status);
    ok(iosb.Information == 2, "append length %lu", (unsigned long)iosb.Information);
    /* A second append keeps landing at the (new) EOF. */
    status = NtWriteFile(handle, NULL, NULL, NULL, &iosb, "DD", 2, NULL, NULL);
    ok(status == STATUS_SUCCESS, "second append -> %08lx", (unsigned long)status);
    read_back(dir, W("log.txt"), buffer, sizeof(buffer), &length);
    ok(length == 10 && memcmp(buffer, "AAAABBCCDD", 10) == 0, "after appends: %lu bytes",
       (unsigned long)length);

    /* Reading through the append-only handle is denied (no FILE_READ_DATA). */
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    status = NtReadFile(handle, NULL, NULL, NULL, &iosb, buffer, 4, &zero, NULL);
    ok(status == STATUS_ACCESS_DENIED, "read on append handle -> %08lx", (unsigned long)status);
    NtClose(handle);

    scrub_file(dir, W("log.txt"));
    NtClose(dir);
}
