/*
 * sem_file/zero_length_write.c — a zero-length NtWriteFile never extends
 * the file (CUI-8 follow-up; PR #95 review round 2, F5). The extend
 * decision `offset + length > fileSize` is length-blind, so a 0-byte write
 * at a far offset silently allocated and zero-filled every gap cluster —
 * on NT (and the pinned Wine, whose unix write loop simply writes nothing)
 * the file is untouched and the call answers STATUS_SUCCESS with
 * Information 0. Pinned at the three offset shapes a caller can spell:
 * explicit far offset, NULL (current position), and the
 * FILE_WRITE_TO_END_OF_FILE sentinel.
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

START_TEST(zero_length_write)
{
    IO_STATUS_BLOCK iosb;
    HANDLE dir, handle = NULL;
    char buffer[64];
    ULONG length;
    NTSTATUS status;

    dir = open_test_dir(W("\\??\\C:\\prstest\\zerowr"));
    if (dir == NULL)
        return;
    scrub_file(dir, W("zero.bin"));

    status =
        open_file(&handle, dir, W("zero.bin"), FILE_WRITE_DATA | SYNCHRONIZE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, FILE_NON_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "seed create -> %08lx", (unsigned long)status);
    status = NtWriteFile(handle, NULL, NULL, NULL, &iosb, "AAAA", 4, NULL, NULL);
    ok(status == STATUS_SUCCESS, "seed write -> %08lx", (unsigned long)status);

    /* Zero bytes at an explicit offset far past EOF: success, nothing
     * written, and — the conviction — the file does NOT grow to 4096. */
    LARGE_INTEGER far_off;
    far_off.QuadPart = 4096;
    iosb.Information = 0x77;
    status = NtWriteFile(handle, NULL, NULL, NULL, &iosb, buffer, 0, &far_off, NULL);
    ok(status == STATUS_SUCCESS, "zero write at 4096 -> %08lx", (unsigned long)status);
    ok(iosb.Information == 0, "zero write information %lu", (unsigned long)iosb.Information);
    read_back(dir, W("zero.bin"), buffer, sizeof(buffer), &length);
    ok(length == 4 && memcmp(buffer, "AAAA", 4) == 0,
       "after zero write at 4096: %lu bytes (must stay 4)", (unsigned long)length);

    /* Zero bytes at the current position (NULL ByteOffset). */
    status = NtWriteFile(handle, NULL, NULL, NULL, &iosb, buffer, 0, NULL, NULL);
    ok(status == STATUS_SUCCESS, "zero write at position -> %08lx", (unsigned long)status);
    ok(iosb.Information == 0, "positioned zero write information %lu",
       (unsigned long)iosb.Information);

    /* Zero bytes through the FILE_WRITE_TO_END_OF_FILE sentinel. */
    LARGE_INTEGER to_end;
    to_end.QuadPart = -1;
    status = NtWriteFile(handle, NULL, NULL, NULL, &iosb, buffer, 0, &to_end, NULL);
    ok(status == STATUS_SUCCESS, "zero write to end -> %08lx", (unsigned long)status);
    ok(iosb.Information == 0, "to-end zero write information %lu", (unsigned long)iosb.Information);
    NtClose(handle);

    read_back(dir, W("zero.bin"), buffer, sizeof(buffer), &length);
    ok(length == 4 && memcmp(buffer, "AAAA", 4) == 0,
       "after all zero writes: %lu bytes (must stay 4)", (unsigned long)length);

    /* The handle and file stay fully usable: a real write still lands. */
    status =
        open_file(&handle, dir, W("zero.bin"), FILE_WRITE_DATA | SYNCHRONIZE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "re-open -> %08lx", (unsigned long)status);
    to_end.QuadPart = -1;
    status = NtWriteFile(handle, NULL, NULL, NULL, &iosb, "BB", 2, &to_end, NULL);
    ok(status == STATUS_SUCCESS && iosb.Information == 2, "real append -> %08lx/%lu",
       (unsigned long)status, (unsigned long)iosb.Information);
    NtClose(handle);
    read_back(dir, W("zero.bin"), buffer, sizeof(buffer), &length);
    ok(length == 6 && memcmp(buffer, "AAAABB", 6) == 0, "after real append: %lu bytes",
       (unsigned long)length);

    scrub_file(dir, W("zero.bin"));
    NtClose(dir);
}
