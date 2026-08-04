/*
 * sem_file/file_pointer_offset.c — the FILE_USE_FILE_POINTER_POSITION
 * offset sentinel (-2).
 *
 * proskrnl refused every negative ByteOffset except the write path's -1
 * (FILE_WRITE_TO_END_OF_FILE), and said so in kernel/io/rw.c: -2 was
 * "unpinned, no baked caller". ntdll:file produced the caller — file.c:5183
 * seeks with SetFilePointer, then writes "DCBA" with offset -2 and expects
 * STATUS_SUCCESS at the seeked position — so the refusal was a divergence,
 * not a deferral, and the whole tail of that subtest failed behind it.
 *
 * -2 means what a NULL ByteOffset means: use the handle's current position,
 * and advance it. This pins that equivalence in both directions, and pins
 * that the refusal still holds one step further down (-3), which is the
 * same subtest's other expectation.
 *
 * Oracle-first (G5).
 */
#include "util.h"

/* The sentinels, spelled as the pinned tree spells them
 * (dlls/ntdll/unix/unix_private.h). */
#define FILE_USE_FILE_POINTER_POSITION ((LONGLONG) - 2)
#define FILE_WRITE_TO_END_OF_FILE      ((LONGLONG) - 1)

static ULONGLONG current_position(HANDLE handle)
{
    FILE_POSITION_INFORMATION position;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    memset(&position, 0, sizeof(position));
    status =
        NtQueryInformationFile(handle, &iosb, &position, sizeof(position), FilePositionInformation);
    ok(status == STATUS_SUCCESS, "query position -> %08lx", (unsigned long)status);
    return NT_SUCCESS(status) ? (ULONGLONG)position.CurrentByteOffset.QuadPart : 0;
}

static void set_position(HANDLE handle, ULONGLONG value)
{
    FILE_POSITION_INFORMATION position;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    position.CurrentByteOffset.QuadPart = (LONGLONG)value;
    status =
        NtSetInformationFile(handle, &iosb, &position, sizeof(position), FilePositionInformation);
    ok(status == STATUS_SUCCESS, "set position -> %08lx", (unsigned long)status);
}

START_TEST(file_pointer_offset)
{
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    HANDLE dir, handle;
    char buffer[8];

    dir = open_test_dir(W("\\??\\C:\\prstest\\fpoff"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("fp.txt"));

    status = open_file(
        &handle, dir, W("fp.txt"), FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "create fp.txt -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(dir);
        return;
    }

    /* "ABCDEFGH" at the front, through the ordinary offset path. */
    offset.QuadPart = 0;
    status = NtWriteFile(handle, NULL, NULL, NULL, &iosb, "ABCDEFGH", 8, &offset, NULL);
    ok(status == STATUS_SUCCESS, "seed write -> %08lx", (unsigned long)status);

    /* --- a write at -2 lands at the current position --------------------- */
    set_position(handle, 4);
    offset.QuadPart = FILE_USE_FILE_POINTER_POSITION;
    poison_iosb(&iosb);
    status = NtWriteFile(handle, NULL, NULL, NULL, &iosb, "wxyz", 4, &offset, NULL);
    ok(status == STATUS_SUCCESS, "write at -2 -> %08lx", (unsigned long)status);
    ok(iosb.Information == 4, "write at -2 moved %lu bytes", (unsigned long)iosb.Information);
    /* ...and it ADVANCES the position, exactly as a NULL offset would. */
    ok(current_position(handle) == 8, "position after -2 write = %lu",
       (unsigned long)current_position(handle));

    /* --- a read at -2 reads from the current position --------------------- */
    set_position(handle, 4);
    offset.QuadPart = FILE_USE_FILE_POINTER_POSITION;
    memset(buffer, 0, sizeof(buffer));
    poison_iosb(&iosb);
    status = NtReadFile(handle, NULL, NULL, NULL, &iosb, buffer, 4, &offset, NULL);
    ok(status == STATUS_SUCCESS, "read at -2 -> %08lx", (unsigned long)status);
    ok(iosb.Information == 4, "read at -2 moved %lu bytes", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "wxyz", 4) == 0, "read at -2 got %.4s", buffer);
    ok(current_position(handle) == 8, "position after -2 read = %lu",
       (unsigned long)current_position(handle));

    /* --- one step further down is still refused --------------------------- */
    offset.QuadPart = -3;
    poison_iosb(&iosb);
    status = NtWriteFile(handle, NULL, NULL, NULL, &iosb, "!!", 2, &offset, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "write at -3 -> %08lx", (unsigned long)status);
    ok(iosb.Status == IOSB_POISON_STATUS, "write at -3 wrote the IOSB: %08lx",
       (unsigned long)iosb.Status);

    offset.QuadPart = -3;
    status = NtReadFile(handle, NULL, NULL, NULL, &iosb, buffer, 2, &offset, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "read at -3 -> %08lx", (unsigned long)status);

    /* --- -1 is the write's end-of-file sentinel, and NOT a read's --------- */
    offset.QuadPart = FILE_WRITE_TO_END_OF_FILE;
    poison_iosb(&iosb);
    status = NtWriteFile(handle, NULL, NULL, NULL, &iosb, "Z", 1, &offset, NULL);
    ok(status == STATUS_SUCCESS, "write at -1 -> %08lx", (unsigned long)status);

    offset.QuadPart = FILE_WRITE_TO_END_OF_FILE;
    status = NtReadFile(handle, NULL, NULL, NULL, &iosb, buffer, 1, &offset, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "read at -1 -> %08lx", (unsigned long)status);

    FILE_DISPOSITION_INFORMATION disposition;
    disposition.DoDeleteFile = TRUE;
    (void)NtSetInformationFile(handle, &iosb, &disposition, sizeof(disposition),
                               FileDispositionInformation);
    NtClose(handle);
    NtClose(dir);
}
