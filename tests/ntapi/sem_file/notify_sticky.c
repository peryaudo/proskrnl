/*
 * sem_file/notify_sticky.c — two rules about a parked directory watch that
 * are each surprising on their own.
 *
 * 1. THE COMPLETION FILTER BELONGS TO THE HANDLE, NOT THE CALL. The first
 *    NtNotifyChangeDirectoryFile on a file object fixes the filter and the
 *    subtree flag; every later arm on the SAME handle reuses them and its
 *    own arguments are ignored. The pinned server says so in a comment —
 *    the filter, subtree and want_data are stored only `if (!dir->filter)`
 *    (third_party/wine server/change.c, DECL_HANDLER(read_directory_changes),
 *    under "assign it once") — and NT reaches the same place by reusing the
 *    existing notify entry for a repeated FsContext.
 *
 *    It reads like a bug and is not, which is exactly why it needs a pin: a
 *    kernel that honours the second call's filter is doing the obvious
 *    thing, and the watch it parks can never complete.
 *
 * 2. A CANCELLED WATCH WRITES ITS IOSB. "An error status skips the IOSB" is
 *    a rule about a request that never STARTED — the caller still holds the
 *    status the syscall returned. A watch that returned STATUS_PENDING has
 *    no other channel left: GetOverlappedResult reads that IOSB and nothing
 *    else, so a kernel that skips it on cancellation leaves the caller
 *    staring at its own initialisation value forever.
 *
 * Both were measured by ntdll:change (change.c:132-:155 for the filter,
 * :304-:309 for the cancel) and both are pinned here because neither is
 * about directory notification specifically — they are about what a pended
 * request owes its caller.
 *
 * Oracle-first (G5).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtNotifyChangeDirectoryFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                                    PIO_STATUS_BLOCK, PVOID, ULONG, ULONG, BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtCancelIoFile(HANDLE, PIO_STATUS_BLOCK);

START_TEST(notify_sticky)
{
    WCHAR dirPath[MAX_PATH + 32];
    WCHAR subPath[MAX_PATH + 64];
    HANDLE dir;
    NTSTATUS status;
    IO_STATUS_BLOCK iosb, iosb2, cancelIosb;
    UCHAR buffer[0x400];
    DWORD len = GetTempPathW(MAX_PATH, dirPath);

    ok(len != 0 && len < MAX_PATH, "GetTempPathW -> %lu", (unsigned long)len);
    if (len == 0 || len >= MAX_PATH)
    {
        return;
    }
    lstrcatW(dirPath, L"prsnotify");
    RemoveDirectoryW(dirPath);
    ok(CreateDirectoryW(dirPath, NULL) != 0, "create the watch directory -> %lu",
       (unsigned long)GetLastError());

    lstrcpyW(subPath, dirPath);
    lstrcatW(subPath, L"\\sub");

    dir = CreateFileW(dirPath, GENERIC_READ | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    ok(dir != INVALID_HANDLE_VALUE, "open the watch directory -> %lu",
       (unsigned long)GetLastError());
    if (dir == INVALID_HANDLE_VALUE)
    {
        RemoveDirectoryW(dirPath);
        return;
    }

    /* --- (1) the first arm fixes the filter ----------------------------
     * Armed for DIR_NAME. Completed, so the handle is idle again — the
     * association is with the HANDLE and survives its watches. */
    iosb.Status = (NTSTATUS)0x01234567;
    iosb.Information = (ULONG_PTR)0x12345678;
    status = NtNotifyChangeDirectoryFile(dir, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer),
                                         FILE_NOTIFY_CHANGE_DIR_NAME, FALSE);
    ok(status == STATUS_PENDING, "the first arm -> %08lx", (unsigned long)status);

    ok(CreateDirectoryW(subPath, NULL) != 0, "create the subdirectory -> %lu",
       (unsigned long)GetLastError());
    ok(WaitForSingleObject(dir, 2000) == WAIT_OBJECT_0, "the first watch did not complete");
    ok(iosb.Status == STATUS_SUCCESS, "the first watch -> %08lx", (unsigned long)iosb.Status);

    /* Now arm for something the next change is NOT: a directory removal is
     * FILE_NOTIFY_CHANGE_DIR_NAME, and this asks for SIZE alone. It
     * completes anyway, because the handle's filter is still the one the
     * first call established. */
    iosb.Status = (NTSTATUS)0x01234567;
    iosb.Information = (ULONG_PTR)0x12345678;
    status = NtNotifyChangeDirectoryFile(dir, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer),
                                         FILE_NOTIFY_CHANGE_SIZE, FALSE);
    ok(status == STATUS_PENDING, "the re-arm -> %08lx", (unsigned long)status);

    ok(RemoveDirectoryW(subPath) != 0, "remove the subdirectory -> %lu",
       (unsigned long)GetLastError());
    ok(WaitForSingleObject(dir, 2000) == WAIT_OBJECT_0,
       "a SIZE-filtered re-arm did not see a DIR_NAME change — the handle's "
       "filter was replaced");

    /* --- (2) a cancelled watch reports STATUS_CANCELLED in its IOSB ----
     * Two of them, so the sweep is over a handle rather than a request, and
     * both must be written. */
    iosb.Status = (NTSTATUS)0x01234567;
    iosb.Information = (ULONG_PTR)0x12345678;
    status = NtNotifyChangeDirectoryFile(dir, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer),
                                         FILE_NOTIFY_CHANGE_DIR_NAME, FALSE);
    ok(status == STATUS_PENDING, "the first watch to cancel -> %08lx", (unsigned long)status);

    iosb2.Status = (NTSTATUS)0x01234567;
    iosb2.Information = (ULONG_PTR)0x12345678;
    status = NtNotifyChangeDirectoryFile(dir, NULL, NULL, NULL, &iosb2, buffer, sizeof(buffer),
                                         FILE_NOTIFY_CHANGE_DIR_NAME, FALSE);
    ok(status == STATUS_PENDING, "the second watch to cancel -> %08lx", (unsigned long)status);

    /* Neither has fired: a second arm does not complete the first. */
    ok(iosb.Status == (NTSTATUS)0x01234567, "the first watch completed too soon: %08lx",
       (unsigned long)iosb.Status);

    cancelIosb.Status = (NTSTATUS)0x111111;
    cancelIosb.Information = (ULONG_PTR)0x222222;
    status = NtCancelIoFile(dir, &cancelIosb);
    ok(status == STATUS_SUCCESS, "cancel -> %08lx", (unsigned long)status);

    ok(iosb.Status == STATUS_CANCELLED, "the first watch's IOSB reads %08lx, wanted CANCELLED",
       (unsigned long)iosb.Status);
    ok(iosb.Information == 0, "the first watch's Information is %lx",
       (unsigned long)iosb.Information);
    ok(iosb2.Status == STATUS_CANCELLED, "the second watch's IOSB reads %08lx, wanted CANCELLED",
       (unsigned long)iosb2.Status);
    ok(iosb2.Information == 0, "the second watch's Information is %lx",
       (unsigned long)iosb2.Information);

    CloseHandle(dir);
    RemoveDirectoryW(dirPath);
}
