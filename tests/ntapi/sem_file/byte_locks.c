/*
 * sem_file/byte_locks.c — NtLockFile/NtUnlockFile byte-range locks (M6).
 *
 * Pins grant/conflict semantics with FailImmediately (the waiting path needs
 * a second thread to ever release, so a single-threaded M6 test sticks to
 * immediate failure): exclusive vs. shared, cross-handle conflicts, the
 * exact-range unlock rule, and unlock-on-close. A FailImmediately conflict
 * is STATUS_FILE_LOCK_CONFLICT on the pinned Wine (dont_wait lock refusal).
 */
#include "util.h"

/* Only the bare form is exercised: the pinned Wine's own PE stack never
 * passes an apc, io_status, or key, so its answer for those is unbuilt
 * (STATUS_NOT_IMPLEMENTED) rather than a contract — and an unbuilt oracle
 * answer is never pinned (Art. 12). The helpers therefore pass NULLs. */
static NTSTATUS lock_range(HANDLE h, long long start, long long length, BOOLEAN exclusive)
{
    LARGE_INTEGER offset, size;

    offset.QuadPart = start;
    size.QuadPart = length;
    return NtLockFile(h, NULL, NULL, NULL, NULL, &offset, &size, NULL, TRUE /* fail now */,
                      exclusive);
}

static NTSTATUS unlock_range(HANDLE h, long long start, long long length)
{
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset, size;

    poison_iosb(&iosb);
    offset.QuadPart = start;
    size.QuadPart = length;
    return NtUnlockFile(h, &iosb, &offset, &size, NULL);
}

START_TEST(byte_locks)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, h1, h2;

    dir = open_test_dir(W("\\??\\C:\\prstest\\locks"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("locked.dat"));

    status = open_file(&h1, dir, W("locked.dat"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create locked.dat -> %08lx", (unsigned long)status);
    static const char blob[64] = "lock me";
    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    status = NtWriteFile(h1, NULL, NULL, NULL, &iosb, blob, sizeof(blob), &offset, NULL);
    ok(status == STATUS_SUCCESS, "fill file -> %08lx", (unsigned long)status);

    status = open_file(&h2, dir, W("locked.dat"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "second open -> %08lx", (unsigned long)status);

    /* --- exclusive lock blocks overlap from the other handle. -------------- */
    status = lock_range(h1, 0, 16, TRUE);
    ok(status == STATUS_SUCCESS, "h1 exclusive [0,16) -> %08lx", (unsigned long)status);
    status = lock_range(h2, 8, 16, TRUE);
    ok(status == STATUS_FILE_LOCK_CONFLICT, "h2 overlap exclusive -> %08lx", (unsigned long)status);
    status = lock_range(h2, 8, 16, FALSE);
    ok(status == STATUS_FILE_LOCK_CONFLICT, "h2 overlap shared -> %08lx", (unsigned long)status);

    /* --- disjoint ranges are fine. ----------------------------------------- */
    status = lock_range(h2, 16, 16, TRUE);
    ok(status == STATUS_SUCCESS, "h2 exclusive [16,32) -> %08lx", (unsigned long)status);

    /* --- shared locks coexist; an exclusive over them does not. ------------ */
    status = lock_range(h1, 32, 8, FALSE);
    ok(status == STATUS_SUCCESS, "h1 shared [32,40) -> %08lx", (unsigned long)status);
    status = lock_range(h2, 32, 8, FALSE);
    ok(status == STATUS_SUCCESS, "h2 shared [32,40) -> %08lx", (unsigned long)status);
    status = lock_range(h2, 32, 8, TRUE);
    ok(status == STATUS_FILE_LOCK_CONFLICT, "exclusive over shared -> %08lx", (unsigned long)status);

    /* --- unlock demands the exact locked range. ---------------------------- */
    status = unlock_range(h1, 0, 8);
    ok(status == STATUS_RANGE_NOT_LOCKED, "partial unlock -> %08lx", (unsigned long)status);
    status = unlock_range(h1, 0, 16);
    ok(status == STATUS_SUCCESS, "exact unlock -> %08lx", (unsigned long)status);
    status = lock_range(h2, 0, 16, TRUE);
    ok(status == STATUS_SUCCESS, "h2 takes the freed range -> %08lx", (unsigned long)status);

    /* --- unlocking a range the handle does not hold fails. ----------------- */
    status = unlock_range(h1, 16, 16);
    ok(status == STATUS_RANGE_NOT_LOCKED, "unlock other handle's lock -> %08lx",
       (unsigned long)status);

    /* --- shared locks unlock per-handle. ----------------------------------- */
    status = unlock_range(h1, 32, 8);
    ok(status == STATUS_SUCCESS, "h1 drops its shared lock -> %08lx", (unsigned long)status);
    status = unlock_range(h1, 32, 8);
    ok(status == STATUS_RANGE_NOT_LOCKED, "h1 double-unlock -> %08lx", (unsigned long)status);
    status = unlock_range(h2, 32, 8);
    ok(status == STATUS_SUCCESS, "h2 drops its shared lock -> %08lx", (unsigned long)status);

    /* --- locks past EOF are legal. ----------------------------------------- */
    status = lock_range(h1, 1024, 64, TRUE);
    ok(status == STATUS_SUCCESS, "lock past EOF -> %08lx", (unsigned long)status);
    status = unlock_range(h1, 1024, 64);
    ok(status == STATUS_SUCCESS, "unlock past EOF -> %08lx", (unsigned long)status);

    /* --- closing a handle releases its locks. ------------------------------ */
    NtClose(h2); /* held [16,32) and [0,16) */
    status = lock_range(h1, 0, 32, TRUE);
    ok(status == STATUS_SUCCESS, "range free after close -> %08lx", (unsigned long)status);
    status = unlock_range(h1, 0, 32);
    ok(status == STATUS_SUCCESS, "final unlock -> %08lx", (unsigned long)status);

    NtClose(h1);
    scrub_file(dir, W("locked.dat"));
    NtClose(dir);
}
