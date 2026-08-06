/*
 * sem_file/dir_handle_signal.c — a file HANDLE is a waitable object, and an
 * outstanding asynchronous request makes it UNSIGNALLED.
 *
 * Convicted by the winetest gate: ntdll:change issues a pending
 * NtNotifyChangeDirectoryFile and then waits on the directory handle
 * itself, requiring a TIMEOUT (change.c:106, :112, :143). proskrnl's file
 * objects are born signalled and never clear (kernel/io/io.h says so in as
 * many words), so all three waits returned immediately.
 *
 * "Always signalled" was a defensible reading while every operation
 * completed inline — an object that is never busy is never unsignalled, and
 * the pinned Wine reports disk file handles signalled too. What breaks it
 * is that NtNotifyChangeDirectoryFile is the one service that genuinely
 * PENDS: it returns STATUS_PENDING and completes later, so there is a real
 * interval during which the object is busy, and NT's rule for that interval
 * is observable. This pin is that interval and nothing else — it does not
 * claim anything about the file object during inline I/O, which stays
 * signalled throughout on both runners because the request never outlives
 * the call.
 *
 * The sequence:
 *   1. a fresh directory handle waits SIGNALLED (nothing outstanding),
 *   2. arming a watch clears it — the wait times out,
 *   3. the change that completes the watch signals it again.
 *
 * Step 3 is what makes step 2 a real contract rather than "the handle is
 * never signalled": an implementation that simply stopped signalling file
 * objects would pass step 2 and fail step 3.
 *
 * Oracle-first (G5).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtNotifyChangeDirectoryFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                                    PIO_STATUS_BLOCK, PVOID, ULONG, ULONG, BOOLEAN);

static UCHAR notifyBuffer[2048];

static NTSTATUS wait_ms(HANDLE object, LONG milliseconds)
{
    LARGE_INTEGER timeout;
    timeout.QuadPart = -(LONGLONG)milliseconds * 10000;
    return NtWaitForSingleObject(object, FALSE, &timeout);
}

START_TEST(dir_handle_signal)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, aux, scratch;

    dir = open_test_dir(W("\\??\\C:\\prstest\\dirsignal"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    aux = open_test_dir(W("\\??\\C:\\prstest\\dirsignal"));
    ok(aux != NULL, "second handle to the test dir");
    if (aux == NULL)
    {
        NtClose(dir);
        return;
    }
    scrub_file(aux, W("trigger.tmp"));

    /* --- 1. nothing outstanding: the handle is signalled ------------------- */
    status = wait_ms(dir, 0);
    ok(status == STATUS_SUCCESS, "idle directory handle -> %08lx", (unsigned long)status);

    /* --- 2. a pending watch makes it busy --------------------------------- */
    iosb.Status = (NTSTATUS)0x01234567;
    iosb.Information = 0;
    status = NtNotifyChangeDirectoryFile(dir, NULL, NULL, NULL, &iosb, notifyBuffer,
                                         sizeof(notifyBuffer), FILE_NOTIFY_CHANGE_FILE_NAME, FALSE);
    ok(status == STATUS_PENDING, "arm the watch -> %08lx", (unsigned long)status);
    if (status != STATUS_PENDING)
    {
        NtClose(aux);
        NtClose(dir);
        return;
    }

    status = wait_ms(dir, 100);
    ok(status == STATUS_TIMEOUT, "handle with a request outstanding -> %08lx",
       (unsigned long)status);

    /* --- 3. the completion signals it ------------------------------------- */
    status = open_file(&scratch, aux, W("trigger.tmp"), FILE_GENERIC_WRITE | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create the trigger -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(scratch);

    status = wait_ms(dir, 2000);
    ok(status == STATUS_SUCCESS, "handle after the watch completed -> %08lx",
       (unsigned long)status);

    /* --- and it STAYS signalled: this is a notification-shaped object, not
     * an auto-reset one, so a second wait succeeds without a second
     * completion. */
    status = wait_ms(dir, 0);
    ok(status == STATUS_SUCCESS, "handle stays signalled -> %08lx", (unsigned long)status);

    scrub_file(aux, W("trigger.tmp"));
    NtClose(aux);
    NtClose(dir);
}
