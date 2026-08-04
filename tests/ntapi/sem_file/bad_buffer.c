/*
 * sem_file/bad_buffer.c — what a bad data buffer costs NtReadFile vs
 * NtWriteFile.
 *
 * Convicted by the winetest gate: ntdll:file (file.c:5077, 5085, 5088)
 * expects STATUS_INVALID_USER_BUFFER from a write with an unreadable
 * buffer, and proskrnl answered STATUS_ACCESS_VIOLATION — the status its
 * probe happens to produce.
 *
 * The two directions genuinely differ, and the pinned Wine says so in one
 * line each (dlls/ntdll/unix/file.c):
 *
 *   NtReadFile:  if (!virtual_check_buffer_for_write( buffer, length ))
 *                    return STATUS_ACCESS_VIOLATION;          (file.c:6064)
 *   NtWriteFile: if (!virtual_check_buffer_for_read( buffer, length ))
 *                { status = STATUS_INVALID_USER_BUFFER; goto done; }
 *                                                             (file.c:6354)
 *
 * — and the `return` vs `goto done` is a second difference, not a stylistic
 * one: the read direction leaves the caller's IOSB and event ALONE, while
 * the write direction falls into the normal completion path, so whether the
 * event ends up signalled is part of the contract. ntdll:file asserts
 * exactly that coupling, which is why this pin checks the side effects and
 * not just the returned status.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtSetEvent(HANDLE, PLONG);
NTSYSAPI NTSTATUS NTAPI NtResetEvent(HANDLE, PLONG);

/* Is `event` signalled right now? A zero-timeout wait, as Wine's own
 * is_signaled() helper does it. */
static BOOLEAN event_signaled(HANDLE event)
{
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    return NtWaitForSingleObject(event, FALSE, &zero) == STATUS_SUCCESS;
}

START_TEST(bad_buffer)
{
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    HANDLE dir, handle, event;

    dir = open_test_dir(W("\\??\\C:\\prstest\\badbuf"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("buf.txt"));

    status = open_file(
        &handle, dir, W("buf.txt"), FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "create buf.txt -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(dir);
        return;
    }

    OBJECT_ATTRIBUTES eventAttr;
    init_attr(&eventAttr, NULL, NULL, 0);
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, &eventAttr, SynchronizationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create event -> %08lx", (unsigned long)status);

    /* --- write: STATUS_INVALID_USER_BUFFER, not ACCESS_VIOLATION -------- */
    poison_iosb(&iosb);
    status = NtWriteFile(handle, NULL, NULL, NULL, &iosb, NULL, 16, NULL, NULL);
    ok(status == STATUS_INVALID_USER_BUFFER, "write NULL buffer -> %08lx", (unsigned long)status);

    /* --- ...and with an event, the two move together --------------------- */
    if (NT_SUCCESS(status) || status == STATUS_INVALID_USER_BUFFER)
    {
        poison_iosb(&iosb);
        (void)NtSetEvent(event, NULL); /* pre-signalled, as ntdll:file leaves it */
        status = NtWriteFile(handle, event, NULL, NULL, &iosb, NULL, 16, NULL, NULL);
        ok(status == STATUS_INVALID_USER_BUFFER, "write NULL buffer + event -> %08lx",
           (unsigned long)status);
        /* ntdll:file's own coupling: the event is signalled exactly when the
         * IOSB was written with the failure. */
        ok(!event_signaled(event) == !(iosb.Status == STATUS_INVALID_USER_BUFFER),
           "event/IOSB disagree: iosb.Status %08lx", (unsigned long)iosb.Status);
    }

    /* --- read: ACCESS_VIOLATION, and the IOSB is left alone -------------- */
    poison_iosb(&iosb);
    status = NtReadFile(handle, NULL, NULL, NULL, &iosb, NULL, 16, NULL, NULL);
    ok(status == STATUS_ACCESS_VIOLATION, "read NULL buffer -> %08lx", (unsigned long)status);
    ok(iosb.Status == IOSB_POISON_STATUS, "read left IOSB written: %08lx",
       (unsigned long)iosb.Status);

    NtClose(event);
    NtClose(handle);
    NtClose(dir);
}
