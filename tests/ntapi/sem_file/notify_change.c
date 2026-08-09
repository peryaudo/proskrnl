/*
 * sem_file/notify_change.c — NtNotifyChangeDirectoryFile (CUI-5).
 *
 * kernelbase's ReadDirectoryChangesW passes it straight through (the
 * OVERLAPPED is the IOSB) and FindFirstChangeNotificationW is the
 * zero-buffer form expecting STATUS_PENDING (dlls/kernelbase/file.c). The
 * contract (pinned Wine dlls/ntdll/unix/file.c NtNotifyChangeDirectoryFile
 * + server/change.c): the call always pends; filter 0 or unknown bits
 * refuse STATUS_INVALID_PARAMETER up front; a change completes the parked
 * request with FILE_NOTIFY_INFORMATION records (FileNameLength in bytes,
 * names relative to the watched directory, the last record's
 * NextEntryOffset 0) and Information = bytes written; a change that cannot
 * be delivered (no buffer, or one too small) completes
 * STATUS_NOTIFY_ENUM_DIR with Information 0; NtCancelIoFile completes a
 * parked watch STATUS_CANCELLED. Each test generates exactly ONE change
 * per armed watch so single-record assertions hold on both backends.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtNotifyChangeDirectoryFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                                    PIO_STATUS_BLOCK, PVOID, ULONG, ULONG, BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtCancelIoFile(HANDLE, PIO_STATUS_BLOCK);
NTSYSAPI NTSTATUS NTAPI NtSetInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
                                             FILE_INFORMATION_CLASS);

static HANDLE watch_dir; /* the watched directory (list access) */
static HANDLE aux_dir;   /* a second handle used to mutate it */

static NTSTATUS wait_ms(HANDLE object, LONG milliseconds)
{
    LARGE_INTEGER timeout;
    timeout.QuadPart = -(LONGLONG)milliseconds * 10000;
    return NtWaitForSingleObject(object, FALSE, &timeout);
}

static void make_file(const void *name)
{
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    NTSTATUS status = open_file(&handle, aux_dir, name, FILE_GENERIC_WRITE | SYNCHRONIZE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OVERWRITE_IF, 0, &iosb);
    ok(status == STATUS_SUCCESS, "make_file -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(handle);
}

/* One record in `buffer` with the given action and name. */
static void check_record(const void *buffer, ULONG information, ULONG action, const void *name)
{
    const FILE_NOTIFY_INFORMATION *record = (const FILE_NOTIFY_INFORMATION *)buffer;
    const unsigned short *p = (const unsigned short *)name;
    unsigned len = 0;
    while (p[len])
        len++;
    ok(record->NextEntryOffset == 0, "record NextEntryOffset %lu",
       (unsigned long)record->NextEntryOffset);
    ok(record->Action == action, "record Action %lu (want %lu)", (unsigned long)record->Action,
       (unsigned long)action);
    ok(record->FileNameLength == len * sizeof(WCHAR), "record FileNameLength %lu",
       (unsigned long)record->FileNameLength);
    ok(memcmp(record->FileName, name, record->FileNameLength) == 0, "record name");
    ok(information >= offsetof(FILE_NOTIFY_INFORMATION, FileName) + record->FileNameLength,
       "Information %lu covers the record", (unsigned long)information);
}

static volatile LONG apc_ran;
static PIO_STATUS_BLOCK apc_iosb_seen;

static void NTAPI notify_apc(PVOID context, PIO_STATUS_BLOCK iosb, ULONG reserved)
{
    (void)reserved;
    apc_iosb_seen = iosb;
    apc_ran = (LONG)(ULONG_PTR)context;
}

START_TEST(notify_change)
{
    NTSTATUS status;
    IO_STATUS_BLOCK iosb, watch_iosb;
    HANDLE event = NULL;
    char buffer[1024];

    aux_dir = open_test_dir(W("\\??\\C:\\prstest\\notify"));
    ok(aux_dir != NULL, "test dir");
    if (aux_dir == NULL)
        return;
    scrub_file(aux_dir, W("born.txt"));
    scrub_file(aux_dir, W("attr.txt"));
    scrub_file(aux_dir, W("apcfile.txt"));

    /* The watch handle, opened the way FindFirstChangeNotificationW opens
     * it (FILE_LIST_DIRECTORY | SYNCHRONIZE, synchronous). */
    {
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        init_ustr(&name, W("\\??\\C:\\prstest\\notify"));
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        status = NtOpenFile(&watch_dir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attr, &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
        ok(status == STATUS_SUCCESS, "open watch handle -> %08lx", (unsigned long)status);
    }
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create event -> %08lx", (unsigned long)status);

    /* --- filter validation refuses before pending --------------------------- */
    status = NtNotifyChangeDirectoryFile(watch_dir, event, NULL, NULL, &iosb, buffer,
                                         sizeof(buffer), 0, FALSE);
    ok(status == STATUS_INVALID_PARAMETER, "filter 0 -> %08lx", (unsigned long)status);
    status = NtNotifyChangeDirectoryFile(watch_dir, event, NULL, NULL, &iosb, buffer,
                                         sizeof(buffer), 0x80000000, FALSE);
    ok(status == STATUS_INVALID_PARAMETER, "bad filter -> %08lx", (unsigned long)status);

    /* --- a created file completes an armed watch ---------------------------- */
    poison_iosb(&watch_iosb);
    memset(buffer, 0, sizeof(buffer));
    status = NtNotifyChangeDirectoryFile(watch_dir, event, NULL, NULL, &watch_iosb, buffer,
                                         sizeof(buffer), FILE_NOTIFY_CHANGE_FILE_NAME, FALSE);
    ok(status == STATUS_PENDING, "arm -> %08lx", (unsigned long)status);
    ok(watch_iosb.Status == IOSB_POISON_STATUS, "armed iosb untouched");
    make_file(W("born.txt"));
    status = wait_ms(event, 5000);
    ok(status == STATUS_SUCCESS, "event after create -> %08lx", (unsigned long)status);
    ok(watch_iosb.Status == STATUS_SUCCESS, "watch iosb.Status %08lx",
       (unsigned long)watch_iosb.Status);
    check_record(buffer, (ULONG)watch_iosb.Information, FILE_ACTION_ADDED, W("born.txt"));

    /* --- a deleted file, through a fresh watch ------------------------------ */
    NtClearEvent(event);
    poison_iosb(&watch_iosb);
    memset(buffer, 0, sizeof(buffer));
    status = NtNotifyChangeDirectoryFile(watch_dir, event, NULL, NULL, &watch_iosb, buffer,
                                         sizeof(buffer), FILE_NOTIFY_CHANGE_FILE_NAME, FALSE);
    ok(status == STATUS_PENDING, "re-arm -> %08lx", (unsigned long)status);
    scrub_file(aux_dir, W("born.txt"));
    status = wait_ms(event, 5000);
    ok(status == STATUS_SUCCESS, "event after delete -> %08lx", (unsigned long)status);
    check_record(buffer, (ULONG)watch_iosb.Information, FILE_ACTION_REMOVED, W("born.txt"));

    /* --- the zero-buffer (FindFirstChangeNotification) shape ---------------- */
    NtClearEvent(event);
    poison_iosb(&watch_iosb);
    status = NtNotifyChangeDirectoryFile(watch_dir, event, NULL, NULL, &watch_iosb, NULL, 0,
                                         FILE_NOTIFY_CHANGE_FILE_NAME, FALSE);
    ok(status == STATUS_PENDING, "zero-buffer arm -> %08lx", (unsigned long)status);
    make_file(W("attr.txt"));
    status = wait_ms(event, 5000);
    ok(status == STATUS_SUCCESS, "event after zero-buffer change -> %08lx", (unsigned long)status);
    ok(watch_iosb.Status == STATUS_NOTIFY_ENUM_DIR, "zero-buffer iosb.Status %08lx",
       (unsigned long)watch_iosb.Status);
    ok(watch_iosb.Information == 0, "zero-buffer Information %lu",
       (unsigned long)watch_iosb.Information);

    /* --- an overflowing record degrades the same way ------------------------ */
    NtClearEvent(event);
    poison_iosb(&watch_iosb);
    status = NtNotifyChangeDirectoryFile(watch_dir, event, NULL, NULL, &watch_iosb, buffer,
                                         8 /* smaller than any record */,
                                         FILE_NOTIFY_CHANGE_FILE_NAME, FALSE);
    ok(status == STATUS_PENDING, "tiny-buffer arm -> %08lx", (unsigned long)status);
    scrub_file(aux_dir, W("attr.txt"));
    status = wait_ms(event, 5000);
    ok(status == STATUS_SUCCESS, "event after tiny-buffer change -> %08lx", (unsigned long)status);
    ok(watch_iosb.Status == STATUS_NOTIFY_ENUM_DIR, "tiny-buffer iosb.Status %08lx",
       (unsigned long)watch_iosb.Status);
    ok(watch_iosb.Information == 0, "tiny-buffer Information %lu",
       (unsigned long)watch_iosb.Information);

    /* The SUBTREE case is not here, and the reason is worth recording: this
     * handle was armed non-recursive above, and the subtree flag is fixed by
     * the FIRST arm exactly as the filter is. An earlier revision arranged
     * the recursive case on this same handle, measured that the oracle never
     * delivered, and concluded the oracle's recursive watcher does not work
     * under the test prefix — it works fine; the handle had simply already
     * been fixed non-recursive. sem_file/notify_queue.c pins the rule on a
     * fresh handle, and is oracle-green. */

    /* --- the APC completion shape ------------------------------------------- */
    apc_ran = 0;
    apc_iosb_seen = NULL;
    poison_iosb(&watch_iosb);
    memset(buffer, 0, sizeof(buffer));
    status =
        NtNotifyChangeDirectoryFile(watch_dir, NULL, notify_apc, (PVOID)(ULONG_PTR)77, &watch_iosb,
                                    buffer, sizeof(buffer), FILE_NOTIFY_CHANGE_FILE_NAME, FALSE);
    ok(status == STATUS_PENDING, "apc arm -> %08lx", (unsigned long)status);
    make_file(W("apcfile.txt"));
    {
        int spins = 0;
        while (apc_ran == 0 && spins++ < 100)
            SleepEx(50, TRUE); /* alertable: the APC fires here */
    }
    ok(apc_ran == 77, "apc ran (%ld)", (long)apc_ran);
    ok(apc_iosb_seen == &watch_iosb, "apc iosb pointer");
    ok(watch_iosb.Status == STATUS_SUCCESS, "apc iosb.Status %08lx",
       (unsigned long)watch_iosb.Status);
    check_record(buffer, (ULONG)watch_iosb.Information, FILE_ACTION_ADDED, W("apcfile.txt"));
    scrub_file(aux_dir, W("apcfile.txt"));

    /* --- NtCancelIoFile completes a parked watch ---------------------------- */
    /* Changes accumulate on the directory handle between watches, so the
     * scrubs above are queued and complete the next arm immediately: arm
     * until one stays PARKED, and that one is the cancel target
     * (sem_file/notify_queue.c pins the queueing itself). */
    {
        int drained = 0;
        for (int i = 0; i < 8; i++)
        {
            NtClearEvent(event);
            poison_iosb(&watch_iosb);
            status =
                NtNotifyChangeDirectoryFile(watch_dir, event, NULL, NULL, &watch_iosb, buffer,
                                            sizeof(buffer), FILE_NOTIFY_CHANGE_FILE_NAME, FALSE);
            ok(status == STATUS_PENDING, "drain arm %d -> %08lx", i, (unsigned long)status);
            if (wait_ms(event, 300) == STATUS_TIMEOUT)
            {
                drained = 1;
                break;
            }
        }
        ok(drained, "watch never parked");
    }
    status = NtCancelIoFile(watch_dir, &iosb);
    ok(status == STATUS_SUCCESS, "cancel -> %08lx", (unsigned long)status);
    status = wait_ms(event, 5000);
    ok(status == STATUS_SUCCESS, "event after cancel -> %08lx", (unsigned long)status);
    /* The cancelled watch signals its event but leaves the IOSB untouched —
     * the pinned Wine's error-completion convention (server/async.c
     * async_terminate passes the IOSB as NULL for an NT_ERROR status; the
     * same shape sem_file/volume_info.c documents for the drive-root
     * handle). */
    ok(watch_iosb.Status == IOSB_POISON_STATUS, "cancelled watch iosb untouched %08lx",
       (unsigned long)watch_iosb.Status);

    NtClose(event);
    NtClose(watch_dir);
    NtClose(aux_dir);
}
