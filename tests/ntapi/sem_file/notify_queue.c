/*
 * sem_file/notify_queue.c — what a directory watch REMEMBERS.
 *
 * sem_file/notify_change.c pins one armed watch seeing one change.
 * Everything here is about the state that outlives a single arm, and each
 * rule has the same single source: the pinned server keeps the notification
 * state on the DIRECTORY OBJECT, not on the request
 * (third_party/wine server/change.c, `struct dir`), and
 * DECL_HANDLER(read_directory_changes) stores the request's parameters only
 * `if (!dir->filter)` — the block it labels "assign it once".
 *
 * 1. CHANGES QUEUE WITH NOTHING ARMED. `dir->change_records` is appended to
 *    by inotify_do_change_notify whether or not a request is parked, and a
 *    later arm that finds the list non-empty completes immediately
 *    (the `if (!list_empty( &dir->change_records ))` wake at the end of the
 *    same handler). A kernel that only delivers to an already-parked watch
 *    loses every change that happens between two arms — which is most of
 *    them, since the caller is running code in between.
 *
 * 2. A RENAME IN PLACE IS TWO CHAINED RECORDS. FILE_ACTION_RENAMED_OLD_NAME
 *    then FILE_ACTION_RENAMED_NEW_NAME, linked by NextEntryOffset and
 *    delivered in ONE completion — read_change drains the whole queue into
 *    one reply and read_changes_apc chains them (dlls/ntdll/unix/file.c).
 *    Delivering only the first is indistinguishable from a plain delete to
 *    the caller.
 *
 * 3. THE SUBTREE FLAG IS STICKY, exactly like the filter. It is stored in
 *    the same "assign it once" block, so a handle first armed recursive
 *    stays recursive however later arms spell it.
 *
 * 4. SO IS "DID THE CALLER PASS A BUFFER". The server stores
 *    `want_data = (buffer != NULL)` there too, and when it is clear
 *    inotify_do_change_notify queues NO RECORD AT ALL — it only wakes the
 *    request. So a handle whose FIRST arm was the zero-buffer
 *    (FindFirstChangeNotification) shape can never report record data
 *    again: every later completion is STATUS_NOTIFY_ENUM_DIR with
 *    Information 0, however large a buffer it is handed.
 *
 * Rules 1-4 are all measured by kernel32:change, which is why they are
 * pinned together. Oracle-first (G5).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtNotifyChangeDirectoryFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                                    PIO_STATUS_BLOCK, PVOID, ULONG, ULONG, BOOLEAN);

#define NOTIFY_FILTER (FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME)

static WCHAR root_path[MAX_PATH + 32];

/* Open the watched directory the way ReadDirectoryChangesW's callers do. */
static HANDLE open_watch(void)
{
    HANDLE handle =
        CreateFileW(root_path, GENERIC_READ | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    ok(handle != INVALID_HANDLE_VALUE, "open the watch directory -> %lu",
       (unsigned long)GetLastError());
    return handle;
}

/* Build root_path + `leaf` (which carries its own leading backslash). */
static void under_root(WCHAR *out, const WCHAR *leaf)
{
    lstrcpyW(out, root_path);
    lstrcatW(out, leaf);
}

/* Check one record; returns its NextEntryOffset so a caller can walk on. */
static ULONG check_record(const FILE_NOTIFY_INFORMATION *record, ULONG action, const WCHAR *name,
                          const char *what)
{
    ULONG nameBytes = (ULONG)(lstrlenW(name) * sizeof(WCHAR));
    ok(record->Action == action, "%s: Action %lu (want %lu)", what, (unsigned long)record->Action,
       (unsigned long)action);
    ok(record->FileNameLength == nameBytes, "%s: FileNameLength %lu (want %lu)", what,
       (unsigned long)record->FileNameLength, (unsigned long)nameBytes);
    if (record->FileNameLength == nameBytes)
    {
        ok(memcmp(record->FileName, name, nameBytes) == 0, "%s: name", what);
    }
    return record->NextEntryOffset;
}

START_TEST(notify_queue)
{
    WCHAR sub[MAX_PATH + 64];
    WCHAR deep[MAX_PATH + 96];
    WCHAR nameA[MAX_PATH + 64];
    WCHAR nameB[MAX_PATH + 64];
    HANDLE dir;
    HANDLE handle;
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    UCHAR buffer[0x400];
    const FILE_NOTIFY_INFORMATION *record;
    ULONG next;
    DWORD len = GetTempPathW(MAX_PATH, root_path);

    ok(len != 0 && len < MAX_PATH, "GetTempPathW -> %lu", (unsigned long)len);
    if (len == 0 || len >= MAX_PATH)
    {
        return;
    }
    lstrcatW(root_path, L"prsnotifyq");
    under_root(sub, L"\\sub");
    under_root(deep, L"\\sub\\deep.txt");
    under_root(nameA, L"\\a.txt");
    under_root(nameB, L"\\b.txt");

    DeleteFileW(deep);
    DeleteFileW(nameA);
    DeleteFileW(nameB);
    RemoveDirectoryW(sub);
    RemoveDirectoryW(root_path);
    ok(CreateDirectoryW(root_path, NULL) != 0, "create the watch directory -> %lu",
       (unsigned long)GetLastError());

    /* --- (1) and (2): queued between watches, and the rename pair --------- */
    dir = open_watch();
    if (dir == INVALID_HANDLE_VALUE)
    {
        RemoveDirectoryW(root_path);
        return;
    }

    /* The first arm fixes filter/subtree/want_data for this handle. */
    poison_iosb(&iosb);
    memset(buffer, 0, sizeof(buffer));
    status = NtNotifyChangeDirectoryFile(dir, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer),
                                         NOTIFY_FILTER, FALSE);
    ok(status == STATUS_PENDING, "first arm -> %08lx", (unsigned long)status);

    handle = CreateFileW(nameA, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(handle != INVALID_HANDLE_VALUE, "create a.txt -> %lu", (unsigned long)GetLastError());
    if (handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(handle);
    }
    ok(WaitForSingleObject(dir, 5000) == WAIT_OBJECT_0, "the first watch did not complete");
    ok(iosb.Status == STATUS_SUCCESS, "first watch iosb.Status %08lx", (unsigned long)iosb.Status);
    check_record((const FILE_NOTIFY_INFORMATION *)buffer, FILE_ACTION_ADDED, L"a.txt", "create");

    /* NOTHING is armed across this rename: the records must survive until
     * the next arm asks for them. */
    ok(MoveFileW(nameA, nameB) != 0, "rename a.txt -> b.txt: %lu", (unsigned long)GetLastError());
    Sleep(300);

    poison_iosb(&iosb);
    memset(buffer, 0, sizeof(buffer));
    status = NtNotifyChangeDirectoryFile(dir, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer),
                                         NOTIFY_FILTER, FALSE);
    ok(status == STATUS_PENDING, "arm after the rename -> %08lx", (unsigned long)status);
    ok(WaitForSingleObject(dir, 5000) == WAIT_OBJECT_0,
       "a change made with nothing armed was dropped instead of queued");
    ok(iosb.Status == STATUS_SUCCESS, "queued watch iosb.Status %08lx", (unsigned long)iosb.Status);

    record = (const FILE_NOTIFY_INFORMATION *)buffer;
    next = check_record(record, FILE_ACTION_RENAMED_OLD_NAME, L"a.txt", "rename old");
    ok(next != 0, "the rename's second record is missing (NextEntryOffset 0)");
    if (next != 0)
    {
        record = (const FILE_NOTIFY_INFORMATION *)((const UCHAR *)record + next);
        next = check_record(record, FILE_ACTION_RENAMED_NEW_NAME, L"b.txt", "rename new");
        ok(next == 0, "a third record after the rename pair (NextEntryOffset %lu)",
           (unsigned long)next);
        ok(iosb.Information == (ULONG_PTR)((const UCHAR *)record - buffer) +
                                   offsetof(FILE_NOTIFY_INFORMATION, FileName) +
                                   record->FileNameLength,
           "Information %lu does not cover both records", (unsigned long)iosb.Information);
    }
    CloseHandle(dir);

    /* --- (3) the subtree flag is sticky ----------------------------------- */
    /* A FRESH handle, because the flag is fixed by the FIRST arm and the
     * handle above was armed non-recursive. */
    dir = open_watch();
    if (dir != INVALID_HANDLE_VALUE)
    {
        poison_iosb(&iosb);
        memset(buffer, 0, sizeof(buffer));
        status = NtNotifyChangeDirectoryFile(dir, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer),
                                             FILE_NOTIFY_CHANGE_FILE_NAME, TRUE);
        ok(status == STATUS_PENDING, "subtree arm -> %08lx", (unsigned long)status);

        /* Created AFTER arming: the pinned server's recursive watch tracks
         * subdirectories it sees appear. The creation is a DIR_NAME event
         * and this filter is FILE_NAME, so it must not complete the watch. */
        ok(CreateDirectoryW(sub, NULL) != 0, "create sub -> %lu", (unsigned long)GetLastError());
        Sleep(300);
        ok(WaitForSingleObject(dir, 0) == WAIT_TIMEOUT, "the directory creation was not filtered");

        handle = CreateFileW(deep, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        ok(handle != INVALID_HANDLE_VALUE, "create sub\\deep.txt -> %lu",
           (unsigned long)GetLastError());
        if (handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle);
        }
        ok(WaitForSingleObject(dir, 5000) == WAIT_OBJECT_0, "the subtree watch did not complete");
        ok(iosb.Status == STATUS_SUCCESS, "subtree iosb.Status %08lx", (unsigned long)iosb.Status);
        check_record((const FILE_NOTIFY_INFORMATION *)buffer, FILE_ACTION_ADDED, L"sub\\deep.txt",
                     "subtree create");

        /* Re-armed NON-recursive: a nested change must still arrive. */
        poison_iosb(&iosb);
        memset(buffer, 0, sizeof(buffer));
        status = NtNotifyChangeDirectoryFile(dir, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer),
                                             FILE_NOTIFY_CHANGE_FILE_NAME, FALSE);
        ok(status == STATUS_PENDING, "non-recursive re-arm -> %08lx", (unsigned long)status);
        ok(DeleteFileW(deep) != 0, "delete sub\\deep.txt -> %lu", (unsigned long)GetLastError());
        ok(WaitForSingleObject(dir, 5000) == WAIT_OBJECT_0,
           "a non-recursive re-arm stopped watching the subtree — the flag was not sticky");
        ok(iosb.Status == STATUS_SUCCESS, "sticky-subtree iosb.Status %08lx",
           (unsigned long)iosb.Status);
        check_record((const FILE_NOTIFY_INFORMATION *)buffer, FILE_ACTION_REMOVED, L"sub\\deep.txt",
                     "subtree delete");
        CloseHandle(dir);
    }
    RemoveDirectoryW(sub);

    /* --- (4) "the caller passed a buffer" is sticky too -------------------- */
    dir = open_watch();
    if (dir != INVALID_HANDLE_VALUE)
    {
        /* The zero-buffer (FindFirstChangeNotification) shape FIRST. */
        poison_iosb(&iosb);
        status = NtNotifyChangeDirectoryFile(dir, NULL, NULL, NULL, &iosb, NULL, 0, NOTIFY_FILTER,
                                             FALSE);
        ok(status == STATUS_PENDING, "zero-buffer arm -> %08lx", (unsigned long)status);
        ok(DeleteFileW(nameB) != 0, "delete b.txt -> %lu", (unsigned long)GetLastError());
        ok(WaitForSingleObject(dir, 5000) == WAIT_OBJECT_0,
           "the zero-buffer watch did not complete");
        ok(iosb.Status == STATUS_NOTIFY_ENUM_DIR, "zero-buffer iosb.Status %08lx",
           (unsigned long)iosb.Status);
        ok(iosb.Information == 0, "zero-buffer Information %lu", (unsigned long)iosb.Information);

        /* Now with a large buffer. The handle can still not report data. */
        poison_iosb(&iosb);
        memset(buffer, 0, sizeof(buffer));
        status = NtNotifyChangeDirectoryFile(dir, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer),
                                             NOTIFY_FILTER, FALSE);
        ok(status == STATUS_PENDING, "buffered re-arm -> %08lx", (unsigned long)status);
        handle = CreateFileW(nameA, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        ok(handle != INVALID_HANDLE_VALUE, "re-create a.txt -> %lu", (unsigned long)GetLastError());
        if (handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle);
        }
        ok(WaitForSingleObject(dir, 5000) == WAIT_OBJECT_0, "the buffered re-arm did not complete");
        ok(iosb.Status == STATUS_NOTIFY_ENUM_DIR,
           "a handle first armed with no buffer reported data again: iosb.Status %08lx",
           (unsigned long)iosb.Status);
        ok(iosb.Information == 0, "buffered re-arm Information %lu",
           (unsigned long)iosb.Information);
        CloseHandle(dir);
    }

    DeleteFileW(nameA);
    DeleteFileW(nameB);
    RemoveDirectoryW(root_path);
}
