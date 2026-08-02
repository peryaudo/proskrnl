/*
 * sem_file/async_inline.c — the CUI-8 §7 pin (docs/19): what a data transfer
 * on an ASYNCHRONOUS disk-file handle (opened without FILE_SYNCHRONOUS_IO_*)
 * answers. Both pend-and-signal and inline-final are legal under the NT
 * contract (§1.1 — STATUS_PENDING is permitted, never required); the oracle's
 * choice, pinned here, is the pending SHAPE over an inline COMPLETION
 * (third_party/wine dlls/ntdll/unix/file.c, NtReadFile/NtWriteFile tails:
 * `ret_status = async_read && type == FD_TYPE_FILE && (status == SUCCESS ||
 * status == END_OF_FILE) ? STATUS_PENDING : status`, writes converting only
 * SUCCESS):
 *   - the call returns STATUS_PENDING, but the IOSB is ALREADY final and the
 *     completion event ALREADY signalled when it returns — a caller that
 *     waits, waits zero time;
 *   - a read at EOF reports STATUS_END_OF_FILE through the IOSB while the
 *     call itself still answers STATUS_PENDING;
 *   - an ApcRoutine is queued at completion, delivered at the next alertable
 *     wait with that final IOSB (apc_completion.c's delivery rule);
 *   - operations issued back-to-back complete in issue order;
 *   - parameter refusals stay inline: a NULL ByteOffset is
 *     STATUS_INVALID_PARAMETER with the IOSB untouched (no position exists
 *     on an asynchronous handle).
 * The same answers must hold on the cold first touch — where proskrnl's
 * page-cache fill does real device round trips — and FileModeInformation
 * keeps reporting what the create established (docs/19 §7's last bullet).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
                                               FILE_INFORMATION_CLASS);

/* Create/open WITHOUT the synchronous-IO create options: the asynchronous
 * flavour open_file (util.h) cannot produce. */
static NTSTATUS open_file_async(HANDLE *handle, HANDLE root, const void *wide_name,
                                ACCESS_MASK access, ULONG share, ULONG disposition,
                                IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    init_ustr(&name, wide_name);
    init_attr(&attr, root, &name, OBJ_CASE_INSENSITIVE);
    *handle = NULL;
    return NtCreateFile(handle, access, &attr, iosb, NULL, FILE_ATTRIBUTE_NORMAL, share,
                        disposition, FILE_NON_DIRECTORY_FILE, NULL, 0);
}

static int apc_calls;
static NTSTATUS apc_status;
static ULONG apc_information;

static void NTAPI inline_apc(PVOID context, PIO_STATUS_BLOCK iosb, ULONG reserved)
{
    (void)context;
    (void)reserved;
    apc_calls++;
    apc_status = iosb->Status;
    apc_information = (ULONG)iosb->Information;
}

START_TEST(async_inline)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, h, ev;
    LARGE_INTEGER offset, timeout;
    char buffer[64];

    dir = open_test_dir(W("\\??\\C:\\prstest\\ainl"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("async.bin"));

    status = open_file_async(&h, dir, W("async.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, &iosb);
    ok(status == STATUS_SUCCESS, "create async.bin -> %08lx", (unsigned long)status);

    /* --- a write answers STATUS_PENDING with the IOSB already final. ------- */
    static const char alpha[] = "abcdefghijklmnopqrstuvwxyz";
    offset.QuadPart = 0;
    poison_iosb(&iosb);
    status = NtWriteFile(h, NULL, NULL, NULL, &iosb, alpha, 26, &offset, NULL);
    ok(status == STATUS_PENDING, "async write -> %08lx (the pending shape)", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS && iosb.Information == 26,
       "async write: iosb final at return %08lx/%lu", (unsigned long)iosb.Status,
       (unsigned long)iosb.Information);

    /* --- a NULL ByteOffset is refused inline: no kernel-owned position. ---- */
    poison_iosb(&iosb);
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 4, NULL, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "async read, no offset -> %08lx", (unsigned long)status);
    ok(iosb.Status == IOSB_POISON_STATUS, "refused read leaves the IOSB alone (%08lx)",
       (unsigned long)iosb.Status);

    /* --- a read answers STATUS_PENDING, data and IOSB already there. ------- */
    offset.QuadPart = 3;
    poison_iosb(&iosb);
    memset(buffer, 0, 8);
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 5, &offset, NULL);
    ok(status == STATUS_PENDING, "async read -> %08lx (the pending shape)", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS && iosb.Information == 5,
       "async read: iosb final at return %08lx/%lu", (unsigned long)iosb.Status,
       (unsigned long)iosb.Information);
    ok(memcmp(buffer, "defgh", 5) == 0, "async read data present at return");

    /* --- the completion event is already signalled at return. -------------- */
    ev = NULL;
    status = NtCreateEvent(&ev, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create event -> %08lx", (unsigned long)status);
    offset.QuadPart = 0;
    poison_iosb(&iosb);
    status = NtReadFile(h, ev, NULL, NULL, &iosb, buffer, 4, &offset, NULL);
    ok(status == STATUS_PENDING, "async read with event -> %08lx", (unsigned long)status);
    timeout.QuadPart = 0; /* poll: signalled means signalled NOW */
    status = NtWaitForSingleObject(ev, FALSE, &timeout);
    ok(status == STATUS_SUCCESS, "event signalled at return -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS && iosb.Information == 4,
       "iosb written before the event: %08lx/%lu", (unsigned long)iosb.Status,
       (unsigned long)iosb.Information);
    NtClose(ev);

    /* --- the file object itself reads as signalled after completion. ------- */
    timeout.QuadPart = 0;
    status = NtWaitForSingleObject(h, FALSE, &timeout);
    ok(status == STATUS_SUCCESS, "wait on async file handle -> %08lx", (unsigned long)status);

    /* --- EOF still answers STATUS_PENDING; the IOSB carries the verdict. --- */
    offset.QuadPart = 26;
    poison_iosb(&iosb);
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 8, &offset, NULL);
    ok(status == STATUS_PENDING, "async read at EOF -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_END_OF_FILE && iosb.Information == 0,
       "EOF lands in the iosb: %08lx/%lu", (unsigned long)iosb.Status,
       (unsigned long)iosb.Information);

    /* --- the short transfer across EOF: same values, pending shape. -------- */
    offset.QuadPart = 20;
    poison_iosb(&iosb);
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 32, &offset, NULL);
    ok(status == STATUS_PENDING && iosb.Status == STATUS_SUCCESS && iosb.Information == 6,
       "async short read across EOF -> %08lx, iosb %08lx/%lu", (unsigned long)status,
       (unsigned long)iosb.Status, (unsigned long)iosb.Information);

    /* --- back-to-back operations on one handle complete in issue order. ---- */
    offset.QuadPart = 0;
    status = NtWriteFile(h, NULL, NULL, NULL, &iosb, "AAAA", 4, &offset, NULL);
    ok(status == STATUS_PENDING, "ordering write 1 -> %08lx", (unsigned long)status);
    offset.QuadPart = 1;
    status = NtWriteFile(h, NULL, NULL, NULL, &iosb, "BB", 2, &offset, NULL);
    ok(status == STATUS_PENDING, "ordering write 2 -> %08lx", (unsigned long)status);
    offset.QuadPart = 0;
    memset(buffer, 0, 8);
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 4, &offset, NULL);
    ok(status == STATUS_PENDING && memcmp(buffer, "ABBA", 4) == 0,
       "back-to-back writes land in issue order");

    /* --- the APC leg still defers to the alertable wait. ------------------- */
    apc_calls = 0;
    offset.QuadPart = 0;
    poison_iosb(&iosb);
    status = NtReadFile(h, NULL, inline_apc, NULL, &iosb, buffer, 4, &offset, NULL);
    ok(status == STATUS_PENDING, "async read with APC -> %08lx", (unsigned long)status);
    ok(apc_calls == 0, "APC not delivered before an alertable wait (%d)", apc_calls);
    timeout.QuadPart = -10000000; /* 1 s: the queued APC must cut it short */
    status = NtDelayExecution(TRUE, &timeout);
    ok(status == STATUS_USER_APC, "alertable delay -> %08lx", (unsigned long)status);
    ok(apc_calls == 1 && apc_status == STATUS_SUCCESS && apc_information == 4,
       "APC delivered with the final iosb (%d, %08lx/%lu)", apc_calls, (unsigned long)apc_status,
       (unsigned long)apc_information);

    /* --- FileModeInformation reports what the create established. ---------- */
    {
        FILE_MODE_INFORMATION mode;
        poison_iosb(&iosb);
        status = NtQueryInformationFile(h, &iosb, &mode, sizeof(mode), FileModeInformation);
        ok(status == STATUS_SUCCESS, "query mode (async) -> %08lx", (unsigned long)status);
        ok((mode.Mode & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)) == 0,
           "async handle mode has no synchronous bits (%08lx)", (unsigned long)mode.Mode);
    }
    NtClose(h);

    /* --- the cold first touch answers the same way. -------------------------
     * Reopening after every handle closed gives proskrnl a cold page cache
     * (the FCB died with the last reference), so this read is the one that
     * does real device work — the §7 case called out explicitly: the answers
     * must not depend on whether the data was already cached. */
    status = open_file_async(&h, dir, W("async.bin"), FILE_GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, &iosb);
    ok(status == STATUS_SUCCESS, "reopen async -> %08lx", (unsigned long)status);
    offset.QuadPart = 0;
    poison_iosb(&iosb);
    memset(buffer, 0, 8);
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 4, &offset, NULL);
    ok(status == STATUS_PENDING, "cold async read -> %08lx (the pending shape)",
       (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS && iosb.Information == 4 && memcmp(buffer, "ABBA", 4) == 0,
       "cold async read: iosb final, data intact (%08lx/%lu)", (unsigned long)iosb.Status,
       (unsigned long)iosb.Information);
    NtClose(h);

    /* --- a sync handle still reports its synchronous bit. ------------------ */
    status = open_file(&h, dir, W("async.bin"), FILE_GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "sync reopen -> %08lx", (unsigned long)status);
    {
        FILE_MODE_INFORMATION mode;
        status = NtQueryInformationFile(h, &iosb, &mode, sizeof(mode), FileModeInformation);
        ok(status == STATUS_SUCCESS, "query mode (sync) -> %08lx", (unsigned long)status);
        ok((mode.Mode & FILE_SYNCHRONOUS_IO_NONALERT) != 0,
           "sync handle mode keeps FILE_SYNCHRONOUS_IO_NONALERT (%08lx)", (unsigned long)mode.Mode);
    }
    NtClose(h);

    /* --- the mode word is the FULL masked create-option set. ----------------
     * The oracle serves options & (FILE_WRITE_THROUGH | FILE_SEQUENTIAL_ONLY
     * | FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_ALERT |
     * FILE_SYNCHRONOUS_IO_NONALERT) — server/fd.c default_fd_get_file_info —
     * so a create carrying non-synchronous mode bits must see them again,
     * exactly, and nothing else. The sync-bit checks above cannot convict a
     * kernel that serves only the synchronous flag. */
    {
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        const ULONG wantMode =
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING | FILE_WRITE_THROUGH;
        init_ustr(&name, W("async.bin"));
        init_attr(&attr, dir, &name, OBJ_CASE_INSENSITIVE);
        h = NULL;
        status = NtCreateFile(&h, FILE_GENERIC_READ, &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                              FILE_NON_DIRECTORY_FILE | wantMode, NULL, 0);
        ok(status == STATUS_SUCCESS, "mode-bits reopen -> %08lx", (unsigned long)status);
        if (status == STATUS_SUCCESS)
        {
            FILE_MODE_INFORMATION mode;
            poison_iosb(&iosb);
            status = NtQueryInformationFile(h, &iosb, &mode, sizeof(mode), FileModeInformation);
            ok(status == STATUS_SUCCESS, "query mode (full word) -> %08lx", (unsigned long)status);
            ok(mode.Mode == wantMode, "mode word is the masked create options (%08lx vs %08lx)",
               (unsigned long)mode.Mode, (unsigned long)wantMode);
            NtClose(h);
        }
    }

    scrub_file(dir, W("async.bin"));
    NtClose(dir);
}
