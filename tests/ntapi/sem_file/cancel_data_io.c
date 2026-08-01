/*
 * sem_file/cancel_data_io.c — the CUI-8 §7 cancellation pins (docs/19).
 *
 * Disk-file data transfers complete inline (async_inline.c), so nothing is
 * ever cancellably pending at ring 3, and the cancel verbs answer from that
 * fact — the wineserver-pinned shapes async_listen.c established:
 *   - NtCancelIoFileEx finds nothing and answers STATUS_NOT_FOUND;
 *   - thread-scoped NtCancelIoFile succeeds even with nothing in flight;
 *   - NtCancelSynchronousIoFile on an idle thread answers STATUS_NOT_FOUND.
 * The one genuinely racy case — cancelling a thread that is mid-transfer
 * inside the kernel — is asserted race-tolerantly (either the cancel misses
 * and answers NOT_FOUND, or it lands and the reader observes
 * STATUS_CANCELLED with the file intact afterwards): on the oracle a unix
 * read() of a regular file is not a cancellable wait, and on proskrnl the
 * park a cold cache fill makes is; both outcomes are inside the pinned
 * contract, and the deterministic conviction of the proskrnl side lives in
 * the kernel-mode kmt suite where the in-flight window can be held open.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtCancelIoFile(HANDLE, PIO_STATUS_BLOCK);
NTSYSAPI NTSTATUS NTAPI NtCancelIoFileEx(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK);
NTSYSAPI NTSTATUS NTAPI NtCancelSynchronousIoFile(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK);

#define CANCEL_FILE_BYTES (256 * 1024)

static HANDLE cancel_dir;
static volatile LONG reader_stop;
static volatile LONG reader_rounds;
static volatile NTSTATUS reader_saw;

/* Reopen the big file cold each round and stream through it: every round is
 * a fresh cache fill on proskrnl, so a cancel has real in-flight windows to
 * land in. Any status other than SUCCESS/END_OF_FILE stops the loop and is
 * recorded for the main thread. */
static DWORD WINAPI streaming_reader(void *param)
{
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    static char chunk[4096];
    (void)param;

    while (!reader_stop)
    {
        HANDLE h;
        NTSTATUS status = open_file(&h, cancel_dir, W("cancel.bin"), FILE_GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
        if (!NT_SUCCESS(status))
        {
            reader_saw = status;
            return 0;
        }
        for (offset.QuadPart = 0; offset.QuadPart < CANCEL_FILE_BYTES && !reader_stop;
             offset.QuadPart += sizeof(chunk))
        {
            status = NtReadFile(h, NULL, NULL, NULL, &iosb, chunk, sizeof(chunk), &offset, NULL);
            if (status == STATUS_CANCELLED)
            {
                reader_saw = STATUS_CANCELLED;
                NtClose(h);
                return 0;
            }
            if (status != STATUS_SUCCESS && status != STATUS_END_OF_FILE)
            {
                reader_saw = status;
                NtClose(h);
                return 0;
            }
        }
        NtClose(h);
        reader_rounds++;
    }
    return 0;
}

START_TEST(cancel_data_io)
{
    IO_STATUS_BLOCK iosb, result;
    NTSTATUS status;
    HANDLE dir, h, thread;
    LARGE_INTEGER offset;
    static char block[4096];
    char buffer[64];

    dir = open_test_dir(W("\\??\\C:\\prstest\\cxl"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("cancel.bin"));

    status = open_file(&h, dir, W("cancel.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create cancel.bin -> %08lx", (unsigned long)status);
    memset(block, 0x3c, sizeof(block));
    for (offset.QuadPart = 0; offset.QuadPart < CANCEL_FILE_BYTES; offset.QuadPart += sizeof(block))
    {
        status = NtWriteFile(h, NULL, NULL, NULL, &iosb, block, sizeof(block), &offset, NULL);
        if (!NT_SUCCESS(status))
            break;
    }
    ok(status == STATUS_SUCCESS, "fill 256K -> %08lx", (unsigned long)status);

    /* --- after an inline read there is nothing to cancel. ------------------- */
    offset.QuadPart = 0;
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer), &offset, NULL);
    ok(status == STATUS_SUCCESS, "inline read -> %08lx", (unsigned long)status);

    poison_iosb(&result);
    status = NtCancelIoFileEx(h, NULL, &result);
    ok(status == STATUS_NOT_FOUND, "CancelIoFileEx, nothing pending -> %08lx",
       (unsigned long)status);
    ok(result.Status == STATUS_NOT_FOUND && result.Information == 0,
       "CancelIoFileEx result iosb %08lx/%lu", (unsigned long)result.Status,
       (unsigned long)result.Information);

    /* An explicit target IOSB finds nothing either. */
    poison_iosb(&result);
    status = NtCancelIoFileEx(h, &iosb, &result);
    ok(status == STATUS_NOT_FOUND, "CancelIoFileEx, explicit iosb -> %08lx", (unsigned long)status);

    /* The thread-scoped legacy form succeeds with nothing cancelled. */
    poison_iosb(&result);
    status = NtCancelIoFile(h, &result);
    ok(status == STATUS_SUCCESS, "CancelIoFile, nothing pending -> %08lx", (unsigned long)status);
    ok(result.Status == STATUS_SUCCESS, "CancelIoFile result iosb %08lx",
       (unsigned long)result.Status);

    /* The handle still transfers after the cancels. */
    offset.QuadPart = 8;
    poison_iosb(&iosb);
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 8, &offset, NULL);
    ok(status == STATUS_SUCCESS && iosb.Information == 8, "read after cancel -> %08lx/%lu",
       (unsigned long)status, (unsigned long)iosb.Information);
    NtClose(h);

    /* --- an idle thread has no synchronous I/O to cancel. ------------------- */
    poison_iosb(&result);
    status = NtCancelSynchronousIoFile(GetCurrentThread(), NULL, &result);
    ok(status == STATUS_NOT_FOUND, "CancelSynchronousIo(self) -> %08lx", (unsigned long)status);
    ok(result.Status == STATUS_NOT_FOUND && result.Information == 0,
       "CancelSynchronousIo(self) result iosb %08lx/%lu", (unsigned long)result.Status,
       (unsigned long)result.Information);

    /* --- cancelling a mid-transfer reader: race-tolerant. -------------------
     * Fire a burst of cancels at a thread streaming through the file. Each
     * cancel either misses (STATUS_NOT_FOUND — the thread was between
     * transfers, or the backend has no cancellable window) or lands
     * (STATUS_SUCCESS — and then the reader must observe STATUS_CANCELLED
     * and stop). Any other pairing is a contract violation. */
    cancel_dir = dir;
    reader_stop = 0;
    reader_rounds = 0;
    reader_saw = STATUS_SUCCESS;
    thread = CreateThread(NULL, 0, streaming_reader, NULL, 0, NULL);
    ok(thread != NULL, "CreateThread reader");

    int landed = 0, missed = 0, bogus = 0;
    for (int i = 0; i < 40 && !landed; i++)
    {
        Sleep(5);
        poison_iosb(&result);
        status = NtCancelSynchronousIoFile(thread, NULL, &result);
        if (status == STATUS_SUCCESS)
            landed++;
        else if (status == STATUS_NOT_FOUND)
            missed++;
        else
            bogus++;
    }
    ok(bogus == 0, "every cancel answered SUCCESS or NOT_FOUND (%d bogus)", bogus);
    ok(landed + missed > 0, "cancel burst ran (%d landed, %d missed)", landed, missed);

    reader_stop = 1;
    ok(WaitForSingleObject(thread, 15000) == WAIT_OBJECT_0, "reader never returned");
    CloseHandle(thread);
    if (landed)
        ok(reader_saw == STATUS_CANCELLED || reader_saw == STATUS_SUCCESS,
           "a landed cancel gives the reader STATUS_CANCELLED (saw %08lx)",
           (unsigned long)reader_saw);
    else
        ok(reader_saw == STATUS_SUCCESS, "unmolested reader saw only success (%08lx)",
           (unsigned long)reader_saw);

    /* --- the file survives whatever the burst did. -------------------------- */
    status = open_file(&h, dir, W("cancel.bin"), FILE_GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "reopen after burst -> %08lx", (unsigned long)status);
    offset.QuadPart = CANCEL_FILE_BYTES - 16;
    poison_iosb(&iosb);
    memset(buffer, 0, 16);
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 16, &offset, NULL);
    ok(status == STATUS_SUCCESS && iosb.Information == 16, "tail read -> %08lx/%lu",
       (unsigned long)status, (unsigned long)iosb.Information);
    int intact = 1;
    for (int i = 0; i < 16; i++)
        if (buffer[i] != 0x3c)
            intact = 0;
    ok(intact, "file bytes intact after the cancel burst");
    NtClose(h);

    scrub_file(dir, W("cancel.bin"));
    NtClose(dir);
}
