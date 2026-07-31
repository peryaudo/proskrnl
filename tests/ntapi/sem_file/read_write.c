/*
 * sem_file/read_write.c — NtReadFile/NtWriteFile semantics on a synchronous
 * file (M6): IOSB update rules, byte offsets vs. the current file position,
 * EOF behaviour, extension, truncation via FileEndOfFileInformation, and
 * event completion (the event is signalled only after the IOSB is written —
 * the contract docs/08 calls out as the class of bug that kills projects).
 */
#include "util.h"

START_TEST(read_write)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, h, ev;
    LARGE_INTEGER offset;
    FILE_POSITION_INFORMATION pos;
    FILE_STANDARD_INFORMATION std;
    char buffer[64];

    dir = open_test_dir(W("\\??\\C:\\prstest\\rw"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("data.bin"));

    status = open_file(&h, dir, W("data.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create data.bin -> %08lx", (unsigned long)status);

    /* --- write at an explicit offset; Information counts the bytes. -------- */
    static const char alpha[] = "abcdefghijklmnopqrstuvwxyz"; /* 26 + NUL */
    offset.QuadPart = 0;
    poison_iosb(&iosb);
    status = NtWriteFile(h, NULL, NULL, NULL, &iosb, alpha, 26, &offset, NULL);
    ok(status == STATUS_SUCCESS, "write 26 at 0 -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS && iosb.Information == 26, "write 26 at 0: iosb %08lx/%lu",
       (unsigned long)iosb.Status, (unsigned long)iosb.Information);

    /* A synchronous write advances the current byte offset past the write. */
    poison_iosb(&iosb);
    status = NtQueryInformationFile(h, &iosb, &pos, sizeof(pos), FilePositionInformation);
    ok(status == STATUS_SUCCESS, "query position -> %08lx", (unsigned long)status);
    ok(pos.CurrentByteOffset.QuadPart == 26, "position after write %ld",
       (long)pos.CurrentByteOffset.QuadPart);

    /* --- read back at an explicit offset. ---------------------------------- */
    offset.QuadPart = 3;
    poison_iosb(&iosb);
    memset(buffer, 0, sizeof(buffer));
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 5, &offset, NULL);
    ok(status == STATUS_SUCCESS, "read 5 at 3 -> %08lx", (unsigned long)status);
    ok(iosb.Information == 5, "read 5 at 3: Information %lu", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "defgh", 5) == 0, "read 5 at 3: got %.5s", buffer);

    /* --- NULL ByteOffset on a synchronous handle uses the position. -------- */
    pos.CurrentByteOffset.QuadPart = 10;
    status = NtSetInformationFile(h, &iosb, &pos, sizeof(pos), FilePositionInformation);
    ok(status == STATUS_SUCCESS, "set position 10 -> %08lx", (unsigned long)status);
    poison_iosb(&iosb);
    memset(buffer, 0, sizeof(buffer));
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 4, NULL, NULL);
    ok(status == STATUS_SUCCESS, "read at position -> %08lx", (unsigned long)status);
    ok(iosb.Information == 4 && memcmp(buffer, "klmn", 4) == 0,
       "read at position: %lu bytes, got %.4s", (unsigned long)iosb.Information, buffer);
    status = NtQueryInformationFile(h, &iosb, &pos, sizeof(pos), FilePositionInformation);
    ok(status == STATUS_SUCCESS && pos.CurrentByteOffset.QuadPart == 14, "position advanced to %ld",
       (long)pos.CurrentByteOffset.QuadPart);

    /* --- a read crossing EOF is short; a read AT EOF is STATUS_END_OF_FILE. */
    offset.QuadPart = 20;
    poison_iosb(&iosb);
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 32, &offset, NULL);
    ok(status == STATUS_SUCCESS, "short read across EOF -> %08lx", (unsigned long)status);
    ok(iosb.Information == 6, "short read across EOF: Information %lu",
       (unsigned long)iosb.Information);

    offset.QuadPart = 26;
    poison_iosb(&iosb);
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 8, &offset, NULL);
    ok(status == STATUS_END_OF_FILE, "read at EOF -> %08lx", (unsigned long)status);
    /* The EOF status lands in the IOSB as well (pinned Wine). */
    ok(iosb.Status == STATUS_END_OF_FILE, "read at EOF: iosb.Status %08lx",
       (unsigned long)iosb.Status);

    /* --- a sparse write past EOF extends and zero-fills the gap. ----------- */
    offset.QuadPart = 40;
    poison_iosb(&iosb);
    status = NtWriteFile(h, NULL, NULL, NULL, &iosb, "ZZ", 2, &offset, NULL);
    ok(status == STATUS_SUCCESS, "write past EOF -> %08lx", (unsigned long)status);
    status = NtQueryInformationFile(h, &iosb, &std, sizeof(std), FileStandardInformation);
    ok(status == STATUS_SUCCESS && std.EndOfFile.QuadPart == 42, "EOF after extend %ld",
       (long)std.EndOfFile.QuadPart);
    offset.QuadPart = 26;
    memset(buffer, 0x5a, sizeof(buffer));
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 14, &offset, NULL);
    ok(status == STATUS_SUCCESS && iosb.Information == 14, "read gap -> %08lx/%lu",
       (unsigned long)status, (unsigned long)iosb.Information);
    int zeros = 1;
    for (int i = 0; i < 14; i++)
        if (buffer[i] != 0)
            zeros = 0;
    ok(zeros, "extension gap is zero-filled");

    /* --- FileEndOfFileInformation truncates and extends. ------------------- */
    FILE_END_OF_FILE_INFORMATION eof;
    eof.EndOfFile.QuadPart = 5;
    status = NtSetInformationFile(h, &iosb, &eof, sizeof(eof), FileEndOfFileInformation);
    ok(status == STATUS_SUCCESS, "truncate to 5 -> %08lx", (unsigned long)status);
    status = NtQueryInformationFile(h, &iosb, &std, sizeof(std), FileStandardInformation);
    ok(status == STATUS_SUCCESS && std.EndOfFile.QuadPart == 5, "EOF after truncate %ld",
       (long)std.EndOfFile.QuadPart);

    eof.EndOfFile.QuadPart = 12;
    status = NtSetInformationFile(h, &iosb, &eof, sizeof(eof), FileEndOfFileInformation);
    ok(status == STATUS_SUCCESS, "extend to 12 -> %08lx", (unsigned long)status);
    offset.QuadPart = 0;
    memset(buffer, 0x5a, sizeof(buffer));
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 12, &offset, NULL);
    ok(status == STATUS_SUCCESS && iosb.Information == 12, "read truncated+extended -> %08lx/%lu",
       (unsigned long)status, (unsigned long)iosb.Information);
    zeros = 1;
    for (int i = 5; i < 12; i++)
        if (buffer[i] != 0)
            zeros = 0;
    ok(memcmp(buffer, "abcde", 5) == 0 && zeros, "truncate+extend zero-fills the tail");

    /* --- event completion: the event is set by a completed read. ----------- */
    ev = NULL;
    status = NtCreateEvent(&ev, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create event -> %08lx", (unsigned long)status);
    offset.QuadPart = 0;
    poison_iosb(&iosb);
    status = NtReadFile(h, ev, NULL, NULL, &iosb, buffer, 4, &offset, NULL);
    ok(status == STATUS_SUCCESS, "read with event -> %08lx", (unsigned long)status);
    LARGE_INTEGER timeout;
    timeout.QuadPart = 0; /* poll: the event must already be signalled */
    status = NtWaitForSingleObject(ev, FALSE, &timeout);
    ok(status == STATUS_SUCCESS, "event signalled after read -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS && iosb.Information == 4,
       "iosb written before the event: %08lx/%lu", (unsigned long)iosb.Status,
       (unsigned long)iosb.Information);
    NtClose(ev);

    /* --- an INVALID event handle does not stop the transfer. ---------------
     *
     * proskrnl used to resolve the event only at completion time and then
     * return its failure as the CALL's status: a bad handle on NtReadFile
     * consumed the bytes, advanced the file pointer and queued the
     * completion APC, and reported STATUS_INVALID_HANDLE -- the data gone
     * and the caller told nothing had happened (docs/review-2026-07 §7).
     *
     * The oracle's answer is that the transfer's own status wins and the
     * event-signal failure is discarded: third_party/wine
     * dlls/ntdll/unix/file.c writes `if (event) NtSetEvent( event, NULL );`
     * with no test of the result. So the bytes AND the status agree, which
     * is the property that matters either way. */
    {
        FILE_POSITION_INFORMATION before, after;
        IO_STATUS_BLOCK posIosb;

        poison_iosb(&iosb);
        status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 4, NULL, NULL);
        ok(status == STATUS_SUCCESS, "positional read before bad-event -> %08lx",
           (unsigned long)status);

        poison_iosb(&posIosb);
        status =
            NtQueryInformationFile(h, &posIosb, &before, sizeof(before), FilePositionInformation);
        ok(status == STATUS_SUCCESS, "query position -> %08lx", (unsigned long)status);

        poison_iosb(&iosb);
        status = NtReadFile(h, (HANDLE)(ULONG_PTR)0xdeadbee0, NULL, NULL, &iosb, buffer, 4, NULL,
                            NULL);
        ok(status == STATUS_SUCCESS, "read with a bad event handle -> %08lx",
           (unsigned long)status);

        poison_iosb(&posIosb);
        status =
            NtQueryInformationFile(h, &posIosb, &after, sizeof(after), FilePositionInformation);
        ok(status == STATUS_SUCCESS, "re-query position -> %08lx", (unsigned long)status);
        ok(after.CurrentByteOffset.QuadPart == before.CurrentByteOffset.QuadPart + 4,
           "the read reported success but moved the pointer by %ld, not 4",
           (long)(after.CurrentByteOffset.QuadPart - before.CurrentByteOffset.QuadPart));
    }

    /* --- file handles are waitable and signalled (fuzzer-found pin: NT
     * signals the file object at I/O completion; with synchronous
     * completion it reads as signalled). ------------------------------------ */
    timeout.QuadPart = 0;
    status = NtWaitForSingleObject(h, FALSE, &timeout);
    ok(status == STATUS_SUCCESS, "wait on file handle -> %08lx", (unsigned long)status);

    /* --- writes need FILE_WRITE_DATA on the handle. ------------------------ */
    HANDLE ro;
    status = open_file(&ro, dir, W("data.bin"), FILE_GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "read-only open -> %08lx", (unsigned long)status);
    offset.QuadPart = 0;
    status = NtWriteFile(ro, NULL, NULL, NULL, &iosb, "x", 1, &offset, NULL);
    ok(status == STATUS_ACCESS_DENIED, "write on read-only handle -> %08lx", (unsigned long)status);
    status = NtReadFile(ro, NULL, NULL, NULL, &iosb, buffer, 1, &offset, NULL);
    ok(status == STATUS_SUCCESS, "read on read-only handle -> %08lx", (unsigned long)status);
    NtClose(ro);

    /* --- reading a directory handle is refused. ---------------------------- */
    offset.QuadPart = 0;
    status = NtReadFile(dir, NULL, NULL, NULL, &iosb, buffer, 4, &offset, NULL);
    ok(status == STATUS_INVALID_DEVICE_REQUEST, "read on directory -> %08lx",
       (unsigned long)status);

    NtClose(h);
    scrub_file(dir, W("data.bin"));
    NtClose(dir);
}
