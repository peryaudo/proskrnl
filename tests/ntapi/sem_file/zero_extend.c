/*
 * sem_file/zero_extend.c — extended file ranges must read as ZEROS (M6).
 *
 * NT guarantees that growing a file — via FileEndOfFileInformation or by
 * writing past EOF — exposes zeros in the new range, never stale disk
 * bytes (MS "SetEndOfFile": "the contents of the file between the previous
 * EOF position and the new position are not defined" is the Win32 wording,
 * but the NT file systems and Wine's ntdll both zero — Wine's server-side
 * ftruncate/pwrite semantics give zeros on every backing FS, so the oracle
 * pins zeros).
 *
 * The close/reopen between the shrink and the grow is the point of the
 * test: it forces the file's cached state to be dropped and reloaded from
 * disk, so an implementation that scrubbed only its in-memory cache (not
 * the on-disk cluster tail) resurrects the truncated bytes. Found by the
 * kmt FAT churn stress (tests/kmt/fat_churn.c); pinned here per Art. 6.
 */
#include "util.h"

#define NAME W("zx.bin")

static void reopen(HANDLE dir, HANDLE *h, IO_STATUS_BLOCK *iosb)
{
    NTSTATUS status = open_file(h, dir, NAME, FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, iosb);
    ok(status == STATUS_SUCCESS, "reopen -> %08lx", (unsigned long)status);
}

START_TEST(zero_extend)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, h;
    LARGE_INTEGER offset;
    FILE_END_OF_FILE_INFORMATION eof;
    unsigned char buffer[2048];
    unsigned i, bad;

    dir = open_test_dir(W("\\??\\C:\\prstest\\zx"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, NAME);

    status = open_file(&h, dir, NAME, FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
    {
        NtClose(dir);
        return;
    }

    /* A non-zero pattern over 1500 bytes (crosses a 512-byte sector and a
     * 1024-byte cluster edge on any small-cluster FAT). */
    for (i = 0; i < 1500; i++)
        buffer[i] = (unsigned char)(0x11 + i % 200);
    offset.QuadPart = 0;
    status = NtWriteFile(h, NULL, NULL, NULL, &iosb, buffer, 1500, &offset, NULL);
    ok(status == STATUS_SUCCESS && iosb.Information == 1500, "write -> %08lx/%lu",
       (unsigned long)status, (unsigned long)iosb.Information);

    /* Shrink to 700, through a CLOSE so cached state cannot carry over. */
    NtClose(h);
    reopen(dir, &h, &iosb);
    eof.EndOfFile.QuadPart = 700;
    status = NtSetInformationFile(h, &iosb, &eof, sizeof(eof), FileEndOfFileInformation);
    ok(status == STATUS_SUCCESS, "shrink to 700 -> %08lx", (unsigned long)status);
    NtClose(h);

    /* Grow back to 1500: bytes 700..1499 must be ZERO, not the old pattern. */
    reopen(dir, &h, &iosb);
    eof.EndOfFile.QuadPart = 1500;
    status = NtSetInformationFile(h, &iosb, &eof, sizeof(eof), FileEndOfFileInformation);
    ok(status == STATUS_SUCCESS, "grow to 1500 -> %08lx", (unsigned long)status);
    memset(buffer, 0xCC, sizeof(buffer));
    offset.QuadPart = 0;
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 1500, &offset, NULL);
    ok(status == STATUS_SUCCESS && iosb.Information == 1500, "read -> %08lx/%lu",
       (unsigned long)status, (unsigned long)iosb.Information);
    for (i = 0; i < 700; i++)
        if (buffer[i] != (unsigned char)(0x11 + i % 200))
            break;
    ok(i == 700, "kept range differs at %u (saw %02x)", i, buffer[i]);
    bad = 0;
    for (i = 700; i < 1500; i++)
        if (buffer[i] != 0)
            bad++;
    ok(bad == 0, "extended range not zero: %u stale bytes (first %02x at %u)", bad, buffer[700],
       700);
    NtClose(h);

    /* Same guarantee for a write PAST EOF: shrink to 300, close, reopen,
     * write 100 bytes at 1200 — the gap 300..1199 must read as zeros. */
    reopen(dir, &h, &iosb);
    eof.EndOfFile.QuadPart = 300;
    status = NtSetInformationFile(h, &iosb, &eof, sizeof(eof), FileEndOfFileInformation);
    ok(status == STATUS_SUCCESS, "shrink to 300 -> %08lx", (unsigned long)status);
    NtClose(h);
    reopen(dir, &h, &iosb);
    for (i = 0; i < 100; i++)
        buffer[i] = 0xEE;
    offset.QuadPart = 1200;
    status = NtWriteFile(h, NULL, NULL, NULL, &iosb, buffer, 100, &offset, NULL);
    ok(status == STATUS_SUCCESS && iosb.Information == 100, "gap write -> %08lx/%lu",
       (unsigned long)status, (unsigned long)iosb.Information);
    memset(buffer, 0xCC, sizeof(buffer));
    offset.QuadPart = 0;
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 1300, &offset, NULL);
    ok(status == STATUS_SUCCESS && iosb.Information == 1300, "read 1300 -> %08lx/%lu",
       (unsigned long)status, (unsigned long)iosb.Information);
    bad = 0;
    for (i = 300; i < 1200; i++)
        if (buffer[i] != 0)
            bad++;
    ok(bad == 0, "gap not zero: %u stale bytes", bad);
    for (i = 1200; i < 1300; i++)
        if (buffer[i] != 0xEE)
            break;
    ok(i == 1300, "written tail differs at %u", i);

    NtClose(h);
    scrub_file(dir, NAME);
    NtClose(dir);
}
