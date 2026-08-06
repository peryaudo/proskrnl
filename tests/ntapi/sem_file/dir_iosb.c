/*
 * sem_file/dir_iosb.c — what NtQueryDirectoryFile writes into the caller's
 * IO_STATUS_BLOCK when it has nothing to return.
 *
 * Convicted by the winetest gate: ntdll:directory asserts `io.Status ==
 * status` after every continuation query (directory.c:243) and proskrnl
 * failed it 117 times in one run — it returned STATUS_NO_MORE_FILES and
 * left the IOSB holding whatever the caller had put there. The test poisons
 * it with 0xdeadbeef first, so "untouched" is exactly what it detects (this
 * pin poisons with util.h's own IOSB_POISON_STATUS, same idea).
 *
 * The rule is a one-liner in the oracle, and it is not the obvious one
 * (dlls/ntdll/unix/file.c, the tail of NtQueryDirectoryFile):
 *
 *     if (status != STATUS_NO_SUCH_FILE) io->Status = status;
 *
 * So this class writes the IOSB on FAILURE too — every failure but one.
 * That single exemption is the whole reason this needs pinning rather than
 * reasoning: the natural implementations are "write it always" and "write
 * it only on success", and both are wrong. STATUS_NO_SUCH_FILE is the
 * status a FIRST scan gives when the mask matches nothing, and it alone
 * leaves the caller's bytes alone.
 *
 * (proskrnl's wider IOSB-on-failure convention is the wineserver's — write
 * only on success — and is recorded in docs/03. This class is served by
 * ntdll's own unix path on the oracle rather than by the server, which is
 * why it diverges from that convention and why the divergence is real
 * boundary behaviour rather than a Wine-internal artifact: the winetest
 * above depends on it.)
 *
 * Oracle-first (G5).
 */
#include "util.h"

/* A FILE_BOTH_DIRECTORY_INFORMATION plus room for a long name. */
static UCHAR dirBuffer[4096];

START_TEST(dir_iosb)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, scratch;
    UNICODE_STRING mask;

    dir = open_test_dir(W("\\??\\C:\\prstest\\diriosb"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("only.tmp"));
    status = open_file(&scratch, dir, W("only.tmp"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create only.tmp -> %08lx", (unsigned long)status);
    NtClose(scratch);

    /* --- the first scan finds the entries and reports the byte count ------- */
    poison_iosb(&iosb);
    status = NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, dirBuffer, sizeof(dirBuffer),
                                  FileBothDirectoryInformation, FALSE, NULL, TRUE);
    ok(status == STATUS_SUCCESS, "first scan -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "first scan iosb.Status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information != 0, "first scan wrote %lu bytes", (unsigned long)iosb.Information);

    /* --- THE POINT: the scan that has nothing left still writes the IOSB ---
     * A caller that poisons the block and reads it back must see the same
     * status the call returned, not its own poison. */
    poison_iosb(&iosb);
    status = NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, dirBuffer, sizeof(dirBuffer),
                                  FileBothDirectoryInformation, FALSE, NULL, FALSE);
    ok(status == STATUS_NO_MORE_FILES, "exhausted scan -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_NO_MORE_FILES, "exhausted scan left iosb.Status %08lx",
       (unsigned long)iosb.Status);

    /* --- and it stays that way for every further call ---------------------- */
    poison_iosb(&iosb);
    status = NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, dirBuffer, sizeof(dirBuffer),
                                  FileBothDirectoryInformation, TRUE, NULL, FALSE);
    ok(status == STATUS_NO_MORE_FILES, "single-entry exhausted scan -> %08lx",
       (unsigned long)status);
    ok(iosb.Status == STATUS_NO_MORE_FILES, "single-entry scan left iosb.Status %08lx",
       (unsigned long)iosb.Status);

    /* --- the one exemption: a scan whose mask matches nothing, on a handle
     * that has never enumerated ------------------------------------------
     * STATUS_NO_SUCH_FILE, and the caller's IOSB is NOT touched. This is the
     * assertion that separates the real rule from "write it always".
     *
     * It needs a FRESH handle, and that is not a detail of the test — it is
     * the difference between the two statuses. NO_SUCH_FILE means "this
     * enumeration never had anything"; a handle that has already listed the
     * directory is simply EXHAUSTED, and answers NO_MORE_FILES no matter
     * what mask the later call carries (measured: passing `restart` on the
     * used handle above still gives 0x80000006). ntdll:directory reaches the
     * NO_SUCH_FILE case the same way, by opening the directory afresh for
     * each masked probe. */
    {
        HANDLE fresh = open_test_dir(W("\\??\\C:\\prstest\\diriosb"));
        ok(fresh != NULL, "reopen the directory");
        if (fresh != NULL)
        {
            mask.Buffer = (PWSTR)W("no-such-name.zzz");
            mask.Length = 16 * sizeof(WCHAR);
            mask.MaximumLength = mask.Length;
            poison_iosb(&iosb);
            status =
                NtQueryDirectoryFile(fresh, NULL, NULL, NULL, &iosb, dirBuffer, sizeof(dirBuffer),
                                     FileBothDirectoryInformation, FALSE, &mask, TRUE);
            ok(status == STATUS_NO_SUCH_FILE, "unmatched mask -> %08lx", (unsigned long)status);
            ok(iosb.Status == IOSB_POISON_STATUS,
               "unmatched mask overwrote iosb.Status with %08lx", (unsigned long)iosb.Status);
            NtClose(fresh);
        }
    }

    /* --- a matching mask scans, then reports NO_MORE_FILES through the IOSB
     * like any other exhausted scan: the exemption is about NO_SUCH_FILE,
     * not about masks. */
    mask.Buffer = (PWSTR)W("only.tmp");
    mask.Length = 8 * sizeof(WCHAR);
    mask.MaximumLength = mask.Length;
    poison_iosb(&iosb);
    status = NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, dirBuffer, sizeof(dirBuffer),
                                  FileBothDirectoryInformation, FALSE, &mask, TRUE);
    ok(status == STATUS_SUCCESS, "matching mask -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "matching mask iosb.Status %08lx",
       (unsigned long)iosb.Status);

    poison_iosb(&iosb);
    status = NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, dirBuffer, sizeof(dirBuffer),
                                  FileBothDirectoryInformation, FALSE, NULL, FALSE);
    ok(status == STATUS_NO_MORE_FILES, "after the masked scan -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_NO_MORE_FILES, "after the masked scan iosb.Status %08lx",
       (unsigned long)iosb.Status);

    scrub_file(dir, W("only.tmp"));
    NtClose(dir);
}
