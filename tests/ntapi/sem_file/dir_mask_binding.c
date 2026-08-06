/*
 * sem_file/dir_mask_binding.c — WHEN a directory mask binds to the handle.
 *
 * Convicted by the winetest gate, and it is the largest single defect the
 * gate has found in this subsystem. ntdll:directory enumerates with one
 * mask, then continues the scan passing `&dummy_mask` on every follow-up
 * call (directory.c:241) — a name that matches nothing. proskrnl rebound
 * the handle to "dummy" and lost the rest of the directory, which is worth
 * roughly 150 of the 203 failures at directory.c:620 and all 34 at :265
 * (two single-entry sweeps that return one entry each and then drop the
 * remaining 17 files).
 *
 * The rule (dlls/ntdll/unix/file.c, get_cached_dir_data):
 *
 *     if (dir_data_cache[entry] && restart_scan && mask &&
 *         !ustring_equal(&dir_data_cache[entry]->mask, mask))
 *         ... discard the snapshot and rebuild with the new mask ...
 *
 * so a mask binds on a handle that has never enumerated, and afterwards
 * ONLY on a call that also asks to restart the scan. A continuation call's
 * mask is ignored outright — not merged, not intersected, ignored. Which
 * is the only reading that makes NtQueryDirectoryFile's own callers work:
 * an enumeration is a cursor over a snapshot chosen when the scan began,
 * and a caller that passes its mask on every call (as kernelbase's
 * FindNextFile does) must not be re-filtering mid-walk.
 *
 * The same function has the other half of the ordering already pinned in
 * sem_file/dir_iosb.c: STATUS_NO_SUCH_FILE is what a scan that never had
 * anything reports, and a handle that has already enumerated says
 * NO_MORE_FILES instead (`if (status == STATUS_NO_SUCH_FILE &&
 * !fresh_handle) status = STATUS_NO_MORE_FILES;`). Both facts are the same
 * idea: the handle remembers its scan.
 *
 * Oracle-first (G5).
 */
#include "util.h"

/* Deliberately small: enough for one entry and not two, so the enumeration
 * is forced to take several calls and the continuation mask matters. */
static UCHAR dirBuffer[512];

static const WCHAR *const kNames[] = {W("bind_a.tmp"), W("bind_b.tmp"), W("bind_c.tmp")};

/* Count entries over a whole enumeration, passing `mask` on every call
 * after the first — the shape ntdll:directory uses. */
static unsigned enumerate(HANDLE dir, UNICODE_STRING *firstMask, UNICODE_STRING *laterMask)
{
    IO_STATUS_BLOCK iosb;
    unsigned count = 0;
    NTSTATUS status =
        NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, dirBuffer, sizeof(dirBuffer),
                             FileBothDirectoryInformation, TRUE, firstMask, TRUE);
    while (NT_SUCCESS(status))
    {
        count++;
        status = NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, dirBuffer, sizeof(dirBuffer),
                                      FileBothDirectoryInformation, TRUE, laterMask, FALSE);
    }
    return count;
}

START_TEST(dir_mask_binding)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, scratch;
    UNICODE_STRING wildMask, dummyMask;
    unsigned withDummy, withNull;

    dir = open_test_dir(W("\\??\\C:\\prstest\\maskbind"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    for (unsigned i = 0; i < 3; i++)
    {
        scrub_file(dir, kNames[i]);
        status = open_file(&scratch, dir, kNames[i], FILE_GENERIC_WRITE | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
        ok(status == STATUS_SUCCESS, "create a test file -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(scratch);
    }

    wildMask.Buffer = (PWSTR)W("bind_*.tmp");
    wildMask.Length = 10 * sizeof(WCHAR);
    wildMask.MaximumLength = wildMask.Length;
    dummyMask.Buffer = (PWSTR)W("dummy");
    dummyMask.Length = 5 * sizeof(WCHAR);
    dummyMask.MaximumLength = dummyMask.Length;

    /* --- the baseline: the three files, continuation calls unmasked ------- */
    withNull = enumerate(dir, &wildMask, NULL);
    ok(withNull == 3, "unmasked continuation saw %u of 3 files", withNull);

    /* --- THE POINT: a matches-nothing mask on every continuation changes
     * nothing, because the scan is already bound. An implementation that
     * rebinds sees exactly ONE entry — the one the first call returned
     * before the dummy mask took effect. */
    withDummy = enumerate(dir, &wildMask, &dummyMask);
    ok(withDummy == 3, "dummy-masked continuation saw %u of 3 files", withDummy);

    /* --- and a rebind DOES happen when the call asks to restart ----------- */
    {
        unsigned count = 0;
        status = NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, dirBuffer, sizeof(dirBuffer),
                                      FileBothDirectoryInformation, TRUE, &wildMask, TRUE);
        ok(NT_SUCCESS(status), "restart with the wildcard -> %08lx", (unsigned long)status);
        /* Restart again, this time WITH the dummy mask: it binds, and the
         * enumeration now finds nothing. */
        status = NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, dirBuffer, sizeof(dirBuffer),
                                      FileBothDirectoryInformation, TRUE, &dummyMask, TRUE);
        while (NT_SUCCESS(status))
        {
            count++;
            status =
                NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, dirBuffer, sizeof(dirBuffer),
                                     FileBothDirectoryInformation, TRUE, NULL, FALSE);
        }
        ok(count == 0, "restart with the dummy mask still saw %u files", count);
    }

    for (unsigned i = 0; i < 3; i++)
        scrub_file(dir, kNames[i]);
    NtClose(dir);
}
