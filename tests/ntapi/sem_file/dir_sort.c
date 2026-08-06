/*
 * sem_file/dir_sort.c — NtQueryDirectoryFile returns entries in
 * case-insensitive sorted order, with "." first and ".." second.
 *
 * Convicted by the winetest gate: ntdll:directory's test_directory_sort
 * walks a whole enumeration and requires
 * `RtlCompareUnicodeString(prev, name, TRUE) < 0` for every adjacent pair
 * (directory.c:311-325). 14 failures on proskrnl, and the pair passes on
 * the pinned oracle, so the order is part of the contract and not an
 * artifact of whichever filesystem is underneath.
 *
 * THIS CONTRADICTS AN EARLIER CLAIM IN THIS DIRECTORY, deliberately.
 * sem_file/query_dir.c's header says "NTFS returns sorted entries, FAT
 * returns disk order — the contract worth pinning is the set, not the
 * order", and every membership check there is order-agnostic on that
 * basis. The reasoning was that proskrnl's backend is FAT and FAT stores
 * entries in creation order, so sorting looked like an NTFS detail leaking
 * into the boundary. It is not: the ORACLE's backend is a unix directory,
 * whose readdir order is neither sorted nor creation order, and it sorts
 * anyway — because the sort belongs to NtQueryDirectoryFile, not to the
 * filesystem under it. The old comment inferred a contract from one
 * backend's behaviour; this pin measures it instead.
 *
 * Strictly increasing, note, not merely non-decreasing: two entries that
 * compare EQUAL case-insensitively would fail the winetest, so a stable
 * sort that leaves `README` beside `readme` in disk order is not enough on
 * a filesystem that could hold both. FAT cannot (its lookup is
 * case-insensitive, so the second create collides with the first), and
 * neither can the oracle's prefix, so the case is unreachable from a test
 * — which is exactly why it is called out here rather than asserted.
 *
 * The assertions are NOT wrapped in `todo_proskrnl`, and the reason is
 * worth recording: FAT's creation order happens to agree with sorted order
 * for some adjacent pairs and for `.`/`..`, so a todo block reports
 * "succeeded (remove the tag)" for those and fails the run anyway. A todo
 * tag can only mark a property that fails WHOLESALE; a property that holds
 * by luck for part of its domain has to land with its implementation.
 *
 * Oracle-first (G5): green on the oracle before the kernel commit that
 * follows it here.
 */
#include "util.h"

static UCHAR dirBuffer[8192];

/* Deliberately created in an order that is neither sorted nor reverse
 * sorted, and with case that differs from the sort order, so a backend
 * returning creation order or byte order fails. */
static const WCHAR *const kNames[] = {
    W("zulu.txt"), W("Alpha.txt"), W("mike.txt"), W("BRAVO.txt"), W("delta.txt"), W("Echo.txt"),
};

/* Case-insensitive compare of two counted UTF-16 names, the same ordering
 * RtlCompareUnicodeString(..., TRUE) gives for the ASCII names above. */
static int compare_ci(const WCHAR *a, unsigned aUnits, const WCHAR *b, unsigned bUnits)
{
    unsigned n = aUnits < bUnits ? aUnits : bUnits;
    for (unsigned i = 0; i < n; i++)
    {
        WCHAR x = a[i], y = b[i];
        if (x >= 'a' && x <= 'z')
            x = (WCHAR)(x - 'a' + 'A');
        if (y >= 'a' && y <= 'z')
            y = (WCHAR)(y - 'a' + 'A');
        if (x != y)
            return x < y ? -1 : 1;
    }
    if (aUnits == bUnits)
        return 0;
    return aUnits < bUnits ? -1 : 1;
}

static int is_name(const WCHAR *n, unsigned units, const WCHAR *want)
{
    unsigned w = 0;
    while (want[w])
        w++;
    if (w != units)
        return 0;
    for (unsigned i = 0; i < units; i++)
    {
        if (n[i] != want[i])
            return 0;
    }
    return 1;
}

START_TEST(dir_sort)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, scratch;
    WCHAR previous[64];
    unsigned previousUnits = 0, index = 0;

    dir = open_test_dir(W("\\??\\C:\\prstest\\dirsort"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    for (unsigned i = 0; i < 6; i++)
        scrub_file(dir, kNames[i]);
    for (unsigned i = 0; i < 6; i++)
    {
        status = open_file(&scratch, dir, kNames[i], FILE_GENERIC_WRITE | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
        ok(status == STATUS_SUCCESS, "create a fixture file -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(scratch);
    }

    /* A small buffer on purpose: the order must hold ACROSS calls, not just
     * within one bufferful, which is the part a per-call sort would get
     * wrong. */
    status = NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, dirBuffer, 512,
                                  FileBothDirectoryInformation, FALSE, NULL, TRUE);
    while (NT_SUCCESS(status))
    {
        ULONG offset = 0;
        for (;;)
        {
            FILE_BOTH_DIRECTORY_INFORMATION *entry =
                (FILE_BOTH_DIRECTORY_INFORMATION *)(dirBuffer + offset);
            unsigned units = entry->FileNameLength / sizeof(WCHAR);

            if (index == 0)
            {
                ok(is_name(entry->FileName, units, W(".")), "first entry is not \".\"");
            }
            else if (index == 1)
            {
                ok(is_name(entry->FileName, units, W("..")), "second entry is not \"..\"");
            }
            else if (index > 2)
            {
                /* Strictly increasing, exactly as the winetest requires. */
                int order = compare_ci(previous, previousUnits, entry->FileName, units);
                ok(order < 0, "entry %u is not after its predecessor (compare %d)", index, order);
            }

            previousUnits = units < 63 ? units : 63;
            for (unsigned i = 0; i < previousUnits; i++)
                previous[i] = entry->FileName[i];
            index++;

            if (entry->NextEntryOffset == 0)
                break;
            offset += entry->NextEntryOffset;
        }
        status = NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, dirBuffer, 512,
                                      FileBothDirectoryInformation, FALSE, NULL, FALSE);
    }
    ok(status == STATUS_NO_MORE_FILES, "enumeration ended with %08lx", (unsigned long)status);
    ok(index == 8, "saw %u entries (6 files + . + ..)", index);

    /* --- the order survives a restart, and a masked scan is sorted too ---- */
    {
        UNICODE_STRING mask;
        unsigned masked = 0;
        mask.Buffer = (PWSTR)W("*.txt");
        mask.Length = 5 * sizeof(WCHAR);
        mask.MaximumLength = mask.Length;
        previousUnits = 0;

        status = NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, dirBuffer, 512,
                                      FileBothDirectoryInformation, TRUE, &mask, TRUE);
        while (NT_SUCCESS(status))
        {
            FILE_BOTH_DIRECTORY_INFORMATION *entry = (FILE_BOTH_DIRECTORY_INFORMATION *)dirBuffer;
            unsigned units = entry->FileNameLength / sizeof(WCHAR);
            if (masked != 0)
            {
                int order = compare_ci(previous, previousUnits, entry->FileName, units);
                ok(order < 0, "masked entry %u is out of order (compare %d)", masked, order);
            }
            previousUnits = units < 63 ? units : 63;
            for (unsigned i = 0; i < previousUnits; i++)
                previous[i] = entry->FileName[i];
            masked++;
            status = NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, dirBuffer, 512,
                                          FileBothDirectoryInformation, TRUE, NULL, FALSE);
        }
        ok(masked == 6, "the masked scan saw %u of 6 .txt files", masked);
    }

    for (unsigned i = 0; i < 6; i++)
        scrub_file(dir, kNames[i]);
    NtClose(dir);
}
