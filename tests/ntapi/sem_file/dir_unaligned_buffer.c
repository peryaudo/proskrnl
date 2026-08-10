/*
 * sem_file/dir_unaligned_buffer.c — NtQueryDirectoryFile does not require its
 * output buffer to be 8-byte aligned.
 *
 * The entries it writes are laid out on 8-byte boundaries RELATIVE TO THE
 * BUFFER (LARGE_INTEGER members, and the NextEntryOffset chain that steps
 * between them), which invites the reading that the buffer itself must be
 * 8-aligned. It must not: every entry offset is relative, and NT copies the
 * bytes wherever the caller asked. A kernel that instead stores each field
 * through a struct pointer inherits the buffer's alignment on every field —
 * legal on x86 hardware, but undefined C, and this build traps it.
 *
 * Convicted by a real caller, not by a sweep: the pinned tree's own
 * dlls/ntdll/actctx.c lookup_manifest_file enumerates windows\winsxs\manifests
 * with `char buffer[8192]` on the stack and FileBothDirectoryInformation. In a
 * 32-bit (WOW64) process, i386 gives that array 4-byte alignment — so the very
 * first SxS lookup any WOW64 GUI applet does lands here, and proskrnl took a
 * #UD in IopFillDirEntry writing CreationTime to buffer+8 (a 4-aligned
 * address) before winemine could paint a window.
 *
 * The three deltas below are the three distinct cases: 4 is what the real
 * caller hands over, 2 leaves the ULONGs misaligned too (NextEntryOffset,
 * FileNameLength), and 1 misaligns even the WCHARs of the name. NT treats the
 * buffer as bytes, so all three answer alike.
 *
 * Oracle-first (G5).
 */
#include "util.h"

/* Deliberately over-sized and given its own 8-aligned base so the test can
 * offset INTO it by a known amount. `long long` for the base alignment; the
 * cast to unsigned char * is where the deltas are applied. */
static long long alignedStore[512];

static const void *population[] = {W("aligned_one.txt"), W("aligned_two.txt"),
                                   W("aligned_three.txt")};

/* Enumerate `dir` into alignedStore+delta and report what came back: the
 * status, and how many of the three population names were seen. */
static NTSTATUS enumerate_at(HANDLE dir, unsigned delta, unsigned *seen)
{
    unsigned char *buffer = (unsigned char *)alignedStore + delta;
    ULONG length = (ULONG)(sizeof(alignedStore) - 8);
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    BOOLEAN restart = TRUE;

    *seen = 0;
    for (;;)
    {
        poison_iosb(&iosb);
        status = NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, buffer, length,
                                      FileBothDirectoryInformation, FALSE, NULL, restart);
        restart = FALSE;
        if (status == STATUS_NO_MORE_FILES)
            return STATUS_SUCCESS;
        if (status != STATUS_SUCCESS)
            return status;

        ULONG offset = 0;
        for (;;)
        {
            /* Read the entry back the same way the kernel wrote it — byte by
             * byte into an aligned local. The test may not itself do the
             * misaligned struct access it is asserting the kernel avoids. */
            FILE_BOTH_DIRECTORY_INFORMATION entry;
            WCHAR name[64];
            memcpy(&entry, buffer + offset, sizeof(entry));
            unsigned units = entry.FileNameLength / sizeof(WCHAR);
            if (units < 64)
            {
                memcpy(name,
                       buffer + offset + FIELD_OFFSET(FILE_BOTH_DIRECTORY_INFORMATION, FileName),
                       units * sizeof(WCHAR));
                name[units] = 0;
                for (unsigned i = 0; i < 3; i++)
                {
                    const WCHAR *want = (const WCHAR *)population[i];
                    unsigned j = 0;
                    while (want[j] && name[j])
                    {
                        WCHAR a = name[j], b = want[j];
                        if (a >= 'A' && a <= 'Z')
                            a = (WCHAR)(a - 'A' + 'a');
                        if (b >= 'A' && b <= 'Z')
                            b = (WCHAR)(b - 'A' + 'a');
                        if (a != b)
                            break;
                        j++;
                    }
                    if (want[j] == 0 && name[j] == 0)
                        (*seen)++;
                }
            }
            if (entry.NextEntryOffset == 0)
                break;
            offset += entry.NextEntryOffset;
        }
    }
}

START_TEST(dir_unaligned_buffer)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, sub, h;

    dir = open_test_dir(W("\\??\\C:\\prstest\\dirunal"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;

    status = open_file(
        &sub, dir, W("pop"),
        FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_TRAVERSE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "create pop dir -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return;
    for (unsigned i = 0; i < 3; i++)
    {
        scrub_file(sub, population[i]);
        status = open_file(&h, sub, population[i], FILE_GENERIC_WRITE, 0, FILE_CREATE, 0, &iosb);
        ok(status == STATUS_SUCCESS, "create population %u -> %08lx", i, (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(h);
    }

    /* An 8-aligned buffer first, so the deltas below are compared against
     * this test's OWN baseline rather than against another test's. */
    unsigned seen = 0;
    status = enumerate_at(sub, 0, &seen);
    ok(status == STATUS_SUCCESS, "aligned enumeration -> %08lx", (unsigned long)status);
    ok(seen == 3, "aligned enumeration saw %u of 3", seen);

    static const unsigned deltas[] = {4, 2, 1};
    for (unsigned i = 0; i < 3; i++)
    {
        seen = 0;
        status = enumerate_at(sub, deltas[i], &seen);
        ok(status == STATUS_SUCCESS, "buffer+%u enumeration -> %08lx", deltas[i],
           (unsigned long)status);
        ok(seen == 3, "buffer+%u enumeration saw %u of 3", deltas[i], seen);
    }

    for (unsigned i = 0; i < 3; i++)
        scrub_file(sub, population[i]);
    NtClose(sub);
    scrub_file(dir, W("pop"));
    NtClose(dir);
}
