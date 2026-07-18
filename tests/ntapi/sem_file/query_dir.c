/*
 * sem_file/query_dir.c — NtQueryDirectoryFile (M6): enumeration across the
 * main directory info classes, the "." / ".." entries, single-entry mode,
 * restart-scan, name masks, and STATUS_NO_MORE_FILES.
 *
 * All membership checks are order-agnostic: NTFS returns sorted entries, FAT
 * returns disk order — the contract worth pinning is the set, not the order.
 */
#include "util.h"

#define MAX_NAMES 32

struct name_set
{
    unsigned count;
    unsigned lengths[MAX_NAMES];
    WCHAR names[MAX_NAMES][64];
};

static void set_add(struct name_set *set, const WCHAR *name, unsigned length_units)
{
    if (set->count == MAX_NAMES || length_units >= 64)
        return;
    set->lengths[set->count] = length_units;
    for (unsigned i = 0; i < length_units; i++)
        set->names[set->count][i] = name[i];
    set->count++;
}

static int set_has(const struct name_set *set, const void *wide)
{
    const WCHAR *want = (const WCHAR *)wide;
    unsigned want_units = 0;
    while (want[want_units])
        want_units++;
    for (unsigned i = 0; i < set->count; i++)
    {
        if (set->lengths[i] != want_units)
            continue;
        unsigned j;
        for (j = 0; j < want_units; j++)
        {
            WCHAR a = set->names[i][j], b = want[j];
            if (a >= 'A' && a <= 'Z')
                a = (WCHAR)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z')
                b = (WCHAR)(b - 'A' + 'a');
            if (a != b)
                break;
        }
        if (j == want_units)
            return 1;
    }
    return 0;
}

/* Enumerate `dir` with FileDirectoryInformation into `set`; returns the
 * number of NtQueryDirectoryFile calls that returned entries. */
static void enumerate(HANDLE dir, struct name_set *set, PUNICODE_STRING mask, BOOLEAN restart)
{
    unsigned char buffer[2048];
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    for (;;)
    {
        poison_iosb(&iosb);
        status = NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer),
                                      FileDirectoryInformation, FALSE, mask, restart);
        restart = FALSE;
        if (status == STATUS_NO_MORE_FILES)
            break;
        ok(status == STATUS_SUCCESS, "enumerate chunk -> %08lx", (unsigned long)status);
        if (status != STATUS_SUCCESS)
            break;
        ok(iosb.Information != 0 && iosb.Information <= sizeof(buffer),
           "enumerate chunk: Information %lu", (unsigned long)iosb.Information);
        unsigned offset = 0;
        for (;;)
        {
            FILE_DIRECTORY_INFORMATION *entry = (FILE_DIRECTORY_INFORMATION *)(buffer + offset);
            set_add(set, entry->FileName, entry->FileNameLength / sizeof(WCHAR));
            if (entry->NextEntryOffset == 0)
                break;
            offset += entry->NextEntryOffset;
        }
    }
}

START_TEST(query_dir)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, sub, h;
    struct name_set set;

    dir = open_test_dir(W("\\??\\C:\\prstest\\qdir"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;

    /* Build a known population inside a fresh subdirectory. */
    status = open_file(
        &sub, dir, W("pop"),
        FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_TRAVERSE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "create pop dir -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return;
    static const void *files[] = {W("alpha.txt"), W("beta.txt"), W("gamma.dat"),
                                  W("LongFileName_With_Mixed.Case")};
    for (unsigned i = 0; i < 4; i++)
    {
        scrub_file(sub, files[i]);
        status = open_file(&h, sub, files[i], FILE_GENERIC_WRITE, 0, FILE_CREATE, 0, &iosb);
        ok(status == STATUS_SUCCESS, "create population %u -> %08lx", i, (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            LARGE_INTEGER off;
            off.QuadPart = 0;
            NtWriteFile(h, NULL, NULL, NULL, &iosb, "x", 1, &off, NULL);
            NtClose(h);
        }
    }
    status =
        open_file(&h, sub, W("nested"), FILE_LIST_DIRECTORY | SYNCHRONIZE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "create nested dir -> %08lx", (unsigned long)status);
    NtClose(h);

    /* --- full enumeration: the population plus "." and "..". --------------- */
    memset(&set, 0, sizeof(set));
    enumerate(sub, &set, NULL, TRUE);
    ok(set_has(&set, W(".")), "dot present");
    ok(set_has(&set, W("..")), "dotdot present");
    ok(set_has(&set, W("alpha.txt")), "alpha.txt present");
    ok(set_has(&set, W("beta.txt")), "beta.txt present");
    ok(set_has(&set, W("gamma.dat")), "gamma.dat present");
    ok(set_has(&set, W("LongFileName_With_Mixed.Case")), "long mixed-case name preserved");
    ok(set_has(&set, W("nested")), "nested dir present");
    ok(set.count == 7, "population count %u", set.count);

    /* --- the long name round-trips with its case preserved exactly. -------- */
    {
        int exact = 0;
        static const WCHAR want[] = W("LongFileName_With_Mixed.Case");
        unsigned want_units = (sizeof(want) / sizeof(WCHAR)) - 1;
        for (unsigned i = 0; i < set.count; i++)
        {
            if (set.lengths[i] != want_units)
                continue;
            unsigned j;
            for (j = 0; j < want_units && set.names[i][j] == want[j]; j++)
                ;
            if (j == want_units)
                exact = 1;
        }
        ok(exact, "long name case preserved byte-for-byte");
    }

    /* --- exhausted enumeration reports STATUS_NO_MORE_FILES again. --------- */
    {
        unsigned char buffer[512];
        poison_iosb(&iosb);
        status = NtQueryDirectoryFile(sub, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer),
                                      FileDirectoryInformation, FALSE, NULL, FALSE);
        ok(status == STATUS_NO_MORE_FILES, "exhausted -> %08lx", (unsigned long)status);
    }

    /* --- restart-scan starts over. ----------------------------------------- */
    memset(&set, 0, sizeof(set));
    enumerate(sub, &set, NULL, TRUE);
    ok(set.count == 7, "restart re-enumerates (%u)", set.count);

    /* --- single-entry mode yields one entry per call. ---------------------- */
    {
        unsigned char buffer[512];
        unsigned calls = 0;
        BOOLEAN restart = TRUE;
        for (;;)
        {
            poison_iosb(&iosb);
            status = NtQueryDirectoryFile(sub, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer),
                                          FileDirectoryInformation, TRUE, NULL, restart);
            restart = FALSE;
            if (status == STATUS_NO_MORE_FILES)
                break;
            ok(status == STATUS_SUCCESS, "single-entry chunk -> %08lx", (unsigned long)status);
            if (status != STATUS_SUCCESS)
                break;
            FILE_DIRECTORY_INFORMATION *entry = (FILE_DIRECTORY_INFORMATION *)buffer;
            ok(entry->NextEntryOffset == 0, "single entry has no next (%lu)",
               (unsigned long)entry->NextEntryOffset);
            calls++;
            if (calls > 16)
                break;
        }
        ok(calls == 7, "single-entry call count %u", calls);
    }

    /* --- a name mask filters. The mask binds per query on the pinned Wine
     * (a NULL mask on a later call REUSES the previous one), so every mask
     * scenario below runs on its own fresh handle to stay deterministic. --- */
    HANDLE sub2;
    {
        UNICODE_STRING mask;
        init_ustr(&mask, W("*.txt"));
        status = open_file(&sub2, dir, W("pop"), FILE_LIST_DIRECTORY | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_DIRECTORY_FILE,
                           &iosb);
        ok(status == STATUS_SUCCESS, "mask handle 1 -> %08lx", (unsigned long)status);
        memset(&set, 0, sizeof(set));
        enumerate(sub2, &set, &mask, TRUE);
        NtClose(sub2);
        ok(set_has(&set, W("alpha.txt")) && set_has(&set, W("beta.txt")), "mask keeps .txt");
        ok(!set_has(&set, W("gamma.dat")), "mask drops .dat");
        ok(set.count == 2, "mask count %u", set.count);
    }
    {
        /* An exact-name mask finds exactly that file. */
        UNICODE_STRING mask;
        init_ustr(&mask, W("gamma.dat"));
        status = open_file(&sub2, dir, W("pop"), FILE_LIST_DIRECTORY | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_DIRECTORY_FILE,
                           &iosb);
        ok(status == STATUS_SUCCESS, "mask handle 2 -> %08lx", (unsigned long)status);
        memset(&set, 0, sizeof(set));
        enumerate(sub2, &set, &mask, TRUE);
        NtClose(sub2);
        ok(set.count == 1 && set_has(&set, W("gamma.dat")), "exact mask count %u", set.count);
    }
    {
        /* A mask matching nothing: no such file. */
        unsigned char buffer[512];
        UNICODE_STRING mask;
        init_ustr(&mask, W("zzz.*"));
        status = open_file(&sub2, dir, W("pop"), FILE_LIST_DIRECTORY | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_DIRECTORY_FILE,
                           &iosb);
        ok(status == STATUS_SUCCESS, "mask handle 3 -> %08lx", (unsigned long)status);
        poison_iosb(&iosb);
        status = NtQueryDirectoryFile(sub2, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer),
                                      FileDirectoryInformation, FALSE, &mask, TRUE);
        /* Nothing matches the mask on the handle's FIRST query:
         * STATUS_NO_SUCH_FILE (later calls would say NO_MORE_FILES). */
        ok(status == STATUS_NO_SUCH_FILE, "empty mask result -> %08lx", (unsigned long)status);
        NtClose(sub2);
    }

    /* --- FileBothDirectoryInformation carries sizes. ------------------------ */
    {
        unsigned char buffer[2048];
        UNICODE_STRING mask;
        init_ustr(&mask, W("alpha.txt"));
        status = open_file(&sub2, dir, W("pop"), FILE_LIST_DIRECTORY | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_DIRECTORY_FILE,
                           &iosb);
        ok(status == STATUS_SUCCESS, "mask handle 4 -> %08lx", (unsigned long)status);
        poison_iosb(&iosb);
        status = NtQueryDirectoryFile(sub2, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer),
                                      FileBothDirectoryInformation, TRUE, &mask, TRUE);
        NtClose(sub2);
        ok(status == STATUS_SUCCESS, "both-dir query -> %08lx", (unsigned long)status);
        if (status == STATUS_SUCCESS)
        {
            FILE_BOTH_DIR_INFORMATION *entry = (FILE_BOTH_DIR_INFORMATION *)buffer;
            ok(entry->EndOfFile.QuadPart == 1, "both-dir EOF %ld", (long)entry->EndOfFile.QuadPart);
            ok((entry->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0, "both-dir attrs %lx",
               (unsigned long)entry->FileAttributes);
        }
    }

    /* --- FileNamesInformation is the thin class. ---------------------------- */
    {
        unsigned char buffer[2048];
        status = open_file(&sub2, dir, W("pop"), FILE_LIST_DIRECTORY | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_DIRECTORY_FILE,
                           &iosb);
        ok(status == STATUS_SUCCESS, "names handle -> %08lx", (unsigned long)status);
        poison_iosb(&iosb);
        status = NtQueryDirectoryFile(sub2, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer),
                                      FileNamesInformation, FALSE, NULL, TRUE);
        ok(status == STATUS_SUCCESS, "names query -> %08lx", (unsigned long)status);
        if (status == STATUS_SUCCESS)
        {
            unsigned offset = 0, count = 0;
            for (;;)
            {
                FILE_NAMES_INFORMATION *entry = (FILE_NAMES_INFORMATION *)(buffer + offset);
                count++;
                if (entry->NextEntryOffset == 0)
                    break;
                offset += entry->NextEntryOffset;
            }
            ok(count == 7, "names count %u", count);
        }
        NtClose(sub2);
    }

    /* --- querying a plain file handle is invalid. --------------------------- */
    {
        unsigned char buffer[512];
        status = open_file(&h, sub, W("alpha.txt"), FILE_GENERIC_READ, FILE_SHARE_READ, FILE_OPEN,
                           0, &iosb);
        ok(status == STATUS_SUCCESS, "open alpha.txt -> %08lx", (unsigned long)status);
        poison_iosb(&iosb);
        status = NtQueryDirectoryFile(h, NULL, NULL, NULL, &iosb, buffer, sizeof(buffer),
                                      FileDirectoryInformation, FALSE, NULL, TRUE);
        ok(status == STATUS_INVALID_PARAMETER, "query-dir on file -> %08lx", (unsigned long)status);
        NtClose(h);
    }

    /* Clean the population so reruns start from the same set. */
    for (unsigned i = 0; i < 4; i++)
        scrub_file(sub, files[i]);
    {
        HANDLE nested;
        status = open_file(&nested, sub, W("nested"), DELETE | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
                           FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, &iosb);
        if (NT_SUCCESS(status))
            NtClose(nested);
    }
    NtClose(sub);
    NtClose(dir);
}
