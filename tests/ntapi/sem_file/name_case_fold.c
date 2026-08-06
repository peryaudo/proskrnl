/*
 * sem_file/name_case_fold.c — case-insensitive name matching folds the
 * Latin-1 Supplement, not just ASCII.
 *
 * Convicted by the winetest gate, after two other fixes made it reachable.
 * ntdll:directory creates `éa.tmp` (U+00E9) and `Éb.tmp` (U+00C9) and
 * requires the enumeration to be strictly increasing under a
 * case-insensitive compare (directory.c:324). With an ASCII-only fold
 * U+00C9 sorts before U+00E9, so `Éb.tmp` lands before `éa.tmp`; with the
 * real fold both become U+00C9 and `éa` sorts first on the `a` < `b`.
 *
 * proskrnl's RtlUpcaseUnicodeChar was ASCII-only, which docs/03 recorded as
 * "unobservable until user mode invents non-ASCII object names". User mode
 * just did. The fold is ONE authority (Art. 11) — Ob name resolution, FAT
 * lookup, Cm enumeration order and this directory sort all go through it —
 * so widening it is deliberately its own change, and this pin covers all
 * four consumers' shared observable: two names that differ only by case
 * are the same name, and two that do not are ordered by their folded form.
 *
 * WHAT IS PINNED IS THE LATIN-1 SUPPLEMENT AND NOTHING BEYOND IT.
 * NT folds through a 64 KiB table; proskrnl carries a rule, not a table.
 * The rule is exactly Unicode's Latin-1 Supplement mapping, including its
 * three irregularities — which is why they are asserted here rather than
 * assumed:
 *
 *   U+00E0..U+00FE except U+00F7  ->  minus 0x20
 *   U+00F7 (division sign)        ->  itself (not a letter)
 *   U+00DF (sharp s)              ->  itself (its uppercase is "SS", which
 *                                     no single-character fold can express)
 *   U+00FF (y with diaeresis)     ->  U+0178, NOT U+00DF
 *
 * That last one is the trap: a fold written as "subtract 0x20 across the
 * range" turns ÿ into ß, silently making two unrelated letters the same
 * name. Greek, Cyrillic and the rest stay unfolded and remain a recorded
 * deviation — asserting anything about them here would fail on proskrnl
 * while passing on the oracle, which is the pin telling the truth.
 *
 * Oracle-first (G5).
 */
#include "util.h"

static UCHAR dirBuffer[4096];

/* Does a case-insensitive open of `probe` find the file created as
 * `created`? That is the fold, observed through the FAT/Ob name path. */
static int same_file(HANDLE dir, const WCHAR *created, const WCHAR *probe)
{
    IO_STATUS_BLOCK iosb;
    HANDLE handle = NULL, opened = NULL;
    NTSTATUS status;
    int found;

    scrub_file(dir, created);
    status = open_file(&handle, dir, created, FILE_GENERIC_WRITE | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create the fold fixture -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return -1;
    NtClose(handle);

    status = open_file(&opened, dir, probe, FILE_GENERIC_READ | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
    found = NT_SUCCESS(status);
    if (found)
        NtClose(opened);
    scrub_file(dir, created);
    return found;
}

START_TEST(name_case_fold)
{
    HANDLE dir;

    dir = open_test_dir(W("\\??\\C:\\prstest\\casefold"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;

    /* --- the ASCII fold, as a control ------------------------------------ */
    ok(same_file(dir, W("fold.tmp"), W("FOLD.TMP")) == 1, "ASCII fold does not match");

    /* --- the Latin-1 fold: the whole point ------------------------------- */
    ok(same_file(dir, W("\u00e9fold.tmp"), W("\u00c9FOLD.TMP")) == 1,
       "U+00E9 does not fold to U+00C9");
    ok(same_file(dir, W("\u00fcfold.tmp"), W("\u00dcFOLD.TMP")) == 1,
       "U+00FC does not fold to U+00DC");
    ok(same_file(dir, W("\u00e0fold.tmp"), W("\u00c0FOLD.TMP")) == 1,
       "U+00E0 does not fold to U+00C0");
    ok(same_file(dir, W("\u00feold.tmp"), W("\u00deOLD.TMP")) == 1,
       "U+00FE does not fold to U+00DE");

    /* --- and the three that must NOT follow the subtract-0x20 rule -------
     * ÿ (U+00FF) folds to U+0178, so a file created as ÿ must NOT be found
     * under ß (U+00DF) — which is exactly what "subtract 0x20" would do,
     * and it would merge two unrelated letters into one name. */
    ok(same_file(dir, W("\u00ffold.tmp"), W("\u00dfOLD.tmp")) == 0,
       "U+00FF wrongly folds to U+00DF");
    /* ß has no single-character uppercase and must fold to itself: a file
     * created as ß is still found as ß, and is a different file from Ÿ. */
    ok(same_file(dir, W("\u00dfold.tmp"), W("\u00dfold.tmp")) == 1, "U+00DF does not match itself");
    ok(same_file(dir, W("\u00dfold.tmp"), W("\u0178old.tmp")) == 0,
       "U+00DF wrongly folds to U+0178");
    /* ÷ is not a letter; it folds to itself and to nothing else. */
    ok(same_file(dir, W("\u00f7old.tmp"), W("\u00f7old.tmp")) == 1, "U+00F7 does not match itself");
    ok(same_file(dir, W("\u00f7old.tmp"), W("\u00d7old.tmp")) == 0,
       "U+00F7 wrongly folds to U+00D7");

    /* --- the ordering consequence, which is what the winetest measures ----
     * `éa` and `Éb` fold to the same first character, so they order on the
     * second: `a` before `b`. Under an ASCII-only fold U+00C9 < U+00E9 and
     * `Éb` comes first. */
    {
        IO_STATUS_BLOCK iosb;
        NTSTATUS status;
        HANDLE scratch;
        WCHAR firstSeen[64];
        unsigned firstUnits = 0;

        scrub_file(dir, W("\u00e9a.tmp"));
        scrub_file(dir, W("\u00c9b.tmp"));
        /* Created in the order the ASCII fold would return them, so a stale
         * fold cannot pass by accident. */
        status = open_file(&scratch, dir, W("\u00c9b.tmp"), FILE_GENERIC_WRITE | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
        ok(status == STATUS_SUCCESS, "create Eb -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(scratch);
        status = open_file(&scratch, dir, W("\u00e9a.tmp"), FILE_GENERIC_WRITE | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
        ok(status == STATUS_SUCCESS, "create ea -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(scratch);

        {
            UNICODE_STRING mask;
            mask.Buffer = (PWSTR)W("*.tmp");
            mask.Length = 5 * sizeof(WCHAR);
            mask.MaximumLength = mask.Length;
            status =
                NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, dirBuffer, sizeof(dirBuffer),
                                     FileBothDirectoryInformation, TRUE, &mask, TRUE);
            ok(NT_SUCCESS(status), "enumerate the fold pair -> %08lx", (unsigned long)status);
            if (NT_SUCCESS(status))
            {
                FILE_BOTH_DIRECTORY_INFORMATION *entry =
                    (FILE_BOTH_DIRECTORY_INFORMATION *)dirBuffer;
                firstUnits = entry->FileNameLength / sizeof(WCHAR);
                for (unsigned i = 0; i < firstUnits && i < 63; i++)
                    firstSeen[i] = entry->FileName[i];
            }
            ok(firstUnits != 0 && firstSeen[0] == 0x00e9,
               "the folded sort put U+%04X first, expected U+00E9",
               firstUnits != 0 ? (unsigned)firstSeen[0] : 0);
        }

        scrub_file(dir, W("\u00e9a.tmp"));
        scrub_file(dir, W("\u00c9b.tmp"));
    }

    NtClose(dir);
}
