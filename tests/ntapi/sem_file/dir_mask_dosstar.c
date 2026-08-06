/*
 * sem_file/dir_mask_dosstar.c — DOS_STAR ('<') in a directory mask.
 *
 * Convicted by the winetest gate: ntdll:directory's mask truth table
 * (mask_tests in dlls/ntdll/tests/directory.c, 77 masks x 18 files) had 48
 * failures left after the mask-binding fix, and every one of them involves
 * '<'. Wine's PE stack emits it constantly — kernelbase's fixup_mask
 * rewrites a DOS glob into these forms before every NtQueryDirectoryFile —
 * so this is not an exotic corner.
 *
 * The rule, from Microsoft's FsRtlIsNameInExpression documentation:
 * DOS_STAR "matches zero or more characters until encountering and matching
 * the final . in the name". The two halves an implementation gets wrong are
 * both in that sentence:
 *
 *   - "until ... the final ." — the mask may resume at the start of ANY
 *     dot-delimited segment, not merely at or before the last dot. That is
 *     what makes `<tmp` match `n.tmp` (resume after the dot) and
 *     `ea.tmp.tmp` (resume after the SECOND dot).
 *
 *   - "and matching" — past the final dot DOS_STAR is spent. The mask
 *     resumes AT that dot's segment, never partway inside it: `<a` matches
 *     `.a` but must NOT match `.aa`, because consuming the extra 'a' would
 *     be DOS_STAR eating characters after the final dot.
 *
 * A run of them collapses (`<<`, `<<<` behave as `<`), and a trailing run
 * of zero-width-capable forms is dropped at the end of the mask, which is
 * what lets `<` alone match a dotless name.
 *
 * DERIVATION AND PROVENANCE. The masks and expectations below are taken
 * from that winetest table — third-party, Windows-verified spec data
 * (docs/08) — and from the MS documentation quoted above. They are NOT a
 * transcription of the oracle's matcher, which is LGPL C and off-limits as
 * kernel reference material (docs/11): reading it to understand observable
 * behaviour is fine, translating it is not.
 *
 * WHAT IS DELIBERATELY ABSENT. Nine cells of that table — masks `<`, `<"`,
 * `<""` against names `.a`, `..a`, `.aa` — cannot be satisfied by any
 * long-name matcher. They match through the entry's 8.3 SHORT name, which
 * proskrnl does not yet report; that is separate work (docs/21 W3a), and
 * the cases are excluded here rather than pinned wrong. Their absence is
 * the reason this pin uses `.a`-shaped names only where the long-name
 * answer is unambiguous.
 *
 * Oracle-first (G5).
 */
#include "util.h"

static UCHAR dirBuffer[4096];

/* One enumeration under `mask`; returns how many entries came back. */
static unsigned count_matches(HANDLE dir, const WCHAR *maskText)
{
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING mask;
    unsigned units = 0, count = 0;
    NTSTATUS status;

    while (maskText[units])
        units++;
    mask.Buffer = (PWSTR)maskText;
    mask.Length = (USHORT)(units * sizeof(WCHAR));
    mask.MaximumLength = mask.Length;

    status = NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, dirBuffer, sizeof(dirBuffer),
                                  FileBothDirectoryInformation, TRUE, &mask, TRUE);
    while (NT_SUCCESS(status))
    {
        count++;
        status = NtQueryDirectoryFile(dir, NULL, NULL, NULL, &iosb, dirBuffer, sizeof(dirBuffer),
                                      FileBothDirectoryInformation, TRUE, NULL, FALSE);
    }
    return count;
}

/* The fixture, chosen so every assertion below is decided by the LONG name.
 * `.` and `..` are always present and are matched as `.` (the parent
 * special case), so every expectation accounts for them explicitly. */
static const WCHAR *const kFiles[] = {
    W("n.tmp"),      /* one dot, three-unit extension */
    W("ea.tmp.tmp"), /* two dots: the resume point is the SECOND one */
    W("ea"),         /* no dot at all */
    W("dsa.tmp"),    /* a second .tmp, so `<tmp` counts more than one */
};

START_TEST(dir_mask_dosstar)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, scratch;

    dir = open_test_dir(W("\\??\\C:\\prstest\\dosstar"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    for (unsigned i = 0; i < 4; i++)
    {
        scrub_file(dir, kFiles[i]);
        status = open_file(&scratch, dir, kFiles[i], FILE_GENERIC_WRITE | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
        ok(status == STATUS_SUCCESS, "create a fixture file -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(scratch);
    }

    /* --- resume AFTER a dot: this is the half that was missing ------------
     * `<tmp` must reach the three .tmp names. A matcher that may only stop
     * at or before the final dot finds none of them. */
    ok(count_matches(dir, W("<tmp")) == 3, "<tmp matched %u of 3 .tmp names",
       count_matches(dir, W("<tmp")));

    /* `<.tmp` says the same thing with the dot spelled out, and must agree:
     * the table gives these two masks identical rows. */
    ok(count_matches(dir, W("<.tmp")) == 3, "<.tmp matched %u of 3 .tmp names",
       count_matches(dir, W("<.tmp")));

    /* --- a run of DOS_STARs collapses ------------------------------------
     * `<<` and `<<<` behave as a single `<`, which for this fixture means
     * everything: the four files plus `.` and `..`. */
    ok(count_matches(dir, W("<<")) == 6, "<< matched %u of 6 entries", count_matches(dir, W("<<")));
    ok(count_matches(dir, W("<<<")) == 6, "<<< matched %u of 6 entries",
       count_matches(dir, W("<<<")));

    /* --- DOS_STAR is SPENT at the final dot -------------------------------
     * `<a` reaches `ea` (no dot: DOS_STAR ranges freely) but nothing with an
     * extension — the 'a' cannot be matched inside `.tmp`. This is the
     * assertion that separates "resume anywhere" from "resume at a segment
     * boundary", and a matcher that allows the former reports 1 too many. */
    ok(count_matches(dir, W("<a")) == 1, "<a matched %u (expected just `ea`)",
       count_matches(dir, W("<a")));

    /* --- a literal tail after the DOS_STAR ------------------------------
     * `<a.tmp` reaches `dsa.tmp` — DOS_STAR consumes `ds` WITHIN the first
     * segment and the mask's literal `a.tmp` matches the rest. It does not
     * reach `ea.tmp.tmp`, whose remainder after any resume point is
     * `tmp.tmp` or `tmp`, neither of which is `a.tmp`. */
    ok(count_matches(dir, W("<a.tmp")) == 1, "<a.tmp matched %u (expected dsa.tmp only)",
       count_matches(dir, W("<a.tmp")));

    /* --- and the plain glob is unaffected by all of this ------------------ */
    ok(count_matches(dir, W("*.tmp")) == 3, "*.tmp matched %u of 3",
       count_matches(dir, W("*.tmp")));
    ok(count_matches(dir, W("*")) == 6, "* matched %u of 6", count_matches(dir, W("*")));

    for (unsigned i = 0; i < 4; i++)
        scrub_file(dir, kFiles[i]);
    NtClose(dir);
}
