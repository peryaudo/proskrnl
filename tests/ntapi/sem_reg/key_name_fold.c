/*
 * sem_reg/key_name_fold.c — registry key names fold through the NLS upcase
 * TABLE, over the whole BMP, per 16-bit code unit.
 *
 * Convicted by the winetest gate. ntdll:reg creates a key named
 * U+00F6 U+00F3 U+014D U+0371 U+D801 U+DC00 and re-opens it as
 * U+00D6 U+00D3 U+014C U+0370 U+D801 U+DC00 (reg.c:346-:355), i.e. it
 * requires the fold to reach Latin Extended-A and Greek — and, at :350,
 * requires the low surrogate U+DC28 NOT to match U+DC00, which is the same
 * test saying the fold is per code UNIT and not per code POINT.
 *
 * Failing it is not one assertion. The subkey that open never returned is
 * never deleted, so its parent still has a child, and test_NtDeleteKey's
 * delete of that parent answers STATUS_ACCESS_DENIED — eleven more
 * assertions about the deleted-key contract (reg.c:821-:854) fail behind one
 * fold.
 *
 * WHAT IS PINNED IS A TABLE, NOT A RULE — and that is the point.
 * proskrnl carried a hand-written rule (ASCII, widened once to the Latin-1
 * Supplement); the oracle carries `nls/l_intl.nls`, which BOTH of its halves
 * read: Wine's PE ntdll maps the uppercase table (dlls/ntdll/unix/env.c
 * init_environment) and wineserver reads the lowercase one for
 * memicmp_strW, which is what compares a registry key name
 * (server/unicode.c). The two tables induce the same partition of the BMP,
 * so equality cannot tell them apart; ordering can, and ntdll's own
 * RtlCompareUnicodeString uses the uppercase one.
 *
 * The cases below are chosen so that an implementation which "upcases with
 * Unicode's simple uppercase mapping" — the obvious thing to write, and the
 * wrong thing — fails. The NLS table is NOT that mapping:
 *
 *   U+03C2 GREEK SMALL LETTER FINAL SIGMA folds to ITSELF, while U+03C3
 *          folds to U+03A3. Unicode's simple uppercase of both is U+03A3.
 *   U+0131 LATIN SMALL LETTER DOTLESS I folds to itself, not to 'I'.
 *   U+01C5 (the title-case digraph) folds to itself, not to U+01C4, while
 *          U+01C6 does fold to U+01C4.
 *
 * Names are spelled as hex escapes, the way Wine's own test spells them, so
 * the CODE UNITS are what the source says — a UTF-8 literal would hide the
 * surrogate pair that half this file is about. The ASCII tail is a separate
 * concatenated literal because a hex escape does not stop at four digits.
 *
 * The FILE-name half of the same authority is sem_file/name_case_fold.c —
 * one fold, two consumers (Art. 11).
 *
 * Oracle-first (G5).
 */
#include "util.h"

static const void *base_path = W("\\Registry\\Machine\\Software\\prsk_m8_case_fold");

/* Does a key created as `created` come back when opened as `probe`? That is
 * the fold, observed through the one thing a caller can see. */
static int same_key(HANDLE base, const void *created, const void *probe)
{
    HANDLE key = NULL;
    NTSTATUS status;
    int found;

    reg_delete_sub(base, created);
    reg_delete_sub(base, probe);
    status = reg_create_sub(base, created, &key, NULL);
    ok(status == STATUS_SUCCESS, "create the fold fixture -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return -1;
    NtClose(key);

    {
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        init_ustr(&name, probe);
        init_attr(&attr, base, &name, OBJ_CASE_INSENSITIVE);
        key = NULL;
        status = NtOpenKey(&key, KEY_ALL_ACCESS, &attr);
    }
    found = NT_SUCCESS(status);
    if (found)
        NtClose(key);
    reg_delete_sub(base, created);
    return found;
}

START_TEST(key_name_fold)
{
    HANDLE base = NULL;
    NTSTATUS status;

    reg_ensure_software();
    reg_delete_path(base_path);
    status = reg_create_path(base_path, &base, NULL);
    ok(status == STATUS_SUCCESS, "create the fold base -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* --- controls: the two ranges proskrnl already folded ---------------- */
    ok(same_key(base, W("fold"), W("FOLD")) == 1, "ASCII does not fold");
    ok(same_key(base, W("\x00e9") W("fold"), W("\x00c9") W("FOLD")) == 1,
       "U+00E9 does not fold to U+00C9");

    /* --- beyond Latin-1, which is what ntdll:reg asks for ---------------- */
    ok(same_key(base, W("\x014d") W("fold"), W("\x014c") W("FOLD")) == 1,
       "U+014D does not fold to U+014C");
    ok(same_key(base, W("\x0371") W("fold"), W("\x0370") W("FOLD")) == 1,
       "U+0371 does not fold to U+0370");
    ok(same_key(base, W("\x0430") W("fold"), W("\x0410") W("FOLD")) == 1,
       "U+0430 does not fold to U+0410");
    /* Not an alphabet case at all: the fullwidth forms fold, and so do the
     * Roman-numeral letterforms. Both are table entries a rule about
     * alphabets would miss. */
    ok(same_key(base, W("\xff41") W("fold"), W("\xff21") W("FOLD")) == 1,
       "U+FF41 does not fold to U+FF21");
    ok(same_key(base, W("\x2170") W("fold"), W("\x2160") W("FOLD")) == 1,
       "U+2170 does not fold to U+2160");

    /* --- the whole winetest name, in one piece (reg.c:346/:353) ---------- */
    ok(same_key(base, W("\x00f6\x00f3\x014d\x0371\xd801\xdc00"),
                W("\x00d6\x00d3\x014c\x0370\xd801\xdc00")) == 1,
       "the ntdll:reg fold name does not match its upper-case form");

    /* --- and the surrogate, which must NOT fold (reg.c:350) --------------
     * U+10400 and U+10428 are an upper/lower pair as CODE POINTS. The fold
     * is per code UNIT, so the low surrogates U+DC00 and U+DC28 are two
     * unrelated units and these are two different keys. An implementation
     * that decoded surrogate pairs before folding — the "more correct" thing
     * to do — fails exactly here and nowhere else. */
    ok(same_key(base, W("\x00f6\x00f3\x014d\x0371\xd801\xdc00"),
                W("\x00d6\x00d3\x014c\x0370\xd801\xdc28")) == 0,
       "the astral pair folded: the fold is not per code unit");

    /* --- three places the NLS table is NOT Unicode's simple uppercase ---- */
    ok(same_key(base, W("\x03c3") W("fold"), W("\x03a3") W("FOLD")) == 1,
       "U+03C3 does not fold to U+03A3");
    ok(same_key(base, W("\x03c2") W("fold"), W("\x03a3") W("FOLD")) == 0,
       "final sigma folded to U+03A3; the table folds it to itself");
    ok(same_key(base, W("\x03c2") W("fold"), W("\x03c2") W("FOLD")) == 1,
       "U+03C2 does not match itself");
    ok(same_key(base, W("\x0131") W("fold"), W("ifold")) == 0, "dotless i folded onto ASCII i");
    ok(same_key(base, W("\x0131") W("fold"), W("\x0131") W("FOLD")) == 1,
       "U+0131 does not match itself");
    ok(same_key(base, W("\x01c6") W("fold"), W("\x01c4") W("FOLD")) == 1,
       "U+01C6 does not fold to U+01C4");
    ok(same_key(base, W("\x01c5") W("fold"), W("\x01c4") W("FOLD")) == 0,
       "the title-case digraph folded to U+01C4; the table folds it to itself");

    reg_delete_path(base_path);
    NtClose(base);
}
