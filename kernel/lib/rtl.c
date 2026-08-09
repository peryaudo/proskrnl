/* kernel/lib/rtl.c — counted UTF-16 string helpers (M3). See rtl.h. */
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/lib/upcase.h"
#include "kernel/init/panic.h"

void RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source)
{
    target->Buffer = (PWSTR)source;
    if (source == 0)
    {
        target->Length = 0;
        target->MaximumLength = 0;
        return;
    }
    ULONG length = (ULONG)KiWideStringLength(source);
    ASSERT(length * sizeof(WCHAR) <= 0xFFFF - sizeof(WCHAR));
    target->Length = (USHORT)(length * sizeof(WCHAR));
    target->MaximumLength = (USHORT)(target->Length + sizeof(WCHAR));
}

/* The NLS three-level trie lookup, exactly as both halves of the oracle
 * spell it (Wine's PE ntdll `casemap()`, dlls/ntdll/locale.c; wineserver's
 * `to_upper()`, server/unicode.c). Each level indexes the same table and the
 * leaf holds a DELTA rather than the folded unit, which is why a lookup for a
 * character with no case is free: its delta is zero.
 *
 * THE FOLD IS PER CODE UNIT, NOT PER CODE POINT, and that is a contract
 * rather than a shortcut. ntdll:reg (reg.c:350) creates a key whose name
 * ends in the surrogate pair U+D801 U+DC00 and requires that the SAME pair
 * with its low half swapped for U+DC28 — the other case of the same astral
 * code point, U+10400/U+10428 — not match it. Decoding the pair first would
 * be the "more correct" thing to do and would fail exactly that assertion.
 *
 * The table itself is generated from the pinned tree's own nls/l_intl.nls
 * (tools/gen_upcase.py; Art. 4 / G4 — 1433 constants nobody types by hand),
 * so this cannot drift from the oracle it is measured against. It replaced a
 * hand-written rule that reached ASCII and then, once, the Latin-1
 * Supplement; docs/03 "Name case folding" carries the history and what is
 * still unmodelled (upcase only; no downcase, no OEM code page).
 *
 * Pinned by tests/ntapi/sem_reg/key_name_fold.c (registry key names, the
 * consumer that convicted the rule) and sem_file/name_case_fold.c (file
 * names and the enumeration ORDER the fold decides). */
WCHAR RtlUpcaseUnicodeChar(WCHAR c)
{
    USHORT level1 = RtlpUpcaseTable[c >> 8];
    USHORT level2 = RtlpUpcaseTable[level1 + ((c >> 4) & 0x0F)];
    return (WCHAR)(c + RtlpUpcaseTable[level2 + (c & 0x0F)]);
}

BOOLEAN RtlEqualUnicodeString(const UNICODE_STRING *s1, const UNICODE_STRING *s2,
                              BOOLEAN caseInsensitive)
{
    if (s1->Length != s2->Length)
    {
        return FALSE;
    }
    ULONG count = s1->Length / sizeof(WCHAR);
    for (ULONG i = 0; i < count; i++)
    {
        WCHAR c1 = s1->Buffer[i];
        WCHAR c2 = s2->Buffer[i];
        if (caseInsensitive)
        {
            c1 = RtlUpcaseUnicodeChar(c1);
            c2 = RtlUpcaseUnicodeChar(c2);
        }
        if (c1 != c2)
        {
            return FALSE;
        }
    }
    return TRUE;
}

/* Ordering compare (M8: Cm keeps subkeys/values sorted). Signature per
 * wine/include/winternl.h; semantics as wine's own: char-by-char difference,
 * then the length difference. */
LONG RtlCompareUnicodeString(const UNICODE_STRING *s1, const UNICODE_STRING *s2,
                             BOOLEAN caseInsensitive)
{
    ULONG count1 = s1->Length / sizeof(WCHAR);
    ULONG count2 = s2->Length / sizeof(WCHAR);
    ULONG count = count1 < count2 ? count1 : count2;
    for (ULONG i = 0; i < count; i++)
    {
        WCHAR c1 = s1->Buffer[i];
        WCHAR c2 = s2->Buffer[i];
        if (caseInsensitive)
        {
            c1 = RtlUpcaseUnicodeChar(c1);
            c2 = RtlUpcaseUnicodeChar(c2);
        }
        if (c1 != c2)
        {
            return (LONG)c1 - (LONG)c2;
        }
    }
    return (LONG)(s1->Length) - (LONG)(s2->Length);
}

void RtlCopyUnicodeString(UNICODE_STRING *target, const UNICODE_STRING *source)
{
    if (source == 0)
    {
        target->Length = 0;
        return;
    }
    USHORT length = source->Length;
    if (length > target->MaximumLength)
    {
        length = target->MaximumLength;
    }
    memcpy(target->Buffer, source->Buffer, length);
    target->Length = length;
    /* Append the terminator when there is room, exactly as the oracle does
     * (third_party/wine dlls/ntdll/rtlstr.c RtlCopyUnicodeString:
     * `if (len < dst->MaximumLength) dst->Buffer[len / sizeof(WCHAR)] = 0;`).
     * Not terminating was latent -- only a test called this -- but this is
     * the shared authority other departments reach for, and one of them
     * (kernel/ob/handle.c) had already hand-rolled its own terminator
     * instead (docs/review-2026-07 §9). */
    if (length < target->MaximumLength)
    {
        target->Buffer[length / sizeof(WCHAR)] = 0;
    }
}

/* Is `name` already a legal DOS 8.3 name? The ONE authority for that
 * question (Art. 11): the directory-enumeration classes suppress the
 * ShortName field on it, and nothing else may re-decide it.
 *
 * It is NOT the same question fs/fat32's FatBuildExact83 answers. That one
 * asks "can this be STORED as a bare 8.3 directory entry", and rejects
 * lower case because FAT would lose it — a fact about the disk. This one
 * asks whether the name IS an 8.3 name, and lower case does not stop it
 * being one. MEASURED on the oracle, which reports no short name at all for
 * `lower.txt` (tests/ntapi/sem_file/short_names.c pins it, and it is the
 * assertion that separates the two rules). Keeping them as two functions
 * is deliberate; merging them would make one of the two answers wrong.
 *
 * The shape is Microsoft's documented 8.3 rule: at most 8 units of base and
 * 3 of extension, at most one dot, no empty base, and none of the
 * characters the FAT specification (§6.1) reserves for structure or for
 * long-name syntax. Non-ASCII is treated as illegal here — NT's answer
 * depends on the OEM code page, which proskrnl does not carry (docs/03
 * "Name case folding"), and refusing is the side that costs only a
 * redundant ShortName rather than a missing one.
 *
 * NT's signature carries an OEM_STRING out-param and a spaces flag; both
 * are accepted as NULL and only the NULL form is used here, so no caller
 * depends on behaviour that is not built (Art. 12). */
BOOLEAN RtlIsNameLegalDOS8Dot3(const UNICODE_STRING *name, POEM_STRING oemName,
                               PBOOLEAN spacesFound)
{
    /* Reserved by the FAT spec §6.1 for structure, plus the long-name
     * syntax characters. Cross-check against that section, not memory. */
    static const char illegal[] = "\"*+,/:;<=>?[\\]|";
    ULONG units = name != 0 ? name->Length / sizeof(WCHAR) : 0;
    ULONG base = 0, ext = 0;
    BOOLEAN sawDot = FALSE;

    if (oemName != 0 || spacesFound != 0)
    {
        /* Unbuilt rather than silently wrong: no caller wants these yet,
         * and inventing an answer is the shape Art. 12 forbids. */
        ASSERT(oemName == 0 && spacesFound == 0);
    }
    if (name == 0 || name->Buffer == 0 || units == 0)
    {
        return FALSE;
    }
    /* "." and ".." are legal, and are the reason the loop below cannot
     * simply reject an empty base (FAT spec §6.1). */
    if ((units == 1 && name->Buffer[0] == '.') ||
        (units == 2 && name->Buffer[0] == '.' && name->Buffer[1] == '.'))
    {
        return TRUE;
    }
    for (ULONG i = 0; i < units; i++)
    {
        WCHAR c = name->Buffer[i];
        if (c == '.')
        {
            if (sawDot || base == 0)
            {
                return FALSE; /* a second dot, or a leading one */
            }
            sawDot = TRUE;
            continue;
        }
        if (c < 0x20 || c > 0x7E)
        {
            return FALSE;
        }
        if (c == ' ')
        {
            /* A space makes the name illegal outright. NT's signature also
             * REPORTS one through `spacesFound`, but that out-param is
             * unbuilt here (asserted NULL above), so there is nothing to
             * record it in — a local flag written and never read would be
             * that unbuilt half pretending to exist. */
            return FALSE;
        }
        for (const char *p = illegal; *p != 0; p++)
        {
            if ((WCHAR)*p == c)
            {
                return FALSE;
            }
        }
        if (sawDot)
        {
            ext++;
        }
        else
        {
            base++;
        }
    }
    if (base == 0 || base > 8 || ext > 3)
    {
        return FALSE;
    }
    return !sawDot || ext != 0;
}
