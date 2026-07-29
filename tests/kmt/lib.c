/* tests/kmt/lib.c — unit tests for kernel/lib (docs/08).
 *
 * The pure library code — LIST_ENTRY primitives, the NUL-terminated string
 * primitives, the Rtl string slice, the mem* intrinsics, the unaligned
 * little-endian accessors — is load-bearing under every dispatcher list, Ob
 * name, boot cmdline and on-disk record, but only ever exercised indirectly
 * by its consumers. These are plain single-threaded unit tests; no waiting,
 * no allocation, caller-owned storage throughout.
 *
 * Deliberately absent: negative tests for the list corruption ASSERTs
 * (double-remove, scribbled links). ASSERT panics the kernel and there is no
 * panic-recovery machinery; the firing assert is itself the diagnostic.
 */
#include "tests/kmt/kmt.h"
#include "kernel/lib/le.h"
#include "kernel/lib/list.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"

/* --- LIST_ENTRY primitives ----------------------------------------------- */

static void test_list_init(void)
{
    LIST_ENTRY head;
    InitializeListHead(&head);
    ok(IsListEmpty(&head), "fresh list not empty");
    ok(head.Flink == &head, "Flink does not point at head");
    ok(head.Blink == &head, "Blink does not point at head");
}

/* Walk the list forward and check it visits exactly `expected[0..count)`. */
static void expect_order(PLIST_ENTRY head, PLIST_ENTRY *expected, int count)
{
    PLIST_ENTRY cursor = head->Flink;
    for (int i = 0; i < count; i++)
    {
        ok(cursor == expected[i], "forward walk position %d wrong", i);
        cursor = cursor->Flink;
    }
    ok(cursor == head, "forward walk does not return to head");
    /* The backward walk must mirror it. */
    cursor = head->Blink;
    for (int i = count - 1; i >= 0; i--)
    {
        ok(cursor == expected[i], "backward walk position %d wrong", i);
        cursor = cursor->Blink;
    }
    ok(cursor == head, "backward walk does not return to head");
}

static void test_list_insert_tail(void)
{
    LIST_ENTRY head, a, b, c;
    InitializeListHead(&head);
    InsertTailList(&head, &a);
    InsertTailList(&head, &b);
    InsertTailList(&head, &c);
    ok(!IsListEmpty(&head), "list with entries reads empty");
    PLIST_ENTRY expected[] = {&a, &b, &c};
    expect_order(&head, expected, 3);
}

static void test_list_insert_head(void)
{
    LIST_ENTRY head, a, b, c;
    InitializeListHead(&head);
    InsertHeadList(&head, &a);
    InsertHeadList(&head, &b);
    InsertHeadList(&head, &c);
    PLIST_ENTRY expected[] = {&c, &b, &a};
    expect_order(&head, expected, 3);
}

static void test_list_mixed_insert(void)
{
    LIST_ENTRY head, a, b, c;
    InitializeListHead(&head);
    InsertTailList(&head, &a);
    InsertHeadList(&head, &b);
    InsertTailList(&head, &c);
    PLIST_ENTRY expected[] = {&b, &a, &c};
    expect_order(&head, expected, 3);
}

static void test_list_remove_entry(void)
{
    LIST_ENTRY head, a, b, c;
    InitializeListHead(&head);
    InsertTailList(&head, &a);
    InsertTailList(&head, &b);
    InsertTailList(&head, &c);

    ok(!RemoveEntryList(&b), "middle remove claims list became empty");
    PLIST_ENTRY expected[] = {&a, &c};
    expect_order(&head, expected, 2);

    ok(!RemoveEntryList(&a), "remove with one entry left claims empty");
    ok(RemoveEntryList(&c), "removing the last entry does not report empty");
    ok(IsListEmpty(&head), "list not empty after removing everything");
}

static void test_list_remove_head(void)
{
    LIST_ENTRY head, a, b, c;
    InitializeListHead(&head);
    InsertTailList(&head, &a);
    InsertTailList(&head, &b);
    InsertTailList(&head, &c);
    /* Tail-insert + head-remove is FIFO — the queue every waiter list uses. */
    ok(RemoveHeadList(&head) == &a, "first dequeue not FIFO");
    ok(RemoveHeadList(&head) == &b, "second dequeue not FIFO");
    ok(RemoveHeadList(&head) == &c, "third dequeue not FIFO");
    ok(IsListEmpty(&head), "list not empty after dequeuing everything");
}

static void test_list_reinsert(void)
{
    LIST_ENTRY head, a, b;
    InitializeListHead(&head);
    InsertTailList(&head, &a);
    InsertTailList(&head, &b);
    RemoveEntryList(&a);
    InsertTailList(&head, &a);
    PLIST_ENTRY expected[] = {&b, &a};
    expect_order(&head, expected, 2);
    RemoveEntryList(&a);
    RemoveEntryList(&b);
}

typedef struct
{
    int before; /* payload on both sides so a bad offset is caught */
    LIST_ENTRY entry;
    int after;
} record_test;

static void test_list_containing_record(void)
{
    LIST_ENTRY head;
    record_test first = {11, {0, 0}, 12};
    record_test second = {21, {0, 0}, 22};
    InitializeListHead(&head);
    InsertTailList(&head, &first.entry);
    InsertTailList(&head, &second.entry);

    record_test *found = CONTAINING_RECORD(head.Flink, record_test, entry);
    ok(found == &first, "CONTAINING_RECORD recovered the wrong record");
    ok(found->before == 11 && found->after == 12, "payload scrambled");
    found = CONTAINING_RECORD(found->entry.Flink, record_test, entry);
    ok(found == &second && found->before == 21 && found->after == 22,
       "second record not recovered through the embedded entry");
}

/* --- NUL-terminated string primitives ------------------------------------ */

static void test_string_length(void)
{
    ok(KiStringLength("") == 0, "empty string has nonzero length");
    ok(KiStringLength("a") == 1, "one-character length wrong");
    ok(KiStringLength("expect=av") == 9, "length %lu, want 9",
       (unsigned long)KiStringLength("expect=av"));
    /* The NUL terminates; bytes after it are not counted. */
    static const char embedded[] = {'a', 'b', '\0', 'c', 'd', '\0'};
    ok(KiStringLength(embedded) == 2, "length ran past the first NUL");

    static const WCHAR wide[] = WSTR("abcd");
    ok(KiWideStringLength(wide) == 4, "wide length %lu, want 4",
       (unsigned long)KiWideStringLength(wide));
    ok(KiWideStringLength(WSTR("")) == 0, "empty wide string has nonzero length");
    /* A high code unit is a character, not a terminator. */
    static const WCHAR high[] = {0xFFFE, 0x0041, 0};
    ok(KiWideStringLength(high) == 2, "wide length stopped on a non-zero unit");
}

static void test_string_equals(void)
{
    ok(KiStringEquals("", ""), "two empty strings compare unequal");
    ok(KiStringEquals("m7", "m7"), "identical strings compare unequal");
    ok(!KiStringEquals("m7", "m8"), "differing last character reads equal");
    ok(!KiStringEquals("abc", "abcd"), "prefix reads equal to the longer string");
    ok(!KiStringEquals("abcd", "abc"), "longer string reads equal to its prefix");
    ok(!KiStringEquals("", "a"), "empty reads equal to non-empty");
    ok(!KiStringEquals("a", ""), "non-empty reads equal to empty");
    /* Case-sensitive (string.h): the boot cmdlines and PE export names it
     * compares are case-exact. */
    ok(!KiStringEquals("abi", "ABI"), "case difference ignored");
    /* Distinct storage with the same content still matches — no pointer
     * comparison hiding in there. */
    char copy[] = {'a', 'b', 'i', '\0'};
    ok(KiStringEquals(copy, "abi"), "equal content in distinct storage reads unequal");
}

static void test_string_starts_with(void)
{
    ok(KiStringStartsWith("expect=av", "expect="), "true prefix not matched");
    ok(KiStringStartsWith("expect=", "expect="), "exact match not matched");
    ok(!KiStringStartsWith("expect", "expect="), "prefix longer than the string matched");
    ok(!KiStringStartsWith("initrd", "expect="), "unrelated string matched");
    ok(!KiStringStartsWith("xexpect=", "expect="), "matched at a non-zero offset");
    /* An empty prefix matches anything, including the empty string. */
    ok(KiStringStartsWith("anything", ""), "empty prefix did not match");
    ok(KiStringStartsWith("", ""), "empty prefix did not match the empty string");
    ok(!KiStringStartsWith("", "a"), "non-empty prefix matched the empty string");
    ok(!KiStringStartsWith("EXPECT=av", "expect="), "case difference ignored");
}

/* --- Rtl counted-string helpers ------------------------------------------ */

static void test_rtl_upcase_unicode_char(void)
{
    ok(RtlUpcaseUnicodeChar('a') == 'A', "'a' not upcased");
    ok(RtlUpcaseUnicodeChar('z') == 'Z', "'z' not upcased");
    ok(RtlUpcaseUnicodeChar('m') == 'M', "'m' not upcased");
    ok(RtlUpcaseUnicodeChar('A') == 'A', "an upper-case letter was changed");
    ok(RtlUpcaseUnicodeChar('0') == '0', "a digit was changed");
    /* The boundaries either side of a-z: '`' (0x60) and '{' (0x7B). */
    ok(RtlUpcaseUnicodeChar('`') == '`', "the character below 'a' was folded");
    ok(RtlUpcaseUnicodeChar('{') == '{', "the character above 'z' was folded");
    /* ASCII-only (rtl.h): no upcase table, so nothing above 0x7F moves. */
    ok(RtlUpcaseUnicodeChar(0x00E9) == 0x00E9, "U+00E9 folded despite ASCII-only contract");
    ok(RtlUpcaseUnicodeChar(0x0430) == 0x0430, "U+0430 folded despite ASCII-only contract");
    ok(RtlUpcaseUnicodeChar(0) == 0, "NUL was changed");
}

static void test_rtl_init_unicode_string(void)
{
    UNICODE_STRING str;
    static const WCHAR abc[] = WSTR("abc");

    RtlInitUnicodeString(&str, abc);
    ok(str.Length == 6, "Length %u, want 6 (bytes, no terminator)", str.Length);
    ok(str.MaximumLength == 8, "MaximumLength %u, want 8 (includes terminator)", str.MaximumLength);
    ok(str.Buffer == (PWSTR)abc, "Buffer does not alias the source");

    static const WCHAR empty[] = WSTR("");
    RtlInitUnicodeString(&str, empty);
    ok(str.Length == 0, "empty: Length %u", str.Length);
    ok(str.MaximumLength == 2, "empty: MaximumLength %u", str.MaximumLength);
    ok(str.Buffer == (PWSTR)empty, "empty: Buffer does not alias the source");

    RtlInitUnicodeString(&str, 0);
    ok(str.Length == 0 && str.MaximumLength == 0, "NULL source: lengths not zeroed");
    ok(str.Buffer == 0, "NULL source: Buffer not NULL");
}

static void test_rtl_equal_unicode_string(void)
{
    UNICODE_STRING abc, abd, abcd, upper;
    RtlInitUnicodeString(&abc, WSTR("abc"));
    RtlInitUnicodeString(&abd, WSTR("abd"));
    RtlInitUnicodeString(&abcd, WSTR("abcd"));
    RtlInitUnicodeString(&upper, WSTR("ABC"));

    ok(RtlEqualUnicodeString(&abc, &abc, FALSE), "identical strings not equal");
    ok(!RtlEqualUnicodeString(&abc, &abd, FALSE), "different content reads equal");
    ok(!RtlEqualUnicodeString(&abc, &abcd, FALSE), "prefix reads equal to longer string");
    ok(!RtlEqualUnicodeString(&abc, &upper, FALSE), "case difference ignored when sensitive");
    ok(RtlEqualUnicodeString(&abc, &upper, TRUE), "case-insensitive compare missed a match");

    /* Upcasing is ASCII-only (rtl.h): U+00E9/U+00C9 (é/É) stay distinct even
     * case-insensitively. */
    static const WCHAR e_acute[] = {0x00E9, 0};
    static const WCHAR e_acute_upper[] = {0x00C9, 0};
    UNICODE_STRING lower_accent, upper_accent;
    RtlInitUnicodeString(&lower_accent, e_acute);
    RtlInitUnicodeString(&upper_accent, e_acute_upper);
    ok(!RtlEqualUnicodeString(&lower_accent, &upper_accent, TRUE),
       "non-ASCII upcased despite ASCII-only contract");
}

static void test_rtl_copy_unicode_string(void)
{
    UNICODE_STRING source, target;
    WCHAR buffer[8];
    RtlInitUnicodeString(&source, WSTR("abc"));

    target.Buffer = buffer;
    target.MaximumLength = sizeof(buffer);
    target.Length = 0;
    RtlCopyUnicodeString(&target, &source);
    ok(target.Length == 6, "full copy: Length %u, want 6", target.Length);
    ok(memcmp(buffer, source.Buffer, 6) == 0, "full copy: content differs");

    /* A 2-WCHAR target truncates byte-wise: Length clamps to MaximumLength. */
    target.MaximumLength = 2 * sizeof(WCHAR);
    target.Length = 0;
    RtlCopyUnicodeString(&target, &source);
    ok(target.Length == 4, "truncating copy: Length %u, want 4", target.Length);
    ok(memcmp(buffer, source.Buffer, 4) == 0, "truncating copy: content differs");

    target.Length = 6;
    RtlCopyUnicodeString(&target, 0);
    ok(target.Length == 0, "NULL source: Length not reset");
}

/* --- mem* intrinsics ------------------------------------------------------ */

static void test_memset_bounds(void)
{
    unsigned char buffer[16];
    memset(buffer, 0x5A, sizeof(buffer));
    memset(buffer + 4, 0xA5, 8);
    for (int i = 0; i < 16; i++)
    {
        unsigned char want = (i >= 4 && i < 12) ? 0xA5 : 0x5A;
        ok(buffer[i] == want, "byte %d is %#x, want %#x", i, buffer[i], want);
    }
}

static void test_memcmp_sign(void)
{
    const unsigned char low[] = {1, 2, 3, 4};
    const unsigned char high[] = {1, 2, 9, 4};
    ok(memcmp(low, low, sizeof(low)) == 0, "equal ranges compare nonzero");
    ok(memcmp(low, high, sizeof(low)) < 0, "lesser range does not compare negative");
    ok(memcmp(high, low, sizeof(low)) > 0, "greater range does not compare positive");
    ok(memcmp(low, high, 2) == 0, "equal prefix compares nonzero");
    ok(memcmp(low, high, 0) == 0, "zero-length compare nonzero");
}

static void test_memmove_overlap(void)
{
    /* dst < src (copy runs forward safely). */
    unsigned char buffer[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    memmove(buffer, buffer + 2, 6);
    const unsigned char forward[] = {2, 3, 4, 5, 6, 7, 6, 7};
    ok(memcmp(buffer, forward, 8) == 0, "dst<src overlap corrupted");

    /* dst > src (a forward copy would eat its own input — must copy backward). */
    unsigned char buffer2[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    memmove(buffer2 + 2, buffer2, 6);
    const unsigned char backward[] = {0, 1, 0, 1, 2, 3, 4, 5};
    ok(memcmp(buffer2, backward, 8) == 0, "dst>src overlap corrupted");

    /* Non-overlapping memcpy for completeness. */
    unsigned char from[4] = {9, 8, 7, 6};
    unsigned char to[4] = {0, 0, 0, 0};
    memcpy(to, from, sizeof(from));
    ok(memcmp(to, from, 4) == 0, "memcpy content differs");
}

/* --- unaligned little-endian accessors ------------------------------------ */

/* Every access is deliberately made at an ODD offset into the buffer: an
 * implementation that cast the pointer to a wider type instead of copying
 * would be unaligned there, which is what these accessors exist to avoid
 * (le.h) and what the UBSan build traps on. */
static void test_le_read(void)
{
    static const unsigned char bytes[] = {0xFF, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0xF0,
                                          0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12};
    ok(KiReadLe16(bytes + 1) == 0x1234, "read16 got %#x", KiReadLe16(bytes + 1));
    ok(KiReadLe32(bytes + 1) == 0x56781234u, "read32 got %#x", KiReadLe32(bytes + 1));
    ok(KiReadLe64(bytes + 1) == 0xDEF0123456781234ull, "read64 wrong");
    /* Byte order is little-endian: the lowest address is the low byte. */
    ok(KiReadLe16(bytes + 7) == 0xDEF0, "read16 byte order reversed");
}

static void test_le_write(void)
{
    unsigned char buffer[16];
    memset(buffer, 0xCC, sizeof(buffer));

    KiWriteLe16(buffer + 1, 0x1234);
    ok(buffer[1] == 0x34 && buffer[2] == 0x12, "write16 byte order wrong");
    ok(buffer[0] == 0xCC && buffer[3] == 0xCC, "write16 spilled outside its two bytes");

    KiWriteLe32(buffer + 5, 0x89ABCDEFu);
    ok(buffer[5] == 0xEF && buffer[6] == 0xCD && buffer[7] == 0xAB && buffer[8] == 0x89,
       "write32 byte order wrong");
    ok(buffer[4] == 0xCC && buffer[9] == 0xCC, "write32 spilled outside its four bytes");

    KiWriteLe64(buffer + 1, 0x0123456789ABCDEFull);
    ok(KiReadLe64(buffer + 1) == 0x0123456789ABCDEFull, "write64 does not round-trip");
    ok(buffer[0] == 0xCC && buffer[9] == 0xCC, "write64 spilled outside its eight bytes");
}

int kmt_run_lib(void)
{
    int failures_before = kmt_failures;
    KMT_RUN(test_list_init);
    KMT_RUN(test_list_insert_tail);
    KMT_RUN(test_list_insert_head);
    KMT_RUN(test_list_mixed_insert);
    KMT_RUN(test_list_remove_entry);
    KMT_RUN(test_list_remove_head);
    KMT_RUN(test_list_reinsert);
    KMT_RUN(test_list_containing_record);
    KMT_RUN(test_string_length);
    KMT_RUN(test_string_equals);
    KMT_RUN(test_string_starts_with);
    KMT_RUN(test_rtl_upcase_unicode_char);
    KMT_RUN(test_rtl_init_unicode_string);
    KMT_RUN(test_rtl_equal_unicode_string);
    KMT_RUN(test_rtl_copy_unicode_string);
    KMT_RUN(test_memset_bounds);
    KMT_RUN(test_memcmp_sign);
    KMT_RUN(test_memmove_overlap);
    KMT_RUN(test_le_read);
    KMT_RUN(test_le_write);
    return kmt_failures - failures_before;
}
