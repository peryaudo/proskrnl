/* tests/kmt/lib.c — unit tests for kernel/lib (docs/08).
 *
 * The pure library code — LIST_ENTRY primitives, the Rtl string slice, the
 * mem* intrinsics — is load-bearing under every dispatcher list and Ob name,
 * but until this suite it was only exercised indirectly. These are plain
 * single-threaded unit tests; no waiting, no allocation, caller-owned
 * storage throughout.
 *
 * Deliberately absent: negative tests for the list corruption ASSERTs
 * (double-remove, scribbled links). ASSERT panics the kernel and there is no
 * panic-recovery machinery; the firing assert is itself the diagnostic.
 */
#include "tests/kmt/kmt.h"
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

/* --- Rtl counted-string helpers ------------------------------------------ */

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
    KMT_RUN(test_rtl_init_unicode_string);
    KMT_RUN(test_rtl_equal_unicode_string);
    KMT_RUN(test_rtl_copy_unicode_string);
    KMT_RUN(test_memset_bounds);
    KMT_RUN(test_memcmp_sign);
    KMT_RUN(test_memmove_overlap);
    return kmt_failures - failures_before;
}
