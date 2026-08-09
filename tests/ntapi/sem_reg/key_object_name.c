/*
 * sem_reg/key_object_name.c — what NtQueryObject says about a KEY handle.
 *
 * A registry key is reachable two ways and they must agree: NtQueryKey's
 * KeyNameInformation and NtQueryObject's ObjectNameInformation report the same
 * full path, because on the oracle a key IS an object-manager object and the
 * generic name walk is what answers both (wine server/registry.c
 * `key_ops.get_full_name = key_get_full_name`, which for a live key defers to
 * default_get_full_name — the same walk every other named object uses).
 *
 * The one thing the key type adds to that walk is a refusal:
 *
 *     static WCHAR *key_get_full_name( struct object *obj, ... )
 *     {
 *         if (key->flags & KEY_DELETED) { set_error( STATUS_KEY_DELETED ); return NULL; }
 *         return default_get_full_name( obj, max, ret_len );
 *     }
 *
 * A deleted key has no path — it is no longer anywhere — so the NAME query
 * fails while the queries that do not need a path keep working. That
 * asymmetry is the pinnable part: ObjectBasicInformation and
 * ObjectTypeInformation answer from the HANDLE and the TYPE, neither of which
 * the delete destroyed, and ntdll:reg measures exactly that pair at
 * reg.c:854/:857.
 *
 * Why this needs a test of its own rather than falling out of the delete
 * suite: an implementation that has no name for a key at all reports SUCCESS
 * with an empty UNICODE_STRING, which satisfies "the query works" and is a
 * fabricated answer (Art. 12) — a caller told a named object is nameless
 * cannot tell two keys apart. So the live case is pinned as hard as the
 * deleted one.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryObject(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

/* As sem_reg/key_info_classes.c spells it (KEY_INFORMATION_CLASS's order). */
#define KEY_NAME_INFO_CLASS 3 /* KeyNameInformation */

static const void *base_path = W("\\Registry\\Machine\\Software\\prsk_m8_keyname");
static const void *leaf_path = W("\\Registry\\Machine\\Software\\prsk_m8_keyname\\Leaf");

/* Case-insensitive comparison of a reported UNICODE_STRING against a wide
 * literal. The two runners are allowed to differ in the CASE they store the
 * built-in hive names in ("\REGISTRY\Machine" on the oracle), and case is not
 * what this test is about — sem_reg/root_case.c is. */
static int name_matches(const UNICODE_STRING *reported, const void *wanted)
{
    const unsigned short *want = (const unsigned short *)wanted;
    unsigned want_units = 0, i;

    while (want[want_units])
        want_units++;
    if (reported->Length != want_units * sizeof(WCHAR))
        return 0;
    for (i = 0; i < want_units; i++)
    {
        WCHAR a = reported->Buffer[i], b = (WCHAR)want[i];
        if (a >= 'A' && a <= 'Z')
            a = (WCHAR)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z')
            b = (WCHAR)(b - 'A' + 'a');
        if (a != b)
            return 0;
    }
    return 1;
}

START_TEST(key_object_name)
{
    HANDLE base = NULL, leaf = NULL;
    NTSTATUS status;
    BYTE raw[1024];
    ULONG used;

    reg_ensure_software();
    reg_delete_path(leaf_path);
    reg_delete_path(base_path);

    status = reg_create_path(base_path, &base, NULL);
    ok(status == STATUS_SUCCESS, "create base -> %08lx", (unsigned long)status);
    status = reg_create_path(leaf_path, &leaf, NULL);
    ok(status == STATUS_SUCCESS, "create leaf -> %08lx", (unsigned long)status);

    /* --- a live key reports its FULL path ------------------------------- */

    memset(raw, 0, sizeof(raw));
    used = 0;
    status = NtQueryObject(leaf, ObjectNameInformation, raw, sizeof(raw), &used);
    ok(status == STATUS_SUCCESS, "live ObjectNameInformation -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        UNICODE_STRING *reported = (UNICODE_STRING *)raw;
        ok(name_matches(reported, leaf_path), "live name is the full path, got %u bytes",
           (unsigned)reported->Length);
        /* The reported buffer is NUL-terminated behind Length, and
         * ReturnLength covers the struct, the name and that terminator. */
        ok(used == sizeof(UNICODE_STRING) + reported->Length + sizeof(WCHAR),
           "ReturnLength %lu for a %u-byte name", (unsigned long)used, (unsigned)reported->Length);
        ok(reported->Length < sizeof(raw) &&
               reported->Buffer[reported->Length / sizeof(WCHAR)] == 0,
           "reported name is NUL-terminated");
    }

    /* The two spellings of the same question agree. KeyNameInformation is
     * NtQueryKey's; both walk to the root. */
    {
        BYTE key_raw[1024];
        ULONG key_used = 0;
        /* KEY_NAME_INFORMATION: ULONG NameLength; WCHAR Name[1]; */
        ULONG name_length;

        memset(key_raw, 0, sizeof(key_raw));
        status = NtQueryKey(leaf, KEY_NAME_INFO_CLASS, key_raw, sizeof(key_raw), &key_used);
        ok(status == STATUS_SUCCESS, "live KeyNameInformation -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            UNICODE_STRING as_string;
            name_length = *(ULONG *)key_raw;
            as_string.Length = (USHORT)name_length;
            as_string.MaximumLength = as_string.Length;
            as_string.Buffer = (PWSTR)(key_raw + sizeof(ULONG));
            ok(name_matches(&as_string, leaf_path),
               "KeyNameInformation is the full path too, %lu bytes", (unsigned long)name_length);
        }
    }

    /* A parent reports the parent's path, so the walk is per-key and not one
     * cached string. */
    memset(raw, 0, sizeof(raw));
    status = NtQueryObject(base, ObjectNameInformation, raw, sizeof(raw), &used);
    ok(status == STATUS_SUCCESS, "base ObjectNameInformation -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        ok(name_matches((UNICODE_STRING *)raw, base_path), "base name is the base path");

    /* --- deleting the key takes its NAME away and nothing else ---------- */

    status = NtDeleteKey(leaf);
    ok(status == STATUS_SUCCESS, "delete leaf -> %08lx", (unsigned long)status);

    memset(raw, 0, sizeof(raw));
    used = 0;
    status = NtQueryObject(leaf, ObjectNameInformation, raw, sizeof(raw), &used);
    ok(status == STATUS_KEY_DELETED, "deleted ObjectNameInformation -> %08lx",
       (unsigned long)status);

    /* The refusal comes BEFORE the buffer-size protocol: a deleted key has no
     * path, so no buffer is big enough and none is too small. An
     * implementation that sized first would answer the length error here and
     * pass every assertion above. */
    used = 0;
    status = NtQueryObject(leaf, ObjectNameInformation, raw, 0, &used);
    ok(status == STATUS_KEY_DELETED, "deleted name query, zero-length buffer -> %08lx",
       (unsigned long)status);

    {
        OBJECT_BASIC_INFORMATION obi;
        memset(&obi, 0, sizeof(obi));
        status = NtQueryObject(leaf, ObjectBasicInformation, &obi, sizeof(obi), NULL);
        ok(status == STATUS_SUCCESS, "deleted ObjectBasicInformation -> %08lx",
           (unsigned long)status);
    }

    /* The TYPE survives the delete as well: the refusal is about the path. */
    memset(raw, 0, sizeof(raw));
    status = NtQueryObject(leaf, ObjectTypeInformation, raw, sizeof(raw), &used);
    ok(status == STATUS_SUCCESS, "deleted ObjectTypeInformation -> %08lx", (unsigned long)status);

    /* And NtQueryKey's own name class refuses with the same status, which is
     * the pre-existing rule this one has to agree with. */
    status = NtQueryKey(leaf, KEY_NAME_INFO_CLASS, raw, sizeof(raw), &used);
    ok(status == STATUS_KEY_DELETED, "deleted KeyNameInformation -> %08lx", (unsigned long)status);

    NtClose(leaf);

    /* The parent is untouched by its child's delete. */
    memset(raw, 0, sizeof(raw));
    status = NtQueryObject(base, ObjectNameInformation, raw, sizeof(raw), &used);
    ok(status == STATUS_SUCCESS, "base name after child delete -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        ok(name_matches((UNICODE_STRING *)raw, base_path), "base name unchanged");

    status = NtDeleteKey(base);
    ok(status == STATUS_SUCCESS, "delete base -> %08lx", (unsigned long)status);
    NtClose(base);
}
