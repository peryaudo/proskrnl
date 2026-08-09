/*
 * sem_reg/root_case.c — the registry namespace is case-insensitive whatever
 * the caller's OBJECT_ATTRIBUTES say.
 *
 * Two halves of one path resolve a registry name, and only one of them is
 * Cm's: the "\Registry" component is an OBJECT-MANAGER name, resolved by the
 * Ob walk, and everything after it is a Cm subkey. Ob honours
 * OBJ_CASE_INSENSITIVE; Cm's subkey compare is unconditionally
 * case-insensitive. So a caller passing Attributes = 0 is asking for a
 * case-SENSITIVE match on exactly one component of the path.
 *
 * The oracle answers such a caller case-insensitively anyway, because
 * ntdll's own registry entry points OR the flag in before the request
 * leaves: dlls/ntdll/unix/registry.c NtCreateKey does
 * `objattr->attributes |= OBJ_OPENIF | OBJ_CASE_INSENSITIVE` and NtOpenKeyEx
 * does `attributes = attr->Attributes | OBJ_CASE_INSENSITIVE`. That is the
 * half proskrnl replaces at the unixlib seam, so on proskrnl the forcing has
 * to live below it — the observable rule is the oracle's either way, and it
 * agrees with what ntdll:reg measures on Windows 10 1607+ (reg.c:541-:558:
 * "\Registry\..." with Attributes = 0 succeeds there, and "\REGISTRY\..."
 * and "\REGISTRY\MACHINE\SOFTWARE\CLASSES" succeed on every version).
 *
 * The negative controls matter as much as the positives: folding case must
 * not make an ABSENT name present, and must not stop a non-key object from
 * type-checking. Each case is run with Attributes = 0 and again with
 * OBJ_CASE_INSENSITIVE, because an implementation that folds only when asked
 * passes every one of the second set.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtOpenKeyEx(PHANDLE, ACCESS_MASK, const OBJECT_ATTRIBUTES *, ULONG);

static const void *sub_key_path = W("\\Registry\\Machine\\Software\\prsk_m8_RootCase");
static const void *sub_key_leaf = W("prsk_m8_RootCase");

/* Open <path> with exactly <flags> in OBJECT_ATTRIBUTES.Attributes. */
static NTSTATUS open_with_flags(const void *path, ULONG flags, HANDLE *out)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    init_ustr(&name, path);
    init_attr(&attr, NULL, &name, flags);
    *out = NULL;
    return NtOpenKey(out, KEY_READ, &attr);
}

/* Create <path> with exactly <flags>. */
static NTSTATUS create_with_flags(const void *path, ULONG flags, HANDLE *out)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    init_ustr(&name, path);
    init_attr(&attr, NULL, &name, flags);
    *out = NULL;
    return NtCreateKey(out, KEY_READ, &attr, 0, NULL, 0, NULL);
}

static const ULONG root_case_flag_sets[2] = {0, OBJ_CASE_INSENSITIVE};

/* <path> must answer <want> on OPEN with Attributes = 0 and again with
 * OBJ_CASE_INSENSITIVE — an implementation that folds only when asked passes
 * the second and fails the first. */
static void expect_open_both_ways(const void *path, NTSTATUS want, const char *label)
{
    unsigned i;

    for (i = 0; i < 2; i++)
    {
        HANDLE key = NULL;
        NTSTATUS status = open_with_flags(path, root_case_flag_sets[i], &key);
        ok(status == want, "%s: NtOpenKey attributes %08lx -> %08lx, wanted %08lx", label,
           (unsigned long)root_case_flag_sets[i], (unsigned long)status, (unsigned long)want);
        if (NT_SUCCESS(status))
            NtClose(key);
    }
}

/* The same over NtCreateKey as well. Only for paths whose last component
 * either exists or is not creatable: NtCreateKey CREATES a missing leaf, so
 * an absent-name control must use expect_open_both_ways instead — the oracle
 * refuted the first draft of this test, where a create under \REGISTRY made
 * the name the next open was supposed to miss. */
static void expect_both_ways(const void *path, NTSTATUS want, const char *label)
{
    unsigned i;

    expect_open_both_ways(path, want, label);
    for (i = 0; i < 2; i++)
    {
        HANDLE key = NULL;
        NTSTATUS status = create_with_flags(path, root_case_flag_sets[i], &key);
        ok(status == want, "%s: NtCreateKey attributes %08lx -> %08lx, wanted %08lx", label,
           (unsigned long)root_case_flag_sets[i], (unsigned long)status, (unsigned long)want);
        if (NT_SUCCESS(status))
            NtClose(key);
    }
}

START_TEST(root_case)
{
    HANDLE key = NULL;
    NTSTATUS status;

    reg_ensure_software();
    reg_delete_path(sub_key_path);

    /* --- the root component, spelled three ways ------------------------- */

    /* "\Registry" itself, and the two case variants of it that ntdll:reg
     * measures. All three name the same object. */
    expect_both_ways(W("\\Registry"), STATUS_SUCCESS, "root as created");
    expect_both_ways(W("\\REGISTRY"), STATUS_SUCCESS, "root upper");
    expect_both_ways(W("\\registry"), STATUS_SUCCESS, "root lower");

    /* The same, with a Cm remainder behind it: the Ob half folds and the Cm
     * half was always folding, so every mixture resolves. \Registry\Machine
     * exists on any real registry. */
    expect_both_ways(W("\\Registry\\Machine"), STATUS_SUCCESS, "machine as created");
    expect_both_ways(W("\\REGISTRY\\Machine"), STATUS_SUCCESS, "machine, root upper");
    expect_both_ways(W("\\REGISTRY\\MACHINE"), STATUS_SUCCESS, "machine, both upper");
    expect_both_ways(W("\\registry\\machine"), STATUS_SUCCESS, "machine, both lower");

    /* --- a mixed-case key created by this test -------------------------- */

    /* Created with one casing, reachable through every other — including
     * from a case-sensitive caller. The leaf is deliberately MixedCase so a
     * kernel that compared the stored spelling byte-for-byte fails here and
     * not only on the built-in names above. */
    status = reg_create_path(sub_key_path, &key, NULL);
    ok(status == STATUS_SUCCESS, "create mixed-case subkey -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(key);

    expect_both_ways(W("\\REGISTRY\\MACHINE\\SOFTWARE\\PRSK_M8_ROOTCASE"), STATUS_SUCCESS,
                     "subkey all upper");
    expect_both_ways(W("\\registry\\machine\\software\\prsk_m8_rootcase"), STATUS_SUCCESS,
                     "subkey all lower");

    /* Relative to a handle, the root component is not in the name at all,
     * and the Cm half still folds. */
    {
        HANDLE software = NULL;
        status = reg_open_path(W("\\Registry\\Machine\\Software"), &software);
        ok(status == STATUS_SUCCESS, "open Software -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            UNICODE_STRING name;
            OBJECT_ATTRIBUTES attr;
            HANDLE sub = NULL;

            init_ustr(&name, W("PRSK_M8_ROOTCASE"));
            init_attr(&attr, software, &name, 0);
            status = NtOpenKey(&sub, KEY_READ, &attr);
            ok(status == STATUS_SUCCESS, "relative open, upper, attributes 0 -> %08lx",
               (unsigned long)status);
            if (NT_SUCCESS(status))
                NtClose(sub);

            /* NtOpenKeyEx takes the same attributes; its options word is
             * ignored (ntdll passes only the attributes to the server). */
            sub = NULL;
            init_ustr(&name, sub_key_leaf);
            init_attr(&attr, software, &name, 0);
            status = NtOpenKeyEx(&sub, KEY_READ, &attr, 0);
            ok(status == STATUS_SUCCESS, "relative NtOpenKeyEx, attributes 0 -> %08lx",
               (unsigned long)status);
            if (NT_SUCCESS(status))
                NtClose(sub);

            NtClose(software);
        }
    }

    /* --- the negative controls ------------------------------------------ */

    /* An absent LAST component is a missing name; an absent INTERMEDIATE one
     * is a missing path. Folding case must not turn either into a hit — a
     * kernel that answered "found" for anything under a folded root would
     * pass every assertion above and fail these two. (ntdll:reg pins the
     * same pair at reg.c:508/:513 for "\Foobar" and "\Foobar\Machine".) */
    expect_both_ways(W("\\prsk_m8_no_such_root"), STATUS_OBJECT_NAME_NOT_FOUND, "absent leaf root");
    expect_both_ways(W("\\prsk_m8_no_such_root\\Machine"), STATUS_OBJECT_PATH_NOT_FOUND,
                     "absent root, path continues");

    /* A root that exists but is NOT a key still type-checks, in either
     * spelling: the fold decides WHICH object is named, never what it is. */
    expect_both_ways(W("\\Device\\Null"), STATUS_OBJECT_TYPE_MISMATCH, "non-key object");
    expect_both_ways(W("\\DEVICE\\NULL"), STATUS_OBJECT_TYPE_MISMATCH, "non-key object, upper");

    /* A missing hive-level name under the FOLDED root: the fold decides which
     * object \REGISTRY names, and the miss below it is still a miss. Open
     * only — NtCreateKey would create it, which the oracle demonstrated when
     * this case was first written with expect_both_ways. */
    expect_open_both_ways(W("\\REGISTRY\\prsk_m8_no_such_hive"), STATUS_OBJECT_NAME_NOT_FOUND,
                          "absent hive under a folded root");

    reg_delete_path(sub_key_path);
}
