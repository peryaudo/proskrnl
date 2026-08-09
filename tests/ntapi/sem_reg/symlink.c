/*
 * sem_reg/symlink.c — registry symbolic links (REG_OPTION_CREATE_LINK).
 *
 * The consumer is win32u's display-device commit (dlls/win32u/sysparams.c
 * write_source_to_registry): it creates volatile link keys under
 * CurrentControlSet\Control\Video, writes their SymbolicLinkValue, and the
 * read-back path resolves them. The semantics pinned here are the oracle's
 * (wine server/registry.c key_lookup_name / create_key / set_value):
 *
 *   - REG_OPTION_CREATE_LINK creates a link-flagged key; the lookup runs
 *     with OBJ_OPENLINK and WITHOUT OBJ_OPENIF, so creating over an existing
 *     link collides instead of opening it.
 *   - A link key accepts exactly one value: SymbolicLinkValue of type
 *     REG_LINK (an absolute \Registry\... path, no trailing NUL). Anything
 *     else is STATUS_ACCESS_DENIED.
 *   - A lookup that lands on a link key resolves through the value: at the
 *     end of a path (open and create both; create may create a missing
 *     destination) and in the middle (the remainder continues under the
 *     target, which must exist).
 *   - OBJ_OPENLINK in OBJECT_ATTRIBUTES opens the link key itself; that is
 *     also the only way to delete one.
 */
#include "util.h"

#ifndef REG_OPTION_CREATE_LINK
#define REG_OPTION_CREATE_LINK 0x00000002
#endif
#ifndef REG_LINK
#define REG_LINK 6
#endif

static const void *base_path = W("\\Registry\\Machine\\Software\\prsk_m8_symlink");
static const void *target_path = W("\\Registry\\Machine\\Software\\prsk_m8_symlink\\target");
static const void *target_sub_path =
    W("\\Registry\\Machine\\Software\\prsk_m8_symlink\\target\\sub");
static const void *link_path = W("\\Registry\\Machine\\Software\\prsk_m8_symlink\\link");
static const void *through_path = W("\\Registry\\Machine\\Software\\prsk_m8_symlink\\link\\sub");
static const void *dangling_path = W("\\Registry\\Machine\\Software\\prsk_m8_symlink\\dangle");
static const void *dangle_target_path =
    W("\\Registry\\Machine\\Software\\prsk_m8_symlink\\dangle_target");
/* A link whose destination runs THROUGH itself, so each follow appends one
 * more component and the path grows without bound. */
static const void *loop_path = W("\\Registry\\Machine\\Software\\prsk_m8_symlink\\loop");
static const void *loop_target_path =
    W("\\Registry\\Machine\\Software\\prsk_m8_symlink\\loop\\loop");
/* Two links naming each other: a cycle whose path length never changes. */
static const void *cycle_a_path = W("\\Registry\\Machine\\Software\\prsk_m8_symlink\\cycle_a");
static const void *cycle_b_path = W("\\Registry\\Machine\\Software\\prsk_m8_symlink\\cycle_b");

/* Open <path> with OBJ_OPENLINK: the link key itself, not its target. */
static NTSTATUS open_link_itself(const void *path, HANDLE *out)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    init_ustr(&name, path);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE | OBJ_OPENLINK);
    return NtOpenKey(out, KEY_ALL_ACCESS, &attr);
}

/* Delete a link key (OBJ_OPENLINK open + delete), for cleanup. */
static void delete_link(const void *path)
{
    HANDLE key;
    if (NT_SUCCESS(open_link_itself(path, &key)))
    {
        NtDeleteKey(key);
        NtClose(key);
    }
}

/* Point the link key at <target>: SymbolicLinkValue, REG_LINK, and the
 * length excludes the terminator — the shape win32u writes
 * (dlls/win32u/sysparams.c write_source_to_registry). */
static NTSTATUS set_link_value(HANDLE link, const void *target)
{
    UNICODE_STRING name, value;
    init_ustr(&name, W("SymbolicLinkValue"));
    init_ustr(&value, target);
    return NtSetValueKey(link, &name, 0, REG_LINK, value.Buffer, value.Length);
}

static ULONG query_dword(HANDLE key, const void *valueName, NTSTATUS *status)
{
    UCHAR buffer[sizeof(reg_kv_partial_info) + sizeof(ULONG)];
    reg_kv_partial_info *info = (reg_kv_partial_info *)buffer;
    UNICODE_STRING name;
    ULONG result_len = 0;
    init_ustr(&name, valueName);
    *status =
        NtQueryValueKey(key, &name, KV_PARTIAL_INFO_CLASS, buffer, sizeof(buffer), &result_len);
    if (*status != STATUS_SUCCESS || info->data_length != sizeof(ULONG))
        return 0;
    return *(ULONG *)info->data;
}

START_TEST(symlink)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE base, target, sub, link;
    ULONG disposition;
    NTSTATUS status;

    reg_ensure_software();

    /* Clean slate: links first (they need the OPENLINK spelling), then the
     * plain keys, children before parents. */
    delete_link(link_path);
    delete_link(dangling_path);
    reg_delete_path(dangle_target_path);
    reg_delete_path(target_sub_path);
    reg_delete_path(target_path);
    reg_delete_path(base_path);

    status = reg_create_path(base_path, &base, NULL);
    ok(status == STATUS_SUCCESS, "create base -> %08lx", (unsigned long)status);
    status = reg_create_path(target_path, &target, NULL);
    ok(status == STATUS_SUCCESS, "create target -> %08lx", (unsigned long)status);
    status = reg_create_path(target_sub_path, &sub, NULL);
    ok(status == STATUS_SUCCESS, "create target sub -> %08lx", (unsigned long)status);
    {
        ULONG marker = 0x11223344, submarker = 0x55667788;
        status = reg_set(target, W("probe"), REG_DWORD, &marker, sizeof(marker));
        ok(status == STATUS_SUCCESS, "set target probe -> %08lx", (unsigned long)status);
        status = reg_set(sub, W("subprobe"), REG_DWORD, &submarker, sizeof(submarker));
        ok(status == STATUS_SUCCESS, "set sub probe -> %08lx", (unsigned long)status);
    }

    /* --- creation ------------------------------------------------------- */

    disposition = 0;
    init_ustr(&name, link_path);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateKey(&link, KEY_ALL_ACCESS, &attr, 0, NULL,
                         REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK, &disposition);
    ok(status == STATUS_SUCCESS, "create link -> %08lx", (unsigned long)status);
    ok(disposition == REG_CREATED_NEW_KEY, "link disposition %lu", (unsigned long)disposition);

    /* A link key takes SymbolicLinkValue/REG_LINK and nothing else. */
    {
        ULONG marker = 1;
        status = reg_set(link, W("probe"), REG_DWORD, &marker, sizeof(marker));
        ok(status == STATUS_ACCESS_DENIED, "non-link value on link -> %08lx",
           (unsigned long)status);
    }
    status = set_link_value(link, target_path);
    ok(status == STATUS_SUCCESS, "set SymbolicLinkValue -> %08lx", (unsigned long)status);

    /* Creating over an existing link collides: CREATE_LINK's lookup drops
     * OBJ_OPENIF (wine server/registry.c create_key). */
    {
        HANDLE again = NULL;
        status = NtCreateKey(&again, KEY_ALL_ACCESS, &attr, 0, NULL,
                             REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK, NULL);
        ok(status == STATUS_OBJECT_NAME_COLLISION, "re-create link -> %08lx",
           (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(again);
    }

    /* --- resolution ------------------------------------------------------ */

    /* Opening the link path lands on the target. */
    {
        HANDLE resolved = NULL;
        ULONG got;
        status = reg_open_path(link_path, &resolved);
        ok(status == STATUS_SUCCESS, "open through link -> %08lx", (unsigned long)status);
        got = query_dword(resolved, W("probe"), &status);
        ok(status == STATUS_SUCCESS && got == 0x11223344, "probe through link -> %08lx value %08lx",
           (unsigned long)status, (unsigned long)got);
        NtClose(resolved);
    }

    /* A link in the MIDDLE of a path: the remainder resolves under the
     * target. */
    {
        HANDLE resolved = NULL;
        ULONG got;
        status = reg_open_path(through_path, &resolved);
        ok(status == STATUS_SUCCESS, "open link\\sub -> %08lx", (unsigned long)status);
        got = query_dword(resolved, W("subprobe"), &status);
        ok(status == STATUS_SUCCESS && got == 0x55667788,
           "subprobe through link -> %08lx value %08lx", (unsigned long)status, (unsigned long)got);
        NtClose(resolved);
    }

    /* NtCreateKey without CREATE_LINK resolves through too: with the target
     * present it is an open of the target. */
    {
        HANDLE resolved = NULL;
        ULONG got;
        disposition = 0;
        status = NtCreateKey(&resolved, KEY_ALL_ACCESS, &attr, 0, NULL, REG_OPTION_VOLATILE,
                             &disposition);
        ok(status == STATUS_SUCCESS, "create over link -> %08lx", (unsigned long)status);
        ok(disposition == REG_OPENED_EXISTING_KEY, "create-over-link disposition %lu",
           (unsigned long)disposition);
        got = query_dword(resolved, W("probe"), &status);
        ok(status == STATUS_SUCCESS && got == 0x11223344,
           "probe via create-over-link -> %08lx value %08lx", (unsigned long)status,
           (unsigned long)got);
        NtClose(resolved);
    }

    /* OBJ_OPENLINK opens the link key itself: SymbolicLinkValue is visible,
     * the target's values are not. */
    {
        HANDLE itself = NULL;
        UCHAR buffer[sizeof(reg_kv_partial_info) + 256 * sizeof(WCHAR)];
        reg_kv_partial_info *info = (reg_kv_partial_info *)buffer;
        UNICODE_STRING target_str;
        ULONG result_len = 0;
        status = open_link_itself(link_path, &itself);
        ok(status == STATUS_SUCCESS, "open link itself -> %08lx", (unsigned long)status);
        init_ustr(&name, W("SymbolicLinkValue"));
        status = NtQueryValueKey(itself, &name, KV_PARTIAL_INFO_CLASS, buffer, sizeof(buffer),
                                 &result_len);
        init_ustr(&target_str, target_path);
        ok(status == STATUS_SUCCESS && info->type == REG_LINK &&
               info->data_length == target_str.Length &&
               memcmp(info->data, target_str.Buffer, info->data_length) == 0,
           "SymbolicLinkValue read-back -> %08lx type %lu len %lu", (unsigned long)status,
           (unsigned long)info->type, (unsigned long)info->data_length);
        query_dword(itself, W("probe"), &status);
        ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "target value via OPENLINK -> %08lx",
           (unsigned long)status);
        NtClose(itself);
    }

    /* --- dangling links --------------------------------------------------- */

    {
        HANDLE dangle = NULL, resolved = NULL;
        UNICODE_STRING dangle_name;
        OBJECT_ATTRIBUTES dangle_attr;
        init_ustr(&dangle_name, dangling_path);
        init_attr(&dangle_attr, NULL, &dangle_name, OBJ_CASE_INSENSITIVE);
        status = NtCreateKey(&dangle, KEY_ALL_ACCESS, &dangle_attr, 0, NULL,
                             REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK, NULL);
        ok(status == STATUS_SUCCESS, "create dangling link -> %08lx", (unsigned long)status);
        status = set_link_value(dangle, dangle_target_path);
        ok(status == STATUS_SUCCESS, "set dangling value -> %08lx", (unsigned long)status);

        /* An open cannot cross into a destination that is not there... */
        status = reg_open_path(dangling_path, &resolved);
        ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "open dangling -> %08lx", (unsigned long)status);

        /* ...but a create makes the destination (wine server/registry.c
         * key_lookup_name: "symlink destination can be created if missing"). */
        disposition = 0;
        status = NtCreateKey(&resolved, KEY_ALL_ACCESS, &dangle_attr, 0, NULL, 0, &disposition);
        ok(status == STATUS_SUCCESS, "create through dangling -> %08lx", (unsigned long)status);
        ok(disposition == REG_CREATED_NEW_KEY, "dangling create disposition %lu",
           (unsigned long)disposition);
        if (NT_SUCCESS(status))
            NtClose(resolved);
        status = reg_open_path(dangle_target_path, &resolved);
        ok(status == STATUS_SUCCESS, "destination exists -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            NtDeleteKey(resolved);
            NtClose(resolved);
        }
        NtDeleteKey(dangle);
        NtClose(dangle);
    }

    /* --- link loops ------------------------------------------------------- */

    /* A resolution that never terminates has to be REFUSED, and the status is
     * not a name error: the oracle's generic name walk gives up after 32
     * nested lookups and answers STATUS_INVALID_PARAMETER (wine
     * server/object.c lookup_named_object: `if (recursion_count > 32)`), which
     * the symlink arm of key_lookup_name reaches through its own
     * lookup_named_object call. ntdll:reg pins the same answer at reg.c:1312.
     *
     * Both shapes below are needed. The first GROWS the path by one component
     * per follow, so a length bound would stop it; the second alternates
     * between two names of constant length, and only a bound on the number of
     * FOLLOWS stops that one. */
    {
        HANDLE loop = NULL, cycle_a = NULL, cycle_b = NULL, resolved = NULL;
        UNICODE_STRING loop_name;
        OBJECT_ATTRIBUTES loop_attr;

        delete_link(loop_path);
        delete_link(cycle_a_path);
        delete_link(cycle_b_path);

        init_ustr(&loop_name, loop_path);
        init_attr(&loop_attr, NULL, &loop_name, OBJ_CASE_INSENSITIVE);
        status = NtCreateKey(&loop, KEY_ALL_ACCESS, &loop_attr, 0, NULL,
                             REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK, NULL);
        ok(status == STATUS_SUCCESS, "create self-extending link -> %08lx", (unsigned long)status);
        status = set_link_value(loop, loop_target_path);
        ok(status == STATUS_SUCCESS, "set self-extending value -> %08lx", (unsigned long)status);

        status = reg_open_path(loop_path, &resolved);
        ok(status == STATUS_INVALID_PARAMETER, "open self-extending loop -> %08lx",
           (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(resolved);

        /* A create resolves through a link the same way, so it refuses
         * identically rather than materialising one of the intermediate
         * names. */
        resolved = NULL;
        status =
            NtCreateKey(&resolved, KEY_ALL_ACCESS, &loop_attr, 0, NULL, REG_OPTION_VOLATILE, NULL);
        ok(status == STATUS_INVALID_PARAMETER, "create through self-extending loop -> %08lx",
           (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(resolved);

        /* OBJ_OPENLINK still reaches the link key itself — which is the only
         * way a loop can be cleaned up. */
        resolved = NULL;
        status = open_link_itself(loop_path, &resolved);
        ok(status == STATUS_SUCCESS, "OPENLINK a looping link -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(resolved);

        /* The two-link cycle. */
        init_ustr(&loop_name, cycle_a_path);
        init_attr(&loop_attr, NULL, &loop_name, OBJ_CASE_INSENSITIVE);
        status = NtCreateKey(&cycle_a, KEY_ALL_ACCESS, &loop_attr, 0, NULL,
                             REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK, NULL);
        ok(status == STATUS_SUCCESS, "create cycle_a -> %08lx", (unsigned long)status);
        init_ustr(&loop_name, cycle_b_path);
        status = NtCreateKey(&cycle_b, KEY_ALL_ACCESS, &loop_attr, 0, NULL,
                             REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK, NULL);
        ok(status == STATUS_SUCCESS, "create cycle_b -> %08lx", (unsigned long)status);
        status = set_link_value(cycle_a, cycle_b_path);
        ok(status == STATUS_SUCCESS, "point cycle_a at cycle_b -> %08lx", (unsigned long)status);
        status = set_link_value(cycle_b, cycle_a_path);
        ok(status == STATUS_SUCCESS, "point cycle_b at cycle_a -> %08lx", (unsigned long)status);

        resolved = NULL;
        status = reg_open_path(cycle_a_path, &resolved);
        ok(status == STATUS_INVALID_PARAMETER, "open two-link cycle -> %08lx",
           (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(resolved);

        NtDeleteKey(loop);
        NtClose(loop);
        NtDeleteKey(cycle_a);
        NtClose(cycle_a);
        NtDeleteKey(cycle_b);
        NtClose(cycle_b);
    }

    /* --- deletion --------------------------------------------------------- */

    /* Deleting through the OPENLINK handle removes the link, not the
     * target. */
    {
        HANDLE itself = NULL, resolved = NULL;
        status = open_link_itself(link_path, &itself);
        ok(status == STATUS_SUCCESS, "reopen link itself -> %08lx", (unsigned long)status);
        status = NtDeleteKey(itself);
        ok(status == STATUS_SUCCESS, "delete link -> %08lx", (unsigned long)status);
        NtClose(itself);
        status = open_link_itself(link_path, &itself);
        ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "link gone -> %08lx", (unsigned long)status);
        status = reg_open_path(target_path, &resolved);
        ok(status == STATUS_SUCCESS, "target survives -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(resolved);
    }

    /* Cleanup. */
    NtClose(link);
    reg_delete_path(target_sub_path);
    NtDeleteKey(target);
    NtClose(target);
    NtClose(sub);
    status = NtDeleteKey(base);
    ok(status == STATUS_SUCCESS, "cleanup delete base -> %08lx", (unsigned long)status);
    NtClose(base);
}
