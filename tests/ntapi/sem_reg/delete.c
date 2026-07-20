/*
 * sem_reg/delete.c — NtDeleteKey semantics and the deleted-key state.
 *
 * A key with subkeys cannot be deleted. Deleting a key does not invalidate
 * open handles to it: the object survives in a "deleted" limbo where every
 * operation through a stale handle fails with STATUS_KEY_DELETED, the name is
 * immediately free for reuse, and the reused name is a NEW key (the stale
 * handle does not see it). REG_OPTION_VOLATILE is accepted at create.
 */
#include "util.h"

static const void *key_path = W("\\Registry\\Machine\\Software\\prsk_m8_delete");
static const void *sub_path = W("\\Registry\\Machine\\Software\\prsk_m8_delete\\sub");

START_TEST(delete)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE base, sub, reborn;
    UCHAR buffer[128];
    ULONG result_len, disposition;
    NTSTATUS status;

    reg_ensure_software();
    reg_delete_path(sub_path);
    reg_delete_path(key_path);

    status = reg_create_path(key_path, &base, NULL);
    ok(status == STATUS_SUCCESS, "create base -> %08lx", (unsigned long)status);
    status = reg_create_sub(base, W("sub"), &sub, NULL);
    ok(status == STATUS_SUCCESS, "create sub -> %08lx", (unsigned long)status);

    /* A key with subkeys cannot be deleted (the Wine oracle reports
     * STATUS_ACCESS_DENIED — server/registry.c delete_key). */
    status = NtDeleteKey(base);
    ok(status == STATUS_ACCESS_DENIED, "delete with subkeys -> %08lx", (unsigned long)status);

    /* Delete the leaf; the parent is then deletable. */
    status = NtDeleteKey(sub);
    ok(status == STATUS_SUCCESS, "delete sub -> %08lx", (unsigned long)status);

    /* The deleted key's handle is still a valid handle onto a dead key:
     * every operation reports STATUS_KEY_DELETED. */
    {
        ULONG val = 1;
        status = reg_set(sub, W("v"), REG_DWORD, &val, sizeof(val));
        ok(status == STATUS_KEY_DELETED, "set on deleted -> %08lx", (unsigned long)status);
        init_ustr(&name, W("v"));
        status =
            NtQueryValueKey(sub, &name, KV_PARTIAL_INFO_CLASS, buffer, sizeof(buffer), &result_len);
        ok(status == STATUS_KEY_DELETED, "query on deleted -> %08lx", (unsigned long)status);
        status = NtEnumerateKey(sub, 0, KEY_BASIC_INFO_CLASS, buffer, sizeof(buffer), &result_len);
        ok(status == STATUS_KEY_DELETED, "enumerate on deleted -> %08lx", (unsigned long)status);
        /* Re-deleting an already-deleted key is a success no-op (Wine
         * server/registry.c delete_key: KEY_DELETED -> return 1). */
        status = NtDeleteKey(sub);
        ok(status == STATUS_SUCCESS, "re-delete deleted -> %08lx", (unsigned long)status);
        init_ustr(&name, W("child"));
        init_attr(&attr, sub, &name, OBJ_CASE_INSENSITIVE);
        status = NtCreateKey(&reborn, KEY_ALL_ACCESS, &attr, 0, NULL, 0, NULL);
        ok(status == STATUS_KEY_DELETED, "create under deleted -> %08lx", (unsigned long)status);
    }

    /* The name is free again: opening it fails, creating it makes a NEW key
     * the stale handle does not alias. */
    status = reg_open_path(sub_path, &reborn);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "open deleted name -> %08lx", (unsigned long)status);
    disposition = 0;
    status = reg_create_path(sub_path, &reborn, &disposition);
    ok(status == STATUS_SUCCESS && disposition == REG_CREATED_NEW_KEY,
       "recreate deleted name -> %08lx disposition %lu", (unsigned long)status,
       (unsigned long)disposition);
    {
        ULONG val = 2;
        status = reg_set(reborn, W("v"), REG_DWORD, &val, sizeof(val));
        ok(status == STATUS_SUCCESS, "set on reborn -> %08lx", (unsigned long)status);
        init_ustr(&name, W("v"));
        status =
            NtQueryValueKey(sub, &name, KV_PARTIAL_INFO_CLASS, buffer, sizeof(buffer), &result_len);
        ok(status == STATUS_KEY_DELETED, "stale handle sees reborn key -> %08lx",
           (unsigned long)status);
    }
    NtClose(sub);
    status = NtDeleteKey(reborn);
    ok(status == STATUS_SUCCESS, "delete reborn -> %08lx", (unsigned long)status);
    NtClose(reborn);

    /* REG_OPTION_VOLATILE is accepted; the key behaves normally within the
     * boot (its non-persistence is pinned by the kernel-side reboot test). */
    init_ustr(&name, W("volatile_sub"));
    init_attr(&attr, base, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateKey(&sub, KEY_ALL_ACCESS, &attr, 0, NULL, REG_OPTION_VOLATILE, &disposition);
    ok(status == STATUS_SUCCESS && disposition == REG_CREATED_NEW_KEY, "volatile create -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        /* A non-volatile child under a volatile parent is refused. */
        UNICODE_STRING childName;
        OBJECT_ATTRIBUTES childAttr;
        init_ustr(&childName, W("stable_child"));
        init_attr(&childAttr, sub, &childName, OBJ_CASE_INSENSITIVE);
        status = NtCreateKey(&reborn, KEY_ALL_ACCESS, &childAttr, 0, NULL, 0, NULL);
        ok(status == STATUS_CHILD_MUST_BE_VOLATILE, "stable child of volatile -> %08lx",
           (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            NtDeleteKey(reborn);
            NtClose(reborn);
        }
        status = NtDeleteKey(sub);
        ok(status == STATUS_SUCCESS, "delete volatile -> %08lx", (unsigned long)status);
        NtClose(sub);
    }

    /* Cleanup. */
    status = NtDeleteKey(base);
    ok(status == STATUS_SUCCESS, "cleanup delete -> %08lx", (unsigned long)status);
    NtClose(base);
}
