/*
 * sem_reg/create_open.c — NtCreateKey/NtOpenKey lifecycle semantics.
 *
 * The registry's create differs from the Ob namespace's: creating over an
 * existing key is NOT a collision — it opens the key and reports
 * REG_OPENED_EXISTING_KEY through the disposition. Only the last path
 * component is created; a missing intermediate fails. Lookup is
 * case-insensitive, relative opens go through OBJECT_ATTRIBUTES.RootDirectory,
 * and a registry path does not resolve as any other object type.
 */
#include "util.h"

static const void *base_path = W("\\Registry\\Machine\\Software\\prsk_m8_create_open");
static const void *base_upcased = W("\\REGISTRY\\MACHINE\\SOFTWARE\\PRSK_M8_CREATE_OPEN");
static const void *missing_leaf = W("\\Registry\\Machine\\Software\\prsk_m8_no_such_key");
static const void *missing_path = W("\\Registry\\Machine\\Software\\prsk_m8_no_such_key\\sub");

START_TEST(create_open)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE base, second, sub;
    ULONG disposition;
    NTSTATUS status;

    reg_ensure_software();

    /* Start from a clean slate in case a previous run died mid-way. */
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_m8_create_open\\sub"));
    reg_delete_path(base_path);

    /* Creating a new key reports REG_CREATED_NEW_KEY. */
    disposition = 0;
    status = reg_create_path(base_path, &base, &disposition);
    ok(status == STATUS_SUCCESS, "create new -> %08lx", (unsigned long)status);
    ok(disposition == REG_CREATED_NEW_KEY, "disposition %lu, expected REG_CREATED_NEW_KEY",
       (unsigned long)disposition);

    /* Creating over an existing key is an open, not a collision. */
    disposition = 0;
    status = reg_create_path(base_path, &second, &disposition);
    ok(status == STATUS_SUCCESS, "create existing -> %08lx", (unsigned long)status);
    ok(disposition == REG_OPENED_EXISTING_KEY, "disposition %lu, expected REG_OPENED_EXISTING_KEY",
       (unsigned long)disposition);
    ok(second != base, "create-existing returned the same handle value");

    /* ...and both handles name ONE key: a value set through the first is
     * visible through the second. */
    {
        ULONG set_val = 0x11223344, got = 0, result_len = 0;
        UCHAR buffer[sizeof(reg_kv_partial_info) + sizeof(ULONG)];
        reg_kv_partial_info *info = (reg_kv_partial_info *)buffer;
        status = reg_set(base, W("probe"), REG_DWORD, &set_val, sizeof(set_val));
        ok(status == STATUS_SUCCESS, "set via handle 1 -> %08lx", (unsigned long)status);
        init_ustr(&name, W("probe"));
        status = NtQueryValueKey(second, &name, KV_PARTIAL_INFO_CLASS, buffer, sizeof(buffer),
                                 &result_len);
        ok(status == STATUS_SUCCESS, "query via handle 2 -> %08lx", (unsigned long)status);
        if (status == STATUS_SUCCESS)
        {
            __builtin_memcpy(&got, info->data, sizeof(got));
            ok(got == set_val, "value set via handle 1 not visible via handle 2 (%08lx)",
               (unsigned long)got);
        }
        init_ustr(&name, W("probe"));
        NtDeleteValueKey(base, &name);
    }
    NtClose(second);

    /* Case-insensitive absolute open resolves to the same key. */
    status = reg_open_path(base_upcased, &second);
    ok(status == STATUS_SUCCESS, "case-mangled open -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(second);

    /* Relative create/open through RootDirectory. */
    disposition = 0;
    status = reg_create_sub(base, W("sub"), &sub, &disposition);
    ok(status == STATUS_SUCCESS, "relative create -> %08lx", (unsigned long)status);
    ok(disposition == REG_CREATED_NEW_KEY, "relative disposition %lu", (unsigned long)disposition);
    NtClose(sub);
    init_ustr(&name, W("SUB"));
    init_attr(&attr, base, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenKey(&sub, KEY_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "relative case-mangled open -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(sub);

    /* A multi-component relative create makes only the LAST component:
     * "deep\\er" under base fails while "deep" does not exist... */
    init_ustr(&name, W("deep\\er"));
    init_attr(&attr, base, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateKey(&sub, KEY_ALL_ACCESS, &attr, 0, NULL, 0, NULL);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "create missing intermediate -> %08lx",
       (unsigned long)status);

    /* Opening a key that does not exist. */
    status = reg_open_path(missing_leaf, &second);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "open missing leaf -> %08lx", (unsigned long)status);
    status = reg_open_path(missing_path, &second);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "open missing path -> %08lx", (unsigned long)status);

    /* A registry path is not an Ob event; a non-key handle is not a key. */
    {
        HANDLE event;
        init_ustr(&name, W("\\Registry\\Machine\\Software"));
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        status = NtCreateEvent(&event, EVENT_ALL_ACCESS, &attr, 0 /* NotificationEvent */, FALSE);
        ok(!NT_SUCCESS(status), "event over a key path -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(event);
    }

    /* Zero DesiredAccess: binding to an EXISTING key is refused (Wine
     * server/handle.c alloc_handle: mapped access 0 -> ACCESS_DENIED), while
     * CREATING a new key is exempt (the no-access-check path). Fuzzer-found. */
    {
        HANDLE zero;
        ULONG zdisp = 0;
        init_ustr(&name, base_path);
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        status = NtOpenKey(&zero, 0, &attr);
        ok(status == STATUS_ACCESS_DENIED, "zero-access open existing -> %08lx",
           (unsigned long)status);
        status = NtCreateKey(&zero, 0, &attr, 0, NULL, 0, &zdisp);
        ok(status == STATUS_ACCESS_DENIED, "zero-access create existing -> %08lx",
           (unsigned long)status);
        init_ustr(&name, W("\\Registry\\Machine\\Software\\prsk_m8_create_open\\zeroed"));
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        status = NtCreateKey(&zero, 0, &attr, 0, NULL, 0, &zdisp);
        ok(status == STATUS_SUCCESS && zdisp == REG_CREATED_NEW_KEY,
           "zero-access create new -> %08lx disposition %lu", (unsigned long)status,
           (unsigned long)zdisp);
        if (NT_SUCCESS(status))
            NtClose(zero);
        reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_m8_create_open\\zeroed"));
    }

    /* --- REG_OPTION_CREATE_LINK: registry symlinks -----------------------
     * Creation succeeds on both runners (GUI-2: win32u's display commit
     * needs real links); the full link semantics are sem_reg/symlink's. */
    {
        HANDLE link = NULL;
        ULONG link_disposition = 0;
        init_ustr(&name, W("\\Registry\\Machine\\Software\\prsk_m8_create_link"));
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        status = NtCreateKey(&link, KEY_ALL_ACCESS, &attr, 0, NULL,
                             REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK, &link_disposition);
        ok(status == STATUS_SUCCESS, "create link key -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            NtDeleteKey(link);
            NtClose(link);
        }
    }

    /* Cleanup: delete sub then base. */
    reg_delete_sub(base, W("sub"));
    status = NtDeleteKey(base);
    ok(status == STATUS_SUCCESS, "cleanup delete -> %08lx", (unsigned long)status);
    NtClose(base);
    status = reg_open_path(base_path, &second);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "reopen after delete -> %08lx",
       (unsigned long)status);
}
