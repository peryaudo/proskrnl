/*
 * sem_reg/reg_rename.c — NtRenameKey semantics (CUI-7).
 *
 * Named reg_rename, not rename: a test is identified by its BASE name in
 * both runners (the .exe, the [KTEST] line, the subtest filter), and
 * sem_file/rename.c already owns `rename` — two sources of that name built
 * to one .exe, so whichever compiled last was the only one on the volume
 * and BOTH graded green off its single verdict line.
 *
 * Oracle behaviour pinned from the pinned tree: ntdll rejects a NULL name
 * with STATUS_ACCESS_VIOLATION and a NULL-buffer/empty name with
 * STATUS_INVALID_PARAMETER before reaching the server (wine
 * dlls/ntdll/unix/registry.c NtRenameKey); the server rejects a
 * multi-component or over-long (> MAX_NAME_LEN chars) name with
 * STATUS_INVALID_PARAMETER, answers STATUS_CANNOT_DELETE both for a
 * parentless key and for an existing sibling with the new name — including
 * the key itself, so a case-only self-rename also refuses — re-sorts the
 * sibling array, and the handle needs KEY_WRITE (wine server/registry.c
 * rename_key + DECL_HANDLER(rename_key) + get_hkey_obj, which turns a
 * deleted key into STATUS_KEY_DELETED first).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtRenameKey(HANDLE, UNICODE_STRING *);

static const void *base_path = W("\\Registry\\Machine\\Software\\prsk_m8_ren");

START_TEST(reg_rename)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE base, key, other, check;
    UCHAR buffer[256];
    ULONG result_len;
    NTSTATUS status;
    WCHAR long_name[300];

    reg_ensure_software();
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_m8_ren\\mm"));
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_m8_ren\\aa"));
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_m8_ren\\zz"));
    reg_delete_path(base_path);

    status = reg_create_path(base_path, &base, NULL);
    ok(status == STATUS_SUCCESS, "create base -> %08lx", (unsigned long)status);
    status = reg_create_sub(base, W("zz"), &key, NULL);
    ok(status == STATUS_SUCCESS, "create zz -> %08lx", (unsigned long)status);
    status = reg_create_sub(base, W("mm"), &other, NULL);
    ok(status == STATUS_SUCCESS, "create mm -> %08lx", (unsigned long)status);

    /* --- the ntdll-side argument ladder ---------------------------------- */
    status = NtRenameKey(key, NULL);
    ok(status == STATUS_ACCESS_VIOLATION, "NULL name -> %08lx", (unsigned long)status);
    name.Length = 0;
    name.MaximumLength = 0;
    name.Buffer = NULL;
    status = NtRenameKey(key, &name);
    ok(status == STATUS_INVALID_PARAMETER, "NULL buffer -> %08lx", (unsigned long)status);
    init_ustr(&name, W("aa"));
    name.Length = 0;
    status = NtRenameKey(key, &name);
    ok(status == STATUS_INVALID_PARAMETER, "empty name -> %08lx", (unsigned long)status);

    /* --- the server-side name ladder ------------------------------------- */
    init_ustr(&name, W("a\\b"));
    status = NtRenameKey(key, &name);
    ok(status == STATUS_INVALID_PARAMETER, "path name -> %08lx", (unsigned long)status);
    for (unsigned i = 0; i < 300; i++)
        long_name[i] = 'x';
    name.Buffer = long_name;
    name.Length = 300 * sizeof(WCHAR);
    name.MaximumLength = name.Length;
    status = NtRenameKey(key, &name);
    ok(status == STATUS_INVALID_PARAMETER, "over-long name -> %08lx", (unsigned long)status);

    /* --- collision arms --------------------------------------------------- */
    init_ustr(&name, W("mm"));
    status = NtRenameKey(key, &name);
    ok(status == STATUS_CANNOT_DELETE, "existing sibling -> %08lx", (unsigned long)status);
    init_ustr(&name, W("ZZ")); /* the key itself, case-insensitively */
    status = NtRenameKey(key, &name);
    ok(status == STATUS_CANNOT_DELETE, "self collision -> %08lx", (unsigned long)status);

    /* --- a parentless key refuses ----------------------------------------- */
    {
        HANDLE root;
        status = reg_open_path_access(W("\\Registry"), KEY_WRITE, &root);
        if (NT_SUCCESS(status))
        {
            init_ustr(&name, W("prsk_never"));
            status = NtRenameKey(root, &name);
            ok(status == STATUS_CANNOT_DELETE, "parentless -> %08lx", (unsigned long)status);
            NtClose(root);
        }
        else
            skip("\\Registry not openable with KEY_WRITE (%08lx)", (unsigned long)status);
    }

    /* --- access + stale-handle arms ---------------------------------------- */
    {
        HANDLE readonly;
        UNICODE_STRING sub;
        init_ustr(&sub, W("zz"));
        init_attr(&attr, base, &sub, OBJ_CASE_INSENSITIVE);
        status = NtOpenKey(&readonly, KEY_READ, &attr);
        ok(status == STATUS_SUCCESS, "open read-only -> %08lx", (unsigned long)status);
        init_ustr(&name, W("aa"));
        status = NtRenameKey(readonly, &name);
        ok(status == STATUS_ACCESS_DENIED, "KEY_READ handle -> %08lx", (unsigned long)status);
        NtClose(readonly);
    }

    /* --- the success arm: zz -> aa, re-sorted, old name free --------------- */
    init_ustr(&name, W("aa"));
    status = NtRenameKey(key, &name);
    ok(status == STATUS_SUCCESS, "rename zz->aa -> %08lx", (unsigned long)status);

    /* Enumeration re-sorts: index 0 is now "aa", index 1 is "mm". */
    status = NtEnumerateKey(base, 0, KEY_BASIC_INFO_CLASS, buffer, sizeof(buffer), &result_len);
    ok(status == STATUS_SUCCESS, "enumerate 0 -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        reg_key_basic_info *info = (reg_key_basic_info *)buffer;
        ok(info->name_length == 2 * sizeof(WCHAR) && info->name[0] == 'a' && info->name[1] == 'a',
           "index 0 is aa (len %lu)", (unsigned long)info->name_length);
    }
    status = NtEnumerateKey(base, 1, KEY_BASIC_INFO_CLASS, buffer, sizeof(buffer), &result_len);
    ok(status == STATUS_SUCCESS, "enumerate 1 -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        reg_key_basic_info *info = (reg_key_basic_info *)buffer;
        ok(info->name_length == 2 * sizeof(WCHAR) && info->name[0] == 'm' && info->name[1] == 'm',
           "index 1 is mm (len %lu)", (unsigned long)info->name_length);
    }

    /* The old name no longer opens; the new one does; the old handle still
     * addresses the renamed key. */
    init_ustr(&name, W("zz"));
    init_attr(&attr, base, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenKey(&check, KEY_READ, &attr);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "old name open -> %08lx", (unsigned long)status);
    init_ustr(&name, W("aa"));
    init_attr(&attr, base, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenKey(&check, KEY_READ, &attr);
    ok(status == STATUS_SUCCESS, "new name open -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(check);
    {
        ULONG val = 7;
        status = reg_set(key, W("v"), REG_DWORD, &val, sizeof(val));
        ok(status == STATUS_SUCCESS, "old handle set on renamed -> %08lx", (unsigned long)status);
    }

    /* --- a deleted key's handle answers STATUS_KEY_DELETED ------------------ */
    status = NtDeleteKey(other);
    ok(status == STATUS_SUCCESS, "delete mm -> %08lx", (unsigned long)status);
    init_ustr(&name, W("nn"));
    status = NtRenameKey(other, &name);
    ok(status == STATUS_KEY_DELETED, "rename deleted -> %08lx", (unsigned long)status);
    NtClose(other);

    /* Cleanup. */
    status = NtDeleteKey(key);
    ok(status == STATUS_SUCCESS, "cleanup aa -> %08lx", (unsigned long)status);
    NtClose(key);
    status = NtDeleteKey(base);
    ok(status == STATUS_SUCCESS, "cleanup base -> %08lx", (unsigned long)status);
    NtClose(base);
}
