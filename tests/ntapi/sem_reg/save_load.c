/*
 * sem_reg/save_load.c — NtSaveKey, the NtLoadKey family and NtUnloadKey
 * (CUI-7).
 *
 * Oracle behaviour pinned from the pinned tree (wine
 * dlls/ntdll/unix/registry.c NtLoadKeyEx/NtUnloadKey/NtSaveKey; wine
 * server/registry.c DECL_HANDLER(load_registry/unload_registry/
 * save_registry)):
 *
 *   - NtSaveKey needs SeBackupPrivilege, the load/unload family
 *     SeRestorePrivilege — both disabled by default in the token, so the
 *     refusal is STATUS_PRIVILEGE_NOT_HELD until NtAdjustPrivilegesToken
 *     enables them. NtUnloadKey's argument ladder (NULL attr/name -> AV,
 *     wrong Length -> INVALID_PARAMETER, odd name -> OBJECT_NAME_INVALID)
 *     runs BEFORE the privilege check; the load family opens the hive FILE
 *     before it, so a missing file answers the file error even without the
 *     privilege.
 *   - The saved file's CONTENT is each implementation's own hive format
 *     (wineserver text, proskrnl PHV1 — docs/03 "Cm hive format"): the pins
 *     are semantic (nonzero size; save then load then query equality),
 *     never byte comparisons.
 *   - The destination is created fresh: loading onto an EXISTING key is
 *     STATUS_OBJECT_NAME_COLLISION (the server's load_registry drops the
 *     ntdll-forced OBJ_OPENIF with the rest of the attributes), RootDirectory
 *     is honored, and the NtLoadKey2/Ex extra arguments (flags, trustkey,
 *     event, access, roothandle, iostatus) are all FIXME-ignored. A file
 *     that is not a hive answers STATUS_NOT_REGISTRY_FILE — and leaves the
 *     just-created destination key behind, empty.
 *   - NtUnloadKey resolves the named key and deletes its subtree
 *     recursively: open handles to the NAMED key refuse with
 *     STATUS_CANNOT_DELETE, but an open handle to a CHILD does not block
 *     the unload — it is left answering STATUS_KEY_DELETED. A missing name
 *     is STATUS_OBJECT_NAME_NOT_FOUND.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtLoadKey(const OBJECT_ATTRIBUTES *, OBJECT_ATTRIBUTES *);
NTSYSAPI NTSTATUS NTAPI NtLoadKey2(const OBJECT_ATTRIBUTES *, OBJECT_ATTRIBUTES *, ULONG);
NTSYSAPI NTSTATUS NTAPI NtLoadKeyEx(const OBJECT_ATTRIBUTES *, OBJECT_ATTRIBUTES *, ULONG, HANDLE,
                                    HANDLE, ACCESS_MASK, HANDLE *, IO_STATUS_BLOCK *);
NTSYSAPI NTSTATUS NTAPI NtUnloadKey(OBJECT_ATTRIBUTES *);
NTSYSAPI NTSTATUS NTAPI NtSaveKey(HANDLE, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
                                    const void *, ULONG, PLARGE_INTEGER, PULONG);
/* set_privilege(), delete_file() and the token prototypes they need live in
 * util.h — save_load_delta.c uses the same two. */

static const void *base_path = W("\\Registry\\Machine\\Software\\prsk_m8_save");
static const void *load_path = W("\\Registry\\Machine\\Software\\prsk_m8_load");
static const void *load2_path = W("\\Registry\\Machine\\Software\\prsk_m8_load2");
static const void *hive_file = W("\\??\\C:\\prsk_m8.hiv");
static const void *junk_file = W("\\??\\C:\\prsk_m8.junk");

/* Query a REG_DWORD value on an open key; 0xffffffff = not there. */
static ULONG query_dword(HANDLE key, const void *valueName)
{
    UNICODE_STRING name;
    UCHAR buffer[64];
    ULONG len;
    reg_kv_partial_info *info = (reg_kv_partial_info *)buffer;
    init_ustr(&name, valueName);
    if (!NT_SUCCESS(
            NtQueryValueKey(key, &name, KV_PARTIAL_INFO_CLASS, buffer, sizeof(buffer), &len)) ||
        info->type != REG_DWORD || info->data_length != sizeof(ULONG))
        return 0xffffffffu;
    ULONG value;
    memcpy(&value, info->data, sizeof(value));
    return value;
}

START_TEST(save_load)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr, fileAttr;
    UNICODE_STRING fileName;
    HANDLE base, sub, file, key, software;
    NTSTATUS status;
    ULONG val;

    reg_ensure_software();
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_m8_save\\sub"));
    reg_delete_path(base_path);
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_m8_load\\sub"));
    reg_delete_path(load_path);
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_m8_load2\\sub"));
    reg_delete_path(load2_path);
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_m8_junkdest"));
    delete_file(hive_file);
    delete_file(junk_file);

    /* --- the subtree to save: two levels, three value types ---------------- */
    status = reg_create_path(base_path, &base, NULL);
    ok(status == STATUS_SUCCESS, "create base -> %08lx", (unsigned long)status);
    val = 42;
    status = reg_set(base, W("dword"), REG_DWORD, &val, sizeof(val));
    ok(status == STATUS_SUCCESS, "set dword -> %08lx", (unsigned long)status);
    status = reg_set(base, W("str"), REG_SZ, W("hello\0"), 12);
    ok(status == STATUS_SUCCESS, "set str -> %08lx", (unsigned long)status);
    status = reg_create_sub(base, W("sub"), &sub, NULL);
    ok(status == STATUS_SUCCESS, "create sub -> %08lx", (unsigned long)status);
    val = 7;
    status = reg_set(sub, W("inner"), REG_DWORD, &val, sizeof(val));
    ok(status == STATUS_SUCCESS, "set inner -> %08lx", (unsigned long)status);
    NtClose(sub);

    /* --- privilege-disabled refusals --------------------------------------- */
    status = open_hive_file(hive_file, GENERIC_WRITE, FILE_OVERWRITE_IF, &file);
    ok(status == STATUS_SUCCESS, "create hive file -> %08lx", (unsigned long)status);
    status = NtSaveKey(base, file);
    ok(status == STATUS_PRIVILEGE_NOT_HELD, "save without SeBackup -> %08lx",
       (unsigned long)status);
    NtClose(file);
    delete_file(hive_file);

    /* NtUnloadKey's ntdll ladder runs before the privilege check. */
    status = NtUnloadKey(NULL);
    ok(status == STATUS_ACCESS_VIOLATION, "unload NULL attr -> %08lx", (unsigned long)status);
    init_attr(&attr, NULL, NULL, 0);
    status = NtUnloadKey(&attr);
    ok(status == STATUS_ACCESS_VIOLATION, "unload NULL name -> %08lx", (unsigned long)status);
    init_ustr(&name, W("x"));
    init_attr(&attr, NULL, &name, 0);
    attr.Length = sizeof(attr) - 4;
    status = NtUnloadKey(&attr);
    ok(status == STATUS_INVALID_PARAMETER, "unload bad Length -> %08lx", (unsigned long)status);
    init_ustr(&name, W("x"));
    name.Length = 1; /* odd */
    init_attr(&attr, NULL, &name, 0);
    status = NtUnloadKey(&attr);
    ok(status == STATUS_OBJECT_NAME_INVALID, "unload odd name -> %08lx", (unsigned long)status);
    init_ustr(&name, W("\\Registry\\Machine\\Software\\prsk_m8_save"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtUnloadKey(&attr);
    ok(status == STATUS_PRIVILEGE_NOT_HELD, "unload without SeRestore -> %08lx",
       (unsigned long)status);

    /* NtLoadKey opens the hive FILE before the privilege check: a missing
     * file answers the file error even with the privilege disabled.
     *
     * The destination is RootDirectory-relative throughout — the one shape
     * the real consumer (kernelbase RegLoadKeyW) issues. An absolute
     * \Registry\... destination is NOT exercised: the oracle's
     * load_registry handler drops the destination attributes on the floor
     * (server/registry.c: create_key(..., attributes=0)), so the absolute
     * form falls over its own case-sensitive root lookup — a server quirk,
     * not a contract (docs/03 "CUI-7" notes). */
    status = reg_open_path(W("\\Registry\\Machine\\Software"), &software);
    ok(status == STATUS_SUCCESS, "open Software -> %08lx", (unsigned long)status);
    init_ustr(&name, W("prsk_m8_load"));
    init_attr(&attr, software, &name, OBJ_CASE_INSENSITIVE);
    init_ustr(&fileName, hive_file);
    init_attr(&fileAttr, NULL, &fileName, OBJ_CASE_INSENSITIVE);
    status = NtLoadKey(&attr, &fileAttr);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "load missing file -> %08lx", (unsigned long)status);

    /* --- enable both privileges (fresh token per test process) ------------- */
    status = set_privilege(PRSK_SE_BACKUP_PRIVILEGE, TRUE);
    ok(status == STATUS_SUCCESS, "enable SeBackup -> %08lx", (unsigned long)status);
    status = set_privilege(PRSK_SE_RESTORE_PRIVILEGE, TRUE);
    ok(status == STATUS_SUCCESS, "enable SeRestore -> %08lx", (unsigned long)status);

    /* Privilege alone does not conjure the file. */
    status = NtLoadKey(&attr, &fileAttr);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "load missing file (priv) -> %08lx",
       (unsigned long)status);

    /* --- save: SUCCESS, nonzero EOF (content is format-private) ------------ */
    status = open_hive_file(hive_file, GENERIC_WRITE, FILE_OVERWRITE_IF, &file);
    ok(status == STATUS_SUCCESS, "recreate hive file -> %08lx", (unsigned long)status);
    status = NtSaveKey(base, file);
    ok(status == STATUS_SUCCESS, "save -> %08lx", (unsigned long)status);
    NtClose(file);
    {
        IO_STATUS_BLOCK iosb;
        FILE_STANDARD_INFORMATION std;
        status = open_hive_file(hive_file, GENERIC_READ, FILE_OPEN, &file);
        ok(status == STATUS_SUCCESS, "reopen hive file -> %08lx", (unsigned long)status);
        status = NtQueryInformationFile(file, &iosb, &std, sizeof(std), FileStandardInformation);
        ok(status == STATUS_SUCCESS && std.EndOfFile.QuadPart > 0, "saved file nonempty (%08lx)",
           (unsigned long)status);
        NtClose(file);
    }

    /* --- a non-hive file refuses, leaving the created dest behind ----------- */
    {
        IO_STATUS_BLOCK iosb;
        static const char junk[] = "this is not a hive, in any format\n";
        UNICODE_STRING junkDest;
        OBJECT_ATTRIBUTES junkAttr;
        status = open_hive_file(junk_file, GENERIC_WRITE, FILE_OVERWRITE_IF, &file);
        ok(status == STATUS_SUCCESS, "create junk -> %08lx", (unsigned long)status);
        status = NtWriteFile(file, NULL, NULL, NULL, &iosb, junk, sizeof(junk) - 1, NULL, NULL);
        ok(status == STATUS_SUCCESS, "write junk -> %08lx", (unsigned long)status);
        NtClose(file);
        init_ustr(&junkDest, W("prsk_m8_junkdest"));
        init_attr(&junkAttr, software, &junkDest, OBJ_CASE_INSENSITIVE);
        init_ustr(&fileName, junk_file);
        init_attr(&fileAttr, NULL, &fileName, OBJ_CASE_INSENSITIVE);
        status = NtLoadKey(&junkAttr, &fileAttr);
        ok(status == STATUS_NOT_REGISTRY_FILE, "load junk -> %08lx", (unsigned long)status);
        /* The destination was created before the parse failed and stays,
         * empty. */
        status = reg_open_path(W("\\Registry\\Machine\\Software\\prsk_m8_junkdest"), &key);
        ok(status == STATUS_SUCCESS, "junk dest created -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            ok(query_dword(key, W("dword")) == 0xffffffffu, "junk dest empty");
            NtDeleteKey(key);
            NtClose(key);
        }
    }

    /* --- load at a fresh destination and read the content back ------------- */
    init_ustr(&fileName, hive_file);
    init_attr(&fileAttr, NULL, &fileName, OBJ_CASE_INSENSITIVE);
    status = NtLoadKey(&attr, &fileAttr);
    ok(status == STATUS_SUCCESS, "load -> %08lx", (unsigned long)status);
    status = reg_open_path(load_path, &key);
    ok(status == STATUS_SUCCESS, "open loaded -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ok(query_dword(key, W("dword")) == 42, "loaded dword");
        HANDLE inner;
        status = reg_create_sub(key, W("sub"), &inner, NULL);
        ok(status == STATUS_SUCCESS, "open loaded sub -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            ok(query_dword(inner, W("inner")) == 7, "loaded inner dword");
            NtClose(inner);
        }
        /* Loading onto the EXISTING key collides (the server drops the
         * ntdll-forced OBJ_OPENIF). */
        status = NtLoadKey(&attr, &fileAttr);
        ok(status == STATUS_OBJECT_NAME_COLLISION, "load over existing -> %08lx",
           (unsigned long)status);

        /* The named key's own open handle blocks unload... */
        status = NtUnloadKey(&attr);
        ok(status == STATUS_CANNOT_DELETE, "unload with open handle -> %08lx",
           (unsigned long)status);
        NtClose(key);
    }

    /* --- NtLoadKey2 / NtLoadKeyEx: the extra arguments are ignored ---------- */
    {
        UNICODE_STRING rel;
        OBJECT_ATTRIBUTES relAttr;
        init_ustr(&rel, W("prsk_m8_load2"));
        init_attr(&relAttr, software, &rel, OBJ_CASE_INSENSITIVE);
        status = NtLoadKey2(&relAttr, &fileAttr, 4 /* REG_NO_LAZY_FLUSH: ignored */);
        ok(status == STATUS_SUCCESS, "load2 -> %08lx", (unsigned long)status);
        status = reg_open_path(load2_path, &key);
        ok(status == STATUS_SUCCESS, "open loaded2 -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            ok(query_dword(key, W("dword")) == 42, "loaded2 dword");
            NtClose(key);
        }
        status = NtUnloadKey(&relAttr);
        ok(status == STATUS_SUCCESS, "unload load2 dest -> %08lx", (unsigned long)status);
        status = NtLoadKeyEx(&relAttr, &fileAttr, 0, 0, 0, 0, NULL, NULL);
        ok(status == STATUS_SUCCESS, "loadex -> %08lx", (unsigned long)status);
        status = NtUnloadKey(&relAttr);
        ok(status == STATUS_SUCCESS, "unload loadex dest -> %08lx", (unsigned long)status);
    }

    /* --- a child handle does not block unload; it goes stale ---------------- */
    {
        HANDLE inner;
        UNICODE_STRING innerName;
        OBJECT_ATTRIBUTES innerAttr;
        init_ustr(&innerName, W("\\Registry\\Machine\\Software\\prsk_m8_load\\sub"));
        init_attr(&innerAttr, NULL, &innerName, OBJ_CASE_INSENSITIVE);
        status = NtOpenKey(&inner, KEY_READ, &innerAttr);
        ok(status == STATUS_SUCCESS, "open child -> %08lx", (unsigned long)status);
        status = NtUnloadKey(&attr);
        ok(status == STATUS_SUCCESS, "unload with child handle -> %08lx", (unsigned long)status);
        {
            UCHAR buffer[64];
            ULONG len;
            UNICODE_STRING valueName;
            init_ustr(&valueName, W("inner"));
            status = NtQueryValueKey(inner, &valueName, KV_PARTIAL_INFO_CLASS, buffer,
                                     sizeof(buffer), &len);
            ok(status == STATUS_KEY_DELETED, "child handle stale -> %08lx", (unsigned long)status);
        }
        NtClose(inner);
        status = reg_open_path(load_path, &key);
        ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "unloaded name gone -> %08lx",
           (unsigned long)status);
    }

    /* --- unloading a missing name ------------------------------------------ */
    init_ustr(&name, W("\\Registry\\Machine\\Software\\prsk_m8_never"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtUnloadKey(&attr);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "unload missing -> %08lx", (unsigned long)status);

    /* NOTE (docs/03 "CUI-7"): creating a non-volatile subkey under a LOADED
     * key answers STATUS_CHILD_MUST_BE_VOLATILE on proskrnl (the graft is
     * volatile — NT mounts do not survive reboot either) where the oracle,
     * whose loaded keys are ordinary keys, allows it. Deliberately not
     * exercised. */

    /* --- unload doubles as the recursive delete of an ordinary subtree ------ */
    init_ustr(&name, W("\\Registry\\Machine\\Software\\prsk_m8_save"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    NtClose(base);
    status = NtUnloadKey(&attr);
    ok(status == STATUS_SUCCESS, "unload ordinary subtree -> %08lx", (unsigned long)status);
    status = reg_open_path(base_path, &key);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "subtree gone -> %08lx", (unsigned long)status);

    /* Cleanup. */
    NtClose(software);
    delete_file(hive_file);
    delete_file(junk_file);
    set_privilege(PRSK_SE_BACKUP_PRIVILEGE, FALSE);
    set_privilege(PRSK_SE_RESTORE_PRIVILEGE, FALSE);
}
