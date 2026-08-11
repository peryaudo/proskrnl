/*
 * sem_reg/save_load_delta.c — what a hive image must round-trip once the
 * on-disk format is a RECORD LOG rather than a whole-tree dump.
 *
 * The on-disk format itself is internal (docs/03 "Cm hive format", Art. 1):
 * no case here reads a hive file's bytes, and none may — the format is not a
 * boundary behaviour and pinning its bytes would freeze an internal. What IS
 * observable from ring 3 is the SAVE/LOAD round trip, and NtSaveKey/NtLoadKey
 * push the same emitter and parser the boot-time hive uses across the
 * boundary. So every property a log format can get wrong that a whole-tree
 * dump cannot is reachable here:
 *
 *   - a value SET and then DELETED must not come back (a log that only ever
 *     appends "set" records replays the deletion away);
 *   - a value SET TWICE must replay to the SECOND value, and a shorter
 *     second write must not leave the first one's tail behind;
 *   - odd-length data must not shift whatever record follows it (the format's
 *     padding rule — this is the only angle ring 3 has on record alignment);
 *   - a zero-length value, and the default (unnamed) value, are values, not
 *     absences;
 *   - a subtree's shape and its keys' names survive, including names that
 *     differ from a sibling only by case (the replay resolver must fold names
 *     through the same NLS table every syscall uses, never a second one);
 *   - a RENAMED key is saved under its new name only.
 *
 * All of it is ordinary oracle-green: the pinned Wine round-trips the same
 * semantics through its own (text) hive format, so nothing here is
 * beyond_oracle. Cases that need NtRestoreKey or NtSetInformationKey — which
 * the oracle does not implement — live in restore_setinfo.c instead.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtLoadKey(const OBJECT_ATTRIBUTES *, OBJECT_ATTRIBUTES *);
NTSYSAPI NTSTATUS NTAPI NtSaveKey(HANDLE, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtRenameKey(HANDLE, UNICODE_STRING *);

static const void *src_path = W("\\Registry\\Machine\\Software\\prsk_phv2_src");
static const void *dst_path = W("\\Registry\\Machine\\Software\\prsk_phv2_dst");
static const void *hive_file = W("\\??\\C:\\prsk_phv2.hiv");

/* Read one value's type + data. Returns FALSE if the value is not there.
 * `bytes` is in/out: in = buffer capacity, out = data length. */
static BOOLEAN query_value(HANDLE key, const void *valueName, ULONG *type, void *data, ULONG *bytes)
{
    UNICODE_STRING name;
    UCHAR buffer[512];
    ULONG len = 0;
    reg_kv_partial_info *info = (reg_kv_partial_info *)buffer;
    init_ustr(&name, valueName);
    if (!NT_SUCCESS(
            NtQueryValueKey(key, &name, KV_PARTIAL_INFO_CLASS, buffer, sizeof(buffer), &len)))
        return FALSE;
    if (info->data_length > *bytes)
        return FALSE;
    *type = info->type;
    *bytes = info->data_length;
    memcpy(data, info->data, info->data_length);
    return TRUE;
}

/* Number of subkeys of an open key. */
static ULONG subkey_count(HANDLE key)
{
    UCHAR buffer[512];
    ULONG len = 0;
    reg_key_full_info *info = (reg_key_full_info *)buffer;
    if (!NT_SUCCESS(NtQueryKey(key, KEY_FULL_INFO_CLASS, buffer, sizeof(buffer), &len)))
        return 0xffffffffu;
    return info->sub_keys;
}

START_TEST(save_load_delta)
{
    UNICODE_STRING name, fileName;
    OBJECT_ATTRIBUTES attr, fileAttr;
    HANDLE src, dst, sub, file, software;
    NTSTATUS status;
    UCHAR data[512];
    ULONG type, bytes, val;

    reg_ensure_software();
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_phv2_src\\gamma\\deep"));
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_phv2_src\\alpha"));
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_phv2_src\\Beta"));
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_phv2_src\\beta"));
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_phv2_src\\gamma"));
    reg_delete_path(src_path);
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_phv2_dst\\gamma\\deep"));
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_phv2_dst\\alpha"));
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_phv2_dst\\Beta"));
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_phv2_dst\\beta"));
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_phv2_dst\\gamma"));
    reg_delete_path(dst_path);
    delete_file(hive_file);

    status = set_privilege(PRSK_SE_BACKUP_PRIVILEGE, TRUE);
    ok(status == STATUS_SUCCESS, "enable SeBackup -> %08lx", (unsigned long)status);
    status = set_privilege(PRSK_SE_RESTORE_PRIVILEGE, TRUE);
    ok(status == STATUS_SUCCESS, "enable SeRestore -> %08lx", (unsigned long)status);

    /* --- build a subtree whose HISTORY differs from its CONTENT ------------ */
    status = reg_create_path(src_path, &src, NULL);
    ok(status == STATUS_SUCCESS, "create src -> %08lx", (unsigned long)status);

    /* set then delete: the deletion is the point. */
    val = 0xdeadbeef;
    ok(reg_set(src, W("gone"), REG_DWORD, &val, sizeof(val)) == STATUS_SUCCESS, "set gone");
    val = 0x2;
    ok(reg_set(src, W("kept"), REG_DWORD, &val, sizeof(val)) == STATUS_SUCCESS, "set kept");
    init_ustr(&name, W("gone"));
    status = NtDeleteValueKey(src, &name);
    ok(status == STATUS_SUCCESS, "delete gone -> %08lx", (unsigned long)status);

    /* set twice, second one SHORTER: no tail of the first may survive. */
    memset(data, 0xaa, 32);
    ok(reg_set(src, W("shrink"), REG_BINARY, data, 32) == STATUS_SUCCESS, "set shrink long");
    memset(data, 0x5b, 4);
    ok(reg_set(src, W("shrink"), REG_BINARY, data, 4) == STATUS_SUCCESS, "set shrink short");

    /* the default (unnamed) value is a value. */
    ok(reg_set(src, W(""), REG_SZ, W("dflt"), 5 * sizeof(WCHAR)) == STATUS_SUCCESS, "set default");

    /* odd data lengths, each FOLLOWED by another value, so a padding slip
     * shifts the next one rather than being invisible. */
    memset(data, 0x11, 1);
    ok(reg_set(src, W("odd1"), REG_BINARY, data, 1) == STATUS_SUCCESS, "set odd1");
    memset(data, 0x33, 3);
    ok(reg_set(src, W("odd3"), REG_BINARY, data, 3) == STATUS_SUCCESS, "set odd3");
    memset(data, 0x77, 7);
    ok(reg_set(src, W("odd7"), REG_BINARY, data, 7) == STATUS_SUCCESS, "set odd7");
    val = 0xabcd1234;
    ok(reg_set(src, W("after_odd"), REG_DWORD, &val, sizeof(val)) == STATUS_SUCCESS, "set after");

    /* a zero-length value of a type that is not REG_NONE. */
    ok(reg_set(src, W("empty"), REG_BINARY, data, 0) == STATUS_SUCCESS, "set empty");

    /* --- children, including two differing only by case ------------------- */
    ok(reg_create_sub(src, W("alpha"), &sub, NULL) == STATUS_SUCCESS, "create alpha");
    val = 1;
    ok(reg_set(sub, W("v"), REG_DWORD, &val, sizeof(val)) == STATUS_SUCCESS, "set alpha v");
    NtClose(sub);
    ok(reg_create_sub(src, W("Beta"), &sub, NULL) == STATUS_SUCCESS, "create Beta");
    val = 2;
    /* two value names differing only by case are ONE value (the fold). */
    ok(reg_set(sub, W("Dup"), REG_DWORD, &val, sizeof(val)) == STATUS_SUCCESS, "set Dup");
    val = 3;
    ok(reg_set(sub, W("dUP"), REG_DWORD, &val, sizeof(val)) == STATUS_SUCCESS, "set dUP");
    NtClose(sub);
    ok(reg_create_sub(src, W("gamma"), &sub, NULL) == STATUS_SUCCESS, "create gamma");
    {
        HANDLE deep;
        ok(reg_create_sub(sub, W("deep"), &deep, NULL) == STATUS_SUCCESS, "create deep");
        val = 9;
        ok(reg_set(deep, W("d"), REG_DWORD, &val, sizeof(val)) == STATUS_SUCCESS, "set deep d");
        NtClose(deep);
    }
    NtClose(sub);

    /* --- save, then load the image at a DIFFERENT path --------------------- */
    status = open_hive_file(hive_file, GENERIC_WRITE, FILE_OVERWRITE_IF, &file);
    ok(status == STATUS_SUCCESS, "create hive file -> %08lx", (unsigned long)status);
    status = NtSaveKey(src, file);
    ok(status == STATUS_SUCCESS, "NtSaveKey -> %08lx", (unsigned long)status);
    NtClose(file);

    /* The destination is named RELATIVE to an open Software handle: the
     * absolute form trips the server's case-sensitive root lookup
     * (save_load.c carries the same note). */
    status = reg_open_path(W("\\Registry\\Machine\\Software"), &software);
    ok(status == STATUS_SUCCESS, "open Software -> %08lx", (unsigned long)status);
    init_ustr(&name, W("prsk_phv2_dst"));
    init_attr(&attr, software, &name, OBJ_CASE_INSENSITIVE);
    init_ustr(&fileName, hive_file);
    init_attr(&fileAttr, NULL, &fileName, OBJ_CASE_INSENSITIVE);
    status = NtLoadKey(&attr, &fileAttr);
    ok(status == STATUS_SUCCESS, "NtLoadKey -> %08lx", (unsigned long)status);

    status = reg_open_path(dst_path, &dst);
    ok(status == STATUS_SUCCESS, "open dst -> %08lx", (unsigned long)status);

    /* --- the deletion did not come back ------------------------------------ */
    bytes = sizeof(data);
    ok(!query_value(dst, W("gone"), &type, data, &bytes), "deleted value stayed deleted");
    bytes = sizeof(data);
    ok(query_value(dst, W("kept"), &type, data, &bytes) && type == REG_DWORD && bytes == 4 &&
           *(ULONG *)data == 2,
       "kept survived");

    /* --- the second write won, with no tail of the first -------------------- */
    bytes = sizeof(data);
    ok(query_value(dst, W("shrink"), &type, data, &bytes), "shrink present");
    ok(bytes == 4, "shrink is 4 bytes, got %lu", (unsigned long)bytes);
    ok(data[0] == 0x5b && data[3] == 0x5b, "shrink holds the SECOND write");

    /* --- the default value is a value --------------------------------------- */
    bytes = sizeof(data);
    ok(query_value(dst, W(""), &type, data, &bytes) && type == REG_SZ, "default value survived");

    /* --- odd lengths did not shift the value that follows -------------------- */
    bytes = sizeof(data);
    ok(query_value(dst, W("odd1"), &type, data, &bytes) && bytes == 1 && data[0] == 0x11, "odd1");
    bytes = sizeof(data);
    ok(query_value(dst, W("odd3"), &type, data, &bytes) && bytes == 3 && data[2] == 0x33, "odd3");
    bytes = sizeof(data);
    ok(query_value(dst, W("odd7"), &type, data, &bytes) && bytes == 7 && data[6] == 0x77, "odd7");
    bytes = sizeof(data);
    ok(query_value(dst, W("after_odd"), &type, data, &bytes) && type == REG_DWORD && bytes == 4 &&
           *(ULONG *)data == 0xabcd1234,
       "the value after the odd ones is intact");

    /* --- a zero-length value is present, not absent -------------------------- */
    bytes = sizeof(data);
    ok(query_value(dst, W("empty"), &type, data, &bytes) && type == REG_BINARY && bytes == 0,
       "zero-length value survived as a value");

    /* --- the subtree shape survived, at both levels --------------------------- */
    ok(subkey_count(dst) == 3, "dst has 3 subkeys, got %lu", (unsigned long)subkey_count(dst));
    status = reg_open_sub_access(dst, W("alpha"), KEY_ALL_ACCESS, &sub);
    ok(status == STATUS_SUCCESS, "open dst alpha -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(sub);
    /* opened case-insensitively: the name stored is "Beta", the lookup is folded. */
    status = reg_open_sub_access(dst, W("bEtA"), KEY_ALL_ACCESS, &sub);
    ok(status == STATUS_SUCCESS, "open dst Beta case-folded -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        bytes = sizeof(data);
        /* the two case-variant value names were ONE value; the last write won. */
        ok(query_value(sub, W("dup"), &type, data, &bytes) && bytes == 4 && *(ULONG *)data == 3,
           "case-variant value names collapsed to one, second write won");
        NtClose(sub);
    }
    status = reg_open_sub_access(dst, W("gamma"), KEY_ALL_ACCESS, &sub);
    ok(status == STATUS_SUCCESS, "open dst gamma -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        HANDLE deep;
        status = reg_open_sub_access(sub, W("deep"), KEY_ALL_ACCESS, &deep);
        ok(status == STATUS_SUCCESS, "open dst gamma\\deep -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            bytes = sizeof(data);
            ok(query_value(deep, W("d"), &type, data, &bytes) && *(ULONG *)data == 9,
               "grandchild value survived");
            NtClose(deep);
        }
        NtClose(sub);
    }

    /* --- a renamed key is saved under its NEW name only ---------------------- */
    ok(reg_create_sub(src, W("oldname"), &sub, NULL) == STATUS_SUCCESS, "create oldname");
    val = 7;
    ok(reg_set(sub, W("r"), REG_DWORD, &val, sizeof(val)) == STATUS_SUCCESS, "set r");
    init_ustr(&name, W("newname"));
    status = NtRenameKey(sub, &name);
    ok(status == STATUS_SUCCESS, "NtRenameKey -> %08lx", (unsigned long)status);
    NtClose(sub);

    delete_file(hive_file);
    status = open_hive_file(hive_file, GENERIC_WRITE, FILE_OVERWRITE_IF, &file);
    ok(status == STATUS_SUCCESS, "re-create hive file -> %08lx", (unsigned long)status);
    status = NtSaveKey(src, file);
    ok(status == STATUS_SUCCESS, "NtSaveKey after rename -> %08lx", (unsigned long)status);
    NtClose(file);

    reg_delete_path(dst_path);
    init_ustr(&name, W("prsk_phv2_dst2"));
    init_attr(&attr, software, &name, OBJ_CASE_INSENSITIVE);
    status = NtLoadKey(&attr, &fileAttr);
    ok(status == STATUS_SUCCESS, "NtLoadKey after rename -> %08lx", (unsigned long)status);
    status = reg_open_path(W("\\Registry\\Machine\\Software\\prsk_phv2_dst2"), &dst);
    ok(status == STATUS_SUCCESS, "open dst2 -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = reg_open_sub_access(dst, W("newname"), KEY_ALL_ACCESS, &sub);
        ok(status == STATUS_SUCCESS, "renamed key saved under its new name -> %08lx",
           (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(sub);
        status = reg_open_sub_access(dst, W("oldname"), KEY_ALL_ACCESS, &sub);
        ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "the old name is gone -> %08lx",
           (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(sub);
        NtClose(dst);
    }

    /* --- cleanup ------------------------------------------------------------- */
    NtClose(src);
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_phv2_src\\gamma\\deep"));
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_phv2_src\\alpha"));
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_phv2_src\\Beta"));
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_phv2_src\\gamma"));
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_phv2_src\\newname"));
    reg_delete_path(src_path);
    NtClose(software);
    delete_file(hive_file);
    set_privilege(PRSK_SE_BACKUP_PRIVILEGE, FALSE);
    set_privilege(PRSK_SE_RESTORE_PRIVILEGE, FALSE);
}
