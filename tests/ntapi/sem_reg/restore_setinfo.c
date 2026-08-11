/*
 * sem_reg/restore_setinfo.c — NtRestoreKey, NtReplaceKey,
 * NtSetInformationKey and NtQueryMultipleValueKey (CUI-7).
 *
 * All four are FIXME-success stubs on the pinned oracle
 * (dlls/ntdll/unix/registry.c), so the whole contract is pinned
 * beyond_oracle against Microsoft documentation (G5/G12 — an oracle
 * FIXME-success is an unbuilt oracle, never a spec):
 *
 *   - ZwSetInformationKey (wdm.h, learn.microsoft.com):
 *     KeyWriteTimeInformation (KEY_SET_INFORMATION_CLASS value 0) takes a
 *     KEY_WRITE_TIME_INFORMATION { LARGE_INTEGER LastWriteTime } and sets
 *     the key's last-write time, observable through NtQueryKey
 *     KeyBasicInformation; the handle needs KEY_SET_VALUE. A wrong length
 *     is STATUS_INFO_LENGTH_MISMATCH, an unknown class
 *     STATUS_INVALID_INFO_CLASS.
 *   - NtQueryMultipleValueKey (winternl.h, learn.microsoft.com; signature
 *     as the pinned Wine's winternl.h spells it — buffer length by value,
 *     required length out): each entry names a value; on success the
 *     entries' Type/DataLength/DataOffset are filled and the data packed
 *     into the shared buffer; a too-small buffer is STATUS_BUFFER_OVERFLOW
 *     with the required length still reported; an unknown value name is
 *     STATUS_OBJECT_NAME_NOT_FOUND; the handle needs KEY_QUERY_VALUE.
 *   - ZwRestoreKey (wdm.h, learn.microsoft.com): needs SeRestorePrivilege
 *     (STATUS_PRIVILEGE_NOT_HELD otherwise); replaces the key's values and
 *     subtree with the hive file's content. Unsupported flags refuse with
 *     STATUS_INVALID_PARAMETER. proskrnl-recorded arms (docs/03 "CUI-7"):
 *     an open handle anywhere under the target refuses CANNOT_DELETE.
 *   - ZwReplaceKey (wdm.h, learn.microsoft.com): needs SeRestorePrivilege;
 *     the target must be the root of a hive — proskrnl has no replaceable
 *     file-backed hive roots at all, so after the privilege gate every key
 *     answers the documented not-a-hive-root refusal
 *     STATUS_INVALID_PARAMETER (docs/03 "CUI-7").
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtRestoreKey(HANDLE, HANDLE, ULONG);
NTSYSAPI NTSTATUS NTAPI NtReplaceKey(POBJECT_ATTRIBUTES, HANDLE, POBJECT_ATTRIBUTES);
/* NtSetInformationKey/NtQueryMultipleValueKey come from mingw's winternl.h.
 * mingw spells NtQueryMultipleValueKey with the wdm shape (BufferLength by
 * POINTER); the pinned Wine's winternl.h — the shape its PE ntdll thunks
 * and therefore the kernel's ABI — passes it by VALUE with the required
 * length out in the last argument. Call through a cast so the test speaks
 * the Wine ABI on both sides. */
typedef NTSTATUS NTAPI qmvk_wine_fn(HANDLE, PVOID, ULONG, PVOID, ULONG, PULONG);
#define NtQueryMultipleValueKeyWine ((qmvk_wine_fn *)(void *)NtQueryMultipleValueKey)
NTSYSAPI NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
                                    const void *, ULONG, PLARGE_INTEGER, PULONG);
NTSYSAPI NTSTATUS NTAPI NtSaveKey(HANDLE, HANDLE);
/* set_privilege(), open_hive_file(), delete_file() and the PRSK_SE_* LUIDs
 * live in util.h — three sem_reg suites use them. */

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif

/* KEY_SET_INFORMATION_CLASS value and record shape, hand-typed from
 * "ZwSetInformationKey function (wdm.h)" + "KEY_SET_INFORMATION_CLASS
 * (wdm.h)", learn.microsoft.com (absent from the pinned Wine tree). */
#define KEY_WRITE_TIME_INFO_CLASS 0

/* KEY_MULTIPLE_VALUE_INFORMATION, snake_case local mirror (winternl.h). */
typedef struct
{
    UNICODE_STRING *value_name;
    ULONG data_length;
    ULONG data_offset;
    ULONG type;
} multi_value_entry;

static const void *base_path = W("\\Registry\\Machine\\Software\\prsk_m8_restore");
static const void *hive_file = W("\\??\\C:\\prsk_m8r.hiv");



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

START_TEST(restore_setinfo)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE base, sub, file;
    NTSTATUS status;
    ULONG val;

    reg_ensure_software();
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_m8_restore\\keep"));
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_m8_restore\\extra"));
    reg_delete_path(base_path);
    delete_file(hive_file);

    status = reg_create_path(base_path, &base, NULL);
    ok(status == STATUS_SUCCESS, "create base -> %08lx", (unsigned long)status);
    val = 1;
    status = reg_set(base, W("marker"), REG_DWORD, &val, sizeof(val));
    ok(status == STATUS_SUCCESS, "set marker -> %08lx", (unsigned long)status);
    val = 100;
    status = reg_set(base, W("num"), REG_DWORD, &val, sizeof(val));
    ok(status == STATUS_SUCCESS, "set num -> %08lx", (unsigned long)status);
    status = reg_set(base, W("txt"), REG_SZ, W("ab\0"), 6);
    ok(status == STATUS_SUCCESS, "set txt -> %08lx", (unsigned long)status);
    status = reg_create_sub(base, W("keep"), &sub, NULL);
    ok(status == STATUS_SUCCESS, "create keep -> %08lx", (unsigned long)status);
    NtClose(sub);

    /* ================= NtSetInformationKey ================================ */
    beyond_oracle
    {
        LONGLONG stamp = 131000000000000000LL; /* an arbitrary FILETIME */
        UCHAR small[4];
        status = NtSetInformationKey(base, KEY_WRITE_TIME_INFO_CLASS, &stamp, sizeof(stamp));
        ok(status == STATUS_SUCCESS, "set write time -> %08lx", (unsigned long)status);
        {
            UCHAR buffer[128];
            ULONG len;
            reg_key_basic_info *info = (reg_key_basic_info *)buffer;
            status = NtQueryKey(base, KEY_BASIC_INFO_CLASS, buffer, sizeof(buffer), &len);
            ok(status == STATUS_SUCCESS, "query key -> %08lx", (unsigned long)status);
            ok(info->last_write_time == stamp, "write time set (%llx)",
               (unsigned long long)info->last_write_time);
        }
        status = NtSetInformationKey(base, KEY_WRITE_TIME_INFO_CLASS, small, sizeof(small));
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "short write time -> %08lx",
           (unsigned long)status);
        status = NtSetInformationKey(base, 100, &stamp, sizeof(stamp));
        ok(status == STATUS_INVALID_INFO_CLASS, "unknown class -> %08lx", (unsigned long)status);
        {
            HANDLE readonly;
            UNICODE_STRING relName;
            OBJECT_ATTRIBUTES relAttr;
            init_ustr(&relName, W("keep"));
            init_attr(&relAttr, base, &relName, OBJ_CASE_INSENSITIVE);
            status = NtOpenKey(&readonly, KEY_QUERY_VALUE, &relAttr);
            ok(status == STATUS_SUCCESS, "open keep query-only -> %08lx", (unsigned long)status);
            status =
                NtSetInformationKey(readonly, KEY_WRITE_TIME_INFO_CLASS, &stamp, sizeof(stamp));
            ok(status == STATUS_ACCESS_DENIED, "no KEY_SET_VALUE -> %08lx", (unsigned long)status);
            NtClose(readonly);
        }
    }

    /* ================= NtQueryMultipleValueKey ============================ */
    beyond_oracle
    {
        multi_value_entry entries[2];
        UNICODE_STRING numName, txtName, missingName;
        UCHAR buffer[64];
        ULONG required;

        init_ustr(&numName, W("num"));
        init_ustr(&txtName, W("txt"));
        memset(entries, 0, sizeof(entries));
        entries[0].value_name = &numName;
        entries[1].value_name = &txtName;
        required = 0;
        status = NtQueryMultipleValueKeyWine(base, entries, 2, buffer, sizeof(buffer), &required);
        ok(status == STATUS_SUCCESS, "query multiple -> %08lx", (unsigned long)status);
        ok(entries[0].type == REG_DWORD && entries[0].data_length == 4, "num entry (%lu/%lu)",
           (unsigned long)entries[0].type, (unsigned long)entries[0].data_length);
        ok(entries[1].type == REG_SZ && entries[1].data_length == 6, "txt entry (%lu/%lu)",
           (unsigned long)entries[1].type, (unsigned long)entries[1].data_length);
        if (entries[0].data_offset + 4 <= sizeof(buffer))
        {
            ULONG num;
            memcpy(&num, buffer + entries[0].data_offset, 4);
            ok(num == 100, "num data (%lu)", (unsigned long)num);
        }
        if (entries[1].data_offset + 6 <= sizeof(buffer))
        {
            ok(memcmp(buffer + entries[1].data_offset, W("ab\0"), 6) == 0, "txt data");
        }
        ok(required >= 10, "required length (%lu)", (unsigned long)required);

        /* A too-small buffer overflows but still reports the requirement. */
        required = 0;
        status = NtQueryMultipleValueKeyWine(base, entries, 2, buffer, 4, &required);
        ok(status == STATUS_BUFFER_OVERFLOW, "small buffer -> %08lx", (unsigned long)status);
        ok(required >= 10, "required after overflow (%lu)", (unsigned long)required);

        /* Unknown value name. */
        init_ustr(&missingName, W("no_such_value"));
        entries[0].value_name = &missingName;
        status = NtQueryMultipleValueKeyWine(base, entries, 1, buffer, sizeof(buffer), &required);
        ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "missing value -> %08lx", (unsigned long)status);

        /* Access: KEY_QUERY_VALUE is required. */
        {
            HANDLE noQuery;
            UNICODE_STRING relName;
            OBJECT_ATTRIBUTES relAttr;
            init_ustr(&relName, W("keep"));
            init_attr(&relAttr, base, &relName, OBJ_CASE_INSENSITIVE);
            status = NtOpenKey(&noQuery, KEY_NOTIFY, &relAttr);
            ok(status == STATUS_SUCCESS, "open keep notify-only -> %08lx", (unsigned long)status);
            entries[0].value_name = &numName;
            status =
                NtQueryMultipleValueKey(noQuery, entries, 1, buffer, sizeof(buffer), &required);
            ok(status == STATUS_ACCESS_DENIED, "no KEY_QUERY_VALUE -> %08lx",
               (unsigned long)status);
            NtClose(noQuery);
        }
    }

    /* ================= NtRestoreKey ======================================= */
    beyond_oracle
    {
        /* Save the current state, mutate, then restore rolls it back. */
        status = open_hive_file(hive_file, GENERIC_WRITE, FILE_OVERWRITE_IF, &file);
        ok(status == STATUS_SUCCESS, "create hive file -> %08lx", (unsigned long)status);
        {
            NTSTATUS restoreStatus;
            /* Privilege disabled: restore refuses before touching anything. */
            restoreStatus = NtRestoreKey(base, file, 0);
            ok(restoreStatus == STATUS_PRIVILEGE_NOT_HELD, "restore without priv -> %08lx",
               (unsigned long)restoreStatus);
        }
        status = set_privilege(PRSK_SE_BACKUP_PRIVILEGE, TRUE);
        ok(status == STATUS_SUCCESS, "enable SeBackup -> %08lx", (unsigned long)status);
        status = set_privilege(PRSK_SE_RESTORE_PRIVILEGE, TRUE);
        ok(status == STATUS_SUCCESS, "enable SeRestore -> %08lx", (unsigned long)status);
        status = NtSaveKey(base, file);
        ok(status == STATUS_SUCCESS, "save -> %08lx", (unsigned long)status);
        NtClose(file);

        /* Mutate: change num, add extra value + subkey, delete keep. */
        val = 999;
        status = reg_set(base, W("num"), REG_DWORD, &val, sizeof(val));
        ok(status == STATUS_SUCCESS, "mutate num -> %08lx", (unsigned long)status);
        val = 5;
        status = reg_set(base, W("added"), REG_DWORD, &val, sizeof(val));
        ok(status == STATUS_SUCCESS, "add value -> %08lx", (unsigned long)status);
        status = reg_create_sub(base, W("extra"), &sub, NULL);
        ok(status == STATUS_SUCCESS, "add extra -> %08lx", (unsigned long)status);
        NtClose(sub);
        reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_m8_restore\\keep"));

        /* Unsupported flags refuse. */
        status = open_hive_file(hive_file, GENERIC_READ, FILE_OPEN, &file);
        ok(status == STATUS_SUCCESS, "open hive file -> %08lx", (unsigned long)status);
        status = NtRestoreKey(base, file, 0x1234);
        ok(status == STATUS_INVALID_PARAMETER, "bad flags -> %08lx", (unsigned long)status);

        /* An open handle under the target refuses (docs/03 "CUI-7"). */
        {
            HANDLE inner;
            UNICODE_STRING relName;
            OBJECT_ATTRIBUTES relAttr;
            init_ustr(&relName, W("extra"));
            init_attr(&relAttr, base, &relName, OBJ_CASE_INSENSITIVE);
            status = NtOpenKey(&inner, KEY_READ, &relAttr);
            ok(status == STATUS_SUCCESS, "open extra -> %08lx", (unsigned long)status);
            status = NtRestoreKey(base, file, 0);
            ok(status == STATUS_CANNOT_DELETE, "restore with open child -> %08lx",
               (unsigned long)status);
            NtClose(inner);
        }

        /* The restore proper: content rolled back to the saved snapshot. */
        status = NtRestoreKey(base, file, 0);
        ok(status == STATUS_SUCCESS, "restore -> %08lx", (unsigned long)status);
        NtClose(file);
        ok(query_dword(base, W("num")) == 100, "num rolled back");
        ok(query_dword(base, W("added")) == 0xffffffffu, "added gone");
        {
            HANDLE check;
            UNICODE_STRING relName;
            OBJECT_ATTRIBUTES relAttr;
            init_ustr(&relName, W("keep"));
            init_attr(&relAttr, base, &relName, OBJ_CASE_INSENSITIVE);
            status = NtOpenKey(&check, KEY_READ, &relAttr);
            ok(status == STATUS_SUCCESS, "keep restored -> %08lx", (unsigned long)status);
            if (NT_SUCCESS(status))
                NtClose(check);
            init_ustr(&relName, W("extra"));
            init_attr(&relAttr, base, &relName, OBJ_CASE_INSENSITIVE);
            status = NtOpenKey(&check, KEY_READ, &relAttr);
            ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "extra gone -> %08lx",
               (unsigned long)status);
        }
    }

    /* ================= NtReplaceKey ======================================= */
    beyond_oracle
    {
        UNICODE_STRING newName, oldName;
        OBJECT_ATTRIBUTES newAttr, oldAttr;
        init_ustr(&newName, hive_file);
        init_attr(&newAttr, NULL, &newName, OBJ_CASE_INSENSITIVE);
        init_ustr(&oldName, W("\\??\\C:\\prsk_m8r.old"));
        init_attr(&oldAttr, NULL, &oldName, OBJ_CASE_INSENSITIVE);

        status = set_privilege(PRSK_SE_RESTORE_PRIVILEGE, FALSE);
        ok(status == STATUS_SUCCESS, "disable SeRestore -> %08lx", (unsigned long)status);
        status = NtReplaceKey(&newAttr, base, &oldAttr);
        ok(status == STATUS_PRIVILEGE_NOT_HELD, "replace without priv -> %08lx",
           (unsigned long)status);
        status = set_privilege(PRSK_SE_RESTORE_PRIVILEGE, TRUE);
        ok(status == STATUS_SUCCESS, "re-enable SeRestore -> %08lx", (unsigned long)status);
        /* No proskrnl key is a replaceable hive root (docs/03 "CUI-7"). */
        status = NtReplaceKey(&newAttr, base, &oldAttr);
        ok(status == STATUS_INVALID_PARAMETER, "replace ordinary key -> %08lx",
           (unsigned long)status);
    }

    /* Cleanup. */
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_m8_restore\\keep"));
    reg_delete_path(W("\\Registry\\Machine\\Software\\prsk_m8_restore\\extra"));
    status = NtDeleteKey(base);
    (void)status;
    NtClose(base);
    reg_delete_path(base_path);
    delete_file(hive_file);
    set_privilege(PRSK_SE_BACKUP_PRIVILEGE, FALSE);
    set_privilege(PRSK_SE_RESTORE_PRIVILEGE, FALSE);
}
