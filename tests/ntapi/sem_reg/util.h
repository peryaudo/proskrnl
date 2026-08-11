/*
 * sem_reg/util.h — shared helpers for the M8 registry (Cm) tests.
 *
 * Same pattern as sem_ob/util.h: wide literals are u"..." (char16_t),
 * UNICODE_STRING/OBJECT_ATTRIBUTES are filled by hand, and the tests use
 * their own snake_case result structs whose layout matches the contract
 * byte-for-byte (static_assert-checked in proskrnl mode), so one definition
 * serves both build modes.
 *
 * All tests operate under \Registry\Machine\Software\<prsk_m8_*> and delete
 * everything they created before exiting, so an oracle run leaves the Wine
 * prefix's registry as it found it.
 */
#ifndef NTAPI_SEM_REG_UTIL_H
#define NTAPI_SEM_REG_UTIL_H

#include "../ntapi.h"

/* char16_t (2-byte) string literal, as Wine's tests spell it. */
#define W(s) u##s

/* Prototypes exactly as wine/include/winternl.h declares them; mingw's
 * winternl.h omits most of the registry set. Enum-typed class parameters are
 * declared ULONG here so the declarations do not depend on which enums each
 * toolchain's winternl.h happens to define; the calling convention and
 * argument sizes are identical. */
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtCreateKey(PHANDLE, ACCESS_MASK, const OBJECT_ATTRIBUTES *, ULONG,
                                    const UNICODE_STRING *, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtOpenKey(PHANDLE, ACCESS_MASK, const OBJECT_ATTRIBUTES *);
NTSYSAPI NTSTATUS NTAPI NtDeleteKey(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtDeleteValueKey(HANDLE, const UNICODE_STRING *);
NTSYSAPI NTSTATUS NTAPI NtSetValueKey(HANDLE, const UNICODE_STRING *, ULONG, ULONG, const void *,
                                      ULONG);
NTSYSAPI NTSTATUS NTAPI NtQueryValueKey(HANDLE, const UNICODE_STRING *, ULONG, void *, ULONG,
                                        ULONG *);
NTSYSAPI NTSTATUS NTAPI NtEnumerateKey(HANDLE, ULONG, ULONG, void *, ULONG, ULONG *);
NTSYSAPI NTSTATUS NTAPI NtEnumerateValueKey(HANDLE, ULONG, ULONG, void *, ULONG, ULONG *);
NTSYSAPI NTSTATUS NTAPI NtQueryKey(HANDLE, ULONG, void *, ULONG, ULONG *);
NTSYSAPI NTSTATUS NTAPI NtFlushKey(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtOpenProcessToken(HANDLE, DWORD, HANDLE *);
NTSYSAPI NTSTATUS NTAPI NtAdjustPrivilegesToken(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, DWORD,
                                                PTOKEN_PRIVILEGES, PDWORD);

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif

/* Privilege LUID values as wine server/token.c spells them (= winnt.h
 * SE_*_PRIVILEGE ordinals). NtSaveKey needs backup, the load/unload family
 * restore; both are disabled by default in the token. */
#define PRSK_SE_BACKUP_PRIVILEGE  17
#define PRSK_SE_RESTORE_PRIVILEGE 18

/* Info-class values as wine/include/winternl.h's KEY_INFORMATION_CLASS /
 * KEY_VALUE_INFORMATION_CLASS enums order them. */
#define KEY_BASIC_INFO_CLASS 0 /* KeyBasicInformation */
#define KEY_NODE_INFO_CLASS  1 /* KeyNodeInformation */
#define KEY_FULL_INFO_CLASS  2 /* KeyFullInformation */

#define KV_BASIC_INFO_CLASS   0 /* KeyValueBasicInformation */
#define KV_FULL_INFO_CLASS    1 /* KeyValueFullInformation */
#define KV_PARTIAL_INFO_CLASS 2 /* KeyValuePartialInformation */

/* mingw's user-mode headers may omit these; values as wine/include/winnt.h. */
#ifndef REG_OPTION_VOLATILE
#define REG_OPTION_VOLATILE 0x00000001
#endif
#ifndef REG_CREATED_NEW_KEY
#define REG_CREATED_NEW_KEY 0x00000001
#endif
#ifndef REG_OPENED_EXISTING_KEY
#define REG_OPENED_EXISTING_KEY 0x00000002
#endif

/* Result-buffer layouts, snake_case; the
 * headers of the variable-size structs (everything before the trailing
 * name/data array) as wine/include/winternl.h defines them. */
typedef struct
{
    LONGLONG last_write_time;
    ULONG title_index;
    ULONG name_length;
    WCHAR name[1];
} reg_key_basic_info;

typedef struct
{
    LONGLONG last_write_time;
    ULONG title_index;
    ULONG class_offset;
    ULONG class_length;
    ULONG sub_keys;
    ULONG max_name_len;
    ULONG max_class_len;
    ULONG values;
    ULONG max_value_name_len;
    ULONG max_value_data_len;
    WCHAR class_name[1];
} reg_key_full_info;

typedef struct
{
    ULONG title_index;
    ULONG type;
    ULONG name_length;
    WCHAR name[1];
} reg_kv_basic_info;

typedef struct
{
    ULONG title_index;
    ULONG type;
    ULONG data_offset;
    ULONG data_length;
    ULONG name_length;
    WCHAR name[1];
} reg_kv_full_info;

typedef struct
{
    ULONG title_index;
    ULONG type;
    ULONG data_length;
    UCHAR data[1];
} reg_kv_partial_info;

/* Fill a UNICODE_STRING over a NUL-terminated 2-byte-unit string. */
static inline void init_ustr(UNICODE_STRING *str, const void *wide)
{
    const unsigned short *p = (const unsigned short *)wide;
    unsigned len = 0;
    while (p[len])
        len++;
    str->Length = (USHORT)(len * 2);
    str->MaximumLength = (USHORT)(len * 2 + 2);
    str->Buffer = (PWSTR)(void *)p;
}

/* Fill OBJECT_ATTRIBUTES; ntdll conventionally passes OBJ_CASE_INSENSITIVE. */
static inline void init_attr(OBJECT_ATTRIBUTES *attr, HANDLE root, UNICODE_STRING *name,
                             ULONG flags)
{
    attr->Length = sizeof(*attr);
    attr->RootDirectory = root;
    attr->ObjectName = name;
    attr->Attributes = flags;
    attr->SecurityDescriptor = NULL;
    attr->SecurityQualityOfService = NULL;
}

/* Create (or open, OPENIF-style) a key by absolute path. */
static inline NTSTATUS reg_create_path(const void *path, HANDLE *out, ULONG *disposition)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    init_ustr(&name, path);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    return NtCreateKey(out, KEY_ALL_ACCESS, &attr, 0, NULL, 0, disposition);
}

/* Create (or open) a subkey relative to an open key handle. */
static inline NTSTATUS reg_create_sub(HANDLE root, const void *sub, HANDLE *out, ULONG *disposition)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    init_ustr(&name, sub);
    init_attr(&attr, root, &name, OBJ_CASE_INSENSITIVE);
    return NtCreateKey(out, KEY_ALL_ACCESS, &attr, 0, NULL, 0, disposition);
}

/* Open a key by absolute path. */
/* reg_open_path with an explicit DesiredAccess. */
static inline NTSTATUS reg_open_path_access(const void *path, ACCESS_MASK access, HANDLE *out)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    init_ustr(&name, path);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    *out = NULL;
    return NtOpenKey(out, access, &attr);
}

/* Open a subkey relative to an open key handle, with an explicit
 * DesiredAccess — the read-only twin of reg_create_sub. */
static inline NTSTATUS reg_open_sub_access(HANDLE root, const void *sub, ACCESS_MASK access,
                                           HANDLE *out)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    init_ustr(&name, sub);
    init_attr(&attr, root, &name, OBJ_CASE_INSENSITIVE);
    *out = NULL;
    return NtOpenKey(out, access, &attr);
}

static inline NTSTATUS reg_open_path(const void *path, HANDLE *out)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    init_ustr(&name, path);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    return NtOpenKey(out, KEY_ALL_ACCESS, &attr);
}

/* Set a named value on an open key. */
static inline NTSTATUS reg_set(HANDLE key, const void *valueName, ULONG type, const void *data,
                               ULONG bytes)
{
    UNICODE_STRING name;
    init_ustr(&name, valueName);
    return NtSetValueKey(key, &name, 0, type, data, bytes);
}

/* Ensure \Registry\Machine\Software exists. Every real registry has it; a
 * fresh (first-boot) proskrnl one does not, and NtCreateKey creates only the
 * last path component — so each test opens-or-creates its parent first. */
static inline void reg_ensure_software(void)
{
    HANDLE key;
    if (NT_SUCCESS(reg_create_path(W("\\Registry\\Machine\\Software"), &key, NULL)))
        NtClose(key);
}

/* Delete the subkey <sub> of <root> (opens it, deletes, closes). */
static inline void reg_delete_sub(HANDLE root, const void *sub)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE key;
    init_ustr(&name, sub);
    init_attr(&attr, root, &name, OBJ_CASE_INSENSITIVE);
    if (NT_SUCCESS(NtOpenKey(&key, KEY_ALL_ACCESS, &attr)))
    {
        NtDeleteKey(key);
        NtClose(key);
    }
}

/* Delete the key at <path> (opens it, deletes, closes). */
static inline void reg_delete_path(const void *path)
{
    HANDLE key;
    if (NT_SUCCESS(reg_open_path(path, &key)))
    {
        NtDeleteKey(key);
        NtClose(key);
    }
}

/* Enable or disable one privilege in the process token. The hive-file
 * syscalls (NtSaveKey, the NtLoadKey family, NtUnloadKey) refuse with
 * STATUS_PRIVILEGE_NOT_HELD until their privilege is enabled. */
static inline NTSTATUS set_privilege(DWORD luidLow, BOOLEAN enable)
{
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    NTSTATUS status =
        NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);
    if (!NT_SUCCESS(status))
        return status;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid.LowPart = luidLow;
    tp.Privileges[0].Luid.HighPart = 0;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
    status = NtAdjustPrivilegesToken(token, FALSE, &tp, 0, NULL, NULL);
    NtClose(token);
    return status;
}

/* Open (or create) a hive image file by NT path, synchronously. */
static inline NTSTATUS open_hive_file(const void *path, ACCESS_MASK access, ULONG disposition,
                                      HANDLE *out)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    init_ustr(&name, path);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    return NtCreateFile(out, access | SYNCHRONIZE, &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
                        disposition, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL,
                        0);
}

/* Delete a file by NT path, if it is there (delete-on-close). */
static inline void delete_file(const void *path)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    init_ustr(&name, path);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    if (NT_SUCCESS(NtCreateFile(
            &handle, DELETE | SYNCHRONIZE, &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN,
            FILE_DELETE_ON_CLOSE | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL,
            0)))
        NtClose(handle);
}

#endif /* NTAPI_SEM_REG_UTIL_H */
