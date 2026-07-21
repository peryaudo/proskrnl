/*
 * sem_se/util.h — shared helpers for the CUI-2 Se (token/security) tests.
 *
 * The oracle behaviour these tests pin is the COMBINATION of Wine's
 * PE-invisible unix layer (dlls/ntdll/unix/security.c: the retlen
 * pre-writes, the fixed-length table, the semi-stub classes) and wineserver
 * (server/token.c: the fixed admin identity, the privilege list, the ACE
 * walk; server/handle.c: magic token pseudo-handles; server/object.c: SD
 * defaulting). On proskrnl the PE thunk syscalls straight into the kernel,
 * which must reproduce the combined behaviour.
 *
 * The identity every test expects is wineserver's token_create_admin()
 * (server/token.c): user S-1-5-21-0-0-0-1000, owner/primary group
 * S-1-5-21-0-0-0-513 (Domain Users), 8 groups, 21 privileges, a 2-ACE
 * default DACL — deterministic on the oracle (security_unix_uid_to_sid
 * maps the server's own uid to local_user_sid unconditionally) and minted
 * identically by proskrnl's SeInitializeSecuritySubsystem.
 */
#ifndef NTAPI_SEM_SE_UTIL_H
#define NTAPI_SEM_SE_UTIL_H

#include "../ntapi.h"

/* char16_t (2-byte) string literal, as Wine's tests spell it. */
#define W(s) u##s

/* Prototypes winternl.h omits (declared as Wine's winternl.h defines them). */
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG,
                                          ULONG);
NTSYSAPI NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, EVENT_TYPE,
                                      BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtOpenEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI NtOpenProcessToken(HANDLE, DWORD, HANDLE *);
NTSYSAPI NTSTATUS NTAPI NtOpenProcessTokenEx(HANDLE, DWORD, DWORD, HANDLE *);
NTSYSAPI NTSTATUS NTAPI NtOpenThreadToken(HANDLE, DWORD, BOOLEAN, HANDLE *);
NTSYSAPI NTSTATUS NTAPI NtOpenThreadTokenEx(HANDLE, DWORD, BOOLEAN, DWORD, HANDLE *);
NTSYSAPI NTSTATUS NTAPI NtQueryInformationToken(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG,
                                                PULONG);
NTSYSAPI NTSTATUS NTAPI NtAdjustPrivilegesToken(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, DWORD,
                                                PTOKEN_PRIVILEGES, PDWORD);
NTSYSAPI NTSTATUS NTAPI NtDuplicateToken(HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN,
                                         TOKEN_TYPE, PHANDLE);
NTSYSAPI NTSTATUS NTAPI NtPrivilegeCheck(HANDLE, PPRIVILEGE_SET, PBOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtAccessCheck(PSECURITY_DESCRIPTOR, HANDLE, ACCESS_MASK, PGENERIC_MAPPING,
                                      PPRIVILEGE_SET, PULONG, PULONG, NTSTATUS *);
NTSYSAPI NTSTATUS NTAPI NtQuerySecurityObject(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
                                              ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtSetSecurityObject(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
NTSYSAPI NTSTATUS NTAPI NtAllocateLocallyUniqueId(PLUID);
NTSYSAPI NTSTATUS NTAPI RtlFormatCurrentUserKeyPath(PUNICODE_STRING);
NTSYSAPI void NTAPI RtlFreeUnicodeString(PUNICODE_STRING);

/* mingw's winternl.h omits the pseudo-handle macros; values as
 * wine/include/winternl.h + wine/include/processthreadsapi.h define them. */
#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif
#ifndef NtCurrentThread
#define NtCurrentThread() ((HANDLE) ~(ULONG_PTR)1)
#endif
#ifndef GetCurrentProcessToken
#define GetCurrentProcessToken() ((HANDLE) ~(ULONG_PTR)3)
#endif
#ifndef GetCurrentThreadToken
#define GetCurrentThreadToken() ((HANDLE) ~(ULONG_PTR)4)
#endif
#ifndef GetCurrentThreadEffectiveToken
#define GetCurrentThreadEffectiveToken() ((HANDLE) ~(ULONG_PTR)5)
#endif

/* mingw's user-mode headers omit a few object rights; values as in
 * wine/include/winnt.h. */
#ifndef EVENT_QUERY_STATE
#define EVENT_QUERY_STATE 0x0001
#endif
#ifndef EVENT_MODIFY_STATE
#define EVENT_MODIFY_STATE 0x0002
#endif

/* mingw's user-mode headers omit the numeric privilege LUID low parts (they
 * live in wine/include/winternl.h; wineserver's token_create_admin builds
 * the admin token from the same values — server/token.c). */
#ifndef SE_TCB_PRIVILEGE
#define SE_TCB_PRIVILEGE                 7
#define SE_SECURITY_PRIVILEGE            8
#define SE_TAKE_OWNERSHIP_PRIVILEGE      9
#define SE_LOAD_DRIVER_PRIVILEGE         10
#define SE_SYSTEM_PROFILE_PRIVILEGE      11
#define SE_SYSTEMTIME_PRIVILEGE          12
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE 13
#define SE_INC_BASE_PRIORITY_PRIVILEGE   14
#define SE_CREATE_PAGEFILE_PRIVILEGE     15
#define SE_INCREASE_QUOTA_PRIVILEGE      5
#define SE_BACKUP_PRIVILEGE              17
#define SE_RESTORE_PRIVILEGE             18
#define SE_SHUTDOWN_PRIVILEGE            19
#define SE_DEBUG_PRIVILEGE               20
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE  22
#define SE_CHANGE_NOTIFY_PRIVILEGE       23
#define SE_REMOTE_SHUTDOWN_PRIVILEGE     24
#define SE_UNDOCK_PRIVILEGE              25
#define SE_MANAGE_VOLUME_PRIVILEGE       28
#define SE_IMPERSONATE_PRIVILEGE         29
#define SE_CREATE_GLOBAL_PRIVILEGE       30
#endif

/* Flat fixed-capacity shapes castable to TOKEN_PRIVILEGES / PRIVILEGE_SET
 * (the real ones end in [ANYSIZE_ARRAY], making indexing past 0 formally
 * undefined; the layouts are identical, array at the same offset). */
typedef struct
{
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[8];
} tp_buf;
#define TP(buf) ((TOKEN_PRIVILEGES *)&(buf))

typedef struct
{
    DWORD PrivilegeCount;
    DWORD Control;
    LUID_AND_ATTRIBUTES Privilege[8];
} ps_buf;
#define PS(buf) ((PRIVILEGE_SET *)&(buf))

/* ---- the oracle's fixed identity (server/token.c) ----------------------- */

/* sid_bytes(count) — the on-wire size of a SID with `count` subauthorities. */
#define SID_BYTES(count) (8 + 4 * (count))

/* Compose a SID in `buf` from header-derived pieces; returns its length.
 * The authority/RID values all come from winnt.h macros — never retyped. */
static inline ULONG make_sid(void *buf, SID_IDENTIFIER_AUTHORITY auth, BYTE count,
                             const DWORD *subs)
{
    SID *sid = buf;
    BYTE i;
    sid->Revision = SID_REVISION;
    sid->SubAuthorityCount = count;
    sid->IdentifierAuthority = auth;
    for (i = 0; i < count; i++)
        sid->SubAuthority[i] = subs[i];
    return SID_BYTES(count);
}

static inline ULONG sid_size(const void *sid)
{
    return SID_BYTES(((const SID *)sid)->SubAuthorityCount);
}

static inline int equal_sid(const void *a, const void *b)
{
    return sid_size(a) == sid_size(b) && memcmp(a, b, sid_size(a)) == 0;
}

/* The boot identity's SIDs, composed exactly as server/token.c spells them. */
typedef struct
{
    BYTE buf[SID_BYTES(8)];
} sid_buf;

static inline ULONG sid_world(sid_buf *out) /* S-1-1-0: Everyone */
{
    static const SID_IDENTIFIER_AUTHORITY auth = {SECURITY_WORLD_SID_AUTHORITY};
    static const DWORD subs[] = {SECURITY_WORLD_RID};
    return make_sid(out->buf, auth, 1, subs);
}

static inline ULONG sid_local(sid_buf *out) /* S-1-2-0: LOCAL */
{
    static const SID_IDENTIFIER_AUTHORITY auth = {SECURITY_LOCAL_SID_AUTHORITY};
    static const DWORD subs[] = {SECURITY_LOCAL_RID};
    return make_sid(out->buf, auth, 1, subs);
}

static inline ULONG sid_interactive(sid_buf *out) /* S-1-5-4 */
{
    static const SID_IDENTIFIER_AUTHORITY auth = {SECURITY_NT_AUTHORITY};
    static const DWORD subs[] = {SECURITY_INTERACTIVE_RID};
    return make_sid(out->buf, auth, 1, subs);
}

static inline ULONG sid_authenticated(sid_buf *out) /* S-1-5-11 */
{
    static const SID_IDENTIFIER_AUTHORITY auth = {SECURITY_NT_AUTHORITY};
    static const DWORD subs[] = {SECURITY_AUTHENTICATED_USER_RID};
    return make_sid(out->buf, auth, 1, subs);
}

static inline ULONG sid_local_system(sid_buf *out) /* S-1-5-18: SYSTEM */
{
    static const SID_IDENTIFIER_AUTHORITY auth = {SECURITY_NT_AUTHORITY};
    static const DWORD subs[] = {SECURITY_LOCAL_SYSTEM_RID};
    return make_sid(out->buf, auth, 1, subs);
}

static inline ULONG sid_local_user(sid_buf *out) /* S-1-5-21-0-0-0-1000 */
{
    static const SID_IDENTIFIER_AUTHORITY auth = {SECURITY_NT_AUTHORITY};
    static const DWORD subs[] = {SECURITY_NT_NON_UNIQUE, 0, 0, 0, 1000};
    return make_sid(out->buf, auth, 5, subs);
}

static inline ULONG sid_domain_users(sid_buf *out) /* S-1-5-21-0-0-0-513 */
{
    static const SID_IDENTIFIER_AUTHORITY auth = {SECURITY_NT_AUTHORITY};
    static const DWORD subs[] = {SECURITY_NT_NON_UNIQUE, 0, 0, 0, DOMAIN_GROUP_RID_USERS};
    return make_sid(out->buf, auth, 5, subs);
}

static inline ULONG sid_builtin_admins(sid_buf *out) /* S-1-5-32-544 */
{
    static const SID_IDENTIFIER_AUTHORITY auth = {SECURITY_NT_AUTHORITY};
    static const DWORD subs[] = {SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS};
    return make_sid(out->buf, auth, 2, subs);
}

static inline ULONG sid_builtin_users(sid_buf *out) /* S-1-5-32-545 */
{
    static const SID_IDENTIFIER_AUTHORITY auth = {SECURITY_NT_AUTHORITY};
    static const DWORD subs[] = {SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS};
    return make_sid(out->buf, auth, 2, subs);
}

static inline ULONG sid_logon(sid_buf *out) /* S-1-5-5-0-0 */
{
    static const SID_IDENTIFIER_AUTHORITY auth = {SECURITY_NT_AUTHORITY};
    static const DWORD subs[] = {SECURITY_LOGON_IDS_RID, 0, 0};
    return make_sid(out->buf, auth, 3, subs);
}

static inline ULONG sid_high_label(sid_buf *out) /* S-1-16-12288 */
{
    static const SID_IDENTIFIER_AUTHORITY auth = {SECURITY_MANDATORY_LABEL_AUTHORITY};
    static const DWORD subs[] = {SECURITY_MANDATORY_HIGH_RID};
    return make_sid(out->buf, auth, 1, subs);
}

/* ---- self-relative SD / ACL builders ------------------------------------ */

/* Append one ACCESS_ALLOWED/DENIED ACE (header + mask + SID) at `dst`;
 * returns the ACE size. Layout per winnt.h ACCESS_ALLOWED_ACE. */
static inline ULONG put_ace(void *dst, BYTE type, BYTE flags, ACCESS_MASK mask, const void *sid)
{
    ACE_HEADER *header = dst;
    ULONG size = 8 + sid_size(sid);
    header->AceType = type;
    header->AceFlags = flags;
    header->AceSize = (WORD)size;
    *(ACCESS_MASK *)((BYTE *)dst + 4) = mask;
    memcpy((BYTE *)dst + 8, sid, sid_size(sid));
    return size;
}

/* Write an ACL header for `total` bytes / `count` ACEs (ACEs follow). */
static inline void put_acl(void *dst, ULONG total, WORD count)
{
    ACL *acl = dst;
    acl->AclRevision = ACL_REVISION;
    acl->Sbz1 = 0;
    acl->AclSize = (WORD)total;
    acl->AceCount = count;
    acl->Sbz2 = 0;
}

/* Build a self-relative SD in `buf`: any of owner/group/dacl may be NULL
 * (dacl_present distinguishes "no DACL" from "empty DACL"). Returns the
 * total length. Layout per winnt.h SECURITY_DESCRIPTOR_RELATIVE. */
static inline ULONG build_sd(void *buf, const void *owner, const void *group, int dacl_present,
                             const void *dacl, ULONG dacl_len)
{
    SECURITY_DESCRIPTOR_RELATIVE *sd = buf;
    ULONG offset = sizeof(*sd);
    memset(sd, 0, sizeof(*sd));
    sd->Revision = SECURITY_DESCRIPTOR_REVISION;
    sd->Control = SE_SELF_RELATIVE;
    if (owner)
    {
        sd->Owner = offset;
        memcpy((BYTE *)buf + offset, owner, sid_size(owner));
        offset += sid_size(owner);
    }
    if (group)
    {
        sd->Group = offset;
        memcpy((BYTE *)buf + offset, group, sid_size(group));
        offset += sid_size(group);
    }
    if (dacl_present)
    {
        sd->Control |= SE_DACL_PRESENT;
        if (dacl)
        {
            sd->Dacl = offset;
            memcpy((BYTE *)buf + offset, dacl, dacl_len);
            offset += dacl_len;
        }
    }
    return offset;
}

/* Duplicate the current process token into an impersonation token (the shape
 * NtAccessCheck demands), at the given level. */
static inline NTSTATUS dup_impersonation(HANDLE src, SECURITY_IMPERSONATION_LEVEL level,
                                         HANDLE *out)
{
    SECURITY_QUALITY_OF_SERVICE qos;
    OBJECT_ATTRIBUTES attr;
    qos.Length = sizeof(qos);
    qos.ImpersonationLevel = level;
    qos.ContextTrackingMode = 0; /* SECURITY_STATIC_TRACKING */
    qos.EffectiveOnly = FALSE;
    memset(&attr, 0, sizeof(attr));
    attr.Length = sizeof(attr);
    attr.SecurityQualityOfService = &qos;
    return NtDuplicateToken(src, 0, &attr, FALSE, TokenImpersonation, out);
}

#endif /* NTAPI_SEM_SE_UTIL_H */
