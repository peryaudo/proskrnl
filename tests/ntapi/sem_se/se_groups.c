/*
 * sem_se/se_groups.c — the variable-length identity classes: TokenGroups,
 * TokenLogonSid, TokenPrivileges, TokenDefaultDacl — exact content, order,
 * attributes, and the buffer/length protocol of each.
 *
 * Oracle: server/token.c token_create_admin (the 8-group / 21-privilege
 * admin identity, in list order) + dlls/ntdll/unix/security.c (the
 * TOKEN_GROUPS layout: attribute+pointer array first, SIDs packed after it,
 * each Sid pointer fixed up to the caller's buffer).
 */
#include "util.h"

/* group index -> (sid builder, attributes), exactly server/token.c
 * admin_groups[] order. */
#define GROUP_ATTRS (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY)

START_TEST(se_groups)
{
    NTSTATUS status;
    HANDLE token = NULL;
    ULONG retlen;

    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &token);
    ok(status == STATUS_SUCCESS, "open -> %08lx", (unsigned long)status);

    /* the expected group list */
    sid_buf expected[8];
    ULONG expected_len[8];
    DWORD expected_attrs[8];
    expected_len[0] = sid_world(&expected[0]);
    expected_attrs[0] = GROUP_ATTRS;
    expected_len[1] = sid_local(&expected[1]);
    expected_attrs[1] = GROUP_ATTRS;
    expected_len[2] = sid_interactive(&expected[2]);
    expected_attrs[2] = GROUP_ATTRS;
    expected_len[3] = sid_authenticated(&expected[3]);
    expected_attrs[3] = GROUP_ATTRS;
    expected_len[4] = sid_domain_users(&expected[4]);
    expected_attrs[4] = GROUP_ATTRS | SE_GROUP_OWNER;
    expected_len[5] = sid_builtin_admins(&expected[5]);
    expected_attrs[5] = GROUP_ATTRS | SE_GROUP_OWNER;
    expected_len[6] = sid_builtin_users(&expected[6]);
    expected_attrs[6] = GROUP_ATTRS;
    expected_len[7] = sid_logon(&expected[7]);
    expected_attrs[7] = GROUP_ATTRS | SE_GROUP_LOGON_ID;

    ULONG sid_total = 0;
    for (int i = 0; i < 8; i++)
        sid_total += expected_len[i];
    ULONG needed = FIELD_OFFSET(TOKEN_GROUPS, Groups[8]) + sid_total;

    /* --- probe with a too-small buffer: BUFFER_TOO_SMALL + needed size ---- */
    TOKEN_GROUPS probe;
    retlen = 0;
    status = NtQueryInformationToken(token, TokenGroups, &probe, sizeof(probe), &retlen);
    ok(status == STATUS_BUFFER_TOO_SMALL, "TokenGroups probe -> %08lx", (unsigned long)status);
    ok(retlen == needed, "TokenGroups needed %lu, expected %lu", (unsigned long)retlen,
       (unsigned long)needed);

    /* --- full read: count, order, attributes, SID bytes, pointer targets -- */
    BYTE buf[1024];
    TOKEN_GROUPS *groups = (TOKEN_GROUPS *)buf;
    retlen = 0;
    status = NtQueryInformationToken(token, TokenGroups, buf, sizeof(buf), &retlen);
    ok(status == STATUS_SUCCESS, "TokenGroups -> %08lx", (unsigned long)status);
    ok(retlen == needed, "TokenGroups retlen %lu", (unsigned long)retlen);
    ok(groups->GroupCount == 8, "GroupCount %lu", (unsigned long)groups->GroupCount);

    /* SIDs are packed immediately after the pointer array, in order */
    const BYTE *expect_sid_at = (const BYTE *)&groups->Groups[8];
    for (ULONG i = 0; i < groups->GroupCount && i < 8; i++)
    {
        ok(groups->Groups[i].Attributes == expected_attrs[i], "group %lu attributes %08lx",
           (unsigned long)i, (unsigned long)groups->Groups[i].Attributes);
        ok(equal_sid(groups->Groups[i].Sid, expected[i].buf), "group %lu SID mismatch",
           (unsigned long)i);
        ok((const BYTE *)groups->Groups[i].Sid == expect_sid_at,
           "group %lu Sid pointer not packed in order", (unsigned long)i);
        expect_sid_at += expected_len[i];
    }

    /* --- TokenLogonSid: just the SE_GROUP_LOGON_ID group ------------------ */
    ULONG logon_needed = FIELD_OFFSET(TOKEN_GROUPS, Groups[1]) + expected_len[7];
    retlen = 0;
    status = NtQueryInformationToken(token, TokenLogonSid, buf, sizeof(buf), &retlen);
    ok(status == STATUS_SUCCESS, "TokenLogonSid -> %08lx", (unsigned long)status);
    ok(retlen == logon_needed, "TokenLogonSid retlen %lu", (unsigned long)retlen);
    ok(groups->GroupCount == 1, "logon GroupCount %lu", (unsigned long)groups->GroupCount);
    ok(groups->Groups[0].Attributes == expected_attrs[7], "logon attributes %08lx",
       (unsigned long)groups->Groups[0].Attributes);
    ok(equal_sid(groups->Groups[0].Sid, expected[7].buf), "logon SID mismatch");

    /* --- TokenPrivileges: the 21-entry admin set, in list order ------------
     * server/token.c admin_privs[]: enabled-by-default = SeChangeNotify,
     * SeLoadDriver, SeImpersonate, SeCreateGlobal; enabled == default at
     * creation, so attrs are (ENABLED|ENABLED_BY_DEFAULT) or 0. */
    static const struct
    {
        DWORD luid_low;
        DWORD attrs;
    } expected_privs[21] = {
        {SE_CHANGE_NOTIFY_PRIVILEGE, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT},
        {SE_TCB_PRIVILEGE, 0},
        {SE_SECURITY_PRIVILEGE, 0},
        {SE_BACKUP_PRIVILEGE, 0},
        {SE_RESTORE_PRIVILEGE, 0},
        {SE_SYSTEMTIME_PRIVILEGE, 0},
        {SE_SHUTDOWN_PRIVILEGE, 0},
        {SE_REMOTE_SHUTDOWN_PRIVILEGE, 0},
        {SE_TAKE_OWNERSHIP_PRIVILEGE, 0},
        {SE_DEBUG_PRIVILEGE, 0},
        {SE_SYSTEM_ENVIRONMENT_PRIVILEGE, 0},
        {SE_SYSTEM_PROFILE_PRIVILEGE, 0},
        {SE_PROF_SINGLE_PROCESS_PRIVILEGE, 0},
        {SE_INC_BASE_PRIORITY_PRIVILEGE, 0},
        {SE_LOAD_DRIVER_PRIVILEGE, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT},
        {SE_CREATE_PAGEFILE_PRIVILEGE, 0},
        {SE_INCREASE_QUOTA_PRIVILEGE, 0},
        {SE_UNDOCK_PRIVILEGE, 0},
        {SE_MANAGE_VOLUME_PRIVILEGE, 0},
        {SE_IMPERSONATE_PRIVILEGE, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT},
        {SE_CREATE_GLOBAL_PRIVILEGE, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT},
    };
    ULONG privs_needed =
        FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges) + 21 * sizeof(LUID_AND_ATTRIBUTES);

    TOKEN_PRIVILEGES *privs = (TOKEN_PRIVILEGES *)buf;
    retlen = 0;
    status = NtQueryInformationToken(token, TokenPrivileges, buf, sizeof(buf), &retlen);
    ok(status == STATUS_SUCCESS, "TokenPrivileges -> %08lx", (unsigned long)status);
    ok(retlen == privs_needed, "TokenPrivileges retlen %lu", (unsigned long)retlen);
    ok(privs->PrivilegeCount == 21, "PrivilegeCount %lu", (unsigned long)privs->PrivilegeCount);
    for (ULONG i = 0; i < privs->PrivilegeCount && i < 21; i++)
    {
        ok(privs->Privileges[i].Luid.LowPart == expected_privs[i].luid_low &&
               privs->Privileges[i].Luid.HighPart == 0,
           "privilege %lu LUID %lu", (unsigned long)i,
           (unsigned long)privs->Privileges[i].Luid.LowPart);
        ok(privs->Privileges[i].Attributes == expected_privs[i].attrs,
           "privilege %lu attributes %08lx", (unsigned long)i,
           (unsigned long)privs->Privileges[i].Attributes);
    }

    /* short: the header fits but the array does not */
    retlen = 0;
    status = NtQueryInformationToken(token, TokenPrivileges, buf, privs_needed - 1, &retlen);
    ok(status == STATUS_BUFFER_TOO_SMALL, "short TokenPrivileges -> %08lx", (unsigned long)status);
    ok(retlen == privs_needed, "short TokenPrivileges retlen %lu", (unsigned long)retlen);

    /* --- TokenDefaultDacl: 2 ACCESS_ALLOWED aces, GENERIC_ALL --------------
     * server/token.c create_default_dacl( domain_users ): SYSTEM then the
     * user parameter (Domain Users for the admin token). */
    sid_buf system_sid, users_sid;
    ULONG system_len = sid_local_system(&system_sid);
    ULONG users_len = sid_domain_users(&users_sid);
    ULONG acl_len = sizeof(ACL) + 2 * 8 + system_len + users_len;
    ULONG dacl_needed = sizeof(TOKEN_DEFAULT_DACL) + acl_len;

    TOKEN_DEFAULT_DACL *dacl_info = (TOKEN_DEFAULT_DACL *)buf;
    retlen = 0;
    status = NtQueryInformationToken(token, TokenDefaultDacl, buf, sizeof(buf), &retlen);
    ok(status == STATUS_SUCCESS, "TokenDefaultDacl -> %08lx", (unsigned long)status);
    ok(retlen == dacl_needed, "TokenDefaultDacl retlen %lu, expected %lu", (unsigned long)retlen,
       (unsigned long)dacl_needed);
    ok(dacl_info->DefaultDacl == (PACL)(dacl_info + 1), "DefaultDacl pointer %p",
       dacl_info->DefaultDacl);

    ACL *acl = dacl_info->DefaultDacl;
    ok(acl->AclRevision == ACL_REVISION, "acl revision %u", acl->AclRevision);
    ok(acl->AclSize == acl_len, "acl size %u, expected %lu", acl->AclSize, (unsigned long)acl_len);
    ok(acl->AceCount == 2, "ace count %u", acl->AceCount);

    ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)(acl + 1);
    ok(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE, "ace 0 type %u", ace->Header.AceType);
    ok(ace->Mask == GENERIC_ALL, "ace 0 mask %08lx", (unsigned long)ace->Mask);
    ok(equal_sid(&ace->SidStart, system_sid.buf), "ace 0 SID not SYSTEM");

    ace = (ACCESS_ALLOWED_ACE *)((BYTE *)ace + ace->Header.AceSize);
    ok(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE, "ace 1 type %u", ace->Header.AceType);
    ok(ace->Mask == GENERIC_ALL, "ace 1 mask %08lx", (unsigned long)ace->Mask);
    ok(equal_sid(&ace->SidStart, users_sid.buf), "ace 1 SID not Domain Users");

    /* short: BUFFER_TOO_SMALL with the needed size */
    retlen = 0;
    status =
        NtQueryInformationToken(token, TokenDefaultDacl, buf, sizeof(TOKEN_DEFAULT_DACL), &retlen);
    ok(status == STATUS_BUFFER_TOO_SMALL, "short TokenDefaultDacl -> %08lx", (unsigned long)status);
    ok(retlen == dacl_needed, "short TokenDefaultDacl retlen %lu", (unsigned long)retlen);

    NtClose(token);
}
