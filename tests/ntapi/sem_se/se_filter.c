/*
 * sem_se/se_filter.c — NtFilterToken (CUI-6, Se-2).
 *
 * CreateRestrictedToken's back end. Oracle behaviour pinned from the pinned
 * tree (dlls/ntdll/unix/security.c NtFilterToken; server/token.c
 * filter_token / token_duplicate): the source handle needs TOKEN_DUPLICATE;
 * the result has the SAME type and level as the source; a group named in
 * SidsToDisable survives but as SE_GROUP_USE_FOR_DENY_ONLY (enabled bits
 * cleared); a privilege named in PrivilegesToDelete is dropped entirely;
 * the Flags and RestrictedSids arguments are ignored (the unix layer
 * FIXMEs them). The new handle carries the source handle's granted access.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtFilterToken(HANDLE, ULONG, PTOKEN_GROUPS, PTOKEN_PRIVILEGES,
                                      PTOKEN_GROUPS, PHANDLE);

/* Flat TOKEN_GROUPS with room for a few SIDs inline. */
typedef struct
{
    DWORD GroupCount;
    SID_AND_ATTRIBUTES Groups[4];
    BYTE sidStorage[4 * 32];
} tg_buf;

static BOOLEAN token_has_group(HANDLE token, const void *sid, ULONG *attrsOut)
{
    BYTE buf[1024];
    ULONG retlen = 0;
    if (NtQueryInformationToken(token, TokenGroups, buf, sizeof(buf), &retlen) != STATUS_SUCCESS)
        return FALSE;
    TOKEN_GROUPS *groups = (TOKEN_GROUPS *)buf;
    for (DWORD i = 0; i < groups->GroupCount; i++)
    {
        if (equal_sid(groups->Groups[i].Sid, sid))
        {
            if (attrsOut)
                *attrsOut = groups->Groups[i].Attributes;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN token_has_privilege(HANDLE token, DWORD luidLow)
{
    BYTE buf[1024];
    ULONG retlen = 0;
    if (NtQueryInformationToken(token, TokenPrivileges, buf, sizeof(buf), &retlen) !=
        STATUS_SUCCESS)
        return FALSE;
    TOKEN_PRIVILEGES *privs = (TOKEN_PRIVILEGES *)buf;
    for (DWORD i = 0; i < privs->PrivilegeCount; i++)
    {
        if (privs->Privileges[i].Luid.LowPart == luidLow && privs->Privileges[i].Luid.HighPart == 0)
            return TRUE;
    }
    return FALSE;
}

START_TEST(se_filter)
{
    NTSTATUS status;
    HANDLE token = NULL;

    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &token);
    ok(status == STATUS_SUCCESS, "open token -> %08lx", (unsigned long)status);
    if (token == NULL)
    {
        skip("no process token");
        return;
    }

    /* The boot token carries BUILTIN\\Administrators and SeChangeNotify. */
    sid_buf admins;
    sid_builtin_admins(&admins);
    ok(token_has_group(token, admins.buf, NULL), "source has the admins group");
    ok(token_has_privilege(token, SE_CHANGE_NOTIFY_PRIVILEGE), "source has SeChangeNotify");

    /* Disable admins, delete SeChangeNotify. */
    tg_buf disable;
    memset(&disable, 0, sizeof(disable));
    disable.GroupCount = 1;
    ULONG adminLen = sid_builtin_admins((sid_buf *)disable.sidStorage);
    disable.Groups[0].Sid = disable.sidStorage;
    disable.Groups[0].Attributes = 0;
    (void)adminLen;

    tp_buf del;
    memset(&del, 0, sizeof(del));
    del.PrivilegeCount = 1;
    del.Privileges[0].Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
    del.Privileges[0].Luid.HighPart = 0;
    del.Privileges[0].Attributes = 0;

    HANDLE filtered = NULL;
    status = NtFilterToken(token, 0, (PTOKEN_GROUPS)&disable, TP(del), NULL, &filtered);
    ok(status == STATUS_SUCCESS, "filter token -> %08lx", (unsigned long)status);
    if (filtered == NULL)
    {
        skip("no filtered token");
        NtClose(token);
        return;
    }

    /* Same type/level as the source (a primary token stays primary). */
    {
        TOKEN_TYPE type = 0;
        ULONG retlen = 0;
        status = NtQueryInformationToken(filtered, TokenType, &type, sizeof(type), &retlen);
        ok(status == STATUS_SUCCESS, "filtered type -> %08lx", (unsigned long)status);
        ok(type == TokenPrimary, "filtered token stays primary (%d)", type);
    }

    /* The disabled group survives but as USE_FOR_DENY_ONLY. */
    {
        ULONG attrs = 0;
        ok(token_has_group(filtered, admins.buf, &attrs), "filtered keeps the group");
        ok((attrs & SE_GROUP_USE_FOR_DENY_ONLY) != 0, "group is deny-only (%08lx)",
           (unsigned long)attrs);
        ok((attrs & SE_GROUP_ENABLED) == 0, "group no longer enabled (%08lx)",
           (unsigned long)attrs);
    }

    /* The deleted privilege is gone. */
    ok(!token_has_privilege(filtered, SE_CHANGE_NOTIFY_PRIVILEGE),
       "SeChangeNotify dropped from the filtered token");

    NtClose(filtered);
    NtClose(token);
}
