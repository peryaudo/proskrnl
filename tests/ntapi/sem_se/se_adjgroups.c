/*
 * sem_se/se_adjgroups.c — NtAdjustGroupsToken and
 * NtImpersonateAnonymousToken (CUI-6, Se-2).
 *
 * Both are stubs on the pinned oracle (dlls/ntdll/unix/security.c
 * NtAdjustGroupsToken / NtImpersonateAnonymousToken: FIXME +
 * STATUS_NOT_IMPLEMENTED), so the whole contract is pinned beyond_oracle
 * against Microsoft documentation:
 *
 *   - AdjustTokenGroups (learn.microsoft.com): a group with SE_GROUP_MANDATORY
 *     cannot be disabled — the call fails STATUS_CANT_DISABLE_MANDATORY;
 *     ResetToDefault restores the default enabled state; the previous-state
 *     buffer follows the AdjustTokenPrivileges protocol (a short buffer is
 *     STATUS_BUFFER_TOO_SMALL with the required length). Needs
 *     TOKEN_ADJUST_GROUPS.
 *   - ImpersonateAnonymousToken (learn.microsoft.com) + WELL_KNOWN_SID
 *     WinAnonymousSid (S-1-5-7): the thread impersonates a token whose user
 *     is ANONYMOUS LOGON; RevertToSelf clears it.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtAdjustGroupsToken(HANDLE, BOOLEAN, PTOKEN_GROUPS, ULONG, PTOKEN_GROUPS,
                                            PULONG);
NTSYSAPI NTSTATUS NTAPI NtImpersonateAnonymousToken(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtSetInformationThread(HANDLE, THREADINFOCLASS, PVOID, ULONG);

#ifndef ThreadImpersonationToken
#define ThreadImpersonationToken ((THREADINFOCLASS)5)
#endif
#ifndef STATUS_CANT_DISABLE_MANDATORY
#define STATUS_CANT_DISABLE_MANDATORY ((NTSTATUS)0xC000005D)
#endif

typedef struct
{
    DWORD GroupCount;
    SID_AND_ATTRIBUTES Groups[2];
    BYTE storage[64];
} tg_one;

START_TEST(se_adjgroups)
{
    NTSTATUS status;
    HANDLE token = NULL;

    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_GROUPS | TOKEN_QUERY, &token);
    ok(status == STATUS_SUCCESS, "open token -> %08lx", (unsigned long)status);
    if (token == NULL)
    {
        skip("no process token");
        return;
    }

    beyond_oracle
    {
        /* --- disabling a mandatory group fails --------------------------- */
        tg_one disable;
        memset(&disable, 0, sizeof(disable));
        disable.GroupCount = 1;
        ULONG worldLen = sid_world((sid_buf *)disable.storage);
        (void)worldLen;
        disable.Groups[0].Sid = disable.storage;
        disable.Groups[0].Attributes = 0; /* clear ENABLED -> disable */
        status = NtAdjustGroupsToken(token, FALSE, (PTOKEN_GROUPS)&disable, 0, NULL, NULL);
        ok(status == STATUS_CANT_DISABLE_MANDATORY, "disable mandatory group -> %08lx",
           (unsigned long)status);

        /* --- ResetToDefault succeeds ------------------------------------- */
        status = NtAdjustGroupsToken(token, TRUE, NULL, 0, NULL, NULL);
        ok(status == STATUS_SUCCESS, "reset to default -> %08lx", (unsigned long)status);

        /* --- enabling an already-enabled group is a no-op success -------- */
        tg_one enable;
        memset(&enable, 0, sizeof(enable));
        enable.GroupCount = 1;
        sid_world((sid_buf *)enable.storage);
        enable.Groups[0].Sid = enable.storage;
        enable.Groups[0].Attributes = SE_GROUP_ENABLED;
        status = NtAdjustGroupsToken(token, FALSE, (PTOKEN_GROUPS)&enable, 0, NULL, NULL);
        ok(status == STATUS_SUCCESS, "enable enabled group -> %08lx", (unsigned long)status);
    }

    /* --- NtImpersonateAnonymousToken --------------------------------------- */
    beyond_oracle
    {
        status = NtImpersonateAnonymousToken(NtCurrentThread());
        ok(status == STATUS_SUCCESS, "impersonate anonymous -> %08lx", (unsigned long)status);

        HANDLE threadToken = NULL;
        status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY, TRUE, &threadToken);
        ok(status == STATUS_SUCCESS, "open anonymous thread token -> %08lx", (unsigned long)status);
        if (threadToken != NULL)
        {
            BYTE userBuf[128];
            ULONG retlen = 0;
            status =
                NtQueryInformationToken(threadToken, TokenUser, userBuf, sizeof(userBuf), &retlen);
            ok(status == STATUS_SUCCESS, "query anonymous user -> %08lx", (unsigned long)status);
            TOKEN_USER *user = (TOKEN_USER *)userBuf;
            /* S-1-5-7 (ANONYMOUS LOGON). */
            sid_buf anon;
            SID_IDENTIFIER_AUTHORITY nt = {{0, 0, 0, 0, 0, 5}};
            DWORD subs[1] = {7};
            make_sid(anon.buf, nt, 1, subs);
            ok(equal_sid(user->User.Sid, anon.buf), "anonymous user is S-1-5-7");
            NtClose(threadToken);
        }

        /* Revert. */
        HANDLE none = NULL;
        status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &none,
                                        sizeof(none));
        ok(status == STATUS_SUCCESS, "revert -> %08lx", (unsigned long)status);
        threadToken = NULL;
        status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY, TRUE, &threadToken);
        ok(status == STATUS_NO_TOKEN, "no token after revert -> %08lx", (unsigned long)status);
    }

    NtClose(token);
}
