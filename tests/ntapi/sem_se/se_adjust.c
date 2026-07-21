/*
 * sem_se/se_adjust.c — NtAdjustPrivilegesToken: enable/disable/remove,
 * DisableAllPrivileges, the previous-state protocol (silent truncation,
 * never BUFFER_TOO_SMALL), STATUS_NOT_ALL_ASSIGNED, the ModifiedId bump,
 * and access enforcement.
 *
 * Oracle: dlls/ntdll/unix/security.c NtAdjustPrivilegesToken +
 * server/token.c adjust_token_privileges / token_adjust_privileges: an
 * unknown LUID sets STATUS_NOT_ALL_ASSIGNED but the walk continues; the
 * previous-state buffer receives only what fits (prev->PrivilegeCount and
 * *retlen describe the FIT, not the need); the modified id is re-allocated
 * on every adjust call, even a no-op.
 */
#include "util.h"

static void set_priv(tp_buf *tp, DWORD luid_low, DWORD attrs)
{
    tp->PrivilegeCount = 1;
    tp->Privileges[0].Luid.LowPart = luid_low;
    tp->Privileges[0].Luid.HighPart = 0;
    tp->Privileges[0].Attributes = attrs;
}

static NTSTATUS priv_enabled(HANDLE token, DWORD luid_low, BOOLEAN *enabled)
{
    ps_buf set;
    set.PrivilegeCount = 1;
    set.Control = PRIVILEGE_SET_ALL_NECESSARY;
    set.Privilege[0].Luid.LowPart = luid_low;
    set.Privilege[0].Luid.HighPart = 0;
    set.Privilege[0].Attributes = 0;
    return NtPrivilegeCheck(token, PS(set), enabled);
}

START_TEST(se_adjust)
{
    NTSTATUS status;
    HANDLE token = NULL;
    tp_buf in, prev;
    DWORD retlen;
    BOOLEAN enabled;

    /* NOTE: this test mutates the process token — isolated on both sides
     * (each oracle test exe gets a fresh admin token; each proskrnl test
     * process a fresh duplicate), restored anyway for hygiene. */
    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);
    ok(status == STATUS_SUCCESS, "open -> %08lx", (unsigned long)status);

    /* --- disable one privilege, observe, re-enable ------------------------ */
    set_priv(&in, SE_CHANGE_NOTIFY_PRIVILEGE, 0);
    status = NtAdjustPrivilegesToken(token, FALSE, TP(in), 0, NULL, NULL);
    ok(status == STATUS_SUCCESS, "disable -> %08lx", (unsigned long)status);
    status = priv_enabled(token, SE_CHANGE_NOTIFY_PRIVILEGE, &enabled);
    ok(status == STATUS_SUCCESS && !enabled, "still enabled after disable");

    /* previous state on re-enable: one entry, attrs = the disabled state */
    memset(&prev, 0, sizeof(prev));
    retlen = 0xdead;
    set_priv(&in, SE_CHANGE_NOTIFY_PRIVILEGE, SE_PRIVILEGE_ENABLED);
    status = NtAdjustPrivilegesToken(token, FALSE, TP(in), sizeof(prev), TP(prev), &retlen);
    ok(status == STATUS_SUCCESS, "re-enable -> %08lx", (unsigned long)status);
    ok(prev.PrivilegeCount == 1, "prev count %lu", (unsigned long)prev.PrivilegeCount);
    ok(retlen == FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges) + sizeof(LUID_AND_ATTRIBUTES),
       "prev retlen %lu", (unsigned long)retlen);
    ok(prev.Privileges[0].Luid.LowPart == SE_CHANGE_NOTIFY_PRIVILEGE, "prev luid %lu",
       (unsigned long)prev.Privileges[0].Luid.LowPart);
    /* it was disabled, but stays enabled-by-default */
    ok(prev.Privileges[0].Attributes == SE_PRIVILEGE_ENABLED_BY_DEFAULT, "prev attributes %08lx",
       (unsigned long)prev.Privileges[0].Attributes);
    status = priv_enabled(token, SE_CHANGE_NOTIFY_PRIVILEGE, &enabled);
    ok(status == STATUS_SUCCESS && enabled, "not re-enabled");

    /* --- unknown LUID: NOT_ALL_ASSIGNED, but the known one is applied ----- */
    in.PrivilegeCount = 2;
    in.Privileges[0].Luid.LowPart = 0x12345; /* not in any token */
    in.Privileges[0].Luid.HighPart = 0;
    in.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    in.Privileges[1].Luid.LowPart = SE_DEBUG_PRIVILEGE;
    in.Privileges[1].Luid.HighPart = 0;
    in.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
    status = NtAdjustPrivilegesToken(token, FALSE, TP(in), 0, NULL, NULL);
    ok(status == STATUS_NOT_ALL_ASSIGNED, "unknown luid -> %08lx", (unsigned long)status);
    status = priv_enabled(token, SE_DEBUG_PRIVILEGE, &enabled);
    ok(status == STATUS_SUCCESS && enabled, "SeDebug not applied despite NOT_ALL_ASSIGNED");

    /* --- previous-state truncation is silent -------------------------------
     * Adjust two privileges with room for only the header: count and retlen
     * describe what fit (nothing), the status stays SUCCESS. */
    in.PrivilegeCount = 2;
    in.Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
    in.Privileges[0].Luid.HighPart = 0;
    in.Privileges[0].Attributes = 0;
    in.Privileges[1].Luid.LowPart = SE_SHUTDOWN_PRIVILEGE;
    in.Privileges[1].Luid.HighPart = 0;
    in.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
    memset(&prev, 0, sizeof(prev));
    prev.PrivilegeCount = 0xdead;
    retlen = 0xdead;
    status = NtAdjustPrivilegesToken(token, FALSE, TP(in),
                                     FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges), TP(prev), &retlen);
    ok(status == STATUS_SUCCESS, "truncated prev -> %08lx", (unsigned long)status);
    ok(prev.PrivilegeCount == 0, "truncated prev count %lu", (unsigned long)prev.PrivilegeCount);
    ok(retlen == FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges), "truncated retlen %lu",
       (unsigned long)retlen);

    /* --- SE_PRIVILEGE_REMOVED shrinks the privilege list ------------------- */
    TOKEN_STATISTICS stats;
    ULONG qretlen;
    status = NtQueryInformationToken(token, TokenStatistics, &stats, sizeof(stats), &qretlen);
    ok(status == STATUS_SUCCESS, "stats -> %08lx", (unsigned long)status);
    ULONG count_before = stats.PrivilegeCount;
    LUID modified_before = stats.ModifiedId;

    set_priv(&in, SE_UNDOCK_PRIVILEGE, SE_PRIVILEGE_REMOVED);
    status = NtAdjustPrivilegesToken(token, FALSE, TP(in), 0, NULL, NULL);
    ok(status == STATUS_SUCCESS, "remove -> %08lx", (unsigned long)status);

    status = NtQueryInformationToken(token, TokenStatistics, &stats, sizeof(stats), &qretlen);
    ok(status == STATUS_SUCCESS, "stats(2) -> %08lx", (unsigned long)status);
    ok(stats.PrivilegeCount == count_before - 1, "count %lu -> %lu", (unsigned long)count_before,
       (unsigned long)stats.PrivilegeCount);

    /* every adjust call bumps ModifiedId */
    ok(stats.ModifiedId.LowPart != modified_before.LowPart ||
           stats.ModifiedId.HighPart != modified_before.HighPart,
       "ModifiedId not bumped by adjust");

    /* a removed privilege is now an unknown LUID */
    set_priv(&in, SE_UNDOCK_PRIVILEGE, SE_PRIVILEGE_ENABLED);
    status = NtAdjustPrivilegesToken(token, FALSE, TP(in), 0, NULL, NULL);
    ok(status == STATUS_NOT_ALL_ASSIGNED, "re-add removed -> %08lx", (unsigned long)status);

    /* --- DisableAllPrivileges ---------------------------------------------- */
    status = NtAdjustPrivilegesToken(token, TRUE, NULL, 0, NULL, NULL);
    ok(status == STATUS_SUCCESS, "disable all -> %08lx", (unsigned long)status);
    status = priv_enabled(token, SE_CHANGE_NOTIFY_PRIVILEGE, &enabled);
    ok(status == STATUS_SUCCESS && !enabled, "SeChangeNotify survived disable-all");
    status = priv_enabled(token, SE_IMPERSONATE_PRIVILEGE, &enabled);
    ok(status == STATUS_SUCCESS && !enabled, "SeImpersonate survived disable-all");

    /* restore the boot defaults for hygiene */
    static const DWORD defaults[4] = {SE_CHANGE_NOTIFY_PRIVILEGE, SE_LOAD_DRIVER_PRIVILEGE,
                                      SE_IMPERSONATE_PRIVILEGE, SE_CREATE_GLOBAL_PRIVILEGE};
    in.PrivilegeCount = 4;
    for (int i = 0; i < 4; i++)
    {
        in.Privileges[i].Luid.LowPart = defaults[i];
        in.Privileges[i].Luid.HighPart = 0;
        in.Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
    }
    status = NtAdjustPrivilegesToken(token, FALSE, TP(in), 0, NULL, NULL);
    ok(status == STATUS_SUCCESS, "restore defaults -> %08lx", (unsigned long)status);
    NtClose(token);

    /* --- access enforcement -------------------------------------------------
     * TOKEN_ADJUST_PRIVILEGES alone suffices without a previous-state buffer;
     * asking for previous state also demands TOKEN_QUERY. */
    HANDLE adjust_only = NULL;
    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &adjust_only);
    ok(status == STATUS_SUCCESS, "open adjust-only -> %08lx", (unsigned long)status);

    set_priv(&in, SE_CHANGE_NOTIFY_PRIVILEGE, SE_PRIVILEGE_ENABLED);
    status = NtAdjustPrivilegesToken(adjust_only, FALSE, TP(in), 0, NULL, NULL);
    ok(status == STATUS_SUCCESS, "adjust without prev -> %08lx", (unsigned long)status);

    memset(&prev, 0, sizeof(prev));
    status = NtAdjustPrivilegesToken(adjust_only, FALSE, TP(in), sizeof(prev), TP(prev), &retlen);
    ok(status == STATUS_ACCESS_DENIED, "prev without TOKEN_QUERY -> %08lx", (unsigned long)status);
    NtClose(adjust_only);

    HANDLE query_only = NULL;
    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &query_only);
    ok(status == STATUS_SUCCESS, "open query-only -> %08lx", (unsigned long)status);
    status = NtAdjustPrivilegesToken(query_only, FALSE, TP(in), 0, NULL, NULL);
    ok(status == STATUS_ACCESS_DENIED, "adjust without TOKEN_ADJUST_PRIVILEGES -> %08lx",
       (unsigned long)status);
    NtClose(query_only);
}
