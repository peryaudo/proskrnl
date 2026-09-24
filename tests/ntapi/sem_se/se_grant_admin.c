/*
 * sem_se/se_grant_admin.c — ProcessWineGrantAdminToken REPLACES the
 * process's primary token with a fresh admin token of elevation type
 * Default.
 *
 * The caller is explorer's desktop start (third_party/wine
 * programs/explorer/desktop.c: "the desktop process should always have an
 * admin token"), which sets the Wine-private class with a NULL buffer and a
 * zero length. The class reaches wineserver's grant_process_admin_token
 * (server/process.c), whose whole body is: resolve the handle for
 * PROCESS_SET_INFORMATION, mint token_create_admin(TRUE,
 * SecurityIdentification, TokenElevationTypeDefault, default_session_id),
 * release the old process token, install the new one. The unix side
 * (dlls/ntdll/unix/process.c, case ProcessWineGrantAdminToken) reads
 * neither the buffer nor the length.
 *
 * What that makes observable, and what this file pins:
 *
 *   - the process token AFTER is a different object: a new TokenId, type
 *     TokenElevationTypeDefault, and — since the admin identity's
 *     Administrators group is enabled — TokenIsElevated TRUE (the Limited
 *     token before answers 0, se_query.c);
 *   - a handle opened BEFORE the grant still names the OLD token, which is
 *     unchanged: the grant installs a new object rather than editing the
 *     existing one;
 *   - the identity is the same fixed admin identity: same user SID, same
 *     session;
 *   - the handle is resolved (a junk handle is STATUS_INVALID_HANDLE) and
 *     the buffer and length are never read.
 *
 * Oracle-first (G5). Nothing here is beyond_oracle. The todo_proskrnl
 * blocks are the asserts the kernel's accept-as-a-no-op arm fails today;
 * the commit that implements the grant deletes them.
 */
#include "util.h"

/* The Wine-private class, as wine/include/winternl.h spells it
 * (ProcessWineGrantAdminToken = 1002, just after
 * ProcessWineMakeProcessSystem = 1000). A wrong number would reach the
 * oracle's STATUS_NOT_IMPLEMENTED default, so the oracle leg validates it. */
#define SE_ProcessWineGrantAdminToken ((PROCESSINFOCLASS)1002)

typedef struct
{
    TOKEN_USER user;
    BYTE sid[SID_BYTES(8)];
} se_user_buf;

static TOKEN_STATISTICS query_stats(HANDLE token, const char *what)
{
    TOKEN_STATISTICS stats;
    ULONG retlen;
    memset(&stats, 0, sizeof(stats));
    NTSTATUS status =
        NtQueryInformationToken(token, TokenStatistics, &stats, sizeof(stats), &retlen);
    ok(status == STATUS_SUCCESS, "%s TokenStatistics -> %08lx", what, (unsigned long)status);
    return stats;
}

static TOKEN_ELEVATION_TYPE query_elevation_type(HANDLE token, const char *what)
{
    TOKEN_ELEVATION_TYPE type = 0;
    ULONG retlen;
    NTSTATUS status =
        NtQueryInformationToken(token, TokenElevationType, &type, sizeof(type), &retlen);
    ok(status == STATUS_SUCCESS, "%s TokenElevationType -> %08lx", what, (unsigned long)status);
    return type;
}

static DWORD query_is_elevated(HANDLE token, const char *what)
{
    TOKEN_ELEVATION elevation;
    ULONG retlen;
    elevation.TokenIsElevated = 0xdead;
    NTSTATUS status =
        NtQueryInformationToken(token, TokenElevation, &elevation, sizeof(elevation), &retlen);
    ok(status == STATUS_SUCCESS, "%s TokenElevation -> %08lx", what, (unsigned long)status);
    return elevation.TokenIsElevated;
}

static DWORD query_session(HANDLE token, const char *what)
{
    DWORD session = 0xdead;
    ULONG retlen;
    NTSTATUS status =
        NtQueryInformationToken(token, TokenSessionId, &session, sizeof(session), &retlen);
    ok(status == STATUS_SUCCESS, "%s TokenSessionId -> %08lx", what, (unsigned long)status);
    return session;
}

static ULONG query_user(HANDLE token, se_user_buf *out, const char *what)
{
    ULONG retlen = 0;
    memset(out, 0, sizeof(*out));
    NTSTATUS status = NtQueryInformationToken(token, TokenUser, out, sizeof(*out), &retlen);
    ok(status == STATUS_SUCCESS, "%s TokenUser -> %08lx", what, (unsigned long)status);
    return retlen;
}

START_TEST(se_grant_admin)
{
    NTSTATUS status;
    HANDLE before = NULL, after = NULL;

    /* --- the token the process starts with -------------------------------- */
    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &before);
    ok(status == STATUS_SUCCESS, "open before -> %08lx", (unsigned long)status);
    TOKEN_STATISTICS statsBefore = query_stats(before, "before");
    ok(query_elevation_type(before, "before") == TokenElevationTypeLimited,
       "before: elevation type is not Limited");
    ok(query_is_elevated(before, "before") == 0, "before: TokenIsElevated is not 0");
    se_user_buf userBefore;
    ULONG userBeforeLength = query_user(before, &userBefore, "before");

    /* --- a handle that resolves to nothing is refused, and nothing moves -- */
    status = NtSetInformationProcess((HANDLE)(ULONG_PTR)0xdeadbeef, SE_ProcessWineGrantAdminToken,
                                     NULL, 0);
    todo_proskrnl
    {
        ok(status == STATUS_INVALID_HANDLE, "junk handle -> %08lx", (unsigned long)status);
    }
    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &after);
    ok(status == STATUS_SUCCESS, "open after refusal -> %08lx", (unsigned long)status);
    TOKEN_STATISTICS statsRefused = query_stats(after, "after refusal");
    ok(statsRefused.TokenId.LowPart == statsBefore.TokenId.LowPart &&
           statsRefused.TokenId.HighPart == statsBefore.TokenId.HighPart,
       "a refused grant replaced the token");
    NtClose(after);
    after = NULL;

    /* --- the grant, exactly as explorer makes it: NULL buffer, 0 length --- */
    status = NtSetInformationProcess(NtCurrentProcess(), SE_ProcessWineGrantAdminToken, NULL, 0);
    ok(status == STATUS_SUCCESS, "grant -> %08lx", (unsigned long)status);

    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &after);
    ok(status == STATUS_SUCCESS, "open after -> %08lx", (unsigned long)status);
    TOKEN_STATISTICS statsAfter = query_stats(after, "after");
    todo_proskrnl
    {
        ok(statsAfter.TokenId.LowPart != statsBefore.TokenId.LowPart ||
               statsAfter.TokenId.HighPart != statsBefore.TokenId.HighPart,
           "the grant kept the old TokenId");
    }
    ok(statsAfter.TokenType == TokenPrimary, "after: token type %d", (int)statsAfter.TokenType);
    todo_proskrnl
    {
        ok(query_elevation_type(after, "after") == TokenElevationTypeDefault,
           "after: elevation type is not Default");
    }
    todo_proskrnl
    {
        ok(query_is_elevated(after, "after") == 1, "after: TokenIsElevated is not 1");
    }
    ok(query_session(after, "after") == 1, "after: session is not 1");

    se_user_buf userAfter;
    ULONG userAfterLength = query_user(after, &userAfter, "after");
    ok(userAfterLength == userBeforeLength && userAfterLength != 0,
       "user retlen %lu before, %lu after", (unsigned long)userBeforeLength,
       (unsigned long)userAfterLength);
    ok(memcmp(userAfter.sid, userBefore.sid, sizeof(userAfter.sid)) == 0,
       "the grant changed the user SID");

    /* --- the handle opened BEFORE still names the old, unchanged token ---- */
    TOKEN_STATISTICS statsOld = query_stats(before, "old handle");
    ok(statsOld.TokenId.LowPart == statsBefore.TokenId.LowPart &&
           statsOld.TokenId.HighPart == statsBefore.TokenId.HighPart,
       "the old handle's TokenId moved");
    ok(query_elevation_type(before, "old handle") == TokenElevationTypeLimited,
       "old handle: elevation type is not Limited");

    /* --- a second grant mints yet another token --------------------------- */
    status = NtSetInformationProcess(NtCurrentProcess(), SE_ProcessWineGrantAdminToken,
                                     (PVOID)(ULONG_PTR)0x10, 0x7fff);
    ok(status == STATUS_SUCCESS, "second grant, junk buffer -> %08lx", (unsigned long)status);
    HANDLE again = NULL;
    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &again);
    ok(status == STATUS_SUCCESS, "open again -> %08lx", (unsigned long)status);
    TOKEN_STATISTICS statsAgain = query_stats(again, "again");
    todo_proskrnl
    {
        ok(statsAgain.TokenId.LowPart != statsAfter.TokenId.LowPart ||
               statsAgain.TokenId.HighPart != statsAfter.TokenId.HighPart,
           "the second grant kept the first grant's TokenId");
    }
    todo_proskrnl
    {
        ok(query_elevation_type(again, "again") == TokenElevationTypeDefault,
           "again: elevation type is not Default");
    }

    NtClose(again);
    NtClose(after);
    NtClose(before);
}
