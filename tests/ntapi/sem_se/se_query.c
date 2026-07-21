/*
 * sem_se/se_query.c — NtQueryInformationToken: the fixed-length protocol and
 * every fixed-size class the baked DLLs read.
 *
 * Oracle: dlls/ntdll/unix/security.c NtQueryInformationToken — the info_len[]
 * table decides *retlen FIRST (pre-write, even when the call later fails),
 * then a short buffer is STATUS_BUFFER_TOO_SMALL, and only then the class
 * switch runs; a class with no case (TokenSource, TokenRestrictedSids, and
 * everything past the switch) is STATUS_NOT_IMPLEMENTED. Identity values are
 * wineserver's token_create_admin (server/token.c): a parentless process
 * gets a primary admin token, TokenElevationTypeLimited, session 1.
 */
#include "util.h"

START_TEST(se_query)
{
    NTSTATUS status;
    HANDLE token = NULL;
    ULONG retlen;

    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &token);
    ok(status == STATUS_SUCCESS, "open -> %08lx", (unsigned long)status);

    /* --- TokenUser: S-1-5-21-0-0-0-1000, Attributes 0 --------------------- */
    struct
    {
        TOKEN_USER user;
        BYTE sid[SID_BYTES(8)];
    } user_buf;
    sid_buf expect;
    ULONG expect_len = sid_local_user(&expect);

    retlen = 0xdead;
    status = NtQueryInformationToken(token, TokenUser, &user_buf, sizeof(user_buf), &retlen);
    ok(status == STATUS_SUCCESS, "TokenUser -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(TOKEN_USER) + expect_len, "TokenUser retlen %lu", (unsigned long)retlen);
    ok(user_buf.user.User.Sid == (PSID)(&user_buf.user + 1),
       "TokenUser Sid pointer %p not the trailing bytes", user_buf.user.User.Sid);
    ok(user_buf.user.User.Attributes == 0, "TokenUser attributes %08lx",
       (unsigned long)user_buf.user.User.Attributes);
    ok(equal_sid(user_buf.user.User.Sid, expect.buf), "TokenUser SID mismatch");

    /* short buffer: BUFFER_TOO_SMALL with the needed size in retlen */
    retlen = 0xdead;
    status = NtQueryInformationToken(token, TokenUser, &user_buf, sizeof(TOKEN_USER), &retlen);
    ok(status == STATUS_BUFFER_TOO_SMALL, "TokenUser short -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(TOKEN_USER) + expect_len, "TokenUser short retlen %lu",
       (unsigned long)retlen);

    /* --- TokenOwner / TokenPrimaryGroup: S-1-5-21-0-0-0-513 --------------- */
    struct
    {
        TOKEN_OWNER owner;
        BYTE sid[SID_BYTES(8)];
    } owner_buf;
    expect_len = sid_domain_users(&expect);

    retlen = 0;
    status = NtQueryInformationToken(token, TokenOwner, &owner_buf, sizeof(owner_buf), &retlen);
    ok(status == STATUS_SUCCESS, "TokenOwner -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(TOKEN_OWNER) + expect_len, "TokenOwner retlen %lu", (unsigned long)retlen);
    ok(equal_sid(owner_buf.owner.Owner, expect.buf), "TokenOwner SID mismatch");

    struct
    {
        TOKEN_PRIMARY_GROUP group;
        BYTE sid[SID_BYTES(8)];
    } group_buf;
    status =
        NtQueryInformationToken(token, TokenPrimaryGroup, &group_buf, sizeof(group_buf), &retlen);
    ok(status == STATUS_SUCCESS, "TokenPrimaryGroup -> %08lx", (unsigned long)status);
    ok(equal_sid(group_buf.group.PrimaryGroup, expect.buf), "TokenPrimaryGroup SID mismatch");

    /* --- TokenType / TokenImpersonationLevel ------------------------------ */
    TOKEN_TYPE type = 0;
    status = NtQueryInformationToken(token, TokenType, &type, sizeof(type), &retlen);
    ok(status == STATUS_SUCCESS, "TokenType -> %08lx", (unsigned long)status);
    ok(type == TokenPrimary, "TokenType %d", (int)type);
    ok(retlen == sizeof(TOKEN_TYPE), "TokenType retlen %lu", (unsigned long)retlen);

    /* a primary token has no impersonation level; the retlen pre-write
     * happens anyway */
    SECURITY_IMPERSONATION_LEVEL level;
    retlen = 0xdead;
    status =
        NtQueryInformationToken(token, TokenImpersonationLevel, &level, sizeof(level), &retlen);
    ok(status == STATUS_INVALID_PARAMETER, "TokenImpersonationLevel -> %08lx",
       (unsigned long)status);
    ok(retlen == sizeof(SECURITY_IMPERSONATION_LEVEL), "level retlen %lu", (unsigned long)retlen);

    /* short fixed-length buffer fails BEFORE the class logic */
    retlen = 0xdead;
    status =
        NtQueryInformationToken(token, TokenImpersonationLevel, &level, sizeof(level) - 1, &retlen);
    ok(status == STATUS_BUFFER_TOO_SMALL, "short level -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(SECURITY_IMPERSONATION_LEVEL), "short level retlen %lu",
       (unsigned long)retlen);

    /* --- TokenStatistics --------------------------------------------------- */
    TOKEN_STATISTICS stats;
    memset(&stats, 0, sizeof(stats));
    status = NtQueryInformationToken(token, TokenStatistics, &stats, sizeof(stats), &retlen);
    ok(status == STATUS_SUCCESS, "TokenStatistics -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(TOKEN_STATISTICS), "stats retlen %lu", (unsigned long)retlen);
    ok(stats.TokenId.LowPart != 0 || stats.TokenId.HighPart != 0, "TokenId is zero");
    ok(stats.ModifiedId.LowPart != 0 || stats.ModifiedId.HighPart != 0, "ModifiedId is zero");
    ok(stats.AuthenticationId.LowPart == 0 && stats.AuthenticationId.HighPart == 0,
       "AuthenticationId %lu:%lu", (unsigned long)stats.AuthenticationId.HighPart,
       (unsigned long)stats.AuthenticationId.LowPart);
    ok(stats.ExpirationTime.QuadPart == 0x7fffffffffffffffLL, "ExpirationTime %llx",
       (unsigned long long)stats.ExpirationTime.QuadPart);
    ok(stats.TokenType == TokenPrimary, "stats type %d", (int)stats.TokenType);
    ok(stats.DynamicCharged == 0 && stats.DynamicAvailable == 0, "dynamic %lu/%lu",
       (unsigned long)stats.DynamicCharged, (unsigned long)stats.DynamicAvailable);
    ok(stats.GroupCount == 8, "GroupCount %lu", (unsigned long)stats.GroupCount);
    ok(stats.PrivilegeCount == 21, "PrivilegeCount %lu", (unsigned long)stats.PrivilegeCount);

    retlen = 0xdead;
    status = NtQueryInformationToken(token, TokenStatistics, &stats, sizeof(stats) - 1, &retlen);
    ok(status == STATUS_BUFFER_TOO_SMALL, "short stats -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(TOKEN_STATISTICS), "short stats retlen %lu", (unsigned long)retlen);

    /* --- TokenSessionId / elevation ---------------------------------------- */
    DWORD session = 0xdead;
    status = NtQueryInformationToken(token, TokenSessionId, &session, sizeof(session), &retlen);
    ok(status == STATUS_SUCCESS, "TokenSessionId -> %08lx", (unsigned long)status);
    ok(session == 1, "session id %lu", (unsigned long)session);

    TOKEN_ELEVATION_TYPE elevation_type = 0;
    status = NtQueryInformationToken(token, TokenElevationType, &elevation_type,
                                     sizeof(elevation_type), &retlen);
    ok(status == STATUS_SUCCESS, "TokenElevationType -> %08lx", (unsigned long)status);
    ok(elevation_type == TokenElevationTypeLimited, "elevation type %d", (int)elevation_type);

    TOKEN_ELEVATION elevation;
    elevation.TokenIsElevated = 0xdead;
    status = NtQueryInformationToken(token, TokenElevation, &elevation, sizeof(elevation), &retlen);
    ok(status == STATUS_SUCCESS, "TokenElevation -> %08lx", (unsigned long)status);
    ok(elevation.TokenIsElevated == 0, "TokenIsElevated %lu",
       (unsigned long)elevation.TokenIsElevated);
    ok(retlen == sizeof(TOKEN_ELEVATION), "elevation retlen %lu", (unsigned long)retlen);

    /* --- the unix-side semi-stub classes ----------------------------------- */
    DWORD value = 0xdead;
    status =
        NtQueryInformationToken(token, TokenVirtualizationEnabled, &value, sizeof(value), &retlen);
    ok(status == STATUS_SUCCESS, "TokenVirtualizationEnabled -> %08lx", (unsigned long)status);
    ok(value == 0, "virtualization %lu", (unsigned long)value);

    value = 0xdead;
    status = NtQueryInformationToken(token, TokenUIAccess, &value, sizeof(value), &retlen);
    ok(status == STATUS_SUCCESS, "TokenUIAccess -> %08lx", (unsigned long)status);
    ok(value == 1, "ui access %lu", (unsigned long)value);

    value = 0xdead;
    status = NtQueryInformationToken(token, TokenIsAppContainer, &value, sizeof(value), &retlen);
    ok(status == STATUS_SUCCESS, "TokenIsAppContainer -> %08lx", (unsigned long)status);
    ok(value == 0, "is app container %lu", (unsigned long)value);

    /* TokenIntegrityLevel: always the high label S-1-16-12288 */
    struct
    {
        TOKEN_MANDATORY_LABEL label;
        BYTE sid[SID_BYTES(8)];
    } label_buf;
    expect_len = sid_high_label(&expect);
    retlen = 0;
    status =
        NtQueryInformationToken(token, TokenIntegrityLevel, &label_buf, sizeof(label_buf), &retlen);
    ok(status == STATUS_SUCCESS, "TokenIntegrityLevel -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(TOKEN_MANDATORY_LABEL) + SID_BYTES(1), "label retlen %lu",
       (unsigned long)retlen);
    ok(label_buf.label.Label.Attributes == (SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED),
       "label attributes %08lx", (unsigned long)label_buf.label.Label.Attributes);
    ok(equal_sid(label_buf.label.Label.Sid, expect.buf), "label SID mismatch");

    /* TokenAppContainerSid: fixed length, NULL pointer out */
    struct
    {
        TOKEN_APPCONTAINER_INFORMATION info;
        BYTE sid[SID_BYTES(8)];
    } container;
    container.info.TokenAppContainer = (PSID)(ULONG_PTR)0xdead;
    status = NtQueryInformationToken(token, TokenAppContainerSid, &container, sizeof(container),
                                     &retlen);
    ok(status == STATUS_SUCCESS, "TokenAppContainerSid -> %08lx", (unsigned long)status);
    ok(container.info.TokenAppContainer == NULL, "app container sid %p",
       container.info.TokenAppContainer);

    /* --- classes with a fixed length but NO implementation -----------------
     * TokenSource: a short buffer still fails BUFFER_TOO_SMALL (the length
     * gate runs first), an adequate one reaches the switch and finds no case.
     */
    TOKEN_SOURCE source;
    retlen = 0xdead;
    status = NtQueryInformationToken(token, TokenSource, &source, sizeof(source) - 1, &retlen);
    ok(status == STATUS_BUFFER_TOO_SMALL, "short TokenSource -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(TOKEN_SOURCE), "short TokenSource retlen %lu", (unsigned long)retlen);

    retlen = 0xdead;
    status = NtQueryInformationToken(token, TokenSource, &source, sizeof(source), &retlen);
    ok(status == STATUS_NOT_IMPLEMENTED, "TokenSource -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(TOKEN_SOURCE), "TokenSource retlen %lu", (unsigned long)retlen);

    BYTE big[256];
    retlen = 0xdead;
    status = NtQueryInformationToken(token, TokenRestrictedSids, big, sizeof(big), &retlen);
    ok(status == STATUS_NOT_IMPLEMENTED, "TokenRestrictedSids -> %08lx", (unsigned long)status);
    ok(retlen == 0, "TokenRestrictedSids retlen %lu", (unsigned long)retlen);

    /* a class beyond MaxTokenInfoClass: retlen pre-written to 0 */
    retlen = 0xdead;
    status =
        NtQueryInformationToken(token, (TOKEN_INFORMATION_CLASS)200, big, sizeof(big), &retlen);
    ok(status == STATUS_NOT_IMPLEMENTED, "class 200 -> %08lx", (unsigned long)status);
    ok(retlen == 0, "class 200 retlen %lu", (unsigned long)retlen);

    /* --- access enforcement: TOKEN_QUERY is required ------------------------ */
    HANDLE dup_only = NULL;
    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_DUPLICATE, &dup_only);
    ok(status == STATUS_SUCCESS, "open TOKEN_DUPLICATE -> %08lx", (unsigned long)status);
    status = NtQueryInformationToken(dup_only, TokenType, &type, sizeof(type), &retlen);
    ok(status == STATUS_ACCESS_DENIED, "query without TOKEN_QUERY -> %08lx", (unsigned long)status);
    NtClose(dup_only);

    NtClose(token);
}
