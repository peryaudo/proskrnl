/*
 * sem_se/se_duplicate.c — NtDuplicateToken: primary -> impersonation at each
 * level, the SecurityQualityOfService plumbing, level validation, granted
 * access inheritance, and the id rules.
 *
 * Oracle: dlls/ntdll/unix/security.c NtDuplicateToken (level comes from
 * attr->SecurityQualityOfService, else SecurityAnonymous) + server/token.c
 * duplicate_token / token_duplicate: requires TOKEN_DUPLICATE on the source
 * handle; access 0 inherits the source HANDLE's granted access; a fresh
 * TokenId always, the ModifiedId copied for primary duplicates or same-level
 * impersonation ones; impersonation-of-impersonation may never raise the
 * level (STATUS_BAD_IMPERSONATION_LEVEL).
 */
#include "util.h"

START_TEST(se_duplicate)
{
    NTSTATUS status;
    HANDLE token = NULL, dup = NULL, redup = NULL;
    ULONG retlen;

    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &token);
    ok(status == STATUS_SUCCESS, "open -> %08lx", (unsigned long)status);

    /* --- primary -> impersonation at every level --------------------------- */
    static const SECURITY_IMPERSONATION_LEVEL levels[] = {
        SecurityAnonymous, SecurityIdentification, SecurityImpersonation, SecurityDelegation};
    for (int i = 0; i < 4; i++)
    {
        dup = NULL;
        status = dup_impersonation(token, levels[i], &dup);
        ok(status == STATUS_SUCCESS, "dup level %d -> %08lx", i, (unsigned long)status);

        TOKEN_TYPE type = 0;
        status = NtQueryInformationToken(dup, TokenType, &type, sizeof(type), &retlen);
        ok(status == STATUS_SUCCESS, "dup type query -> %08lx", (unsigned long)status);
        ok(type == TokenImpersonation, "dup %d type %d", i, (int)type);

        SECURITY_IMPERSONATION_LEVEL level = (SECURITY_IMPERSONATION_LEVEL)-1;
        status =
            NtQueryInformationToken(dup, TokenImpersonationLevel, &level, sizeof(level), &retlen);
        ok(status == STATUS_SUCCESS, "dup level query -> %08lx", (unsigned long)status);
        ok(level == levels[i], "dup level %d, expected %d", (int)level, (int)levels[i]);
        NtClose(dup);
    }

    /* --- no SQOS means SecurityAnonymous ----------------------------------- */
    OBJECT_ATTRIBUTES attr;
    memset(&attr, 0, sizeof(attr));
    attr.Length = sizeof(attr);
    dup = NULL;
    status = NtDuplicateToken(token, TOKEN_QUERY, &attr, FALSE, TokenImpersonation, &dup);
    ok(status == STATUS_SUCCESS, "dup no-SQOS -> %08lx", (unsigned long)status);
    SECURITY_IMPERSONATION_LEVEL level = (SECURITY_IMPERSONATION_LEVEL)-1;
    status = NtQueryInformationToken(dup, TokenImpersonationLevel, &level, sizeof(level), &retlen);
    ok(status == STATUS_SUCCESS && level == SecurityAnonymous, "no-SQOS level %d", (int)level);

    /* an anonymous impersonation token cannot be privilege-checked */
    PRIVILEGE_SET set;
    BOOLEAN held;
    set.PrivilegeCount = 1;
    set.Control = 0;
    set.Privilege[0].Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
    set.Privilege[0].Luid.HighPart = 0;
    set.Privilege[0].Attributes = 0;
    status = NtPrivilegeCheck(dup, &set, &held);
    ok(status == STATUS_BAD_IMPERSONATION_LEVEL, "check anonymous -> %08lx", (unsigned long)status);
    NtClose(dup);

    /* --- a NULL attributes pointer also means SecurityAnonymous ------------ */
    dup = NULL;
    status = NtDuplicateToken(token, TOKEN_QUERY, NULL, FALSE, TokenImpersonation, &dup);
    ok(status == STATUS_SUCCESS, "dup NULL attr -> %08lx", (unsigned long)status);
    NtClose(dup);

    /* --- id rules: fresh TokenId, ModifiedId copied for a primary dup ------ */
    TOKEN_STATISTICS src_stats, dup_stats;
    status =
        NtQueryInformationToken(token, TokenStatistics, &src_stats, sizeof(src_stats), &retlen);
    ok(status == STATUS_SUCCESS, "src stats -> %08lx", (unsigned long)status);

    dup = NULL;
    status = NtDuplicateToken(token, TOKEN_QUERY, NULL, FALSE, TokenPrimary, &dup);
    ok(status == STATUS_SUCCESS, "dup primary -> %08lx", (unsigned long)status);
    status = NtQueryInformationToken(dup, TokenStatistics, &dup_stats, sizeof(dup_stats), &retlen);
    ok(status == STATUS_SUCCESS, "dup stats -> %08lx", (unsigned long)status);
    ok(dup_stats.TokenId.LowPart != src_stats.TokenId.LowPart ||
           dup_stats.TokenId.HighPart != src_stats.TokenId.HighPart,
       "duplicate kept the TokenId");
    ok(dup_stats.ModifiedId.LowPart == src_stats.ModifiedId.LowPart &&
           dup_stats.ModifiedId.HighPart == src_stats.ModifiedId.HighPart,
       "primary duplicate did not copy ModifiedId");
    ok(dup_stats.TokenType == TokenPrimary, "dup primary type %d", (int)dup_stats.TokenType);
    ok(dup_stats.GroupCount == src_stats.GroupCount, "dup group count %lu",
       (unsigned long)dup_stats.GroupCount);
    ok(dup_stats.PrivilegeCount == src_stats.PrivilegeCount, "dup privilege count %lu",
       (unsigned long)dup_stats.PrivilegeCount);
    NtClose(dup);

    /* --- the duplicate is a NEW object -------------------------------------
     * adjusting the duplicate must not touch the source */
    HANDLE mutable_dup = NULL;
    status = NtDuplicateToken(token, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, NULL, FALSE,
                              TokenPrimary, &mutable_dup);
    ok(status == STATUS_SUCCESS, "dup mutable -> %08lx", (unsigned long)status);
    struct
    {
        TOKEN_PRIVILEGES tp;
        LUID_AND_ATTRIBUTES pad[1];
    } adj;
    adj.tp.PrivilegeCount = 1;
    adj.tp.Privileges[0].Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
    adj.tp.Privileges[0].Luid.HighPart = 0;
    adj.tp.Privileges[0].Attributes = 0;
    status = NtAdjustPrivilegesToken(mutable_dup, FALSE, &adj.tp, 0, NULL, NULL);
    ok(status == STATUS_SUCCESS, "adjust dup -> %08lx", (unsigned long)status);

    set.PrivilegeCount = 1;
    set.Control = PRIVILEGE_SET_ALL_NECESSARY;
    status = NtPrivilegeCheck(token, &set, &held);
    ok(status == STATUS_SUCCESS && held, "adjusting the duplicate leaked into the source");
    NtClose(mutable_dup);

    /* --- level validation: impersonation may never gain level -------------- */
    HANDLE ident = NULL;
    status = dup_impersonation(token, SecurityIdentification, &ident);
    ok(status == STATUS_SUCCESS, "dup ident -> %08lx", (unsigned long)status);

    /* need TOKEN_DUPLICATE on the intermediate to re-duplicate it */
    HANDLE ident_dup = NULL;
    status = NtDuplicateObject(NtCurrentProcess(), ident, NtCurrentProcess(), &ident_dup,
                               TOKEN_QUERY | TOKEN_DUPLICATE, 0, 0);
    ok(status == STATUS_SUCCESS, "widen ident handle -> %08lx", (unsigned long)status);

    redup = NULL;
    status = dup_impersonation(ident_dup, SecurityImpersonation, &redup);
    ok(status == STATUS_BAD_IMPERSONATION_LEVEL, "raise level -> %08lx", (unsigned long)status);

    redup = NULL;
    status = dup_impersonation(ident_dup, SecurityIdentification, &redup);
    ok(status == STATUS_SUCCESS, "same level -> %08lx", (unsigned long)status);
    NtClose(redup);
    NtClose(ident_dup);
    NtClose(ident);

    /* --- access: TOKEN_DUPLICATE is required on the source ------------------ */
    HANDLE query_only = NULL;
    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &query_only);
    ok(status == STATUS_SUCCESS, "open query-only -> %08lx", (unsigned long)status);
    dup = NULL;
    status = NtDuplicateToken(query_only, TOKEN_QUERY, NULL, FALSE, TokenPrimary, &dup);
    ok(status == STATUS_ACCESS_DENIED, "dup without TOKEN_DUPLICATE -> %08lx",
       (unsigned long)status);
    NtClose(query_only);

    /* --- access 0 inherits the source handle's granted access --------------
     * source handle: TOKEN_QUERY|TOKEN_DUPLICATE. A dup with access 0 can
     * query (inherited TOKEN_QUERY) but a dup from a duplicate-only handle
     * cannot. */
    dup = NULL;
    status = NtDuplicateToken(token, 0, NULL, FALSE, TokenPrimary, &dup);
    ok(status == STATUS_SUCCESS, "dup access 0 -> %08lx", (unsigned long)status);
    TOKEN_TYPE type = 0;
    status = NtQueryInformationToken(dup, TokenType, &type, sizeof(type), &retlen);
    ok(status == STATUS_SUCCESS, "inherited TOKEN_QUERY -> %08lx", (unsigned long)status);
    NtClose(dup);

    HANDLE dup_only = NULL;
    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_DUPLICATE, &dup_only);
    ok(status == STATUS_SUCCESS, "open dup-only -> %08lx", (unsigned long)status);
    dup = NULL;
    status = NtDuplicateToken(dup_only, 0, NULL, FALSE, TokenPrimary, &dup);
    ok(status == STATUS_SUCCESS, "dup from dup-only -> %08lx", (unsigned long)status);
    status = NtQueryInformationToken(dup, TokenType, &type, sizeof(type), &retlen);
    ok(status == STATUS_ACCESS_DENIED, "no inherited TOKEN_QUERY -> %08lx", (unsigned long)status);
    NtClose(dup);
    NtClose(dup_only);

    NtClose(token);
}
