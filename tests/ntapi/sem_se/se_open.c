/*
 * sem_se/se_open.c — opening tokens: NtOpenProcessToken(Ex),
 * NtOpenThreadToken(Ex), the magic token pseudo-handles, handle identity,
 * and NtAllocateLocallyUniqueId.
 *
 * Oracle: dlls/ntdll/unix/security.c (NtOpenProcessTokenEx pre-writes
 * *handle = 0), server/token.c open_token (process resolved with access 0;
 * a fresh thread has no token -> STATUS_NO_TOKEN), server/handle.c
 * get_magic_handle (0xfffffffa/b/c resolve to the effective/thread/process
 * token, bypassing the access check; they are not table entries, so
 * NtClose on one is STATUS_INVALID_HANDLE).
 */
#include "util.h"

START_TEST(se_open)
{
    NTSTATUS status;
    HANDLE token = NULL, token2 = NULL, dup = NULL;

    /* --- process token: plain open ---------------------------------------- */
    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &token);
    ok(status == STATUS_SUCCESS, "open TOKEN_QUERY -> %08lx", (unsigned long)status);
    ok(token != NULL, "handle not written");
    NtClose(token);

    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ALL_ACCESS, &token);
    ok(status == STATUS_SUCCESS, "open TOKEN_ALL_ACCESS -> %08lx", (unsigned long)status);
    NtClose(token);

    /* MAXIMUM_ALLOWED maps through the token GENERIC_MAPPING to all access
     * (wineserver alloc_handle: MAXIMUM_ALLOWED -> GENERIC_ALL -> mapped);
     * proven by a TOKEN_QUERY use succeeding through the handle. */
    status = NtOpenProcessToken(NtCurrentProcess(), MAXIMUM_ALLOWED, &token);
    ok(status == STATUS_SUCCESS, "open MAXIMUM_ALLOWED -> %08lx", (unsigned long)status);
    TOKEN_STATISTICS stats;
    ULONG retlen = 0;
    status = NtQueryInformationToken(token, TokenStatistics, &stats, sizeof(stats), &retlen);
    ok(status == STATUS_SUCCESS, "query through MAXIMUM_ALLOWED handle -> %08lx",
       (unsigned long)status);

    /* --- the Ex variant and a bad process handle -------------------------- */
    status = NtOpenProcessTokenEx(NtCurrentProcess(), TOKEN_QUERY, 0, &token2);
    ok(status == STATUS_SUCCESS, "OpenProcessTokenEx -> %08lx", (unsigned long)status);
    NtClose(token2);

    /* Failed open still zeroes *handle (unix-side pre-write; on proskrnl only
     * the kernel can do it). */
    token2 = (HANDLE)(ULONG_PTR)0xdeadbeef;
    status = NtOpenProcessToken((HANDLE)(ULONG_PTR)0x1234bad0, TOKEN_QUERY, &token2);
    ok(status == STATUS_INVALID_HANDLE, "bad process handle -> %08lx", (unsigned long)status);
    ok(token2 == NULL, "failed open left *handle = %p", token2);

    /* --- both opens reach the SAME token object ---------------------------
     * Disable SeChangeNotifyPrivilege through handle A; the change is visible
     * through handle B (open_token hands out the process token object itself,
     * never a copy). se_adjust.c re-enables and covers the full semantics. */
    HANDLE handle_a = NULL, handle_b = NULL;
    status =
        NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &handle_a);
    ok(status == STATUS_SUCCESS, "open A -> %08lx", (unsigned long)status);
    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &handle_b);
    ok(status == STATUS_SUCCESS, "open B -> %08lx", (unsigned long)status);

    struct
    {
        TOKEN_PRIVILEGES tp;
        LUID_AND_ATTRIBUTES pad[1];
    } adj;
    adj.tp.PrivilegeCount = 1;
    adj.tp.Privileges[0].Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
    adj.tp.Privileges[0].Luid.HighPart = 0;
    adj.tp.Privileges[0].Attributes = 0; /* disable */
    status = NtAdjustPrivilegesToken(handle_a, FALSE, &adj.tp, 0, NULL, NULL);
    ok(status == STATUS_SUCCESS, "adjust via A -> %08lx", (unsigned long)status);

    PRIVILEGE_SET check;
    BOOLEAN held = TRUE;
    check.PrivilegeCount = 1;
    check.Control = PRIVILEGE_SET_ALL_NECESSARY;
    check.Privilege[0].Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
    check.Privilege[0].Luid.HighPart = 0;
    check.Privilege[0].Attributes = 0;
    status = NtPrivilegeCheck(handle_b, &check, &held);
    ok(status == STATUS_SUCCESS, "privilege check via B -> %08lx", (unsigned long)status);
    ok(!held, "adjust through A not visible through B (same object)");

    /* restore for the rest of the suite (fresh oracle prefixes share the
     * wineserver across tests in one run) */
    adj.tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    status = NtAdjustPrivilegesToken(handle_a, FALSE, &adj.tp, 0, NULL, NULL);
    ok(status == STATUS_SUCCESS, "re-enable -> %08lx", (unsigned long)status);
    NtClose(handle_a);
    NtClose(handle_b);

    /* --- thread tokens: no impersonation anywhere in CUI-2 ---------------- */
    dup = (HANDLE)(ULONG_PTR)0xdeadbeef;
    status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY, FALSE, &dup);
    ok(status == STATUS_NO_TOKEN, "OpenThreadToken -> %08lx", (unsigned long)status);
    ok(dup == NULL, "failed thread open left *handle = %p", dup);

    status = NtOpenThreadTokenEx(NtCurrentThread(), TOKEN_QUERY, TRUE, 0, &dup);
    ok(status == STATUS_NO_TOKEN, "OpenThreadTokenEx -> %08lx", (unsigned long)status);

    /* --- magic pseudo-handles ---------------------------------------------
     * ~3 = process token, ~5 = thread effective token (falls back to the
     * process token): usable with no open at all, access check bypassed.
     * ~4 = thread token: no thread token exists -> INVALID_HANDLE. */
    TOKEN_TYPE type = 0;
    status =
        NtQueryInformationToken(GetCurrentProcessToken(), TokenType, &type, sizeof(type), &retlen);
    ok(status == STATUS_SUCCESS, "query via ~3 -> %08lx", (unsigned long)status);
    ok(type == TokenPrimary, "process token type %d", (int)type);

    type = 0;
    status = NtQueryInformationToken(GetCurrentThreadEffectiveToken(), TokenType, &type,
                                     sizeof(type), &retlen);
    ok(status == STATUS_SUCCESS, "query via ~5 -> %08lx", (unsigned long)status);
    ok(type == TokenPrimary, "effective token type %d", (int)type);

    status =
        NtQueryInformationToken(GetCurrentThreadToken(), TokenType, &type, sizeof(type), &retlen);
    ok(status == STATUS_INVALID_HANDLE, "query via ~4 -> %08lx", (unsigned long)status);

    /* NtClose on any pseudo handle in [~5, ~0] is a successful no-op
     * (dlls/ntdll/unix/server.c NtClose's HandleToLong range check) */
    status = NtClose(GetCurrentProcessToken());
    ok(status == STATUS_SUCCESS, "NtClose(~3) -> %08lx", (unsigned long)status);

    /* --- a token handle behaves as a normal Ob handle --------------------- */
    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &token2);
    ok(status == STATUS_SUCCESS, "reopen -> %08lx", (unsigned long)status);
    status = NtDuplicateObject(NtCurrentProcess(), token2, NtCurrentProcess(), &dup, 0, 0,
                               DUPLICATE_SAME_ACCESS);
    ok(status == STATUS_SUCCESS, "NtDuplicateObject -> %08lx", (unsigned long)status);
    status = NtQueryInformationToken(dup, TokenType, &type, sizeof(type), &retlen);
    ok(status == STATUS_SUCCESS, "query via duplicated handle -> %08lx", (unsigned long)status);
    NtClose(dup);
    NtClose(token2);
    NtClose(token);

    /* --- NtAllocateLocallyUniqueId: one monotonic authority --------------- */
    LUID first = {0, 0}, second = {0, 0};
    status = NtAllocateLocallyUniqueId(&first);
    ok(status == STATUS_SUCCESS, "AllocateLuid -> %08lx", (unsigned long)status);
    status = NtAllocateLocallyUniqueId(&second);
    ok(status == STATUS_SUCCESS, "AllocateLuid(2) -> %08lx", (unsigned long)status);
    ok(first.LowPart != 0 || first.HighPart != 0, "first LUID is zero");
    ok(second.HighPart > first.HighPart ||
           (second.HighPart == first.HighPart && second.LowPart > first.LowPart),
       "LUIDs not increasing (%lu -> %lu)", (unsigned long)first.LowPart,
       (unsigned long)second.LowPart);

    status = NtAllocateLocallyUniqueId(NULL);
    ok(status == STATUS_ACCESS_VIOLATION, "AllocateLuid(NULL) -> %08lx", (unsigned long)status);
}
