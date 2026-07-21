/*
 * sem_se/se_access.c — NtAccessCheck (the wineserver ACE walk, exactly) and
 * NtPrivilegeCheck.
 *
 * Oracle: dlls/ntdll/unix/security.c NtAccessCheck (NULL privs/retlen ->
 * ACCESS_VIOLATION; *retlen out is always max(needed, sizeof(PRIVILEGE_SET));
 * a smaller in-size is BUFFER_TOO_SMALL) + server/token.c access_check /
 * token_access_check: impersonation tokens only (NO_IMPERSONATION_TOKEN),
 * above SecurityAnonymous (BAD_IMPERSONATION_LEVEL); generic bits in the
 * desired mask -> GENERIC_NOT_MAPPED; an owner-less SD ->
 * INVALID_SECURITY_DESCR; no DACL grants everything, an empty DACL denies
 * everything; the deny/allow walk with the owner short-circuit
 * (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE).
 */
#include "util.h"

/* One access check, returning the syscall status; granted/result out. */
static NTSTATUS check(HANDLE token, void *sd, ACCESS_MASK desired, GENERIC_MAPPING *mapping,
                      ACCESS_MASK *granted, NTSTATUS *result)
{
    struct
    {
        PRIVILEGE_SET set;
        LUID_AND_ATTRIBUTES pad[3];
    } privs;
    ULONG len = sizeof(privs);
    *granted = 0xdeadbeef;
    *result = (NTSTATUS)0xdeadbeef;
    return NtAccessCheck(sd, token, desired, mapping, &privs.set, &len, granted, result);
}

START_TEST(se_access)
{
    NTSTATUS status, result;
    ACCESS_MASK granted;
    HANDLE process_token = NULL, token = NULL;
    sid_buf owner, group, world, admins;
    BYTE sd_buf[256], acl_buf[128];
    ULONG acl_len, at;

    /* the event GENERIC_MAPPING, as wineserver's event_type declares it
     * (server/event.c): read/write = STANDARD_RIGHTS | specific bits. */
    GENERIC_MAPPING mapping;
    mapping.GenericRead = STANDARD_RIGHTS_READ | EVENT_QUERY_STATE;
    mapping.GenericWrite = STANDARD_RIGHTS_WRITE | EVENT_MODIFY_STATE;
    mapping.GenericExecute = STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE;
    mapping.GenericAll = EVENT_ALL_ACCESS;

    sid_domain_users(&owner);
    sid_domain_users(&group);
    sid_world(&world);
    sid_builtin_admins(&admins);

    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &process_token);
    ok(status == STATUS_SUCCESS, "open -> %08lx", (unsigned long)status);
    status = dup_impersonation(process_token, SecurityImpersonation, &token);
    ok(status == STATUS_SUCCESS, "dup impersonation -> %08lx", (unsigned long)status);

    /* --- argument pre-checks ----------------------------------------------- */
    build_sd(sd_buf, owner.buf, group.buf, 0, NULL, 0);
    ULONG len = 64;
    status =
        NtAccessCheck(sd_buf, token, EVENT_QUERY_STATE, &mapping, NULL, &len, &granted, &result);
    ok(status == STATUS_ACCESS_VIOLATION, "NULL privs -> %08lx", (unsigned long)status);
    struct
    {
        PRIVILEGE_SET set;
        LUID_AND_ATTRIBUTES pad[3];
    } privs;
    status = NtAccessCheck(sd_buf, token, EVENT_QUERY_STATE, &mapping, &privs.set, NULL, &granted,
                           &result);
    ok(status == STATUS_ACCESS_VIOLATION, "NULL retlen -> %08lx", (unsigned long)status);

    /* the privilege-set size protocol: out is max(needed, sizeof) = 20; a
     * smaller in-buffer is BUFFER_TOO_SMALL */
    len = sizeof(PRIVILEGE_SET) - 1;
    status = NtAccessCheck(sd_buf, token, EVENT_QUERY_STATE, &mapping, &privs.set, &len, &granted,
                           &result);
    ok(status == STATUS_BUFFER_TOO_SMALL, "small privs -> %08lx", (unsigned long)status);
    ok(len == sizeof(PRIVILEGE_SET), "privs retlen %lu", (unsigned long)len);

    /* --- token shape rules -------------------------------------------------- */
    status = check(process_token, sd_buf, EVENT_QUERY_STATE, &mapping, &granted, &result);
    ok(status == STATUS_NO_IMPERSONATION_TOKEN, "primary token -> %08lx", (unsigned long)status);

    HANDLE anon = NULL;
    status = dup_impersonation(process_token, SecurityAnonymous, &anon);
    ok(status == STATUS_SUCCESS, "dup anonymous -> %08lx", (unsigned long)status);
    status = check(anon, sd_buf, EVENT_QUERY_STATE, &mapping, &granted, &result);
    ok(status == STATUS_BAD_IMPERSONATION_LEVEL, "anonymous token -> %08lx", (unsigned long)status);
    NtClose(anon);

    /* --- SD shape rules ------------------------------------------------------ */
    status = check(token, sd_buf, GENERIC_READ, &mapping, &granted, &result);
    ok(status == STATUS_GENERIC_NOT_MAPPED, "generic desired -> %08lx", (unsigned long)status);

    build_sd(sd_buf, NULL, group.buf, 0, NULL, 0);
    status = check(token, sd_buf, EVENT_QUERY_STATE, &mapping, &granted, &result);
    ok(status == STATUS_INVALID_SECURITY_DESCR, "ownerless SD -> %08lx", (unsigned long)status);

    build_sd(sd_buf, owner.buf, NULL, 0, NULL, 0);
    status = check(token, sd_buf, EVENT_QUERY_STATE, &mapping, &granted, &result);
    ok(status == STATUS_INVALID_SECURITY_DESCR, "groupless SD -> %08lx", (unsigned long)status);

    /* --- no DACL: everything is granted -------------------------------------- */
    build_sd(sd_buf, owner.buf, group.buf, 0, NULL, 0);
    status =
        check(token, sd_buf, EVENT_QUERY_STATE | EVENT_MODIFY_STATE, &mapping, &granted, &result);
    ok(status == STATUS_SUCCESS, "no DACL -> %08lx", (unsigned long)status);
    ok(result == STATUS_SUCCESS, "no DACL result %08lx", (unsigned long)result);
    ok(granted == (EVENT_QUERY_STATE | EVENT_MODIFY_STATE), "no DACL granted %08lx",
       (unsigned long)granted);

    status = check(token, sd_buf, MAXIMUM_ALLOWED, &mapping, &granted, &result);
    ok(status == STATUS_SUCCESS && result == STATUS_SUCCESS, "no DACL max -> %08lx/%08lx",
       (unsigned long)status, (unsigned long)result);
    ok(granted == mapping.GenericAll, "no DACL max granted %08lx", (unsigned long)granted);

    /* --- empty DACL (present, zero aces): everything is denied ---------------- */
    put_acl(acl_buf, sizeof(ACL), 0);
    build_sd(sd_buf, owner.buf, group.buf, 1, acl_buf, sizeof(ACL));
    status = check(token, sd_buf, EVENT_QUERY_STATE, &mapping, &granted, &result);
    ok(status == STATUS_SUCCESS, "empty DACL -> %08lx", (unsigned long)status);
    ok(result == STATUS_ACCESS_DENIED, "empty DACL result %08lx", (unsigned long)result);
    ok(granted == 0, "empty DACL granted %08lx", (unsigned long)granted);

    /* ... but the owner short-circuit still grants the standard set, when
     * that is all the caller asks for (the token's owner IS in the token) */
    status = check(token, sd_buf, READ_CONTROL, &mapping, &granted, &result);
    ok(status == STATUS_SUCCESS && result == STATUS_SUCCESS, "owner rc -> %08lx/%08lx",
       (unsigned long)status, (unsigned long)result);
    ok(granted == READ_CONTROL, "owner rc granted %08lx", (unsigned long)granted);

    status =
        check(token, sd_buf, STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE, &mapping, &granted, &result);
    ok(status == STATUS_SUCCESS && result == STATUS_SUCCESS, "owner std -> %08lx/%08lx",
       (unsigned long)status, (unsigned long)result);
    ok(granted == (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE), "owner std granted %08lx",
       (unsigned long)granted);

    /* an SD owned by someone not in the token gets no short-circuit */
    sid_buf other_owner;
    static const SID_IDENTIFIER_AUTHORITY nt_auth = {SECURITY_NT_AUTHORITY};
    static const DWORD other_subs[] = {SECURITY_NT_NON_UNIQUE, 1, 2, 3, 4242};
    make_sid(other_owner.buf, nt_auth, 5, other_subs);
    build_sd(sd_buf, other_owner.buf, group.buf, 1, acl_buf, sizeof(ACL));
    status = check(token, sd_buf, READ_CONTROL, &mapping, &granted, &result);
    ok(status == STATUS_SUCCESS, "foreign owner -> %08lx", (unsigned long)status);
    ok(result == STATUS_ACCESS_DENIED, "foreign owner result %08lx", (unsigned long)result);

    /* --- an allow ACE for Everyone ------------------------------------------- */
    at = sizeof(ACL);
    at += put_ace(acl_buf + at, ACCESS_ALLOWED_ACE_TYPE, 0, EVENT_MODIFY_STATE, world.buf);
    put_acl(acl_buf, at, 1);
    acl_len = at;
    build_sd(sd_buf, owner.buf, group.buf, 1, acl_buf, acl_len);

    status = check(token, sd_buf, EVENT_MODIFY_STATE, &mapping, &granted, &result);
    ok(status == STATUS_SUCCESS && result == STATUS_SUCCESS, "allow ace -> %08lx/%08lx",
       (unsigned long)status, (unsigned long)result);
    ok(granted == EVENT_MODIFY_STATE, "allow ace granted %08lx", (unsigned long)granted);

    status = check(token, sd_buf, EVENT_QUERY_STATE, &mapping, &granted, &result);
    ok(status == STATUS_SUCCESS, "ungranted right -> %08lx", (unsigned long)status);
    ok(result == STATUS_ACCESS_DENIED, "ungranted right result %08lx", (unsigned long)result);

    /* generic mask inside an ACE is mapped per-ACE */
    at = sizeof(ACL);
    at += put_ace(acl_buf + at, ACCESS_ALLOWED_ACE_TYPE, 0, GENERIC_ALL, world.buf);
    put_acl(acl_buf, at, 1);
    build_sd(sd_buf, owner.buf, group.buf, 1, acl_buf, at);
    status = check(token, sd_buf, MAXIMUM_ALLOWED, &mapping, &granted, &result);
    ok(status == STATUS_SUCCESS && result == STATUS_SUCCESS, "generic ace -> %08lx/%08lx",
       (unsigned long)status, (unsigned long)result);
    ok(granted == mapping.GenericAll, "generic ace granted %08lx", (unsigned long)granted);

    /* --- deny beats a later allow; INHERIT_ONLY aces are skipped -------------- */
    at = sizeof(ACL);
    at += put_ace(acl_buf + at, ACCESS_DENIED_ACE_TYPE, 0, EVENT_MODIFY_STATE, admins.buf);
    at += put_ace(acl_buf + at, ACCESS_ALLOWED_ACE_TYPE, 0, EVENT_MODIFY_STATE | EVENT_QUERY_STATE,
                  world.buf);
    put_acl(acl_buf, at, 2);
    build_sd(sd_buf, owner.buf, group.buf, 1, acl_buf, at);

    status = check(token, sd_buf, EVENT_MODIFY_STATE, &mapping, &granted, &result);
    ok(status == STATUS_SUCCESS, "deny walk -> %08lx", (unsigned long)status);
    ok(result == STATUS_ACCESS_DENIED, "denied result %08lx", (unsigned long)result);

    status = check(token, sd_buf, EVENT_QUERY_STATE, &mapping, &granted, &result);
    ok(status == STATUS_SUCCESS && result == STATUS_SUCCESS, "non-denied bit -> %08lx/%08lx",
       (unsigned long)status, (unsigned long)result);
    ok(granted == EVENT_QUERY_STATE, "non-denied granted %08lx", (unsigned long)granted);

    /* MAXIMUM_ALLOWED accumulates: the owner short-circuit's standard set
     * (the SD's owner is in the token) plus the allowed bits minus denied */
    status = check(token, sd_buf, MAXIMUM_ALLOWED, &mapping, &granted, &result);
    ok(status == STATUS_SUCCESS && result == STATUS_SUCCESS, "max with deny -> %08lx/%08lx",
       (unsigned long)status, (unsigned long)result);
    ok(granted == (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | EVENT_QUERY_STATE),
       "max with deny granted %08lx", (unsigned long)granted);

    /* the same deny ACE marked INHERIT_ONLY is ignored */
    at = sizeof(ACL);
    at += put_ace(acl_buf + at, ACCESS_DENIED_ACE_TYPE, INHERIT_ONLY_ACE, EVENT_MODIFY_STATE,
                  admins.buf);
    at += put_ace(acl_buf + at, ACCESS_ALLOWED_ACE_TYPE, 0, EVENT_MODIFY_STATE, world.buf);
    put_acl(acl_buf, at, 2);
    build_sd(sd_buf, owner.buf, group.buf, 1, acl_buf, at);
    status = check(token, sd_buf, EVENT_MODIFY_STATE, &mapping, &granted, &result);
    ok(status == STATUS_SUCCESS && result == STATUS_SUCCESS, "inherit-only -> %08lx/%08lx",
       (unsigned long)status, (unsigned long)result);
    ok(granted == EVENT_MODIFY_STATE, "inherit-only granted %08lx", (unsigned long)granted);

    /* --- an absolute-format SD behaves identically ----------------------------
     * (on the oracle ntdll's marshalling normalizes; on proskrnl the kernel's
     * capture path must accept both forms) */
    SECURITY_DESCRIPTOR abs_sd;
    memset(&abs_sd, 0, sizeof(abs_sd));
    abs_sd.Revision = SECURITY_DESCRIPTOR_REVISION;
    abs_sd.Control = SE_DACL_PRESENT;
    abs_sd.Owner = (PSID)owner.buf;
    abs_sd.Group = (PSID)group.buf;
    abs_sd.Dacl = (PACL)acl_buf; /* the inherit-only + allow ACL from above */
    status = check(token, &abs_sd, EVENT_MODIFY_STATE, &mapping, &granted, &result);
    ok(status == STATUS_SUCCESS && result == STATUS_SUCCESS, "absolute SD -> %08lx/%08lx",
       (unsigned long)status, (unsigned long)result);
    ok(granted == EVENT_MODIFY_STATE, "absolute SD granted %08lx", (unsigned long)granted);

    /* --- NtPrivilegeCheck ------------------------------------------------------
     * (the boot token: SeChangeNotify enabled, SeDebug present but disabled) */
    ps_buf two;
    BOOLEAN held;

    two.PrivilegeCount = 1;
    two.Control = PRIVILEGE_SET_ALL_NECESSARY;
    two.Privilege[0].Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
    two.Privilege[0].Luid.HighPart = 0;
    two.Privilege[0].Attributes = 0;
    status = NtPrivilegeCheck(token, PS(two), &held);
    ok(status == STATUS_SUCCESS, "check held -> %08lx", (unsigned long)status);
    ok(held, "SeChangeNotify not held");
    /* the write-back marks used privileges */
    ok(two.Privilege[0].Attributes == SE_PRIVILEGE_USED_FOR_ACCESS, "used mark %08lx",
       (unsigned long)two.Privilege[0].Attributes);

    two.Privilege[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
    two.Privilege[0].Attributes = 0;
    status = NtPrivilegeCheck(token, PS(two), &held);
    ok(status == STATUS_SUCCESS, "check disabled -> %08lx", (unsigned long)status);
    ok(!held, "disabled SeDebug counted as held");
    ok(two.Privilege[0].Attributes == 0, "disabled marked used: %08lx",
       (unsigned long)two.Privilege[0].Attributes);

    /* ALL_NECESSARY vs any-of, over {held, not held} */
    two.PrivilegeCount = 2;
    two.Control = PRIVILEGE_SET_ALL_NECESSARY;
    two.Privilege[0].Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
    two.Privilege[0].Luid.HighPart = 0;
    two.Privilege[0].Attributes = 0;
    two.Privilege[1].Luid.LowPart = SE_DEBUG_PRIVILEGE;
    two.Privilege[1].Luid.HighPart = 0;
    two.Privilege[1].Attributes = 0;
    status = NtPrivilegeCheck(token, PS(two), &held);
    ok(status == STATUS_SUCCESS && !held, "all-necessary with one missing held");

    two.Control = 0;
    two.Privilege[0].Attributes = 0;
    two.Privilege[1].Attributes = 0;
    status = NtPrivilegeCheck(token, PS(two), &held);
    ok(status == STATUS_SUCCESS && held, "any-of with one held not held");

    /* a primary token is fine for NtPrivilegeCheck (unlike NtAccessCheck) */
    two.PrivilegeCount = 1;
    two.Control = 0;
    two.Privilege[0].Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
    two.Privilege[0].Attributes = 0;
    status = NtPrivilegeCheck(process_token, PS(two), &held);
    ok(status == STATUS_SUCCESS && held, "primary token check -> %08lx", (unsigned long)status);

    NtClose(token);
    NtClose(process_token);
}
