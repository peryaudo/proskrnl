/*
 * sem_se/se_setinfo.c — NtSetInformationToken (CUI-6, Se-2).
 *
 * SetTokenInformation's back end. Only three classes reach the pinned
 * tree's unix layer (dlls/ntdll/unix/security.c NtSetInformationToken):
 * TokenDefaultDacl (the one with real semantics — needs TOKEN_ADJUST_DEFAULT,
 * server/token.c set_token_default_dacl; length is checked BEFORE the
 * null-pointer check; a zero-size DACL clears it; a malformed ACL is
 * STATUS_INVALID_ACL), and TokenSessionId / TokenIntegrityLevel, which the
 * oracle accepts as a no-op under its own FIXME (a pinned fixed answer,
 * G12-legal). Every other class the oracle answers STATUS_NOT_IMPLEMENTED
 * for, so none is pinned (G12).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtSetInformationToken(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG);

#ifndef STATUS_INVALID_ACL
#define STATUS_INVALID_ACL ((NTSTATUS)0xC0000077)
#endif

START_TEST(se_setinfo)
{
    NTSTATUS status;
    HANDLE token = NULL;

    status = NtOpenProcessToken(
        NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, &token);
    ok(status == STATUS_SUCCESS, "open token -> %08lx", (unsigned long)status);
    if (token == NULL)
    {
        skip("no process token");
        return;
    }

    /* --- TokenDefaultDacl: length checked before the null pointer -------- */
    status = NtSetInformationToken(token, TokenDefaultDacl, NULL, sizeof(TOKEN_DEFAULT_DACL) - 1);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short default dacl -> %08lx", (unsigned long)status);

    /* Build a fresh DACL (one allow ACE) and install it. */
    sid_buf world;
    ULONG worldLen = sid_world(&world);
    BYTE aclBuf[256];
    ULONG aceLen =
        put_ace(aclBuf + sizeof(ACL), 0 /* ACCESS_ALLOWED_ACE_TYPE */, 0, GENERIC_ALL, world.buf);
    put_acl(aclBuf, sizeof(ACL) + aceLen, 1);
    (void)worldLen;

    TOKEN_DEFAULT_DACL setDacl;
    setDacl.DefaultDacl = (PACL)aclBuf;
    status = NtSetInformationToken(token, TokenDefaultDacl, &setDacl, sizeof(setDacl));
    ok(status == STATUS_SUCCESS, "set default dacl -> %08lx", (unsigned long)status);

    /* Read it back — the installed ACL size must match. */
    {
        BYTE queryBuf[512];
        ULONG retlen = 0;
        status =
            NtQueryInformationToken(token, TokenDefaultDacl, queryBuf, sizeof(queryBuf), &retlen);
        ok(status == STATUS_SUCCESS, "query default dacl -> %08lx", (unsigned long)status);
        TOKEN_DEFAULT_DACL *got = (TOKEN_DEFAULT_DACL *)queryBuf;
        ok(got->DefaultDacl != NULL, "default dacl present");
        if (got->DefaultDacl != NULL)
        {
            ok(got->DefaultDacl->AclSize == ((ACL *)aclBuf)->AclSize, "dacl size %u vs %u",
               got->DefaultDacl->AclSize, ((ACL *)aclBuf)->AclSize);
        }
    }

    /* --- zero-size DACL clears it ---------------------------------------- */
    {
        TOKEN_DEFAULT_DACL clear;
        clear.DefaultDacl = NULL;
        status = NtSetInformationToken(token, TokenDefaultDacl, &clear, sizeof(clear));
        ok(status == STATUS_SUCCESS, "clear default dacl -> %08lx", (unsigned long)status);
        BYTE queryBuf[512];
        ULONG retlen = 0;
        status =
            NtQueryInformationToken(token, TokenDefaultDacl, queryBuf, sizeof(queryBuf), &retlen);
        ok(status == STATUS_SUCCESS, "query cleared dacl -> %08lx", (unsigned long)status);
        ok(((TOKEN_DEFAULT_DACL *)queryBuf)->DefaultDacl == NULL, "dacl cleared");
    }

    /* --- TokenSessionId / TokenIntegrityLevel: accepted no-ops ----------- */
    {
        ULONG session = 1;
        status = NtSetInformationToken(token, TokenSessionId, &session, sizeof(session));
        ok(status == STATUS_SUCCESS, "set session id -> %08lx", (unsigned long)status);
    }

    NtClose(token);
}
