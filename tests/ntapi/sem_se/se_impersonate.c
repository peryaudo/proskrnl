/*
 * sem_se/se_impersonate.c — thread impersonation attach (CUI-6, Se-2).
 *
 * The RtlImpersonateSelf / SetThreadToken / RevertToSelf mechanism, which
 * runs through NtSetInformationThread(ThreadImpersonationToken) — not a
 * token syscall. Oracle behaviour pinned from the pinned tree
 * (dlls/ntdll/unix/thread.c set_thread_info; server/thread.c
 * security_set_thread_token; server/token.c open_token OPEN_TOKEN_THREAD):
 * attaching an impersonation token (handle needs TOKEN_IMPERSONATE) makes
 * NtOpenThreadToken succeed and the ~4 effective-thread-token pseudo-handle
 * resolve; a length other than sizeof(HANDLE) is STATUS_INVALID_PARAMETER;
 * a NULL handle reverts (RevertToSelf), after which NtOpenThreadToken is
 * STATUS_NO_TOKEN again; an anonymous-level thread token opens with
 * STATUS_CANT_OPEN_ANONYMOUS.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtSetInformationThread(HANDLE, THREADINFOCLASS, PVOID, ULONG);

#ifndef ThreadImpersonationToken
#define ThreadImpersonationToken ((THREADINFOCLASS)5)
#endif
#ifndef STATUS_CANT_OPEN_ANONYMOUS
#define STATUS_CANT_OPEN_ANONYMOUS ((NTSTATUS)0xC00000A6)
#endif

static NTSTATUS attach(HANDLE tokenHandle)
{
    return NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &tokenHandle,
                                  sizeof(tokenHandle));
}

/* Duplicate as an impersonation token with TOKEN_IMPERSONATE — the access
 * security_set_thread_token resolves the handle with (server/thread.c). */
static NTSTATUS dup_impersonation_access(HANDLE src, SECURITY_IMPERSONATION_LEVEL level,
                                         HANDLE *out)
{
    SECURITY_QUALITY_OF_SERVICE qos;
    OBJECT_ATTRIBUTES attr;
    qos.Length = sizeof(qos);
    qos.ImpersonationLevel = level;
    qos.ContextTrackingMode = 0;
    qos.EffectiveOnly = FALSE;
    memset(&attr, 0, sizeof(attr));
    attr.Length = sizeof(attr);
    attr.SecurityQualityOfService = &qos;
    return NtDuplicateToken(src, TOKEN_IMPERSONATE | TOKEN_QUERY, &attr, FALSE, TokenImpersonation,
                            out);
}

START_TEST(se_impersonate)
{
    NTSTATUS status;
    HANDLE processToken = NULL, impToken = NULL, threadToken = NULL;
    ULONG retlen = 0;
    TOKEN_TYPE type = 0;

    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &processToken);
    ok(status == STATUS_SUCCESS, "open process token -> %08lx", (unsigned long)status);
    if (processToken == NULL)
    {
        skip("no process token");
        return;
    }

    /* --- no thread token to begin with ------------------------------------ */
    status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY, TRUE, &threadToken);
    ok(status == STATUS_NO_TOKEN, "no thread token initially -> %08lx", (unsigned long)status);

    /* --- attach a SecurityImpersonation token ----------------------------- */
    status = dup_impersonation_access(processToken, SecurityImpersonation, &impToken);
    ok(status == STATUS_SUCCESS, "duplicate impersonation token -> %08lx", (unsigned long)status);

    /* Wrong length refuses. */
    status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &impToken,
                                    sizeof(impToken) - 1);
    ok(status == STATUS_INVALID_PARAMETER, "bad-length attach -> %08lx", (unsigned long)status);

    status = attach(impToken);
    ok(status == STATUS_SUCCESS, "attach -> %08lx", (unsigned long)status);

    /* NtOpenThreadToken now succeeds and names an impersonation token. */
    threadToken = NULL;
    status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY, TRUE, &threadToken);
    ok(status == STATUS_SUCCESS, "open thread token after attach -> %08lx", (unsigned long)status);
    if (threadToken != NULL)
    {
        status = NtQueryInformationToken(threadToken, TokenType, &type, sizeof(type), &retlen);
        ok(status == STATUS_SUCCESS, "query thread token -> %08lx", (unsigned long)status);
        ok(type == TokenImpersonation, "thread token is impersonation (%d)", type);
        NtClose(threadToken);
    }

    /* The ~4 effective-thread-token pseudo-handle now resolves. */
    type = 0;
    status =
        NtQueryInformationToken(GetCurrentThreadToken(), TokenType, &type, sizeof(type), &retlen);
    ok(status == STATUS_SUCCESS, "~4 resolves after attach -> %08lx", (unsigned long)status);

    /* --- revert (RevertToSelf): NULL handle -------------------------------- */
    status = attach(NULL);
    ok(status == STATUS_SUCCESS, "revert -> %08lx", (unsigned long)status);
    threadToken = (HANDLE)(ULONG_PTR)0xabc;
    status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY, TRUE, &threadToken);
    ok(status == STATUS_NO_TOKEN, "no thread token after revert -> %08lx", (unsigned long)status);
    status =
        NtQueryInformationToken(GetCurrentThreadToken(), TokenType, &type, sizeof(type), &retlen);
    ok(status == STATUS_INVALID_HANDLE, "~4 refuses after revert -> %08lx", (unsigned long)status);

    /* --- an anonymous-level token opens CANT_OPEN_ANONYMOUS ---------------- */
    {
        HANDLE anon = NULL;
        status = dup_impersonation_access(processToken, SecurityAnonymous, &anon);
        ok(status == STATUS_SUCCESS, "duplicate anonymous token -> %08lx", (unsigned long)status);
        if (anon != NULL)
        {
            status = attach(anon);
            ok(status == STATUS_SUCCESS, "attach anonymous -> %08lx", (unsigned long)status);
            threadToken = NULL;
            status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY, TRUE, &threadToken);
            ok(status == STATUS_CANT_OPEN_ANONYMOUS, "open anonymous thread token -> %08lx",
               (unsigned long)status);
            attach(NULL); /* revert */
            NtClose(anon);
        }
    }

    NtClose(impToken);
    NtClose(processToken);
}
