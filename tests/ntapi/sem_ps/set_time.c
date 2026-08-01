/*
 * sem_ps/set_time.c — NtSetSystemTime and the SystemTimeAdjustmentInformation
 * pair (CUI-7).
 *
 * Differential arms (wine dlls/ntdll/unix/sync.c NtSetSystemTime;
 * dlls/ntdll/unix/system.c NtQuerySystemInformation class 28): *old is
 * always written with the current time; a set within half a second of now
 * is a success no-op; a larger set without SeSystemtimePrivilege (disabled
 * by default in the token on both sides) is STATUS_PRIVILEGE_NOT_HELD. The
 * adjustment query answers {156250, 156250, TRUE} at exactly
 * sizeof(SYSTEM_TIME_ADJUSTMENT_QUERY) and STATUS_INFO_LENGTH_MISMATCH at
 * any other length — pinned BEFORE any set, where the oracle's fixed
 * answer and proskrnl's stored state coincide.
 *
 * beyond_oracle arms, against Microsoft documentation (the oracle refuses
 * large sets outright and stubs the setter): "SetSystemTime function" +
 * "SetSystemTimeAdjustment function" + "Privilege Constants
 * (SE_SYSTEMTIME_NAME)", learn.microsoft.com — with the privilege enabled
 * the clock really moves (observable through NtQuerySystemTime) and is
 * restored immediately (sem_ps/time.c's wall-clock floor must stay true);
 * the adjustment setter stores state the query then reflects, refuses
 * without the privilege, and unknown classes/lengths refuse with
 * STATUS_INVALID_INFO_CLASS / STATUS_INFO_LENGTH_MISMATCH.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtSetSystemTime(const LARGE_INTEGER *, LARGE_INTEGER *);
NTSYSAPI NTSTATUS NTAPI NtSetSystemInformation(ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtQuerySystemTime(PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtOpenProcessToken(HANDLE, DWORD, HANDLE *);
NTSYSAPI NTSTATUS NTAPI NtAdjustPrivilegesToken(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, DWORD,
                                                PTOKEN_PRIVILEGES, PDWORD);

#define SYSTEM_TIME_ADJUSTMENT_INFO  28
#define PRSK_SE_SYSTEMTIME_PRIVILEGE 12

typedef struct
{
    ULONG time_adjustment;
    BOOLEAN time_adjustment_disabled;
} sys_time_adjustment;

typedef struct
{
    ULONG time_adjustment;
    ULONG time_increment;
    BOOLEAN time_adjustment_disabled;
} sys_time_adjustment_query;

#define TICKS_PER_SEC 10000000LL

static NTSTATUS set_privilege(DWORD luidLow, BOOLEAN enable)
{
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    NTSTATUS status =
        NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);
    if (!NT_SUCCESS(status))
        return status;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid.LowPart = luidLow;
    tp.Privileges[0].Luid.HighPart = 0;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
    status = NtAdjustPrivilegesToken(token, FALSE, &tp, 0, NULL, NULL);
    NtClose(token);
    return status;
}

START_TEST(set_time)
{
    NTSTATUS status;
    LARGE_INTEGER now, target, old, check;

    /* --- the adjustment query, pinned before any set ------------------------- */
    {
        sys_time_adjustment_query query;
        memset(&query, 0, sizeof(query));
        status = NtQuerySystemInformation(SYSTEM_TIME_ADJUSTMENT_INFO, &query, sizeof(query), NULL);
        ok(status == STATUS_SUCCESS, "adjustment query -> %08lx", (unsigned long)status);
        ok(query.time_adjustment == 156250 && query.time_increment == 156250 &&
               query.time_adjustment_disabled == TRUE,
           "adjustment defaults (%lu %lu %u)", (unsigned long)query.time_adjustment,
           (unsigned long)query.time_increment, query.time_adjustment_disabled);
        status = NtQuerySystemInformation(SYSTEM_TIME_ADJUSTMENT_INFO, &query, 8, NULL);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "short adjustment query -> %08lx",
           (unsigned long)status);
        status = NtQuerySystemInformation(SYSTEM_TIME_ADJUSTMENT_INFO, &query, 16, NULL);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "long adjustment query -> %08lx",
           (unsigned long)status);
    }

    /* --- small diff: success no-op; *old always the current time ------------- */
    status = NtQuerySystemTime(&now);
    ok(status == STATUS_SUCCESS, "query time -> %08lx", (unsigned long)status);
    target.QuadPart = now.QuadPart + TICKS_PER_SEC / 5; /* +0.2 s */
    old.QuadPart = 0;
    status = NtSetSystemTime(&target, &old);
    ok(status == STATUS_SUCCESS, "small set -> %08lx", (unsigned long)status);
    ok(old.QuadPart >= now.QuadPart && old.QuadPart - now.QuadPart < 5 * TICKS_PER_SEC,
       "*old is the current time");
    status = NtQuerySystemTime(&check);
    ok(check.QuadPart - now.QuadPart < 5 * TICKS_PER_SEC, "small set was a no-op");

    /* --- large diff without the privilege refuses ---------------------------- */
    target.QuadPart = now.QuadPart + 3600 * TICKS_PER_SEC;
    old.QuadPart = 0;
    status = NtSetSystemTime(&target, &old);
    ok(status == STATUS_PRIVILEGE_NOT_HELD, "unprivileged set -> %08lx", (unsigned long)status);

    /* --- the privileged arms (the oracle refuses / stubs these) -------------- */
    beyond_oracle
    {
        status = set_privilege(PRSK_SE_SYSTEMTIME_PRIVILEGE, TRUE);
        ok(status == STATUS_SUCCESS, "enable SeSystemtime -> %08lx", (unsigned long)status);

        /* The clock really moves, and is restored immediately. */
        status = NtQuerySystemTime(&now);
        ok(status == STATUS_SUCCESS, "query before set -> %08lx", (unsigned long)status);
        target.QuadPart = now.QuadPart + 3600 * TICKS_PER_SEC;
        old.QuadPart = 0;
        status = NtSetSystemTime(&target, &old);
        ok(status == STATUS_SUCCESS, "privileged set -> %08lx", (unsigned long)status);
        ok(old.QuadPart >= now.QuadPart && old.QuadPart - now.QuadPart < 5 * TICKS_PER_SEC,
           "*old before the jump");
        status = NtQuerySystemTime(&check);
        ok(status == STATUS_SUCCESS, "query after set -> %08lx", (unsigned long)status);
        ok(check.QuadPart - now.QuadPart >= 3590 * TICKS_PER_SEC,
           "clock moved forward (~1h: %lld s)",
           (long long)((check.QuadPart - now.QuadPart) / TICKS_PER_SEC));
        /* Restore: subtract the same hour from the CURRENT reading so the
         * elapsed test time survives the round-trip. */
        status = NtQuerySystemTime(&check);
        target.QuadPart = check.QuadPart - 3600 * TICKS_PER_SEC;
        status = NtSetSystemTime(&target, NULL);
        ok(status == STATUS_SUCCESS, "restore clock -> %08lx", (unsigned long)status);
        status = NtQuerySystemTime(&check);
        ok(check.QuadPart - now.QuadPart < 60 * TICKS_PER_SEC, "clock restored");

        /* The adjustment setter: privilege-gated, stored, reflected. */
        sys_time_adjustment adjust;
        sys_time_adjustment_query query;
        status = set_privilege(PRSK_SE_SYSTEMTIME_PRIVILEGE, FALSE);
        ok(status == STATUS_SUCCESS, "disable SeSystemtime -> %08lx", (unsigned long)status);
        adjust.time_adjustment = 100000;
        adjust.time_adjustment_disabled = FALSE;
        status = NtSetSystemInformation(SYSTEM_TIME_ADJUSTMENT_INFO, &adjust, sizeof(adjust));
        ok(status == STATUS_PRIVILEGE_NOT_HELD, "unprivileged adjust -> %08lx",
           (unsigned long)status);
        status = set_privilege(PRSK_SE_SYSTEMTIME_PRIVILEGE, TRUE);
        ok(status == STATUS_SUCCESS, "re-enable SeSystemtime -> %08lx", (unsigned long)status);
        status = NtSetSystemInformation(SYSTEM_TIME_ADJUSTMENT_INFO, &adjust, 3);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "short adjust -> %08lx", (unsigned long)status);
        status = NtSetSystemInformation(SYSTEM_TIME_ADJUSTMENT_INFO, &adjust, sizeof(adjust));
        ok(status == STATUS_SUCCESS, "adjust -> %08lx", (unsigned long)status);
        memset(&query, 0, sizeof(query));
        status = NtQuerySystemInformation(SYSTEM_TIME_ADJUSTMENT_INFO, &query, sizeof(query), NULL);
        ok(status == STATUS_SUCCESS, "query adjusted -> %08lx", (unsigned long)status);
        ok(query.time_adjustment == 100000 && query.time_increment == 156250 &&
               query.time_adjustment_disabled == FALSE,
           "adjustment reflected (%lu %lu %u)", (unsigned long)query.time_adjustment,
           (unsigned long)query.time_increment, query.time_adjustment_disabled);
        /* Restore the boot state. */
        adjust.time_adjustment = 156250;
        adjust.time_adjustment_disabled = TRUE;
        status = NtSetSystemInformation(SYSTEM_TIME_ADJUSTMENT_INFO, &adjust, sizeof(adjust));
        ok(status == STATUS_SUCCESS, "restore adjust -> %08lx", (unsigned long)status);

        /* Unknown set classes refuse loudly with the specific NT failure. */
        status = NtSetSystemInformation(200, &adjust, sizeof(adjust));
        ok(status == STATUS_INVALID_INFO_CLASS, "unknown set class -> %08lx",
           (unsigned long)status);

        set_privilege(PRSK_SE_SYSTEMTIME_PRIVILEGE, FALSE);
    }
}
