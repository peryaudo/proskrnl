/*
 * sem_se/se_adjust_hostile.c — NtAdjustPrivilegesToken's NewState pointer is
 * mandatory unless DisableAllPrivileges says otherwise, and a bad one is a
 * status rather than a fault.
 *
 * Convicted by the pointer-torture matrix (issue #32 A1,
 * tests/ntapi/syscall/ptr_torture.c): with DisableAllPrivileges FALSE the
 * service reads `newState->PrivilegeCount` (kernel/se/token.c) with no NULL
 * check in front of it, so a NULL NewState formed a member address on a null
 * pointer — undefined behaviour, which this kernel builds as a trap, which
 * is a #UD, which is a machine halt from an unprivileged caller. The
 * dispatcher's fault-recovery frame does not help: it catches page faults,
 * and a UBSan trap is not one.
 *
 * The shape is worth naming, because it is not "a missing probe". The read
 * DOES go through KiCopyFromUser — the right authority, doing the right
 * validation. It is the ADDRESS ARITHMETIC in the argument, `&p->member`,
 * that runs first and is already undefined for p == NULL, before any probe
 * can be consulted. Every capture written that way has the same hole, and
 * NULL is the one hostile pointer every caller can produce by accident.
 *
 * Oracle-first (G5): measured under the pinned Wine before the kernel
 * change. DisableAllPrivileges TRUE is the control — there NewState is
 * genuinely optional (wineserver's token_disable_privileges path never looks
 * at it), so the same NULL must SUCCEED, which is what makes the refusal
 * above about the pointer rather than about the argument being absent.
 */
#include "util.h"

/* Unmapped and ALIGNED (sem_file/hostile_name.c explains why alignment is
 * held constant); NULL is tested separately because it is its own case. */
#define BAD_POINTER ((void *)(ULONG_PTR)0x1000)

START_TEST(se_adjust_hostile)
{
    NTSTATUS status;
    HANDLE token = NULL;
    DWORD retlen;
    tp_buf prev;

    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);
    ok(status == STATUS_SUCCESS, "open -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return;

    /* NewState NULL, and it is not optional here. */
    status = NtAdjustPrivilegesToken(token, FALSE, NULL, 0, NULL, NULL);
    ok(status == STATUS_ACCESS_VIOLATION, "NULL NewState -> %08lx", (unsigned long)status);

    /* NewState unreadable. */
    status = NtAdjustPrivilegesToken(token, FALSE, BAD_POINTER, 0, NULL, NULL);
    ok(status == STATUS_ACCESS_VIOLATION, "unreadable NewState -> %08lx", (unsigned long)status);

    /* PreviousState unwritable, with a well-formed NewState. The adjust
     * itself is a no-op (a zero PrivilegeCount), so this asks only about the
     * reply buffer. */
    {
        tp_buf in;
        memset(&in, 0, sizeof(in));
        in.PrivilegeCount = 0;
        retlen = 0xdead;
        status = NtAdjustPrivilegesToken(token, FALSE, TP(in), sizeof(prev), BAD_POINTER, &retlen);
        ok(status == STATUS_ACCESS_VIOLATION, "unwritable PreviousState -> %08lx",
           (unsigned long)status);
    }

    /* The control: with DisableAllPrivileges the same NULL NewState is
     * legal, so the refusals above are about the POINTER and not about the
     * service refusing everything. Re-enabling is left to the token's own
     * isolation (each test process gets a fresh one) — se_adjust.c owns the
     * enable/disable semantics; this file owns only the refusals. */
    status = NtAdjustPrivilegesToken(token, TRUE, NULL, 0, NULL, NULL);
    ok(status == STATUS_SUCCESS, "control: DisableAllPrivileges with a NULL NewState -> %08lx",
       (unsigned long)status);

    NtClose(token);
}
