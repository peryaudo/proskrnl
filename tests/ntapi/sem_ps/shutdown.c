/*
 * sem_ps/shutdown.c — NtShutdownSystem's refusal arms (CUI-7).
 *
 * The pinned oracle stubs the whole service (dlls/ntdll/unix/system.c:
 * FIXME + STATUS_SUCCESS), so both arms are beyond_oracle against
 * Microsoft documentation — and both leave the machine running:
 *
 *   - "NtShutdownSystem" / "Privilege Constants (SE_SHUTDOWN_NAME)",
 *     learn.microsoft.com: the caller needs SeShutdownPrivilege — present
 *     but disabled in the default token, so the call refuses
 *     STATUS_PRIVILEGE_NOT_HELD.
 *   - SHUTDOWN_ACTION (winternl.h) has exactly ShutdownNoReboot /
 *     ShutdownReboot / ShutdownPowerOff; anything else refuses
 *     STATUS_INVALID_PARAMETER even with the privilege enabled.
 *
 * The live arms (the machine actually halting / rebooting) are exercised
 * by the tests/run cui7 acceptance leg, never here.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtShutdownSystem(ULONG);
NTSYSAPI NTSTATUS NTAPI NtOpenProcessToken(HANDLE, DWORD, HANDLE *);
NTSYSAPI NTSTATUS NTAPI NtAdjustPrivilegesToken(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, DWORD,
                                                PTOKEN_PRIVILEGES, PDWORD);

#define PRSK_SE_SHUTDOWN_PRIVILEGE 19

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

START_TEST(shutdown)
{
    NTSTATUS status;

    beyond_oracle
    {
        /* Without the privilege, every action refuses. */
        status = NtShutdownSystem(0 /* ShutdownNoReboot */);
        ok(status == STATUS_PRIVILEGE_NOT_HELD, "shutdown without priv -> %08lx",
           (unsigned long)status);
        status = NtShutdownSystem(2 /* ShutdownPowerOff */);
        ok(status == STATUS_PRIVILEGE_NOT_HELD, "poweroff without priv -> %08lx",
           (unsigned long)status);

        /* With it, an out-of-range action still refuses — and the machine
         * survives to report it. */
        status = set_privilege(PRSK_SE_SHUTDOWN_PRIVILEGE, TRUE);
        ok(status == STATUS_SUCCESS, "enable SeShutdown -> %08lx", (unsigned long)status);
        status = NtShutdownSystem(99);
        ok(status == STATUS_INVALID_PARAMETER, "bad action -> %08lx", (unsigned long)status);
        set_privilege(PRSK_SE_SHUTDOWN_PRIVILEGE, FALSE);
    }
}
