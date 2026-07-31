/*
 * sem_ps/continue_bad_rip.c — NtContinue to an address outside user space is
 * an access violation delivered to the process, not a refusal and not a
 * kernel fault.
 *
 * IRET checks the CS:RIP it loads, so resuming a ring-3 CONTEXT whose Rip is
 * non-canonical raises #GP with the KERNEL CS still loaded -- which is a
 * machine halt on behalf of an unprivileged caller. (Choosing iretq over
 * sysret for the return path correctly avoids the classic
 * non-canonical-RCX hole; IRET has its own.)
 *
 * The oracle answers with STATUS_ACCESS_VIOLATION reported to the thread,
 * exactly as it would if the address were merely unmapped, so that is what
 * is pinned here (Art. 5, green on Wine first). The handler returns
 * CONTINUE_SEARCH -- there is nothing to resume to -- so the test observes
 * the code and then unwinds through its own second NtContinue.
 */
#include "../ntapi.h"

#include <windows.h>

NTSYSAPI NTSTATUS NTAPI NtContinue(CONTEXT *, BOOLEAN);

/* volatile: written from the exception handler mid-statement. */
static volatile LONG fault_hits;
static volatile DWORD fault_code;
static CONTEXT resume_context;

static LONG CALLBACK bad_rip_veh(EXCEPTION_POINTERS *info)
{
    fault_hits++;
    fault_code = info->ExceptionRecord->ExceptionCode;
    /* Resume somewhere sane: back at the captured context, with the
     * `attempted` flag already set so the second pass falls through. */
    NtContinue(&resume_context, FALSE);
    return EXCEPTION_CONTINUE_SEARCH; /* never reached */
}

START_TEST(continue_bad_rip)
{
    static volatile int attempted = 0;
    CONTEXT bad;
    void *handler;

    handler = AddVectoredExceptionHandler(1, bad_rip_veh);
    ok(handler != NULL, "no vectored handler");
    if (handler == NULL)
        return;

    fault_hits = 0;
    fault_code = 0;

    memset(&resume_context, 0, sizeof(resume_context));
    resume_context.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&resume_context);

    if (!attempted)
    {
        attempted = 1;
        memset(&bad, 0, sizeof(bad));
        bad.ContextFlags = CONTEXT_FULL;
        RtlCaptureContext(&bad);
        /* The lowest non-canonical address on x86-64 with 48-bit linear
         * addresses (Intel SDM Vol. 1 §3.3.7.1): bit 47 set, bits 63:48
         * clear. Also above KI_USER_SPACE_LIMIT, so a kernel that bounds
         * rather than canonicalises catches it too. */
        bad.Rip = 0x0000800000000000ULL;
        NtContinue(&bad, FALSE);
        ok(0, "NtContinue with a bad Rip returned and resumed normally");
    }

    ok(fault_hits == 1, "bad-Rip continue raised %ld exceptions, expected 1", (long)fault_hits);
    ok(fault_code == (DWORD)STATUS_ACCESS_VIOLATION, "bad-Rip continue code %08lx, expected %08lx",
       (unsigned long)fault_code, (unsigned long)STATUS_ACCESS_VIOLATION);

    RemoveVectoredExceptionHandler(handler);
}
