/*
 * sem_ps/context_foreign.c — foreign-thread NtGet/SetContextThread (CUI-6).
 *
 * The sanctioned SuspendThread + GetThreadContext (+ SetThreadContext)
 * profiler/GC pattern (its debugger consumer is gone). Oracle behaviour
 * pinned from the pinned tree: a suspended sibling's context is readable
 * (Rip in user space, integer registers present), its XMM state comes back
 * through CONTEXT_FLOATING_POINT, and a written Rip redirects the thread on
 * resume. The proskrnl path reads the SUSPENDED target's saved trap frame
 * and fxArea rather than the live CPU; the oracle reads the real
 * ptrace/thread state, so both agree at this boundary.
 */
#include "util.h"

#include <windows.h>

static volatile LONG spin_rounds;
static volatile LONG spin_stop;
static volatile LONG escaped;
static volatile LONG escape_release;

/* A double whose bits we can recognise in the saved XMM6. */
static const double fp_sentinel = 1234.5;

static DWORD WINAPI spinner(void *param)
{
    (void)param;
    double val = fp_sentinel;
    while (!spin_stop)
    {
        /* Keep XMM6 pinned to the sentinel at every suspend point (XMM6 is
         * nonvolatile, so nothing else clobbers it between iterations). */
        __asm__ volatile("movsd %0, %%xmm6" ::"m"(val) : "xmm6");
        spin_rounds++;
    }
    return 0;
}

/* SetContext redirect target: mark, wait for release, then exit cleanly (its
 * own frame is valid — we align Rsp before redirecting). */
static void escape_routine(void)
{
    InterlockedExchange(&escaped, 1);
    while (!escape_release)
    {
        YieldProcessor();
    }
    ExitThread(0x1234);
}

START_TEST(context_foreign)
{
    NTSTATUS status;
    (void)status;

    /* --- read a suspended sibling's context -------------------------------- */
    spin_stop = 0;
    spin_rounds = 0;
    HANDLE thread = CreateThread(NULL, 0, spinner, NULL, 0, NULL);
    ok(thread != NULL, "create spinner");
    /* Let it run and load XMM6 at least once. */
    while (spin_rounds < 1000)
    {
        Sleep(1);
    }

    DWORD suspendCount = SuspendThread(thread);
    ok(suspendCount == 0, "suspend count %lu", (unsigned long)suspendCount);

    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_FLOATING_POINT;
    BOOL got = GetThreadContext(thread, &ctx);
    ok(got, "GetThreadContext foreign");
    ok(ctx.Rip != 0, "foreign Rip captured (%p)", (void *)ctx.Rip);
    ok(ctx.Rip < 0x00008000000000000ULL, "foreign Rip in user space");
    ok(ctx.Rsp != 0, "foreign Rsp captured");
    {
        ULONGLONG sentinelBits;
        memcpy(&sentinelBits, &fp_sentinel, sizeof(sentinelBits));
        ok(ctx.Xmm6.Low == sentinelBits, "foreign XMM6 sentinel (%016llx vs %016llx)",
           (unsigned long long)ctx.Xmm6.Low, (unsigned long long)sentinelBits);
    }

    /* --- redirect Rip and prove it took ------------------------------------ */
    escaped = 0;
    escape_release = 0;
    CONTEXT redirect;
    memset(&redirect, 0, sizeof(redirect));
    redirect.ContextFlags = CONTEXT_CONTROL;
    got = GetThreadContext(thread, &redirect);
    ok(got, "GetThreadContext for redirect");
    redirect.Rip = (ULONG_PTR)escape_routine;
    /* Jump (not call) leaves Rsp 16-aligned; the ABI wants rsp%16==8 at a
     * function's entry, so bias it down by 8. */
    redirect.Rsp = (redirect.Rsp & ~(ULONG_PTR)0xF) - 8;
    got = SetThreadContext(thread, &redirect);
    ok(got, "SetThreadContext redirect");

    spin_stop = 1; /* so if the redirect failed the loop would still end */
    ResumeThread(thread);

    DWORD waited = 0;
    while (!escaped && waited < 5000)
    {
        Sleep(5);
        waited += 5;
    }
    ok(escaped == 1, "redirected thread reached the escape routine");

    InterlockedExchange(&escape_release, 1);
    WaitForSingleObject(thread, 5000);
    {
        DWORD code = 0;
        GetExitCodeThread(thread, &code);
        ok(code == 0x1234, "escape routine exit code %lx", (unsigned long)code);
    }
    CloseHandle(thread);
}
