/*
 * sem_ps/breakpoint.c — a ring-3 `int3` is STATUS_BREAKPOINT.
 *
 * DbgBreakPoint, __debugbreak and every CRT assert in the Wine stack come
 * down to an `int3` executed by user code. That is a SOFTWARE interrupt, so
 * the CPU checks the IDT gate's DPL: at DPL 0 the instruction raises #GP
 * rather than #BP, and the process dies with STATUS_ACCESS_VIOLATION at an
 * address that has nothing to do with the breakpoint. proskrnl's own
 * KiUserFaultStatus already had `case 3: return STATUS_BREAKPOINT;`, which
 * was unreachable code for the whole life of the file.
 *
 * Contract (Microsoft, DebugBreak): "Causes a breakpoint exception to occur
 * in the current process... the EXCEPTION_BREAKPOINT exception" --
 * https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugbreak
 * EXCEPTION_BREAKPOINT is STATUS_BREAKPOINT (0x80000003). #BP is a TRAP, so
 * the reported context is already past the int3 and continuing execution
 * resumes at the next instruction.
 *
 * Why the calls only run on proskrnl. The oracle cannot be asked: a ring-3
 * int3 under the pinned Wine, with no debugger present, does not return a
 * status to compare against -- the process wedges in Wine's debugger-attach
 * path and never comes back, so the run hangs instead of answering. The
 * observation mechanism (a vectored handler resuming execution) is the same
 * one sem_mm/guard_pages uses and works on both legs.
 */
#include "../ntapi.h"

#include <windows.h>

/* volatile: written from the exception handler mid-statement. */
static volatile LONG breakpoint_hits;
static volatile DWORD breakpoint_code;

static LONG CALLBACK breakpoint_veh(EXCEPTION_POINTERS *info)
{
    breakpoint_hits++;
    breakpoint_code = info->ExceptionRecord->ExceptionCode;
    if (info->ExceptionRecord->ExceptionCode == (DWORD)STATUS_BREAKPOINT)
    {
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

START_TEST(breakpoint)
{
    void *handler;
    volatile int reached_after = 0;

    if (!ntapi_ctx.on_proskrnl)
    {
        skip("ring-3 int3: the pinned Wine wedges on it with no debugger attached");
        return;
    }

    handler = AddVectoredExceptionHandler(1, breakpoint_veh);
    ok(handler != NULL, "no vectored handler");
    if (handler == NULL)
        return;

    beyond_oracle
    {
        breakpoint_hits = 0;
        breakpoint_code = 0;
        __debugbreak();
        reached_after = 1;

        ok(breakpoint_hits == 1, "int3 raised %ld exceptions, expected 1", (long)breakpoint_hits);
        ok(breakpoint_code == (DWORD)STATUS_BREAKPOINT, "int3 exception code %08lx, expected %08lx",
           (unsigned long)breakpoint_code, (unsigned long)STATUS_BREAKPOINT);
        ok(reached_after == 1, "execution resumed past the int3");

        /* A second one: nothing about handling the first left the gate or
         * the thread in a one-shot state. */
        breakpoint_hits = 0;
        breakpoint_code = 0;
        __debugbreak();
        ok(breakpoint_hits == 1, "second int3 raised %ld exceptions", (long)breakpoint_hits);
        ok(breakpoint_code == (DWORD)STATUS_BREAKPOINT, "second int3 code %08lx",
           (unsigned long)breakpoint_code);
    }

    RemoveVectoredExceptionHandler(handler);
}
