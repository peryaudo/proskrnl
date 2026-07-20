/*
 * sem_mm/guard_pages.c — PAGE_GUARD semantics (M5, docs/02 "guard-page stack
 * growth"): a guard page is committed but traps once, the first touch raises
 * STATUS_GUARD_PAGE_VIOLATION and clears the guard bit, and the page is an
 * ordinary accessible page afterwards.
 *
 * Behaviour as Wine implements it (dlls/ntdll/unix/virtual.c VPROT_GUARD and
 * virtual_handle_fault), pinned here on the oracle (Art. 5). Observing the
 * exception needs a vectored handler, which proskrnl cannot deliver until the
 * M7 user-mode dispatcher — so this test is ORACLE-ONLY for now (out of the
 * manifest); the kernel side of guard semantics is proven by the stack-growth
 * test and the kmt M5 suite.
 */
#include "util.h"

#include <windows.h>

/* volatile: written from the exception handler mid-statement; without it the
 * compiler may cache the counter across the faulting access. */
static volatile LONG guard_faults;
static void *volatile guard_fault_addr;

static LONG CALLBACK guard_veh(EXCEPTION_POINTERS *info)
{
    if (info->ExceptionRecord->ExceptionCode == (DWORD)STATUS_GUARD_PAGE_VIOLATION)
    {
        guard_faults++;
        guard_fault_addr = (void *)info->ExceptionRecord->ExceptionInformation[1];
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

START_TEST(guard_pages)
{
    NTSTATUS status;
    MEMORY_BASIC_INFORMATION mbi;
    volatile char *page;
    void *base = NULL;
    void *handler;
    SIZE_T size = 0x2000;

    /* Committing with PAGE_GUARD is a valid protection. */
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_RESERVE | MEM_COMMIT,
                                     PAGE_READWRITE | PAGE_GUARD);
    ok(status == STATUS_SUCCESS, "commit guarded -> %08lx", (unsigned long)status);

    status = NtQueryVirtualMemory(NtCurrentProcess(), base, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), NULL);
    ok(status == STATUS_SUCCESS, "query guarded -> %08lx", (unsigned long)status);
    ok(mbi.State == MEM_COMMIT, "guarded State %lx", (unsigned long)mbi.State);
    ok(mbi.Protect == (PAGE_READWRITE | PAGE_GUARD), "guarded Protect %lx",
       (unsigned long)mbi.Protect);

    handler = AddVectoredExceptionHandler(1, guard_veh);
    ok(handler != NULL, "no vectored handler");

    /* First touch: one STATUS_GUARD_PAGE_VIOLATION, then the access repeats
     * and succeeds — the guard bit is one-shot. */
    page = (volatile char *)base;
    guard_faults = 0;
    page[0] = 0x5a;
    ok(guard_faults == 1, "first touch raised %ld guard faults", (long)guard_faults);
    ok(guard_fault_addr == base, "guard fault address %p, expected %p", guard_fault_addr, base);
    ok(page[0] == 0x5a, "write lost after guard fault");

    status = NtQueryVirtualMemory(NtCurrentProcess(), base, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), NULL);
    ok(status == STATUS_SUCCESS, "query after touch -> %08lx", (unsigned long)status);
    ok(mbi.Protect == PAGE_READWRITE, "Protect after touch %lx, guard should be gone",
       (unsigned long)mbi.Protect);

    /* Second touch: an ordinary page now. */
    page[1] = 0x6b;
    ok(guard_faults == 1, "second touch raised another guard fault");

    /* The second page keeps its own guard bit until touched. */
    status = NtQueryVirtualMemory(NtCurrentProcess(), (char *)base + 0x1000,
                                  MEMORY_BASIC_INFO_CLASS, &mbi, sizeof(mbi), NULL);
    ok(status == STATUS_SUCCESS, "query second page -> %08lx", (unsigned long)status);
    ok(mbi.Protect == (PAGE_READWRITE | PAGE_GUARD), "second page Protect %lx",
       (unsigned long)mbi.Protect);
    page[0x1000] = 0x7c;
    ok(guard_faults == 2, "second page touch raised %ld guard faults", (long)guard_faults);

    RemoveVectoredExceptionHandler(handler);

    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "release -> %08lx", (unsigned long)status);
}
