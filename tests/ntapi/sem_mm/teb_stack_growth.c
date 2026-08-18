/*
 * sem_mm/teb_stack_growth.c — WHICH region the guard-page fault path grows,
 * and who gets to say so.
 *
 * A guard-page touch has two possible answers: GROW (clear the guard, commit
 * a fresh guard one page down, publish the new NT_TIB.StackLimit) or REFUSE
 * (clear the guard and raise STATUS_GUARD_PAGE_VIOLATION). Which one a page
 * gets is decided by a single question — is this address inside THIS THREAD'S
 * STACK — and the pinned oracle answers it from the TEB and from nothing else
 * (third_party/wine dlls/ntdll/unix/virtual.c, `is_inside_thread_stack`:
 * `stack->start = teb->DeallocationStack; stack->end = teb->Tib.StackBase;`
 * then `ptr > stack->start && ptr <= stack->end`, called from
 * `virtual_handle_fault` with the fault address rounded DOWN to its page).
 *
 * So the three TEB fields are not a report of where the stack is — they are
 * the DEFINITION of it, and user mode may move them. `SwitchToFiber` does
 * exactly that on every switch (dlls/kernelbase/thread.c), and
 * kernel32:virtual's `test_stack_commit` does it by hand: it reserves 4 MiB,
 * commits only the top page PAGE_GUARD, points the TEB at it and runs a
 * function there, expecting the whole region to commit itself a guard page at
 * a time (dlls/kernel32/tests/virtual.c:2486-:2499).
 *
 * A kernel that answers the question from its OWN record of where it put the
 * thread's stack agrees with the oracle for every stack it created and
 * refuses every stack user mode made — which is a fault, not a diagnostic:
 * the refusal is delivered as an exception, and delivering it writes below a
 * stack pointer that is sitting on the region nothing would commit.
 *
 * Trusting the TEB grants nothing: the whole action is committing one page of
 * the caller's OWN address space and writing the caller's OWN TEB, both of
 * which the caller can do itself with NtAllocateVirtualMemory. What it costs
 * is the tidier statement; what it buys is the oracle's rule.
 *
 * Every case here runs on the REAL stack and touches a guard page in a
 * separate reserved region, because the rule is about the faulting ADDRESS
 * and not about rsp. Oracle-first (G5); nothing here is beyond_oracle.
 */
#include "util.h"

#include <windows.h> /* NT_TIB, NtCurrentTeb, the vectored-handler API */

/* mingw's winternl.h declares the TEB as Reserved[] arrays, so this field is
 * reached by offset. 0x1478 is the x64 offset the pinned tree's own header
 * states in its offset-comment column (third_party/wine include/winternl.h,
 * `PVOID DeallocationStack; /​* e0c/1478 *​/`), which is where
 * abi/ntpebteb.h's generated `offsetof(TEB, DeallocationStack) == 0x1478`
 * static_assert comes from. G8: re-verify there, not from memory. The first
 * assertion in the body proves the offset names a live field on the ORACLE
 * before anything is concluded from it. */
#define MM_TEB_DEALLOCATION_STACK_OFFSET 0x1478

#define MM_PAGE 0x1000

/* Every case builds the same shape test_stack_commit does — a reservation
 * with exactly one committed PAGE_GUARD page in it — and touches that page.
 * The guard sits EIGHT pages above the base so a growth from it lands well
 * clear of the oracle's guaranteed space (three pages), which is a different
 * arm with a different answer (see guard_veh). */
#define MM_REGION_PAGES 16
#define MM_GUARD_PAGE   8

/* volatile throughout: the TEB fields are written by the kernel behind this
 * code's back, and the claim/touch/restore sequence must not be reordered —
 * every access below the window is through a volatile lvalue. */
static PVOID volatile *teb_deallocation_stack(void)
{
    return (PVOID volatile *)((char *)NtCurrentTeb() + MM_TEB_DEALLOCATION_STACK_OFFSET);
}

static volatile NT_TIB *teb_tib(void)
{
    return (volatile NT_TIB *)NtCurrentTeb();
}

static volatile LONG guard_faults;
static volatile LONG overflow_faults;
static void *volatile guard_fault_addr;

/* Both codes are answered HERE, inside the window, and that is not tidiness:
 * an EXCEPTION_CONTINUE_SEARCH from this handler runs the SEH dispatcher,
 * which validates the registration chain against NT_TIB.StackLimit/StackBase
 * — the very fields the window has pointed elsewhere — and kills the process
 * with "Exception frame is not in stack limits" before any assertion can
 * report what happened (measured; it is how the first draft of this file
 * failed). STATUS_STACK_OVERFLOW is the oracle's GUARANTEED-SPACE arm
 * (grow_thread_stack: a growth landing below `start + page_size +
 * max(TEB.GuaranteedStackBytes, 2 * page_size)` commits the guarantee and
 * raises instead of pushing another guard). Every case below deliberately
 * sits well above that floor, so the counter exists to prove the cases are
 * measuring the arm they claim to. */
static LONG CALLBACK guard_veh(EXCEPTION_POINTERS *info)
{
    DWORD code = info->ExceptionRecord->ExceptionCode;

    if (code == (DWORD)STATUS_GUARD_PAGE_VIOLATION)
    {
        guard_faults++;
        guard_fault_addr = (void *)info->ExceptionRecord->ExceptionInformation[1];
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code == (DWORD)STATUS_STACK_OVERFLOW)
    {
        overflow_faults++;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* The window below claims a synthetic stack, so for its duration the REAL
 * stack is not a stack as far as the fault path is concerned. On a kernel
 * that grows stacks on demand (proskrnl; the oracle commits its stacks up
 * front) a call that reached a fresh page in that window would take the
 * refusal arm — and delivering the exception writes below an rsp whose page
 * is the one that was not committed. So the frames the window uses are
 * touched BEFORE it opens. Frames stay under a page so no toolchain's stack
 * probe is involved (as sem_mm/stack_growth.c). */
#define MM_PRIME_FRAME 2048
#define MM_PRIME_DEPTH 8

/* The frame is read back AFTER the recursion so neither the buffer nor the
 * call can be elided into a tail jump that reuses one frame. */
__attribute__((noinline)) static char prime_stack(int depth)
{
    volatile char frame[MM_PRIME_FRAME];
    char deeper = 0;
    int i;

    for (i = MM_PRIME_FRAME - 64; i >= 0; i -= 64)
        frame[i] = (char)depth;
    if (depth > 0)
        deeper = prime_stack(depth - 1);
    return (char)(frame[0] + deeper);
}

struct mm_claim
{
    PVOID dealloc;
    PVOID base;
    PVOID limit;
};

static void save_claim(struct mm_claim *saved)
{
    saved->dealloc = *teb_deallocation_stack();
    saved->base = teb_tib()->StackBase;
    saved->limit = teb_tib()->StackLimit;
}

static void restore_claim(const struct mm_claim *saved)
{
    *teb_deallocation_stack() = saved->dealloc;
    teb_tib()->StackBase = saved->base;
    teb_tib()->StackLimit = saved->limit;
}

struct mm_probe
{
    LONG faults;    /* guard-page violations delivered by the touch  */
    LONG overflows; /* STATUS_STACK_OVERFLOW, i.e. the guarantee arm */
    void *faultAddr;
    /* NT_TIB.StackLimit either side of the touch. `limitBefore` is read
     * INSIDE the window rather than once at the top of the test: on a kernel
     * that grows stacks on demand, priming can lower the REAL StackLimit
     * between two cases, and a "did it move" assertion measured against a
     * stale value fails for that instead of for what it is about. */
    PVOID limitBefore;
    PVOID limitAfter;
};

/* Touch `address` with the TEB claiming [low, high) as this thread's stack;
 * `low == NULL` leaves the TEB alone (the control arm). The TEB is restored
 * before anything is asserted: an ok() inside the window would run library
 * code on a thread whose stack it has lied about. */
static void probe_touch(void *low, void *high, void *address, struct mm_probe *probe)
{
    struct mm_claim saved;

    (void)prime_stack(MM_PRIME_DEPTH);
    guard_faults = 0;
    overflow_faults = 0;
    guard_fault_addr = NULL;
    save_claim(&saved);
    if (low != NULL)
    {
        *teb_deallocation_stack() = low;
        teb_tib()->StackBase = high;
        teb_tib()->StackLimit = high;
    }
    probe->limitBefore = teb_tib()->StackLimit;
    *(volatile char *)address = 0x5a;
    probe->limitAfter = teb_tib()->StackLimit;
    restore_claim(&saved);
    probe->faults = guard_faults;
    probe->overflows = overflow_faults;
    probe->faultAddr = guard_fault_addr;
}

/* A reserved region of `pages` pages, with page `guardPage` committed
 * PAGE_READWRITE|PAGE_GUARD — the shape test_stack_commit builds. */
static char *make_region(SIZE_T pages, SIZE_T guardPage)
{
    void *base = NULL;
    void *guard;
    SIZE_T size = pages * MM_PAGE;
    NTSTATUS status;

    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_RESERVE, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "reserve -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        return NULL;
    }
    guard = (char *)base + guardPage * MM_PAGE;
    size = MM_PAGE;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &guard, 0, &size, MEM_COMMIT,
                                     PAGE_READWRITE | PAGE_GUARD);
    ok(status == STATUS_SUCCESS, "commit guard -> %08lx", (unsigned long)status);
    return (char *)base;
}

static void free_region(char *base)
{
    void *address = base;
    SIZE_T size = 0;
    NTSTATUS status = NtFreeVirtualMemory(NtCurrentProcess(), &address, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "release -> %08lx", (unsigned long)status);
}

static void query_page(void *address, MEMORY_BASIC_INFORMATION *mbi, const char *what)
{
    NTSTATUS status;

    memset(mbi, 0, sizeof(*mbi));
    status = NtQueryVirtualMemory(NtCurrentProcess(), address, MEMORY_BASIC_INFO_CLASS, mbi,
                                  sizeof(*mbi), NULL);
    ok(status == STATUS_SUCCESS, "%s: query %p -> %08lx", what, address, (unsigned long)status);
}

/* The GROW answer, stated once: the touched page is an ordinary committed
 * page, the page below it is the new guard, and StackLimit names the touched
 * page. */
static void expect_grown(char *touched, const struct mm_probe *probe, const char *what)
{
    MEMORY_BASIC_INFORMATION mbi;

    ok(probe->faults == 0, "%s: %ld guard violations delivered, wanted growth", what,
       (long)probe->faults);
    ok(probe->overflows == 0, "%s: %ld stack overflows — the touch is inside the guarantee", what,
       (long)probe->overflows);
    ok(probe->limitAfter == (PVOID)touched, "%s: StackLimit %p, wanted %p", what, probe->limitAfter,
       (void *)touched);

    query_page(touched, &mbi, what);
    ok(mbi.State == MEM_COMMIT, "%s: touched State %lx", what, (unsigned long)mbi.State);
    ok(mbi.Protect == PAGE_READWRITE, "%s: touched Protect %lx, guard should be gone", what,
       (unsigned long)mbi.Protect);

    query_page(touched - MM_PAGE, &mbi, what);
    ok(mbi.State == MEM_COMMIT, "%s: page below State %lx, wanted the new guard", what,
       (unsigned long)mbi.State);
    ok(mbi.Protect == (PAGE_READWRITE | PAGE_GUARD), "%s: page below Protect %lx", what,
       (unsigned long)mbi.Protect);
}

/* The REFUSE answer: exactly one violation naming the touched address, the
 * guard consumed anyway, nothing committed below, and StackLimit untouched. */
static void expect_refused(char *touched, const struct mm_probe *probe, const char *what)
{
    PVOID limitBefore = probe->limitBefore;
    MEMORY_BASIC_INFORMATION mbi;

    ok(probe->faults == 1, "%s: %ld guard violations delivered, wanted 1", what,
       (long)probe->faults);
    ok(probe->overflows == 0, "%s: %ld stack overflows, wanted none", what, (long)probe->overflows);
    ok(probe->faultAddr == touched, "%s: violation named %p, wanted %p", what, probe->faultAddr,
       (void *)touched);
    ok(probe->limitAfter == limitBefore, "%s: StackLimit moved to %p from %p", what,
       probe->limitAfter, limitBefore);

    query_page(touched, &mbi, what);
    ok(mbi.State == MEM_COMMIT, "%s: touched State %lx", what, (unsigned long)mbi.State);
    ok(mbi.Protect == PAGE_READWRITE, "%s: touched Protect %lx, the guard is one-shot either way",
       what, (unsigned long)mbi.Protect);

    query_page(touched - MM_PAGE, &mbi, what);
    ok(mbi.State == MEM_RESERVE, "%s: page below State %lx, nothing should have been committed",
       what, (unsigned long)mbi.State);
}

START_TEST(teb_stack_growth)
{
    struct mm_probe probe;
    struct mm_claim before;
    void *handler;
    char *region;

    /* G8: prove the hand-typed offset names the DeallocationStack before
     * anything writes through it. A wrong offset would corrupt some
     * neighbouring TEB pointer instead of failing. */
    ok(*teb_deallocation_stack() != NULL, "TEB+%#x is not the DeallocationStack",
       MM_TEB_DEALLOCATION_STACK_OFFSET);
    ok((char *)*teb_deallocation_stack() < (char *)teb_tib()->StackLimit,
       "TEB+%#x (%p) is not below StackLimit %p", MM_TEB_DEALLOCATION_STACK_OFFSET,
       *teb_deallocation_stack(), teb_tib()->StackLimit);

    save_claim(&before);
    handler = AddVectoredExceptionHandler(1, guard_veh);
    ok(handler != NULL, "no vectored handler");

    /* 1. The TEB is the authority. A region this thread never had a stack in
     *    grows the moment the TEB says it is one. */
    region = make_region(MM_REGION_PAGES, MM_GUARD_PAGE);
    if (region != NULL)
    {
        probe_touch(region, region + MM_REGION_PAGES * MM_PAGE, region + MM_GUARD_PAGE * MM_PAGE,
                    &probe);
        expect_grown(region + MM_GUARD_PAGE * MM_PAGE, &probe, "claimed");
        free_region(region);
    }

    /* 2. The control, and it is what makes case 1 mean anything: the SAME
     *    region and the SAME touch, with the TEB left alone, is refused. */
    region = make_region(MM_REGION_PAGES, MM_GUARD_PAGE);
    if (region != NULL)
    {
        probe_touch(NULL, NULL, region + MM_GUARD_PAGE * MM_PAGE, &probe);
        expect_refused(region + MM_GUARD_PAGE * MM_PAGE, &probe, "unclaimed");
        free_region(region);
    }

    /* 3. The low edge is EXCLUSIVE: DeallocationStack's own page is not
     *    inside the stack (`ptr > stack->start`), so the region's first page
     *    is refused even though the TEB claims the region. That page is the
     *    reservation's floor — growing it would have nowhere to put the next
     *    guard. */
    region = make_region(MM_REGION_PAGES, 0);
    if (region != NULL)
    {
        probe_touch(region, region + MM_REGION_PAGES * MM_PAGE, region, &probe);
        ok(probe.faults == 1, "low edge: %ld guard violations, wanted 1", (long)probe.faults);
        ok(probe.overflows == 0, "low edge: %ld stack overflows, wanted none",
           (long)probe.overflows);
        ok(probe.faultAddr == region, "low edge: violation named %p, wanted %p", probe.faultAddr,
           (void *)region);
        ok(probe.limitAfter == probe.limitBefore, "low edge: StackLimit moved to %p from %p",
           probe.limitAfter, probe.limitBefore);
        free_region(region);
    }

    /* 4. The high edge is INCLUSIVE (`ptr <= stack->end`), which is the half
     *    an implementation writing the obvious half-open range gets wrong:
     *    a fault page at StackBase itself — one page ABOVE the last byte the
     *    stack can hold — still grows. What convicts here is the guard
     *    appearing BELOW the touched page: a fresh stack's StackLimit is its
     *    StackBase, so this case's published StackLimit is the value it
     *    claimed either way and that half of expect_grown says nothing. */
    region = make_region(MM_REGION_PAGES, MM_GUARD_PAGE);
    if (region != NULL)
    {
        probe_touch(region, region + MM_GUARD_PAGE * MM_PAGE, region + MM_GUARD_PAGE * MM_PAGE,
                    &probe);
        expect_grown(region + MM_GUARD_PAGE * MM_PAGE, &probe, "at StackBase");
        free_region(region);
    }

    /* 5. One page further up is outside, so cases 4 and 5 differ by exactly
     *    the comparison's edge and nothing else. */
    region = make_region(MM_REGION_PAGES, MM_GUARD_PAGE);
    if (region != NULL)
    {
        probe_touch(region, region + (MM_GUARD_PAGE - 1) * MM_PAGE,
                    region + MM_GUARD_PAGE * MM_PAGE, &probe);
        expect_refused(region + MM_GUARD_PAGE * MM_PAGE, &probe, "above StackBase");
        free_region(region);
    }

    RemoveVectoredExceptionHandler(handler);

    /* The window restored the TEB every time; if it did not, everything after
     * this test in the same process is running on a lie. */
    ok(*teb_deallocation_stack() == before.dealloc && teb_tib()->StackBase == before.base,
       "the TEB was not restored: dealloc %p base %p", *teb_deallocation_stack(),
       teb_tib()->StackBase);
}
