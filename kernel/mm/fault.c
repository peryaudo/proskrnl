/* kernel/mm/fault.c — guard pages + stack growth (M5). See fault.h.
 *
 * Behaviour reference: Wine's virtual_handle_fault/grow_thread_stack
 * (dlls/ntdll/unix/virtual.c — behaviour, not code): a guard touch clears
 * the guard bit; when the page belongs to the thread's stack the kernel
 * additionally commits the next page down as the new guard and lowers
 * NT_TIB.StackLimit, so ordinary deep recursion never observes a fault
 * (pinned by tests/ntapi/sem_mm/stack_growth.c). WHICH region is a stack is
 * the TEB's answer and only the TEB's — see the citation below.
 *
 * What is deliberately NOT built is the oracle's GUARANTEED-SPACE arm: a
 * growth landing below `DeallocationStack + page_size +
 * max(TEB.GuaranteedStackBytes, 2 * page_size)` commits the guarantee in one
 * go and raises STATUS_STACK_OVERFLOW instead of pushing another guard.
 * Here the guard simply walks down to page one and the reserve then runs out
 * as an ordinary access violation. Measured, not assumed — the pin's first
 * draft tripped the oracle's arm with a small region — and recorded in
 * docs/03 "Which region the guard-page fault path GROWS".
 */
#include "kernel/mm/fault.h"
#include "kernel/mm/virtual.h"
#include "kernel/mm/phys.h"
#include "kernel/ps/ps.h"
#include "kernel/init/panic.h"
#include "kernel/lib/dbgprint.h"

#include <stddef.h> /* offsetof, for the TEB fields read below */

#include "abi/ntpebteb.h"
#include "abi/ntpsapi.h"
#include "abi/ntstatus.h"

/* One pointer-sized field out of a user structure, all-or-nothing: the TEB
 * spans two pages and DeallocationStack lives on the second, so a single
 * page translation cannot reach all three fields. A page a process has freed
 * under itself reads as "no value" rather than faulting the kernel. */
static BOOLEAN MipReadUserPointer(PMI_ADDRESS_SPACE space, uint64_t userAddress, uint64_t *value)
{
    return MiCopyFromUserRange(space, value, userAddress, sizeof(*value)) == sizeof(*value);
}

NTSTATUS MiHandleUserFault(uint64_t faultAddress, BOOLEAN writeAccess)
{
    PKTHREAD tcb = KeGetCurrentThread();
    PEPROCESS process = tcb->process;
    ASSERT(process != PsInitialSystemProcess); /* ring-3 faults only */
    PMI_ADDRESS_SPACE space = &process->addressSpace;

    uint64_t page = faultAddress & ~(PAGE_SIZE - 1ULL);

    /* CUI-7 write-watch + CUI-9 COW: a store into a present page whose
     * recorded protection is writable but whose PTE is not — a clean
     * watched page marks and resumes, a still-shared master page copies,
     * repoints and resumes. Ordered before the guard arm, which only ever
     * sees not-present pages (the resolver itself declines guard pages, so
     * a guarded writecopy page consumes its guard FIRST and the next store
     * copies — hazard G). A claimed fault that could not get a frame is
     * STATUS_IN_PAGE_ERROR, delivered like any fault status (hazard E). */
    if (writeAccess)
    {
        NTSTATUS resolved;
        if (MiResolveWriteFault(space, page, &resolved))
        {
            return resolved;
        }
    }

    if (!MiClearGuardPage(space, page))
    {
        return STATUS_ACCESS_VIOLATION; /* not a guard page: M4 containment */
    }

    /* THIS thread's TEB — the faulting thread's, never the process's idea of
     * one: a created thread carries its own (ETHREAD), and only the main
     * thread's lives on EPROCESS. */
    PETHREAD thread = tcb->threadObject;
    uint64_t tebBase =
        thread != 0 && thread->tebBase != 0 ? thread->tebBase : (uint64_t)(uintptr_t)process->teb;

    /* "Is this address inside THIS thread's stack" is a question the TEB
     * answers, and the oracle asks nothing else: is_inside_thread_stack
     * (dlls/ntdll/unix/virtual.c) reads DeallocationStack and Tib.StackBase
     * out of the TEB and tests `ptr > start && ptr <= end` against the fault
     * address rounded down to its page. The kernel's own record of where it
     * put the stack agrees for every stack the kernel made and refuses every
     * stack USER MODE made — and user mode makes them: SwitchToFiber swaps
     * these three fields on every switch (dlls/kernelbase/thread.c), and
     * kernel32:virtual's test_stack_commit points them at a hand-built
     * reservation and runs a function on it.
     *
     * Believing the TEB grants nothing, which is what makes it safe to
     * believe: the whole action below is committing one page of the caller's
     * OWN address space and writing the caller's OWN TEB, both of which the
     * caller can do for itself with NtAllocateVirtualMemory. Pinned by
     * tests/ntapi/sem_mm/teb_stack_growth.c (both edges; the high one is
     * INCLUSIVE). */
    uint64_t stackStart = 0;
    uint64_t stackEnd = 0;
    if (!MipReadUserPointer(space, tebBase + offsetof(TEB, DeallocationStack), &stackStart) ||
        !MipReadUserPointer(space, tebBase + offsetof(TEB, Tib.StackBase), &stackEnd))
    {
        return STATUS_GUARD_PAGE_VIOLATION; /* no readable TEB: not a stack */
    }

    /* Not the stack? One-shot guard semantics: the guard is consumed and the
     * exception is delivered. */
    if (page <= stackStart || page > stackEnd)
    {
        return STATUS_GUARD_PAGE_VIOLATION;
    }

    /* Stack growth: the touched guard page is now an ordinary stack page;
     * push a fresh guard one page down while the claimed reserve lasts.
     *
     * `newGuard >= stackStart` is a TEST and not an ASSERT on purpose: the
     * extent check above is `page > stackStart` with `page` page-aligned and
     * stackStart a field USER MODE owns, so an unaligned DeallocationStack
     * one byte inside the touched page's predecessor satisfies it and still
     * puts the next guard below the claimed base. Asserting the invariant
     * would make a ring-3 process able to panic the machine — in the one
     * diff whose whole argument is that these fields are user-owned. Where
     * this arm declines, the oracle would be in its guaranteed space raising
     * STATUS_STACK_OVERFLOW (the unbuilt arm named at the top of this file);
     * here the touched page is simply usable and the next deeper touch is a
     * contained AV. */
    uint64_t newGuard = page - PAGE_SIZE;
    if (newGuard >= stackStart)
    {
        PVOID base = (PVOID)(uintptr_t)newGuard;
        SIZE_T size = PAGE_SIZE;
        NTSTATUS status =
            MiAllocateVirtualMemory(space, &base, &size, MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD);
        if (!NT_SUCCESS(status))
        {
            /* Out of frames mid-growth: the touched page itself is usable,
             * so resume; the next guardless touch is a contained AV. */
            DbgPrint("[USERFAULT] stack guard commit failed (%#x)\n", (unsigned)status);
        }
    }
    if (newGuard < stackStart + PAGE_SIZE + 2 * PAGE_SIZE)
    {
        /* The unbuilt arm, naming itself rather than diverging quietly: from
         * here down NT commits the guarantee in one go and raises
         * STATUS_STACK_OVERFLOW, and this kernel keeps walking the guard.
         * The bound is the FLOOR of the oracle's split — its `guaranteed` is
         * max(TEB.GuaranteedStackBytes, 2 * page_size), so a thread that
         * called SetThreadStackGuarantee crosses earlier than this and says
         * nothing. A line here is the only warning a later plain AV in a
         * deep stack gets. */
        DbgPrint("[USERFAULT] stack growth at %#lx is inside the guaranteed space of the stack "
                 "based at %#lx (STATUS_STACK_OVERFLOW unbuilt — docs/03)\n",
                 (unsigned long)page, (unsigned long)stackStart);
    }

    /* NT publishes growth in the TEB: StackLimit = lowest committed
     * non-guard page (Wine's grow_thread_stack does exactly this) — in the
     * FAULTING thread's TEB. */
    uint64_t limit = page;
    MiCopyToUserRangeChecked(space, tebBase + offsetof(TEB, Tib.StackLimit), &limit, sizeof(limit));

    return STATUS_SUCCESS;
}
