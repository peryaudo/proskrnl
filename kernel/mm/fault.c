/* kernel/mm/fault.c — guard pages + stack growth (M5). See fault.h.
 *
 * Behaviour reference: Wine's virtual_handle_fault/grow_thread_stack
 * (dlls/ntdll/unix/virtual.c — behaviour, not code): a guard touch clears
 * the guard bit; when the page belongs to the thread's stack the kernel
 * additionally commits the next page down as the new guard and lowers
 * NT_TIB.StackLimit, so ordinary deep recursion never observes a fault
 * (pinned by tests/ntapi/sem_mm/stack_growth.c). When the reserve is
 * exhausted the last guard simply becomes a normal page — the next deeper
 * touch is an ordinary access violation (a stack overflow death; refining
 * that into STATUS_STACK_OVERFLOW delivery needs the M7 dispatcher).
 */
#include "kernel/mm/fault.h"
#include "kernel/mm/virtual.h"
#include "kernel/mm/phys.h"
#include "kernel/ps/ps.h"
#include "kernel/init/panic.h"
#include "kernel/lib/dbgprint.h"
#include "arch/x86_64/mmu.h"

#include "abi/ntpsapi.h"
#include "abi/ntstatus.h"

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

    /* THIS thread's stack bounds: an NtCreateThreadEx thread carries its own
     * region (ETHREAD); the main thread's lives on EPROCESS. Growing only
     * the faulting thread's stack is the NT rule (M9: conhost's input
     * thread was the first additional thread to recurse past its initial
     * commit). */
    PETHREAD thread = tcb->threadObject;
    uint64_t stackAllocationBase = thread != 0 && thread->stackAllocationBase != 0
                                       ? thread->stackAllocationBase
                                       : process->stackAllocationBase;
    uint64_t stackBase =
        thread != 0 && thread->stackAllocationBase != 0 ? thread->stackBase : process->stackBase;
    uint64_t tebBase =
        thread != 0 && thread->tebBase != 0 ? thread->tebBase : (uint64_t)(uintptr_t)process->teb;

    /* Not the stack? One-shot guard semantics: the guard is consumed and the
     * (would-be) exception ends the process until M7 can deliver it. */
    if (page < stackAllocationBase || page >= stackBase)
    {
        return STATUS_GUARD_PAGE_VIOLATION;
    }

    /* Stack growth: the touched guard page is now an ordinary stack page;
     * push a fresh guard one page down while the reserve lasts. */
    uint64_t newGuard = page - PAGE_SIZE;
    if (newGuard >= stackAllocationBase)
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

    /* NT publishes growth in the TEB: StackLimit = lowest committed
     * non-guard page (Wine's grow_thread_stack does exactly this) — in the
     * FAULTING thread's TEB. */
    NT_TIB *tib = MiPhysicalToVirtual(MiTranslateUserPage(space->pml4Physical, tebBase, 0, 0));
    tib->StackLimit = (PVOID)(uintptr_t)page;

    return STATUS_SUCCESS;
}
