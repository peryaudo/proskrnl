/* kernel/mm/fault.h — user page-fault resolution (M5, docs/04).
 *
 * Under Art. 3 there is no demand paging, no COW and no eviction, so the
 * ONLY fault the kernel ever resolves is a guard-page touch: stack growth
 * when the guard belongs to the faulting thread's stack, a one-shot
 * STATUS_GUARD_PAGE_VIOLATION otherwise. Everything else stays what M4 made
 * it — a contained access violation.
 */
#ifndef PROSKRNL_KERNEL_MM_FAULT_H
#define PROSKRNL_KERNEL_MM_FAULT_H

#include <stdint.h>

#include "abi/ntdef.h"

/* Resolve a ring-3 page fault at `faultAddress` (CR2).
 *   STATUS_SUCCESS               resolved (stack grown / guard consumed); resume.
 *   STATUS_GUARD_PAGE_VIOLATION  a non-stack guard fired (guard now cleared);
 *                                no user dispatcher before M7, so the caller
 *                                terminates the process with this status.
 *   STATUS_ACCESS_VIOLATION      not ours; the M4 containment applies.
 */
NTSTATUS MiHandleUserFault(uint64_t faultAddress);

#endif /* PROSKRNL_KERNEL_MM_FAULT_H */
