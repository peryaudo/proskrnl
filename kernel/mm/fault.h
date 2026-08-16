/* kernel/mm/fault.h — user page-fault resolution (M5, docs/04).
 *
 * Under Art. 3 there is no demand paging and no eviction, so the kernel
 * resolves exactly three fault shapes: a guard-page touch (stack growth
 * when the guard belongs to the faulting thread's stack, a one-shot
 * STATUS_GUARD_PAGE_VIOLATION otherwise), CUI-7's write-watch mark, and
 * CUI-9's image COW copy (docs/17). Everything else stays what M4 made
 * it — a contained access violation.
 */
#ifndef PROSKRNL_KERNEL_MM_FAULT_H
#define PROSKRNL_KERNEL_MM_FAULT_H

#include <stdint.h>

#include "abi/ntdef.h"

/* Resolve a ring-3 page fault at `faultAddress` (CR2). `writeAccess` is the
 * #PF error code's W bit (bit 1 — Intel SDM Vol. 3A §4.7 "Page-Fault
 * Exceptions"): the CUI-7/CUI-9 write arm resolves a write to a present
 * page before the guard logic runs — a watched page marks, a still-shared
 * master page copies (MiResolveWriteFault; a guard page is not-present, so
 * the arms cannot collide).
 *   STATUS_SUCCESS               resolved (watch marked / master copied /
 *                                stack grown / guard consumed); resume.
 *   STATUS_GUARD_PAGE_VIOLATION  a non-stack guard fired (guard now cleared);
 *                                no user dispatcher before M7, so the caller
 *                                terminates the process with this status.
 *   STATUS_ACCESS_VIOLATION      not ours; the M4 containment applies.
 */
NTSTATUS MiHandleUserFault(uint64_t faultAddress, BOOLEAN writeAccess);

#endif /* PROSKRNL_KERNEL_MM_FAULT_H */
