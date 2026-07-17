/* kernel/mm/virtual.h — user virtual address space: VADs + NtAllocate/Free/
 * QueryVirtualMemory (M4).
 *
 * The boundary shape is NT's reserve/commit two-step (docs/05 "forced");
 * the internals are the simplest correct thing (Art. 3): a sorted linked
 * list of VADs, one ULONG of protection state per page, commit maps a
 * zeroed frame immediately (no demand paging, no COW — pages exist the
 * moment commit succeeds, which is also what makes page-table-walk probing
 * in syscall/uaccess.c sound).
 */
#ifndef PROSKRNL_KERNEL_MM_VIRTUAL_H
#define PROSKRNL_KERNEL_MM_VIRTUAL_H

#include <stdint.h>

#include "abi/ntdef.h"
#include "abi/ntmmapi.h"
#include "kernel/lib/list.h"

/* One user address space: the hardware root + the VAD list (ascending base,
 * non-overlapping). Embedded in EPROCESS. */
typedef struct
{
    uint64_t pml4Physical;
    LIST_ENTRY vadListHead;
} MI_ADDRESS_SPACE, *PMI_ADDRESS_SPACE;

/* NT reserves on 64 KiB boundaries (MEM_RESERVE rounds down to this); the
 * value is the documented Win32 allocation granularity. */
#define MI_ALLOCATION_GRANULARITY 0x10000ULL

NTSTATUS MiCreateAddressSpace(PMI_ADDRESS_SPACE space);
/* Free every committed frame, VAD, and user-half page table. The address
 * space must not be the current CR3. */
void MiDeleteAddressSpace(PMI_ADDRESS_SPACE space);

/* The engines under the three Nt* — also what Ps uses to build a process
 * image/stack/TEB, so every user page is VAD-tracked. In/out parameters
 * are kernel copies; the Nt wrappers own user probing and write-back. */
NTSTATUS MiAllocateVirtualMemory(PMI_ADDRESS_SPACE space, PVOID *baseInOut, SIZE_T *sizeInOut,
                                 ULONG type, ULONG protect);
NTSTATUS MiFreeVirtualMemory(PMI_ADDRESS_SPACE space, PVOID *baseInOut, SIZE_T *sizeInOut,
                             ULONG type);
NTSTATUS MiQueryVirtualMemoryBasic(PMI_ADDRESS_SPACE space, const void *address,
                                   PMEMORY_BASIC_INFORMATION info);

#endif /* PROSKRNL_KERNEL_MM_VIRTUAL_H */
