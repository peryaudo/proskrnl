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

/* One VAD; layout private to virtual.c. Section views (M5) traffic in
 * opaque pointers through the plumbing below. */
typedef struct MI_VAD MI_VAD, *PMI_VAD;

/* NT reserves on 64 KiB boundaries (MEM_RESERVE rounds down to this); the
 * value is the documented Win32 allocation granularity
 * (SYSTEM_INFO.dwAllocationGranularity). Cross-check: third_party/wine
 * dlls/ntdll/unix/virtual.c, `granularity_mask = 0xffff`. */
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

/* --- section-view plumbing (mm/section.c, M5) ------------------------------ */

/* Lowest free 64K-aligned region of `size` bytes (0 = address space full) /
 * emptiness check for an explicit base. */
uint64_t MiFindFreeViewBase(PMI_ADDRESS_SPACE space, uint64_t size);
BOOLEAN MiViewRangeIsFree(PMI_ADDRESS_SPACE space, uint64_t base, uint64_t size);

/* Create + insert a mapped-view VAD (`vadType` MEM_MAPPED or MEM_IMAGE), all
 * pages uncommitted. `sectionBody` is the referenced Section object body the
 * view pins (released at unmap); `ownsFrames` says decommit/teardown frees
 * the frames (an image view's private full copy) or leaves them to their
 * owner (a data view sharing the section's / page cache's frames). */
PMI_VAD MiCreateMappedVad(PMI_ADDRESS_SPACE space, uint64_t base, uint64_t size,
                          ULONG allocationProtect, ULONG vadType, PVOID sectionBody,
                          BOOLEAN ownsFrames);

/* Commit one page of a mapped VAD with an explicitly provided frame. */
void MiCommitFrameInVad(PMI_ADDRESS_SPACE space, PMI_VAD vad, uint64_t virtualAddress,
                        uint64_t frame, ULONG protect);

/* Unwind a partially built view: decommit (honouring ownsFrames), unlink,
 * free. Does NOT release the section reference — the caller owns that. */
void MiDeleteMappedVad(PMI_ADDRESS_SPACE space, PMI_VAD vad);

/* NtUnmapViewOfSection engine: tear down the view containing `address` and
 * release the section reference the VAD owns. STATUS_NOT_MAPPED_VIEW when
 * the address hits nothing or hits private (NtAllocateVirtualMemory) memory. */
NTSTATUS MiUnmapView(PMI_ADDRESS_SPACE space, uint64_t address);

/* Copy into / zero freshly committed pages of a (possibly non-current)
 * address space through the HHDM. The range must be committed. */
void MiCopyToUserRange(PMI_ADDRESS_SPACE space, uint64_t userBase, const void *source,
                       uint64_t length);
void MiZeroUserRange(PMI_ADDRESS_SPACE space, uint64_t userBase, uint64_t length);

/* Resolve a process-handle argument of an Mm Nt* (the pseudo-handle or a
 * real Process handle); *referenced tells the caller to dereference. Shared
 * by the NtAllocate/Free/Query wrappers here and the section Nt* (M5). */
struct EPROCESS; /* kernel/ps/ps.h */
NTSTATUS MiReferenceProcessByHandle(HANDLE processHandle, ACCESS_MASK desiredAccess,
                                    struct EPROCESS **process, BOOLEAN *referenced);

/* --- guard pages (mm/fault.c, M5) ------------------------------------------ */

/* If `pageAddress` is a committed PAGE_GUARD page: clear the guard bit (the
 * page becomes an ordinary present page) and return TRUE. Else FALSE. */
BOOLEAN MiClearGuardPage(PMI_ADDRESS_SPACE space, uint64_t pageAddress);

#endif /* PROSKRNL_KERNEL_MM_VIRTUAL_H */
