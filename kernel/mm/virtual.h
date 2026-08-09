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

/* NT never allocates the first 64K. The same value as the granularity above
 * and a different fact: this one is the FLOOR of the user address space,
 * which mm/section.c's image arm needs because the oracle raises a placement
 * limit to it (map_image_view, "make sure the DOS area remains free") and
 * then refuses a ceiling below it.
 *
 * Cross-check: third_party/wine dlls/ntdll/unix/virtual.c,
 * `virtual_set_large_address_space` — `address_space_start = (void *)0x10000`
 * for a win64 non-wow64 process, which is every process here, and which
 * dlls/ntdll/unix/env.c calls unconditionally at startup. Do NOT read the
 * `address_space_start` INITIALIZER at the head of that file for this value:
 * its x86_64 arm is 0x110000, the pre-startup DOS-area setting, and a reader
 * who stops there will think this constant is wrong. */
#define MI_LOWEST_USER_ADDRESS 0x10000ULL

NTSTATUS MiCreateAddressSpace(PMI_ADDRESS_SPACE space);
/* Free every committed frame, VAD, and user-half page table. The address
 * space must not be the current CR3. */
void MiDeleteAddressSpace(PMI_ADDRESS_SPACE space);

/* The engines under the three Nt* — also what Ps uses to build a process
 * image/stack/TEB, so every user page is VAD-tracked. In/out parameters
 * are kernel copies; the Nt wrappers own user probing and write-back. */
NTSTATUS MiAllocateVirtualMemory(PMI_ADDRESS_SPACE space, PVOID *baseInOut, SIZE_T *sizeInOut,
                                 ULONG type, ULONG protect);

/* The CUI-7 constrained form the classic entry delegates to (one engine):
 * limitLow/limitHigh bound the block inclusive of its last byte, align
 * raises the 64K placement step; zeros mean unconstrained. `attributes` is
 * the MEM_EXTENDED_PARAMETER_* word the caller supplied — it belongs to the
 * ENGINE and not to the parameter parser, because the same word is accepted
 * and dropped on the mapping path (section.c NtMapViewOfSectionEx). */
NTSTATUS MiAllocateVirtualMemoryEx(PMI_ADDRESS_SPACE space, PVOID *baseInOut, SIZE_T *sizeInOut,
                                   ULONG type, ULONG protect, uint64_t limitLow, uint64_t limitHigh,
                                   uint64_t align, ULONG attributes);

/* The captured/validated MEM_EXTENDED_PARAMETER contract (CUI-7); ONE
 * parser for the whole *Ex family (virtual.c MiCaptureExtendedParams,
 * mirroring the oracle's get_extended_params ladder — Art. 11). */
typedef struct
{
    uint64_t limitLow;
    uint64_t limitHigh; /* inclusive last usable byte; 0 = unconstrained */
    uint64_t align;
    ULONG attributes;
    /* MemExtendedParameterImageMachine; 0 = unconstrained. Read by the
     * mapping engine's IMAGE arm only (section.c MipMapImageView) — the
     * allocation path and a data view both ignore it, which is why it is
     * carried out of the parser rather than acted on inside it. */
    USHORT machine;
} MI_EXTENDED_PARAMS;

NTSTATUS MiCaptureExtendedParams(const MEM_EXTENDED_PARAMETER *parameters, ULONG count,
                                 MI_EXTENDED_PARAMS *out);
NTSTATUS MiFreeVirtualMemory(PMI_ADDRESS_SPACE space, PVOID *baseInOut, SIZE_T *sizeInOut,
                             ULONG type);
NTSTATUS MiQueryVirtualMemoryBasic(PMI_ADDRESS_SPACE space, const void *address,
                                   PMEMORY_BASIC_INFORMATION info);
/* M10 (docs/21 W5 tail): the WHOLE reservation the address falls in, where
 * MiQueryVirtualMemoryBasic reports the run of like-protected pages inside
 * it. Same VAD walk, different question — a free address is a REFUSAL here
 * (STATUS_INVALID_ADDRESS) rather than a described hole. */
NTSTATUS MiQueryVirtualMemoryRegion(PMI_ADDRESS_SPACE space, const void *address,
                                    PMEMORY_REGION_INFORMATION info);
/* M10 (docs/21 W5 tail): which IMAGE view the address falls in, if any. Same
 * VAD walk once more — a mapped-but-not-image address is a SUCCESS with an
 * all-zero struct, and only a free (or out-of-range) address is the refusal
 * STATUS_INVALID_ADDRESS. The struct is zeroed on every path, including that
 * refusal. */
NTSTATUS MiQueryVirtualMemoryImage(PMI_ADDRESS_SPACE space, const void *address,
                                   PMEMORY_IMAGE_INFORMATION info);
/* Reprotect a committed run (M7); reports the previous protection. */
NTSTATUS MiProtectVirtualMemory(PMI_ADDRESS_SPACE space, uint64_t *baseInOut, uint64_t *sizeInOut,
                                ULONG newProtect, ULONG *oldProtectOut);

/* M10 winetest: the ProcessVmCounters substrate — reserved (every VAD) and
 * committed bytes by a VAD walk. With no paging (Art. 3) every committed
 * page is resident, so committed IS the working set. */
void MiQueryVmCounters(PMI_ADDRESS_SPACE space, uint64_t *reservedBytesOut,
                       uint64_t *committedBytesOut);

/* --- section-view plumbing (mm/section.c, M5) ------------------------------ */

/* Lowest free 64K-aligned region of `size` bytes (0 = address space full),
 * bounded by the CUI-7 placement limits (zeros mean unconstrained) — the one
 * free-range authority every view placement resolves through. */
uint64_t MiFindFreeViewBaseEx(PMI_ADDRESS_SPACE space, uint64_t size, uint64_t limitLow,
                              uint64_t limitHigh, uint64_t align);
BOOLEAN MiViewRangeIsFree(PMI_ADDRESS_SPACE space, uint64_t base, uint64_t size);

/* The other half of the same placement constraint: does a range the CALLER
 * named fit inside the limits? (0 = unconstrained, either end.) */
BOOLEAN MiRangeWithinLimits(uint64_t base, uint64_t size, uint64_t limitLow, uint64_t limitHigh);

/* The highest address a `zeroBits` placement may occupy, INCLUSIVE (0 =
 * unconstrained) — the argument NtAllocateVirtualMemory and
 * NtMapViewOfSection both carry, read through the oracle's one definition.
 * The long form is at the definition (mm/virtual.c). */
uint64_t MiZeroBitsLimit(uint64_t zeroBits);

/* The classic entry point's zero_bits contract as one call: STATUS_INVALID_
 * PARAMETER_3 for the two bands NT refuses (22..31 and 33..0xfffe), else the
 * placement ceiling above. Shared by NtAllocateVirtualMemory and
 * NtSetInformationProcess(ProcessThreadStackAllocation), which the oracle
 * implements by calling the former — so the bands are stated once (Art. 11).
 * The long form is at the definition (mm/virtual.c). */
NTSTATUS MiZeroBitsPlacementLimit(uint64_t zeroBits, uint64_t *limitHighOut);

/* Create + insert a mapped-view VAD (`vadType` MEM_MAPPED or MEM_IMAGE), all
 * pages uncommitted. `sectionBody` is the referenced Section object body the
 * view pins (released at unmap); `ownsFrames` says decommit/teardown frees
 * the frames (an image view's private full copy) or leaves them to their
 * owner (a data view sharing the section's / page cache's frames). */
PMI_VAD MiCreateMappedVad(PMI_ADDRESS_SPACE space, uint64_t base, uint64_t size,
                          ULONG allocationProtect, ULONG vadType, PVOID sectionBody,
                          BOOLEAN ownsFrames, uint64_t sectionOffset);

/* Commit one page of a mapped VAD with an explicitly provided frame.
 * `ownedFrame` says decommit frees it (a private copy) or leaves it to its
 * owner (a shared master / section / page-cache / kernel frame); on a
 * master-bound VAD it lands in the per-page ownership record, elsewhere it
 * must agree with the VAD-wide ownsFrames. */
void MiCommitFrameInVad(PMI_ADDRESS_SPACE space, PMI_VAD vad, uint64_t virtualAddress,
                        uint64_t frame, ULONG protect, BOOLEAN ownedFrame);

/* CUI-9 image masters: bind a MEM_IMAGE VAD to its (identity, base) master
 * (kernel/mm/section.c owns the master object; the VAD owns one reference
 * on success). The per-page private/shared record this allocates is the
 * frame-ownership authority MiDecommitPages and the §8 sweep consult. */
NTSTATUS MiBindVadImageMaster(PMI_VAD vad, PVOID master);

/* Debug sweep (docs/17 §8): ASSERT that no writable PTE points at a frame
 * a shared image master owns, and that shared PTEs point exactly at their
 * master frame. The range form is the hot-path check, scoped to the pages
 * a map/re-protect just touched (a no-op on a masterless VAD); the
 * whole-space form sweeps every image VAD and is the kmt suite's. */
void MiAssertVadNoWritableMasterPteRange(PMI_ADDRESS_SPACE space, PMI_VAD vad, uint64_t base,
                                         uint64_t size);
void MiAssertNoWritableMasterPte(PMI_ADDRESS_SPACE space);

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

/* CUI-4: fault-tolerant copies for NtRead/WriteVirtualMemory. Each stops at
 * the first page that is not present (read) / not present-and-writable
 * (write) and returns the bytes moved; a short result is the caller's
 * STATUS_PARTIAL_COPY. */
uint64_t MiCopyFromUserRange(PMI_ADDRESS_SPACE space, void *dest, uint64_t userBase,
                             uint64_t length);
uint64_t MiCopyToUserRangeChecked(PMI_ADDRESS_SPACE space, uint64_t userBase, const void *source,
                                  uint64_t length);

/* Resolve a process-handle argument of an Mm Nt* (the pseudo-handle or a
 * real Process handle); *referenced tells the caller to dereference. Shared
 * by the NtAllocate/Free/Query wrappers here and the section Nt* (M5). */
struct EPROCESS; /* kernel/ps/ps.h */
NTSTATUS MiReferenceProcessByHandle(HANDLE processHandle, ACCESS_MASK desiredAccess,
                                    struct EPROCESS **process, BOOLEAN *referenced);

/* --- guard pages (mm/fault.c, M5) ------------------------------------------ */

/* The ONE write-fault authority (Art. 11): a write reached a present,
 * non-hardware-writable page whose recorded protection allows writing —
 * either a clean watched page (CUI-7: mark + open) or a still-shared image
 * master page (CUI-9: copy + repoint + open). TRUE = claimed, with
 * *statusOut STATUS_SUCCESS (retry the access) or STATUS_IN_PAGE_ERROR
 * (the copy got no frame; NO state changed — hazard E). FALSE = a real
 * protection violation / uncommitted / guard. Serves the ring-3 fault
 * (mm/fault.c), the probe retry (syscall/uaccess.c) and the cross-process
 * checked copy. */
BOOLEAN MiResolveWriteFault(PMI_ADDRESS_SPACE space, uint64_t pageAddress, NTSTATUS *statusOut);

/* CUI-9 hazard-E fault injection: fail the NEXT COW frame allocation
 * (kmt-set; docs/17 §8 — the atomicity path must be executed, not assumed). */
extern BOOLEAN MiCowFailNextAllocation;
/* Lazy COW copies resolved so far (the sharing metric's counterpart). */
ULONG MiGetCowCopyCount(void);

/* If `pageAddress` is a committed PAGE_GUARD page: clear the guard bit (the
 * page becomes an ordinary present page) and return TRUE. Else FALSE. */
BOOLEAN MiClearGuardPage(PMI_ADDRESS_SPACE space, uint64_t pageAddress);

#endif /* PROSKRNL_KERNEL_MM_VIRTUAL_H */
