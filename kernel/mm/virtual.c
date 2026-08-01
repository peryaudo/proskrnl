/* kernel/mm/virtual.c — user virtual memory: VADs + NtAllocate/Free/Query
 * VirtualMemory (M4). See virtual.h for the Art. 3 shape.
 *
 * The boundary semantics here — rounding, status codes, the
 * MemoryBasicInformation runs — are pinned by tests/ntapi/sem_mm/
 * reserve_commit.c, which is green on the pinned Wine oracle; where this
 * file makes a choice, it is the choice Wine's implementation makes
 * (dlls/ntdll/unix/virtual.c is the reference for behaviour, not code).
 */
#include "kernel/mm/virtual.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/pool.h"
#include "kernel/mm/section.h"
#include "kernel/ps/ps.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "arch/x86_64/mmu.h"

#include "abi/ntstatus.h"

/* One reservation: [base, base + size), page-granular, with one protection
 * word per page (0 = reserved-only, else the committed PAGE_* value —
 * possibly carrying PAGE_GUARD, in which case the frame is mapped
 * not-present until the guard fires). M5 adds mapped views: `type` is
 * MEM_PRIVATE for NtAllocateVirtualMemory memory, MEM_MAPPED/MEM_IMAGE for
 * section views; a view pins its Section object (one reference, owned by
 * the VAD, released when the VAD dies) and `ownsFrames` says whether
 * decommit returns the frames to the allocator (private memory and image
 * full copies) or leaves them alone (shared data-section frames). */
struct MI_VAD
{
    LIST_ENTRY listEntry; /* on MI_ADDRESS_SPACE.vadListHead, ascending */
    uint64_t base;
    uint64_t size;
    ULONG allocationProtect;
    PULONG pageProtect;
    ULONG type;        /* MEM_PRIVATE / MEM_MAPPED / MEM_IMAGE */
    PVOID sectionBody; /* referenced Section body; 0 for private */
    BOOLEAN ownsFrames;
};

/* NT never allocates the first 64K. Cross-check: third_party/wine
 * dlls/ntdll/unix/virtual.c, `address_space_start = (void *)0x10000`. */
#define MI_LOWEST_USER_ADDRESS 0x10000ULL

static uint64_t MiRoundDown(uint64_t value, uint64_t align)
{
    return value & ~(align - 1);
}

static uint64_t MiRoundUp(uint64_t value, uint64_t align)
{
    return (value + align - 1) & ~(align - 1);
}

static ULONG MiVadPageCount(PMI_VAD vad)
{
    return (ULONG)(vad->size / PAGE_SIZE);
}

/* Valid anonymous-commit protections (Wine's get_vprot_flags): the WRITECOPY
 * flavours need a backing file and are rejected for private memory. */
static NTSTATUS MiCheckPageProtect(ULONG protect)
{
    switch (protect & ~(PAGE_GUARD | PAGE_NOCACHE))
    {
    case PAGE_NOACCESS:
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
        return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_PAGE_PROTECTION;
    }
}

static void MiProtectToPteBits(ULONG protect, int *present, int *writable, int *executable)
{
    ULONG bits = protect & ~(PAGE_GUARD | PAGE_NOCACHE);
    /* A guard page is committed but mapped not-present so the first touch
     * traps (mm/fault.c clears the guard and remaps). */
    *present = bits != PAGE_NOACCESS && (protect & PAGE_GUARD) == 0;
    /* The WRITECOPY flavours appear on image views only (M5); every mapping
     * is already a private full copy (Art. 3: no COW), so they are plain
     * writable here — only the reported protection keeps the NT name. */
    *writable = bits == PAGE_READWRITE || bits == PAGE_EXECUTE_READWRITE ||
                bits == PAGE_WRITECOPY || bits == PAGE_EXECUTE_WRITECOPY;
    *executable = bits == PAGE_EXECUTE || bits == PAGE_EXECUTE_READ ||
                  bits == PAGE_EXECUTE_READWRITE || bits == PAGE_EXECUTE_WRITECOPY;
}

/* The VAD containing `address`, or 0. */
static PMI_VAD MiFindVad(PMI_ADDRESS_SPACE space, uint64_t address)
{
    for (PLIST_ENTRY entry = space->vadListHead.Flink; entry != &space->vadListHead;
         entry = entry->Flink)
    {
        PMI_VAD vad = CONTAINING_RECORD(entry, MI_VAD, listEntry);
        if (address >= vad->base && address < vad->base + vad->size)
        {
            return vad;
        }
        if (vad->base > address)
        {
            break; /* ascending list */
        }
    }
    return 0;
}

static BOOLEAN MiRangeIsFree(PMI_ADDRESS_SPACE space, uint64_t base, uint64_t size)
{
    for (PLIST_ENTRY entry = space->vadListHead.Flink; entry != &space->vadListHead;
         entry = entry->Flink)
    {
        PMI_VAD vad = CONTAINING_RECORD(entry, MI_VAD, listEntry);
        if (base < vad->base + vad->size && vad->base < base + size)
        {
            return FALSE;
        }
        if (vad->base >= base + size)
        {
            break;
        }
    }
    return TRUE;
}

/* Lowest aligned hole of `size` bytes, bottom-up like Wine. 0 = full. The
 * CUI-7 placement constraints (VirtualAlloc2's MEM_ADDRESS_REQUIREMENTS)
 * ride the same walk: limitLow/limitHigh bound the block INCLUSIVE of its
 * last byte, align raises the 64K step (0s = unconstrained; THE one
 * free-range authority — classic and Ex allocations both resolve here). */
static uint64_t MiFindFreeRegion(PMI_ADDRESS_SPACE space, uint64_t size, uint64_t limitLow,
                                 uint64_t limitHigh, uint64_t align)
{
    if (align < MI_ALLOCATION_GRANULARITY)
    {
        align = MI_ALLOCATION_GRANULARITY;
    }
    if (limitHigh == 0)
    {
        limitHigh = KI_USER_SPACE_LIMIT - 1;
    }
    uint64_t floor = MI_LOWEST_USER_ADDRESS;
    if (limitLow > floor)
    {
        floor = limitLow;
    }
    uint64_t candidate = MiRoundUp(floor, align);
    for (PLIST_ENTRY entry = space->vadListHead.Flink; entry != &space->vadListHead;
         entry = entry->Flink)
    {
        PMI_VAD vad = CONTAINING_RECORD(entry, MI_VAD, listEntry);
        if (candidate + size <= vad->base)
        {
            break;
        }
        if (vad->base + vad->size > candidate)
        {
            /* candidate only ever moves up: a VAD ending below the floor
             * never passes this test, so the floor holds. */
            candidate = MiRoundUp(vad->base + vad->size, align);
        }
    }
    if (candidate + size - 1 <= limitHigh && candidate + size <= KI_USER_SPACE_LIMIT)
    {
        return candidate;
    }
    return 0;
}

static void MiInsertVad(PMI_ADDRESS_SPACE space, PMI_VAD vad)
{
    PLIST_ENTRY entry = space->vadListHead.Flink;
    while (entry != &space->vadListHead &&
           CONTAINING_RECORD(entry, MI_VAD, listEntry)->base < vad->base)
    {
        entry = entry->Flink;
    }
    /* Insert before `entry`. */
    vad->listEntry.Flink = entry;
    vad->listEntry.Blink = entry->Blink;
    entry->Blink->Flink = &vad->listEntry;
    entry->Blink = &vad->listEntry;
}

/* Commit (or re-protect) the pages [base, base+size) inside `vad`. Frames
 * appear immediately, zeroed (Art. 3: no demand paging). */
static NTSTATUS MiCommitPages(PMI_ADDRESS_SPACE space, PMI_VAD vad, uint64_t base, uint64_t size,
                              ULONG protect)
{
    int present, writable, executable;
    MiProtectToPteBits(protect, &present, &writable, &executable);
    for (uint64_t page = base; page < base + size; page += PAGE_SIZE)
    {
        ULONG index = (ULONG)((page - vad->base) / PAGE_SIZE);
        if (vad->pageProtect[index] == 0)
        {
            uint64_t frame = MiAllocatePage();
            if (frame == 0)
            {
                return STATUS_NO_MEMORY; /* earlier pages stay committed, as NT */
            }
            memset(MiPhysicalToVirtual(frame), 0, PAGE_SIZE);
            MiMapUserPage(space->pml4Physical, page, frame, present, writable, executable);
        }
        else if (vad->pageProtect[index] != protect)
        {
            uint64_t frame = MiTranslateUserPage(space->pml4Physical, page, 0, 0);
            ASSERT(frame != 0); /* committed pages always keep their frame */
            MiUnmapUserPage(space->pml4Physical, page);
            MiMapUserPage(space->pml4Physical, page, frame, present, writable, executable);
        }
        vad->pageProtect[index] = protect;
    }
    return STATUS_SUCCESS;
}

static void MiDecommitPages(PMI_ADDRESS_SPACE space, PMI_VAD vad, uint64_t base, uint64_t size)
{
    for (uint64_t page = base; page < base + size; page += PAGE_SIZE)
    {
        ULONG index = (ULONG)((page - vad->base) / PAGE_SIZE);
        if (vad->pageProtect[index] != 0)
        {
            uint64_t frame = MiTranslateUserPage(space->pml4Physical, page, 0, 0);
            ASSERT(frame != 0);
            MiUnmapUserPage(space->pml4Physical, page);
            if (vad->ownsFrames)
            {
                MiFreePage(frame);
            }
            vad->pageProtect[index] = 0;
        }
    }
}

static void MiUnlinkAndFreeVad(PMI_VAD vad)
{
    RemoveEntryList(&vad->listEntry);
    if (vad->sectionBody != 0)
    {
        ObDereferenceObject(vad->sectionBody); /* the view's pin on the section */
    }
    MiFreePool(vad->pageProtect);
    MiFreePool(vad);
}

static PMI_VAD MiCreateVad(uint64_t base, uint64_t size, ULONG allocationProtect)
{
    PMI_VAD vad = MiAllocatePool(sizeof(MI_VAD));
    if (vad == 0)
    {
        return 0;
    }
    vad->base = base;
    vad->size = size;
    vad->allocationProtect = allocationProtect;
    vad->type = MEM_PRIVATE;
    vad->sectionBody = 0;
    vad->ownsFrames = TRUE;
    vad->pageProtect = MiAllocatePool((size / PAGE_SIZE) * sizeof(ULONG));
    if (vad->pageProtect == 0)
    {
        MiFreePool(vad);
        return 0;
    }
    return vad;
}

/* --- the engines (virtual.h) ----------------------------------------------- */

NTSTATUS MiCreateAddressSpace(PMI_ADDRESS_SPACE space)
{
    space->pml4Physical = MiCreateUserPml4();
    if (space->pml4Physical == 0)
    {
        return STATUS_NO_MEMORY;
    }
    InitializeListHead(&space->vadListHead);
    return STATUS_SUCCESS;
}

void MiDeleteAddressSpace(PMI_ADDRESS_SPACE space)
{
    while (!IsListEmpty(&space->vadListHead))
    {
        PMI_VAD vad = CONTAINING_RECORD(space->vadListHead.Flink, MI_VAD, listEntry);
        MiDecommitPages(space, vad, vad->base, vad->size);
        MiUnlinkAndFreeVad(vad);
    }
    MiDeleteUserPml4(space->pml4Physical);
    space->pml4Physical = 0;
}

NTSTATUS MiAllocateVirtualMemory(PMI_ADDRESS_SPACE space, PVOID *baseInOut, SIZE_T *sizeInOut,
                                 ULONG type, ULONG protect)
{
    return MiAllocateVirtualMemoryEx(space, baseInOut, sizeInOut, type, protect, 0, 0, 0);
}

NTSTATUS MiAllocateVirtualMemoryEx(PMI_ADDRESS_SPACE space, PVOID *baseInOut, SIZE_T *sizeInOut,
                                   ULONG type, ULONG protect, uint64_t limitLow, uint64_t limitHigh,
                                   uint64_t align)
{
    uint64_t requestedBase = (uint64_t)(uintptr_t)*baseInOut;
    uint64_t size = *sizeInOut;

    if (size == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (type & ~(ULONG)(MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN | MEM_WRITE_WATCH | MEM_RESET))
    {
        return STATUS_INVALID_PARAMETER;
    }
    /* Refuse an oversized request BEFORE the page rounding below, which
     * otherwise wraps: MiRoundUp(requestedBase + size, PAGE_SIZE) - base can
     * come out as 0 (or as a small value), and the size == 0 test above has
     * already been passed on the pre-rounding value. A rounded size of 0
     * reaches MiCreateVad and then MiAllocatePool(0), which panics.
     *
     * Position matters as much as the rule. The oracle splits these two
     * across a call boundary: NtAllocateVirtualMemory validates the type mask
     * (`if (type & ~type_mask) return STATUS_INVALID_PARAMETER;`) and only
     * then calls allocate_virtual_memory, which opens with
     * `if (is_beyond_limit( 0, size, working_set_limit )) return
     * STATUS_WORKING_SET_LIMIT_RANGE;` (third_party/wine
     * dlls/ntdll/unix/virtual.c). So a bad type outranks an oversized size,
     * and this test has to sit AFTER the mask check above -- both orders look
     * right until a caller gets both arguments wrong at once, which is why
     * sem_mm/reserve_commit pins it.
     *
     * working_set_limit starts at 0x7fffffff0000, i.e. KI_USER_SPACE_LIMIT.
     * With addr == 0 the macro reduces to a strict `size > limit`, so exactly
     * the limit falls through to the ordinary out-of-memory path. */
    if (size > KI_USER_SPACE_LIMIT)
    {
        return STATUS_WORKING_SET_LIMIT_RANGE;
    }
    if ((type & (MEM_COMMIT | MEM_RESERVE | MEM_RESET)) == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = MiCheckPageProtect(protect);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    uint64_t base;
    if (requestedBase != 0)
    {
        /* Explicit base: reserve rounds down to the 64K granularity,
         * commit-into-reservation to the page (Wine's exact rule). */
        base = MiRoundDown(requestedBase,
                           (type & MEM_RESERVE) ? MI_ALLOCATION_GRANULARITY : (uint64_t)PAGE_SIZE);
        size = MiRoundUp(requestedBase + size, PAGE_SIZE) - base;
        if (base < MI_LOWEST_USER_ADDRESS || base + size < base ||
            base + size > KI_USER_SPACE_LIMIT)
        {
            return STATUS_INVALID_PARAMETER;
        }
    }
    else
    {
        base = 0;
        size = MiRoundUp(size, PAGE_SIZE);
    }

    /* Structural backstop for the rounding above. The size > limit test at the
     * top of this function is what a caller observes, but nothing downstream
     * is prepared for a zero-sized VAD: MiCreateVad would call
     * MiAllocatePool(0) (a panic), and a zero-length VAD could never be found
     * by MiFindVad afterwards, so it would be unfreeable and unqueryable. */
    if (size == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (type & MEM_RESET)
    {
        /* MEM_RESET: contents may be discarded. Nothing is ever paged out
         * (Art. 3), so keeping them is a correct implementation. */
        PMI_VAD vad = MiFindVad(space, base);
        if (vad == 0 || base + size > vad->base + vad->size)
        {
            return STATUS_NOT_MAPPED_VIEW;
        }
        *baseInOut = (PVOID)(uintptr_t)base;
        *sizeInOut = size;
        return STATUS_SUCCESS;
    }

    if ((type & MEM_RESERVE) || requestedBase == 0)
    {
        if (requestedBase == 0)
        {
            base = MiFindFreeRegion(space, size, limitLow, limitHigh, align);
            if (base == 0)
            {
                return STATUS_NO_MEMORY;
            }
        }
        else if (!MiRangeIsFree(space, base, size))
        {
            return STATUS_CONFLICTING_ADDRESSES;
        }
        PMI_VAD vad = MiCreateVad(base, size, protect);
        if (vad == 0)
        {
            return STATUS_NO_MEMORY;
        }
        MiInsertVad(space, vad);
        if (type & MEM_COMMIT)
        {
            status = MiCommitPages(space, vad, base, size, protect);
            if (!NT_SUCCESS(status))
            {
                MiDecommitPages(space, vad, base, size);
                MiUnlinkAndFreeVad(vad);
                return status;
            }
        }
    }
    else
    {
        /* Commit into an existing reservation; the whole range must sit in
         * one VAD (Wine: find_view(base, size) else NOT_MAPPED_VIEW). */
        PMI_VAD vad = MiFindVad(space, base);
        if (vad == 0 || base + size > vad->base + vad->size)
        {
            return STATUS_NOT_MAPPED_VIEW;
        }
        if (vad->type != MEM_PRIVATE)
        {
            /* SEC_COMMIT views are fully committed at map time; committing
             * over them is a no-op NT reports as such (SEC_RESERVE commit
             * arrives with a real pagefile, post-M5). */
            return STATUS_ALREADY_COMMITTED;
        }
        status = MiCommitPages(space, vad, base, size, protect);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    *baseInOut = (PVOID)(uintptr_t)base;
    *sizeInOut = size;
    return STATUS_SUCCESS;
}

NTSTATUS MiFreeVirtualMemory(PMI_ADDRESS_SPACE space, PVOID *baseInOut, SIZE_T *sizeInOut,
                             ULONG type)
{
    uint64_t address = (uint64_t)(uintptr_t)*baseInOut;
    uint64_t size = *sizeInOut;

    uint64_t base = MiRoundDown(address, PAGE_SIZE);
    if (size != 0)
    {
        size = MiRoundUp(address + size, PAGE_SIZE) - base;
    }
    if (base == 0)
    {
        return STATUS_INVALID_PARAMETER; /* Wine: never free the first page */
    }
    PMI_VAD vad = MiFindVad(space, base);
    if (vad == 0)
    {
        return STATUS_MEMORY_NOT_ALLOCATED;
    }
    if (vad->type != MEM_PRIVATE)
    {
        /* A section view is unmapped, never freed (Wine: !is_view_valloc ->
         * STATUS_INVALID_PARAMETER; pinned by sem_mm/anonymous_section). */
        return STATUS_INVALID_PARAMETER;
    }
    if (size == 0 && base != vad->base)
    {
        return STATUS_FREE_VM_NOT_AT_BASE;
    }
    if (vad->base + vad->size - base < size)
    {
        return STATUS_UNABLE_TO_FREE_VM;
    }

    if (type == MEM_DECOMMIT)
    {
        /* size 0 = the whole VAD, and the reported size stays 0 (the shape
         * Wine's own test pins for modern Windows). */
        MiDecommitPages(space, vad, base, size != 0 ? size : vad->base + vad->size - base);
    }
    else if (type == MEM_RELEASE)
    {
        if (size == 0)
        {
            size = vad->size;
        }
        MiDecommitPages(space, vad, base, size);
        if (base == vad->base && size == vad->size)
        {
            MiUnlinkAndFreeVad(vad);
        }
        else if (base == vad->base || base + size == vad->base + vad->size)
        {
            /* Shrink from the start or the end. */
            uint64_t newBase = (base == vad->base) ? base + size : vad->base;
            uint64_t newSize = vad->size - size;
            PMI_VAD shrunk = MiCreateVad(newBase, newSize, vad->allocationProtect);
            if (shrunk == 0)
            {
                return STATUS_NO_MEMORY;
            }
            memcpy(shrunk->pageProtect, vad->pageProtect + (newBase - vad->base) / PAGE_SIZE,
                   (newSize / PAGE_SIZE) * sizeof(ULONG));
            MiUnlinkAndFreeVad(vad);
            MiInsertVad(space, shrunk);
        }
        else
        {
            /* Split: keep [vadBase, base) and [base+size, vadEnd). */
            PMI_VAD head = MiCreateVad(vad->base, base - vad->base, vad->allocationProtect);
            PMI_VAD tail = MiCreateVad(base + size, vad->base + vad->size - (base + size),
                                       vad->allocationProtect);
            if (head == 0 || tail == 0)
            {
                if (head != 0)
                {
                    MiFreePool(head->pageProtect);
                    MiFreePool(head);
                }
                if (tail != 0)
                {
                    MiFreePool(tail->pageProtect);
                    MiFreePool(tail);
                }
                return STATUS_NO_MEMORY;
            }
            memcpy(head->pageProtect, vad->pageProtect, MiVadPageCount(head) * sizeof(ULONG));
            memcpy(tail->pageProtect, vad->pageProtect + (tail->base - vad->base) / PAGE_SIZE,
                   MiVadPageCount(tail) * sizeof(ULONG));
            MiUnlinkAndFreeVad(vad);
            MiInsertVad(space, head);
            MiInsertVad(space, tail);
        }
    }
    else
    {
        return STATUS_INVALID_PARAMETER;
    }

    *baseInOut = (PVOID)(uintptr_t)base;
    *sizeInOut = size;
    return STATUS_SUCCESS;
}

NTSTATUS MiQueryVirtualMemoryBasic(PMI_ADDRESS_SPACE space, const void *address,
                                   PMEMORY_BASIC_INFORMATION info)
{
    uint64_t base = MiRoundDown((uint64_t)(uintptr_t)address, PAGE_SIZE);
    if (base >= KI_USER_SPACE_LIMIT)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PMI_VAD vad = MiFindVad(space, base);
    info->BaseAddress = (PVOID)(uintptr_t)base;
    if (vad == 0)
    {
        /* Free: the run extends to the next reservation (or the limit). */
        uint64_t end = KI_USER_SPACE_LIMIT;
        for (PLIST_ENTRY entry = space->vadListHead.Flink; entry != &space->vadListHead;
             entry = entry->Flink)
        {
            PMI_VAD next = CONTAINING_RECORD(entry, MI_VAD, listEntry);
            if (next->base > base)
            {
                end = next->base;
                break;
            }
        }
        info->AllocationBase = 0;
        info->AllocationProtect = 0;
        info->RegionSize = end - base;
        info->State = MEM_FREE;
        info->Protect = PAGE_NOACCESS;
        info->Type = 0;
        return STATUS_SUCCESS;
    }

    ULONG first = (ULONG)((base - vad->base) / PAGE_SIZE);
    ULONG protect = vad->pageProtect[first];
    ULONG last = first;
    while (last + 1 < MiVadPageCount(vad) && (vad->pageProtect[last + 1] == 0) == (protect == 0) &&
           vad->pageProtect[last + 1] == vad->pageProtect[first])
    {
        last++;
    }
    info->AllocationBase = (PVOID)(uintptr_t)vad->base;
    info->AllocationProtect = vad->allocationProtect;
    info->RegionSize = (uint64_t)(last - first + 1) * PAGE_SIZE;
    info->State = protect != 0 ? MEM_COMMIT : MEM_RESERVE;
    info->Protect = protect;
    info->Type = vad->type;
    return STATUS_SUCCESS;
}

/* --- section-view plumbing (virtual.h; used by mm/section.c) ---------------- */

uint64_t MiFindFreeViewBase(PMI_ADDRESS_SPACE space, uint64_t size)
{
    return MiFindFreeViewBaseEx(space, size, 0, 0, 0);
}

uint64_t MiFindFreeViewBaseEx(PMI_ADDRESS_SPACE space, uint64_t size, uint64_t limitLow,
                              uint64_t limitHigh, uint64_t align)
{
    return MiFindFreeRegion(space, MiRoundUp(size, PAGE_SIZE), limitLow, limitHigh, align);
}

BOOLEAN MiViewRangeIsFree(PMI_ADDRESS_SPACE space, uint64_t base, uint64_t size)
{
    if (base < MI_LOWEST_USER_ADDRESS || base + size < base || base + size > KI_USER_SPACE_LIMIT)
    {
        return FALSE;
    }
    return MiRangeIsFree(space, base, MiRoundUp(size, PAGE_SIZE));
}

PMI_VAD MiCreateMappedVad(PMI_ADDRESS_SPACE space, uint64_t base, uint64_t size,
                          ULONG allocationProtect, ULONG vadType, PVOID sectionBody,
                          BOOLEAN ownsFrames)
{
    ASSERT(vadType == MEM_MAPPED || vadType == MEM_IMAGE);
    /* A section-backed view pins its section body; a body-less mapped VAD is
     * only valid when it does not own its frames (M7: the shared
     * KUSER_SHARED_DATA page maps one kernel-owned frame with no section). */
    ASSERT(sectionBody != 0 || !ownsFrames);
    PMI_VAD vad = MiCreateVad(base, MiRoundUp(size, PAGE_SIZE), allocationProtect);
    if (vad == 0)
    {
        return 0;
    }
    vad->type = vadType;
    vad->sectionBody = sectionBody;
    vad->ownsFrames = ownsFrames;
    MiInsertVad(space, vad);
    return vad;
}

void MiCommitFrameInVad(PMI_ADDRESS_SPACE space, PMI_VAD vad, uint64_t virtualAddress,
                        uint64_t frame, ULONG protect)
{
    ULONG index = (ULONG)((virtualAddress - vad->base) / PAGE_SIZE);
    ASSERT(virtualAddress >= vad->base && index < MiVadPageCount(vad));
    ASSERT(vad->pageProtect[index] == 0); /* views commit each page exactly once */
    int present, writable, executable;
    MiProtectToPteBits(protect, &present, &writable, &executable);
    MiMapUserPage(space->pml4Physical, virtualAddress, frame, present, writable, executable);
    vad->pageProtect[index] = protect;
}

void MiDeleteMappedVad(PMI_ADDRESS_SPACE space, PMI_VAD vad)
{
    MiDecommitPages(space, vad, vad->base, vad->size);
    MiUnlinkAndFreeVad(vad);
}

NTSTATUS MiUnmapView(PMI_ADDRESS_SPACE space, uint64_t address)
{
    PMI_VAD vad = MiFindVad(space, MiRoundDown(address, PAGE_SIZE));
    if (vad == 0 || vad->type == MEM_PRIVATE)
    {
        return STATUS_NOT_MAPPED_VIEW;
    }
    MiDeleteMappedVad(space, vad);
    return STATUS_SUCCESS;
}

void MiCopyToUserRange(PMI_ADDRESS_SPACE space, uint64_t userBase, const void *source,
                       uint64_t length)
{
    const char *from = source;
    uint64_t copied = 0;
    while (copied < length)
    {
        uint64_t va = userBase + copied;
        uint64_t pageOffset = va & (PAGE_SIZE - 1);
        uint64_t chunk = PAGE_SIZE - pageOffset;
        if (chunk > length - copied)
        {
            chunk = length - copied;
        }
        uint64_t frame = MiTranslateUserPage(space->pml4Physical, va - pageOffset, 0, 0);
        ASSERT(frame != 0);
        memcpy((char *)MiPhysicalToVirtual(frame) + pageOffset, from + copied, chunk);
        copied += chunk;
    }
}

void MiZeroUserRange(PMI_ADDRESS_SPACE space, uint64_t userBase, uint64_t length)
{
    uint64_t zeroed = 0;
    while (zeroed < length)
    {
        uint64_t va = userBase + zeroed;
        uint64_t pageOffset = va & (PAGE_SIZE - 1);
        uint64_t chunk = PAGE_SIZE - pageOffset;
        if (chunk > length - zeroed)
        {
            chunk = length - zeroed;
        }
        uint64_t frame = MiTranslateUserPage(space->pml4Physical, va - pageOffset, 0, 0);
        ASSERT(frame != 0);
        memset((char *)MiPhysicalToVirtual(frame) + pageOffset, 0, chunk);
        zeroed += chunk;
    }
}

/* CUI-4: NtReadVirtualMemory's engine — copy from a (possibly non-current)
 * address space's user range into a kernel/current-space buffer, stopping at
 * the first page that is not present. Returns the bytes copied (< length ==
 * a fault). Unlike MiCopyToUserRange it never asserts: a probe of another
 * process's memory can legitimately hit an unmapped page. */
uint64_t MiCopyFromUserRange(PMI_ADDRESS_SPACE space, void *dest, uint64_t userBase,
                             uint64_t length)
{
    char *to = dest;
    uint64_t copied = 0;
    while (copied < length)
    {
        uint64_t va = userBase + copied;
        uint64_t pageOffset = va & (PAGE_SIZE - 1);
        uint64_t chunk = PAGE_SIZE - pageOffset;
        if (chunk > length - copied)
        {
            chunk = length - copied;
        }
        int present = 0;
        uint64_t frame = MiTranslateUserPage(space->pml4Physical, va - pageOffset, 0, &present);
        if (frame == 0 || !present)
        {
            break;
        }
        memcpy(to + copied, (const char *)MiPhysicalToVirtual(frame) + pageOffset, chunk);
        copied += chunk;
    }
    return copied;
}

/* NtWriteVirtualMemory's engine — the present-and-writable-checked mirror of
 * MiCopyToUserRange. Stops at the first page that is not present-and-writable;
 * returns the bytes written. */
uint64_t MiCopyToUserRangeChecked(PMI_ADDRESS_SPACE space, uint64_t userBase, const void *source,
                                  uint64_t length)
{
    const char *from = source;
    uint64_t written = 0;
    while (written < length)
    {
        uint64_t va = userBase + written;
        uint64_t pageOffset = va & (PAGE_SIZE - 1);
        uint64_t chunk = PAGE_SIZE - pageOffset;
        if (chunk > length - written)
        {
            chunk = length - written;
        }
        int present = 0;
        int writable = 0;
        uint64_t frame =
            MiTranslateUserPage(space->pml4Physical, va - pageOffset, &writable, &present);
        if (frame == 0 || !present || !writable)
        {
            break;
        }
        memcpy((char *)MiPhysicalToVirtual(frame) + pageOffset, from + written, chunk);
        written += chunk;
    }
    return written;
}

/* --- guard pages (virtual.h; used by mm/fault.c) ---------------------------- */

BOOLEAN MiClearGuardPage(PMI_ADDRESS_SPACE space, uint64_t pageAddress)
{
    ASSERT((pageAddress & (PAGE_SIZE - 1)) == 0);
    PMI_VAD vad = MiFindVad(space, pageAddress);
    if (vad == 0)
    {
        return FALSE;
    }
    ULONG index = (ULONG)((pageAddress - vad->base) / PAGE_SIZE);
    ULONG protect = vad->pageProtect[index];
    if (protect == 0 || (protect & PAGE_GUARD) == 0)
    {
        return FALSE;
    }
    /* One-shot: drop the guard bit and make the (already committed) frame
     * an ordinary present page. */
    uint64_t frame = MiTranslateUserPage(space->pml4Physical, pageAddress, 0, 0);
    ASSERT(frame != 0);
    ULONG newProtect = protect & ~(ULONG)PAGE_GUARD;
    int present, writable, executable;
    MiProtectToPteBits(newProtect, &present, &writable, &executable);
    MiUnmapUserPage(space->pml4Physical, pageAddress);
    MiMapUserPage(space->pml4Physical, pageAddress, frame, present, writable, executable);
    vad->pageProtect[index] = newProtect;
    return TRUE;
}

/* --- the Nt* surface -------------------------------------------------------- */

/* Resolve a process-handle argument (virtual.h): the pseudo-handle or a real
 * handle to a Process object; *referenced tells the caller to dereference.
 * Shared with the section Nt* in mm/section.c (M5). */
NTSTATUS MiReferenceProcessByHandle(HANDLE processHandle, ACCESS_MASK desiredAccess,
                                    PEPROCESS *process, BOOLEAN *referenced)
{
    if (processHandle == NtCurrentProcess())
    {
        *process = KeGetCurrentThread()->process;
        *referenced = FALSE;
        return STATUS_SUCCESS;
    }
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(processHandle, desiredAccess, &PspProcessType,
                                                ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *process = body;
    *referenced = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS NtAllocateVirtualMemory(HANDLE process, PVOID *baseInOut, ULONG_PTR zeroBits,
                                 SIZE_T *sizeInOut, ULONG type, ULONG protect)
{
    /* Wine's zero_bits validation shape; a nonzero value only constrains
     * placement, which the bottom-up allocator already satisfies. */
    if ((zeroBits > 21 && zeroBits < 32) ||
        (zeroBits > 32 && zeroBits < MI_ALLOCATION_GRANULARITY - 1))
    {
        return STATUS_INVALID_PARAMETER_3;
    }

    NTSTATUS status = KiProbeForWrite(baseInOut, sizeof(*baseInOut), sizeof(*baseInOut));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(sizeInOut, sizeof(*sizeInOut), sizeof(*sizeInOut));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PEPROCESS target;
    BOOLEAN referenced;
    status = MiReferenceProcessByHandle(process, PROCESS_VM_OPERATION, &target, &referenced);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PVOID base = *baseInOut;
    SIZE_T size = *sizeInOut;
    status = MiAllocateVirtualMemory(&target->addressSpace, &base, &size, type, protect);
    if (NT_SUCCESS(status))
    {
        *baseInOut = base;
        *sizeInOut = size;
    }
    if (referenced)
    {
        ObDereferenceObject(target);
    }
    return status;
}

/* --- the VirtualAlloc2 extended-parameter contract (CUI-7) ------------------ */

/* Capture + validate a user MEM_EXTENDED_PARAMETER array, mirroring the
 * oracle's ladder exactly (wine dlls/ntdll/unix/virtual.c
 * get_extended_params; pinned by sem_mm/alloc_ex): unknown or duplicated
 * types refuse; AddressRequirements validates alignment (power of two,
 * >= the 64K granularity), a 64K-aligned Lowest below the user-space
 * limit, and a page-end Highest above Lowest within the limit;
 * NumaNode/PartitionHandle/UserPhysicalHandle are accepted and ignored. */
NTSTATUS MiCaptureExtendedParams(const MEM_EXTENDED_PARAMETER *parameters, ULONG count,
                                 MI_EXTENDED_PARAMS *out)
{
    memset(out, 0, sizeof(*out));
    if (count == 0)
    {
        return STATUS_SUCCESS;
    }
    if (parameters == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = KiProbeForRead(parameters, (SIZE_T)count * sizeof(*parameters),
                                     _Alignof(MEM_EXTENDED_PARAMETER));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    ULONG present = 0;
    for (ULONG i = 0; i < count; i++)
    {
        ULONG parameterType = (ULONG)parameters[i].Type;
        if (parameterType >= 32 || (present & (1u << parameterType)) != 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        present |= 1u << parameterType;
        switch (parameterType)
        {
        case MemExtendedParameterAddressRequirements:
        {
            const MEM_ADDRESS_REQUIREMENTS *requirements = parameters[i].Pointer;
            status = KiProbeForRead(requirements, sizeof(*requirements), sizeof(uint64_t));
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            uint64_t alignment = requirements->Alignment;
            uint64_t low = (uint64_t)(uintptr_t)requirements->LowestStartingAddress;
            uint64_t high = (uint64_t)(uintptr_t)requirements->HighestEndingAddress;
            if (alignment != 0)
            {
                if ((alignment & (alignment - 1)) != 0 ||
                    alignment - 1 < MI_ALLOCATION_GRANULARITY - 1)
                {
                    return STATUS_INVALID_PARAMETER;
                }
                out->align = alignment;
            }
            if (low != 0)
            {
                if (low >= KI_USER_SPACE_LIMIT || (low & (MI_ALLOCATION_GRANULARITY - 1)) != 0)
                {
                    return STATUS_INVALID_PARAMETER;
                }
                out->limitLow = low;
            }
            if (high != 0)
            {
                /* The (high + 1) & (page_mask - 1) test is the oracle's own
                 * arithmetic, reproduced bit for bit (wine
                 * dlls/ntdll/unix/virtual.c get_extended_params). */
                if (high > KI_USER_SPACE_LIMIT || high <= out->limitLow ||
                    ((high + 1) & ((uint64_t)PAGE_SIZE - 1 - 1)) != 0)
                {
                    return STATUS_INVALID_PARAMETER;
                }
                out->limitHigh = high;
            }
            break;
        }
        case MemExtendedParameterAttributeFlags:
            out->attributes = parameters[i].ULong;
            break;
        case MemExtendedParameterImageMachine:
            out->machine = (USHORT)parameters[i].ULong;
            break;
        case MemExtendedParameterNumaNode:
        case MemExtendedParameterPartitionHandle:
        case MemExtendedParameterUserPhysicalHandle:
            break; /* accepted and ignored, as the oracle */
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtAllocateVirtualMemoryEx(HANDLE process, PVOID *baseInOut, SIZE_T *sizeInOut, ULONG type,
                                   ULONG protect, MEM_EXTENDED_PARAMETER *parameters, ULONG count)
{
    NTSTATUS status = KiProbeForWrite(baseInOut, sizeof(*baseInOut), sizeof(*baseInOut));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(sizeInOut, sizeof(*sizeInOut), sizeof(*sizeInOut));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* The oracle's own order (pinned by sem_mm/alloc_ex): parameters first,
     * then the Ex type mask, then base-vs-requirements, then the size. */
    MI_EXTENDED_PARAMS extended;
    status = MiCaptureExtendedParams(parameters, count, &extended);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (type & ~(ULONG)(MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN | MEM_WRITE_WATCH | MEM_RESET |
                        MEM_RESERVE_PLACEHOLDER | MEM_REPLACE_PLACEHOLDER))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (type & (MEM_RESERVE_PLACEHOLDER | MEM_REPLACE_PLACEHOLDER))
    {
        /* Placeholders are deliberately unbuilt: no baked consumer, and the
         * milestone scope is the delegating *Ex forms (docs/03 "CUI-7").
         * Loud refusal, never a fake success (Art. 12; the SEC_RESERVE
         * precedent in section.c). */
        return STATUS_NOT_IMPLEMENTED;
    }
    if (*baseInOut != 0 &&
        (extended.align != 0 || extended.limitLow != 0 || extended.limitHigh != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (*sizeInOut == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PEPROCESS target;
    BOOLEAN referenced;
    status = MiReferenceProcessByHandle(process, PROCESS_VM_OPERATION, &target, &referenced);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PVOID base = *baseInOut;
    SIZE_T size = *sizeInOut;
    status = MiAllocateVirtualMemoryEx(&target->addressSpace, &base, &size, type, protect,
                                       extended.limitLow, extended.limitHigh, extended.align);
    if (NT_SUCCESS(status))
    {
        *baseInOut = base;
        *sizeInOut = size;
    }
    if (referenced)
    {
        ObDereferenceObject(target);
    }
    return status;
}

NTSTATUS NtFreeVirtualMemory(HANDLE process, PVOID *baseInOut, SIZE_T *sizeInOut, ULONG type)
{
    NTSTATUS status = KiProbeForWrite(baseInOut, sizeof(*baseInOut), sizeof(*baseInOut));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(sizeInOut, sizeof(*sizeInOut), sizeof(*sizeInOut));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PEPROCESS target;
    BOOLEAN referenced;
    status = MiReferenceProcessByHandle(process, PROCESS_VM_OPERATION, &target, &referenced);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PVOID base = *baseInOut;
    SIZE_T size = *sizeInOut;
    status = MiFreeVirtualMemory(&target->addressSpace, &base, &size, type);
    if (NT_SUCCESS(status))
    {
        *baseInOut = base;
        *sizeInOut = size;
    }
    if (referenced)
    {
        ObDereferenceObject(target);
    }
    return status;
}

NTSTATUS NtQueryVirtualMemory(HANDLE process, LPCVOID address,
                              MEMORY_INFORMATION_CLASS informationClass, PVOID buffer,
                              SIZE_T length, SIZE_T *returnLength)
{
    if (informationClass != MemoryBasicInformation)
    {
        return STATUS_INVALID_INFO_CLASS;
    }
    if (length < sizeof(MEMORY_BASIC_INFORMATION))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    NTSTATUS status = KiProbeForWrite(buffer, sizeof(MEMORY_BASIC_INFORMATION), sizeof(uint64_t));
    if (NT_SUCCESS(status) && returnLength != 0)
    {
        status = KiProbeForWrite(returnLength, sizeof(*returnLength), sizeof(*returnLength));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PEPROCESS target;
    BOOLEAN referenced;
    status = MiReferenceProcessByHandle(process, PROCESS_QUERY_INFORMATION, &target, &referenced);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    MEMORY_BASIC_INFORMATION info;
    status = MiQueryVirtualMemoryBasic(&target->addressSpace, address, &info);
    if (NT_SUCCESS(status))
    {
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
    }
    if (referenced)
    {
        ObDereferenceObject(target);
    }
    return status;
}

/* Change the protection of a committed run and report the previous protection
 * (M7: ntdll's loader flips .text/.data protection during import fixups). The
 * range must lie inside one VAD and be fully committed — the reprotect reuses
 * the same frames (no COW, Art. 3), only rewriting the PTE bits. */
NTSTATUS MiProtectVirtualMemory(PMI_ADDRESS_SPACE space, uint64_t *baseInOut, uint64_t *sizeInOut,
                                ULONG newProtect, ULONG *oldProtectOut)
{
    NTSTATUS status = MiCheckPageProtect(newProtect);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t base = MiRoundDown(*baseInOut, PAGE_SIZE);
    uint64_t end = MiRoundUp(*baseInOut + *sizeInOut, PAGE_SIZE);
    if (end <= base)
    {
        return STATUS_INVALID_PARAMETER;
    }
    PMI_VAD vad = MiFindVad(space, base);
    if (vad == 0 || end > vad->base + vad->size)
    {
        return STATUS_INVALID_ADDRESS; /* not a single committed region */
    }

    /* Check the WHOLE range before touching any of it. NT requires every
     * page in the range to be committed, and discovering an uncommitted one
     * halfway through used to leave the range half-reprotected while
     * reporting failure -- ntdll's loader flips section protections through
     * this path, so a partly-applied change is a process that runs with the
     * wrong page permissions (docs/review-2026-07 §7). */
    for (uint64_t page = base; page < end; page += PAGE_SIZE)
    {
        ULONG index = (ULONG)((page - vad->base) / PAGE_SIZE);
        if (vad->pageProtect[index] == 0)
        {
            return STATUS_NOT_COMMITTED;
        }
    }

    int present, writable, executable;
    MiProtectToPteBits(newProtect, &present, &writable, &executable);
    ULONG oldProtect = 0;
    for (uint64_t page = base; page < end; page += PAGE_SIZE)
    {
        ULONG index = (ULONG)((page - vad->base) / PAGE_SIZE);
        if (page == base)
        {
            oldProtect = vad->pageProtect[index];
        }
        uint64_t frame = MiTranslateUserPage(space->pml4Physical, page, 0, 0);
        ASSERT(frame != 0);
        MiUnmapUserPage(space->pml4Physical, page);
        MiMapUserPage(space->pml4Physical, page, frame, present, writable, executable);
        vad->pageProtect[index] = newProtect;
    }
    *baseInOut = base;
    *sizeInOut = end - base;
    *oldProtectOut = oldProtect;
    return STATUS_SUCCESS;
}

void MiQueryVmCounters(PMI_ADDRESS_SPACE space, uint64_t *reservedBytesOut,
                       uint64_t *committedBytesOut)
{
    uint64_t reserved = 0;
    uint64_t committed = 0;
    for (PLIST_ENTRY entry = space->vadListHead.Flink; entry != &space->vadListHead;
         entry = entry->Flink)
    {
        PMI_VAD vad = CONTAINING_RECORD(entry, MI_VAD, listEntry);
        reserved += vad->size;
        uint64_t pages = vad->size / PAGE_SIZE;
        for (uint64_t i = 0; i < pages; i++)
        {
            if (vad->pageProtect[i] != 0)
            {
                committed += PAGE_SIZE;
            }
        }
    }
    *reservedBytesOut = reserved;
    *committedBytesOut = committed;
}

NTSTATUS NtProtectVirtualMemory(HANDLE process, PVOID *baseInOut, SIZE_T *sizeInOut,
                                ULONG newProtect, ULONG *oldProtect)
{
    NTSTATUS status = KiProbeForWrite(baseInOut, sizeof(*baseInOut), sizeof(*baseInOut));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(sizeInOut, sizeof(*sizeInOut), sizeof(*sizeInOut));
    }
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(oldProtect, sizeof(*oldProtect), sizeof(*oldProtect));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PEPROCESS target;
    BOOLEAN referenced;
    status = MiReferenceProcessByHandle(process, PROCESS_VM_OPERATION, &target, &referenced);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    uint64_t base = (uint64_t)(uintptr_t)*baseInOut;
    uint64_t size = *sizeInOut;
    ULONG old = 0;
    status = MiProtectVirtualMemory(&target->addressSpace, &base, &size, newProtect, &old);
    if (NT_SUCCESS(status))
    {
        *baseInOut = (PVOID)(uintptr_t)base;
        *sizeInOut = size;
        *oldProtect = old;
    }
    if (referenced)
    {
        ObDereferenceObject(target);
    }
    return status;
}

/* kernel/io/file.c: the Mm<->Io seam for file identity (the
 * IopBuildSectionBacking pattern, mm/section.c). */
BOOLEAN IoIsSameUnderlyingFile(PVOID fileBody1, PVOID fileBody2);

NTSTATUS NtAreMappedFilesTheSame(PVOID address1, PVOID address2)
{
    /* The loader's find_existing_module probe (dlls/ntdll/loader.c): is the
     * image at address2 the same on-disk file as the module at address1?
     * Statuses and their ORDER as the oracle's dlls/ntdll/unix/virtual.c
     * NtAreMappedFilesTheSame + server/mapping.c is_same_mapping, pinned by
     * sem_mm/mapped_same: both addresses must land in views; private
     * (NtAllocateVirtualMemory) memory refuses CONFLICTING_ADDRESSES; one
     * view is trivially the same; two views are the same only when the
     * FIRST is an image view and both name the same on-disk file. */
    PMI_ADDRESS_SPACE space = &KeGetCurrentThread()->process->addressSpace;
    PMI_VAD vad1 = MiFindVad(space, (uint64_t)(uintptr_t)address1);
    PMI_VAD vad2 = MiFindVad(space, (uint64_t)(uintptr_t)address2);
    if (vad1 == 0 || vad2 == 0)
    {
        return STATUS_INVALID_ADDRESS;
    }
    if (vad1->type == MEM_PRIVATE || vad2->type == MEM_PRIVATE)
    {
        return STATUS_CONFLICTING_ADDRESSES;
    }
    if (vad1 == vad2)
    {
        return STATUS_SUCCESS;
    }
    PMI_SECTION section1 = vad1->sectionBody;
    PMI_SECTION section2 = vad2->sectionBody;
    if (section1 == 0 || section2 == 0 || section1->fileObject == 0 || section2->fileObject == 0 ||
        (section1->attributes & SEC_IMAGE) == 0 ||
        !IoIsSameUnderlyingFile(section1->fileObject, section2->fileObject))
    {
        return STATUS_NOT_SAME_DEVICE;
    }
    return STATUS_SUCCESS;
}

/* CUI-4: cross-process memory access (toolhelp/debug readers). Contract from
 * ntdll's unix side (dlls/ntdll/unix/virtual.c): a read validates the OUT
 * buffer (ACCESS_VIOLATION on failure, bytes 0), then moves from the target
 * address space, reporting STATUS_PARTIAL_COPY with bytes 0 on any fault; a
 * write validates the source buffer (PARTIAL_COPY on failure) then moves into
 * the target. The buffer is always in the CALLER's address space (direct
 * access under the current CR3); only the far side rides MiTranslateUserPage +
 * the HHDM. Pinned by sem_ps/virtual_memory. */
NTSTATUS NtReadVirtualMemory(HANDLE processHandle, const void *baseAddress, void *buffer,
                             SIZE_T size, SIZE_T *bytesRead)
{
    if (bytesRead != 0)
    {
        NTSTATUS probe = KiProbeForWrite(bytesRead, sizeof(*bytesRead), sizeof(*bytesRead));
        if (!NT_SUCCESS(probe))
        {
            return probe;
        }
        *bytesRead = 0;
    }
    if (size == 0)
    {
        return STATUS_SUCCESS;
    }
    /* The OUT buffer must be writable in the caller (Wine's
     * virtual_check_buffer_for_write); failure is ACCESS_VIOLATION, not a
     * partial copy. */
    if (!NT_SUCCESS(KiProbeForWrite(buffer, size, 1)))
    {
        return STATUS_ACCESS_VIOLATION;
    }

    PEPROCESS process;
    BOOLEAN referenced = FALSE;
    NTSTATUS status =
        MiReferenceProcessByHandle(processHandle, PROCESS_VM_READ, &process, &referenced);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    uint64_t copied =
        MiCopyFromUserRange(&process->addressSpace, buffer, (uint64_t)(uintptr_t)baseAddress, size);
    if (referenced)
    {
        ObDereferenceObject(process);
    }
    if (copied != size)
    {
        return STATUS_PARTIAL_COPY; /* bytesRead already 0 (Wine's fault shape) */
    }
    if (bytesRead != 0)
    {
        *bytesRead = size;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtWriteVirtualMemory(HANDLE processHandle, void *baseAddress, const void *buffer,
                              SIZE_T size, SIZE_T *bytesWritten)
{
    if (bytesWritten != 0)
    {
        NTSTATUS probe =
            KiProbeForWrite(bytesWritten, sizeof(*bytesWritten), sizeof(*bytesWritten));
        if (!NT_SUCCESS(probe))
        {
            return probe;
        }
        *bytesWritten = 0;
    }
    if (size == 0)
    {
        return STATUS_SUCCESS;
    }
    /* The source must be readable in the caller (Wine's
     * virtual_check_buffer_for_read); failure is STATUS_PARTIAL_COPY. */
    if (!NT_SUCCESS(KiProbeForRead(buffer, size, 1)))
    {
        return STATUS_PARTIAL_COPY;
    }

    PEPROCESS process;
    BOOLEAN referenced = FALSE;
    NTSTATUS status =
        MiReferenceProcessByHandle(processHandle, PROCESS_VM_WRITE, &process, &referenced);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    uint64_t written = MiCopyToUserRangeChecked(&process->addressSpace,
                                                (uint64_t)(uintptr_t)baseAddress, buffer, size);
    if (referenced)
    {
        ObDereferenceObject(process);
    }
    if (written != size)
    {
        return STATUS_PARTIAL_COPY;
    }
    if (bytesWritten != 0)
    {
        *bytesWritten = size;
    }
    return STATUS_SUCCESS;
}
