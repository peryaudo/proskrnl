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
#include "kernel/ps/ps.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "arch/x86_64/mmu.h"

#include "abi/ntstatus.h"

/* One reservation: [base, base + size), page-granular, with one protection
 * word per page (0 = reserved-only, else the committed PAGE_* value). */
typedef struct
{
    LIST_ENTRY listEntry; /* on MI_ADDRESS_SPACE.vadListHead, ascending */
    uint64_t base;
    uint64_t size;
    ULONG allocationProtect;
    PULONG pageProtect;
} MI_VAD, *PMI_VAD;

#define MI_LOWEST_USER_ADDRESS 0x10000ULL /* NT never allocates the first 64K */

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
    *present = bits != PAGE_NOACCESS;
    *writable = bits == PAGE_READWRITE || bits == PAGE_EXECUTE_READWRITE;
    *executable =
        bits == PAGE_EXECUTE || bits == PAGE_EXECUTE_READ || bits == PAGE_EXECUTE_READWRITE;
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

/* Lowest 64K-aligned hole of `size` bytes, bottom-up like Wine. 0 = full. */
static uint64_t MiFindFreeRegion(PMI_ADDRESS_SPACE space, uint64_t size)
{
    uint64_t candidate = MiRoundUp(MI_LOWEST_USER_ADDRESS, MI_ALLOCATION_GRANULARITY);
    for (PLIST_ENTRY entry = space->vadListHead.Flink; entry != &space->vadListHead;
         entry = entry->Flink)
    {
        PMI_VAD vad = CONTAINING_RECORD(entry, MI_VAD, listEntry);
        if (candidate + size <= vad->base)
        {
            return candidate;
        }
        if (vad->base + vad->size > candidate)
        {
            candidate = MiRoundUp(vad->base + vad->size, MI_ALLOCATION_GRANULARITY);
        }
    }
    if (candidate + size <= KI_USER_SPACE_LIMIT)
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
            MiFreePage(frame);
            vad->pageProtect[index] = 0;
        }
    }
}

static void MiUnlinkAndFreeVad(PMI_VAD vad)
{
    RemoveEntryList(&vad->listEntry);
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
            base = MiFindFreeRegion(space, size);
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
    info->Type = MEM_PRIVATE;
    return STATUS_SUCCESS;
}

/* --- the Nt* surface -------------------------------------------------------- */

/* Resolve a process-handle argument. M4: the pseudo-handle or a real handle
 * to a Process object; *referenced tells the caller to dereference. */
static NTSTATUS MipReferenceProcess(HANDLE processHandle, ACCESS_MASK desiredAccess,
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
    status = MipReferenceProcess(process, PROCESS_VM_OPERATION, &target, &referenced);
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
    status = MipReferenceProcess(process, PROCESS_VM_OPERATION, &target, &referenced);
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
    status = MipReferenceProcess(process, PROCESS_QUERY_INFORMATION, &target, &referenced);
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
