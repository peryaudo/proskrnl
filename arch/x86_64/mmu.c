/* arch/x86_64/mmu.c — kernel page-table management (M2). See mmu.h.
 *
 * Four-level x86-64 paging, no PCID, no global pages games: the simplest
 * correct thing (Art. 3). The kernel image is mapped with 4 KiB pages from the
 * Limine-reported physical base; all of physical memory is re-mapped at the
 * HHDM offset with 2 MiB pages (RW + NX). Page-table frames come from
 * MiAllocatePage and are reached through the HHDM.
 *
 * Constants cross-check: Intel SDM Vol. 3A, "Paging" — 4-level PTE bit
 * layout (P bit 0, R/W bit 1, U/S bit 2, PWT bit 3, PCD bit 4, PS bit 7,
 * XD bit 63, address bits 51:12 = 0x000FFFFFFFFFF000, 9-bit index per level
 * starting at bit 12), the default PAT encoding there (PCD=1 PWT=1 selects
 * entry 3 = strong uncacheable) — and the IA32_EFER register (NXE bit 11;
 * also QEMU target/i386/cpu.h MSR_EFER_NXE).
 */
#include "arch/x86_64/mmu.h"
#include "arch/x86_64/io.h"
#include "kernel/mm/phys.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "limine.h"

#define PTE_PRESENT (1ULL << 0)
#define PTE_WRITE   (1ULL << 1)
#define PTE_USER    (1ULL << 2)
#define PTE_PWT     (1ULL << 3) /* with PCD: PAT entry 3, strong uncacheable */
#define PTE_PCD     (1ULL << 4)
#define PTE_LARGE   (1ULL << 7) /* PS: 2 MiB page in a PDE */
#define PTE_NX      (1ULL << 63)
#define PTE_ADDRESS 0x000FFFFFFFFFF000ULL

#define LARGE_PAGE_SIZE (2ULL * 1024 * 1024)

#define IA32_EFER     0xC0000080
#define IA32_EFER_NXE (1ULL << 11)

static uint64_t MiKernelPml4;    /* physical address of the kernel PML4 */
static int MiKernelPml4IsFrozen; /* set before the first process PML4 copy */

static uint64_t *MiTableEntry(uint64_t tablePhysical, int index)
{
    return (uint64_t *)MiPhysicalToVirtual(tablePhysical) + index;
}

/* Get the page table one level down from *entry, allocating it if absent.
 * Returns the physical address of the lower table. tableFlags carries the
 * permissive intermediate-entry bits (user walks add PTE_USER; the leaf
 * decides the effective protection). */
static uint64_t MiEnsureTable(uint64_t *entry, uint64_t tableFlags)
{
    if (*entry & PTE_PRESENT)
    {
        if (*entry & PTE_LARGE)
        {
            KiPanic("MiEnsureTable: 4 KiB mapping inside an existing 2 MiB page");
        }
        return *entry & PTE_ADDRESS;
    }
    uint64_t table = MiAllocatePage();
    if (table == 0)
    {
        KiPanic("MiEnsureTable: out of physical pages");
    }
    memset(MiPhysicalToVirtual(table), 0, PAGE_SIZE);
    *entry = table | tableFlags;
    return table;
}

static void MiMapPageInternal(uint64_t virtualAddress, uint64_t physicalAddress, uint64_t flags)
{
    uint64_t pageMask = ((flags & PTE_LARGE) ? LARGE_PAGE_SIZE : PAGE_SIZE) - 1;
    ASSERT((virtualAddress & pageMask) == 0);
    ASSERT((physicalAddress & pageMask) == 0);
    int pml4Index = (int)((virtualAddress >> 39) & 0x1FF);
    int pdptIndex = (int)((virtualAddress >> 30) & 0x1FF);
    int pdIndex = (int)((virtualAddress >> 21) & 0x1FF);
    int ptIndex = (int)((virtualAddress >> 12) & 0x1FF);

    /* Process PML4s share the kernel half by copying the boot-time top-level
     * entries (MiCreateUserPml4); a new kernel PML4 slot after that copy
     * would be invisible to every existing process. */
    uint64_t *pml4Entry = MiTableEntry(MiKernelPml4, pml4Index);
    if (MiKernelPml4IsFrozen && (*pml4Entry & PTE_PRESENT) == 0)
    {
        KiPanic("MiMapPage: new kernel PML4 slot after the kernel half was frozen");
    }
    uint64_t pdpt = MiEnsureTable(pml4Entry, PTE_PRESENT | PTE_WRITE);
    uint64_t pd = MiEnsureTable(MiTableEntry(pdpt, pdptIndex), PTE_PRESENT | PTE_WRITE);
    uint64_t *pde = MiTableEntry(pd, pdIndex);

    if (flags & PTE_LARGE)
    {
        if (*pde & PTE_PRESENT)
        {
            return; /* memmap entries overlap after 2 MiB rounding; idempotent */
        }
        *pde = physicalAddress | flags;
        return;
    }

    uint64_t pt = MiEnsureTable(pde, PTE_PRESENT | PTE_WRITE);
    uint64_t *pte = MiTableEntry(pt, ptIndex);
    if (*pte & PTE_PRESENT)
    {
        KiPanic("MiMapPage: virtual address already mapped");
    }
    *pte = physicalAddress | flags;
}

void MiMapPage(uint64_t virtualAddress, uint64_t physicalAddress, int writable)
{
    uint64_t flags = PTE_PRESENT | PTE_NX | (writable ? PTE_WRITE : 0);
    MiMapPageInternal(virtualAddress, physicalAddress, flags);
}

void MiMapDevicePage(uint64_t virtualAddress, uint64_t physicalAddress)
{
    MiMapPageInternal(virtualAddress, physicalAddress,
                      PTE_PRESENT | PTE_WRITE | PTE_NX | PTE_PCD | PTE_PWT);
}

/* Return a pointer to the live PTE for virtualAddress, or 0 if any level is
 * absent. largePage reports a 2 MiB PDE mapping (whose PDE is returned). */
static uint64_t *MiFindEntry(uint64_t virtualAddress, int *largePage)
{
    uint64_t *entry = MiTableEntry(MiKernelPml4, (int)((virtualAddress >> 39) & 0x1FF));
    if (!(*entry & PTE_PRESENT))
    {
        return 0;
    }
    entry = MiTableEntry(*entry & PTE_ADDRESS, (int)((virtualAddress >> 30) & 0x1FF));
    if (!(*entry & PTE_PRESENT))
    {
        return 0;
    }
    entry = MiTableEntry(*entry & PTE_ADDRESS, (int)((virtualAddress >> 21) & 0x1FF));
    if (!(*entry & PTE_PRESENT))
    {
        return 0;
    }
    if (*entry & PTE_LARGE)
    {
        *largePage = 1;
        return entry;
    }
    *largePage = 0;
    entry = MiTableEntry(*entry & PTE_ADDRESS, (int)((virtualAddress >> 12) & 0x1FF));
    if (!(*entry & PTE_PRESENT))
    {
        return 0;
    }
    return entry;
}

void MiUnmapPage(uint64_t virtualAddress)
{
    int largePage = 0;
    uint64_t *entry = MiFindEntry(virtualAddress, &largePage);
    if (entry == 0 || largePage)
    {
        KiPanic("MiUnmapPage: address not mapped as a 4 KiB page");
    }
    *entry = 0;
    MiInvlpgCount++;
    __asm__ volatile("invlpg (%0)" : : "r"(virtualAddress) : "memory");
}

uint64_t MiVirtualToPhysical(uint64_t virtualAddress)
{
    int largePage = 0;
    uint64_t *entry = MiFindEntry(virtualAddress, &largePage);
    if (entry == 0)
    {
        return 0;
    }
    if (largePage)
    {
        return (*entry & PTE_ADDRESS & ~(LARGE_PAGE_SIZE - 1)) +
               (virtualAddress & (LARGE_PAGE_SIZE - 1));
    }
    return (*entry & PTE_ADDRESS) + (virtualAddress & (PAGE_SIZE - 1));
}

extern char KiImageEnd[]; /* linker.ld */

void MiInitializeVirtualMemory(uint64_t kernelPhysicalBase, uint64_t kernelVirtualBase,
                               struct limine_memmap_response *memoryMap)
{
    MiKernelPml4 = MiAllocatePage();
    if (MiKernelPml4 == 0)
    {
        KiPanic("MiInitializeVirtualMemory: out of physical pages");
    }
    memset(MiPhysicalToVirtual(MiKernelPml4), 0, PAGE_SIZE);

    /* The kernel image, 4 KiB pages, RWX. (Per-section W^X can come later;
     * the simplest correct mapping first — Art. 3.) */
    uint64_t imageEnd = (uint64_t)(uintptr_t)KiImageEnd;
    for (uint64_t virt = kernelVirtualBase; virt < imageEnd; virt += PAGE_SIZE)
    {
        MiMapPageInternal(virt, kernelPhysicalBase + (virt - kernelVirtualBase),
                          PTE_PRESENT | PTE_WRITE);
    }

    /* The HHDM: every memmap region re-mapped at the direct-map offset with
     * 2 MiB pages, RW + NX. Rounding to 2 MiB may spill past a region's edge;
     * nothing dereferences the spill, and overlaps are mapped once. */
    uint64_t hhdmOffset = (uint64_t)(uintptr_t)MiPhysicalToVirtual(0);
    for (uint64_t i = 0; i < memoryMap->entry_count; i++)
    {
        struct limine_memmap_entry *entry = memoryMap->entries[i];
        uint64_t base = entry->base & ~(LARGE_PAGE_SIZE - 1);
        uint64_t end = entry->base + entry->length;
        for (uint64_t physical = base; physical < end; physical += LARGE_PAGE_SIZE)
        {
            MiMapPageInternal(hhdmOffset + physical, physical,
                              PTE_PRESENT | PTE_WRITE | PTE_LARGE | PTE_NX);
        }
    }

    /* NX needs EFER.NXE (Limine usually sets it; do not rely on that). */
    KiWriteMsr(IA32_EFER, KiReadMsr(IA32_EFER) | IA32_EFER_NXE);
    __asm__ volatile("mov %0, %%cr3" : : "r"(MiKernelPml4) : "memory");
}

/* --- per-process address spaces (M4) --------------------------------------- */

uint64_t MiGetKernelPml4(void)
{
    return MiKernelPml4;
}

void MiFreezeKernelPml4(void)
{
    MiKernelPml4IsFrozen = 1;
}

uint64_t MiCreateUserPml4(void)
{
    ASSERT(MiKernelPml4IsFrozen);
    uint64_t pml4 = MiAllocatePage();
    if (pml4 == 0)
    {
        return 0;
    }
    uint64_t *table = MiPhysicalToVirtual(pml4);
    const uint64_t *kernelTable = MiPhysicalToVirtual(MiKernelPml4);
    memset(table, 0, PAGE_SIZE / 2);
    /* Share the kernel half: the upper 256 slots point at the SAME PDPTs. */
    memcpy(table + 256, kernelTable + 256, PAGE_SIZE / 2);
    return pml4;
}

/* Free a user-half page-table subtree at `level` (3 = PDPT under a PML4E). */
static void MipFreeTableTree(uint64_t tablePhysical, int level)
{
    uint64_t *table = MiPhysicalToVirtual(tablePhysical);
    if (level > 1)
    {
        for (int index = 0; index < 512; index++)
        {
            if (table[index] & PTE_PRESENT)
            {
                ASSERT((table[index] & PTE_LARGE) == 0); /* user maps are 4 KiB only */
                MipFreeTableTree(table[index] & PTE_ADDRESS, level - 1);
            }
        }
    }
    else
    {
        /* Leaf table: the process's own frames must already be unmapped by
         * mm/virtual.c teardown; a survivor is a leaked-frame bug. */
        for (int index = 0; index < 512; index++)
        {
            ASSERT(table[index] == 0);
        }
    }
    MiFreePage(tablePhysical);
}

void MiDeleteUserPml4(uint64_t pml4Physical)
{
    ASSERT(pml4Physical != MiKernelPml4);
    uint64_t *table = MiPhysicalToVirtual(pml4Physical);
    for (int index = 0; index < 256; index++) /* user half only */
    {
        if (table[index] & PTE_PRESENT)
        {
            MipFreeTableTree(table[index] & PTE_ADDRESS, 3);
        }
    }
    MiFreePage(pml4Physical);
}

/* CUI-9 hazard H (docs/17 §6H): every PTE rewrite below already ends in a
 * local invlpg (uniprocessor — no shootdown), and because "the code looks
 * done once the PTE is rewritten" is exactly how the flush gets dropped,
 * the count is exported and kmt asserts it moves across a COW resolve.
 * QEMU's softmmu can forgive a missing flush that real hardware will not,
 * so the counter — not a green boot — is the evidence. */
uint64_t MiInvlpgCount;

void MiMapUserPage(uint64_t pml4Physical, uint64_t virtualAddress, uint64_t physicalAddress,
                   int present, int writable, int executable)
{
    ASSERT((virtualAddress & (PAGE_SIZE - 1)) == 0);
    ASSERT((physicalAddress & (PAGE_SIZE - 1)) == 0);
    ASSERT(virtualAddress < (1ULL << 47)); /* canonical user half */

    uint64_t tableFlags = PTE_PRESENT | PTE_WRITE | PTE_USER;
    uint64_t pdpt = MiEnsureTable(MiTableEntry(pml4Physical, (int)((virtualAddress >> 39) & 0x1FF)),
                                  tableFlags);
    uint64_t pd =
        MiEnsureTable(MiTableEntry(pdpt, (int)((virtualAddress >> 30) & 0x1FF)), tableFlags);
    uint64_t pt =
        MiEnsureTable(MiTableEntry(pd, (int)((virtualAddress >> 21) & 0x1FF)), tableFlags);
    uint64_t *pte = MiTableEntry(pt, (int)((virtualAddress >> 12) & 0x1FF));
    if (*pte != 0)
    {
        KiPanic("MiMapUserPage: user address already mapped");
    }
    /* A not-present mapping (PAGE_NOACCESS commit) keeps the frame address in
     * the PTE — hardware ignores every bit while P is clear — so teardown and
     * queries can still find the committed frame. */
    uint64_t entry = physicalAddress | PTE_USER;
    if (present)
    {
        entry |= PTE_PRESENT;
    }
    if (writable)
    {
        entry |= PTE_WRITE;
    }
    if (!executable)
    {
        entry |= PTE_NX;
    }
    *pte = entry;
    MiInvlpgCount++;
    __asm__ volatile("invlpg (%0)" : : "r"(virtualAddress) : "memory");
}

/* Return the live PTE slot for a user address, or 0 when a level is absent. */
static uint64_t *MipFindUserEntry(uint64_t pml4Physical, uint64_t virtualAddress)
{
    uint64_t *entry = MiTableEntry(pml4Physical, (int)((virtualAddress >> 39) & 0x1FF));
    if (!(*entry & PTE_PRESENT))
    {
        return 0;
    }
    entry = MiTableEntry(*entry & PTE_ADDRESS, (int)((virtualAddress >> 30) & 0x1FF));
    if (!(*entry & PTE_PRESENT))
    {
        return 0;
    }
    entry = MiTableEntry(*entry & PTE_ADDRESS, (int)((virtualAddress >> 21) & 0x1FF));
    if (!(*entry & PTE_PRESENT))
    {
        return 0;
    }
    return MiTableEntry(*entry & PTE_ADDRESS, (int)((virtualAddress >> 12) & 0x1FF));
}

void MiUnmapUserPage(uint64_t pml4Physical, uint64_t virtualAddress)
{
    uint64_t *pte = MipFindUserEntry(pml4Physical, virtualAddress);
    if (pte == 0 || *pte == 0)
    {
        KiPanic("MiUnmapUserPage: user address not mapped");
    }
    *pte = 0;
    MiInvlpgCount++;
    __asm__ volatile("invlpg (%0)" : : "r"(virtualAddress) : "memory");
}

uint64_t MiTranslateUserPage(uint64_t pml4Physical, uint64_t virtualAddress, int *writable,
                             int *present)
{
    uint64_t *pte = MipFindUserEntry(pml4Physical, virtualAddress);
    if (pte == 0 || *pte == 0)
    {
        return 0;
    }
    if (writable != 0)
    {
        *writable = (*pte & PTE_WRITE) != 0;
    }
    if (present != 0)
    {
        *present = (*pte & PTE_PRESENT) != 0;
    }
    return *pte & PTE_ADDRESS;
}

int MiTestVirtualMemory(void)
{
    /* A probe address in an otherwise-unused canonical higher-half region. */
    const uint64_t probe = 0xFFFFC00000000000ULL;

    uint64_t frame = MiAllocatePage();
    if (frame == 0)
    {
        return 0;
    }
    MiMapPage(probe, frame, 1);
    if (MiVirtualToPhysical(probe) != frame)
    {
        return 0;
    }

    /* The same frame through both views: probe mapping and the HHDM. The
     * fixed-address store is the point of the test (NOLINT). */
    volatile uint64_t *viaProbe = (volatile uint64_t *)probe;
    volatile uint64_t *viaHhdm = MiPhysicalToVirtual(frame);
    viaProbe[0] = 0x4D3220505245464CULL; /* NOLINT(clang-analyzer-core.FixedAddressDereference) */
    if (viaHhdm[0] != 0x4D3220505245464CULL)
    {
        return 0;
    }
    viaHhdm[511] = 0x1122334455667788ULL;
    if (viaProbe[511] != 0x1122334455667788ULL)
    {
        return 0;
    }

    MiUnmapPage(probe);
    if (MiVirtualToPhysical(probe) != 0)
    {
        return 0;
    }
    MiFreePage(frame);
    return 1;
}
