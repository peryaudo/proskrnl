/* arch/x86_64/mmu.c — kernel page-table management (M2). See mmu.h.
 *
 * Four-level x86-64 paging, no PCID, no global pages games: the simplest
 * correct thing (Art. 3). The kernel image is mapped with 4 KiB pages from the
 * Limine-reported physical base; all of physical memory is re-mapped at the
 * HHDM offset with 2 MiB pages (RW + NX). Page-table frames come from
 * MiAllocatePage and are reached through the HHDM.
 */
#include "arch/x86_64/mmu.h"
#include "arch/x86_64/io.h"
#include "kernel/mm/phys.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "limine.h"

#define PTE_PRESENT (1ULL << 0)
#define PTE_WRITE   (1ULL << 1)
#define PTE_LARGE   (1ULL << 7) /* PS: 2 MiB page in a PDE */
#define PTE_NX      (1ULL << 63)
#define PTE_ADDRESS 0x000FFFFFFFFFF000ULL

#define LARGE_PAGE_SIZE (2ULL * 1024 * 1024)

#define IA32_EFER     0xC0000080
#define IA32_EFER_NXE (1ULL << 11)

static uint64_t MiKernelPml4; /* physical address of the kernel PML4 */

static uint64_t *MiTableEntry(uint64_t tablePhysical, int index)
{
    return (uint64_t *)MiPhysicalToVirtual(tablePhysical) + index;
}

/* Get the page table one level down from *entry, allocating it if absent.
 * Returns the physical address of the lower table. */
static uint64_t MiEnsureTable(uint64_t *entry)
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
    /* Intermediate entries stay maximally permissive; the leaf decides. */
    *entry = table | PTE_PRESENT | PTE_WRITE;
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

    uint64_t pdpt = MiEnsureTable(MiTableEntry(MiKernelPml4, pml4Index));
    uint64_t pd = MiEnsureTable(MiTableEntry(pdpt, pdptIndex));
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

    uint64_t pt = MiEnsureTable(pde);
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
