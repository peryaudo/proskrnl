/* kernel/mm/phys.c — physical page frame allocator (M1). See phys.h. */
#include "kernel/mm/phys.h"
#include "limine.h"

static uint64_t MiHhdmOffset;   /* phys -> virt offset (HHDM) */
static uint64_t MiFreeListHead; /* phys addr of top free frame; 0 == empty */
static uint64_t MiFreePageCount;
static uint64_t MiTotalPageCount;

static inline uint64_t *MiFrameToVirtual(uint64_t Physical)
{
    return (uint64_t *)(uintptr_t)(MiHhdmOffset + Physical);
}

void MmFreePage(uint64_t Page)
{
    /* Thread the free list through the frames themselves: store the old head
     * in this frame, then make this frame the new head. */
    *MiFrameToVirtual(Page) = MiFreeListHead;
    MiFreeListHead = Page;
    MiFreePageCount++;
}

uint64_t MmAllocatePage(void)
{
    if (MiFreeListHead == 0)
    {
        return 0;
    }
    uint64_t Page = MiFreeListHead;
    MiFreeListHead = *MiFrameToVirtual(Page);
    MiFreePageCount--;
    return Page;
}

uint64_t MmGetFreePageCount(void)
{
    return MiFreePageCount;
}
uint64_t MmGetTotalPageCount(void)
{
    return MiTotalPageCount;
}

void MmInitializePhysicalMemory(uint64_t HhdmOffset, struct limine_memmap_response *MemoryMap)
{
    MiHhdmOffset = HhdmOffset;
    MiFreeListHead = 0;
    MiFreePageCount = 0;
    MiTotalPageCount = 0;

    for (uint64_t i = 0; i < MemoryMap->entry_count; i++)
    {
        struct limine_memmap_entry *Entry = MemoryMap->entries[i];
        if (Entry->type != LIMINE_MEMMAP_USABLE)
        {
            continue;
        }
        uint64_t Base = (Entry->base + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
        uint64_t End = (Entry->base + Entry->length) & ~(uint64_t)(PAGE_SIZE - 1);
        for (uint64_t Page = Base; Page + PAGE_SIZE <= End; Page += PAGE_SIZE)
        {
            /* Skip the NULL frame so MmAllocatePage()==0 unambiguously means OOM. */
            if (Page == 0)
            {
                continue;
            }
            MmFreePage(Page);
            MiTotalPageCount++;
        }
    }
}

int MiTestPhysicalAllocator(void)
{
    uint64_t Before = MiFreePageCount;

    uint64_t A = MmAllocatePage();
    uint64_t B = MmAllocatePage();
    if (A == 0 || B == 0 || A == B)
    {
        return 0;
    }

    /* Read/write the frame through the HHDM. */
    volatile uint64_t *Virtual = MiFrameToVirtual(A);
    Virtual[0] = 0xDEADBEEFCAFEBABEULL;
    Virtual[511] = 0x0123456789ABCDEFULL;
    if (Virtual[0] != 0xDEADBEEFCAFEBABEULL || Virtual[511] != 0x0123456789ABCDEFULL)
    {
        return 0;
    }

    /* LIFO reuse: free A then B; the next alloc must return B. */
    MmFreePage(A);
    MmFreePage(B);
    uint64_t C = MmAllocatePage();
    if (C != B)
    {
        return 0;
    }
    MmFreePage(C);

    return MiFreePageCount == Before;
}
