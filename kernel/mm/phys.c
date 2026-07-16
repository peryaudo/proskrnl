/* kernel/mm/phys.c — physical page frame allocator (M1). See phys.h. */
#include "kernel/mm/phys.h"
#include "limine.h"

static uint64_t MiHhdmOffset;   /* phys -> virt offset (HHDM) */
static uint64_t MiFreeListHead; /* phys addr of top free frame; 0 == empty */
static uint64_t MiFreePageCount;
static uint64_t MiTotalPageCount;

static inline uint64_t *MiFrameToVirtual(uint64_t physical)
{
    return (uint64_t *)(uintptr_t)(MiHhdmOffset + physical);
}

void *MiPhysicalToVirtual(uint64_t physical)
{
    return (void *)(uintptr_t)(MiHhdmOffset + physical);
}

void MiFreePage(uint64_t page)
{
    /* Thread the free list through the frames themselves: store the old head
     * in this frame, then make this frame the new head. */
    *MiFrameToVirtual(page) = MiFreeListHead;
    MiFreeListHead = page;
    MiFreePageCount++;
}

uint64_t MiAllocatePage(void)
{
    if (MiFreeListHead == 0)
    {
        return 0;
    }
    uint64_t page = MiFreeListHead;
    MiFreeListHead = *MiFrameToVirtual(page);
    MiFreePageCount--;
    return page;
}

uint64_t MiGetFreePageCount(void)
{
    return MiFreePageCount;
}
uint64_t MiGetTotalPageCount(void)
{
    return MiTotalPageCount;
}

void MiInitializePhysicalMemory(uint64_t hhdmOffset, struct limine_memmap_response *memoryMap)
{
    MiHhdmOffset = hhdmOffset;
    MiFreeListHead = 0;
    MiFreePageCount = 0;
    MiTotalPageCount = 0;

    for (uint64_t i = 0; i < memoryMap->entry_count; i++)
    {
        struct limine_memmap_entry *entry = memoryMap->entries[i];
        if (entry->type != LIMINE_MEMMAP_USABLE)
        {
            continue;
        }
        uint64_t base = (entry->base + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
        uint64_t end = (entry->base + entry->length) & ~(uint64_t)(PAGE_SIZE - 1);
        for (uint64_t page = base; page + PAGE_SIZE <= end; page += PAGE_SIZE)
        {
            /* Skip the NULL frame so MiAllocatePage()==0 unambiguously means OOM. */
            if (page == 0)
            {
                continue;
            }
            MiFreePage(page);
            MiTotalPageCount++;
        }
    }
}

int MiTestPhysicalAllocator(void)
{
    uint64_t before = MiFreePageCount;

    uint64_t a = MiAllocatePage();
    uint64_t b = MiAllocatePage();
    if (a == 0 || b == 0 || a == b)
    {
        return 0;
    }

    /* Read/write the frame through the HHDM. */
    volatile uint64_t *mapped = MiFrameToVirtual(a);
    mapped[0] = 0xDEADBEEFCAFEBABEULL;
    mapped[511] = 0x0123456789ABCDEFULL;
    if (mapped[0] != 0xDEADBEEFCAFEBABEULL || mapped[511] != 0x0123456789ABCDEFULL)
    {
        return 0;
    }

    /* LIFO reuse: free a then b; the next alloc must return b. */
    MiFreePage(a);
    MiFreePage(b);
    uint64_t c = MiAllocatePage();
    if (c != b)
    {
        return 0;
    }
    MiFreePage(c);

    return MiFreePageCount == before;
}
