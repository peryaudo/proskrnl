/* kernel/mm/phys.c — physical page frame allocator (M1). See phys.h. */
#include "kernel/mm/phys.h"
#include "limine.h"

static uint64_t hhdm;              /* phys -> virt offset (HHDM) */
static uint64_t free_head;         /* phys addr of top free frame; 0 == empty */
static uint64_t free_frames;
static uint64_t total_frames;

static inline uint64_t *frame_ptr(uint64_t phys)
{
    return (uint64_t *)(uintptr_t)(hhdm + phys);
}

void phys_free(uint64_t page)
{
    /* Thread the free list through the frames themselves: store the old head
     * in this frame, then make this frame the new head. */
    *frame_ptr(page) = free_head;
    free_head = page;
    free_frames++;
}

uint64_t phys_alloc(void)
{
    if (free_head == 0) {
        return 0;
    }
    uint64_t page = free_head;
    free_head = *frame_ptr(page);
    free_frames--;
    return page;
}

uint64_t phys_free_count(void)  { return free_frames; }
uint64_t phys_total_count(void) { return total_frames; }

void phys_init(uint64_t hhdm_offset, struct limine_memmap_response *mm)
{
    hhdm = hhdm_offset;
    free_head = 0;
    free_frames = 0;
    total_frames = 0;

    for (uint64_t i = 0; i < mm->entry_count; i++) {
        struct limine_memmap_entry *e = mm->entries[i];
        if (e->type != LIMINE_MEMMAP_USABLE) {
            continue;
        }
        uint64_t base = (e->base + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
        uint64_t end  = (e->base + e->length) & ~(uint64_t)(PAGE_SIZE - 1);
        for (uint64_t p = base; p + PAGE_SIZE <= end; p += PAGE_SIZE) {
            /* Skip the NULL frame so phys_alloc()==0 unambiguously means OOM. */
            if (p == 0) {
                continue;
            }
            phys_free(p);
            total_frames++;
        }
    }
}

int phys_selftest(void)
{
    uint64_t before = free_frames;

    uint64_t a = phys_alloc();
    uint64_t b = phys_alloc();
    if (a == 0 || b == 0 || a == b) {
        return 0;
    }

    /* Read/write the frame through the HHDM. */
    volatile uint64_t *va = frame_ptr(a);
    va[0] = 0xDEADBEEFCAFEBABEULL;
    va[511] = 0x0123456789ABCDEFULL;
    if (va[0] != 0xDEADBEEFCAFEBABEULL || va[511] != 0x0123456789ABCDEFULL) {
        return 0;
    }

    /* LIFO reuse: free a then b; the next alloc must return b. */
    phys_free(a);
    phys_free(b);
    uint64_t c = phys_alloc();
    if (c != b) {
        return 0;
    }
    phys_free(c);

    return free_frames == before;
}
