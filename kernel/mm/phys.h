/* kernel/mm/phys.h — physical page frame allocator (M1).
 *
 * The floor of Mm: hand out and reclaim 4 KiB physical frames. A free-frame
 * stack (Article 3: the simplest correct thing) — no buddy, no zones. Pages are
 * returned as physical addresses; callers reach their contents via the HHDM.
 */
#ifndef PROSKRNL_KERNEL_MM_PHYS_H
#define PROSKRNL_KERNEL_MM_PHYS_H

#include <stdint.h>

#define PAGE_SIZE 4096

struct limine_memmap_response; /* forward */

/* Seed the allocator from Limine's memory map; hhdm_offset maps phys->virt. */
void phys_init(uint64_t hhdm_offset, struct limine_memmap_response *mm);

/* Allocate / free one physical frame. phys_alloc returns 0 when out of memory. */
uint64_t phys_alloc(void);
void     phys_free(uint64_t page);

uint64_t phys_free_count(void);
uint64_t phys_total_count(void);

/* In-kernel self-test (kmt-style): alloc, write/read a pattern via HHDM, free,
 * check LIFO reuse and the free count. Returns 1 on pass. */
int phys_selftest(void);

#endif /* PROSKRNL_KERNEL_MM_PHYS_H */
