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

/* Seed the allocator from Limine's memory map; hhdmOffset maps phys->virt. */
void MiInitializePhysicalMemory(uint64_t hhdmOffset, struct limine_memmap_response *memoryMap);

/* Allocate / free one physical frame. MiAllocatePage returns 0 when OOM. */
uint64_t MiAllocatePage(void);
void MiFreePage(uint64_t page);

/* Reach a physical frame's contents through the higher-half direct map. */
void *MiPhysicalToVirtual(uint64_t physical);

uint64_t MiGetFreePageCount(void);
uint64_t MiGetTotalPageCount(void);

/* In-kernel self-test (kmt-style): alloc, write/read a pattern via HHDM, free,
 * check LIFO reuse and the free count. Returns 1 on pass. */
int MiTestPhysicalAllocator(void);

#endif /* PROSKRNL_KERNEL_MM_PHYS_H */
