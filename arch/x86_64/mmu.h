/* arch/x86_64/mmu.h — kernel page-table management (M2).
 *
 * Builds the kernel's own address space (PML4) — the kernel image plus the
 * higher-half direct map — and switches CR3 off the bootloader's tables. Then
 * provides single-page map/unmap/translate for everything above (the pool, and
 * later M4/M5 user address spaces). `Mi` because this is the page-table floor
 * of Mm, even though the code is arch-specific (docs/04, docs/15).
 */
#ifndef PROSKRNL_ARCH_X86_64_MMU_H
#define PROSKRNL_ARCH_X86_64_MMU_H

#include <stdint.h>

struct limine_memmap_response; /* forward */

/* Build the kernel PML4 (image RWX by section flags' simplest reading, HHDM
 * RW+NX) and load it into CR3. Needs the physical allocator up first. */
void MiInitializeVirtualMemory(uint64_t kernelPhysicalBase, uint64_t kernelVirtualBase,
                               struct limine_memmap_response *memoryMap);

/* Map / unmap one 4 KiB kernel page in the kernel PML4. Intermediate tables
 * are allocated on demand; mapping over an existing mapping panics. */
void MiMapPage(uint64_t virtualAddress, uint64_t physicalAddress, int writable);
void MiUnmapPage(uint64_t virtualAddress);

/* Walk the kernel page tables. Returns 0 when the address is unmapped. */
uint64_t MiVirtualToPhysical(uint64_t virtualAddress);

/* In-kernel self-test (M1 style): map a frame at a probe address, check both
 * views agree, unmap, check the translation is gone. Returns 1 on pass. */
int MiTestVirtualMemory(void);

#endif /* PROSKRNL_ARCH_X86_64_MMU_H */
