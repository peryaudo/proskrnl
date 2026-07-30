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

/* As MiMapPage(writable), but strongly uncacheable — for register windows
 * whose reads and writes are side effects, not memory. Unmap with
 * MiUnmapPage. */
void MiMapDevicePage(uint64_t virtualAddress, uint64_t physicalAddress);

/* Walk the kernel page tables. Returns 0 when the address is unmapped. */
uint64_t MiVirtualToPhysical(uint64_t virtualAddress);

/* In-kernel self-test (M1 style): map a frame at a probe address, check both
 * views agree, unmap, check the translation is gone. Returns 1 on pass. */
int MiTestVirtualMemory(void);

/* --- per-process address spaces (M4) -------------------------------------- */

/* The kernel PML4, for address spaces that ARE the kernel (the system
 * process) and for CR3 comparisons at context switch. */
uint64_t MiGetKernelPml4(void);

/* A process PML4: the kernel half is shared by copying the boot-time upper
 * 256 PML4 entries. That copy is only sound if the kernel half never grows a
 * NEW PML4 slot afterwards — MiFreezeKernelPml4 (called before the first
 * process exists) turns any such growth into a panic. */
void MiFreezeKernelPml4(void);
uint64_t MiCreateUserPml4(void);
/* Free every user-half page-table frame plus the PML4 itself. Leaf frames
 * (the process's memory) must already be gone — mm/virtual.c owns those. */
void MiDeleteUserPml4(uint64_t pml4Physical);

/* Map / unmap / translate one user 4 KiB page in a process PML4. writable /
 * executable pick the PTE bits; a PAGE_NOACCESS-style commit maps the frame
 * with the present bit clear (the frame stays retrievable for teardown).
 * MiTranslateUserPage returns the frame (even for a not-present commit) or
 * 0 when nothing is mapped; *writable reports the write bit when non-0. */
void MiMapUserPage(uint64_t pml4Physical, uint64_t virtualAddress, uint64_t physicalAddress,
                   int present, int writable, int executable);
void MiUnmapUserPage(uint64_t pml4Physical, uint64_t virtualAddress);
uint64_t MiTranslateUserPage(uint64_t pml4Physical, uint64_t virtualAddress, int *writable,
                             int *present);

#endif /* PROSKRNL_ARCH_X86_64_MMU_H */
