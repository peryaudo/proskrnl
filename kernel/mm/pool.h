/* kernel/mm/pool.h — the kernel pool (M2).
 *
 * ONE pool (Constitution Art. 3: no Paged/NonPaged split — nothing is ever
 * paged out). A first-fit free list over a brk-style kernel heap: the heap
 * grows by mapping fresh physical frames at MI_POOL_BASE via MiMapPage, so
 * allocations larger than a page are virtually contiguous. Internal (`Mi`)
 * because NT's ExAllocatePool* carry different signatures/contracts (docs/15).
 */
#ifndef PROSKRNL_KERNEL_MM_POOL_H
#define PROSKRNL_KERNEL_MM_POOL_H

#include <stdint.h>

void MiInitializePool(void);

/* Allocate / free pool memory. 16-byte aligned; returns 0 when out of memory.
 * MiAllocatePool zeroes the block (callers are kernel structures; a stale
 * DISPATCHER_HEADER is exactly the silent-corruption bug we refuse to chase). */
void *MiAllocatePool(uint64_t numberOfBytes);
void MiFreePool(void *pointer);

/* Bytes currently handed out; the M2 test checks alloc/free balance. */
uint64_t MiGetPoolBytesInUse(void);

/* In-kernel self-test (M1 style). Returns 1 on pass. */
int MiTestPool(void);

#endif /* PROSKRNL_KERNEL_MM_POOL_H */
