/* kernel/mm/kasan.h — minimal KASAN: pool shadow + poisoning (M3).
 *
 * The docs/08 sanitizer: ~a shadow byte per 8 pool bytes, __asan_* outline
 * hooks, and pool redzones. Scope is deliberately the POOL ONLY — handle
 * tables and object refcounts (the LLM's favourite bug site, docs/05) live
 * there, and a range check in the hook keeps every non-pool access free.
 * All kernel C is compiled with -fsanitize=kernel-address in outline mode
 * (Makefile) except pool.c and kasan.c themselves, which manage the
 * poisoning and may legally touch red zones.
 *
 * Art. 6 note: a KASAN report NAMES A SUSPECT; only a differential test
 * convicts. And per docs/08, "KASAN went quiet" is never a fix.
 */
#ifndef PROSKRNL_KERNEL_MM_KASAN_H
#define PROSKRNL_KERNEL_MM_KASAN_H

#include <stdint.h>

/* Wire-up called by pool.c. */
void MiKasanInitialize(void);
/* Ensure shadow exists for the pool up to `poolEnd` (called on heap growth);
 * new shadow starts poisoned as free memory. */
void MiKasanCoverPool(uint64_t poolEnd);
/* An allocation: `data` valid for `requestedBytes`; the block's header and
 * the tail up to `blockBytes` (total block size incl. header) are red zone. */
void MiKasanMarkAllocated(void *data, uint64_t requestedBytes, uint64_t blockBytes);
/* A free: the whole block (header included) becomes poisoned. */
void MiKasanMarkFreed(void *block, uint64_t blockBytes);

/* Explicit range check for the uninstrumented mem* intrinsics (string.c);
 * no-op for addresses outside the pool. */
void MiKasanCheckRange(void *address, uint64_t size, int isWrite, void *caller);

/* Test hook (tests/kmt): while `counter` is non-null a report increments it
 * instead of panicking. Pass 0 to restore fatal reports. */
void MiKasanSetReportCounter(int *counter);

#endif /* PROSKRNL_KERNEL_MM_KASAN_H */
