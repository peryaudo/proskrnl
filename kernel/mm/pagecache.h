/* kernel/mm/pagecache.h — the unified page cache (M5 seed, M6 general form;
 * docs/04 mm/pagecache.c, docs/05 "page cache = (file, offset) -> physical
 * page, never evicted, writeback immediate").
 *
 * One MI_PAGE_CACHE holds a file stream's resident pages: an array of
 * physical frames covering [0, fileSize) rounded up to pages. Everything
 * that touches file bytes — NtReadFile/NtWriteFile (M6 Io), mapped data
 * views (mm/section.c), the RAM-disk (init/initrd.c) — goes through the
 * same frames, so mapped-view/read-write coherence is structural (Art. 3:
 * no eviction, the cache never shrinks; frames past a truncated EOF are
 * kept and re-zeroed so a later extension reads zeroes).
 *
 * Writeback is the owner's job (the FAT32 FCB writes dirtied ranges through
 * to disk immediately; the RAM-disk is read-only) — the cache itself is
 * pure memory.
 */
#ifndef PROSKRNL_KERNEL_MM_PAGECACHE_H
#define PROSKRNL_KERNEL_MM_PAGECACHE_H

#include <stdint.h>

#include "abi/ntdef.h"
#include "kernel/syscall/uaccess.h"

typedef struct MI_PAGE_CACHE
{
    uint64_t fileSize; /* logical stream size in bytes */
    ULONG pageCount;   /* frames held = pages covering max fileSize ever seen */
    ULONG capacity;    /* slots allocated in frames[] */
    uint64_t *frames;  /* physical frame per page; all present (no holes) */
} MI_PAGE_CACHE, *PMI_PAGE_CACHE;

void MiInitializePageCache(PMI_PAGE_CACHE cache);
/* Free every frame and the array; the cache returns to the empty state. */
void MiDeletePageCache(PMI_PAGE_CACHE cache);

/* Set the stream size. Growing allocates zeroed frames for the new pages;
 * shrinking keeps the frames but zeroes [newSize, old covered end) so a
 * later extension observes NT's zero-fill rule through views and reads. */
NTSTATUS MiResizePageCache(PMI_PAGE_CACHE cache, uint64_t newFileSize);

/* Copy in/out of the cached pages. The caller bounds-checks against
 * fileSize; offset+length must lie within the covered pages. */
/* The bulk data path in and out of the cache. `token` is the probe backing
 * `buffer` (issue #96 C): these run after the fill/placement parks, so the
 * entry probe is stale and the token is what proves a fresh one was taken.
 * A kernel-owned buffer passes KiKernelToken, which names the opt-out. */
void MiCacheRead(const MI_PAGE_CACHE *cache, uint64_t offset, const KI_PROBE_TOKEN *token,
                 void *buffer, uint64_t length);
void MiCacheWrite(PMI_PAGE_CACHE cache, uint64_t offset, const KI_PROBE_TOKEN *token,
                  const void *buffer, uint64_t length);

#endif /* PROSKRNL_KERNEL_MM_PAGECACHE_H */
