/* kernel/mm/pool.c — the single kernel pool (M2). See pool.h.
 *
 * Layout: every block (free or allocated) carries a 16-byte header holding its
 * total size and a magic tag. Free blocks are additionally threaded on an
 * address-ordered singly-linked free list, so freeing coalesces neighbours in
 * one pass. The heap is a contiguous virtual range starting at MI_POOL_BASE;
 * when first-fit finds nothing, the heap end grows page by page.
 */
#include "kernel/mm/pool.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/kasan.h"
#include "arch/x86_64/mmu.h"
#include "kernel/lib/string.h"
#include "kernel/ke/ke.h"
#include "kernel/init/panic.h"

#include <stddef.h>

#define MI_POOL_ALLOCATED_MAGIC 0x504F4F4C41ULL /* "POOLA" */
#define MI_POOL_FREE_MAGIC      0x504F4F4C46ULL /* "POOLF" */

#define MI_POOL_ALIGN 16
/* An allocated block's header is size+magic (16 bytes = MI_POOL_ALIGN); the
 * nextFree link overlays the body while the block sits on the free list. */
#define MI_POOL_MIN_SPLIT (MI_POOL_ALIGN + MI_POOL_ALIGN)

typedef struct MI_POOL_HEADER
{
    uint64_t size; /* total bytes including this header */
    uint64_t magic;
    /* free blocks only; the field lives in the (unused) block body */
    struct MI_POOL_HEADER *nextFree;
} MI_POOL_HEADER, *PMI_POOL_HEADER;

_Static_assert(offsetof(MI_POOL_HEADER, nextFree) == MI_POOL_ALIGN,
               "user data must start 16-byte aligned after the header");

static PMI_POOL_HEADER MiPoolFreeList;    /* address-ordered */
static uint64_t MiPoolEnd = MI_POOL_BASE; /* first unmapped heap byte */
static uint64_t MiPoolBytesInUse;

void MiInitializePool(void)
{
    MiPoolFreeList = 0;
    MiPoolEnd = MI_POOL_BASE;
    MiPoolBytesInUse = 0;
    MiKasanInitialize();
}

uint64_t MiGetPoolBytesInUse(void)
{
    return MiPoolBytesInUse;
}

/* Insert a free block keeping address order, then coalesce with both sides. */
static void MiInsertFreeBlock(PMI_POOL_HEADER block)
{
    ASSERT(block->size >= MI_POOL_MIN_SPLIT && (block->size & (MI_POOL_ALIGN - 1)) == 0);
    ASSERT((uint64_t)(uintptr_t)block >= MI_POOL_BASE &&
           (uint64_t)(uintptr_t)block + block->size <= MiPoolEnd);
    block->magic = MI_POOL_FREE_MAGIC;

    PMI_POOL_HEADER *link = &MiPoolFreeList;
    while (*link != 0 && *link < block)
    {
        link = &(*link)->nextFree;
    }
    block->nextFree = *link;
    *link = block;

    /* Coalesce forward first (so the backward merge sees the merged size). */
    PMI_POOL_HEADER next = block->nextFree;
    if (next != 0 && (char *)block + block->size == (char *)next)
    {
        block->size += next->size;
        block->nextFree = next->nextFree;
        next->magic = 0;
    }
    if (link != &MiPoolFreeList)
    {
        /* link points at the previous block's embedded nextFree field; step
         * back to its header (container-of — confuses the array-bound
         * analyzer, hence the NOLINT). */
        PMI_POOL_HEADER previous =
            (PMI_POOL_HEADER)((char *)link - offsetof(MI_POOL_HEADER, nextFree));
        /* NOLINTNEXTLINE(clang-analyzer-security.ArrayBound) */
        if ((char *)previous + previous->size == (char *)block)
        {
            previous->size += block->size;
            previous->nextFree = block->nextFree;
            block->magic = 0;
        }
    }
}

/* Grow the heap by whole pages and hand the new range to the free list. */
static int MiExpandPool(uint64_t bytesNeeded)
{
    uint64_t pages = (bytesNeeded + PAGE_SIZE - 1) / PAGE_SIZE;
    PMI_POOL_HEADER block = (PMI_POOL_HEADER)(uintptr_t)MiPoolEnd;
    uint64_t mapped = 0;
    for (; mapped < pages; mapped++)
    {
        uint64_t frame = MiAllocatePage();
        if (frame == 0)
        {
            break;
        }
        MiMapPage(MiPoolEnd, frame, 1);
        MiPoolEnd += PAGE_SIZE;
        MiKasanCoverPool(MiPoolEnd); /* new heap starts shadow-poisoned */
    }
    if (mapped == 0)
    {
        return 0;
    }
    /* A PARTIAL expansion still hands what it got to the free list. The old
     * code returned early on the first failed page, so MiPoolEnd had already
     * advanced past frames that were never inserted anywhere: permanently
     * unreachable, and unreachable in a way that compounds -- a large
     * MEM_RESERVE costs size/1024 bytes of pool per VAD, so a caller can
     * drain physical memory this way (docs/review-2026-07 §7). The block is
     * still short of what was asked for, so this returns failure when it is
     * -- the caller retries or fails, but the frames are accounted for
     * either way. */
    block->size = mapped * PAGE_SIZE;
    MiInsertFreeBlock(block);
    return mapped == pages;
}

void *MiAllocatePool(uint64_t numberOfBytes)
{
    ASSERT(!KiInCompletionDrain); /* docs/20 R2: no allocator traffic in the drain */
    if (numberOfBytes == 0)
    {
        KiPanic("MiAllocatePool: zero-byte allocation");
    }
    uint64_t needed =
        MI_POOL_ALIGN + ((numberOfBytes + MI_POOL_ALIGN - 1) & ~(uint64_t)(MI_POOL_ALIGN - 1));
    /* Keep every block big enough to become a free-list node again. */
    if (needed < MI_POOL_MIN_SPLIT)
    {
        needed = MI_POOL_MIN_SPLIT;
    }

    for (int attempt = 0; attempt < 2; attempt++)
    {
        PMI_POOL_HEADER *link = &MiPoolFreeList;
        while (*link != 0)
        {
            PMI_POOL_HEADER block = *link;
            if (block->magic != MI_POOL_FREE_MAGIC)
            {
                KiPanic("MiAllocatePool: corrupt free list");
            }
            if (block->size >= needed)
            {
                if (block->size - needed >= MI_POOL_MIN_SPLIT)
                {
                    PMI_POOL_HEADER rest = (PMI_POOL_HEADER)((char *)block + needed);
                    rest->size = block->size - needed;
                    rest->magic = MI_POOL_FREE_MAGIC;
                    rest->nextFree = block->nextFree;
                    *link = rest;
                    block->size = needed;
                }
                else
                {
                    *link = block->nextFree;
                }
                block->magic = MI_POOL_ALLOCATED_MAGIC;
                MiPoolBytesInUse += block->size;
                void *data = (char *)block + MI_POOL_ALIGN;
                /* Unpoison before zeroing — memset checks its ranges — and
                 * zero only the caller-visible bytes: the red-zone tail is
                 * unreachable for instrumented code either way. */
                MiKasanMarkAllocated(data, numberOfBytes, block->size);
                memset(data, 0, numberOfBytes);
                return data;
            }
            link = &block->nextFree;
        }
        if (!MiExpandPool(needed))
        {
            return 0;
        }
    }
    return 0;
}

void MiFreePool(void *pointer)
{
    ASSERT(!KiInCompletionDrain); /* docs/20 R2: no allocator traffic in the drain */
    if (pointer == 0)
    {
        KiPanic("MiFreePool: NULL pointer");
    }
    PMI_POOL_HEADER block = (PMI_POOL_HEADER)((char *)pointer - MI_POOL_ALIGN);
    if (block->magic != MI_POOL_ALLOCATED_MAGIC)
    {
        KiPanic("MiFreePool: bad block (double free or corruption)");
    }
    ASSERT(MiPoolBytesInUse >= block->size);
    MiPoolBytesInUse -= block->size;
    MiKasanMarkFreed(block, block->size);
    MiInsertFreeBlock(block);
}

int MiTestPool(void)
{
    uint64_t before = MiPoolBytesInUse;

    /* Small allocations: distinct, aligned, zeroed, patterned independently. */
    unsigned char *a = MiAllocatePool(24);
    unsigned char *b = MiAllocatePool(200);
    unsigned char *c = MiAllocatePool(24);
    if (a == 0 || b == 0 || c == 0)
    {
        return 0;
    }
    if (((uintptr_t)a | (uintptr_t)b | (uintptr_t)c) & (MI_POOL_ALIGN - 1))
    {
        return 0;
    }
    for (int i = 0; i < 24; i++)
    {
        if (a[i] != 0)
        {
            return 0;
        }
        a[i] = 0xAA;
        c[i] = 0xCC;
    }
    memset(b, 0xBB, 200);
    if (a[10] != 0xAA || b[100] != 0xBB || c[10] != 0xCC)
    {
        return 0;
    }

    /* A multi-page allocation must be virtually contiguous and writable. */
    unsigned char *big = MiAllocatePool(3 * PAGE_SIZE + 100);
    if (big == 0)
    {
        return 0;
    }
    memset(big, 0x5A, 3 * PAGE_SIZE + 100);
    if (big[0] != 0x5A || big[3 * PAGE_SIZE + 99] != 0x5A)
    {
        return 0;
    }

    /* Free middle then neighbours: coalescing must let the trio re-emerge as
     * one block able to serve a request none of the pieces could alone. */
    MiFreePool(b);
    MiFreePool(a);
    MiFreePool(c);
    MiFreePool(big);

    void *wide = MiAllocatePool(200 + 24 + 24);
    if (wide == 0)
    {
        return 0;
    }
    MiFreePool(wide);

    return MiPoolBytesInUse == before;
}
