/* kernel/mm/pagecache.c — the unified page cache (see pagecache.h). */
#include "kernel/mm/pagecache.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "abi/ntstatus.h"

void MiInitializePageCache(PMI_PAGE_CACHE cache)
{
    cache->fileSize = 0;
    cache->pageCount = 0;
    cache->capacity = 0;
    cache->frames = 0;
}

void MiDeletePageCache(PMI_PAGE_CACHE cache)
{
    for (ULONG i = 0; i < cache->pageCount; i++)
    {
        MiFreePage(cache->frames[i]);
    }
    if (cache->frames != 0)
    {
        MiFreePool(cache->frames);
    }
    MiInitializePageCache(cache);
}

NTSTATUS MiResizePageCache(PMI_PAGE_CACHE cache, uint64_t newFileSize)
{
    ULONG newPages = (ULONG)((newFileSize + PAGE_SIZE - 1) / PAGE_SIZE);

    if (newPages > cache->capacity)
    {
        /* Grow the slot array (doubling keeps section/view users' pointer to
         * the CACHE stable — only this internal array moves). */
        ULONG newCapacity = cache->capacity != 0 ? cache->capacity : 8;
        while (newCapacity < newPages)
        {
            newCapacity *= 2;
        }
        uint64_t *grown = MiAllocatePool((uint64_t)newCapacity * sizeof(uint64_t));
        if (grown == 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (cache->pageCount != 0)
        {
            memcpy(grown, cache->frames, cache->pageCount * sizeof(uint64_t));
        }
        if (cache->frames != 0)
        {
            MiFreePool(cache->frames);
        }
        cache->frames = grown;
        cache->capacity = newCapacity;
    }

    for (ULONG i = cache->pageCount; i < newPages; i++)
    {
        uint64_t frame = MiAllocatePage();
        if (frame == 0)
        {
            /* Keep what we have consistent; the caller sees the failure. */
            cache->pageCount = i;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memset(MiPhysicalToVirtual(frame), 0, PAGE_SIZE);
        cache->frames[i] = frame;
    }
    if (newPages > cache->pageCount)
    {
        cache->pageCount = newPages;
    }

    if (newFileSize < cache->fileSize)
    {
        /* Truncation: the frames stay (no eviction), but the cut-off bytes
         * must read as zero if the file is later extended — through a mapped
         * view as well as through NtReadFile, so scrub the cache itself. */
        uint64_t coveredEnd = (uint64_t)cache->pageCount * PAGE_SIZE;
        for (uint64_t position = newFileSize; position < coveredEnd;)
        {
            uint64_t pageOffset = position & (PAGE_SIZE - 1);
            uint64_t chunk = PAGE_SIZE - pageOffset;
            char *page = MiPhysicalToVirtual(cache->frames[position / PAGE_SIZE]);
            memset(page + pageOffset, 0, chunk);
            position += chunk;
        }
    }

    cache->fileSize = newFileSize;
    return STATUS_SUCCESS;
}

void MiCacheRead(const MI_PAGE_CACHE *cache, uint64_t offset, void *buffer, uint64_t length)
{
    ASSERT(offset + length <= (uint64_t)cache->pageCount * PAGE_SIZE);
    uint64_t copied = 0;
    while (copied < length)
    {
        uint64_t position = offset + copied;
        uint64_t pageOffset = position & (PAGE_SIZE - 1);
        uint64_t chunk = PAGE_SIZE - pageOffset;
        if (chunk > length - copied)
        {
            chunk = length - copied;
        }
        const char *page = MiPhysicalToVirtual(cache->frames[position / PAGE_SIZE]);
        memcpy((char *)buffer + copied, page + pageOffset, chunk);
        copied += chunk;
    }
}

void MiCacheWrite(PMI_PAGE_CACHE cache, uint64_t offset, const void *buffer, uint64_t length)
{
    ASSERT(offset + length <= (uint64_t)cache->pageCount * PAGE_SIZE);
    uint64_t copied = 0;
    while (copied < length)
    {
        uint64_t position = offset + copied;
        uint64_t pageOffset = position & (PAGE_SIZE - 1);
        uint64_t chunk = PAGE_SIZE - pageOffset;
        if (chunk > length - copied)
        {
            chunk = length - copied;
        }
        char *page = MiPhysicalToVirtual(cache->frames[position / PAGE_SIZE]);
        memcpy(page + pageOffset, (const char *)buffer + copied, chunk);
        copied += chunk;
    }
}
