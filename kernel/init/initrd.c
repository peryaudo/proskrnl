/* kernel/init/initrd.c — the M5 seed RAM-disk (see initrd.h).
 *
 * A fixed table of named blobs. Registration happens once at boot from
 * KiSystemStartup (before the scheduler), lookups afterwards from thread
 * context; under Art. 3 (uniprocessor, no preemption) no locking is needed.
 */
#include "kernel/init/initrd.h"
#include "kernel/init/panic.h"
#include "abi/ntstatus.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/string.h"

#define KI_RAMDISK_MAX_FILES 16

static KI_RAMDISK_FILE KiRamdiskFiles[KI_RAMDISK_MAX_FILES];
static ULONG KiRamdiskFileCount;

/* No strlen/strcmp in the freestanding lib (string.h carries only the
 * compiler-mandated mem* intrinsics); local equivalents. */
static uint64_t KipStringLength(const char *s)
{
    uint64_t n = 0;
    while (s[n] != '\0')
    {
        n++;
    }
    return n;
}

static int KipStringEquals(const char *a, const char *b)
{
    while (*a != '\0' && *a == *b)
    {
        a++;
        b++;
    }
    return *a == *b;
}

const char *KiRamdiskBasename(const char *path)
{
    const char *base = path;
    for (const char *p = path; *p != '\0'; p++)
    {
        if (*p == '/')
        {
            base = p + 1;
        }
    }
    return base;
}

PKI_RAMDISK_FILE KiRegisterRamdiskFile(const char *path, const void *data, uint64_t size)
{
    if (KiRamdiskFileCount == KI_RAMDISK_MAX_FILES)
    {
        return 0;
    }
    ASSERT(((uint64_t)(uintptr_t)data & (PAGE_SIZE - 1)) == 0); /* Limine loads page-aligned */

    const char *base = KiRamdiskBasename(path);
    uint64_t length = KipStringLength(base) + 1;
    char *name = MiAllocatePool(length);
    if (name == 0)
    {
        return 0;
    }
    memcpy(name, base, length);

    PKI_RAMDISK_FILE file = &KiRamdiskFiles[KiRamdiskFileCount++];
    file->name = name;
    file->data = data;
    file->size = size;
    file->pageCache = 0;
    return file;
}

PKI_RAMDISK_FILE KiFindRamdiskFile(const char *name)
{
    for (ULONG i = 0; i < KiRamdiskFileCount; i++)
    {
        if (KipStringEquals(KiRamdiskFiles[i].name, name))
        {
            return &KiRamdiskFiles[i];
        }
    }
    return 0;
}

NTSTATUS KiReadRamdiskFile(const KI_RAMDISK_FILE *file, uint64_t offset, void *buffer,
                           uint64_t length, uint64_t *bytesRead)
{
    if (offset >= file->size)
    {
        *bytesRead = 0;
        return STATUS_END_OF_FILE;
    }
    if (length > file->size - offset)
    {
        length = file->size - offset;
    }

    if (file->pageCache != 0)
    {
        /* Through the page cache (one page at a time via the HHDM), so a
         * read always sees exactly what a mapped view sees. */
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
            const char *page = MiPhysicalToVirtual(file->pageCache[position / PAGE_SIZE]);
            memcpy((char *)buffer + copied, page + pageOffset, chunk);
            copied += chunk;
        }
    }
    else
    {
        memcpy(buffer, (const char *)file->data + offset, length);
    }
    *bytesRead = length;
    return STATUS_SUCCESS;
}
