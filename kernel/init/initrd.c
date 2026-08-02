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
#include "kernel/mm/pagecache.h"
#include "kernel/lib/string.h"

#define KI_RAMDISK_MAX_FILES 32

static KI_RAMDISK_FILE KiRamdiskFiles[KI_RAMDISK_MAX_FILES];
static ULONG KiRamdiskFileCount;

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
    uint64_t length = KiStringLength(base) + 1;
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
    MiInitializePageCache(&file->cache);
    return file;
}

PKI_RAMDISK_FILE KiFindRamdiskFile(const char *name)
{
    for (ULONG i = 0; i < KiRamdiskFileCount; i++)
    {
        if (KiStringEquals(KiRamdiskFiles[i].name, name))
        {
            return &KiRamdiskFiles[i];
        }
    }
    return 0;
}

NTSTATUS KiEnsureRamdiskCache(PKI_RAMDISK_FILE file)
{
    if (file->cache.frames != 0)
    {
        return STATUS_SUCCESS;
    }
    NTSTATUS status = MiResizePageCache(&file->cache, file->size);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    {
        /* The RAM disk's own image: kernel memory, never the caller's. */
        KI_PROBE_TOKEN token = KiKernelToken((void *)(uintptr_t)file->data, file->size);
        MiCacheWrite(&file->cache, 0, &token, file->data, file->size);
    }
    return STATUS_SUCCESS;
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

    if (file->cache.frames != 0)
    {
        /* Through the page cache, so a read always sees exactly what a
         * mapped view sees. */
        KI_PROBE_TOKEN token = KiKernelToken(buffer, length);
        MiCacheRead(&file->cache, offset, &token, buffer, length);
    }
    else
    {
        memcpy(buffer, (const char *)file->data + offset, length);
    }
    *bytesRead = length;
    return STATUS_SUCCESS;
}
