/* fs/fat32/file.c — file data over the unified page cache, cluster sizing,
 * and the IO_VFS_OPS table the Io manager drives (see fat.h, kernel/io/vfs.h).
 *
 * NT semantics (share modes, delete-pending checks, case-insensitivity)
 * live where NT puts them: the FS calls the Io layer's share-access
 * accounting at the create point; the delete rules are enforced in
 * SetDisposition/Cleanup here (docs/04 "ntsem" concern, folded into the ops).
 */
#include "fs/fat32/fat.h"
#include "kernel/io/io.h"
#include "kernel/mm/pool.h"
#include "kernel/mm/phys.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "abi/ntstatus.h"

static uint64_t FatClusterBytes(PFAT_VOLUME volume)
{
    return (uint64_t)volume->sectorsPerCluster * volume->bytesPerSector;
}

/* --- data <-> disk --------------------------------------------------------- */

/* Longest run of whole sectors starting at byte `position` that stays
 * inside one cluster (from `sectorInCluster`), inside one cache page (a
 * frame is one physically contiguous DMA target), and covering no whole
 * sector past `limitByte` — the unit of a direct-DMA transfer (CUI-8,
 * docs/19 §5a). `position` is always sector-aligned, so a sector never
 * straddles a page (512 divides 4096). */
static uint32_t FatRunSectors(PFAT_VOLUME volume, ULONG sectorInCluster, uint64_t position,
                              uint64_t limitByte)
{
    ASSERT(position % FAT_SECTOR_SIZE == 0 && position < limitByte);
    uint32_t run = volume->sectorsPerCluster - sectorInCluster;
    uint32_t pageRun = (uint32_t)((PAGE_SIZE - (position % PAGE_SIZE)) / FAT_SECTOR_SIZE);
    if (run > pageRun)
    {
        run = pageRun;
    }
    uint64_t limitRun = (limitByte - position + FAT_SECTOR_SIZE - 1) / FAT_SECTOR_SIZE;
    if (run > limitRun)
    {
        run = (uint32_t)limitRun;
    }
    return run;
}

NTSTATUS FatEnsureCache(PFAT_FCB fcb)
{
    ASSERT(!fcb->isDirectory);
    if (fcb->cacheLoaded)
    {
        return STATUS_SUCCESS;
    }
    NTSTATUS status = MiResizePageCache(&fcb->cache, fcb->fileSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* Page-granularity runs straight into the cache frames: the device DMAs
     * the frame itself, no bounce (docs/19 §5a). */
    PFAT_VOLUME volume = fcb->volume;
    ULONG cluster = fcb->firstCluster;
    uint64_t position = 0;
    while (cluster != 0 && position < fcb->fileSize)
    {
        uint64_t clusterSector = FatClusterToSector(volume, cluster);
        ULONG s = 0;
        while (s < volume->sectorsPerCluster && position < fcb->fileSize)
        {
            uint32_t run = FatRunSectors(volume, s, position, fcb->fileSize);
            uint64_t physical = fcb->cache.frames[position / PAGE_SIZE] + (position % PAGE_SIZE);
            status = FatReadSectorsPhysical(volume, clusterSector + s, run, physical);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            s += run;
            position += (uint64_t)run * FAT_SECTOR_SIZE;
        }
        cluster = FatGetNextCluster(volume, cluster);
    }
    fcb->cacheLoaded = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS FatWritebackRange(PFAT_FCB fcb, uint64_t offset, uint64_t length)
{
    ASSERT(fcb->cacheLoaded);
    PFAT_VOLUME volume = fcb->volume;
    uint64_t clusterBytes = FatClusterBytes(volume);
    if (length == 0 || offset >= fcb->fileSize)
    {
        return STATUS_SUCCESS;
    }
    if (length > fcb->fileSize - offset)
    {
        length = fcb->fileSize - offset;
    }

    uint64_t firstByte = offset & ~(uint64_t)(FAT_SECTOR_SIZE - 1);
    uint64_t endByte = offset + length;
    ULONG clusterIndex = (ULONG)(firstByte / clusterBytes);
    ULONG cluster = FatWalkChain(volume, fcb->firstCluster, clusterIndex);

    for (uint64_t position = firstByte; position < endByte && cluster != 0;)
    {
        uint64_t clusterSector = FatClusterToSector(volume, cluster);
        ULONG sectorInCluster = (ULONG)((position % clusterBytes) / FAT_SECTOR_SIZE);
        while (sectorInCluster < volume->sectorsPerCluster && position < endByte)
        {
            uint32_t run = FatRunSectors(volume, sectorInCluster, position, endByte);
            uint64_t physical = fcb->cache.frames[position / PAGE_SIZE] + (position % PAGE_SIZE);
            NTSTATUS status =
                FatWriteSectorsPhysical(volume, clusterSector + sectorInCluster, run, physical);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            sectorInCluster += run;
            position += (uint64_t)run * FAT_SECTOR_SIZE;
        }
        cluster = FatGetNextCluster(volume, cluster);
    }
    return STATUS_SUCCESS;
}

NTSTATUS FatSetFileSize(PFAT_FCB fcb, uint64_t newSize)
{
    ASSERT(!fcb->isDirectory);
    PFAT_VOLUME volume = fcb->volume;
    uint64_t clusterBytes = FatClusterBytes(volume);
    if (newSize > 0xFFFFFFFFULL) /* spec §6.4: 32-bit DIR_FileSize */
    {
        return STATUS_DISK_FULL;
    }
    NTSTATUS status = FatEnsureCache(fcb);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t oldSize = fcb->fileSize;

    ULONG haveClusters = FatChainLength(volume, fcb->firstCluster);
    ULONG wantClusters = (ULONG)((newSize + clusterBytes - 1) / clusterBytes);

    if (wantClusters > haveClusters)
    {
        ULONG oldLast =
            haveClusters != 0 ? FatWalkChain(volume, fcb->firstCluster, haveClusters - 1) : 0;
        ULONG last = oldLast;
        ULONG firstFresh = 0;
        unsigned char zero[FAT_SECTOR_SIZE];
        memset(zero, 0, sizeof(zero));
        for (ULONG i = haveClusters; i < wantClusters; i++)
        {
            ULONG fresh;
            status = FatAllocateCluster(volume, last, &fresh);
            if (NT_SUCCESS(status))
            {
                if (firstFresh == 0)
                {
                    firstFresh = fresh;
                }
                last = fresh;
                /* Zero-fill on disk immediately so the extension reads as
                 * zeroes even across a remount (Art. 3: immediate writeback). */
                for (ULONG s = 0; s < volume->sectorsPerCluster && NT_SUCCESS(status); s++)
                {
                    status = FatWriteSector(volume, FatClusterToSector(volume, fresh) + s, zero);
                }
            }
            if (!NT_SUCCESS(status))
            {
                /* Unwind the partial extension: a failed grow must leave the
                 * volume exactly as it was. The dir entry still shows the old
                 * size/first-cluster (no metadata flush yet), so any cluster
                 * kept linked here would be orphaned the moment the FCB goes
                 * away — fsck.fat/fatsweep convict it as a lost cluster (the
                 * fatstress nearfull leg caught this via the kmt6 persist.dat
                 * write hitting DISK_FULL with no corrective truncate). */
                if (firstFresh != 0)
                {
                    FatFreeChain(volume, firstFresh);
                    if (oldLast != 0)
                    {
                        FatSetFatEntry(volume, oldLast, FAT_ENTRY_MASK); /* EOC */
                    }
                }
                return status;
            }
        }
        if (fcb->firstCluster == 0)
        {
            fcb->firstCluster = firstFresh;
        }
    }
    else if (wantClusters < haveClusters)
    {
        /* The shrink's statuses are kept, not dropped. A failed FAT write
         * here leaves the chain and the on-disk metadata disagreeing, which
         * is exactly what the caller needs to be told (§12). */
        if (wantClusters == 0)
        {
            NTSTATUS freeStatus = FatFreeChain(volume, fcb->firstCluster);
            fcb->firstCluster = 0;
            if (!NT_SUCCESS(freeStatus))
            {
                status = freeStatus;
            }
        }
        else
        {
            ULONG lastKept = FatWalkChain(volume, fcb->firstCluster, wantClusters - 1);
            ULONG firstFreed = FatGetNextCluster(volume, lastKept);
            NTSTATUS cutStatus = FatSetFatEntry(volume, lastKept, FAT_ENTRY_MASK); /* EOC */
            if (firstFreed != 0)
            {
                NTSTATUS freeStatus = FatFreeChain(volume, firstFreed);
                if (NT_SUCCESS(cutStatus))
                {
                    cutStatus = freeStatus;
                }
            }
            if (!NT_SUCCESS(cutStatus))
            {
                status = cutStatus;
            }
        }
    }

    /* The recorded size follows the CHAIN, whatever happens next. Returning
     * early from here left fcb->fileSize describing a chain that no longer
     * existed, and the next read of the vanished tail silently zero-filled
     * (§12). Metadata is flushed on the way out of every path below. */
    fcb->fileSize = newSize;
    LARGE_INTEGER shrinkNow = FatCurrentNtTime();
    FatNtTimeToFatTime(shrinkNow, &fcb->writeDate, &fcb->writeTime);
    if (!NT_SUCCESS(status))
    {
        FatFlushFcbMetadata(fcb);
        return status;
    }

    status = MiResizePageCache(&fcb->cache, newSize);
    if (!NT_SUCCESS(status))
    {
        FatFlushFcbMetadata(fcb);
        return status;
    }

    if (newSize > oldSize && oldSize != 0)
    {
        /* An extended range must read as ZEROS (NT rule; pinned by
         * sem_file/zero_extend, found by the kmt FAT churn stress). Two
         * stale-byte sources survive a plain resize: the cache page holding
         * the old EOF carries the on-disk sector tail FatEnsureCache read
         * past EOF, and the old last cluster's tail on DISK still holds
         * truncated bytes (freshly allocated clusters are zero-filled, kept
         * ones are not). Scrub the cache window and write the kept-cluster
         * tail through. */
        uint64_t cacheEnd = (oldSize + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
        if (cacheEnd > newSize)
        {
            cacheEnd = newSize;
        }
        for (uint64_t position = oldSize; position < cacheEnd;)
        {
            uint64_t pageOffset = position & (PAGE_SIZE - 1);
            uint64_t chunk = PAGE_SIZE - pageOffset;
            if (chunk > cacheEnd - position)
            {
                chunk = cacheEnd - position;
            }
            char *page = MiPhysicalToVirtual(fcb->cache.frames[position / PAGE_SIZE]);
            memset(page + pageOffset, 0, chunk);
            position += chunk;
        }
        uint64_t diskEnd = (oldSize + clusterBytes - 1) / clusterBytes * clusterBytes;
        if (diskEnd > newSize)
        {
            diskEnd = newSize;
        }
        if (diskEnd > oldSize)
        {
            status = FatWritebackRange(fcb, oldSize, diskEnd - oldSize);
            if (!NT_SUCCESS(status))
            {
                FatFlushFcbMetadata(fcb);
                return status;
            }
        }
    }

    LARGE_INTEGER now = FatCurrentNtTime();
    FatNtTimeToFatTime(now, &fcb->writeDate, &fcb->writeTime);
    return FatFlushFcbMetadata(fcb);
}

/* --- vfs ops ---------------------------------------------------------------- */

static PFAT_FCB FatFcbOf(PFILE_OBJECT file)
{
    return (PFAT_FCB)file->fsContext;
}

/* CUI-5 change notification (bodies below, past the vfs ops they hook). */
static NTSTATUS FatBuildFcbPath(PFAT_FCB target, WCHAR *buffer, ULONG capacity, ULONG *lengthOut);
static void FatReportChange(PIO_DEVICE device, PFAT_FCB parent, const UNICODE_STRING *name,
                            ULONG filterBit, ULONG action);

/* The name-class filter bit for an entry (files vs directories). */
static ULONG FatNameFilterBit(PFAT_FCB fcb)
{
    return fcb->isDirectory ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME;
}

/* Map FILE_ATTRIBUTE_* to the FAT attribute byte (files get ARCHIVE, the
 * classic FAT dirty-bit convention). */
static UCHAR FatAttributesFromNt(ULONG ntAttributes, BOOLEAN directory)
{
    UCHAR attributes = directory ? FAT_ATTR_DIRECTORY : FAT_ATTR_ARCHIVE;
    if (ntAttributes & FILE_ATTRIBUTE_READONLY)
    {
        attributes |= FAT_ATTR_READ_ONLY;
    }
    if (ntAttributes & FILE_ATTRIBUTE_HIDDEN)
    {
        attributes |= FAT_ATTR_HIDDEN;
    }
    if (ntAttributes & FILE_ATTRIBUTE_SYSTEM)
    {
        attributes |= FAT_ATTR_SYSTEM;
    }
    return attributes;
}

static ULONG FatAttributesToNt(UCHAR fatAttributes)
{
    ULONG attributes = 0;
    if (fatAttributes & FAT_ATTR_READ_ONLY)
    {
        attributes |= FILE_ATTRIBUTE_READONLY;
    }
    if (fatAttributes & FAT_ATTR_HIDDEN)
    {
        attributes |= FILE_ATTRIBUTE_HIDDEN;
    }
    if (fatAttributes & FAT_ATTR_SYSTEM)
    {
        attributes |= FILE_ATTRIBUTE_SYSTEM;
    }
    if (fatAttributes & FAT_ATTR_DIRECTORY)
    {
        attributes |= FILE_ATTRIBUTE_DIRECTORY;
    }
    if (fatAttributes & FAT_ATTR_ARCHIVE)
    {
        attributes |= FILE_ATTRIBUTE_ARCHIVE;
    }
    return attributes != 0 ? attributes : FILE_ATTRIBUTE_NORMAL;
}

/* Walk `path` (no leading backslash; empty = root) from `base` down to the
 * final component. Returns the referenced parent and the leaf name; a path
 * naming the root returns *parentOut = 0 and the referenced root in
 * *foundOut. */
static NTSTATUS FatResolveParent(PFAT_FCB base, const UNICODE_STRING *path, PFAT_FCB *parentOut,
                                 UNICODE_STRING *leafOut, BOOLEAN *trailingSlashOut)
{
    UNICODE_STRING remaining = *path;
    *trailingSlashOut = FALSE;

    /* Strip one trailing backslash ("dir\" opens the directory). */
    if (remaining.Length >= sizeof(WCHAR) &&
        remaining.Buffer[remaining.Length / sizeof(WCHAR) - 1] == '\\')
    {
        remaining.Length -= sizeof(WCHAR);
        *trailingSlashOut = TRUE;
    }

    PFAT_FCB current = base;
    FatReferenceFcb(current);
    for (;;)
    {
        /* Split the next component. */
        ULONG units = remaining.Length / sizeof(WCHAR);
        if (units == 0)
        {
            *parentOut = current; /* empty leaf: the caller opens `current` */
            leafOut->Buffer = 0;
            leafOut->Length = 0;
            leafOut->MaximumLength = 0;
            return STATUS_SUCCESS;
        }
        ULONG i;
        for (i = 0; i < units && remaining.Buffer[i] != '\\'; i++)
        {
        }
        if (i == 0)
        {
            FatDereferenceFcb(current);
            return STATUS_OBJECT_NAME_INVALID; /* empty component ("a\\\\b") */
        }
        UNICODE_STRING component;
        component.Buffer = remaining.Buffer;
        component.Length = (USHORT)(i * sizeof(WCHAR));
        component.MaximumLength = component.Length;
        /* NT filename character rules (MS "Naming Files, Paths": the
         * reserved set " * / : < > ? \ | and controls) — a wildcard or
         * reserved character in any component is STATUS_OBJECT_NAME_INVALID
         * on the oracle (kernel32:directory pins the wildcard half). */
        for (ULONG k = 0; k < i; k++)
        {
            WCHAR c = component.Buffer[k];
            if (c < 0x20 || c == L'"' || c == L'*' || c == L'/' || c == L':' || c == L'<' ||
                c == L'>' || c == L'?' || c == L'|')
            {
                FatDereferenceFcb(current);
                return STATUS_OBJECT_NAME_INVALID;
            }
        }
        BOOLEAN isFinal = i == units;
        if (isFinal)
        {
            *parentOut = current;
            *leafOut = component;
            return STATUS_SUCCESS;
        }
        remaining.Buffer += i + 1;
        remaining.Length = (USHORT)((units - i - 1) * sizeof(WCHAR));

        PFAT_FCB child;
        NTSTATUS status = FatLookup(current, &component, &child);
        FatDereferenceFcb(current);
        if (!NT_SUCCESS(status))
        {
            return status == STATUS_OBJECT_NAME_NOT_FOUND ? STATUS_OBJECT_PATH_NOT_FOUND : status;
        }
        if (!child->isDirectory)
        {
            FatDereferenceFcb(child);
            return STATUS_OBJECT_PATH_NOT_FOUND;
        }
        current = child;
    }
}

static NTSTATUS FatVfsCreateLocked(PIO_DEVICE device, PFILE_OBJECT file, const UNICODE_STRING *path,
                                   PFILE_OBJECT relativeTo, ACCESS_MASK grantedAccess,
                                   ULONG shareAccess, ULONG fileAttributes, ULONG disposition,
                                   ULONG options, ULONG_PTR *information)
{
    PFAT_VOLUME volume = device->context;
    PFAT_FCB base = relativeTo != 0 ? FatFcbOf(relativeTo) : volume->root;
    if (relativeTo != 0 && !base->isDirectory)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PFAT_FCB parent;
    UNICODE_STRING leaf;
    BOOLEAN trailingSlash;
    NTSTATUS status = FatResolveParent(base, path, &parent, &leaf, &trailingSlash);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PFAT_FCB fcb = 0;
    BOOLEAN created = FALSE;
    if (leaf.Length == 0)
    {
        /* The path named `parent` itself (the root, or "dir\"). */
        fcb = parent;
        parent = 0;
    }
    else
    {
        status = FatLookup(parent, &leaf, &fcb);
        if (status == STATUS_OBJECT_NAME_NOT_FOUND)
        {
            /* Missing leaf: create if the disposition says so. */
            if (disposition == FILE_OPEN || disposition == FILE_OVERWRITE)
            {
                FatDereferenceFcb(parent);
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
            BOOLEAN directory = (options & FILE_DIRECTORY_FILE) != 0;
            if (directory && trailingSlash)
            {
                trailingSlash = FALSE;
            }
            status = FatCreateEntry(
                parent, &leaf, directory,
                (UCHAR)(FatAttributesFromNt(fileAttributes, directory) & ~FAT_ATTR_DIRECTORY),
                &fcb);
            created = TRUE;
        }
        if (!NT_SUCCESS(status))
        {
            FatDereferenceFcb(parent);
            return status;
        }
        FatDereferenceFcb(parent);
        parent = 0;
    }

    /* --- the NT open rules, in NT's order ---------------------------------- */
    if (!created)
    {
        if (fcb->header.deletePending)
        {
            FatDereferenceFcb(fcb);
            return STATUS_DELETE_PENDING;
        }
        if (disposition == FILE_CREATE)
        {
            FatDereferenceFcb(fcb);
            return STATUS_OBJECT_NAME_COLLISION;
        }
    }
    /* A create that fails a TYPE check below has already written the
     * directory entry, so the refusal must take it back -- a trailing
     * backslash without FILE_DIRECTORY_FILE used to leave a zero-length
     * orphan file behind (docs/review-2026-07 §7). `created` is the flag
     * that says the entry is ours to undo. */
#define FAT_REFUSE_CREATED(refusalStatus)                                                          \
    do                                                                                             \
    {                                                                                              \
        if (created)                                                                               \
        {                                                                                          \
            FatDeleteEntry(fcb);                                                                   \
        }                                                                                          \
        FatDereferenceFcb(fcb);                                                                    \
        return (refusalStatus);                                                                    \
    } while (0)

    if (fcb->isDirectory && (options & FILE_NON_DIRECTORY_FILE))
    {
        FAT_REFUSE_CREATED(STATUS_FILE_IS_A_DIRECTORY);
    }
    if (!fcb->isDirectory && ((options & FILE_DIRECTORY_FILE) || trailingSlash))
    {
        FAT_REFUSE_CREATED(trailingSlash ? STATUS_OBJECT_NAME_INVALID : STATUS_NOT_A_DIRECTORY);
    }
    if (fcb->isDirectory && (disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF ||
                             disposition == FILE_SUPERSEDE))
    {
        FAT_REFUSE_CREATED(STATUS_FILE_IS_A_DIRECTORY);
    }
    /* Write access to a read-only file is refused at open (NT rule). */
    if (!created && (fcb->attributes & FAT_ATTR_READ_ONLY) &&
        (grantedAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)))
    {
        FatDereferenceFcb(fcb);
        return STATUS_ACCESS_DENIED;
    }
    /* And so is FILE_DELETE_ON_CLOSE, which is the same deletion
     * FatVfsSetDisposition already refuses on a read-only file -- it just
     * arrives by a different door, and used to walk straight past the check
     * (docs/review-2026-07 §11). The oracle answers STATUS_CANNOT_DELETE
     * here, at OPEN, not silently at close. */
    if (!created && (fcb->attributes & FAT_ATTR_READ_ONLY) && (options & FILE_DELETE_ON_CLOSE))
    {
        FatDereferenceFcb(fcb);
        return STATUS_CANNOT_DELETE;
    }

    /* Share modes: the NT point — after existence and typing, before any
     * overwrite side effect. */
    status = IoCheckShareAccess(grantedAccess, shareAccess, &fcb->header);
    if (!NT_SUCCESS(status))
    {
        FAT_REFUSE_CREATED(status);
    }
#undef FAT_REFUSE_CREATED
    IoSetShareAccess(grantedAccess, shareAccess, &fcb->header);
    file->shareCounted = TRUE;

    /* Overwrite/supersede truncates. */
    if (!created && !fcb->isDirectory &&
        (disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF ||
         disposition == FILE_SUPERSEDE))
    {
        status = FatSetFileSize(fcb, 0);
        if (!NT_SUCCESS(status))
        {
            IoRemoveShareAccess(grantedAccess, shareAccess, &fcb->header);
            file->shareCounted = FALSE;
            FatDereferenceFcb(fcb);
            return status;
        }
        fcb->attributes = FatAttributesFromNt(fileAttributes, FALSE);
        FatFlushFcbMetadata(fcb);
        *information = disposition == FILE_SUPERSEDE ? FILE_SUPERSEDED : FILE_OVERWRITTEN;
    }
    else
    {
        *information = created ? FILE_CREATED : FILE_OPENED;
    }

    if (created)
    {
        FatReportChange(device, fcb->parent, &fcb->longName, FatNameFilterBit(fcb),
                        FILE_ACTION_ADDED);
    }
    file->fsContext = fcb;
    file->fcb = &fcb->header;
    file->isDirectory = fcb->isDirectory;
    fcb->openObjectCount++;
    return STATUS_SUCCESS;
}

static void FatVfsCleanupLocked(PFILE_OBJECT file)
{
    PFAT_FCB fcb = FatFcbOf(file);
    ASSERT(fcb->openObjectCount > 0);
    fcb->openObjectCount--;
    /* The Io layer released this open's share slots and locks already; the
     * FS applies delete-on-close / disposition when the LAST open goes.
     * "Last" counts EVERY open, not just data-access ones: the pinned Wine
     * defers the unlink while any fd for the inode remains — even an
     * attributes-only open — and applies it when the list empties
     * (server/fd.c check_sharing ignores such opens for sharing, but the
     * inode's closed-list unlink still waits for them). A delete intent
     * whose own handle closes early is latched in unlinkPending rather than
     * dropped (fuzzer-found: scrub-then-recreate reported FILE_CREATED where
     * the oracle reports FILE_OVERWRITTEN). */
    BOOLEAN wantDelete = file->deleteOnClose || fcb->header.deletePending || fcb->unlinkPending;
    if (!wantDelete || fcb->isRoot)
    {
        return;
    }
    if (fcb->openObjectCount != 0)
    {
        fcb->unlinkPending = TRUE; /* the last open's cleanup applies it */
        return;
    }
    if (fcb->isDirectory)
    {
        BOOLEAN empty;
        if (!NT_SUCCESS(FatIsDirectoryEmpty(fcb, &empty)) || !empty)
        {
            return; /* a non-empty directory silently survives (NT rule) */
        }
    }
    if (fcb->header.sectionCount != 0)
    {
        /* Live mapped sections pin the file -- but the intent is LATCHED so
         * the section's own release can apply it. Returning without latching
         * dropped the delete forever, since nothing re-enters the FS when
         * the section goes away (docs/review-2026-07 §7). */
        fcb->unlinkPending = TRUE;
        return;
    }
    FatDeleteEntry(fcb);
    FatReportChange(file->device, fcb->parent, &fcb->longName, FatNameFilterBit(fcb),
                    FILE_ACTION_REMOVED);
    fcb->header.deletePending = FALSE;
    fcb->unlinkPending = FALSE;
    MiResizePageCache(&fcb->cache, 0);
    fcb->cacheLoaded = FALSE;
}

/* The file's last section backing is gone: apply a delete the mapped state
 * forced FatVfsCleanup to defer (see there). No handle is closing, so none
 * of Cleanup's per-open bookkeeping runs -- only the latched intent. */
static void FatVfsSectionsReleasedLocked(PFILE_OBJECT file)
{
    PFAT_FCB fcb = FatFcbOf(file);
    if (fcb->isRoot || fcb->openObjectCount != 0)
    {
        return; /* still open: the last cleanup will apply it */
    }
    if (!fcb->unlinkPending && !fcb->header.deletePending)
    {
        return;
    }
    if (fcb->isDirectory)
    {
        BOOLEAN empty;
        if (!NT_SUCCESS(FatIsDirectoryEmpty(fcb, &empty)) || !empty)
        {
            return;
        }
    }
    FatDeleteEntry(fcb);
    FatReportChange(file->device, fcb->parent, &fcb->longName, FatNameFilterBit(fcb),
                    FILE_ACTION_REMOVED);
    fcb->header.deletePending = FALSE;
    fcb->unlinkPending = FALSE;
    MiResizePageCache(&fcb->cache, 0);
    fcb->cacheLoaded = FALSE;
}

static void FatVfsCloseLocked(PFILE_OBJECT file)
{
    FatDereferenceFcb(FatFcbOf(file));
}

static NTSTATUS FatVfsGetCacheLocked(PFILE_OBJECT file, PMI_PAGE_CACHE *cache)
{
    PFAT_FCB fcb = FatFcbOf(file);
    if (fcb->isDirectory)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    NTSTATUS status = FatEnsureCache(fcb);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *cache = &fcb->cache;
    return STATUS_SUCCESS;
}

static NTSTATUS FatVfsWritebackRangeLocked(PFILE_OBJECT file, uint64_t offset, uint64_t length)
{
    PFAT_FCB fcb = FatFcbOf(file);
    LARGE_INTEGER now = FatCurrentNtTime();
    FatNtTimeToFatTime(now, &fcb->writeDate, &fcb->writeTime);
    NTSTATUS status = FatWritebackRange(fcb, offset, length);
    if (NT_SUCCESS(status))
    {
        status = FatFlushFcbMetadata(fcb);
    }
    if (NT_SUCCESS(status) && !fcb->isRoot)
    {
        FatReportChange(file->device, fcb->parent, &fcb->longName,
                        FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
                        FILE_ACTION_MODIFIED);
    }
    return status;
}

static NTSTATUS FatVfsSetEndOfFileLocked(PFILE_OBJECT file, uint64_t endOfFile)
{
    PFAT_FCB fcb = FatFcbOf(file);
    if (fcb->isDirectory)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    NTSTATUS status = FatSetFileSize(fcb, endOfFile);
    if (NT_SUCCESS(status))
    {
        FatReportChange(file->device, fcb->parent, &fcb->longName,
                        FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                        FILE_ACTION_MODIFIED);
    }
    return status;
}

static NTSTATUS FatVfsGetInfoLocked(PFILE_OBJECT file, IO_FILE_INFO *info)
{
    PFAT_FCB fcb = FatFcbOf(file);
    uint64_t clusterBytes = FatClusterBytes(fcb->volume);
    info->creationTime = FatTimeToNtTime(fcb->createDate, fcb->createTime, fcb->createTimeTenth);
    info->lastAccessTime = FatTimeToNtTime(fcb->accessDate, 0, 0);
    info->lastWriteTime = FatTimeToNtTime(fcb->writeDate, fcb->writeTime, 0);
    info->endOfFile = fcb->fileSize;
    info->allocationSize = (fcb->fileSize + clusterBytes - 1) / clusterBytes * clusterBytes;
    info->fileId = FatFileId(fcb->parentDirCluster, fcb->dirEntryIndex);
    info->fileAttributes = FatAttributesToNt(fcb->attributes);
    info->isDirectory = fcb->isDirectory;
    return STATUS_SUCCESS;
}

static NTSTATUS FatVfsSetBasicLocked(PFILE_OBJECT file, const FILE_BASIC_INFORMATION *basic)
{
    PFAT_FCB fcb = FatFcbOf(file);
    if (basic->FileAttributes != 0)
    {
        UCHAR keep = (UCHAR)(fcb->attributes & (FAT_ATTR_DIRECTORY | FAT_ATTR_ARCHIVE));
        fcb->attributes = (UCHAR)(FatAttributesFromNt(basic->FileAttributes, FALSE) &
                                  ~(FAT_ATTR_DIRECTORY | FAT_ATTR_ARCHIVE));
        fcb->attributes |= keep;
    }
    /* Time fields: 0 = leave unchanged, -1 = NT's "disable implicit
     * updates" (also left unchanged here). */
    if (basic->LastWriteTime.QuadPart > 0)
    {
        FatNtTimeToFatTime(basic->LastWriteTime, &fcb->writeDate, &fcb->writeTime);
    }
    if (basic->CreationTime.QuadPart > 0)
    {
        FatNtTimeToFatTime(basic->CreationTime, &fcb->createDate, &fcb->createTime);
    }
    if (basic->LastAccessTime.QuadPart > 0)
    {
        USHORT ignoredTime;
        FatNtTimeToFatTime(basic->LastAccessTime, &fcb->accessDate, &ignoredTime);
    }
    NTSTATUS status = FatFlushFcbMetadata(fcb);
    if (NT_SUCCESS(status) && !fcb->isRoot)
    {
        FatReportChange(file->device, fcb->parent, &fcb->longName, FILE_NOTIFY_CHANGE_ATTRIBUTES,
                        FILE_ACTION_MODIFIED);
    }
    return status;
}

static NTSTATUS FatVfsSetDispositionLocked(PFILE_OBJECT file, BOOLEAN deleteFile)
{
    PFAT_FCB fcb = FatFcbOf(file);
    if (fcb->isRoot)
    {
        return STATUS_CANNOT_DELETE;
    }
    if (!deleteFile)
    {
        fcb->header.deletePending = FALSE;
        return STATUS_SUCCESS;
    }
    if (fcb->attributes & FAT_ATTR_READ_ONLY)
    {
        return STATUS_CANNOT_DELETE;
    }
    if (fcb->header.sectionCount != 0)
    {
        return STATUS_CANNOT_DELETE; /* mapped (the pinned Wine rule too) */
    }
    if (fcb->isDirectory)
    {
        BOOLEAN empty;
        NTSTATUS status = FatIsDirectoryEmpty(fcb, &empty);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (!empty)
        {
            return STATUS_DIRECTORY_NOT_EMPTY;
        }
    }
    fcb->header.deletePending = TRUE;
    return STATUS_SUCCESS;
}

static NTSTATUS FatVfsRenameLocked(PFILE_OBJECT file, PFILE_OBJECT relativeTo,
                                   const UNICODE_STRING *path, ULONG renameFlags)
{
    PFAT_FCB fcb = FatFcbOf(file);
    PFAT_VOLUME volume = fcb->volume;
    if (fcb->isRoot)
    {
        return STATUS_INVALID_PARAMETER;
    }
    PFAT_FCB base = relativeTo != 0 ? FatFcbOf(relativeTo) : volume->root;
    if (relativeTo != 0 && !base->isDirectory)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PFAT_FCB newParent;
    UNICODE_STRING leaf;
    BOOLEAN trailingSlash;
    NTSTATUS status = FatResolveParent(base, path, &newParent, &leaf, &trailingSlash);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (leaf.Length == 0 || (trailingSlash && !fcb->isDirectory))
    {
        FatDereferenceFcb(newParent);
        return STATUS_OBJECT_NAME_INVALID;
    }
    /* Moving a directory under itself (or into itself) would detach its
     * subtree from the namespace: refuse before touching the disk. */
    for (PFAT_FCB ancestor = newParent; ancestor != 0; ancestor = ancestor->parent)
    {
        if (ancestor == fcb)
        {
            FatDereferenceFcb(newParent);
            return STATUS_INVALID_PARAMETER;
        }
    }

    PFAT_FCB existing = 0;
    status = FatLookup(newParent, &leaf, &existing);
    if (NT_SUCCESS(status))
    {
        if (existing == fcb)
        {
            /* The target names the source itself. Identical spelling is the
             * pinned no-op success (Wine server/fd.c set_fd_name: same
             * dev+ino returns without error); a different spelling is a
             * case-change rename and falls through to the slot rewrite. */
            BOOLEAN identical = leaf.Length == fcb->longName.Length &&
                                memcmp(leaf.Buffer, fcb->longName.Buffer, leaf.Length) == 0;
            FatDereferenceFcb(existing);
            if (identical)
            {
                FatDereferenceFcb(newParent);
                return STATUS_SUCCESS;
            }
        }
        else
        {
            /* The replace rules, in the pinned Wine's order (server/fd.c
             * set_fd_name): collision without the flag; a non-regular
             * target, a read-only target without IGNORE_READONLY, and a
             * currently-open target all refuse with ACCESS_DENIED. */
            NTSTATUS refuse = STATUS_SUCCESS;
            if (!(renameFlags & FILE_RENAME_REPLACE_IF_EXISTS))
            {
                refuse = STATUS_OBJECT_NAME_COLLISION;
            }
            else if (existing->isDirectory)
            {
                refuse = STATUS_ACCESS_DENIED;
            }
            else if ((existing->attributes & FAT_ATTR_READ_ONLY) &&
                     !(renameFlags & FILE_RENAME_IGNORE_READONLY_ATTRIBUTE))
            {
                refuse = STATUS_ACCESS_DENIED;
            }
            else if (existing->openObjectCount != 0 || existing->header.sectionCount != 0)
            {
                refuse = STATUS_ACCESS_DENIED;
            }
            if (refuse != STATUS_SUCCESS)
            {
                FatDereferenceFcb(existing);
                FatDereferenceFcb(newParent);
                return refuse;
            }
            status = FatDeleteEntry(existing);
            FatDereferenceFcb(existing);
            if (!NT_SUCCESS(status))
            {
                FatDereferenceFcb(newParent);
                return status;
            }
        }
    }
    else if (status != STATUS_OBJECT_NAME_NOT_FOUND)
    {
        FatDereferenceFcb(newParent);
        return status;
    }

    /* Capture the pre-move identity for the change reports (the rename
     * rewrites the FCB in place; the old parent could otherwise die with
     * its pin inside FatRenameEntry). */
    PFAT_FCB oldParent = fcb->parent;
    FatReferenceFcb(oldParent);
    WCHAR oldName[260];
    ULONG oldNameBytes = fcb->longName.Length <= sizeof(oldName) ? fcb->longName.Length : 0;
    memcpy(oldName, fcb->longName.Buffer, oldNameBytes);

    status = FatRenameEntry(fcb, newParent, &leaf);
    if (NT_SUCCESS(status) && IoDirectoryWatchesActive())
    {
        UNICODE_STRING oldNameString;
        oldNameString.Buffer = oldName;
        oldNameString.Length = (USHORT)oldNameBytes;
        oldNameString.MaximumLength = (USHORT)oldNameBytes;
        ULONG bit = FatNameFilterBit(fcb);
        if (oldParent == newParent)
        {
            /* The pinned pair for an in-place rename; one-shot watches see
             * the OLD_NAME record. */
            FatReportChange(file->device, oldParent, &oldNameString, bit,
                            FILE_ACTION_RENAMED_OLD_NAME);
            FatReportChange(file->device, newParent, &fcb->longName, bit,
                            FILE_ACTION_RENAMED_NEW_NAME);
        }
        else
        {
            FatReportChange(file->device, oldParent, &oldNameString, bit, FILE_ACTION_REMOVED);
            FatReportChange(file->device, newParent, &fcb->longName, bit, FILE_ACTION_ADDED);
        }
    }
    FatDereferenceFcb(oldParent);
    FatDereferenceFcb(newParent);
    return status;
}

static NTSTATUS FatVfsReadDirectoryLocked(PFILE_OBJECT file, ULONG *cursor, IO_DIR_ENTRY *entry)
{
    PFAT_FCB fcb = FatFcbOf(file);
    if (!fcb->isDirectory)
    {
        return STATUS_INVALID_PARAMETER;
    }
    return FatReadDirectoryEntry(fcb, cursor, entry);
}

static NTSTATUS FatBuildFcbPath(PFAT_FCB target, WCHAR *buffer, ULONG capacity, ULONG *lengthOut)
{
    /* Reconstruct "\a\b\c" by walking the parent chain. */
    PFAT_FCB chain[64];
    ULONG depth = 0;
    for (PFAT_FCB fcb = target; fcb != 0 && !fcb->isRoot; fcb = fcb->parent)
    {
        if (depth == 64)
        {
            return STATUS_OBJECT_PATH_INVALID;
        }
        chain[depth++] = fcb;
    }

    ULONG lengthBytes = 0;
    if (depth == 0)
    {
        lengthBytes = sizeof(WCHAR); /* the root is "\" */
    }
    for (ULONG i = 0; i < depth; i++)
    {
        lengthBytes += sizeof(WCHAR) + chain[i]->longName.Length;
    }
    *lengthOut = lengthBytes;

    ULONG written = 0;
    for (ULONG i = depth; i > 0; i--)
    {
        if (written + sizeof(WCHAR) <= capacity)
        {
            buffer[written / sizeof(WCHAR)] = '\\';
        }
        written += sizeof(WCHAR);
        PFAT_FCB fcb = chain[i - 1];
        ULONG copy = fcb->longName.Length;
        if (written + copy > capacity)
        {
            copy = capacity > written ? capacity - written : 0;
        }
        memcpy((char *)buffer + written, fcb->longName.Buffer, copy);
        written += fcb->longName.Length;
    }
    if (depth == 0)
    {
        if (capacity >= sizeof(WCHAR))
        {
            buffer[0] = '\\';
        }
        written = sizeof(WCHAR);
    }
    return written <= capacity ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;
}

/* Deliberately UNGATED (the one exception besides the GetCache hot path):
 * a pure in-memory FCB-chain walk with no blocking point is already atomic
 * under the one-CPU no-preemption model (docs/20 §5's standing argument),
 * and `buffer` may be the caller's USER buffer (FileNameInformation fills
 * in place) — which must never be touched under the gate, because a ring-0
 * fault on it unwinds past the release (docs/20 R3). */
static NTSTATUS FatVfsQueryName(PFILE_OBJECT file, WCHAR *buffer, ULONG capacity, ULONG *lengthOut)
{
    return FatBuildFcbPath(FatFcbOf(file), buffer, capacity, lengthOut);
}

/* CUI-5: report one directory change to the kernel's watch list (cheap
 * when nothing is armed). `parent` is the mutated directory's FCB. */
static void FatReportChange(PIO_DEVICE device, PFAT_FCB parent, const UNICODE_STRING *name,
                            ULONG filterBit, ULONG action)
{
    if (!IoDirectoryWatchesActive())
    {
        return;
    }
    WCHAR path[260];
    ULONG lengthBytes = 0;
    if (!NT_SUCCESS(FatBuildFcbPath(parent, path, sizeof(path), &lengthBytes)) ||
        lengthBytes > sizeof(path))
    {
        return;
    }
    UNICODE_STRING parentPath;
    parentPath.Buffer = path;
    parentPath.Length = (USHORT)lengthBytes;
    parentPath.MaximumLength = (USHORT)lengthBytes;
    IoReportDirectoryChange(device, &parentPath, name, filterBit, action);
}

static NTSTATUS FatVfsQueryVolumeInfoLocked(PIO_DEVICE device, IO_VOLUME_INFO *info)
{
    return FatQueryVolumeInfo((PFAT_VOLUME)device->context, info);
}

static NTSTATUS FatVfsSetVolumeLabelLocked(PIO_DEVICE device, const WCHAR *label, ULONG labelBytes)
{
    return FatSetVolumeLabel((PFAT_VOLUME)device->context, label, labelBytes);
}

/* --- the volume-gate wrappers (CUI-8, docs/20 R1) --------------------------
 * Every published op serializes on the volume gate; the *Locked functions
 * above never take it themselves, so internal calls cannot recurse. Once a
 * gate holder can park mid-operation (docs/19 §5c), a second thread entering
 * any op parks here instead of interleaving with half-done volume state —
 * the repair for every "BROKEN by F1" row in docs/20 §3.
 *
 * GetCache is the one exception shape (docs/20 R5): the cache-hot read path
 * — every NtReadFile after the first — stays gate-free on a double-checked
 * `cacheLoaded`, sound because the flag transitions only under the gate,
 * flag reads/writes are atomic under the one-lock model, and a loaded cache
 * is never unloaded while the FCB lives. */

static NTSTATUS FatVfsCreate(PIO_DEVICE device, PFILE_OBJECT file, const UNICODE_STRING *path,
                             PFILE_OBJECT relativeTo, ACCESS_MASK grantedAccess, ULONG shareAccess,
                             ULONG fileAttributes, ULONG disposition, ULONG options,
                             ULONG_PTR *information)
{
    PFAT_VOLUME volume = device->context;
    FatAcquireVolumeGate(volume);
    NTSTATUS status = FatVfsCreateLocked(device, file, path, relativeTo, grantedAccess, shareAccess,
                                         fileAttributes, disposition, options, information);
    FatReleaseVolumeGate(volume);
    return status;
}

static void FatVfsCleanup(PFILE_OBJECT file)
{
    PFAT_VOLUME volume = FatFcbOf(file)->volume;
    FatAcquireVolumeGate(volume);
    FatVfsCleanupLocked(file);
    FatReleaseVolumeGate(volume);
}

static void FatVfsSectionsReleased(PFILE_OBJECT file)
{
    PFAT_VOLUME volume = FatFcbOf(file)->volume;
    FatAcquireVolumeGate(volume);
    FatVfsSectionsReleasedLocked(file);
    FatReleaseVolumeGate(volume);
}

static void FatVfsClose(PFILE_OBJECT file)
{
    /* Snapshot the volume first: the call may free the FCB. */
    PFAT_VOLUME volume = FatFcbOf(file)->volume;
    FatAcquireVolumeGate(volume);
    FatVfsCloseLocked(file);
    FatReleaseVolumeGate(volume);
}

static NTSTATUS FatVfsGetCache(PFILE_OBJECT file, PMI_PAGE_CACHE *cache)
{
    PFAT_FCB fcb = FatFcbOf(file);
    if (!fcb->isDirectory && fcb->cacheLoaded)
    {
        *cache = &fcb->cache; /* the hot path: no gate (docs/20 R5) */
        return STATUS_SUCCESS;
    }
    PFAT_VOLUME volume = fcb->volume;
    FatAcquireVolumeGate(volume);
    NTSTATUS status = FatVfsGetCacheLocked(file, cache); /* re-checks under the gate */
    FatReleaseVolumeGate(volume);
    return status;
}

static NTSTATUS FatVfsWritebackRange(PFILE_OBJECT file, uint64_t offset, uint64_t length)
{
    PFAT_VOLUME volume = FatFcbOf(file)->volume;
    FatAcquireVolumeGate(volume);
    NTSTATUS status = FatVfsWritebackRangeLocked(file, offset, length);
    FatReleaseVolumeGate(volume);
    return status;
}

static NTSTATUS FatVfsSetEndOfFile(PFILE_OBJECT file, uint64_t endOfFile)
{
    PFAT_VOLUME volume = FatFcbOf(file)->volume;
    FatAcquireVolumeGate(volume);
    NTSTATUS status = FatVfsSetEndOfFileLocked(file, endOfFile);
    FatReleaseVolumeGate(volume);
    return status;
}

static NTSTATUS FatVfsGetInfo(PFILE_OBJECT file, IO_FILE_INFO *info)
{
    PFAT_VOLUME volume = FatFcbOf(file)->volume;
    FatAcquireVolumeGate(volume);
    NTSTATUS status = FatVfsGetInfoLocked(file, info);
    FatReleaseVolumeGate(volume);
    return status;
}

static NTSTATUS FatVfsSetBasic(PFILE_OBJECT file, const FILE_BASIC_INFORMATION *basic)
{
    PFAT_VOLUME volume = FatFcbOf(file)->volume;
    FatAcquireVolumeGate(volume);
    NTSTATUS status = FatVfsSetBasicLocked(file, basic);
    FatReleaseVolumeGate(volume);
    return status;
}

static NTSTATUS FatVfsSetDisposition(PFILE_OBJECT file, BOOLEAN deleteFile)
{
    PFAT_VOLUME volume = FatFcbOf(file)->volume;
    FatAcquireVolumeGate(volume);
    NTSTATUS status = FatVfsSetDispositionLocked(file, deleteFile);
    FatReleaseVolumeGate(volume);
    return status;
}

static NTSTATUS FatVfsRename(PFILE_OBJECT file, PFILE_OBJECT relativeTo, const UNICODE_STRING *path,
                             ULONG flags)
{
    PFAT_VOLUME volume = FatFcbOf(file)->volume;
    FatAcquireVolumeGate(volume);
    NTSTATUS status = FatVfsRenameLocked(file, relativeTo, path, flags);
    FatReleaseVolumeGate(volume);
    return status;
}

static NTSTATUS FatVfsReadDirectory(PFILE_OBJECT file, ULONG *cursor, IO_DIR_ENTRY *entry)
{
    PFAT_VOLUME volume = FatFcbOf(file)->volume;
    FatAcquireVolumeGate(volume);
    NTSTATUS status = FatVfsReadDirectoryLocked(file, cursor, entry);
    FatReleaseVolumeGate(volume);
    return status;
}

static NTSTATUS FatVfsQueryVolumeInfo(PIO_DEVICE device, IO_VOLUME_INFO *info)
{
    PFAT_VOLUME volume = device->context;
    FatAcquireVolumeGate(volume);
    NTSTATUS status = FatVfsQueryVolumeInfoLocked(device, info);
    FatReleaseVolumeGate(volume);
    return status;
}

static NTSTATUS FatVfsSetVolumeLabel(PIO_DEVICE device, const WCHAR *label, ULONG labelBytes)
{
    PFAT_VOLUME volume = device->context;
    FatAcquireVolumeGate(volume);
    NTSTATUS status = FatVfsSetVolumeLabelLocked(device, label, labelBytes);
    FatReleaseVolumeGate(volume);
    return status;
}

const IO_VFS_OPS FatVfsOps = {
    .Create = FatVfsCreate,
    .Cleanup = FatVfsCleanup,
    .SectionsReleased = FatVfsSectionsReleased,
    .Close = FatVfsClose,
    .GetCache = FatVfsGetCache,
    .WritebackRange = FatVfsWritebackRange,
    .SetEndOfFile = FatVfsSetEndOfFile,
    .GetInfo = FatVfsGetInfo,
    .SetBasic = FatVfsSetBasic,
    .SetDisposition = FatVfsSetDisposition,
    .Rename = FatVfsRename,
    .ReadDirectory = FatVfsReadDirectory,
    .QueryName = FatVfsQueryName,
    .QueryVolumeInfo = FatVfsQueryVolumeInfo,
    .SetVolumeLabel = FatVfsSetVolumeLabel,
};
