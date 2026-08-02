/* fs/fat32/fat.c — mount (GPT + BPB), the FAT itself, cluster allocation,
 * FCB lifetime, and time conversion (see fat.h).
 *
 * Spec citations: "Microsoft FAT Specification" (Aug 30 2005, the fatgen103
 * successor) by section; UEFI Specification 2.10 §5 for GPT; Microsoft's
 * FILETIME documentation for the NT time epoch (100 ns intervals since
 * January 1, 1601, https://learn.microsoft.com/en-us/windows/win32/api/
 * minwinbase/ns-minwinbase-filetime).
 */
#include "fs/fat32/fat.h"
#include "kernel/io/io.h"
#include "drivers/virtio/blk.h"
#include "kernel/mm/pool.h"
#include "kernel/ke/ke.h"
#include "kernel/lib/le.h"
#include "kernel/lib/string.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/init/panic.h"
#include "abi/ntstatus.h"

/* --- the volume I/O gate (CUI-8, docs/20 R1) ------------------------------- */

void FatAcquireVolumeGate(PFAT_VOLUME volume)
{
    /* A dying thread's rundown still does real I/O (delete-on-close,
     * cleanup writeback); KiAcquireEventGate parks it as a QUEUED waiter
     * under the rundownWait exemption rather than spinning a try/yield
     * loop against the holder (which starves — see event.c). */
    KiAcquireEventGate(&volume->ioGate);
}

void FatReleaseVolumeGate(PFAT_VOLUME volume)
{
    ASSERT(KeReadStateEvent(&volume->ioGate) == 0); /* held: release must pair */
    KeSetEvent(&volume->ioGate, 0, FALSE);
}

/* --- sector I/O ------------------------------------------------------------ */

NTSTATUS FatReadSector(PFAT_VOLUME volume, uint64_t sector, void *buffer)
{
    return VioBlkReadSectors(volume->partitionFirstLba + sector, 1, buffer);
}

NTSTATUS FatWriteSector(PFAT_VOLUME volume, uint64_t sector, const void *buffer)
{
    return VioBlkWriteSectors(volume->partitionFirstLba + sector, 1, buffer);
}

NTSTATUS FatReadSectorsPhysical(PFAT_VOLUME volume, uint64_t sector, uint32_t sectorCount,
                                uint64_t physical)
{
    return VioBlkReadSectorsPhysical(volume->partitionFirstLba + sector, sectorCount, physical);
}

NTSTATUS FatWriteSectorsPhysical(PFAT_VOLUME volume, uint64_t sector, uint32_t sectorCount,
                                 uint64_t physical)
{
    return VioBlkWriteSectorsPhysical(volume->partitionFirstLba + sector, sectorCount, physical);
}

BOOLEAN FatIsDataCluster(PFAT_VOLUME volume, ULONG cluster)
{
    /* Cluster numbering starts at 2 and the last valid one is
     * clusterCount + 1 (spec §4). */
    return cluster >= 2 && cluster < volume->clusterCount + 2;
}

uint64_t FatClusterToSector(PFAT_VOLUME volume, ULONG cluster)
{
    /* FirstSectorofCluster = ((N-2) * BPB_SecPerClus) + FirstDataSector
     * (spec §6.7); cluster numbering starts at 2 (spec §4). This ASSERT is a
     * genuine kernel invariant rather than a check on disk contents: every
     * cluster number that reaches here has already been filtered by
     * FatIsDataCluster, at the point it was read off the volume. */
    ASSERT(FatIsDataCluster(volume, cluster));
    return (uint64_t)(cluster - 2) * volume->sectorsPerCluster + volume->firstDataSector;
}

/* --- the FAT --------------------------------------------------------------- */

ULONG FatGetNextCluster(PFAT_VOLUME volume, ULONG cluster)
{
    /* Both ends are checked, and both used to be assumed. The INPUT arrives
     * from a directory entry's DIR_FstClus, so a file whose entry names
     * 0x0FFFFFF0 tripped the old ASSERT and panicked the kernel on first
     * read; the RETURNED value is a raw FAT entry, equally attacker-chosen
     * on a crafted image, and it was handed straight back to a caller that
     * would index with it next time round (docs/review-2026-07 §4). An
     * out-of-range value on either side reads as end-of-chain -- the same
     * answer this already gives for the EOC and bad-cluster markers, which
     * every caller already handles. */
    if (!FatIsDataCluster(volume, cluster))
    {
        return 0;
    }
    ULONG value = volume->fat[cluster] & FAT_ENTRY_MASK; /* mask: spec §4.1 read code */
    if (value >= FAT_END_OF_CHAIN || value == 0x0FFFFFF7u /* bad cluster, spec §4 */)
    {
        return 0;
    }
    if (!FatIsDataCluster(volume, value))
    {
        return 0;
    }
    return value;
}

/* Write one FAT entry through to every FAT copy on disk (spec §4: FAT
 * mirroring is the default; BPB_ExtFlags mirroring-off is not supported —
 * mformat images mirror). */
NTSTATUS FatSetFatEntry(PFAT_VOLUME volume, ULONG cluster, ULONG value)
{
    ASSERT(FatIsDataCluster(volume, cluster));
    /* The free count is maintained HERE, at the single site that changes a
     * FAT entry, rather than rescanned: FSInfo is rewritten on every
     * allocation and every chain release, and an O(clusterCount) scan per
     * cluster made the boot itself too slow to finish. */
    BOOLEAN wasFree = (volume->fat[cluster] & FAT_ENTRY_MASK) == 0;
    BOOLEAN nowFree = (value & FAT_ENTRY_MASK) == 0;
    if (wasFree && !nowFree)
    {
        volume->freeClusters--;
    }
    else if (!wasFree && nowFree)
    {
        volume->freeClusters++;
    }
    /* Preserve the reserved high 4 bits (spec §4.1 write code). */
    volume->fat[cluster] = (volume->fat[cluster] & 0xF0000000u) | (value & FAT_ENTRY_MASK);

    /* FATOffset = N * 4; sector = RsvdSecCnt + FATOffset / BytsPerSec
     * (spec §4.1). Write the containing sector to each FAT copy. */
    ULONG fatOffset = cluster * 4;
    ULONG sectorInFat = fatOffset / volume->bytesPerSector;
    const unsigned char *sectorData =
        (const unsigned char *)volume->fat + (uint64_t)sectorInFat * volume->bytesPerSector;
    for (ULONG copy = 0; copy < volume->fatCount; copy++)
    {
        NTSTATUS status = FatWriteSector(
            volume, volume->reservedSectors + (uint64_t)copy * volume->fatSizeSectors + sectorInFat,
            sectorData);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }
    return STATUS_SUCCESS;
}

/* Rewrite the FSInfo sector's free-cluster count and next-free hint (spec
 * §5: FSI_LeadSig 0x41615252 at 0, FSI_StrucSig 0x61417272 at 484,
 * FSI_Free_Count at 488, FSI_Nxt_Free at 492, FSI_TrailSig 0xAA550000 at
 * 508). It was never read OR written, so free-space reports from Windows and
 * mtools were stale after proskrnl wrote anything
 * (docs/review-2026-07 §12).
 *
 * Best effort by design: FSInfo is a HINT, and the authoritative free count
 * is the FAT itself, which FatQueryVolumeInfo already counts live. A failure
 * here must not fail the allocation that triggered it. */
void FatUpdateFsInfo(PFAT_VOLUME volume)
{
    if (volume->fsInfoSector == 0)
    {
        return;
    }
    unsigned char sector[FAT_SECTOR_SIZE];
    if (!NT_SUCCESS(FatReadSector(volume, volume->fsInfoSector, sector)))
    {
        return;
    }
    if (KiReadLe32(sector) != 0x41615252u || KiReadLe32(sector + 484) != 0x61417272u ||
        KiReadLe32(sector + 508) != 0xAA550000u)
    {
        volume->fsInfoSector = 0; /* not an FSInfo sector after all */
        return;
    }
    KiWriteLe32(sector + 488, volume->freeClusters);
    KiWriteLe32(sector + 492, volume->nextFreeHint);
    (void)FatWriteSector(volume, volume->fsInfoSector, sector);
}

NTSTATUS FatAllocateCluster(PFAT_VOLUME volume, ULONG previousOrZero, ULONG *clusterOut)
{
    ULONG total = volume->clusterCount;
    ULONG candidate = volume->nextFreeHint;
    for (ULONG scanned = 0; scanned < total; scanned++)
    {
        if (candidate < 2 || candidate >= total + 2)
        {
            candidate = 2;
        }
        if ((volume->fat[candidate] & FAT_ENTRY_MASK) == 0) /* free (spec §4) */
        {
            NTSTATUS status = FatSetFatEntry(volume, candidate, FAT_ENTRY_MASK); /* EOC */
            if (NT_SUCCESS(status) && previousOrZero != 0)
            {
                status = FatSetFatEntry(volume, previousOrZero, candidate);
            }
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            volume->nextFreeHint = candidate + 1;
            *clusterOut = candidate;
            FatUpdateFsInfo(volume);
            return STATUS_SUCCESS;
        }
        candidate++;
    }
    return STATUS_DISK_FULL;
}

NTSTATUS FatFreeChain(PFAT_VOLUME volume, ULONG firstCluster)
{
    /* Returns a status now. It was `void` and swallowed every
     * FatSetFatEntry failure, so a write error while releasing a chain --
     * which leaves the FAT and the file's metadata disagreeing on disk --
     * was invisible to every caller (docs/review-2026-07 §12). The walk
     * continues past a failure so the rest of the chain is still released,
     * and the FIRST failure is what comes back. */
    NTSTATUS result = STATUS_SUCCESS;
    ULONG cluster = firstCluster;
    BOOLEAN freedAny = FALSE;
    while (FatIsDataCluster(volume, cluster))
    {
        ULONG next = FatGetNextCluster(volume, cluster);
        NTSTATUS status = FatSetFatEntry(volume, cluster, 0);
        if (!NT_SUCCESS(status) && NT_SUCCESS(result))
        {
            result = status;
        }
        freedAny = TRUE;
        cluster = next;
    }
    if (freedAny)
    {
        FatUpdateFsInfo(volume);
    }
    return result;
}

/* Every chain walk in the filesystem is bounded by the number of clusters on
 * the volume, because a chain longer than that has revisited one -- i.e. it
 * is cyclic. A crafted image with a cyclic chain otherwise hangs the kernel
 * FOREVER: uniprocessor, no preemption, and the walk never blocks, so
 * nothing else ever runs again (docs/review-2026-07 §4). Reaching the bound
 * ends the walk as if the chain ended, which is what every caller of these
 * primitives already copes with; there is no repair to attempt here and no
 * caller that could act on a distinct status. */
ULONG FatWalkChain(PFAT_VOLUME volume, ULONG firstCluster, ULONG index)
{
    ULONG cluster = firstCluster;
    ULONG steps = 0;
    while (index != 0 && cluster != 0)
    {
        if (steps++ > volume->clusterCount)
        {
            return 0; /* cyclic chain */
        }
        cluster = FatGetNextCluster(volume, cluster);
        index--;
    }
    return cluster;
}

ULONG FatChainLength(PFAT_VOLUME volume, ULONG firstCluster)
{
    ULONG count = 0;
    ULONG cluster = firstCluster;
    while (cluster != 0)
    {
        count++;
        cluster = FatGetNextCluster(volume, cluster);
        if (count > volume->clusterCount)
        {
            /* Was a KiPanic. A cyclic chain is a property of the MEDIA, not
             * of the kernel, and mounting a crafted image must not halt the
             * machine. */
            break;
        }
    }
    return count;
}

/* --- FCB lifetime ---------------------------------------------------------- */

void FatReferenceFcb(PFAT_FCB fcb)
{
    fcb->referenceCount++;
}

void FatDereferenceFcb(PFAT_FCB fcb)
{
    ASSERT(fcb->referenceCount > 0);
    if (--fcb->referenceCount != 0)
    {
        return;
    }
    ASSERT(!fcb->isRoot); /* the root holds a permanent self-reference */
    ASSERT(fcb->header.shareAccess.openCount == 0);
    RemoveEntryList(&fcb->volumeEntry);
    MiDeletePageCache(&fcb->cache);
    if (fcb->longName.Buffer != 0)
    {
        MiFreePool(fcb->longName.Buffer);
    }
    PFAT_FCB parent = fcb->parent;
    MiFreePool(fcb);
    if (parent != 0)
    {
        FatDereferenceFcb(parent);
    }
}

NTSTATUS FatGetFcb(PFAT_FCB dir, ULONG sfnSlot, ULONG lfnStartSlot, const unsigned char sfn[32],
                   const UNICODE_STRING *longName, PFAT_FCB *out)
{
    PFAT_VOLUME volume = dir->volume;

    /* One FCB per on-disk file: identity = (directory cluster, SFN slot).
     * A slot index is stable for the file's lifetime — deletion marks 0xE5
     * in place, never compacts (spec §6.1). */
    ULONG dirCluster = FatDirCluster(dir);
    for (PLIST_ENTRY entry = volume->fcbList.Flink; entry != &volume->fcbList; entry = entry->Flink)
    {
        PFAT_FCB fcb = CONTAINING_RECORD(entry, FAT_FCB, volumeEntry);
        if (fcb->parentDirCluster == dirCluster && fcb->dirEntryIndex == sfnSlot && !fcb->isRoot &&
            !fcb->entryDeleted)
        {
            FatReferenceFcb(fcb);
            *out = fcb;
            return STATUS_SUCCESS;
        }
    }

    PFAT_FCB fcb = MiAllocatePool(sizeof(FAT_FCB));
    if (fcb == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    IopInitializeFcb(&fcb->header);
    fcb->volume = volume;
    fcb->referenceCount = 1;
    fcb->parent = dir;
    FatReferenceFcb(dir);
    fcb->isRoot = FALSE;
    fcb->parentDirCluster = dirCluster;
    fcb->dirEntryIndex = sfnSlot;
    fcb->lfnStartIndex = lfnStartSlot;
    /* Fields per the spec §6 directory-entry layout. */
    fcb->attributes = sfn[11];
    fcb->isDirectory = (sfn[11] & FAT_ATTR_DIRECTORY) != 0;
    fcb->createTimeTenth = sfn[13];
    fcb->createTime = KiReadLe16(sfn + 14);
    fcb->createDate = KiReadLe16(sfn + 16);
    fcb->accessDate = KiReadLe16(sfn + 18);
    fcb->writeTime = KiReadLe16(sfn + 22);
    fcb->writeDate = KiReadLe16(sfn + 24);
    fcb->firstCluster = ((ULONG)KiReadLe16(sfn + 20) << 16) | KiReadLe16(sfn + 26);
    /* An entry naming a cluster off the volume is a corrupt entry; treat it
     * as the empty chain (which 0 already means here) rather than letting it
     * reach FatClusterToSector's ASSERT. */
    if (fcb->firstCluster != 0 && !FatIsDataCluster(dir->volume, fcb->firstCluster))
    {
        fcb->firstCluster = 0;
    }
    fcb->fileSize = KiReadLe32(sfn + 28);
    MiInitializePageCache(&fcb->cache);
    fcb->cacheLoaded = FALSE;
    fcb->openObjectCount = 0;
    fcb->unlinkPending = FALSE;
    fcb->entryDeleted = FALSE;

    PWSTR nameCopy = MiAllocatePool(longName->Length);
    if (nameCopy == 0)
    {
        FatDereferenceFcb(dir);
        MiFreePool(fcb);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memcpy(nameCopy, longName->Buffer, longName->Length);
    fcb->longName.Buffer = nameCopy;
    fcb->longName.Length = longName->Length;
    fcb->longName.MaximumLength = longName->Length;

    InsertTailList(&volume->fcbList, &fcb->volumeEntry);
    *out = fcb;
    return STATUS_SUCCESS;
}

/* --- time ------------------------------------------------------------------ */

static const USHORT FatDaysPerMonth[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

static int FatIsLeapYear(int year)
{
    return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

/* Days from 1601-01-01 (the NT epoch — MS FILETIME documentation) to
 * year-month-day, computed by calendar arithmetic (no recalled constants). */
static uint64_t FatDaysSinceNtEpoch(int year, int month, int day)
{
    uint64_t days = 0;
    for (int y = 1601; y < year; y++)
    {
        days += FatIsLeapYear(y) ? 366 : 365;
    }
    for (int m = 1; m < month; m++)
    {
        days += FatDaysPerMonth[m - 1];
        if (m == 2 && FatIsLeapYear(year))
        {
            days += 1;
        }
    }
    return days + (uint64_t)(day - 1);
}

#define FAT_100NS_PER_SECOND 10000000ULL

LARGE_INTEGER FatTimeToNtTime(USHORT fatDate, USHORT fatTime, UCHAR tenths)
{
    LARGE_INTEGER result;
    if (fatDate == 0)
    {
        result.QuadPart = 0;
        return result;
    }
    /* Date: day 4:0 (1..31), month 8:5 (1..12), year-since-1980 15:9;
     * time: 2-second count 4:0, minutes 10:5, hours 15:11 (spec §6.3). */
    int day = fatDate & 0x1F;
    int month = (fatDate >> 5) & 0x0F;
    int year = 1980 + ((fatDate >> 9) & 0x7F);
    int seconds = (fatTime & 0x1F) * 2;
    int minutes = (fatTime >> 5) & 0x3F;
    int hours = (fatTime >> 11) & 0x1F;
    if (month < 1 || month > 12 || day < 1)
    {
        result.QuadPart = 0;
        return result;
    }
    uint64_t totalSeconds = FatDaysSinceNtEpoch(year, month, day) * 86400ULL +
                            (uint64_t)hours * 3600 + (uint64_t)minutes * 60 + (uint64_t)seconds;
    result.QuadPart =
        (LONGLONG)(totalSeconds * FAT_100NS_PER_SECOND + (uint64_t)tenths * 1000000ULL);
    return result;
}

void FatNtTimeToFatTime(LARGE_INTEGER ntTime, USHORT *fatDate, USHORT *fatTime)
{
    uint64_t totalSeconds = (uint64_t)ntTime.QuadPart / FAT_100NS_PER_SECOND;
    uint64_t days = totalSeconds / 86400;
    uint64_t daySeconds = totalSeconds % 86400;

    int year = 1601;
    for (;;)
    {
        uint64_t inYear = FatIsLeapYear(year) ? 366 : 365;
        if (days < inYear)
        {
            break;
        }
        days -= inYear;
        year++;
    }
    int month = 1;
    for (;;)
    {
        uint64_t inMonth = FatDaysPerMonth[month - 1] + (month == 2 && FatIsLeapYear(year) ? 1 : 0);
        if (days < inMonth)
        {
            break;
        }
        days -= inMonth;
        month++;
    }
    int day = (int)days + 1;

    if (year < 1980)
    {
        /* Below the FAT epoch (spec §6.3: years count from 1980). */
        year = 1980;
        month = 1;
        day = 1;
        daySeconds = 0;
    }
    if (year > 2107)
    {
        year = 2107; /* spec §6.3: 7-bit year, 1980..2107 */
    }
    *fatDate = (USHORT)((day & 0x1F) | ((month & 0x0F) << 5) | (((year - 1980) & 0x7F) << 9));
    *fatTime = (USHORT)((ULONG)(daySeconds % 60) / 2 | (((ULONG)(daySeconds / 60) % 60) << 5) |
                        (((ULONG)(daySeconds / 3600)) << 11));
}

LARGE_INTEGER FatCurrentNtTime(void)
{
    /* The system clock, CMOS-RTC-seeded at boot (CUI-1, kernel/ke/timer.c):
     * real wall-clock UTC under QEMU's default -rtc base=utc. */
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    return now;
}

/* --- mount ----------------------------------------------------------------- */

/* Find the first GPT data partition that is not the BIOS-boot stage.
 * UEFI 2.10 §5.3.2 (header at LBA 1, signature "EFI PART"), §5.3.3
 * (128-byte entries; zero TypeGUID = unused). CRCs are not verified — the
 * image was written moments ago by tools/mkimage.sh; a torn header fails
 * the signature check loudly instead. */
static NTSTATUS FatFindDataPartition(uint64_t *firstLbaOut)
{
    unsigned char sector[FAT_SECTOR_SIZE];
    NTSTATUS status = VioBlkReadSectors(1, 1, sector);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* Signature: ASCII "EFI PART" = 64-bit 0x5452415020494645 (UEFI 2.10
     * Table 5.5). */
    if (KiReadLe64(sector + 0) != 0x5452415020494645ULL)
    {
        return STATUS_UNRECOGNIZED_VOLUME;
    }
    uint64_t entryArrayLba = KiReadLe64(sector + 72);
    uint32_t entryCount = KiReadLe32(sector + 80);
    uint32_t entrySize = KiReadLe32(sector + 84);
    if (entrySize < 128 || entrySize > FAT_SECTOR_SIZE)
    {
        return STATUS_UNRECOGNIZED_VOLUME;
    }

    /* BIOS boot partition GUID 21686148-6449-6E6F-744E-656564454649 (GNU
     * GRUB manual, "BIOS installation") in the UEFI Appendix A mixed-endian
     * on-disk order. */
    static const unsigned char biosBootGuid[16] = {0x48, 0x61, 0x68, 0x21, 0x49, 0x64, 0x6F, 0x6E,
                                                   0x74, 0x4E, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49};
    static const unsigned char zeroGuid[16] = {0};

    ULONG perSector = FAT_SECTOR_SIZE / entrySize;
    for (uint32_t index = 0; index < entryCount; index++)
    {
        if (index % perSector == 0)
        {
            status = VioBlkReadSectors(entryArrayLba + index / perSector, 1, sector);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
        }
        const unsigned char *entry = sector + (index % perSector) * entrySize;
        if (memcmp(entry, zeroGuid, 16) == 0) /* unused (UEFI Table 5.6) */
        {
            continue;
        }
        if (memcmp(entry, biosBootGuid, 16) == 0)
        {
            continue;
        }
        *firstLbaOut = KiReadLe64(entry + 32); /* StartingLBA (UEFI Table 5.6) */
        return STATUS_SUCCESS;
    }
    return STATUS_UNRECOGNIZED_VOLUME;
}

/* Every bound the rest of fs/fat32 relies on is derived here, from a boot
 * sector the volume author controls. Anything that gets through becomes an
 * ASSERT precondition elsewhere -- FatGetNextCluster, FatSetFatEntry and
 * FatClusterToSector all assert `cluster < clusterCount + 2` -- so a
 * clusterCount that does not match the FAT actually read from disk turns
 * those asserts into no-ops and lets attacker-chosen indices run off the
 * end of volume->fat, for writes as well as reads.
 *
 * Field offsets and the FAT-type rule are FAT spec §3.1/§3.3/§3.5
 * (Microsoft "FAT32 File System Specification" 1.03). */
NTSTATUS FatValidateBpb(const unsigned char *boot, PFAT_BPB_GEOMETRY out)
{
    ULONG bytesPerSector = KiReadLe16(boot + 11);
    ULONG sectorsPerCluster = boot[13];
    ULONG reservedSectors = KiReadLe16(boot + 14);
    ULONG fatCount = boot[16];
    ULONG rootEntryCount = KiReadLe16(boot + 17);
    ULONG totalSectors16 = KiReadLe16(boot + 19);
    ULONG fatSize16 = KiReadLe16(boot + 22);
    ULONG totalSectors32 = KiReadLe32(boot + 32);
    ULONG fatSize32 = KiReadLe32(boot + 36);
    ULONG rootCluster = KiReadLe32(boot + 44);

    if (bytesPerSector != FAT_SECTOR_SIZE || sectorsPerCluster == 0 || reservedSectors == 0 ||
        fatCount == 0)
    {
        return STATUS_UNRECOGNIZED_VOLUME;
    }
    /* §3.1 BPB_SecPerClus: a power of two greater than 0, and small enough
     * that the cluster stays inside the spec's 32 KB ceiling -- 128 sectors
     * at the 512-byte sector size required above. Anything else makes the
     * cluster<->sector mapping below meaningless. */
    if (sectorsPerCluster > 128 || (sectorsPerCluster & (sectorsPerCluster - 1)) != 0)
    {
        return STATUS_UNRECOGNIZED_VOLUME;
    }

    /* FAT type is determined SOLELY by the cluster count (spec §3.5). */
    ULONG fatSize = fatSize16 != 0 ? fatSize16 : fatSize32;
    ULONG totalSectors = totalSectors16 != 0 ? totalSectors16 : totalSectors32;
    if (fatSize == 0 || totalSectors == 0)
    {
        /* A zero fatSize would also reach MiAllocatePool(0), which panics. */
        return STATUS_UNRECOGNIZED_VOLUME;
    }
    ULONG rootDirSectors =
        (rootEntryCount * 32 + bytesPerSector - 1) / bytesPerSector; /* 0 on FAT32 */

    /* firstDataSector in 64-bit, so a large fatCount * fatSize cannot wrap
     * into a small in-range value before the comparison below. */
    uint64_t firstDataSector64 =
        (uint64_t)reservedSectors + (uint64_t)fatCount * fatSize + rootDirSectors;
    if (firstDataSector64 >= totalSectors)
    {
        /* Otherwise totalSectors - firstDataSector underflows and yields a
         * near-4-billion cluster count for a tiny volume. */
        return STATUS_UNRECOGNIZED_VOLUME;
    }
    ULONG firstDataSector = (ULONG)firstDataSector64;
    ULONG dataSectors = totalSectors - firstDataSector;
    ULONG clusterCount = dataSectors / sectorsPerCluster;
    if (clusterCount < 65525)
    {
        DbgPrint("fat32: volume is FAT12/16 (%lu clusters) — not supported\n",
                 (unsigned long)clusterCount);
        return STATUS_UNRECOGNIZED_VOLUME;
    }

    /* The FAT must actually be able to describe every cluster it claims: the
     * table holds fatSize * bytesPerSector / 4 32-bit entries, and entries 0
     * and 1 are reserved, so the highest valid index is clusterCount + 1.
     * This is the invariant FatQueryVolumeInfo already asserted at use time;
     * checking it at mount is what makes that assert unreachable. */
    uint64_t fatEntries = ((uint64_t)fatSize * bytesPerSector) / sizeof(ULONG);
    if ((uint64_t)clusterCount + 2 > fatEntries)
    {
        return STATUS_UNRECOGNIZED_VOLUME;
    }

    /* The root directory must start at a real data cluster. */
    if (rootCluster < 2 || rootCluster >= clusterCount + 2)
    {
        return STATUS_UNRECOGNIZED_VOLUME;
    }

    out->bytesPerSector = bytesPerSector;
    out->sectorsPerCluster = sectorsPerCluster;
    out->reservedSectors = reservedSectors;
    out->fatCount = fatCount;
    out->fatSizeSectors = fatSize;
    out->totalSectors = totalSectors;
    out->firstDataSector = firstDataSector;
    out->clusterCount = clusterCount;
    out->rootCluster = rootCluster;
    return STATUS_SUCCESS;
}

NTSTATUS FatMountBootVolume(PFAT_VOLUME *volumeOut)
{
    uint64_t partitionLba;
    NTSTATUS status = FatFindDataPartition(&partitionLba);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    unsigned char boot[FAT_SECTOR_SIZE];
    status = VioBlkReadSectors(partitionLba, 1, boot);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* Boot-sector signature 0x55 at 510, 0xAA at 511 (spec §3.3). */
    if (boot[510] != 0x55 || boot[511] != 0xAA)
    {
        return STATUS_UNRECOGNIZED_VOLUME;
    }

    FAT_BPB_GEOMETRY geometry;
    status = FatValidateBpb(boot, &geometry);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    ULONG bytesPerSector = geometry.bytesPerSector;
    ULONG sectorsPerCluster = geometry.sectorsPerCluster;
    ULONG reservedSectors = geometry.reservedSectors;
    ULONG fatCount = geometry.fatCount;
    ULONG fatSize = geometry.fatSizeSectors;
    ULONG totalSectors = geometry.totalSectors;
    ULONG firstDataSector = geometry.firstDataSector;
    ULONG clusterCount = geometry.clusterCount;
    ULONG rootCluster = geometry.rootCluster;

    PFAT_VOLUME volume = MiAllocatePool(sizeof(FAT_VOLUME));
    if (volume == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    volume->partitionFirstLba = partitionLba;
    volume->bytesPerSector = bytesPerSector;
    volume->sectorsPerCluster = sectorsPerCluster;
    volume->reservedSectors = reservedSectors;
    volume->fatCount = fatCount;
    volume->fatSizeSectors = fatSize;
    volume->rootCluster = rootCluster;
    volume->totalSectors = totalSectors;
    volume->firstDataSector = firstDataSector;
    volume->clusterCount = clusterCount;
    volume->nextFreeHint = 2;
    /* BPB_FSInfo (spec §3.3, offset 48): the sector holding the free-cluster
     * count and the next-free hint. 0 and 0xFFFF both mean "absent"
     * (§3.5 / §4). */
    volume->fsInfoSector = KiReadLe16(boot + 48);
    if (volume->fsInfoSector == 0 || volume->fsInfoSector == 0xFFFF ||
        volume->fsInfoSector >= reservedSectors)
    {
        volume->fsInfoSector = 0; /* no usable FSInfo on this volume */
    }
    InitializeListHead(&volume->fcbList);
    /* Born signalled: the gate is free until its first holder (CUI-8). */
    KeInitializeEvent(&volume->ioGate, SynchronizationEvent, TRUE);

    /* Volume identity for the FileFs* classes: BS_VolID at 67, BS_VolLab at
     * 71 (11 OEM chars, space-padded) — spec §3.3 FAT32 boot sector; same
     * offsets Wine's mountmgr reads for a FAT32 superblock (0x43/0x47,
     * dlls/mountmgr.sys/device.c VOLUME_GetSuperblock{Serial,Label}).
     * "NO NAME    " is the spec's no-label sentinel (§3.3 BS_VolLab). */
    volume->volumeSerial = KiReadLe32(boot + 67);
    ULONG labelUnits = 11;
    while (labelUnits > 0 && (boot[71 + labelUnits - 1] == ' ' || boot[71 + labelUnits - 1] == 0))
    {
        labelUnits--;
    }
    if (labelUnits == 7 && memcmp(boot + 71, "NO NAME", 7) == 0)
    {
        labelUnits = 0;
    }
    for (ULONG i = 0; i < labelUnits; i++)
    {
        volume->volumeLabel[i] = (WCHAR)boot[71 + i];
    }
    volume->volumeLabelLength = (USHORT)(labelUnits * sizeof(WCHAR));

    /* The whole (first) FAT in pool; every entry write goes through to all
     * copies (FatSetFatEntry). */
    volume->fat = MiAllocatePool((uint64_t)fatSize * bytesPerSector);
    if (volume->fat == 0)
    {
        MiFreePool(volume);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    for (ULONG sector = 0; sector < fatSize; sector++)
    {
        status = FatReadSector(volume, reservedSectors + sector,
                               (unsigned char *)volume->fat + (uint64_t)sector * bytesPerSector);
        if (!NT_SUCCESS(status))
        {
            MiFreePool(volume->fat);
            MiFreePool(volume);
            return status;
        }
    }

    /* Count the free clusters ONCE, at mount; FatSetFatEntry keeps it
     * current from here (see there). */
    volume->freeClusters = 0;
    for (ULONG cluster = 2; cluster < clusterCount + 2; cluster++)
    {
        if ((volume->fat[cluster] & FAT_ENTRY_MASK) == 0)
        {
            volume->freeClusters++;
        }
    }

    /* The root FCB: no directory entry of its own, no times, no size
     * (spec §6.6). It lives forever (one permanent self-reference). */
    PFAT_FCB root = MiAllocatePool(sizeof(FAT_FCB));
    if (root == 0)
    {
        MiFreePool(volume->fat);
        MiFreePool(volume);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    IopInitializeFcb(&root->header);
    root->volume = volume;
    root->referenceCount = 1;
    root->parent = 0;
    root->isDirectory = TRUE;
    root->isRoot = TRUE;
    root->parentDirCluster = 0;
    root->dirEntryIndex = 0;
    root->lfnStartIndex = 0;
    root->firstCluster = rootCluster;
    root->fileSize = 0;
    root->attributes = FAT_ATTR_DIRECTORY;
    root->writeTime = root->writeDate = 0;
    root->createTime = root->createDate = 0;
    root->createTimeTenth = 0;
    root->accessDate = 0;
    root->longName.Buffer = 0;
    root->longName.Length = 0;
    root->longName.MaximumLength = 0;
    MiInitializePageCache(&root->cache);
    root->cacheLoaded = FALSE;
    root->openObjectCount = 0;
    root->unlinkPending = FALSE;
    root->entryDeleted = FALSE;
    InsertTailList(&volume->fcbList, &root->volumeEntry);
    volume->root = root;

    DbgPrint("fat32: mounted at LBA %lu, %lu clusters of %lu bytes\n", (unsigned long)partitionLba,
             (unsigned long)clusterCount, (unsigned long)(sectorsPerCluster * bytesPerSector));
    *volumeOut = volume;
    return STATUS_SUCCESS;
}

/* CUI-5: NtSetVolumeInformationFile(FileFsLabelInformation). NT's FAT
 * driver is the contract (fastfat volinfo.c FatSetFsLabelInfo — the pinned
 * Wine's set-volume-info is an unconditional-success stub); the write-back
 * is pinned beyond_oracle by sem_file/ea_volume.c. The label lands in
 * BS_VolLab (spec §3.3, offset 71) and in the root directory's volume-id
 * entry when one exists (spec §6.2), stored upper-case OEM space-padded
 * (spec §6.1); an empty label writes the spec's "NO NAME    " sentinel. */
NTSTATUS FatSetVolumeLabel(PFAT_VOLUME volume, const WCHAR *label, ULONG labelBytes)
{
    ULONG units = labelBytes / sizeof(WCHAR);
    if (units > 11)
    {
        return STATUS_INVALID_VOLUME_LABEL;
    }
    unsigned char oem[11];
    memset(oem, ' ', sizeof(oem));
    for (ULONG i = 0; i < units; i++)
    {
        WCHAR c = label[i];
        if (c < 0x20 || c > 0x7E)
        {
            return STATUS_INVALID_VOLUME_LABEL; /* OEM-representable only */
        }
        if (c >= 'a' && c <= 'z')
        {
            c = (WCHAR)(c - 'a' + 'A');
        }
        oem[i] = (unsigned char)c;
    }
    if (units == 0)
    {
        memcpy(oem, "NO NAME    ", 11);
    }

    unsigned char boot[FAT_SECTOR_SIZE];
    NTSTATUS status = FatReadSector(volume, 0, boot);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    memcpy(boot + 71, oem, 11);
    status = FatWriteSector(volume, 0, boot);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    for (ULONG slot = 0;; slot++)
    {
        unsigned char entry[32];
        status = FatReadDirSlot(volume->root, slot, entry);
        if (status == STATUS_NO_MORE_FILES)
        {
            break;
        }
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (entry[0] == 0x00)
        {
            break;
        }
        if (entry[0] == 0xE5 || (entry[11] & FAT_ATTR_LONG_NAME_MASK) == FAT_ATTR_LONG_NAME)
        {
            continue;
        }
        if (entry[11] & FAT_ATTR_VOLUME_ID)
        {
            memcpy(entry, oem, 11);
            status = FatWriteDirSlot(volume->root, slot, entry);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            break;
        }
    }

    ULONG served = units;
    if (units == 0)
    {
        served = 0;
    }
    for (ULONG i = 0; i < served; i++)
    {
        volume->volumeLabel[i] = (WCHAR)oem[i];
    }
    volume->volumeLabelLength = (USHORT)(served * sizeof(WCHAR));
    return STATUS_SUCCESS;
}

NTSTATUS FatQueryVolumeInfo(PFAT_VOLUME volume, IO_VOLUME_INFO *info)
{
    ASSERT(volume->clusterCount + 2 <= volume->fatSizeSectors * volume->bytesPerSector / 4);

    /* Count free clusters off the in-pool FAT (a pure memory sweep: no
     * blocking, so it is atomic under the no-preemption model). Entry 0 =
     * free (spec §4); data clusters are 2 .. CountofClusters+1 (§3.5). */
    uint64_t freeCount = 0;
    for (ULONG cluster = 2; cluster < volume->clusterCount + 2; cluster++)
    {
        if ((volume->fat[cluster] & FAT_ENTRY_MASK) == 0)
        {
            freeCount++;
        }
    }

    info->serialNumber = volume->volumeSerial;
    info->labelLength = volume->volumeLabelLength;
    memcpy(info->label, volume->volumeLabel, volume->volumeLabelLength);
    info->totalUnits = volume->clusterCount;
    info->freeUnits = freeCount;
    info->sectorsPerUnit = volume->sectorsPerCluster;
    info->bytesPerSector = volume->bytesPerSector;
    /* The FileFsAttributeInformation answer for a FAT32 volume, exactly as
     * the pinned Wine reports it (dlls/ntdll/unix/file.c
     * NtQueryVolumeInformationFile, MOUNTMGR_FS_TYPE_FAT32 branch):
     * case-preserving, 255-unit components, not an object-id filesystem. */
    info->fsName = WSTR("FAT32");
    info->fsNameLength = 5 * sizeof(WCHAR);
    info->fsAttributes = FILE_CASE_PRESERVED_NAMES;
    info->maxComponentLength = 255;
    info->supportsObjects = FALSE;
    return STATUS_SUCCESS;
}
