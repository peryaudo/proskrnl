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
#include "kernel/lib/string.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/init/panic.h"
#include "abi/ntstatus.h"

/* --- little-endian field readers (the disk format is little-endian and so
 * is x86-64, but unaligned loads through memcpy keep UBSan quiet) --------- */
static uint16_t FatRead16(const unsigned char *p)
{
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}
static uint32_t FatRead32(const unsigned char *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}
static uint64_t FatRead64(const unsigned char *p)
{
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
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

uint64_t FatClusterToSector(PFAT_VOLUME volume, ULONG cluster)
{
    /* FirstSectorofCluster = ((N-2) * BPB_SecPerClus) + FirstDataSector
     * (spec §6.7); cluster numbering starts at 2 (spec §4). */
    ASSERT(cluster >= 2 && cluster < volume->clusterCount + 2);
    return (uint64_t)(cluster - 2) * volume->sectorsPerCluster + volume->firstDataSector;
}

/* --- the FAT --------------------------------------------------------------- */

ULONG FatGetNextCluster(PFAT_VOLUME volume, ULONG cluster)
{
    ASSERT(cluster >= 2 && cluster < volume->clusterCount + 2);
    ULONG value = volume->fat[cluster] & FAT_ENTRY_MASK; /* mask: spec §4.1 read code */
    if (value >= FAT_END_OF_CHAIN || value == 0x0FFFFFF7u /* bad cluster, spec §4 */)
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
    ASSERT(cluster >= 2 && cluster < volume->clusterCount + 2);
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
            return STATUS_SUCCESS;
        }
        candidate++;
    }
    return STATUS_DISK_FULL;
}

void FatFreeChain(PFAT_VOLUME volume, ULONG firstCluster)
{
    ULONG cluster = firstCluster;
    while (cluster >= 2 && cluster < volume->clusterCount + 2)
    {
        ULONG next = FatGetNextCluster(volume, cluster);
        FatSetFatEntry(volume, cluster, 0);
        cluster = next;
    }
}

ULONG FatWalkChain(PFAT_VOLUME volume, ULONG firstCluster, ULONG index)
{
    ULONG cluster = firstCluster;
    while (index != 0 && cluster != 0)
    {
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
            KiPanic("fat32: cluster chain loop");
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
        if (fcb->parentDirCluster == dirCluster && fcb->dirEntryIndex == sfnSlot && !fcb->isRoot)
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
    fcb->createTime = FatRead16(sfn + 14);
    fcb->createDate = FatRead16(sfn + 16);
    fcb->accessDate = FatRead16(sfn + 18);
    fcb->writeTime = FatRead16(sfn + 22);
    fcb->writeDate = FatRead16(sfn + 24);
    fcb->firstCluster = ((ULONG)FatRead16(sfn + 20) << 16) | FatRead16(sfn + 26);
    fcb->fileSize = FatRead32(sfn + 28);
    MiInitializePageCache(&fcb->cache);
    fcb->cacheLoaded = FALSE;
    fcb->openObjectCount = 0;
    fcb->unlinkPending = FALSE;

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
    if (FatRead64(sector + 0) != 0x5452415020494645ULL)
    {
        return STATUS_UNRECOGNIZED_VOLUME;
    }
    uint64_t entryArrayLba = FatRead64(sector + 72);
    uint32_t entryCount = FatRead32(sector + 80);
    uint32_t entrySize = FatRead32(sector + 84);
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
        *firstLbaOut = FatRead64(entry + 32); /* StartingLBA (UEFI Table 5.6) */
        return STATUS_SUCCESS;
    }
    return STATUS_UNRECOGNIZED_VOLUME;
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

    /* BPB fields by offset (spec §3.1/§3.3). */
    ULONG bytesPerSector = FatRead16(boot + 11);
    ULONG sectorsPerCluster = boot[13];
    ULONG reservedSectors = FatRead16(boot + 14);
    ULONG fatCount = boot[16];
    ULONG rootEntryCount = FatRead16(boot + 17);
    ULONG totalSectors16 = FatRead16(boot + 19);
    ULONG fatSize16 = FatRead16(boot + 22);
    ULONG totalSectors32 = FatRead32(boot + 32);
    ULONG fatSize32 = FatRead32(boot + 36);
    ULONG rootCluster = FatRead32(boot + 44);

    if (bytesPerSector != FAT_SECTOR_SIZE || sectorsPerCluster == 0 || reservedSectors == 0 ||
        fatCount == 0)
    {
        return STATUS_UNRECOGNIZED_VOLUME;
    }

    /* FAT type is determined SOLELY by the cluster count (spec §3.5). */
    ULONG fatSize = fatSize16 != 0 ? fatSize16 : fatSize32;
    ULONG totalSectors = totalSectors16 != 0 ? totalSectors16 : totalSectors32;
    ULONG rootDirSectors =
        (rootEntryCount * 32 + bytesPerSector - 1) / bytesPerSector; /* 0 on FAT32 */
    ULONG firstDataSector = reservedSectors + fatCount * fatSize + rootDirSectors;
    ULONG dataSectors = totalSectors - firstDataSector;
    ULONG clusterCount = dataSectors / sectorsPerCluster;
    if (clusterCount < 65525)
    {
        DbgPrint("fat32: volume is FAT12/16 (%lu clusters) — not supported\n",
                 (unsigned long)clusterCount);
        return STATUS_UNRECOGNIZED_VOLUME;
    }

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
    InitializeListHead(&volume->fcbList);

    /* Volume identity for the FileFs* classes: BS_VolID at 67, BS_VolLab at
     * 71 (11 OEM chars, space-padded) — spec §3.3 FAT32 boot sector; same
     * offsets Wine's mountmgr reads for a FAT32 superblock (0x43/0x47,
     * dlls/mountmgr.sys/device.c VOLUME_GetSuperblock{Serial,Label}).
     * "NO NAME    " is the spec's no-label sentinel (§3.3 BS_VolLab). */
    volume->volumeSerial = FatRead32(boot + 67);
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
    InsertTailList(&volume->fcbList, &root->volumeEntry);
    volume->root = root;

    DbgPrint("fat32: mounted at LBA %lu, %lu clusters of %lu bytes\n", (unsigned long)partitionLba,
             (unsigned long)clusterCount, (unsigned long)(sectorsPerCluster * bytesPerSector));
    *volumeOut = volume;
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
