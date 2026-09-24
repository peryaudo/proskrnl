/* drivers/memdisk.c — the boot disk as a RAM copy (LIVE-1; see memdisk.h).
 *
 * Nothing here is a device: the image is ordinary memory the bootloader
 * filled, so a read or write is a bounds check and a memcpy, completed
 * inline. The one decision this driver owns is that the image is the
 * WHOLE disk — the GPT the FAT32 mount walks (fs/fat32/fat.c
 * FatFindDataPartition) is inside it — so the file system mounts it
 * exactly as it mounts a virtio-blk disk, through drivers/disk.c.
 */
#include "drivers/memdisk.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "abi/ntstatus.h"

static unsigned char *MemDiskImage;
static uint64_t MemDiskSectors;

BOOLEAN MemDiskInitialize(void *image, uint64_t size)
{
    ASSERT(MemDiskImage == 0); /* one boot disk, adopted once */
    uint64_t sectors = size / MEM_DISK_SECTOR_SIZE;
    /* The smallest image a GPT disk fits in: the protective MBR (LBA 0), the
     * header (LBA 1) and at least one sector of partition entries — UEFI
     * 2.10 §5.3.1. Anything smaller cannot be the disk this driver serves,
     * and a mount that then fails on it would name the wrong culprit. */
    if (image == 0 || sectors < 3)
    {
        DbgPrint("memdisk: module of %lu bytes is not a disk image; refused\n",
                 (unsigned long)size);
        return FALSE;
    }
    if (size % MEM_DISK_SECTOR_SIZE != 0)
    {
        DbgPrint("memdisk: %lu trailing bytes past the last whole sector ignored\n",
                 (unsigned long)(size % MEM_DISK_SECTOR_SIZE));
    }
    MemDiskImage = image;
    MemDiskSectors = sectors;
    DbgPrint("[KTEST] memdisk READY sectors=%lu (%lu MiB in RAM; writes are not persisted)\n",
             (unsigned long)sectors, (unsigned long)(size / (1024 * 1024)));
    return TRUE;
}

BOOLEAN MemDiskIsPresent(void)
{
    return MemDiskImage != 0;
}

uint64_t MemDiskSectorCount(void)
{
    return MemDiskSectors;
}

/* How many of [sectorLba, sectorLba + sectorCount) lie on the disk — the
 * in-range PREFIX, written so neither the sum nor the byte offset can wrap
 * (a caller-chosen ~0 LBA is a pinned out-of-range case, tests/kmt/m6_blk.c). */
static uint32_t MemDiskInRangeSectors(uint64_t sectorLba, uint32_t sectorCount)
{
    if (sectorLba >= MemDiskSectors)
    {
        return 0;
    }
    uint64_t room = MemDiskSectors - sectorLba;
    return sectorCount <= room ? sectorCount : (uint32_t)room;
}

/* The boot-disk contract (drivers/disk.h, pinned by tests/kmt/m6_blk.c
 * test_blk_out_of_range): a transfer reaching past the last sector fails
 * with STATUS_IO_DEVICE_ERROR, and its in-range prefix may have been
 * transferred by then — virtio-blk's chunked loop transfers every whole
 * in-range chunk first. The memdisk transfers the whole in-range prefix:
 * the same shape, not a stricter all-or-nothing contract of its own. */
NTSTATUS MemDiskReadSectors(uint64_t sectorLba, uint32_t sectorCount, void *buffer)
{
    ASSERT(MemDiskImage != 0);
    uint32_t inRange = MemDiskInRangeSectors(sectorLba, sectorCount);
    if (inRange != 0)
    {
        memcpy(buffer, MemDiskImage + sectorLba * MEM_DISK_SECTOR_SIZE,
               (uint64_t)inRange * MEM_DISK_SECTOR_SIZE);
    }
    return inRange == sectorCount ? STATUS_SUCCESS : STATUS_IO_DEVICE_ERROR;
}

NTSTATUS MemDiskWriteSectors(uint64_t sectorLba, uint32_t sectorCount, const void *buffer)
{
    ASSERT(MemDiskImage != 0);
    uint32_t inRange = MemDiskInRangeSectors(sectorLba, sectorCount);
    if (inRange != 0)
    {
        memcpy(MemDiskImage + sectorLba * MEM_DISK_SECTOR_SIZE, buffer,
               (uint64_t)inRange * MEM_DISK_SECTOR_SIZE);
    }
    return inRange == sectorCount ? STATUS_SUCCESS : STATUS_IO_DEVICE_ERROR;
}
