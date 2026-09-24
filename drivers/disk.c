/* drivers/disk.c — the boot disk's one dispatch point (LIVE-1; see disk.h).
 *
 * The memdisk is asked first because it can only be present if the boot
 * put it there on purpose, and IoInitializeTransport then leaves virtio-blk
 * down: at most one of the two answers MemDiskIsPresent / VioBlkIsPresent.
 */
#include "drivers/disk.h"
#include "drivers/memdisk.h"
#include "drivers/virtio/blk.h"
#include "kernel/mm/phys.h"
#include "abi/ntstatus.h"

BOOLEAN DiskIsPresent(void)
{
    return MemDiskIsPresent() || VioBlkIsPresent();
}

BOOLEAN DiskIsQueued(void)
{
    return !MemDiskIsPresent() && VioBlkIsPresent();
}

uint64_t DiskSectorCount(void)
{
    return MemDiskIsPresent() ? MemDiskSectorCount() : VioBlkSectorCount();
}

NTSTATUS DiskReadSectors(uint64_t sectorLba, uint32_t sectorCount, void *buffer)
{
    if (MemDiskIsPresent())
    {
        return MemDiskReadSectors(sectorLba, sectorCount, buffer);
    }
    return VioBlkReadSectors(sectorLba, sectorCount, buffer);
}

NTSTATUS DiskWriteSectors(uint64_t sectorLba, uint32_t sectorCount, const void *buffer)
{
    if (MemDiskIsPresent())
    {
        return MemDiskWriteSectors(sectorLba, sectorCount, buffer);
    }
    return VioBlkWriteSectors(sectorLba, sectorCount, buffer);
}

/* The memdisk reaches a physical run through the HHDM, which maps every
 * memmap region (arch/x86_64/mmu.c MiInitializeVirtualMemory) — page-cache
 * frames included. */
NTSTATUS DiskReadSectorsPhysical(uint64_t sectorLba, uint32_t sectorCount, uint64_t physical)
{
    if (MemDiskIsPresent())
    {
        return MemDiskReadSectors(sectorLba, sectorCount, MiPhysicalToVirtual(physical));
    }
    return VioBlkReadSectorsPhysical(sectorLba, sectorCount, physical);
}

NTSTATUS DiskWriteSectorsPhysical(uint64_t sectorLba, uint32_t sectorCount, uint64_t physical)
{
    if (MemDiskIsPresent())
    {
        return MemDiskWriteSectors(sectorLba, sectorCount, MiPhysicalToVirtual(physical));
    }
    return VioBlkWriteSectorsPhysical(sectorLba, sectorCount, physical);
}
