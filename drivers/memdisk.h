/* drivers/memdisk.h — the memdisk: a whole boot disk held in RAM (LIVE-1).
 *
 * A live medium (tools/mkimage.sh's liveusb image, docs/02 "LIVE-1") carries
 * the system disk as ONE Limine boot module tagged `memdisk`: a raw disk
 * image, GPT and FAT32 volume and all, which the firmware reads off the
 * stick through its own USB stack and Limine loads into physical memory
 * before the kernel runs. This driver makes that memory the boot disk, so
 * no USB mass-storage driver is needed to run from a stick. Writes land in
 * the RAM copy and nowhere else: the medium is never written, and every
 * change is gone at power-off (the WinPE RAM-disk model — docs/03 "LIVE-1
 * notes").
 *
 * Sectors are 512 bytes, the unit the FAT32 driver and the GPT it reads are
 * laid out in (fs/fat32/fat.h FAT_SECTOR_SIZE). Every transfer is a copy
 * completed before the call returns — there is no device to wait for.
 */
#ifndef PROSKRNL_DRIVERS_MEMDISK_H
#define PROSKRNL_DRIVERS_MEMDISK_H

#include <stdint.h>

#include "abi/ntdef.h"

#define MEM_DISK_SECTOR_SIZE 512

/* Adopt [image, image + size) — the module's bytes through the HHDM, which
 * stay mapped and are never handed to the frame allocator (Limine types
 * them EXECUTABLE_AND_MODULES, not USABLE; kernel/mm/phys.c) — as the boot
 * disk. A trailing partial sector is not addressable. Returns FALSE (and
 * says why on serial) for an image too small to hold a GPT disk. */
BOOLEAN MemDiskInitialize(void *image, uint64_t size);

BOOLEAN MemDiskIsPresent(void);
uint64_t MemDiskSectorCount(void);

/* Same contract as the virtio-blk synchronous pair (drivers/virtio/blk.h):
 * STATUS_IO_DEVICE_ERROR for any range reaching past the last sector, with
 * the in-range prefix transferred first. */
NTSTATUS MemDiskReadSectors(uint64_t sectorLba, uint32_t sectorCount, void *buffer);
NTSTATUS MemDiskWriteSectors(uint64_t sectorLba, uint32_t sectorCount, const void *buffer);

#endif /* PROSKRNL_DRIVERS_MEMDISK_H */
