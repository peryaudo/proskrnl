/* drivers/disk.h — THE boot disk: the one place that decides which driver
 * the FAT32 boot volume's sectors come from (LIVE-1).
 *
 * Two drivers can be it: virtio-blk (every QEMU leg; drivers/virtio/blk.h)
 * and the memdisk (a live medium's RAM copy; drivers/memdisk.h). A boot
 * that carries a memdisk module has said which disk it runs from, so the
 * memdisk wins and virtio-blk is not brought up at all
 * (kernel/io/file.c IoInitializeTransport). Every consumer — the mount,
 * the file system's sector traffic, the Io layer's presence check — asks
 * here, so the choice is made once (Art. 11) rather than by each caller
 * testing drivers.
 *
 * The synchronous surface is the virtio-blk one, verbatim. The QUEUED
 * surface (submit/await, the docs/19 §5a depth) is virtio-blk's alone:
 * DiskIsQueued says whether it exists, and a caller that batches
 * (fs/fat32/file.c) falls back to the synchronous physical pair when it
 * does not — a memdisk transfer is a memcpy that has finished before it
 * could have been queued.
 */
#ifndef PROSKRNL_DRIVERS_DISK_H
#define PROSKRNL_DRIVERS_DISK_H

#include <stdint.h>

#include "abi/ntdef.h"

BOOLEAN DiskIsPresent(void);

/* TRUE when the boot disk is virtio-blk, i.e. the VioBlk submit/await
 * batch surface drives it; FALSE for the memdisk (and for no disk). */
BOOLEAN DiskIsQueued(void);

uint64_t DiskSectorCount(void);

NTSTATUS DiskReadSectors(uint64_t sectorLba, uint32_t sectorCount, void *buffer);
NTSTATUS DiskWriteSectors(uint64_t sectorLba, uint32_t sectorCount, const void *buffer);

/* At most one page per call, into / out of one physically contiguous run
 * (a page-cache frame) — the virtio-blk direct-DMA contract. */
NTSTATUS DiskReadSectorsPhysical(uint64_t sectorLba, uint32_t sectorCount, uint64_t physical);
NTSTATUS DiskWriteSectorsPhysical(uint64_t sectorLba, uint32_t sectorCount, uint64_t physical);

#endif /* PROSKRNL_DRIVERS_DISK_H */
