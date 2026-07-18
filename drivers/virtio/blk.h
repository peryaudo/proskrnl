/* drivers/virtio/blk.h — virtio-blk: the M6 boot disk (docs/02, docs/04).
 *
 * Synchronous sector I/O over one polled virtqueue. The disk the FAT32
 * volume (fs/fat32) mounts is QEMU's `-drive if=virtio` boot image
 * (tools/qemu.sh).
 */
#ifndef PROSKRNL_DRIVERS_VIRTIO_BLK_H
#define PROSKRNL_DRIVERS_VIRTIO_BLK_H

#include <stdint.h>

#include "abi/ntdef.h"

/* virtio-blk always speaks 512-byte sectors regardless of blk_size
 * (virtio 1.2 cs01 §5.2.5: "does not affect the units used in the
 * protocol (always 512 bytes)"). */
#define VIO_BLK_SECTOR_SIZE 512

/* Probe PCI bus 0, bring the device up per the virtio 1.2 cs01 §3.1.1
 * initialization sequence, and set up the request queue. Returns TRUE when
 * a disk is ready; FALSE when no virtio-blk function exists. */
BOOLEAN VioBlkInitialize(void);

BOOLEAN VioBlkIsPresent(void);
uint64_t VioBlkSectorCount(void);

/* Synchronous sector I/O through an internal bounce frame (buffers may be
 * physically discontiguous pool/cache memory). */
NTSTATUS VioBlkReadSectors(uint64_t sectorLba, uint32_t sectorCount, void *buffer);
NTSTATUS VioBlkWriteSectors(uint64_t sectorLba, uint32_t sectorCount, const void *buffer);

#endif /* PROSKRNL_DRIVERS_VIRTIO_BLK_H */
