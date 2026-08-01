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

/* Requests that may be in flight at once (CUI-8, docs/19 §5a). An internal
 * capacity choice, not a spec value: it sizes the control-slot frame and is
 * comfortably under the ring's 256-descriptor budget at 3 descriptors per
 * request. */
#define VIO_BLK_MAX_INFLIGHT 16

/* One block request, CALLER-embedded (stack or batch array — never pool
 * owned by the driver): the issuer's frame owns the request from submit to
 * observed completion and never unwinds past it (docs/20 R4). The caller
 * fills the transfer description; the driver owns the bookkeeping fields
 * from submit until `completed` reads TRUE, after which `result` is the
 * verdict. */
typedef struct VIO_BLK_REQUEST
{
    uint32_t type; /* driver-internal VIO_BLK_T_* */
    uint64_t sectorLba;
    uint32_t sectorCount;
    uint64_t dataPhysical; /* one physically contiguous run */
    volatile BOOLEAN completed;
    NTSTATUS result;
    uint16_t descHead;
    uint8_t controlSlot;
} VIO_BLK_REQUEST;

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

/* Synchronous direct-DMA sector I/O: the device reads/writes the caller's
 * physically contiguous buffer itself — no bounce, no copy (CUI-8, docs/19
 * §5a; the page cache's frames are single 4 KiB frames, so page-granularity
 * transfers describe them to the device directly). At most one page per
 * call. */
NTSTATUS VioBlkReadSectorsPhysical(uint64_t sectorLba, uint32_t sectorCount, uint64_t physical);
NTSTATUS VioBlkWriteSectorsPhysical(uint64_t sectorLba, uint32_t sectorCount, uint64_t physical);

#endif /* PROSKRNL_DRIVERS_VIRTIO_BLK_H */
