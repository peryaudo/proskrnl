/* drivers/virtio/virtio.h — virtio 1.x over the modern PCI transport (M6).
 *
 * Written from the OASIS specification "Virtual I/O Device (VIRTIO) Version
 * 1.2", Committee Specification 01 (virtio-v1.2-cs01) — cited per section
 * below — with the pinned third_party/qemu as the runtime cross-check
 * (docs/09 Art. 4 / gate G8). Provenance: public spec only (docs/11).
 *
 * Scope: exactly what a polling, uniprocessor, no-MSI-X driver needs — the
 * split virtqueue, the common/notify/device config capabilities, and the
 * status/feature handshake. No interrupts: requests are submitted and the
 * used ring is polled — the simplest correct thing (Art. 3's principle),
 * which also makes every transfer complete inline. That second property is
 * a consequence of this driver, not a kernel-wide rule; docs/19 is the plan
 * for harvesting completions off the submitting path instead.
 */
#ifndef PROSKRNL_DRIVERS_VIRTIO_VIRTIO_H
#define PROSKRNL_DRIVERS_VIRTIO_VIRTIO_H

#include <stdint.h>
#include <stddef.h>
#include "abi/ntdef.h"
#include "drivers/pci.h"

/* --- device status (virtio 1.2 cs01 §2.1) -------------------------------- */
#define VIRTIO_STATUS_ACKNOWLEDGE        1
#define VIRTIO_STATUS_DRIVER             2
#define VIRTIO_STATUS_DRIVER_OK          4
#define VIRTIO_STATUS_FEATURES_OK        8
#define VIRTIO_STATUS_DEVICE_NEEDS_RESET 64
#define VIRTIO_STATUS_FAILED             128

/* --- reserved feature bits (virtio 1.2 cs01 §6) --------------------------- */
#define VIRTIO_F_VERSION_1 32ULL

/* --- split virtqueue (virtio 1.2 cs01 §2.7) ------------------------------- */

/* §2.7.5: 16 bytes per descriptor. */
typedef struct
{
    uint64_t addr; /* le64 guest-physical buffer address */
    uint32_t len;  /* le32 */
    uint16_t flags;
    uint16_t next; /* valid iff flags & VIRTQ_DESC_F_NEXT */
} VIRTQ_DESC;
_Static_assert(sizeof(VIRTQ_DESC) == 16, "virtq_desc is 16 bytes (virtio 1.2 cs01 §2.7.5)");

#define VIRTQ_DESC_F_NEXT  1 /* §2.7.5 */
#define VIRTQ_DESC_F_WRITE 2 /* §2.7.5: device write-only buffer */

/* §2.7.6: avail ring — le16 flags, le16 idx, le16 ring[qsize]. */
typedef struct
{
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[]; /* qsize entries */
} VIRTQ_AVAIL;

/* §2.7.8: used ring — le16 flags, le16 idx, {le32 id, le32 len}[qsize]. */
typedef struct
{
    uint32_t id;
    uint32_t len;
} VIRTQ_USED_ELEM;
_Static_assert(sizeof(VIRTQ_USED_ELEM) == 8, "used elem is 8 bytes (virtio 1.2 cs01 §2.7.8)");

typedef struct
{
    uint16_t flags;
    uint16_t idx;
    VIRTQ_USED_ELEM ring[]; /* qsize entries */
} VIRTQ_USED;

/* --- PCI transport (virtio 1.2 cs01 §4.1) --------------------------------- */

#define VIRTIO_PCI_VENDOR                     0x1AF4 /* §4.1.2 */
#define VIRTIO_PCI_DEVICE_ID_MIN              0x1000 /* §4.1.2: 0x1000..0x107F are virtio */
#define VIRTIO_PCI_DEVICE_ID_MAX              0x107F
#define VIRTIO_PCI_DEVICE_ID_BLK_TRANSITIONAL 0x1001 /* §4.1.2.1 */
#define VIRTIO_PCI_DEVICE_ID_MODERN_BASE      0x1040 /* §4.1.2: 0x1040 + type */

/* Virtio device types (§5, "Device Types"); the modern PCI device id is
 * VIRTIO_PCI_DEVICE_ID_MODERN_BASE + type (§4.1.2). Cross-check:
 * third_party/qemu include/standard-headers/linux/virtio_ids.h. */
#define VIRTIO_DEVICE_TYPE_BLK   2  /* §5.2 */
#define VIRTIO_DEVICE_TYPE_INPUT 18 /* §5.8 */

/* Vendor-specific capability layout (virtio 1.2 cs01 §4.1.4); cap_vndr is
 * PCI capability ID 0x09 (PCI Local Bus Spec 3.0 §6.7 vendor-specific). */
#define VIRTIO_PCI_CAP_VNDR_ID    0x09
#define VIRTIO_PCI_CAP_COMMON_CFG 1 /* §4.1.4 cfg_type values */
#define VIRTIO_PCI_CAP_NOTIFY_CFG 2
#define VIRTIO_PCI_CAP_ISR_CFG    3
#define VIRTIO_PCI_CAP_DEVICE_CFG 4
#define VIRTIO_PCI_CAP_PCI_CFG    5

/* virtio_pci_cap config-space byte offsets (§4.1.4). */
#define VIRTIO_PCI_CAP_OFF_CFG_TYPE          3
#define VIRTIO_PCI_CAP_OFF_BAR               4
#define VIRTIO_PCI_CAP_OFF_OFFSET            8
#define VIRTIO_PCI_CAP_OFF_LENGTH            12
#define VIRTIO_PCI_NOTIFY_CAP_OFF_MULTIPLIER 16 /* §4.1.4.4 notify_off_multiplier */

/* Common configuration structure (virtio 1.2 cs01 §4.1.4.3); the offsets
 * follow the spec's packed little-endian struct (all fields naturally
 * aligned — pinned by the static_asserts on the struct below). */
typedef struct
{
    volatile uint32_t deviceFeatureSelect; /* 0x00 */
    volatile uint32_t deviceFeature;       /* 0x04 */
    volatile uint32_t driverFeatureSelect; /* 0x08 */
    volatile uint32_t driverFeature;       /* 0x0C */
    volatile uint16_t configMsixVector;    /* 0x10 */
    volatile uint16_t numQueues;           /* 0x12 */
    volatile uint8_t deviceStatus;         /* 0x14: writing 0 resets (§4.1.4.3) */
    volatile uint8_t configGeneration;     /* 0x15 */
    volatile uint16_t queueSelect;         /* 0x16 */
    volatile uint16_t queueSize;           /* 0x18 */
    volatile uint16_t queueMsixVector;     /* 0x1A */
    volatile uint16_t queueEnable;         /* 0x1C */
    volatile uint16_t queueNotifyOff;      /* 0x1E */
    volatile uint64_t queueDesc;           /* 0x20 */
    volatile uint64_t queueDriver;         /* 0x28 */
    volatile uint64_t queueDevice;         /* 0x30 */
} VIRTIO_PCI_COMMON_CFG;
_Static_assert(offsetof(VIRTIO_PCI_COMMON_CFG, deviceStatus) == 0x14,
               "common cfg layout (virtio 1.2 cs01 §4.1.4.3)");
_Static_assert(offsetof(VIRTIO_PCI_COMMON_CFG, queueNotifyOff) == 0x1E,
               "common cfg layout (virtio 1.2 cs01 §4.1.4.3)");
_Static_assert(offsetof(VIRTIO_PCI_COMMON_CFG, queueDevice) == 0x30,
               "common cfg layout (virtio 1.2 cs01 §4.1.4.3)");

/* --- one polled split virtqueue (virtqueue.c) ------------------------------ */

typedef struct
{
    uint16_t queueSize;
    uint16_t freeHead;    /* head of the free-descriptor chain */
    uint16_t lastUsedIdx; /* our private used-ring cursor (§2.7.14) */
    VIRTQ_DESC *desc;     /* descriptor area (one frame) */
    VIRTQ_AVAIL *avail;   /* driver area (one frame) */
    VIRTQ_USED *used;     /* device area (one frame) */
    uint64_t descPhysical;
    uint64_t availPhysical;
    uint64_t usedPhysical;
    volatile uint16_t *notify; /* this queue's notify address (mapped MMIO) */
    uint16_t queueIndex;
} VIO_VIRTQUEUE;

/* Allocate the three ring areas (one 4 KiB frame each — enough for any
 * queue size <= 256 at the §2.7 area sizes) and set up the free list.
 * Caps queueSize at 256 so the areas fit their frames. */
int VioInitializeVirtqueue(VIO_VIRTQUEUE *queue, uint16_t queueIndex, uint16_t queueSize);

/* Submit one 3-part chain (header / data / status per the caller's flags)
 * and poll the used ring until it completes (§2.7.13 submission barriers,
 * §2.7.14 polling). Returns 0 on poll timeout, 1 on completion. */
typedef struct
{
    uint64_t physical;
    uint32_t length;
    int deviceWrites; /* VIRTQ_DESC_F_WRITE */
} VIO_SEGMENT;

int VioSubmitAndPoll(VIO_VIRTQUEUE *queue, const VIO_SEGMENT *segments, int segmentCount);

/* --- receive queues (device -> driver; virtqueue.c) ------------------------ */
/* A receive queue (virtio-input's eventq, §5.8.2) inverts the request/reply
 * shape above: the driver supplies empty device-writable buffers up front
 * and the device fills them whenever it has something to say. The two calls
 * below are that supply path (§2.7.13) and a non-blocking used-ring poll
 * (§2.7.14) — never a wait, because nothing may block the caller here.
 *
 * Such a queue keeps a fixed 1:1 descriptor-slot-to-buffer mapping owned by
 * its driver and re-posts a slot once its buffer has been consumed, so the
 * free list VioInitializeVirtqueue builds goes unused; a queue is used one
 * way or the other, never both. */

/* Publish one device-writable buffer in descriptor slot `descriptorIndex`.
 * Does not notify: callers batch that with VioNotifyQueue, which also keeps
 * the initial fill from notifying before DRIVER_OK (§3.1.1). */
void VioPostReceiveBuffer(VIO_VIRTQUEUE *queue, uint16_t descriptorIndex, uint64_t physical,
                          uint32_t length);

/* §4.1.5.2: tell the device the avail ring moved. */
void VioNotifyQueue(VIO_VIRTQUEUE *queue);

/* Pop one used element if the device has published one (§2.7.14). Returns 0
 * when the used ring is empty, else 1 with *idOut = the head descriptor
 * index and *lengthOut = the number of bytes the device wrote. */
int VioTryPopUsed(VIO_VIRTQUEUE *queue, uint16_t *idOut, uint32_t *lengthOut);

/* --- the shared modern-PCI transport (pci.c) ------------------------------- */

/* One virtio function brought up through the §3.1.1 initialization
 * sequence. Every virtio driver in the tree mints its transport through
 * this one path (Art. 11): the BAR mapping window is a single cursor, so a
 * second copy of the mapping code would hand out overlapping kernel VAs. */
typedef struct
{
    KI_PCI_FUNCTION function;
    VIRTIO_PCI_COMMON_CFG *commonCfg;
    volatile uint8_t *deviceCfg;  /* §4.1.4.6 device-specific config */
    volatile uint8_t *notifyBase; /* §4.1.4.4 notify structure */
    uint32_t notifyMultiplier;    /* §4.1.4.4 notify_off_multiplier */
    uint32_t deviceFeaturesLow;   /* offered bits 0..31, as read */
    const char *name;             /* "virtio-blk"; log prefix only */
} VIO_PCI_DEVICE;

/* §3.1.1 steps 1-4 (read half): find the function, enable MMIO decoding and
 * bus mastering, map the common/notify/device-config capabilities, reset,
 * ACKNOWLEDGE|DRIVER, and confirm the device offers VERSION_1. Leaves the
 * offered low feature word in out->deviceFeaturesLow so the caller can
 * refuse on a device-specific bit before features are written back.
 * `transitionalId` is the §4.1.2.1 legacy id to also accept, or 0 for a
 * modern-only device. `instance` is a 0-based index among same-id functions
 * (two virtio-input devices on one bus); single-device drivers pass 0.
 * Returns FALSE (loudly, on serial) when absent. */
BOOLEAN VioPciSetupModernDevice(uint8_t deviceType, uint16_t transitionalId, const char *name,
                                unsigned instance, VIO_PCI_DEVICE *out);

/* §3.1.1 step 4 (write half) plus steps 5-6: accept VERSION_1 and nothing
 * else, set FEATURES_OK, and confirm the readback. */
BOOLEAN VioPciAcceptFeatures(VIO_PCI_DEVICE *device);

/* §3.1.1 step 7 for one queue: select it, size the rings, publish the three
 * area addresses, resolve the notify address (§4.1.4.4), enable. */
BOOLEAN VioPciSetupQueue(VIO_PCI_DEVICE *device, VIO_VIRTQUEUE *queue, uint16_t queueIndex);

/* §3.1.1 step 8: the device is live. */
void VioPciSetDriverOk(VIO_PCI_DEVICE *device);

/* §2.1: give up on this device — the driver sets FAILED and walks away. */
void VioPciSetFailed(VIO_PCI_DEVICE *device);

#endif /* PROSKRNL_DRIVERS_VIRTIO_VIRTIO_H */
