/* drivers/virtio/net.h — virtio-net over the shared modern-PCI transport
 * (Net-1, docs/24 §4a; see net.c).
 *
 * The device half of the networking path: rings, buffers, and the
 * harvest-store-wake drain. Everything above it — pbufs, protocol input,
 * timers — is the netd mainloop's (drivers/net/), reached through the
 * staged receive ring and the work event below; nothing here parses a
 * byte.
 */
#ifndef PROSKRNL_DRIVERS_VIRTIO_NET_H
#define PROSKRNL_DRIVERS_VIRTIO_NET_H

#include <stdint.h>
#include "abi/ntdef.h"
#include "kernel/ke/ke.h"

#define VIO_NET_MAC_BYTES 6

/* The largest frame the device may hand us or we may hand it: an untagged
 * Ethernet frame (14-byte header + 1500-byte MTU payload; IEEE 802.3 /
 * the pinned QEMU net/eth.h ETH_MAX_MTU usage — no VLAN is negotiated,
 * no jumbo, no VIRTIO_NET_F_MTU). With the 12-byte virtio-net header a
 * whole receive fits one page with room to spare (docs/24 §2: the DMA
 * floor is one page). */
#define VIO_NET_MAX_FRAME 1514

/* Probe (pre-freeze, from IoInitializeTransport beside blk and input: the
 * BAR map and every DMA allocation happen before MiFreezeKernelPml4).
 * Brings the device to DRIVER_OK with all receive buffers posted. Returns
 * FALSE (loudly, on serial) when absent — every image but the net leg's. */
BOOLEAN VioNetInitialize(void);
BOOLEAN VioNetIsPresent(void);

/* The device's own MAC (read from device config under VIRTIO_NET_F_MAC —
 * the device's claim, never invented). Valid once present. */
const uint8_t *VioNetMacAddress(void);

/* The one harvest authority's net arm (Art. 11), called by
 * IoDrainDeviceCompletions with the dispatcher lock held: pop completed
 * transmit slots back to the free set, stage received frames for the
 * consumer, set the work event. Harvest-store-wake and nothing more
 * (docs/20 R2) — no allocation, no parsing, no lwIP. */
void VioNetDrain(void);

/* The consumer registration (netd's bring-up): until a consumer is live,
 * VioNetDrain leaves receive completions in the used ring — pull-based
 * harvest loses nothing, and the device dropping frames once its buffers
 * are exhausted is what a NIC with no reader does. */
void VioNetSetReceiveConsumerLive(BOOLEAN live);

/* The wake registration (netd's bring-up): the event VioNetDrain sets
 * when a harvest staged work. netd owns the event (Net-2: the mainloop
 * parks on it for loopback/AFD work too, NIC or not) and hands it down
 * here; until registered the drain stages silently. */
void VioNetSetWakeEvent(PKEVENT event);

/* Pop one staged received frame into `frame` (at most VIO_NET_MAX_FRAME
 * bytes; *lengthOut = the frame's length, virtio-net header already
 * stripped), repost its buffer to the device, and return 1; 0 when
 * nothing is staged. Thread context only — takes the dispatcher lock
 * internally. */
int VioNetPopReceivedFrame(void *frame, uint32_t *lengthOut);

/* Transmit one Ethernet frame (copied into a bounce slot — lwIP's pools
 * owe no physical contiguity, docs/24 §4a). Returns 1, or 0 with a loud
 * counted drop when every transmit slot is in flight — never a wait
 * (docs/24 §4b: no code path blocks while inside lwIP, and the caller is
 * lwIP's linkoutput). Thread context only — takes the dispatcher lock
 * internally. */
int VioNetTransmitFrame(const void *frame, uint32_t length);

/* The docs/24 §6e numbers for the [KTEST] net stats line: frames in/out,
 * the two loud-drop counters, and the staged ring's high-water mark. */
typedef struct
{
    uint64_t rxFrames;
    uint64_t txFrames;
    uint64_t rxStagedDrops; /* staged ring full at harvest */
    uint64_t txSlotDrops;   /* every transmit slot in flight */
    uint32_t rxStagedHighWater;
} VIO_NET_STATS;

void VioNetQueryStats(VIO_NET_STATS *stats);

#endif /* PROSKRNL_DRIVERS_VIRTIO_NET_H */
