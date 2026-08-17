/* drivers/virtio/net.c — virtio-net over the shared modern-PCI transport
 * (Net-1, docs/24 §4a; see net.h, virtio.h).
 *
 * Written from the OASIS virtio 1.2 cs01 specification (sections cited
 * inline) against the pinned third_party/qemu device model
 * (hw/net/virtio-net.c, include/standard-headers/linux/virtio_net.h).
 * Provenance: public spec only (docs/11).
 *
 * Feature negotiation is minimal and deliberate: VIRTIO_NET_F_MAC (the
 * device's own address, read from config — never invented) plus VERSION_1,
 * and nothing else. NOT negotiated, each an axis Article 3 refuses and
 * absence of negotiation is absence of code (docs/24 §5): the
 * checksum/TSO/GSO offload family (lwIP computes and verifies every
 * checksum in software), MRG_RXBUF (a full frame fits one page;
 * multi-buffer receive buys nothing), CTRL_VQ, multiqueue, EVENT_IDX
 * (docs/19 §11c: the device may notify per completion; we build no
 * coalescing we cannot convict a need for).
 *
 * No MSI-X vector, deliberately (docs/19 §11f is the controlling
 * precedent): VioNetDrain joins IoDrainDeviceCompletions — the one
 * harvest authority (Art. 11) — and is reached from the tick tail, a
 * 1 ms guest-clocked receive/completion bound against TCP timers whose
 * granularity is hundreds of milliseconds. blk's interrupt was convicted
 * by idle-hlt and microsecond parks; a socket wake has no such consumer,
 * and the tick already runs unconditionally so no busy-poll arm comes
 * back. The escape stays named: a separate change against this same
 * drain seam, if a latency consumer ever convicts the millisecond.
 *
 * The drain is harvest-store-wake and nothing more (docs/20 R2): pop
 * used receive buffers onto the fixed staged ring, pop completed
 * transmit slots back to the free set, set the netd work event. No pbuf
 * is allocated, no byte is parsed, no lwIP function runs in drain
 * context — protocol input belongs to the netd mainloop (drivers/net/).
 */
#include "drivers/virtio/net.h"
#include "drivers/virtio/virtio.h"
#include "kernel/mm/phys.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

/* --- virtio-net protocol (virtio 1.2 cs01 §5.1) ---------------------------- */

/* Feature bit (§5.1.3; cross-check pinned virtio_net.h VIRTIO_NET_F_MAC). */
#define VIO_NET_F_MAC 5

/* Every transferred packet is fronted by this header (§5.1.6). Under
 * VERSION_1 the num_buffers field is ALWAYS present — the 10-byte
 * headerless-num_buffers shape is legacy-only (§5.1.6.1; pinned QEMU
 * hw/net/virtio-net.c virtio_net_set_mrg_rx_bufs: version_1 =>
 * guest_hdr_len = sizeof(virtio_net_hdr_mrg_rxbuf) regardless of
 * MRG_RXBUF). Getting the size wrong shifts every frame by two bytes, so
 * it is pinned by the static_assert. The field's VALUE is another story,
 * measured against the cross-check device model: §5.1.6.4.1 says the
 * device sets it to 1 without MRG_RXBUF, but the pinned QEMU's
 * receive_header (hw/net/virtio-net.c) writes only the 10-byte
 * virtio_net_hdr prefix in that path and never touches bytes 10..11 —
 * the field reads back as stale buffer memory. So this driver skips the
 * 12 bytes and never reads any of them; nothing in the header matters
 * without an offload negotiated. */
typedef struct
{
    uint8_t flags;       /* §5.1.6: VIRTIO_NET_HDR_F_*; 0 — no offloads */
    uint8_t gsoType;     /* §5.1.6: VIRTIO_NET_HDR_GSO_NONE = 0 */
    uint16_t hdrLen;     /* le16; unused without offloads */
    uint16_t gsoSize;    /* le16; unused without GSO */
    uint16_t csumStart;  /* le16; unused without F_NEEDS_CSUM */
    uint16_t csumOffset; /* le16; unused without F_NEEDS_CSUM */
    uint16_t numBuffers; /* le16; device writes 1 (no MRG_RXBUF) */
} VIO_NET_HEADER;
_Static_assert(sizeof(VIO_NET_HEADER) == 12,
               "virtio-net header is 12 bytes under VERSION_1 (§5.1.6)");

/* §5.1.2: virtqueue 0 is receiveq1, 1 is transmitq1 (2 would be the
 * controlq — CTRL_VQ is not negotiated, so it is never configured). */
#define VIO_NET_RX_QUEUE 0
#define VIO_NET_TX_QUEUE 1

/* Device config (§5.1.4): the MAC occupies the first six bytes; every
 * later field sits behind a feature this driver leaves unnegotiated. */
#define VIO_NET_CFG_OFF_MAC 0

/* --- driver state ---------------------------------------------------------- */

/* Buffer counts. Internal recorded facts, not spec values (docs/24 §7:
 * sizes are recorded with rationale; re-sizing on conviction is a
 * one-line change, never a dynamic allocator):
 *  - rx: 64 one-page buffers = ~96 KiB of full-MTU backlog between 1 ms
 *    harvests — two orders of magnitude above the acceptance path's
 *    needs; the staged ring is sized to match, so a full ring (the loud
 *    drop) means the CONSUMER stalled, not the harvest.
 *  - tx: 16 one-page bounce slots = 16 frames in flight per wake; lwIP
 *    paces itself by its own window, and an exhausted set is a loud
 *    counted drop the stack retransmits over, never a wait. */
#define VIO_NET_RX_BUFFERS 64
#define VIO_NET_TX_SLOTS   16

static BOOLEAN VioNetPresent;
static VIO_PCI_DEVICE VioNetDevice;
static VIO_VIRTQUEUE VioNetRxQueue;
static VIO_VIRTQUEUE VioNetTxQueue;
static uint8_t VioNetMac[VIO_NET_MAC_BYTES];

static uint16_t VioNetRxBufferCount;
static uint64_t VioNetRxBufferPhysical[VIO_NET_RX_BUFFERS];
static uint8_t *VioNetRxBuffer[VIO_NET_RX_BUFFERS];

static uint64_t VioNetTxSlotPhysical[VIO_NET_TX_SLOTS];
static uint8_t *VioNetTxSlot[VIO_NET_TX_SLOTS];
static BOOLEAN VioNetTxSlotBusy[VIO_NET_TX_SLOTS];
/* head descriptor index -> transmit slot + 1 (0 = none); the §2.7.8 used
 * id is the chain head, blk's cookie-map shape. Sized for the largest
 * ring VioInitializeVirtqueue allows. */
static uint16_t VioNetTxSlotByHead[256];

/* The staged receive ring (docs/24 §4a): drain pushes {slot, length},
 * the netd mainloop pops in thread context. Fixed size — full means the
 * consumer is stalled, and the frame is dropped loudly (the counter
 * rides the [KTEST] net stats line) with its buffer reposted, which is
 * what a NIC under overload does. */
typedef struct
{
    uint16_t slot;
    uint16_t length; /* device-written bytes, header included */
} VIO_NET_STAGED_FRAME;
static VIO_NET_STAGED_FRAME VioNetStaged[VIO_NET_RX_BUFFERS];
static uint32_t VioNetStagedHead; /* oldest staged entry */
static uint32_t VioNetStagedCount;

static BOOLEAN VioNetConsumerLive;
static KEVENT VioNetEvent;

static VIO_NET_STATS VioNetStats;

BOOLEAN VioNetInitialize(void)
{
    /* §3.1.1 steps 1-4: net is transitional 0x1000 or modern 0x1040+1
     * (§4.1.2.1, §5.1.1). */
    if (!VioPciSetupModernDevice(VIRTIO_DEVICE_TYPE_NET, VIRTIO_PCI_DEVICE_ID_NET_TRANSITIONAL,
                                 "virtio-net", 0, &VioNetDevice))
    {
        return FALSE;
    }
    /* The MAC must be the device's claim: without the feature the config
     * bytes are unspecified, and a driver that invents an address puts a
     * fabricated identity on a real wire (G12's shape at the device). */
    if ((VioNetDevice.deviceFeaturesLow & (1u << VIO_NET_F_MAC)) == 0)
    {
        DbgPrint("virtio-net: device offers no MAC (F_MAC clear)\n");
        VioPciSetFailed(&VioNetDevice);
        return FALSE;
    }
    if (!VioPciAcceptFeatures(&VioNetDevice, 1u << VIO_NET_F_MAC))
    {
        return FALSE;
    }

    /* Step 7: both queues. The §4.1.4.3 queue msix_vector stays at
     * NO_VECTOR — no MSI-X is enabled for this function (header comment);
     * the INTx the device raises instead is never routed and never read,
     * the virtio-input precedent. */
    if (!VioPciSetupQueue(&VioNetDevice, &VioNetRxQueue, VIO_NET_RX_QUEUE) ||
        !VioPciSetupQueue(&VioNetDevice, &VioNetTxQueue, VIO_NET_TX_QUEUE))
    {
        return FALSE;
    }

    /* DMA buffers before going live — and before MiFreezeKernelPml4, like
     * every allocation here (the caller is IoInitializeTransport). */
    VioNetRxBufferCount =
        VioNetRxQueue.queueSize < VIO_NET_RX_BUFFERS ? VioNetRxQueue.queueSize : VIO_NET_RX_BUFFERS;
    for (uint16_t slot = 0; slot < VioNetRxBufferCount; slot++)
    {
        VioNetRxBufferPhysical[slot] = MiAllocatePage();
        if (VioNetRxBufferPhysical[slot] == 0)
        {
            VioPciSetFailed(&VioNetDevice);
            return FALSE;
        }
        VioNetRxBuffer[slot] = MiPhysicalToVirtual(VioNetRxBufferPhysical[slot]);
    }
    for (uint16_t slot = 0; slot < VIO_NET_TX_SLOTS; slot++)
    {
        VioNetTxSlotPhysical[slot] = MiAllocatePage();
        if (VioNetTxSlotPhysical[slot] == 0)
        {
            VioPciSetFailed(&VioNetDevice);
            return FALSE;
        }
        VioNetTxSlot[slot] = MiPhysicalToVirtual(VioNetTxSlotPhysical[slot]);
    }

    /* All receive buffers posted before DRIVER_OK (§5.1.5: the driver
     * SHOULD populate the receive queue before enabling), one whole page
     * each so the 12-byte header plus a full frame always fits. */
    for (uint16_t slot = 0; slot < VioNetRxBufferCount; slot++)
    {
        VioPostReceiveBuffer(&VioNetRxQueue, slot, VioNetRxBufferPhysical[slot], PAGE_SIZE);
    }

    KeInitializeEvent(&VioNetEvent, NotificationEvent, FALSE);

    /* Step 8: DRIVER_OK, then the deferred buffer-available notify
     * (§3.1.1 step 8; VioPostReceiveBuffer never notifies on its own). */
    VioPciSetDriverOk(&VioNetDevice);
    VioNotifyQueue(&VioNetRxQueue);

    /* The MAC: six bytes at config offset 0, valid under the negotiated
     * F_MAC (§5.1.4); byte reads keep the MMIO access width simple. */
    for (unsigned i = 0; i < VIO_NET_MAC_BYTES; i++)
    {
        VioNetMac[i] = VioNetDevice.deviceCfg[VIO_NET_CFG_OFF_MAC + i];
    }

    VioNetPresent = TRUE;
    DbgPrint("virtio-net: %02x:%x id %04x, mac %02x:%02x:%02x:%02x:%02x:%02x, "
             "rx %u bufs / tx %u slots\n",
             VioNetDevice.function.device, VioNetDevice.function.function,
             VioNetDevice.function.deviceId, VioNetMac[0], VioNetMac[1], VioNetMac[2], VioNetMac[3],
             VioNetMac[4], VioNetMac[5], VioNetRxBufferCount, VIO_NET_TX_SLOTS);
    return TRUE;
}

BOOLEAN VioNetIsPresent(void)
{
    return VioNetPresent;
}

const uint8_t *VioNetMacAddress(void)
{
    ASSERT(VioNetPresent);
    return VioNetMac;
}

PKEVENT VioNetWorkEvent(void)
{
    ASSERT(VioNetPresent);
    return &VioNetEvent;
}

void VioNetSetReceiveConsumerLive(BOOLEAN live)
{
    VioNetConsumerLive = live;
}

/* --- the drain (dispatcher lock held; docs/20 R2) -------------------------- */

void VioNetDrain(void)
{
    if (!VioNetPresent)
    {
        return;
    }
    ASSERT(KiIsDispatcherLockHeld());

    int work = 0;
    uint16_t head;
    uint32_t length;

    /* Transmit completions: return the slots to the free set. */
    while (VioHarvestUsed(&VioNetTxQueue, &head, &length))
    {
        ASSERT(head < 256 && VioNetTxSlotByHead[head] != 0);
        uint16_t slot = (uint16_t)(VioNetTxSlotByHead[head] - 1);
        VioNetTxSlotByHead[head] = 0;
        ASSERT(VioNetTxSlotBusy[slot]);
        VioNetTxSlotBusy[slot] = FALSE;
        VioNetStats.txFrames++;
        work = 1;
    }

    /* Received frames: stage the slot indices for the netd mainloop. With
     * no live consumer the used entries simply stay in the ring —
     * pull-based harvest loses nothing (the blk precedent), and a device
     * that exhausts its buffers drops frames, which is what a NIC with no
     * reader does. */
    while (VioNetConsumerLive && VioTryPopUsed(&VioNetRxQueue, &head, &length))
    {
        ASSERT(head < VioNetRxBufferCount);
        if (VioNetStagedCount == VioNetRxBufferCount)
        {
            /* Consumer stalled: drop loudly (counted, on the stats line)
             * and hand the buffer straight back so the supply never
             * drains. Repost + notify is store-only MMIO — legal here. */
            VioNetStats.rxStagedDrops++;
            VioPostReceiveBuffer(&VioNetRxQueue, head, VioNetRxBufferPhysical[head], PAGE_SIZE);
            VioNotifyQueue(&VioNetRxQueue);
            continue;
        }
        uint32_t tail = (VioNetStagedHead + VioNetStagedCount) % VioNetRxBufferCount;
        VioNetStaged[tail].slot = head;
        VioNetStaged[tail].length = (uint16_t)length;
        VioNetStagedCount++;
        if (VioNetStagedCount > VioNetStats.rxStagedHighWater)
        {
            VioNetStats.rxStagedHighWater = VioNetStagedCount;
        }
        VioNetStats.rxFrames++;
        work = 1;
    }

    if (work)
    {
        /* The same edge the tick's timer expiry already drives: KiWaitTest
         * readies the parked netd thread, never switches (docs/18 §6d). */
        KeSetEvent(&VioNetEvent, 0, FALSE);
    }
}

/* --- thread-context consumers ---------------------------------------------- */

int VioNetPopReceivedFrame(void *frame, uint32_t *lengthOut)
{
    ASSERT(VioNetPresent);
    uint64_t flags = KiAcquireDispatcherLock();
    if (VioNetStagedCount == 0)
    {
        KiReleaseDispatcherLock(flags);
        return 0;
    }
    VIO_NET_STAGED_FRAME staged = VioNetStaged[VioNetStagedHead];
    VioNetStagedHead = (VioNetStagedHead + 1) % VioNetRxBufferCount;
    VioNetStagedCount--;

    /* The device fills the header and at least an Ethernet header behind
     * it, or the wire format is broken — not a condition to paper over.
     * The header's CONTENT is deliberately never read (struct comment
     * above: the pinned QEMU leaves num_buffers unwritten in the
     * no-MRG_RXBUF path, and no offload is negotiated that would make any
     * other field meaningful). */
    ASSERT(staged.length >= sizeof(VIO_NET_HEADER));

    uint32_t frameLength = staged.length - sizeof(VIO_NET_HEADER);
    if (frameLength > VIO_NET_MAX_FRAME)
    {
        frameLength = VIO_NET_MAX_FRAME; /* never overrun the caller */
    }
    memcpy(frame, VioNetRxBuffer[staged.slot] + sizeof(VIO_NET_HEADER), frameLength);
    *lengthOut = frameLength;

    /* Hand the slot straight back (the virtio-input shape): the supply
     * must not drain while the consumer is consuming. */
    VioPostReceiveBuffer(&VioNetRxQueue, staged.slot, VioNetRxBufferPhysical[staged.slot],
                         PAGE_SIZE);
    VioNotifyQueue(&VioNetRxQueue);
    KiReleaseDispatcherLock(flags);
    return 1;
}

int VioNetTransmitFrame(const void *frame, uint32_t length)
{
    ASSERT(VioNetPresent);
    ASSERT(length <= VIO_NET_MAX_FRAME);
    uint64_t flags = KiAcquireDispatcherLock();

    /* Claim-fill-submit-register under one hold (blk's F2 discipline): a
     * drain between the claim and the map registration must not see a
     * chain whose cookie is missing. */
    uint16_t slot;
    for (slot = 0; slot < VIO_NET_TX_SLOTS; slot++)
    {
        if (!VioNetTxSlotBusy[slot])
        {
            break;
        }
    }
    if (slot == VIO_NET_TX_SLOTS)
    {
        /* Every slot in flight: a loud counted drop, never a wait — the
         * caller is lwIP's linkoutput and no code path may block inside
         * the stack (docs/24 §4b); TCP retransmits over it. */
        VioNetStats.txSlotDrops++;
        KiReleaseDispatcherLock(flags);
        return 0;
    }

    VIO_NET_HEADER *header = (VIO_NET_HEADER *)VioNetTxSlot[slot];
    memset(header, 0, sizeof(*header)); /* no offloads: flags 0, GSO_NONE (§5.1.6.2) */
    memcpy(VioNetTxSlot[slot] + sizeof(*header), frame, length);

    VIO_SEGMENT segment = {VioNetTxSlotPhysical[slot], sizeof(*header) + length, 0};
    uint16_t head;
    if (!VioSubmitChain(&VioNetTxQueue, &segment, 1, &head))
    {
        /* Ring full with free slots means completions are unharvested;
         * drop loudly rather than draining from under the caller. */
        VioNetStats.txSlotDrops++;
        KiReleaseDispatcherLock(flags);
        return 0;
    }
    VioNetTxSlotBusy[slot] = TRUE;
    ASSERT(head < 256 && VioNetTxSlotByHead[head] == 0);
    VioNetTxSlotByHead[head] = slot + 1;
    VioNotifyQueue(&VioNetTxQueue);
    KiReleaseDispatcherLock(flags);
    return 1;
}

void VioNetQueryStats(VIO_NET_STATS *stats)
{
    uint64_t flags = KiAcquireDispatcherLock();
    *stats = VioNetStats;
    KiReleaseDispatcherLock(flags);
}
