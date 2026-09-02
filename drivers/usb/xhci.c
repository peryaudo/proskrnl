/* drivers/usb/xhci.c — the xHCI host controller driver (USB-1): one
 * controller, its root ports, and the devices on them, enough of USB to
 * address a device and read its descriptors, run control transfers on EP0,
 * and service one interrupt IN endpoint per device.
 *
 * Written from the public specifications — eXtensible Host Controller
 * Interface for USB, Revision 1.2 (Intel, May 2019; "§" below), Universal
 * Serial Bus Specification Revision 2.0 ("USB 2.0 §") — cited per constant
 * (G8), against the pinned third_party/qemu device model
 * (hw/usb/hcd-xhci.c, hw/usb/hcd-xhci-pci.c) as the runtime cross-check.
 * Provenance: public spec only; no Linux, BSD, or ReactOS USB code
 * consulted (docs/11, docs/provenance.md).
 *
 * The shape is the tree's, not a USB stack's: no PnP, no IRP, no hub
 * driver, no hot-plug (docs/03 "WDM / PnP dropped"; drivers are statically
 * linked and probe what they need at boot). Two phases, because the
 * kernel's boot order forces them: XhciInitialize runs from
 * IoInitializeTransport, before the kernel PML4 freezes and before there is
 * a scheduler — it maps registers, allocates every DMA frame, resets and
 * starts the controller with bounded register spins and nothing else;
 * XhciEnumerate runs on the first kernel thread, where a millisecond nap
 * exists, and does the port resets and the addressing that need one.
 *
 * No interrupt, under the policy docs/19 §11f states for input: the event
 * ring is polled from the \Device\Input0/1 readers at 1 kHz through their
 * source's TryRead (drivers/hid.c), and at 1 kHz from the enumeration waits
 * before that. INTE stays clear, so the controller never asserts anything
 * (QEMU: xhci_intr_update requires USBCMD_INTE). Interrupts remain the
 * named exit, not a side effect (docs/19 §11d).
 *
 * Refusals are loud (Art. 12): a controller feature this driver has not
 * built (64-byte contexts, more scratchpad than the budget, more devices
 * than the budget, a stalled endpoint) names itself on serial and the
 * device or controller is left unused, never half-driven.
 */
#include "drivers/usb/xhci.h"
#include "drivers/pci.h"
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h" /* KPROCESSOR_MODE for the nap */
#include "kernel/mm/phys.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "abi/ntstatus.h"

/* --- PCI identity ----------------------------------------------------------- */

/* Class code 0Ch (serial bus) / 03h (USB) / 30h (xHCI) — xHCI 1.2 §5.2.2
 * (the PCI Code and ID Assignment Specification's row); cross-check pinned
 * QEMU hw/usb/hcd-xhci-pci.c: PCI_CLASS_SERIAL_USB, config[PCI_CLASS_PROG]
 * = 0x30. */
#define XHCI_PCI_BASE_CLASS 0x0C
#define XHCI_PCI_SUB_CLASS  0x03
#define XHCI_PCI_PROG_IF    0x30

/* --- Capability registers (§5.3, Table 5-9) ---------------------------------- */

/* Byte offsets from BAR0. CAPLENGTH is the low byte of dword 0 and
 * HCIVERSION its high word (§5.3.1/§5.3.2); read as one dword because the
 * pinned QEMU serves every region with min_access_size 4
 * (hw/usb/hcd-xhci.c xhci_cap_ops, and returns 0x01000000 | LEN_CAP here). */
#define XHCI_CAP_CAPLENGTH_HCIVERSION 0x00
#define XHCI_CAP_HCSPARAMS1           0x04 /* §5.3.3: MaxSlots 7:0, MaxIntrs 18:8, MaxPorts 31:24 */
#define XHCI_CAP_HCSPARAMS2           0x08 /* §5.3.4: ERST Max 7:4, Max Scratchpad Bufs Hi 25:21 Lo 31:27 */
#define XHCI_CAP_HCCPARAMS1           0x10 /* §5.3.6: AC64 bit 0, CSZ bit 2, xECP 31:16 (dwords) */
#define XHCI_CAP_DBOFF                0x14 /* §5.3.7: doorbell array offset, bits 31:2 */
#define XHCI_CAP_RTSOFF               0x18 /* §5.3.8: runtime register space offset, bits 31:5 */

#define XHCI_HCCPARAMS1_AC64 0x1u
#define XHCI_HCCPARAMS1_CSZ  0x4u

/* --- Extended capabilities (§7, Table 7-1) ------------------------------------ */

/* Each starts with a dword: Capability ID 7:0, Next Pointer 15:8 in dwords
 * (0 ends the list) — §7 Figure 7-1. IDs: 1 USB Legacy Support (§7.1), 2
 * Supported Protocol (§7.2). Cross-check pinned QEMU xhci_cap_read: 0x20 =
 * 0x02000402 (id 2, next 4, USB 2.0), 0x30 = 0x03000002 (id 2, next 0). */
#define XHCI_EXTCAP_ID_LEGACY   1
#define XHCI_EXTCAP_ID_PROTOCOL 2

/* USB Legacy Support: USBLEGSUP at +0 — HC BIOS Owned Semaphore bit 16, HC
 * OS Owned Semaphore bit 24 (§7.1.1 Table 7-2); USBLEGCTLSTS at +4 — the
 * SMI enables in bits 0, 4, 13, 14, 15 and the RW1C SMI status bits 29, 30,
 * 31 (§7.1.2 Table 7-3). The pinned QEMU offers no legacy capability, so
 * these have no runtime cross-check in the tree; they are exercised only on
 * firmware that hands the controller over (§4.22.1). */
#define XHCI_LEGSUP_BIOS_OWNED (1u << 16)
#define XHCI_LEGSUP_OS_OWNED   (1u << 24)
#define XHCI_LEGCTLSTS_OFFSET  4
#define XHCI_LEGCTLSTS_SMI_ENABLE_MASK                                                             \
    ((1u << 0) | (1u << 4) | (1u << 13) | (1u << 14) | (1u << 15))
#define XHCI_LEGCTLSTS_SMI_STATUS_RW1C ((1u << 29) | (1u << 30) | (1u << 31))

/* Supported Protocol: dword 0 Revision Minor 23:16 / Major 31:24, dword 2
 * Compatible Port Offset 7:0 / Compatible Port Count 15:8 (§7.2 Table
 * 7-4). Read for the serial line only — which ports are USB2 or USB3 is
 * something PORTSC already tells (a SuperSpeed port enables without a
 * reset, §4.19.1.2.4). */
#define XHCI_PROTOCOL_PORT_INFO_OFFSET 8

/* --- Operational registers (§5.4, Table 5-18; base = BAR0 + CAPLENGTH) -------- */

#define XHCI_OP_USBCMD   0x00  /* §5.4.1 Table 5-20 */
#define XHCI_OP_USBSTS   0x04  /* §5.4.2 Table 5-21 */
#define XHCI_OP_PAGESIZE 0x08  /* §5.4.3: bit n set -> 2^(n+12) bytes supported */
#define XHCI_OP_CRCR     0x18  /* §5.4.5: command ring pointer 63:6, RCS bit 0 */
#define XHCI_OP_DCBAAP   0x30  /* §5.4.6: device context base address array, 63:6 */
#define XHCI_OP_CONFIG   0x38  /* §5.4.7: MaxSlotsEn 7:0 */
#define XHCI_OP_PORTSC   0x400 /* §5.4.8: PORTSC(n) at 0x400 + 0x10 * (n - 1) */
#define XHCI_PORT_STRIDE 0x10

/* Cross-check for every bit below: pinned QEMU hw/usb/hcd-xhci.c "bit
 * definitions" (USBCMD_*, USBSTS_*, PORTSC_*, CRCR_*, IMAN_*, ERDP_EHB). */
#define XHCI_USBCMD_RS    (1u << 0)
#define XHCI_USBCMD_HCRST (1u << 1)
#define XHCI_USBCMD_INTE  (1u << 2)

#define XHCI_USBSTS_HCH (1u << 0)
#define XHCI_USBSTS_CNR (1u << 11)
#define XHCI_USBSTS_HCE (1u << 12)

#define XHCI_PAGESIZE_4K 0x1u

#define XHCI_CRCR_RCS 0x1u

/* PORTSC (§5.4.8 Table 5-27). PED is RW1C — a 1 written to it DISABLES the
 * port — and CSC/PEC/WRC/OCC/PRC/PLC/CEC are RW1C change bits, so a PORTSC
 * write carries only PP, PR, and the one change bit being acknowledged,
 * never a read-back value. The pinned QEMU masks these on write and would
 * have hidden the mistake; silicon does not. */
#define XHCI_PORTSC_CCS         (1u << 0)
#define XHCI_PORTSC_PED         (1u << 1)
#define XHCI_PORTSC_PR          (1u << 4)
#define XHCI_PORTSC_PP          (1u << 9)
#define XHCI_PORTSC_SPEED_SHIFT 10
#define XHCI_PORTSC_SPEED_MASK  0xFu
#define XHCI_PORTSC_CSC         (1u << 17)
#define XHCI_PORTSC_PRC         (1u << 21)

/* --- Runtime registers (§5.5, Table 5-35; base = BAR0 + RTSOFF) --------------- */

/* Interrupter 0's register set starts at 0x20 (§5.5.2): IMAN +0 (IP bit 0
 * RW1C, IE bit 1), IMOD +4, ERSTSZ +8 (15:0), ERSTBA +0x10 (63:6), ERDP
 * +0x18 (63:4, EHB bit 3 RW1C). Cross-check pinned QEMU xhci_runtime_write. */
#define XHCI_RT_IR0    0x20
#define XHCI_IR_IMAN   0x00
#define XHCI_IR_ERSTSZ 0x08
#define XHCI_IR_ERSTBA 0x10
#define XHCI_IR_ERDP   0x18
#define XHCI_ERDP_EHB  (1u << 3)

/* --- Doorbells (§5.6; base = BAR0 + DBOFF) ------------------------------------ */

/* Doorbell n at 4 * n; the value's DB Target 7:0 is 0 for the command ring
 * on doorbell 0 and the endpoint's DCI on a device slot's doorbell (§5.6
 * Table 5-44). Cross-check pinned QEMU xhci_doorbell_write. */
#define XHCI_DB_COMMAND 0

/* --- TRBs (§6.4) --------------------------------------------------------------- */

/* Control dword (word 3): Cycle bit 0, Toggle Cycle bit 1 (Link), ISP bit 2,
 * CH bit 4, IOC bit 5, IDT bit 6, TRB Type 15:10, DIR bit 16 (Data/Status
 * stage), TRT 17:16 (Setup stage; 3 = IN data, 2 = OUT data, 0 = none),
 * BSR bit 9 (Address Device), Slot ID 31:24 (commands and events), Endpoint
 * ID 20:16 (Transfer Event). Status dword (word 2): TRB Transfer Length /
 * residual 16:0 (23:0 in events), Completion Code 31:24 (events). §6.4.1,
 * §6.4.2, §6.4.3; cross-check pinned QEMU TRB_C, TRB_LK_TC, TRB_TR_ISP,
 * TRB_TR_IOC, TRB_TR_IDT, TRB_TYPE_SHIFT, TRB_TR_DIR, TRB_CR_BSR,
 * TRB_CR_SLOTID_SHIFT, TRB_CR_EPID_SHIFT, xhci_write_event. */
#define XHCI_TRB_CYCLE         (1u << 0)
#define XHCI_TRB_TOGGLE_CYCLE  (1u << 1)
#define XHCI_TRB_ISP           (1u << 2)
#define XHCI_TRB_IOC           (1u << 5)
#define XHCI_TRB_IDT           (1u << 6)
#define XHCI_TRB_BSR           (1u << 9)
#define XHCI_TRB_TYPE_SHIFT    10
#define XHCI_TRB_TYPE_MASK     0x3Fu
#define XHCI_TRB_DIR_IN        (1u << 16)
#define XHCI_TRB_TRT_IN        (3u << 16)
#define XHCI_TRB_TRT_OUT       (2u << 16)
#define XHCI_TRB_EPID_SHIFT    16
#define XHCI_TRB_EPID_MASK     0x1Fu
#define XHCI_TRB_SLOT_SHIFT    24
#define XHCI_TRB_LENGTH_MASK   0x1FFFFu
#define XHCI_EVENT_LENGTH_MASK 0xFFFFFFu
#define XHCI_EVENT_CC_SHIFT    24

/* TRB types (§6.4.6 Table 6-91; cross-check pinned QEMU hw/usb/hcd-xhci.h
 * enum TRBType, which is the same numbering). */
#define XHCI_TRB_TYPE_NORMAL             1
#define XHCI_TRB_TYPE_SETUP_STAGE        2
#define XHCI_TRB_TYPE_DATA_STAGE         3
#define XHCI_TRB_TYPE_STATUS_STAGE       4
#define XHCI_TRB_TYPE_LINK               6
#define XHCI_TRB_TYPE_ENABLE_SLOT        9
#define XHCI_TRB_TYPE_ADDRESS_DEVICE     11
#define XHCI_TRB_TYPE_CONFIGURE_ENDPOINT 12
#define XHCI_TRB_TYPE_EVALUATE_CONTEXT   13
#define XHCI_TRB_TYPE_TRANSFER_EVENT     32
#define XHCI_TRB_TYPE_COMMAND_COMPLETION 33
#define XHCI_TRB_TYPE_PORT_STATUS_CHANGE 34
#define XHCI_TRB_TYPE_HOST_CONTROLLER    37

/* One frame of TRBs per ring; the last slot of a producer ring is its Link
 * TRB. An Event Ring Segment Table entry is 16 bytes: base 63:6, size 15:0
 * of dword 2 (§6.5 Table 6-95); one segment of 256 (16..4096 is legal,
 * §6.5; the pinned QEMU xhci_er_reset dies outside that range and on any
 * ERSTSZ but 1 — HCSPARAMS2 ERST Max = 0 means one segment, §5.3.4). */
#define XHCI_RING_TRBS      (PAGE_SIZE / sizeof(XHCI_TRB))
#define XHCI_RING_LINK_SLOT (XHCI_RING_TRBS - 1)
#define XHCI_ERST_SIZE_WORD 2

/* --- Contexts (§6.2), 32-byte layout (HCCPARAMS1.CSZ = 0) -------------------- */

/* Device context: slot context at 0, endpoint context for DCI i at 32 * i
 * (§6.2.1 Figure 6-1). Input context: input control context at 0 — Drop
 * flags dword 0, Add flags dword 1 (§6.2.5.1) — then the same, shifted by
 * one context (§6.2.5 Figure 6-5). Cross-check pinned QEMU
 * xhci_address_slot: ictx+32 slot, ictx+64 EP0; xhci_configure_slot:
 * ictx+32+32*i. 64-byte contexts (CSZ = 1) are refused at bring-up. */
#define XHCI_CONTEXT_BYTES          32
#define XHCI_CONTEXT_DWORDS         (XHCI_CONTEXT_BYTES / 4)
#define XHCI_INPUT_CONTROL_ADD_WORD 1
#define XHCI_DEVICE_CONTEXT_ENTRIES 32 /* slot + DCI 1..31 */

/* Slot context (§6.2.2 Table 6-4): dword 0 Route String 19:0, Speed 23:20,
 * Context Entries 31:27; dword 1 Root Hub Port Number 23:16; dword 3
 * Slot State 31:27. Cross-check pinned QEMU xhci_lookup_uport
 * (slot_ctx[1] >> 16), SLOT_CONTEXT_ENTRIES_SHIFT 27, SLOT_STATE_SHIFT. */
#define XHCI_SLOT_SPEED_SHIFT           20
#define XHCI_SLOT_CONTEXT_ENTRIES_SHIFT 27
#define XHCI_SLOT_ROOT_PORT_SHIFT       16

/* Endpoint context (§6.2.3 Table 6-8): dword 0 Interval 23:16, Max ESIT
 * Payload Hi 31:24; dword 1 CErr 2:1, EP Type 5:3, Max Packet Size 31:16;
 * dwords 2-3 TR Dequeue Pointer 63:4 with DCS bit 0; dword 4 Average TRB
 * Length 15:0, Max ESIT Payload Lo 31:16. EP Type 4 = Control, 7 =
 * Interrupt IN (Table 6-9). Cross-check pinned QEMU xhci_init_epctx
 * (EP_TYPE_SHIFT 3, max_psize = ctx[1] >> 16, interval = ctx[0] >> 16 & 0xff,
 * dequeue = ctx[2] & ~0xf | ctx[3] << 32, ccs = ctx[2] & 1). */
#define XHCI_EP_INTERVAL_SHIFT    16
#define XHCI_EP_CERR_SHIFT        1
#define XHCI_EP_TYPE_SHIFT        3
#define XHCI_EP_MAX_PACKET_SHIFT  16
#define XHCI_EP_TYPE_CONTROL      4
#define XHCI_EP_TYPE_INTERRUPT_IN 7
#define XHCI_EP_DCS               0x1u
#define XHCI_EP_MAX_ESIT_LO_SHIFT 16
#define XHCI_EP_CERR_DEFAULT      3 /* §4.8.2.1 recommends 3 retries */

/* --- Bounds ------------------------------------------------------------------- */

/* Register spins in phase 1 (no clock yet): the pinned QEMU completes
 * HCRST and RS synchronously, so any bound passes it; on silicon HCRST is
 * specified to complete before CNR clears and takes milliseconds, and a
 * million uncached reads is on the order of a second. Beyond it the
 * controller is refused, not waited on forever. */
#define XHCI_SPIN_LIMIT 1000000u

/* Phase 2 waits, in 1 ms naps: a command or control transfer on the pinned
 * QEMU completes within the same nap; USB 2.0 §9.2.6.4 allows a device 5 s
 * for a standard request, and 1 s is the driver's patience before a device
 * is refused. Port reset: USB 2.0 §7.1.7.5 has the reset signal itself
 * last 10-20 ms (50 ms on a root hub), so 500 naps is generous. */
#define XHCI_WAIT_NAPS       1000u
#define XHCI_PORT_RESET_NAPS 500u

/* USB 2.0 timing after connect and reset, honoured with naps: §7.1.7.3
 * debounce 100 ms after a connect before a reset; §7.1.7.5 reset recovery
 * 10 ms before the device must answer; §9.2.6.3 SET_ADDRESS recovery 2 ms.
 * The pinned QEMU needs none of them; a bare-metal device does. */
#define USB_DEBOUNCE_MS       100u
#define USB_RESET_RECOVERY_MS 10u
#define USB_SET_ADDRESS_MS    2u

/* Scratchpad buffers the controller may demand (§4.20). The pinned QEMU
 * asks for none (HCSPARAMS2 = 0xF); a controller asking for more than this
 * is refused, not partially served. */
#define XHCI_MAX_SCRATCHPAD 16

/* --- Standard requests this file issues itself (USB 2.0 §9.4 Table 9-3/9-4) --- */

#define USB_REQUEST_TYPE_DEVICE_TO_HOST_STANDARD 0x80
#define USB_REQUEST_GET_DESCRIPTOR               6
#define USB_DESCRIPTOR_TYPE_DEVICE               1
#define USB_DESCRIPTOR_TYPE_CONFIGURATION        2
#define USB_DEVICE_DESCRIPTOR_OFF_MAX_PACKET0    7 /* bMaxPacketSize0, §9.6.1 Table 9-8 */
#define USB_DEVICE_DESCRIPTOR_OFF_VENDOR         8
#define USB_DEVICE_DESCRIPTOR_OFF_PRODUCT        10
#define USB_CONFIG_DESCRIPTOR_OFF_TOTAL_LENGTH   2 /* wTotalLength, §9.6.3 Table 9-10 */
#define USB_REPORT_BUFFER_OFFSET                 256

/* --- State --------------------------------------------------------------------- */

typedef struct XHCI_CONTROLLER
{
    BOOLEAN present;
    BOOLEAN enumerated; /* phase 2 done: the rings belong to the readers now */
    KI_PCI_FUNCTION function;
    volatile uint8_t *base;        /* BAR0 */
    volatile uint8_t *op;          /* operational registers */
    volatile uint8_t *rt;          /* runtime registers */
    volatile uint8_t *db;          /* doorbell array */
    uint32_t extendedCapabilities; /* byte offset of the first, 0 if none */
    unsigned maxSlots, maxPorts;

    uint64_t dcbaaPhysical;
    uint64_t *dcbaa; /* device context base address array (§6.1) */
    XHCI_RING commandRing;

    /* The event ring, consumer side: dequeue index and consumer cycle state
     * (§4.9.4). */
    uint64_t eventRingPhysical, erstPhysical;
    XHCI_TRB *eventRing;
    uint32_t eventDequeue;
    uint32_t eventCycle;

    BOOLEAN inPoll; /* the drain is not re-entrant, and asserts it */

    /* Phase 2's one outstanding wait: the TRB whose completion is awaited,
     * and the data-stage TRB whose residual it wants to know. */
    uint64_t awaitedPhysical;
    BOOLEAN awaitedDone;
    XHCI_TRB awaitedEvent;
    uint64_t awaitedDataPhysical;
    uint32_t awaitedDataResidual;
    BOOLEAN awaitedDataSeen;
} XHCI_CONTROLLER;

static XHCI_CONTROLLER XhciController;
static USB_DEVICE XhciDevices[USB_MAX_DEVICES];
static unsigned XhciDeviceTotal;
static USB_DEVICE *XhciSlotDevice[256]; /* slot id -> device (slot ids are 8 bits, §6.4.2.2) */

/* --- MMIO ---------------------------------------------------------------------- */

static uint32_t XhciRead32(volatile uint8_t *base, uint32_t offset)
{
    return *(volatile uint32_t *)(base + offset);
}

static void XhciWrite32(volatile uint8_t *base, uint32_t offset, uint32_t value)
{
    *(volatile uint32_t *)(base + offset) = value;
}

/* 64-bit registers as two dword stores, low half first: the pinned QEMU
 * acts on the HIGH half's write for CRCR (ring init) and ERSTBA (event
 * ring reset), so the low half must already hold its value. */
static void XhciWrite64(volatile uint8_t *base, uint32_t offset, uint64_t value)
{
    XhciWrite32(base, offset, (uint32_t)value);
    XhciWrite32(base, offset + 4, (uint32_t)(value >> 32));
}

/* Ordering between the driver's DMA writes (write-back memory) and the
 * doorbell (uncached MMIO): mfence, and the compiler barrier it implies —
 * the same primitive drivers/virtio/virtqueue.c uses at its avail ring. */
static void XhciMemoryBarrier(void)
{
    __sync_synchronize();
}

static BOOLEAN XhciSpinUntil(volatile uint8_t *base, uint32_t offset, uint32_t mask, uint32_t want)
{
    for (unsigned spin = 0; spin < XHCI_SPIN_LIMIT; spin++)
    {
        if ((XhciRead32(base, offset) & mask) == want)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/* The host controller error bit: once set the controller has stopped
 * (§5.4.2 HCE), and everything after it would be programming a corpse. */
static BOOLEAN XhciHealthy(const char *step)
{
    if (XhciRead32(XhciController.op, XHCI_OP_USBSTS) & XHCI_USBSTS_HCE)
    {
        DbgPrint("usb: xhci host controller error after %s; controller refused\n", step);
        return FALSE;
    }
    return TRUE;
}

/* --- Frames -------------------------------------------------------------------- */

/* One zeroed frame. MiAllocatePage hands back whatever the frame held;
 * every DMA structure here must start as zeroes (a context with garbage in
 * it is a TRB Error at best). Frames are never freed: the controller holds
 * their addresses for the kernel's lifetime, like virtio's rings. */
static void *XhciAllocateFrame(uint64_t *physicalOut)
{
    uint64_t physical = MiAllocatePage();
    if (physical == 0)
    {
        return 0;
    }
    void *virtual = MiPhysicalToVirtual(physical);
    memset(virtual, 0, PAGE_SIZE);
    *physicalOut = physical;
    return virtual;
}

/* --- Rings --------------------------------------------------------------------- */

static BOOLEAN XhciRingInitialize(XHCI_RING *ring)
{
    ring->trbs = XhciAllocateFrame(&ring->physical);
    if (ring->trbs == 0)
    {
        return FALSE;
    }
    ring->enqueue = 0;
    ring->cycle = 1;
    /* The Link TRB: pointer back to the base, Toggle Cycle set (§6.4.4.1
     * Table 6-92). Its cycle bit stays 0 — the consumer's cycle state is 1
     * until it follows this link, so it stops here until XhciRingPush
     * writes the current cycle into it. */
    XHCI_TRB *link = &ring->trbs[XHCI_RING_LINK_SLOT];
    link->words[0] = (uint32_t)ring->physical;
    link->words[1] = (uint32_t)(ring->physical >> 32);
    link->words[2] = 0;
    link->words[3] = (XHCI_TRB_TYPE_LINK << XHCI_TRB_TYPE_SHIFT) | XHCI_TRB_TOGGLE_CYCLE;
    return TRUE;
}

/* Enqueue one TRB (its control dword without the cycle bit) and return its
 * physical address, which is what the completion event names (§4.9.2:
 * the producer writes the TRB, then its cycle bit; the consumer stops at a
 * cycle mismatch). At the Link TRB the producer hands the link its cycle
 * bit and toggles its own (§4.9.2.2). */
static uint64_t XhciRingPush(XHCI_RING *ring, uint64_t parameter, uint32_t status, uint32_t control)
{
    ASSERT(ring->enqueue < XHCI_RING_LINK_SLOT);
    XHCI_TRB *trb = &ring->trbs[ring->enqueue];
    uint64_t physical = ring->physical + (uint64_t)ring->enqueue * sizeof(XHCI_TRB);
    trb->words[0] = (uint32_t)parameter;
    trb->words[1] = (uint32_t)(parameter >> 32);
    trb->words[2] = status;
    XhciMemoryBarrier();
    trb->words[3] = (control & ~XHCI_TRB_CYCLE) | (ring->cycle ? XHCI_TRB_CYCLE : 0);
    ring->enqueue++;
    if (ring->enqueue == XHCI_RING_LINK_SLOT)
    {
        XHCI_TRB *link = &ring->trbs[XHCI_RING_LINK_SLOT];
        XhciMemoryBarrier();
        link->words[3] = (link->words[3] & ~XHCI_TRB_CYCLE) | (ring->cycle ? XHCI_TRB_CYCLE : 0);
        ring->enqueue = 0;
        ring->cycle ^= 1;
    }
    return physical;
}

static void XhciRingDoorbell(unsigned slot, unsigned target)
{
    XhciMemoryBarrier();
    XhciWrite32(XhciController.db, slot * 4, target);
}

/* --- Event ring ---------------------------------------------------------------- */

static uint8_t XhciEventCompletionCode(const XHCI_TRB *event)
{
    return (uint8_t)(event->words[2] >> XHCI_EVENT_CC_SHIFT);
}

static uint64_t XhciEventParameter(const XHCI_TRB *event)
{
    return (uint64_t)event->words[0] | ((uint64_t)event->words[1] << 32);
}

static void XhciDispatchTransferEvent(const XHCI_TRB *event)
{
    XHCI_CONTROLLER *hc = &XhciController;
    uint64_t trbPhysical = XhciEventParameter(event);
    uint32_t residual = event->words[2] & XHCI_EVENT_LENGTH_MASK;
    uint8_t completionCode = XhciEventCompletionCode(event);
    unsigned slot = event->words[3] >> XHCI_TRB_SLOT_SHIFT;
    unsigned dci = (event->words[3] >> XHCI_TRB_EPID_SHIFT) & XHCI_TRB_EPID_MASK;

    if (!hc->enumerated)
    {
        /* Phase 2 owns EP0: the awaited status stage, or the data stage
         * whose residual it wants. */
        if (trbPhysical == hc->awaitedPhysical && !hc->awaitedDone)
        {
            hc->awaitedEvent = *event;
            hc->awaitedDone = TRUE;
            return;
        }
        if (trbPhysical == hc->awaitedDataPhysical && hc->awaitedDataPhysical != 0)
        {
            hc->awaitedDataResidual = residual;
            hc->awaitedDataSeen = TRUE;
            return;
        }
    }
    USB_DEVICE *device = slot < 256 ? XhciSlotDevice[slot] : 0;
    if (device != 0 && device->OnTransfer != 0 && dci == device->intrDci &&
        trbPhysical == device->intrTrbPhysical)
    {
        device->intrTrbPhysical = 0;
        device->OnTransfer(device, completionCode, residual);
        return;
    }
    DbgPrint("usb: unexpected transfer event slot %u dci %u cc %u trb %#llx\n", slot, dci,
             completionCode, (unsigned long long)trbPhysical);
}

void XhciPollEvents(void)
{
    XHCI_CONTROLLER *hc = &XhciController;
    ASSERT(hc->present);
    /* Two readers park in turn, never at once: the kernel is uniprocessor
     * and non-preemptive (Art. 3), and this drain contains no wait, so a
     * second entry can only be a bug. */
    ASSERT(!hc->inPoll);
    hc->inPoll = TRUE;

    unsigned drained = 0;
    for (;;)
    {
        volatile XHCI_TRB *slot = &hc->eventRing[hc->eventDequeue];
        uint32_t control = slot->words[3];
        if ((control & XHCI_TRB_CYCLE) != (hc->eventCycle ? XHCI_TRB_CYCLE : 0))
        {
            break; /* the controller has not written this one yet (§4.9.4) */
        }
        XhciMemoryBarrier();
        XHCI_TRB event;
        event.words[0] = slot->words[0];
        event.words[1] = slot->words[1];
        event.words[2] = slot->words[2];
        event.words[3] = control;

        unsigned type = (control >> XHCI_TRB_TYPE_SHIFT) & XHCI_TRB_TYPE_MASK;
        switch (type)
        {
        case XHCI_TRB_TYPE_TRANSFER_EVENT:
            XhciDispatchTransferEvent(&event);
            break;
        case XHCI_TRB_TYPE_COMMAND_COMPLETION:
            if (!hc->enumerated && !hc->awaitedDone &&
                XhciEventParameter(&event) == hc->awaitedPhysical)
            {
                hc->awaitedEvent = event;
                hc->awaitedDone = TRUE;
            }
            else
            {
                DbgPrint("usb: unexpected command completion cc %u trb %#llx\n",
                         XhciEventCompletionCode(&event),
                         (unsigned long long)XhciEventParameter(&event));
            }
            break;
        case XHCI_TRB_TYPE_PORT_STATUS_CHANGE:
            /* Port ID in parameter bits 31:24 (§6.4.2.3). Consumed and
             * named: hot-plug is not built, and enumeration reads PORTSC
             * directly rather than trusting a change event. */
            DbgPrint("usb: port %u status change (no hot-plug; ignored)\n",
                     (unsigned)(event.words[0] >> 24));
            break;
        case XHCI_TRB_TYPE_HOST_CONTROLLER:
            /* Event Ring Full Error (§4.9.4.1) is the one worth naming: it
             * means events were lost while nobody polled. */
            DbgPrint("usb: host controller event cc %u%s\n", XhciEventCompletionCode(&event),
                     XhciEventCompletionCode(&event) == XHCI_CC_EVENT_RING_FULL
                         ? " (event ring full: events lost)"
                         : "");
            break;
        default:
            DbgPrint("usb: unexpected event type %u\n", type);
            break;
        }

        hc->eventDequeue++;
        if (hc->eventDequeue == XHCI_RING_TRBS)
        {
            hc->eventDequeue = 0;
            hc->eventCycle ^= 1;
        }
        drained++;
    }
    if (drained != 0)
    {
        /* Tell the controller where the software dequeue pointer is, with
         * EHB written as 1 to clear it (§5.5.2.3.3). High half first: the
         * pinned QEMU acts on the low half's write. */
        uint64_t erdp = hc->eventRingPhysical + (uint64_t)hc->eventDequeue * sizeof(XHCI_TRB);
        XhciWrite32(hc->rt, XHCI_RT_IR0 + XHCI_IR_ERDP + 4, (uint32_t)(erdp >> 32));
        XhciWrite32(hc->rt, XHCI_RT_IR0 + XHCI_IR_ERDP, (uint32_t)erdp | XHCI_ERDP_EHB);
    }
    hc->inPoll = FALSE;
}

/* --- Phase 1: bring-up ------------------------------------------------------- */

/* Walk the extended capability list (§7): the USB Legacy Support handoff
 * (§4.22.1) when firmware owns the controller, and one serial line per
 * Supported Protocol range. Bounded, the way KiPciFindCapability bounds
 * PCI's list: 64 links is more than a 4 KiB register space holds. */
static BOOLEAN XhciHandleExtendedCapabilities(void)
{
    XHCI_CONTROLLER *hc = &XhciController;
    uint32_t offset = hc->extendedCapabilities;
    BOOLEAN sawLegacy = FALSE;
    for (unsigned link = 0; offset != 0 && link < 64; link++)
    {
        uint32_t header = XhciRead32(hc->base, offset);
        uint32_t id = header & 0xFF;
        uint32_t next = (header >> 8) & 0xFF;
        if (id == XHCI_EXTCAP_ID_LEGACY)
        {
            sawLegacy = TRUE;
            if (header & XHCI_LEGSUP_BIOS_OWNED)
            {
                /* §4.22.1: set HC OS Owned, wait for firmware to release. */
                XhciWrite32(hc->base, offset, header | XHCI_LEGSUP_OS_OWNED);
                if (!XhciSpinUntil(hc->base, offset, XHCI_LEGSUP_BIOS_OWNED, 0))
                {
                    DbgPrint("usb: firmware never released the xHCI (USBLEGSUP %#x); refused\n",
                             XhciRead32(hc->base, offset));
                    return FALSE;
                }
                DbgPrint("usb: xhci taken over from firmware\n");
            }
            else
            {
                XhciWrite32(hc->base, offset, header | XHCI_LEGSUP_OS_OWNED);
            }
            /* No SMIs from here on: clear the enables, acknowledge the
             * RW1C status bits (§7.1.2). */
            uint32_t control = XhciRead32(hc->base, offset + XHCI_LEGCTLSTS_OFFSET);
            control &= ~XHCI_LEGCTLSTS_SMI_ENABLE_MASK;
            control |= XHCI_LEGCTLSTS_SMI_STATUS_RW1C;
            XhciWrite32(hc->base, offset + XHCI_LEGCTLSTS_OFFSET, control);
        }
        else if (id == XHCI_EXTCAP_ID_PROTOCOL)
        {
            uint32_t ports = XhciRead32(hc->base, offset + XHCI_PROTOCOL_PORT_INFO_OFFSET);
            unsigned first = ports & 0xFF;
            unsigned count = (ports >> 8) & 0xFF;
            DbgPrint("usb: xhci USB %u.%u ports %u..%u\n", header >> 24, (header >> 16) & 0xFF,
                     first, first + count - 1);
        }
        offset = next != 0 ? offset + next * 4 : 0;
    }
    if (!sawLegacy)
    {
        DbgPrint("usb: no USB Legacy Support capability; no firmware handoff needed\n");
    }
    return TRUE;
}

static BOOLEAN XhciAllocateDeviceFrames(USB_DEVICE *device)
{
    device->outputContext = XhciAllocateFrame(&device->outputContextPhysical);
    device->inputContext = XhciAllocateFrame(&device->inputContextPhysical);
    device->scratch = XhciAllocateFrame(&device->scratchPhysical);
    if (device->outputContext == 0 || device->inputContext == 0 || device->scratch == 0)
    {
        return FALSE;
    }
    return XhciRingInitialize(&device->ep0Ring) && XhciRingInitialize(&device->intrRing);
}

BOOLEAN XhciInitialize(void)
{
    XHCI_CONTROLLER *hc = &XhciController;
    memset(hc, 0, sizeof(*hc));

    if (!KiPciFindDeviceByClass(XHCI_PCI_BASE_CLASS, XHCI_PCI_SUB_CLASS, XHCI_PCI_PROG_IF, 0,
                                &hc->function))
    {
        DbgPrint("usb: no xHCI controller on PCI bus 0\n");
        return FALSE;
    }
    uint64_t bar = KiPciReadMemoryBar(&hc->function, 0);
    if (bar == 0)
    {
        DbgPrint("usb: xhci %02x:%x BAR0 is not a memory BAR; refused\n", hc->function.device,
                 hc->function.function);
        return FALSE;
    }
    /* Enable MMIO decoding + bus mastering (PCI 3.0 §6.2.2 Table 6-1). */
    uint16_t command = KiPciReadConfig16(&hc->function, PCI_CONFIG_COMMAND);
    KiPciWriteConfig16(&hc->function, PCI_CONFIG_COMMAND,
                       command | PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER);

    /* The register space's size is what the capability registers say it
     * is: map one page to read them, then the whole extent. The first page
     * stays mapped (the window never unmaps, drivers/pci.h). */
    volatile uint8_t *probe = KiPciMapMmio(bar, PAGE_SIZE);
    uint32_t lengthVersion = XhciRead32(probe, XHCI_CAP_CAPLENGTH_HCIVERSION);
    uint32_t capLength = lengthVersion & 0xFF;
    uint32_t hciVersion = lengthVersion >> 16;
    uint32_t hcsParams1 = XhciRead32(probe, XHCI_CAP_HCSPARAMS1);
    uint32_t hcsParams2 = XhciRead32(probe, XHCI_CAP_HCSPARAMS2);
    uint32_t hccParams1 = XhciRead32(probe, XHCI_CAP_HCCPARAMS1);
    uint32_t dbOffset = XhciRead32(probe, XHCI_CAP_DBOFF) & ~0x3u;
    uint32_t rtOffset = XhciRead32(probe, XHCI_CAP_RTSOFF) & ~0x1Fu;
    hc->maxSlots = hcsParams1 & 0xFF;
    hc->maxPorts = hcsParams1 >> 24;

    if (hciVersion < 0x0100 || hc->maxSlots == 0 || hc->maxPorts == 0)
    {
        DbgPrint("usb: xhci %02x:%x implausible (HCIVERSION %04x, %u slots, %u ports); refused\n",
                 hc->function.device, hc->function.function, hciVersion, hc->maxSlots,
                 hc->maxPorts);
        return FALSE;
    }
    if (hccParams1 & XHCI_HCCPARAMS1_CSZ)
    {
        /* 64-byte contexts (§6.2.1, CSZ = 1): a second layout this driver
         * has not built. Refused rather than half-supported (Art. 12). */
        DbgPrint("usb: xhci uses 64-byte contexts; unbuilt, controller refused\n");
        return FALSE;
    }
    uint64_t extent = capLength + XHCI_OP_PORTSC + (uint64_t)XHCI_PORT_STRIDE * hc->maxPorts;
    if (rtOffset + XHCI_RT_IR0 + 0x20 > extent)
    {
        extent = rtOffset + XHCI_RT_IR0 + 0x20;
    }
    if (dbOffset + 4 * ((uint64_t)hc->maxSlots + 1) > extent)
    {
        extent = dbOffset + 4 * ((uint64_t)hc->maxSlots + 1);
    }
    hc->base = KiPciMapMmio(bar, extent);
    hc->op = hc->base + capLength;
    hc->rt = hc->base + rtOffset;
    hc->db = hc->base + dbOffset;
    hc->extendedCapabilities = (hccParams1 >> 16) * 4;

    if ((XhciRead32(hc->op, XHCI_OP_PAGESIZE) & XHCI_PAGESIZE_4K) == 0)
    {
        DbgPrint("usb: xhci does not support 4 KiB pages (PAGESIZE %#x); refused\n",
                 XhciRead32(hc->op, XHCI_OP_PAGESIZE));
        return FALSE;
    }
    if (!XhciHandleExtendedCapabilities())
    {
        return FALSE;
    }

    /* §4.2 step 1: halt, reset, wait for the controller to be ready. A
     * running controller (firmware left it so) must halt before HCRST. */
    uint32_t usbCommand = XhciRead32(hc->op, XHCI_OP_USBCMD);
    if (usbCommand & XHCI_USBCMD_RS)
    {
        XhciWrite32(hc->op, XHCI_OP_USBCMD, usbCommand & ~XHCI_USBCMD_RS);
        if (!XhciSpinUntil(hc->op, XHCI_OP_USBSTS, XHCI_USBSTS_HCH, XHCI_USBSTS_HCH))
        {
            DbgPrint("usb: xhci would not halt; refused\n");
            return FALSE;
        }
    }
    XhciWrite32(hc->op, XHCI_OP_USBCMD, XHCI_USBCMD_HCRST);
    if (!XhciSpinUntil(hc->op, XHCI_OP_USBCMD, XHCI_USBCMD_HCRST, 0) ||
        !XhciSpinUntil(hc->op, XHCI_OP_USBSTS, XHCI_USBSTS_CNR, 0))
    {
        DbgPrint("usb: xhci reset did not complete; refused\n");
        return FALSE;
    }
    if (!XhciHealthy("reset"))
    {
        return FALSE;
    }

    /* Every DMA frame, now, before the kernel PML4 freezes: the array, the
     * command ring, the event ring and its one-entry segment table, the
     * scratchpad the controller asks for, and each device's five. */
    hc->dcbaa = XhciAllocateFrame(&hc->dcbaaPhysical);
    XHCI_TRB *eventRing = XhciAllocateFrame(&hc->eventRingPhysical);
    uint64_t *erst = XhciAllocateFrame(&hc->erstPhysical);
    if (hc->dcbaa == 0 || eventRing == 0 || erst == 0 || !XhciRingInitialize(&hc->commandRing))
    {
        DbgPrint("usb: out of frames for the xhci rings; refused\n");
        return FALSE;
    }
    hc->eventRing = eventRing;
    for (unsigned index = 0; index < USB_MAX_DEVICES; index++)
    {
        if (!XhciAllocateDeviceFrames(&XhciDevices[index]))
        {
            DbgPrint("usb: out of frames for device %u; refused\n", index);
            return FALSE;
        }
    }
    /* Max Scratchpad Bufs = Hi (25:21) << 5 | Lo (31:27) (§5.3.4 Table
     * 5-10). The array of their addresses is what DCBAA[0] points at
     * (§6.6). */
    unsigned scratchpads = (((hcsParams2 >> 21) & 0x1F) << 5) | ((hcsParams2 >> 27) & 0x1F);
    if (scratchpads > XHCI_MAX_SCRATCHPAD)
    {
        DbgPrint("usb: xhci wants %u scratchpad buffers, budget is %u; refused\n", scratchpads,
                 XHCI_MAX_SCRATCHPAD);
        return FALSE;
    }
    if (scratchpads != 0)
    {
        uint64_t arrayPhysical;
        uint64_t *array = XhciAllocateFrame(&arrayPhysical);
        if (array == 0)
        {
            DbgPrint("usb: out of frames for the scratchpad array; refused\n");
            return FALSE;
        }
        for (unsigned index = 0; index < scratchpads; index++)
        {
            uint64_t physical;
            if (XhciAllocateFrame(&physical) == 0)
            {
                DbgPrint("usb: out of frames for scratchpad %u; refused\n", index);
                return FALSE;
            }
            array[index] = physical;
        }
        hc->dcbaa[0] = arrayPhysical;
    }

    /* §4.2 steps 3-8: slots enabled, the array, the command ring with its
     * initial cycle state, the one event ring segment, the dequeue pointer;
     * then run. Interrupter 0 stays without IE and USBCMD without INTE:
     * events are polled. */
    XhciWrite32(hc->op, XHCI_OP_CONFIG, hc->maxSlots);
    XhciWrite64(hc->op, XHCI_OP_DCBAAP, hc->dcbaaPhysical);
    XhciWrite64(hc->op, XHCI_OP_CRCR, hc->commandRing.physical | XHCI_CRCR_RCS);
    erst[0] = hc->eventRingPhysical;
    ((uint32_t *)erst)[XHCI_ERST_SIZE_WORD] = XHCI_RING_TRBS;
    hc->eventDequeue = 0;
    hc->eventCycle = 1;
    XhciWrite32(hc->rt, XHCI_RT_IR0 + XHCI_IR_ERSTSZ, 1);
    XhciWrite64(hc->rt, XHCI_RT_IR0 + XHCI_IR_ERDP, hc->eventRingPhysical);
    XhciWrite64(hc->rt, XHCI_RT_IR0 + XHCI_IR_ERSTBA, hc->erstPhysical);
    if (!XhciHealthy("ring setup"))
    {
        return FALSE;
    }
    XhciMemoryBarrier();
    XhciWrite32(hc->op, XHCI_OP_USBCMD, XHCI_USBCMD_RS);
    if (!XhciSpinUntil(hc->op, XHCI_OP_USBSTS, XHCI_USBSTS_HCH, 0) || !XhciHealthy("run"))
    {
        DbgPrint("usb: xhci did not start; refused\n");
        return FALSE;
    }

    hc->present = TRUE;
    DbgPrint("[KTEST] usb xhci READY %02x:%x id %04x:%04x hciversion %04x ports %u slots %u\n",
             hc->function.device, hc->function.function, hc->function.vendorId,
             hc->function.deviceId, hciVersion, hc->maxPorts, hc->maxSlots);
    return TRUE;
}

BOOLEAN XhciIsPresent(void)
{
    return XhciController.present;
}

/* --- Phase 2: waiting, commands, control transfers ---------------------------- */

static NTSTATUS XhciNap(unsigned milliseconds)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -(LONGLONG)milliseconds * 10000; /* relative 100 ns units */
    return KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

/* Poll for the completion of one TRB, napping between polls. Returns the
 * completion code, XHCI_CC_TIMEOUT when nothing arrived. */
static uint8_t XhciAwait(uint64_t trbPhysical, uint64_t dataPhysical, XHCI_TRB *eventOut,
                         uint32_t *dataResidualOut)
{
    XHCI_CONTROLLER *hc = &XhciController;
    ASSERT(!hc->enumerated);
    hc->awaitedPhysical = trbPhysical;
    hc->awaitedDone = FALSE;
    hc->awaitedDataPhysical = dataPhysical;
    hc->awaitedDataSeen = FALSE;
    hc->awaitedDataResidual = 0;
    for (unsigned nap = 0; nap < XHCI_WAIT_NAPS; nap++)
    {
        XhciPollEvents();
        if (hc->awaitedDone)
        {
            break;
        }
        if (XhciNap(1) != STATUS_SUCCESS)
        {
            break;
        }
    }
    hc->awaitedPhysical = 0;
    hc->awaitedDataPhysical = 0;
    if (!hc->awaitedDone)
    {
        return XHCI_CC_TIMEOUT;
    }
    *eventOut = hc->awaitedEvent;
    if (dataResidualOut != 0)
    {
        *dataResidualOut = hc->awaitedDataSeen ? hc->awaitedDataResidual : 0;
    }
    return XhciEventCompletionCode(&hc->awaitedEvent);
}

/* One command: enqueue, ring doorbell 0, wait for its Command Completion
 * Event (§4.6.1). The event's Slot ID (control 31:24) is returned through
 * slotOut for Enable Slot. */
static uint8_t XhciCommand(uint64_t parameter, uint32_t control, unsigned *slotOut)
{
    XHCI_CONTROLLER *hc = &XhciController;
    uint64_t physical = XhciRingPush(&hc->commandRing, parameter, 0, control);
    XhciRingDoorbell(0, XHCI_DB_COMMAND);
    XHCI_TRB event;
    uint8_t completionCode = XhciAwait(physical, 0, &event, 0);
    if (slotOut != 0)
    {
        *slotOut = completionCode == XHCI_CC_TIMEOUT ? 0 : event.words[3] >> XHCI_TRB_SLOT_SHIFT;
    }
    return completionCode;
}

uint8_t XhciControlTransfer(USB_DEVICE *device, uint8_t requestType, uint8_t request,
                            uint16_t value, uint16_t index, uint64_t bufferPhysical,
                            uint16_t length, uint16_t *transferredOut)
{
    ASSERT(device->present && device->slotId != 0);
    BOOLEAN in = (requestType & USB_REQUEST_TYPE_DEVICE_TO_HOST_STANDARD) != 0;

    /* The setup packet (USB 2.0 §9.3 Table 9-2: bmRequestType, bRequest,
     * wValue, wIndex, wLength, little-endian) rides in the Setup Stage
     * TRB's parameter itself (IDT, §6.4.1.2.1 Table 6-25), length 8. */
    uint64_t setup = (uint64_t)requestType | ((uint64_t)request << 8) | ((uint64_t)value << 16) |
                     ((uint64_t)index << 32) | ((uint64_t)length << 48);
    uint32_t transferType = length == 0 ? 0 : (in ? XHCI_TRB_TRT_IN : XHCI_TRB_TRT_OUT);
    XhciRingPush(&device->ep0Ring, setup, 8,
                 (XHCI_TRB_TYPE_SETUP_STAGE << XHCI_TRB_TYPE_SHIFT) | XHCI_TRB_IDT | transferType);
    uint64_t dataPhysical = 0;
    if (length != 0)
    {
        /* ISP: a short data stage reports its residual (§6.4.1.2.2), which
         * is how a descriptor shorter than asked for is sized. */
        dataPhysical = XhciRingPush(&device->ep0Ring, bufferPhysical, length,
                                    (XHCI_TRB_TYPE_DATA_STAGE << XHCI_TRB_TYPE_SHIFT) |
                                        XHCI_TRB_ISP | (in ? XHCI_TRB_DIR_IN : 0));
    }
    /* Status stage direction is opposite the data stage's, IN when there
     * is no data stage (§4.11.2.2 Table 4-7). */
    uint64_t statusPhysical =
        XhciRingPush(&device->ep0Ring, 0, 0,
                     (XHCI_TRB_TYPE_STATUS_STAGE << XHCI_TRB_TYPE_SHIFT) | XHCI_TRB_IOC |
                         ((length == 0 || !in) ? XHCI_TRB_DIR_IN : 0));
    XhciRingDoorbell(device->slotId, 1); /* EP0 is DCI 1 (§4.5.1) */

    XHCI_TRB event;
    uint32_t residual = 0;
    uint8_t completionCode = XhciAwait(statusPhysical, dataPhysical, &event, &residual);
    if (transferredOut != 0)
    {
        *transferredOut = (uint16_t)(residual <= length ? length - residual : 0);
    }
    if (completionCode != XHCI_CC_SUCCESS && completionCode != XHCI_CC_SHORT_PACKET)
    {
        DbgPrint("usb: slot %u control %02x/%02x value %04x index %04x: cc %u\n", device->slotId,
                 requestType, request, value, index, completionCode);
    }
    return completionCode;
}

/* --- Phase 2: enumeration ------------------------------------------------------- */

static uint16_t XhciDefaultMaxPacket0(uint8_t speed)
{
    /* Default control pipe sizes before the device descriptor is read
     * (§4.3 step 6 / Table 4-3 by speed; USB 2.0 §5.5.3): low 8, full 8
     * (then bMaxPacketSize0), high 64, super 512. */
    switch (speed)
    {
    case USB_SPEED_LOW:
    case USB_SPEED_FULL:
        return 8;
    case USB_SPEED_HIGH:
        return 64;
    case USB_SPEED_SUPER:
        return 512;
    default:
        return 0;
    }
}

static uint32_t *XhciInputSlotContext(USB_DEVICE *device)
{
    return device->inputContext + XHCI_CONTEXT_DWORDS;
}

static uint32_t *XhciInputEndpointContext(USB_DEVICE *device, unsigned dci)
{
    return device->inputContext + XHCI_CONTEXT_DWORDS * (1 + dci);
}

static void XhciFillEp0Context(USB_DEVICE *device)
{
    uint32_t *ep0 = XhciInputEndpointContext(device, 1);
    memset(ep0, 0, XHCI_CONTEXT_BYTES);
    ep0[1] = (XHCI_EP_TYPE_CONTROL << XHCI_EP_TYPE_SHIFT) |
             (XHCI_EP_CERR_DEFAULT << XHCI_EP_CERR_SHIFT) |
             ((uint32_t)device->ep0MaxPacket << XHCI_EP_MAX_PACKET_SHIFT);
    /* The dequeue pointer is where the driver's enqueue is, with the
     * driver's cycle state (§4.3.3, §6.2.3 DCS). */
    uint64_t dequeue =
        device->ep0Ring.physical + (uint64_t)device->ep0Ring.enqueue * sizeof(XHCI_TRB);
    ep0[2] = (uint32_t)dequeue | (device->ep0Ring.cycle ? XHCI_EP_DCS : 0);
    ep0[3] = (uint32_t)(dequeue >> 32);
    ep0[4] = 8; /* average TRB length: control TRBs (§4.14.1.1) */
}

/* Reset a USB2 root port and wait for it to enable (§4.19.1.1.2 → Enabled
 * through PR; a SuperSpeed port enables on its own, §4.19.1.2.4). */
static BOOLEAN XhciResetPort(unsigned port)
{
    XHCI_CONTROLLER *hc = &XhciController;
    uint32_t offset = XHCI_OP_PORTSC + XHCI_PORT_STRIDE * (port - 1);
    XhciWrite32(hc->op, offset, XHCI_PORTSC_PP | XHCI_PORTSC_PR);
    for (unsigned nap = 0; nap < XHCI_PORT_RESET_NAPS; nap++)
    {
        uint32_t portsc = XhciRead32(hc->op, offset);
        if ((portsc & XHCI_PORTSC_PR) == 0 && (portsc & XHCI_PORTSC_PED))
        {
            /* Acknowledge the change bits this reset raised (RW1C). */
            XhciWrite32(hc->op, offset, XHCI_PORTSC_PP | XHCI_PORTSC_PRC | XHCI_PORTSC_CSC);
            return TRUE;
        }
        if (XhciNap(1) != STATUS_SUCCESS)
        {
            return FALSE;
        }
    }
    return FALSE;
}

static BOOLEAN XhciReadDescriptors(USB_DEVICE *device)
{
    uint16_t got = 0;
    uint8_t cc;

    /* Device descriptor: the first 8 bytes carry bMaxPacketSize0, which a
     * full/low-speed device's EP0 context must match before anything
     * longer is asked for (§4.3 step 8). */
    cc = XhciControlTransfer(device, USB_REQUEST_TYPE_DEVICE_TO_HOST_STANDARD,
                             USB_REQUEST_GET_DESCRIPTOR, USB_DESCRIPTOR_TYPE_DEVICE << 8, 0,
                             device->scratchPhysical, 8, &got);
    if ((cc != XHCI_CC_SUCCESS && cc != XHCI_CC_SHORT_PACKET) || got < 8)
    {
        DbgPrint("usb: port %u: device descriptor (8) failed, cc %u got %u\n", device->port, cc,
                 got);
        return FALSE;
    }
    uint16_t maxPacket0 = device->scratch[USB_DEVICE_DESCRIPTOR_OFF_MAX_PACKET0];
    if (device->speed == USB_SPEED_SUPER)
    {
        maxPacket0 = (uint16_t)(1u << maxPacket0); /* USB 3 encodes it as an exponent */
    }
    if (maxPacket0 != device->ep0MaxPacket)
    {
        /* Evaluate Context with only the EP0 context added (§4.6.7, Add
         * flags = A1) tells the controller the real size. */
        device->ep0MaxPacket = maxPacket0;
        uint32_t *ep0 = XhciInputEndpointContext(device, 1);
        ep0[1] = (ep0[1] & 0xFFFFu) | ((uint32_t)maxPacket0 << XHCI_EP_MAX_PACKET_SHIFT);
        device->inputContext[0] = 0;
        device->inputContext[XHCI_INPUT_CONTROL_ADD_WORD] = 1u << 1;
        cc = XhciCommand(device->inputContextPhysical,
                         (XHCI_TRB_TYPE_EVALUATE_CONTEXT << XHCI_TRB_TYPE_SHIFT) |
                             ((uint32_t)device->slotId << XHCI_TRB_SLOT_SHIFT),
                         0);
        if (cc != XHCI_CC_SUCCESS)
        {
            DbgPrint("usb: port %u: evaluate context for EP0 max packet %u failed, cc %u\n",
                     device->port, maxPacket0, cc);
            return FALSE;
        }
        DbgPrint("usb: port %u: EP0 max packet is %u\n", device->port, maxPacket0);
    }

    cc = XhciControlTransfer(device, USB_REQUEST_TYPE_DEVICE_TO_HOST_STANDARD,
                             USB_REQUEST_GET_DESCRIPTOR, USB_DESCRIPTOR_TYPE_DEVICE << 8, 0,
                             device->scratchPhysical, USB_DEVICE_DESCRIPTOR_LENGTH, &got);
    if ((cc != XHCI_CC_SUCCESS && cc != XHCI_CC_SHORT_PACKET) || got < USB_DEVICE_DESCRIPTOR_LENGTH)
    {
        DbgPrint("usb: port %u: device descriptor failed, cc %u got %u\n", device->port, cc, got);
        return FALSE;
    }
    memcpy(device->deviceDescriptor, device->scratch, USB_DEVICE_DESCRIPTOR_LENGTH);

    /* Configuration 0's header for wTotalLength, then the whole set (USB
     * 2.0 §9.6.3): interfaces, class descriptors, endpoints. */
    cc = XhciControlTransfer(device, USB_REQUEST_TYPE_DEVICE_TO_HOST_STANDARD,
                             USB_REQUEST_GET_DESCRIPTOR, USB_DESCRIPTOR_TYPE_CONFIGURATION << 8, 0,
                             device->scratchPhysical, USB_CONFIG_DESCRIPTOR_LENGTH, &got);
    if ((cc != XHCI_CC_SUCCESS && cc != XHCI_CC_SHORT_PACKET) || got < USB_CONFIG_DESCRIPTOR_LENGTH)
    {
        DbgPrint("usb: port %u: configuration descriptor failed, cc %u got %u\n", device->port, cc,
                 got);
        return FALSE;
    }
    uint16_t total = (uint16_t)(device->scratch[USB_CONFIG_DESCRIPTOR_OFF_TOTAL_LENGTH] |
                                (device->scratch[USB_CONFIG_DESCRIPTOR_OFF_TOTAL_LENGTH + 1] << 8));
    if (total < USB_CONFIG_DESCRIPTOR_LENGTH || total > USB_CONFIG_SET_MAX)
    {
        DbgPrint("usb: port %u: configuration set of %u bytes; beyond %u is unbuilt, refused\n",
                 device->port, total, USB_CONFIG_SET_MAX);
        return FALSE;
    }
    cc = XhciControlTransfer(device, USB_REQUEST_TYPE_DEVICE_TO_HOST_STANDARD,
                             USB_REQUEST_GET_DESCRIPTOR, USB_DESCRIPTOR_TYPE_CONFIGURATION << 8, 0,
                             device->scratchPhysical, total, &got);
    if ((cc != XHCI_CC_SUCCESS && cc != XHCI_CC_SHORT_PACKET) || got < total)
    {
        DbgPrint("usb: port %u: configuration set failed, cc %u got %u of %u\n", device->port, cc,
                 got, total);
        return FALSE;
    }
    memcpy(device->configSet, device->scratch, total);
    device->configSetLength = total;
    return TRUE;
}

static void XhciEnumeratePort(unsigned port)
{
    XHCI_CONTROLLER *hc = &XhciController;
    uint32_t offset = XHCI_OP_PORTSC + XHCI_PORT_STRIDE * (port - 1);
    uint32_t portsc = XhciRead32(hc->op, offset);
    if ((portsc & XHCI_PORTSC_CCS) == 0)
    {
        return;
    }
    if ((portsc & XHCI_PORTSC_PED) == 0)
    {
        if (!XhciResetPort(port))
        {
            DbgPrint("usb: port %u: reset did not enable the port (PORTSC %#x); left alone\n", port,
                     XhciRead32(hc->op, offset));
            return;
        }
        XhciNap(USB_RESET_RECOVERY_MS);
        portsc = XhciRead32(hc->op, offset);
    }
    uint8_t speed = (portsc >> XHCI_PORTSC_SPEED_SHIFT) & XHCI_PORTSC_SPEED_MASK;
    uint16_t maxPacket0 = XhciDefaultMaxPacket0(speed);
    if (maxPacket0 == 0)
    {
        DbgPrint("usb: port %u: unknown port speed id %u; refused\n", port, speed);
        return;
    }
    if (XhciDeviceTotal == USB_MAX_DEVICES)
    {
        DbgPrint("usb: port %u: connected, not enumerated: the device budget (%u) is spent\n", port,
                 USB_MAX_DEVICES);
        return;
    }
    USB_DEVICE *device = &XhciDevices[XhciDeviceTotal];
    device->present = TRUE;
    device->port = (uint8_t)port;
    device->speed = speed;
    device->ep0MaxPacket = maxPacket0;
    XhciDeviceTotal++;

    /* §4.3.3: Enable Slot; then an input context naming the port and
     * speed with EP0's control pipe (Add flags A0 | A1 exactly — the
     * pinned QEMU xhci_address_slot insists); Address Device with BSR = 0
     * (§4.6.5), which has the controller issue SET_ADDRESS itself. */
    unsigned slot = 0;
    uint8_t cc = XhciCommand(0, XHCI_TRB_TYPE_ENABLE_SLOT << XHCI_TRB_TYPE_SHIFT, &slot);
    if (cc != XHCI_CC_SUCCESS || slot == 0 || slot > hc->maxSlots)
    {
        DbgPrint("usb: port %u: enable slot failed, cc %u slot %u\n", port, cc, slot);
        return;
    }
    device->slotId = (uint8_t)slot;
    XhciSlotDevice[slot] = device;
    hc->dcbaa[slot] = device->outputContextPhysical;

    device->inputContext[0] = 0;
    device->inputContext[XHCI_INPUT_CONTROL_ADD_WORD] = 0x3;
    uint32_t *slotContext = XhciInputSlotContext(device);
    memset(slotContext, 0, XHCI_CONTEXT_BYTES);
    slotContext[0] = ((uint32_t)speed << XHCI_SLOT_SPEED_SHIFT) |
                     (1u << XHCI_SLOT_CONTEXT_ENTRIES_SHIFT); /* route string 0: a root port */
    slotContext[1] = (uint32_t)port << XHCI_SLOT_ROOT_PORT_SHIFT;
    XhciFillEp0Context(device);
    cc = XhciCommand(device->inputContextPhysical,
                     (XHCI_TRB_TYPE_ADDRESS_DEVICE << XHCI_TRB_TYPE_SHIFT) |
                         ((uint32_t)slot << XHCI_TRB_SLOT_SHIFT),
                     0);
    if (cc != XHCI_CC_SUCCESS)
    {
        DbgPrint("usb: port %u: address device failed, cc %u\n", port, cc);
        return;
    }
    XhciNap(USB_SET_ADDRESS_MS);

    if (!XhciReadDescriptors(device))
    {
        return;
    }
    device->addressed = TRUE;
    DbgPrint(
        "usb: port %u slot %u: speed %u, id %04x:%04x, class %02x/%02x/%02x, %u config bytes\n",
        port, slot, speed,
        device->deviceDescriptor[USB_DEVICE_DESCRIPTOR_OFF_VENDOR] |
            (device->deviceDescriptor[USB_DEVICE_DESCRIPTOR_OFF_VENDOR + 1] << 8),
        device->deviceDescriptor[USB_DEVICE_DESCRIPTOR_OFF_PRODUCT] |
            (device->deviceDescriptor[USB_DEVICE_DESCRIPTOR_OFF_PRODUCT + 1] << 8),
        device->deviceDescriptor[USB_DEVICE_DESCRIPTOR_OFF_CLASS],
        device->deviceDescriptor[USB_DEVICE_DESCRIPTOR_OFF_CLASS + 1],
        device->deviceDescriptor[USB_DEVICE_DESCRIPTOR_OFF_CLASS + 2], device->configSetLength);
}

void XhciEnumerate(void)
{
    XHCI_CONTROLLER *hc = &XhciController;
    if (!hc->present)
    {
        return;
    }
    ASSERT(!hc->enumerated);
    /* Connect debounce (USB 2.0 §7.1.7.3): a device plugged at power-on is
     * settled long before this runs, but the spec's 100 ms costs nothing. */
    XhciNap(USB_DEBOUNCE_MS);
    for (unsigned port = 1; port <= hc->maxPorts; port++)
    {
        XhciEnumeratePort(port);
    }
    DbgPrint("usb: %u device%s on %u root ports\n", XhciDeviceTotal,
             XhciDeviceTotal == 1 ? "" : "s", hc->maxPorts);
}

unsigned XhciDeviceCount(void)
{
    return XhciDeviceTotal;
}

USB_DEVICE *XhciDevice(unsigned index)
{
    return index < XhciDeviceTotal ? &XhciDevices[index] : 0;
}

/* --- Interrupt IN endpoints ------------------------------------------------------ */

/* xHCI Interval field for an interrupt endpoint from the descriptor's
 * bInterval (§6.2.3.6 Table 6-12): high/super speed count 125 us frames as
 * 2^(bInterval-1), so Interval = bInterval - 1; full/low speed count
 * milliseconds, rounded down to a power of two of 125 us units, clamped to
 * the 3..10 (1 ms to 128 ms) the table allows. */
static uint8_t XhciInterruptInterval(uint8_t speed, uint8_t bInterval)
{
    if (speed == USB_SPEED_HIGH || speed == USB_SPEED_SUPER)
    {
        if (bInterval < 1)
        {
            return 0;
        }
        return (uint8_t)(bInterval > 16 ? 15 : bInterval - 1);
    }
    unsigned frames = (bInterval == 0 ? 1u : bInterval) * 8u; /* ms -> 125 us units */
    uint8_t interval = 0;
    while ((2u << interval) <= frames)
    {
        interval++;
    }
    if (interval < 3)
    {
        interval = 3;
    }
    if (interval > 10)
    {
        interval = 10;
    }
    return interval;
}

uint8_t XhciConfigureInterruptIn(USB_DEVICE *device, uint8_t endpointAddress, uint16_t maxPacket,
                                 uint8_t interval)
{
    ASSERT(device->addressed && device->intrDci == 0);
    ASSERT((endpointAddress & 0x80) != 0); /* IN (USB 2.0 §9.6.6 bit 7) */
    unsigned number = endpointAddress & 0xF;
    unsigned dci = number * 2 + 1; /* §4.5.1: IN endpoints are odd DCIs */
    if (number == 0 || maxPacket == 0 || maxPacket > USB_REPORT_BUFFER_OFFSET)
    {
        DbgPrint("usb: slot %u: endpoint %02x max packet %u unusable\n", device->slotId,
                 endpointAddress, maxPacket);
        return XHCI_CC_TRB_ERROR;
    }

    /* Configure Endpoint (§4.6.6): Add flags A0 (the slot context, whose
     * Context Entries grows to the new DCI) and the endpoint's own; A1
     * must stay clear (the pinned QEMU xhci_configure_slot checks). */
    uint32_t *slotContext = XhciInputSlotContext(device);
    slotContext[0] = (slotContext[0] & ~(0x1Fu << XHCI_SLOT_CONTEXT_ENTRIES_SHIFT)) |
                     ((uint32_t)dci << XHCI_SLOT_CONTEXT_ENTRIES_SHIFT);
    uint32_t *endpoint = XhciInputEndpointContext(device, dci);
    memset(endpoint, 0, XHCI_CONTEXT_BYTES);
    uint8_t xhciInterval = XhciInterruptInterval(device->speed, interval);
    endpoint[0] = ((uint32_t)xhciInterval << XHCI_EP_INTERVAL_SHIFT);
    endpoint[1] = (XHCI_EP_TYPE_INTERRUPT_IN << XHCI_EP_TYPE_SHIFT) |
                  (XHCI_EP_CERR_DEFAULT << XHCI_EP_CERR_SHIFT) |
                  ((uint32_t)maxPacket << XHCI_EP_MAX_PACKET_SHIFT);
    endpoint[2] = (uint32_t)device->intrRing.physical | XHCI_EP_DCS;
    endpoint[3] = (uint32_t)(device->intrRing.physical >> 32);
    /* Average TRB length and Max ESIT Payload: one report per service
     * interval (§4.14.1.1, §4.14.2). */
    endpoint[4] = maxPacket | ((uint32_t)maxPacket << XHCI_EP_MAX_ESIT_LO_SHIFT);
    device->inputContext[0] = 0;
    device->inputContext[XHCI_INPUT_CONTROL_ADD_WORD] = 0x1u | (1u << dci);
    uint8_t cc = XhciCommand(device->inputContextPhysical,
                             (XHCI_TRB_TYPE_CONFIGURE_ENDPOINT << XHCI_TRB_TYPE_SHIFT) |
                                 ((uint32_t)device->slotId << XHCI_TRB_SLOT_SHIFT),
                             0);
    if (cc != XHCI_CC_SUCCESS)
    {
        DbgPrint("usb: slot %u: configure endpoint %02x failed, cc %u\n", device->slotId,
                 endpointAddress, cc);
        return cc;
    }
    device->intrDci = (uint8_t)dci;
    device->intrMaxPacket = maxPacket;
    DbgPrint("usb: slot %u: endpoint %02x interrupt IN, %u bytes, interval 2^%u x 125 us\n",
             device->slotId, endpointAddress, maxPacket, xhciInterval);
    return XHCI_CC_SUCCESS;
}

uint8_t *XhciReportBuffer(USB_DEVICE *device)
{
    return device->scratch + USB_REPORT_BUFFER_OFFSET;
}

void XhciPostInterruptIn(USB_DEVICE *device)
{
    ASSERT(device->intrDci != 0);
    ASSERT(device->intrTrbPhysical == 0);
    if (device->failed)
    {
        return;
    }
    /* One Normal TRB (§6.4.1.1) of one report: IOC so its completion is an
     * event, ISP so a report shorter than the endpoint's maximum is one
     * too, with its residual. */
    device->intrTrbPhysical =
        XhciRingPush(&device->intrRing, device->scratchPhysical + USB_REPORT_BUFFER_OFFSET,
                     device->intrMaxPacket,
                     (XHCI_TRB_TYPE_NORMAL << XHCI_TRB_TYPE_SHIFT) | XHCI_TRB_IOC | XHCI_TRB_ISP);
    XhciRingDoorbell(device->slotId, device->intrDci);
}

/* Called by the class driver once it has armed its endpoints: from here the
 * rings belong to the readers, and the phase-2 waits are asserted away. */
void XhciFinishEnumeration(void)
{
    XhciController.enumerated = TRUE;
}
