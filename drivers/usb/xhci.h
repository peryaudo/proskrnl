/* drivers/usb/xhci.h — the xHCI host controller and the USB devices on its
 * root ports (USB-1). See xhci.c for the design; the consumer is
 * drivers/usb/hidboot.c, the HID boot-protocol keyboard/mouse that feeds
 * \Device\Input0 / \Device\Input1 (drivers/hid.c, HACK-002). */
#ifndef PROSKRNL_DRIVERS_USB_XHCI_H
#define PROSKRNL_DRIVERS_USB_XHCI_H

#include "abi/ntdef.h"
#include <stdint.h>

/* One TRB: parameter (two dwords), status, control (xHCI 1.2 §6.4 Figure
 * 6-6). Dword arrays rather than bitfields on purpose: every field is a
 * cited shift/mask below, and the layout is then the spec's, not the
 * compiler's. */
typedef struct XHCI_TRB
{
    uint32_t words[4];
} XHCI_TRB;
_Static_assert(sizeof(XHCI_TRB) == 16, "a TRB is 16 bytes (xHCI 1.2 §6.4)");

/* A producer ring the driver enqueues into and the controller consumes: the
 * command ring and every transfer ring (§4.9.2). One frame of 256 TRBs, the
 * last of which is a Link TRB back to the base with Toggle Cycle set
 * (§4.9.2.2/§6.4.4.1). The enqueue index and the producer cycle state are
 * software state; the controller keeps its own dequeue and consumer cycle. */
typedef struct XHCI_RING
{
    XHCI_TRB *trbs; /* one MiAllocatePage frame, through the HHDM */
    uint64_t physical;
    uint32_t enqueue;
    uint32_t cycle; /* producer cycle state, starts 1 (§4.9.2) */
} XHCI_RING;

/* Root-port speed as PORTSC reports it — the Protocol Speed ID, which with
 * the default Supported Protocol capabilities (§7.2.2.1.1 Table 7-13) is:
 * 1 full, 2 low, 3 high, 4 super. The same number goes verbatim into the
 * slot context's Speed field (§6.2.2). Cross-check: pinned QEMU
 * hw/usb/hcd-xhci.c PORTSC_SPEED_FULL/LOW/HIGH/SUPER = 1<<10 .. 4<<10. */
#define USB_SPEED_FULL  1
#define USB_SPEED_LOW   2
#define USB_SPEED_HIGH  3
#define USB_SPEED_SUPER 4

/* Descriptor sizes and the longest configuration descriptor set the driver
 * reads (USB 2.0 §9.6.1 device = 18 bytes, §9.6.3 configuration header = 9;
 * the whole set, capped at one byte's worth of wTotalLength — a boot HID
 * device's fits in under 64). */
#define USB_DEVICE_DESCRIPTOR_LENGTH 18
/* bDeviceClass, bDeviceSubClass, bDeviceProtocol at 4, 5, 6 (USB 2.0
 * §9.6.1 Table 9-8); a class-per-interface device (a HID one) has 0 in all
 * three. */
#define USB_DEVICE_DESCRIPTOR_OFF_CLASS 4
#define USB_CONFIG_DESCRIPTOR_LENGTH    9
#define USB_CONFIG_SET_MAX              255

/* One USB device on a root port, from Enable Slot through Address Device
 * and the descriptor reads (§4.3). Everything a class driver needs to
 * decide whether it wants the device is cached here; the DMA frames are
 * the device's for the kernel's lifetime. */
typedef struct USB_DEVICE
{
    BOOLEAN present;   /* record in use (a port had a device) */
    BOOLEAN addressed; /* Address Device succeeded; descriptors valid */
    BOOLEAN failed;    /* an endpoint faulted; no further transfers */
    uint8_t port;      /* root hub port number, 1-based (§4.19.7) */
    uint8_t speed;     /* USB_SPEED_* (PORTSC Port Speed, §5.4.8) */
    uint8_t slotId;
    uint16_t ep0MaxPacket;

    /* DMA frames, all one page, all zeroed at allocation. */
    uint64_t outputContextPhysical, inputContextPhysical, scratchPhysical;
    uint32_t *outputContext; /* device context: slot + 31 endpoint contexts */
    uint32_t *inputContext;  /* input control context + the same */
    uint8_t *scratch;        /* descriptor reads at 0, the report buffer at +256 */
    XHCI_RING ep0Ring;
    XHCI_RING intrRing;

    uint8_t deviceDescriptor[USB_DEVICE_DESCRIPTOR_LENGTH];
    uint8_t configSet[USB_CONFIG_SET_MAX]; /* the configuration descriptor and what follows */
    uint16_t configSetLength;

    /* The one interrupt IN endpoint a class driver configured (a boot HID
     * device has exactly one), and the completion sink for its TRBs. */
    uint8_t intrDci; /* device context index: 2 * endpoint number + 1 (§4.5.1) */
    uint16_t intrMaxPacket;
    uint64_t intrTrbPhysical; /* the one Normal TRB in flight, 0 when none */
    /* NOLINTBEGIN(readability-identifier-naming) — a dispatch slot is a name
     * of code, PascalCase like IO_VFS_OPS's (docs/15). */
    void (*OnTransfer)(struct USB_DEVICE *device, uint8_t completionCode, uint32_t residual);
    /* NOLINTEND(readability-identifier-naming) */
    void *context;
} USB_DEVICE;

/* How many root-port devices get a slot and frames. A boot keyboard and a
 * boot mouse are the consumers; two more so a hub-less bare-metal box with
 * a stray device still enumerates the two that matter. A further connected
 * port is refused loudly, not silently skipped. */
#define USB_MAX_DEVICES 4

/* Phase 1, from IoInitializeTransport (before MiFreezeKernelPml4, no
 * scheduler, interrupts off): find the controller by class code, map its
 * registers, allocate every DMA frame, reset and start it. Bounded
 * register spins only. FALSE, loudly, when there is no xHCI or it refuses
 * to come up; nothing is left half-programmed. */
BOOLEAN XhciInitialize(void);
BOOLEAN XhciIsPresent(void);

/* Phase 2, on the first kernel thread (KeDelayExecutionThread available):
 * reset every connected root port, Enable Slot + Address Device, read the
 * device and configuration descriptors into the USB_DEVICE records. After
 * this the records are read-only for class drivers. */
void XhciEnumerate(void);
unsigned XhciDeviceCount(void);
USB_DEVICE *XhciDevice(unsigned index);

/* A control transfer on EP0 (USB 2.0 §9.3; §4.11.2.2 control TDs): the
 * setup packet fields verbatim, an optional data stage into/out of a
 * physical buffer. Returns the xHCI completion code of the status stage
 * (XHCI_CC_SUCCESS = 1) and, for IN transfers, how many bytes arrived.
 * Phase 2 only: it parks between event-ring polls. */
uint8_t XhciControlTransfer(USB_DEVICE *device, uint8_t requestType, uint8_t request,
                            uint16_t value, uint16_t index, uint64_t bufferPhysical,
                            uint16_t length, uint16_t *transferredOut);

/* Configure one interrupt IN endpoint (bEndpointAddress, wMaxPacketSize,
 * bInterval as the endpoint descriptor states them; USB 2.0 §9.6.6) via
 * Configure Endpoint (§4.6.6), then arm it: one Normal TRB of
 * intrMaxPacket bytes into the report buffer, re-posted by XhciPostInterruptIn
 * after each completion. Phase 2 for the configure; the re-post never
 * parks and is legal from a reader's drain. */
uint8_t XhciConfigureInterruptIn(USB_DEVICE *device, uint8_t endpointAddress, uint16_t maxPacket,
                                 uint8_t interval);
void XhciPostInterruptIn(USB_DEVICE *device);
uint8_t *XhciReportBuffer(USB_DEVICE *device);

/* The class driver's declaration that every endpoint it wants is armed:
 * from here the rings belong to the \Device\Input0/1 readers, and a
 * phase-2 wait is a bug the driver asserts. */
void XhciFinishEnumeration(void);

/* Drain the event ring: route transfer events to their device's OnTransfer,
 * consume everything else. Never blocks; the readers of \Device\Input0/1
 * call it at 1 kHz through their source's TryRead (drivers/hid.c). */
void XhciPollEvents(void);

/* Completion codes this driver decides on (§6.4.5 Table 6-90; cross-check
 * pinned QEMU hw/usb/hcd-xhci.h enum TRBCCode). */
#define XHCI_CC_SUCCESS               1
#define XHCI_CC_USB_TRANSACTION_ERROR 4
#define XHCI_CC_TRB_ERROR             5
#define XHCI_CC_STALL_ERROR           6
#define XHCI_CC_SHORT_PACKET          13
#define XHCI_CC_EVENT_RING_FULL       21
#define XHCI_CC_TIMEOUT               0 /* ours: no completion arrived (0 is "invalid", §6.4.5) */

#endif /* PROSKRNL_DRIVERS_USB_XHCI_H */
