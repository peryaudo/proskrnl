/* drivers/virtio/input.c — virtio-input over the shared modern-PCI
 * transport (virtio 1.2 cs01 §5.8; see virtio.h, drivers/hidproto.h).
 *
 * Written from the OASIS virtio 1.2 cs01 specification (sections cited
 * inline) against the pinned third_party/qemu device model. Provenance:
 * public spec only (docs/11).
 *
 * The event source under \Device\Input0 (drivers/hid.c, HACK-002). Only
 * the eventq: this is a keyboard we read, never one we talk back to.
 *
 * No interrupt. The kernel has no device-IRQ path at all (kernel/ke/irq.c
 * panics on any vector but the clock), and the established shape for an
 * input stream here is the one CondrvSerialRead already uses -- drain what
 * is there, else nap a millisecond and look again (Art. 3: the simplest
 * correct thing). The used ring IS the buffer: QEMU's eventq holds 64
 * entries, which is ~16 keystrokes of press/release/SYN backlog while
 * nobody is reading, so a second ring inside the kernel would buy only a
 * larger number.
 */
#include "drivers/virtio/input.h"
#include "drivers/virtio/virtio.h"
#include "drivers/hidproto.h"
#include "kernel/mm/phys.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/init/panic.h"

/* One event per buffer (§5.8.6.1), so the ring's depth is the number of
 * buffers we post. 64 is what QEMU's eventq offers (pinned tree
 * hw/input/virtio-input.c: virtio_add_queue(..., 64, ...)); VioPciSetupQueue
 * negotiates the device's own size and we fill exactly that. */
#define VIO_INPUT_MAX_EVENTS (PAGE_SIZE / sizeof(HID_INPUT_EVENT))

static BOOLEAN VioInputPresent;
static VIO_PCI_DEVICE VioInputDevice;
static VIO_VIRTQUEUE VioInputEventQueue;

/* The DMA page the device writes events into: one frame, sliced into
 * 8-byte slots, slot i permanently owned by descriptor i. */
static uint64_t VioInputSlotsPhysical;
static HID_INPUT_EVENT *VioInputSlots;
static uint16_t VioInputSlotCount;

static uint64_t VioInputSlotPhysical(uint16_t slot)
{
    return VioInputSlotsPhysical + (uint64_t)slot * sizeof(HID_INPUT_EVENT);
}

BOOLEAN VioInputInitialize(void)
{
    /* §4.1.2: input is modern-only -- there is no transitional device id
     * for a device type introduced after the legacy interface. */
    if (!VioPciSetupModernDevice(VIRTIO_DEVICE_TYPE_INPUT, 0, "virtio-input", 0, &VioInputDevice))
    {
        return FALSE;
    }
    if (!VioPciAcceptFeatures(&VioInputDevice))
    {
        return FALSE;
    }

    /* §5.8.2 defines two virtqueues: 0 eventq, 1 statusq. We configure only
     * the eventq -- a driver uses the queues it configures, and the statusq
     * carries output to the device (keyboard LEDs, force feedback) that
     * nothing above us can ask for. Said out loud rather than left as a
     * silent gap, and \Device\Input0 has no Write op to match (Art. 12). */
    if (!VioPciSetupQueue(&VioInputDevice, &VioInputEventQueue, 0))
    {
        return FALSE;
    }
    DbgPrint("virtio-input: statusq unconfigured -- no LED/output path (GUI-1 scope)\n");

    VioInputSlotsPhysical = MiAllocatePage();
    if (VioInputSlotsPhysical == 0)
    {
        VioPciSetFailed(&VioInputDevice);
        return FALSE;
    }
    VioInputSlots = MiPhysicalToVirtual(VioInputSlotsPhysical);

    VioInputSlotCount = VioInputEventQueue.queueSize;
    if (VioInputSlotCount > VIO_INPUT_MAX_EVENTS)
    {
        VioInputSlotCount = (uint16_t)VIO_INPUT_MAX_EVENTS; /* one frame of slots */
    }
    for (uint16_t slot = 0; slot < VioInputSlotCount; slot++)
    {
        VioPostReceiveBuffer(&VioInputEventQueue, slot, VioInputSlotPhysical(slot),
                             sizeof(HID_INPUT_EVENT));
    }

    /* Step 8. QEMU activates its input handler at DRIVER_OK and discards
     * events before it (pinned tree hw/input/virtio-input.c: `active =
     * status & DRIVER_OK`, virtio_input_hid handler registered there), so
     * nothing can arrive until this line. */
    VioPciSetDriverOk(&VioInputDevice);
    VioNotifyQueue(&VioInputEventQueue);

    VioInputPresent = TRUE;
    DbgPrint("virtio-input: %02x:%x id %04x, %u event buffers\n", VioInputDevice.function.device,
             VioInputDevice.function.function, VioInputDevice.function.deviceId, VioInputSlotCount);
    return TRUE;
}

BOOLEAN VioInputIsPresent(void)
{
    return VioInputPresent;
}

int VioInputTryReadEvent(HID_INPUT_EVENT *event)
{
    ASSERT(VioInputPresent);

    uint16_t slot;
    uint32_t length;
    if (!VioTryPopUsed(&VioInputEventQueue, &slot, &length))
    {
        return 0;
    }
    /* The device fills a whole event or nothing (§5.8.6.1). A short write
     * would mean the device and this driver disagree about the wire format,
     * which is not a condition to paper over. */
    ASSERT(slot < VioInputSlotCount);
    ASSERT(length >= sizeof(HID_INPUT_EVENT));

    *event = VioInputSlots[slot];

    /* Hand the slot straight back: the buffer supply must not drain while
     * a reader is draining events, or the device starts dropping reports. */
    VioPostReceiveBuffer(&VioInputEventQueue, slot, VioInputSlotPhysical(slot),
                         sizeof(HID_INPUT_EVENT));
    VioNotifyQueue(&VioInputEventQueue);
    return 1;
}
