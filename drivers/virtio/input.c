/* drivers/virtio/input.c — virtio-input over the shared modern-PCI
 * transport (virtio 1.2 cs01 §5.8; see virtio.h, drivers/hidproto.h).
 *
 * Written from the OASIS virtio 1.2 cs01 specification (sections cited
 * inline) against the pinned third_party/qemu device model. Provenance:
 * public spec only (docs/11).
 *
 * The event sources under \Device\Input0 and \Device\Input1 (drivers/hid.c,
 * HACK-002). Up to two instances: the keyboard (GUI-1) and the pointer —
 * QEMU's tablet — which joined at GUI-4. Which function is which is decided
 * by the device's own EV_BITS config, never by PCI enumeration order. Only
 * the eventq on both: devices we read, never ones we talk back to.
 *
 * No interrupt, deliberately (docs/19 §11f): blk owns the tree's one
 * device vector, and a 1 kHz input poll is not a cost the way a
 * per-transfer busy-spin was — the established shape for an input stream
 * here is the one CondrvSerialRead already uses -- drain what is there,
 * else nap a millisecond and look again (Art. 3: the simplest correct
 * thing). The used ring IS the buffer: QEMU's eventq holds 64
 * entries, which is ~16 keystrokes of press/release/SYN backlog while
 * nobody is reading, so a second ring inside the kernel would buy only a
 * larger number.
 */
#include "drivers/virtio/input.h"
#include "drivers/virtio/virtio.h"
#include "drivers/hidproto.h"
#include "kernel/mm/phys.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

/* One event per buffer (§5.8.6.1), so the ring's depth is the number of
 * buffers we post. 64 is what QEMU's eventq offers (pinned tree
 * hw/input/virtio-input.c: virtio_add_queue(..., 64, ...)); VioPciSetupQueue
 * negotiates the device's own size and we fill exactly that. */
#define VIO_INPUT_MAX_EVENTS (PAGE_SIZE / sizeof(HID_INPUT_EVENT))

/* Keyboard + pointer; a third virtio-input function has no consumer. */
#define VIO_INPUT_MAX_INSTANCES 2

/* Device-config selectors (virtio 1.2 cs01 §5.8.4, cross-check the pinned
 * QEMU include/standard-headers/linux/virtio_input.h enum
 * virtio_input_config_select). The config layout is struct
 * virtio_input_config: select at 0, subsel at 1, size at 2, reserved[5],
 * payload union at 8. An unsupported select/subsel pair reads back size 0
 * (§5.8.5.1; QEMU hw/input/virtio-input.c virtio_input_get_config memsets
 * the config on a miss). */
#define VIO_INPUT_CFG_EV_BITS     0x11
#define VIO_INPUT_CFG_ABS_INFO    0x12
#define VIO_INPUT_CFG_OFF_SELECT  0
#define VIO_INPUT_CFG_OFF_SUBSEL  1
#define VIO_INPUT_CFG_OFF_SIZE    2
#define VIO_INPUT_CFG_OFF_PAYLOAD 8

static VIO_INPUT_INSTANCE VioInputInstances[VIO_INPUT_MAX_INSTANCES];
static VIO_INPUT_INSTANCE *VioInputKeyboardInstance;
static VIO_INPUT_INSTANCE *VioInputPointerInstance;

static uint64_t VioInputSlotPhysical(const VIO_INPUT_INSTANCE *input, uint16_t slot)
{
    return input->slotsPhysical + (uint64_t)slot * sizeof(HID_INPUT_EVENT);
}

/* Select a config view and return its size byte (0 = the device does not
 * have that entry). Device config is byte-accessible MMIO (§4.1.4.6). */
static uint8_t VioInputSelectConfig(VIO_PCI_DEVICE *device, uint8_t select, uint8_t subsel)
{
    device->deviceCfg[VIO_INPUT_CFG_OFF_SELECT] = select;
    device->deviceCfg[VIO_INPUT_CFG_OFF_SUBSEL] = subsel;
    return device->deviceCfg[VIO_INPUT_CFG_OFF_SIZE];
}

/* Little-endian 32-bit field out of the selected config payload (§5.8.4:
 * config fields are le32; byte reads keep the MMIO access width simple). */
static uint32_t VioInputReadConfigLe32(VIO_PCI_DEVICE *device, unsigned offset)
{
    volatile uint8_t *payload = device->deviceCfg + VIO_INPUT_CFG_OFF_PAYLOAD + offset;
    return (uint32_t)payload[0] | ((uint32_t)payload[1] << 8) | ((uint32_t)payload[2] << 16) |
           ((uint32_t)payload[3] << 24);
}

/* struct virtio_input_absinfo: min, max, fuzz, flat, res, five le32s in
 * that order (§5.8.4; pinned virtio_input.h). Cached at init so the ioctl
 * that reports it (drivers/hid.c) never touches MMIO. */
static void VioInputReadAbsInfo(VIO_PCI_DEVICE *device, uint8_t axis, VIO_INPUT_ABS_INFO *info)
{
    if (VioInputSelectConfig(device, VIO_INPUT_CFG_ABS_INFO, axis) == 0)
    {
        memset(info, 0, sizeof(*info));
        return;
    }
    info->min = VioInputReadConfigLe32(device, 0);
    info->max = VioInputReadConfigLe32(device, 4);
    info->fuzz = VioInputReadConfigLe32(device, 8);
    info->flat = VioInputReadConfigLe32(device, 12);
    info->res = VioInputReadConfigLe32(device, 16);
}

static BOOLEAN VioInputSetupInstance(VIO_INPUT_INSTANCE *input, unsigned instance)
{
    /* §4.1.2: input is modern-only -- there is no transitional device id
     * for a device type introduced after the legacy interface. */
    if (!VioPciSetupModernDevice(VIRTIO_DEVICE_TYPE_INPUT, 0, "virtio-input", instance,
                                 &input->device))
    {
        return FALSE;
    }
    if (!VioPciAcceptFeatures(&input->device, 0))
    {
        return FALSE;
    }

    /* Classify by what the device itself advertises: a pointer is the
     * instance whose EV_BITS have an EV_ABS entry (QEMU's tablet reports
     * ABS_X/ABS_Y there; its keyboard has no EV_ABS view at all). PCI order
     * decides nothing. */
    input->isPointer = VioInputSelectConfig(&input->device, VIO_INPUT_CFG_EV_BITS, HID_EV_ABS) != 0;
    if (input->isPointer)
    {
        VioInputReadAbsInfo(&input->device, HID_ABS_X, &input->absX);
        VioInputReadAbsInfo(&input->device, HID_ABS_Y, &input->absY);
    }

    /* §5.8.2 defines two virtqueues: 0 eventq, 1 statusq. We configure only
     * the eventq -- a driver uses the queues it configures, and the statusq
     * carries output to the device (keyboard LEDs, force feedback) that
     * nothing above us can ask for. Said out loud rather than left as a
     * silent gap, and neither device has a Write op to match (Art. 12). */
    if (!VioPciSetupQueue(&input->device, &input->eventQueue, 0))
    {
        return FALSE;
    }
    DbgPrint("virtio-input: statusq unconfigured -- no LED/output path (GUI-1 scope)\n");

    input->slotsPhysical = MiAllocatePage();
    if (input->slotsPhysical == 0)
    {
        VioPciSetFailed(&input->device);
        return FALSE;
    }
    input->slots = MiPhysicalToVirtual(input->slotsPhysical);

    input->slotCount = input->eventQueue.queueSize;
    if (input->slotCount > VIO_INPUT_MAX_EVENTS)
    {
        input->slotCount = (uint16_t)VIO_INPUT_MAX_EVENTS; /* one frame of slots */
    }
    for (uint16_t slot = 0; slot < input->slotCount; slot++)
    {
        VioPostReceiveBuffer(&input->eventQueue, slot, VioInputSlotPhysical(input, slot),
                             sizeof(HID_INPUT_EVENT));
    }

    /* Step 8. QEMU activates its input handler at DRIVER_OK and discards
     * events before it (pinned tree hw/input/virtio-input.c: `active =
     * status & DRIVER_OK`, virtio_input_hid handler registered there), so
     * nothing can arrive until this line. */
    VioPciSetDriverOk(&input->device);
    VioNotifyQueue(&input->eventQueue);

    input->present = TRUE;
    DbgPrint("virtio-input: %02x:%x id %04x, %u event buffers, %s\n", input->device.function.device,
             input->device.function.function, input->device.function.deviceId, input->slotCount,
             input->isPointer ? "pointer (EV_ABS)" : "keyboard");
    return TRUE;
}

BOOLEAN VioInputInitialize(void)
{
    for (unsigned instance = 0; instance < VIO_INPUT_MAX_INSTANCES; instance++)
    {
        VIO_INPUT_INSTANCE *input = &VioInputInstances[instance];
        if (!VioInputSetupInstance(input, instance))
        {
            break; /* a miss ends the scan; the setup said so on serial */
        }
        if (input->isPointer)
        {
            if (VioInputPointerInstance == 0)
            {
                VioInputPointerInstance = input;
            }
            else
            {
                DbgPrint("virtio-input: second pointer ignored\n");
            }
        }
        else
        {
            if (VioInputKeyboardInstance == 0)
            {
                VioInputKeyboardInstance = input;
            }
            else
            {
                DbgPrint("virtio-input: second keyboard ignored\n");
            }
        }
    }
    return VioInputKeyboardInstance != 0 || VioInputPointerInstance != 0;
}

VIO_INPUT_INSTANCE *VioInputKeyboard(void)
{
    return VioInputKeyboardInstance;
}

VIO_INPUT_INSTANCE *VioInputPointer(void)
{
    return VioInputPointerInstance;
}

int VioInputTryReadEvent(VIO_INPUT_INSTANCE *input, HID_INPUT_EVENT *event)
{
    ASSERT(input != 0 && input->present);

    uint16_t slot;
    uint32_t length;
    if (!VioTryPopUsed(&input->eventQueue, &slot, &length))
    {
        return 0;
    }
    /* The device fills a whole event or nothing (§5.8.6.1). A short write
     * would mean the device and this driver disagree about the wire format,
     * which is not a condition to paper over. */
    ASSERT(slot < input->slotCount);
    ASSERT(length >= sizeof(HID_INPUT_EVENT));

    *event = input->slots[slot];

    /* Hand the slot straight back: the buffer supply must not drain while
     * a reader is draining events, or the device starts dropping reports. */
    VioPostReceiveBuffer(&input->eventQueue, slot, VioInputSlotPhysical(input, slot),
                         sizeof(HID_INPUT_EVENT));
    VioNotifyQueue(&input->eventQueue);
    return 1;
}

static int VioInputTryReadSource(void *context, HID_INPUT_EVENT *event)
{
    return VioInputTryReadEvent(context, event);
}

static void VioInputFillSource(VIO_INPUT_INSTANCE *input, HID_SOURCE *source)
{
    memset(source, 0, sizeof(*source));
    source->TryRead = VioInputTryReadSource;
    source->context = input;
    source->name = "virtio-input";
    if (input->isPointer)
    {
        source->abs.minX = input->absX.min;
        source->abs.maxX = input->absX.max;
        source->abs.minY = input->absY.min;
        source->abs.maxY = input->absY.max;
    }
}

BOOLEAN VioInputKeyboardSource(HID_SOURCE *source)
{
    if (VioInputKeyboardInstance == 0)
    {
        return FALSE;
    }
    VioInputFillSource(VioInputKeyboardInstance, source);
    return TRUE;
}

BOOLEAN VioInputPointerSource(HID_SOURCE *source)
{
    if (VioInputPointerInstance == 0)
    {
        return FALSE;
    }
    VioInputFillSource(VioInputPointerInstance, source);
    return TRUE;
}
