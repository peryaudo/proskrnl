/* drivers/usb/hidboot.c — USB HID boot-protocol keyboard and mouse over
 * xHCI (USB-1): the second event source behind \Device\Input0 and
 * \Device\Input1 (drivers/hid.c, HACK-002), for the day the machine is
 * not QEMU and has no virtio-input.
 *
 * Written from the public specifications — Device Class Definition for
 * Human Interface Devices (HID) Version 1.11 ("HID 1.11 §", Appendix B for
 * the boot reports), HID Usage Tables (the Keyboard/Keypad page), USB 2.0
 * §9 for the descriptors and requests — cited per constant (G8), against
 * the pinned third_party/qemu device model (hw/usb/dev-hid.c,
 * hw/input/hid.c) as the runtime cross-check. Provenance: public spec
 * only (docs/11, docs/provenance.md).
 *
 * Boot protocol only, by decision: HID 1.11 §4.3 / Appendix B fixes the
 * two report formats a BIOS can rely on — an 8-byte keyboard report and a
 * 3+-byte mouse report — so a device that offers them (bInterfaceSubClass
 * 1) is driven without parsing its report descriptor, and one that does
 * not (QEMU's usb-tablet among them) is named on serial and left alone
 * (Art. 12), not half-parsed. The report-descriptor parser that would
 * drive the rest is unbuilt and says so.
 *
 * Events leave here in the \Device\Input0/1 wire format (drivers/hidproto.h):
 * evdev codes, verbatim. The one translation is a renumbering — HID usage
 * to evdev keycode, the generated drivers/usb/usbkeymap.h — of the same
 * physical key, never a layout (a layout belongs in user32, above the
 * boundary). The mouse is a RELATIVE pointer, which the contract gained
 * with this driver: motion is EV_REL REL_X/REL_Y and the abs range it
 * answers is all zeros.
 *
 * No output path: keyboard LEDs (SET_REPORT, HID 1.11 §7.2.2) have no
 * consumer above the boundary, exactly as virtio-input's statusq has none,
 * and \Device\Input0 correspondingly has no Write op (Art. 12).
 */
#include "drivers/usb/hidboot.h"
#include "drivers/usb/xhci.h"
#include "drivers/usb/usbkeymap.h"
#include "drivers/hid.h"
#include "drivers/hidproto.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

/* --- Descriptors (USB 2.0 §9.6) and class identity (HID 1.11 §4) ------------- */

/* Descriptor types (USB 2.0 §9.4 Table 9-5) and the byte offsets read
 * from each (§9.6.3 Table 9-10 configuration, §9.6.5 Table 9-12
 * interface, §9.6.6 Table 9-13 endpoint). Every descriptor starts with
 * bLength, bDescriptorType. */
#define USB_DESCRIPTOR_TYPE_CONFIGURATION  2
#define USB_DESCRIPTOR_TYPE_INTERFACE      4
#define USB_DESCRIPTOR_TYPE_ENDPOINT       5
#define USB_DESCRIPTOR_OFF_LENGTH          0
#define USB_DESCRIPTOR_OFF_TYPE            1
#define USB_CONFIG_OFF_CONFIGURATION_VALUE 5
#define USB_INTERFACE_OFF_NUMBER           2
#define USB_INTERFACE_OFF_CLASS            5
#define USB_INTERFACE_OFF_SUBCLASS         6
#define USB_INTERFACE_OFF_PROTOCOL         7
#define USB_INTERFACE_DESCRIPTOR_LENGTH    9
#define USB_ENDPOINT_OFF_ADDRESS           2
#define USB_ENDPOINT_OFF_ATTRIBUTES        3
#define USB_ENDPOINT_OFF_MAX_PACKET        4
#define USB_ENDPOINT_OFF_INTERVAL          6
#define USB_ENDPOINT_DESCRIPTOR_LENGTH     7
#define USB_ENDPOINT_ADDRESS_IN            0x80 /* bit 7 = IN (§9.6.6) */
#define USB_ENDPOINT_TRANSFER_TYPE_MASK    0x3  /* bmAttributes 1:0 */
#define USB_ENDPOINT_TRANSFER_INTERRUPT    0x3

/* HID class code 3 (HID 1.11 §4.1), Boot Interface Subclass 1 (§4.2),
 * protocols Keyboard 1 / Mouse 2 (§4.3). Cross-check pinned QEMU
 * hw/usb/dev-hid.c: desc_iface_keyboard {USB_CLASS_HID, 0x01, 0x01},
 * desc_iface_mouse {USB_CLASS_HID, 0x01, 0x02}, desc_iface_tablet
 * {USB_CLASS_HID, 0x00, 0x00} -- the one this driver refuses. */
#define USB_CLASS_HID             3
#define USB_HID_SUBCLASS_BOOT     1
#define USB_HID_PROTOCOL_KEYBOARD 1
#define USB_HID_PROTOCOL_MOUSE    2

/* Requests: SET_CONFIGURATION bmRequestType 00h bRequest 9 (USB 2.0
 * §9.4.7); SET_PROTOCOL bmRequestType 21h (host-to-device, class,
 * interface) bRequest 0Bh wValue 0 = boot protocol (HID 1.11 §7.2.6);
 * SET_IDLE bRequest 0Ah wValue duration << 8 | report id, 0 = only report
 * on change (§7.2.4). Cross-check pinned QEMU hw/usb/dev-hid.c
 * usb_hid_handle_control: HID_SET_PROTOCOL stores value, SET_IDLE stores
 * value >> 8. */
#define USB_REQUEST_TYPE_HOST_TO_DEVICE_STANDARD 0x00
#define USB_REQUEST_TYPE_HOST_TO_DEVICE_CLASS_IF 0x21
#define USB_REQUEST_SET_CONFIGURATION            9
#define USB_HID_REQUEST_SET_IDLE                 0x0A
#define USB_HID_REQUEST_SET_PROTOCOL             0x0B
#define USB_HID_PROTOCOL_BOOT                    0

/* Boot reports (HID 1.11 Appendix B). Keyboard (B.1): byte 0 modifier
 * bits -- bit n is the usage E0h + n, LeftControl through RightGUI (HID
 * Usage Tables §10) -- byte 1 reserved, bytes 2..7 the pressed usages,
 * 01h in a key slot meaning ErrorRollOver (too many keys). Mouse (B.2):
 * byte 0 buttons -- bit 0 button 1 (left), bit 1 button 2 (right), bit 2
 * button 3 (middle) -- byte 1 X and byte 2 Y as signed deltas, bytes 3
 * onward device-specific. Cross-check pinned QEMU hw/input/hid.c
 * hid_keyboard_poll (modifiers, 0, six keys, HID_USAGE_ERROR_ROLLOVER
 * 0x01) and hid_pointer_poll (buttons, dx, dy, dz for the mouse; the
 * fourth byte is the wheel, sign already turned so positive is up). */
#define USB_HID_KEYBOARD_REPORT_LENGTH 8
#define USB_HID_KEYBOARD_OFF_MODIFIERS 0
#define USB_HID_KEYBOARD_OFF_KEYS      2
#define USB_HID_KEYBOARD_KEY_SLOTS     6
#define USB_HID_USAGE_MODIFIER_BASE    0xE0
#define USB_HID_USAGE_ERROR_ROLLOVER   0x01
#define USB_HID_MOUSE_REPORT_MIN       3
#define USB_HID_MOUSE_OFF_BUTTONS      0
#define USB_HID_MOUSE_OFF_X            1
#define USB_HID_MOUSE_OFF_Y            2
#define USB_HID_MOUSE_OFF_WHEEL        3
#define USB_HID_MOUSE_BUTTON_LEFT      0x1
#define USB_HID_MOUSE_BUTTON_RIGHT     0x2
#define USB_HID_MOUSE_BUTTON_MIDDLE    0x4

/* --- State --------------------------------------------------------------------- */

/* Events a device can hold while nobody reads: 256 is 64 keystrokes of
 * press + SYN + release + SYN, four times what QEMU's virtio-input eventq
 * buffers for the same purpose (drivers/virtio/input.c). A report that
 * does not fit is dropped whole and counted -- the device's own rule for
 * an unread report (a HID device holds no history), said out loud. */
#define USB_HID_FIFO_EVENTS 256

typedef struct USB_HID_DEVICE
{
    USB_DEVICE *device;
    BOOLEAN isKeyboard;
    uint8_t previous[USB_HID_KEYBOARD_REPORT_LENGTH]; /* last keyboard report */
    uint8_t buttons;                                  /* last mouse button byte */
    HID_INPUT_EVENT fifo[USB_HID_FIFO_EVENTS];
    unsigned head, tail, count;
    unsigned droppedReports;
    unsigned reportsSeen;
} USB_HID_DEVICE;

static USB_HID_DEVICE UsbHidKeyboard;
static USB_HID_DEVICE UsbHidPointer;
static BOOLEAN UsbHidKeyboardPresent;
static BOOLEAN UsbHidPointerPresent;

/* --- The event FIFO --------------------------------------------------------- */

static void UsbHidPush(USB_HID_DEVICE *hid, uint16_t type, uint16_t code, uint32_t value)
{
    ASSERT(hid->count < USB_HID_FIFO_EVENTS);
    HID_INPUT_EVENT *event = &hid->fifo[hid->tail];
    event->type = type;
    event->code = code;
    event->value = value;
    hid->tail = (hid->tail + 1) % USB_HID_FIFO_EVENTS;
    hid->count++;
}

static int UsbHidPop(USB_HID_DEVICE *hid, HID_INPUT_EVENT *event)
{
    if (hid->count == 0)
    {
        return 0;
    }
    *event = hid->fifo[hid->head];
    hid->head = (hid->head + 1) % USB_HID_FIFO_EVENTS;
    hid->count--;
    return 1;
}

/* A report becomes a burst of events ending in SYN_REPORT, all or nothing:
 * a half-delivered report (a press without its SYN, a release lost) would
 * leave a key stuck above the boundary. */
static BOOLEAN UsbHidReserve(USB_HID_DEVICE *hid, unsigned events)
{
    if (hid->count + events <= USB_HID_FIFO_EVENTS)
    {
        return TRUE;
    }
    if (hid->droppedReports == 0)
    {
        DbgPrint("usb-hid: %s report dropped: %u events queued and nobody reading\n",
                 hid->isKeyboard ? "keyboard" : "mouse", hid->count);
    }
    hid->droppedReports++;
    return FALSE;
}

/* --- Report parsing ---------------------------------------------------------- */

static BOOLEAN UsbHidKeyboardHas(const uint8_t *report, uint8_t usage)
{
    for (unsigned slot = 0; slot < USB_HID_KEYBOARD_KEY_SLOTS; slot++)
    {
        if (report[USB_HID_KEYBOARD_OFF_KEYS + slot] == usage)
        {
            return TRUE;
        }
    }
    return FALSE;
}

static void UsbHidKeyEvent(USB_HID_DEVICE *hid, uint8_t usage, uint32_t value)
{
    uint16_t code = UsbKeymapUsageToEvdev[usage];
    if (code == 0)
    {
        DbgPrint("usb-hid: keyboard usage %02x has no evdev key; dropped\n", usage);
        return;
    }
    UsbHidPush(hid, HID_EV_KEY, code, value);
}

static void UsbHidParseKeyboard(USB_HID_DEVICE *hid, const uint8_t *report, unsigned length)
{
    if (length < USB_HID_KEYBOARD_REPORT_LENGTH)
    {
        DbgPrint("usb-hid: keyboard report of %u bytes (boot protocol says 8); dropped\n", length);
        return;
    }
    /* ErrorRollOver: the device cannot say which keys are down. The
     * previous state stands until it can (HID 1.11 B.1). */
    if (UsbHidKeyboardHas(report, USB_HID_USAGE_ERROR_ROLLOVER))
    {
        return;
    }
    /* Worst case: every modifier flips and all six slots turn over. */
    if (!UsbHidReserve(hid, 8 + 2 * USB_HID_KEYBOARD_KEY_SLOTS + 1))
    {
        return;
    }
    unsigned before = hid->count;
    uint8_t oldModifiers = hid->previous[USB_HID_KEYBOARD_OFF_MODIFIERS];
    uint8_t newModifiers = report[USB_HID_KEYBOARD_OFF_MODIFIERS];
    for (unsigned bit = 0; bit < 8; bit++)
    {
        uint8_t mask = (uint8_t)(1u << bit);
        if ((oldModifiers ^ newModifiers) & mask)
        {
            UsbHidKeyEvent(hid, (uint8_t)(USB_HID_USAGE_MODIFIER_BASE + bit),
                           (newModifiers & mask) ? 1 : 0);
        }
    }
    /* Releases before presses, so a key that moved slots is never seen
     * pressed twice. A slot of 0 is empty (HID Usage Tables §10). */
    for (unsigned slot = 0; slot < USB_HID_KEYBOARD_KEY_SLOTS; slot++)
    {
        uint8_t usage = hid->previous[USB_HID_KEYBOARD_OFF_KEYS + slot];
        if (usage != 0 && !UsbHidKeyboardHas(report, usage))
        {
            UsbHidKeyEvent(hid, usage, 0);
        }
    }
    for (unsigned slot = 0; slot < USB_HID_KEYBOARD_KEY_SLOTS; slot++)
    {
        uint8_t usage = report[USB_HID_KEYBOARD_OFF_KEYS + slot];
        if (usage != 0 && !UsbHidKeyboardHas(hid->previous, usage))
        {
            UsbHidKeyEvent(hid, usage, 1);
        }
    }
    if (hid->count != before)
    {
        UsbHidPush(hid, HID_EV_SYN, 0, 0);
    }
    memcpy(hid->previous, report, USB_HID_KEYBOARD_REPORT_LENGTH);
}

static void UsbHidParseMouse(USB_HID_DEVICE *hid, const uint8_t *report, unsigned length)
{
    if (length < USB_HID_MOUSE_REPORT_MIN)
    {
        DbgPrint("usb-hid: mouse report of %u bytes (boot protocol says 3+); dropped\n", length);
        return;
    }
    /* Three buttons, two axes, a wheel, SYN. */
    if (!UsbHidReserve(hid, 3 + 3 + 1))
    {
        return;
    }
    unsigned before = hid->count;
    uint8_t buttons = report[USB_HID_MOUSE_OFF_BUTTONS];
    uint8_t changed = (uint8_t)(buttons ^ hid->buttons);
    if (changed & USB_HID_MOUSE_BUTTON_LEFT)
    {
        UsbHidPush(hid, HID_EV_KEY, HID_BTN_LEFT, (buttons & USB_HID_MOUSE_BUTTON_LEFT) ? 1 : 0);
    }
    if (changed & USB_HID_MOUSE_BUTTON_RIGHT)
    {
        UsbHidPush(hid, HID_EV_KEY, HID_BTN_RIGHT, (buttons & USB_HID_MOUSE_BUTTON_RIGHT) ? 1 : 0);
    }
    if (changed & USB_HID_MOUSE_BUTTON_MIDDLE)
    {
        UsbHidPush(hid, HID_EV_KEY, HID_BTN_MIDDLE,
                   (buttons & USB_HID_MOUSE_BUTTON_MIDDLE) ? 1 : 0);
    }
    hid->buttons = buttons;
    int8_t dx = (int8_t)report[USB_HID_MOUSE_OFF_X];
    int8_t dy = (int8_t)report[USB_HID_MOUSE_OFF_Y];
    if (dx != 0)
    {
        UsbHidPush(hid, HID_EV_REL, HID_REL_X, (uint32_t)(int32_t)dx);
    }
    if (dy != 0)
    {
        UsbHidPush(hid, HID_EV_REL, HID_REL_Y, (uint32_t)(int32_t)dy);
    }
    if (length > USB_HID_MOUSE_OFF_WHEEL)
    {
        int8_t wheel = (int8_t)report[USB_HID_MOUSE_OFF_WHEEL];
        if (wheel != 0)
        {
            UsbHidPush(hid, HID_EV_REL, HID_REL_WHEEL, (uint32_t)(int32_t)wheel);
        }
    }
    if (hid->count != before)
    {
        UsbHidPush(hid, HID_EV_SYN, 0, 0);
    }
}

/* Transfer completion for the one interrupt IN TRB in flight: parse, then
 * re-arm. Called from XhciPollEvents, which the readers drive; never
 * blocks. */
static void UsbHidOnTransfer(USB_DEVICE *device, uint8_t completionCode, uint32_t residual)
{
    USB_HID_DEVICE *hid = device->context;
    if (completionCode != XHCI_CC_SUCCESS && completionCode != XHCI_CC_SHORT_PACKET)
    {
        /* A halted endpoint (STALL, transaction errors past CErr) needs
         * Reset Endpoint + Set TR Dequeue Pointer (§4.6.8, §4.6.10) to
         * recover, which is unbuilt: the device stops here, loudly, and
         * its reader blocks on a stream that has ended rather than on
         * fabricated events (Art. 12). */
        DbgPrint("usb-hid: %s endpoint failed, cc %u; device stopped (endpoint recovery unbuilt)\n",
                 hid->isKeyboard ? "keyboard" : "mouse", completionCode);
        device->failed = TRUE;
        return;
    }
    unsigned length = residual <= device->intrMaxPacket ? device->intrMaxPacket - residual : 0;
    const uint8_t *report = XhciReportBuffer(device);
    hid->reportsSeen++;
    if (hid->isKeyboard)
    {
        UsbHidParseKeyboard(hid, report, length);
    }
    else
    {
        UsbHidParseMouse(hid, report, length);
    }
    XhciPostInterruptIn(device);
}

static int UsbHidTryRead(void *context, HID_INPUT_EVENT *event)
{
    USB_HID_DEVICE *hid = context;
    XhciPollEvents();
    return UsbHidPop(hid, event);
}

/* --- Bring-up ------------------------------------------------------------------ */

/* Find the first boot-protocol HID interface in a configuration set and
 * its interrupt IN endpoint. Descriptors are walked by bLength (USB 2.0
 * §9.5): class descriptors (the HID descriptor, type 21h) sit between the
 * interface and its endpoints and are skipped like anything unknown. */
static BOOLEAN UsbHidFindBootInterface(const USB_DEVICE *device, uint8_t *interfaceOut,
                                       uint8_t *protocolOut, uint8_t *endpointOut,
                                       uint16_t *maxPacketOut, uint8_t *intervalOut)
{
    const uint8_t *set = device->configSet;
    unsigned length = device->configSetLength;
    unsigned offset = 0;
    BOOLEAN inBootInterface = FALSE;
    while (offset + 2 <= length)
    {
        unsigned descriptorLength = set[offset + USB_DESCRIPTOR_OFF_LENGTH];
        uint8_t type = set[offset + USB_DESCRIPTOR_OFF_TYPE];
        if (descriptorLength < 2 || offset + descriptorLength > length)
        {
            return FALSE; /* a malformed set names nothing */
        }
        if (type == USB_DESCRIPTOR_TYPE_INTERFACE &&
            descriptorLength >= USB_INTERFACE_DESCRIPTOR_LENGTH)
        {
            uint8_t protocol = set[offset + USB_INTERFACE_OFF_PROTOCOL];
            inBootInterface =
                set[offset + USB_INTERFACE_OFF_CLASS] == USB_CLASS_HID &&
                set[offset + USB_INTERFACE_OFF_SUBCLASS] == USB_HID_SUBCLASS_BOOT &&
                (protocol == USB_HID_PROTOCOL_KEYBOARD || protocol == USB_HID_PROTOCOL_MOUSE);
            if (inBootInterface)
            {
                *interfaceOut = set[offset + USB_INTERFACE_OFF_NUMBER];
                *protocolOut = protocol;
            }
        }
        else if (inBootInterface && type == USB_DESCRIPTOR_TYPE_ENDPOINT &&
                 descriptorLength >= USB_ENDPOINT_DESCRIPTOR_LENGTH)
        {
            uint8_t address = set[offset + USB_ENDPOINT_OFF_ADDRESS];
            uint8_t attributes = set[offset + USB_ENDPOINT_OFF_ATTRIBUTES];
            if ((address & USB_ENDPOINT_ADDRESS_IN) &&
                (attributes & USB_ENDPOINT_TRANSFER_TYPE_MASK) == USB_ENDPOINT_TRANSFER_INTERRUPT)
            {
                *endpointOut = address;
                *maxPacketOut = (uint16_t)(set[offset + USB_ENDPOINT_OFF_MAX_PACKET] |
                                           (set[offset + USB_ENDPOINT_OFF_MAX_PACKET + 1] << 8));
                *intervalOut = set[offset + USB_ENDPOINT_OFF_INTERVAL];
                return TRUE;
            }
        }
        offset += descriptorLength;
    }
    return FALSE;
}

static BOOLEAN UsbHidAttach(USB_DEVICE *device, USB_HID_DEVICE *hid, uint8_t interfaceNumber,
                            uint8_t endpoint, uint16_t maxPacket, uint8_t interval)
{
    const char *kind = hid->isKeyboard ? "keyboard" : "mouse";
    /* Configure Endpoint before SET_CONFIGURATION (§4.3.5: the controller
     * must know the endpoint before the device starts using it). */
    if (XhciConfigureInterruptIn(device, endpoint, maxPacket, interval) != XHCI_CC_SUCCESS)
    {
        return FALSE;
    }
    uint8_t configurationValue = device->configSet[USB_CONFIG_OFF_CONFIGURATION_VALUE];
    if (XhciControlTransfer(device, USB_REQUEST_TYPE_HOST_TO_DEVICE_STANDARD,
                            USB_REQUEST_SET_CONFIGURATION, configurationValue, 0, 0, 0,
                            0) != XHCI_CC_SUCCESS)
    {
        DbgPrint("usb-hid: %s: SET_CONFIGURATION(%u) refused\n", kind, configurationValue);
        return FALSE;
    }
    if (XhciControlTransfer(device, USB_REQUEST_TYPE_HOST_TO_DEVICE_CLASS_IF,
                            USB_HID_REQUEST_SET_PROTOCOL, USB_HID_PROTOCOL_BOOT, interfaceNumber, 0,
                            0, 0) != XHCI_CC_SUCCESS)
    {
        DbgPrint("usb-hid: %s: SET_PROTOCOL(boot) refused\n", kind);
        return FALSE;
    }
    /* Idle 0: report only on change (HID 1.11 §7.2.4). Optional for a
     * mouse per §7.2.4, so its refusal is noted, not fatal. */
    if (XhciControlTransfer(device, USB_REQUEST_TYPE_HOST_TO_DEVICE_CLASS_IF,
                            USB_HID_REQUEST_SET_IDLE, 0, interfaceNumber, 0, 0,
                            0) != XHCI_CC_SUCCESS)
    {
        DbgPrint("usb-hid: %s: SET_IDLE(0) refused; the device reports at its own rate\n", kind);
    }
    hid->device = device;
    device->context = hid;
    device->OnTransfer = UsbHidOnTransfer;
    XhciPostInterruptIn(device);
    DbgPrint("[KTEST] usb hid %s port=%u slot=%u speed=%u ep=%02x mps=%u interval=%u\n", kind,
             device->port, device->slotId, device->speed, endpoint, maxPacket, interval);
    return TRUE;
}

void UsbHidInitialize(void)
{
    if (!XhciIsPresent())
    {
        DbgPrint("usb-hid: no xHCI; no USB input\n");
        return;
    }
    XhciEnumerate();
    for (unsigned index = 0; index < XhciDeviceCount(); index++)
    {
        USB_DEVICE *device = XhciDevice(index);
        if (!device->addressed)
        {
            continue; /* the enumeration said why */
        }
        uint8_t interfaceNumber = 0, protocol = 0, endpoint = 0, interval = 0;
        uint16_t maxPacket = 0;
        if (!UsbHidFindBootInterface(device, &interfaceNumber, &protocol, &endpoint, &maxPacket,
                                     &interval))
        {
            DbgPrint("usb-hid: port %u slot %u: no boot-protocol keyboard/mouse interface; "
                     "left alone (report-descriptor HID is unbuilt%s)\n",
                     device->port, device->slotId,
                     device->deviceDescriptor[USB_DEVICE_DESCRIPTOR_OFF_CLASS] == 0
                         ? "; a usb-tablet needs usb-mouse"
                         : "");
            continue;
        }
        USB_HID_DEVICE *hid;
        if (protocol == USB_HID_PROTOCOL_KEYBOARD)
        {
            if (UsbHidKeyboardPresent)
            {
                DbgPrint("usb-hid: port %u: second keyboard ignored\n", device->port);
                continue;
            }
            hid = &UsbHidKeyboard;
            hid->isKeyboard = TRUE;
        }
        else
        {
            if (UsbHidPointerPresent)
            {
                DbgPrint("usb-hid: port %u: second mouse ignored\n", device->port);
                continue;
            }
            hid = &UsbHidPointer;
            hid->isKeyboard = FALSE;
        }
        if (UsbHidAttach(device, hid, interfaceNumber, endpoint, maxPacket, interval))
        {
            if (hid->isKeyboard)
            {
                UsbHidKeyboardPresent = TRUE;
            }
            else
            {
                UsbHidPointerPresent = TRUE;
            }
        }
    }
    XhciFinishEnumeration();
    if (!UsbHidKeyboardPresent && !UsbHidPointerPresent)
    {
        DbgPrint("usb-hid: no boot-protocol keyboard or mouse on the xHCI\n");
    }
}

static void UsbHidFillSource(USB_HID_DEVICE *hid, HID_SOURCE *source)
{
    memset(source, 0, sizeof(*source));
    source->TryRead = UsbHidTryRead;
    source->context = hid;
    source->name = "usb-hid boot";
    /* A relative pointer: no absolute axes, so the range it publishes is
     * empty (drivers/hidproto.h). */
}

BOOLEAN UsbHidKeyboardSource(HID_SOURCE *source)
{
    if (!UsbHidKeyboardPresent)
    {
        return FALSE;
    }
    UsbHidFillSource(&UsbHidKeyboard, source);
    return TRUE;
}

BOOLEAN UsbHidPointerSource(HID_SOURCE *source)
{
    if (!UsbHidPointerPresent)
    {
        return FALSE;
    }
    UsbHidFillSource(&UsbHidPointer, source);
    return TRUE;
}
