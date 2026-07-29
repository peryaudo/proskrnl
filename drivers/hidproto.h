/* drivers/hidproto.h — the \Device\Input0 / \Device\Input1 contract
 * (GUI-1, pointer at GUI-4; HACK-002).
 *
 * The kernel <-> user protocol for the raw input devices, shared by
 * drivers/hid.c and everything that opens them (tests/gui, and
 * user/wine/dlls/winefb.drv/input.c from GUI-2). Outside abi/ for the same
 * reason as drivers/fbproto.h: NT has no such devices, so there is nothing
 * in Wine's headers to generate the contract from.
 *
 * The devices are HACK-002 (docs/10): NT routes raw input through win32k
 * and csrss into the input queue, and route (a) (docs/07) has neither, so
 * the display backend needs raw event sources. Like \Device\Fb0 they sit at
 * the OUTSIDE of the boundary (Art. 2's GUI exception). Input0 is the
 * keyboard (FILE_DEVICE_KEYBOARD); Input1, since GUI-4, the pointer —
 * QEMU's tablet — (FILE_DEVICE_MOUSE). Which virtio function is which is
 * the device's own claim (EV_BITS advertise EV_ABS), never PCI order.
 *
 * Contract, identical per stream:
 *
 *   NtCreateFile(\Device\InputN, FILE_GENERIC_READ, share = 0)
 *   NtReadFile(buffer, length)  -> n whole HID_INPUT_EVENTs, Information = n * 8
 *
 * Reads BLOCK until at least one event is available; there is no
 * poll/peek mode (a read that returned "nothing yet" has no consumer --
 * GUI-3's unified waiting lives in user mode, docs/07 -- and an unbuilt
 * mode must refuse rather than exist half-way, Art. 12). A read returns
 * only whole events; a buffer smaller than one event is an error rather
 * than a silent short read. Each device opens EXCLUSIVELY: a second open
 * gets STATUS_SHARING_VIOLATION, because two readers of one event stream
 * would each see an arbitrary half of it.
 *
 * Input0 has no ioctl at all. Input1 has exactly one verb,
 * IOCTL_PRSHID_GET_ABS_INFO: the absolute-axis range the device itself
 * published (virtio ABS_INFO), reported verbatim so that neither side
 * bakes in a QEMU constant — the fbproto GET_MODE precedent ("the mode
 * the bootloader set, reported verbatim"). Events are still never
 * translated or scaled here: scaling to screen pixels is user mode's,
 * exactly as scancode translation is.
 *
 * Buffering and overflow are the device's, not ours: QEMU's virtio-input
 * holds a 64-entry eventq and drops whole NEW reports when it is full
 * (pinned tree hw/input/virtio-input.c virtio_input_send,
 * trace_virtio_input_queue_full). The driver's obligation is only to keep
 * buffers posted promptly, which the read path does as it drains.
 */
#ifndef PROSKRNL_DRIVERS_HIDPROTO_H
#define PROSKRNL_DRIVERS_HIDPROTO_H

#include <stdint.h>

/* CTL_CODE / METHOD_BUFFERED / FILE_READ_ACCESS / FILE_DEVICE_MOUSE. Both
 * sides of this contract get them from their own view of the same Microsoft
 * definitions: the kernel from abi/ntioapi.h (generated from the pinned
 * Wine winioctl.h, Art. 4), a PE client from mingw's winioctl.h. */
#ifdef _WIN32
#include <winioctl.h>
#else
#include "abi/ntioapi.h"
#endif

/* One input event, the virtio-input wire format passed through verbatim
 * (virtio 1.2 cs01 §5.8.6 struct virtio_input_event {le16 type; le16 code;
 * le32 value}). type/code/value are Linux evdev codes, which that section
 * fixes as the encoding; cross-check third_party/qemu
 * include/standard-headers/linux/input-event-codes.h.
 *
 * Passed through rather than translated on purpose: any translation here
 * would be a keyboard layout, and a layout belongs in user32 above the
 * boundary, not in a driver below it. */
typedef struct HID_INPUT_EVENT
{
    uint16_t type;
    uint16_t code;
    uint32_t value;
} HID_INPUT_EVENT;
_Static_assert(sizeof(HID_INPUT_EVENT) == 8, "virtio_input_event is 8 bytes (virtio 1.2 §5.8.6)");

/* Event types (input-event-codes.h EV_*, fixed by virtio 1.2 cs01 §5.8).
 * Only the ones a consumer exists for; the rest are added when one does. */
#define HID_EV_SYN 0x00 /* report boundary; SYN_REPORT (code 0) ends a report */
#define HID_EV_KEY 0x01 /* key/button: value 1 = press, 0 = release, 2 = autorepeat */
#define HID_EV_REL 0x02 /* relative axis: the tablet's wheel arrives here */
#define HID_EV_ABS 0x03 /* absolute axis: value in the device's ABS_INFO range */

/* EV_ABS axis codes (input-event-codes.h ABS_*). The pointer instance is
 * the one whose EV_BITS advertise EV_ABS (drivers/virtio/input.c). */
#define HID_ABS_X 0x00
#define HID_ABS_Y 0x01

/* EV_REL axis codes (input-event-codes.h REL_*): what QEMU's tablet emits
 * beyond the abs axes. */
#define HID_REL_WHEEL 0x08

/* EV_KEY pointer-button codes (input-event-codes.h BTN_*): well above the
 * keyboard range, so a button can never be mistaken for a key. */
#define HID_BTN_LEFT   0x110
#define HID_BTN_RIGHT  0x111
#define HID_BTN_MIDDLE 0x112

/* Function code 0x800: 0x000-0x7FF are reserved to Microsoft, custom codes
 * start at 0x800 (MS docs, "Defining I/O Control Codes"). */
#define IOCTL_PRSHID_GET_ABS_INFO                                                                  \
    CTL_CODE(FILE_DEVICE_MOUSE, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)

/* The pointer's absolute-axis ranges, as the device published them
 * (virtio 1.2 cs01 §5.8.4 ABS_INFO min/max, cached at init). Inclusive on
 * both ends. fuzz/flat/res are not reported: no consumer. */
typedef struct HID_ABS_INFO
{
    uint32_t minX;
    uint32_t maxX;
    uint32_t minY;
    uint32_t maxY;
} HID_ABS_INFO;
_Static_assert(sizeof(HID_ABS_INFO) == 16, "HID_ABS_INFO layout is the \\Device\\Input1 contract");

#endif /* PROSKRNL_DRIVERS_HIDPROTO_H */
