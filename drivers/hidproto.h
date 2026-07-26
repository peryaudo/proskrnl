/* drivers/hidproto.h — the \Device\Input0 contract (GUI-1, HACK-002).
 *
 * The kernel <-> user protocol for the raw input device, shared by
 * drivers/hid.c and everything that opens \Device\Input0 (tests/gui, and
 * user/wine/winefb.drv/input.c from GUI-2). Outside abi/ for the same
 * reason as drivers/fbproto.h: NT has no such device, so there is nothing
 * in Wine's headers to generate the contract from.
 *
 * \Device\Input0 is HACK-002 (docs/10): NT routes raw input through win32k
 * and csrss into the input queue, and route (a) (docs/07) has neither, so
 * the display backend needs a raw event source. Like \Device\Fb0 it sits at
 * the OUTSIDE of the boundary (Art. 2's GUI exception).
 *
 * Contract:
 *
 *   NtCreateFile(\Device\Input0, FILE_GENERIC_READ, share = 0)
 *   NtReadFile(buffer, length)  -> n whole HID_INPUT_EVENTs, Information = n * 8
 *
 * Reads BLOCK until at least one event is available; there is no
 * poll/peek mode and no ioctl (a read that returned "nothing yet" has no
 * consumer -- GUI-3's unified waiting lives in user mode, docs/07 -- and an
 * unbuilt mode must refuse rather than exist half-way, Art. 12). A read
 * returns only whole events; a buffer smaller than one event is an error
 * rather than a silent short read. The device opens EXCLUSIVELY: a second
 * open gets STATUS_SHARING_VIOLATION, because two readers of one event
 * stream would each see an arbitrary half of it.
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
#define HID_EV_ABS 0x03 /* absolute axis: value in the device's ABS_INFO range */

/* EV_ABS axis codes (input-event-codes.h ABS_*). The pointer instance is
 * the one whose EV_BITS advertise EV_ABS (drivers/virtio/input.c). */
#define HID_ABS_X 0x00
#define HID_ABS_Y 0x01

#endif /* PROSKRNL_DRIVERS_HIDPROTO_H */
