/* drivers/hid.h — \Device\Input0 / \Device\Input1, the raw input streams
 * (GUI-1, pointer at GUI-4; HACK-002). The wire contract is
 * drivers/hidproto.h. */
#ifndef PROSKRNL_DRIVERS_HID_H
#define PROSKRNL_DRIVERS_HID_H

#include "abi/ntdef.h"
#include "drivers/hidproto.h"

/* An event source behind one stream: what a driver hands hid.c so the two
 * devices can be published over whichever hardware is there — virtio-input
 * (drivers/virtio/input.c) or a USB HID boot device (drivers/usb/hidboot.c,
 * USB-1) — through one publication path (G10/Art. 11). TryRead takes one
 * event if the device has published one and never blocks; the waiting is
 * hid.c's. The abs range is what the pointer device itself published; all
 * zeros is a relative pointer (drivers/hidproto.h). */
typedef struct HID_SOURCE
{
    /* NOLINTBEGIN(readability-identifier-naming) — a dispatch slot is a name
     * of code, PascalCase like IO_VFS_OPS's (docs/15). */
    int (*TryRead)(void *context, HID_INPUT_EVENT *event);
    /* NOLINTEND(readability-identifier-naming) */
    void *context;
    HID_ABS_INFO abs;
    const char *name; /* for the publish line on serial */
} HID_SOURCE;

/* Publish \Device\Input0 (keyboard) and \Device\Input1 (pointer) over the
 * sources that came up — virtio-input first, else USB HID — each only if a
 * device exists.
 * Needs a handle table (IoPublishDevice), so it runs on the first kernel
 * thread. No device means no name: an open then fails
 * STATUS_OBJECT_NAME_NOT_FOUND rather than blocking forever on an event
 * stream nothing will ever feed (Art. 12). */
void HidInitialize(void);

#endif /* PROSKRNL_DRIVERS_HID_H */
