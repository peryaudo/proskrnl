/* drivers/hid.h — \Device\Input0 / \Device\Input1, the raw input streams
 * (GUI-1, pointer at GUI-4; HACK-002). The wire contract is
 * drivers/hidproto.h. */
#ifndef PROSKRNL_DRIVERS_HID_H
#define PROSKRNL_DRIVERS_HID_H

/* Publish \Device\Input0 (keyboard) and \Device\Input1 (pointer) over the
 * virtio-input instances that came up — each only if its device exists.
 * Needs a handle table (IoPublishDevice), so it runs on the first kernel
 * thread. No device means no name: an open then fails
 * STATUS_OBJECT_NAME_NOT_FOUND rather than blocking forever on an event
 * stream nothing will ever feed (Art. 12). */
void HidInitialize(void);

#endif /* PROSKRNL_DRIVERS_HID_H */
