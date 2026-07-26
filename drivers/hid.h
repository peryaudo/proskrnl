/* drivers/hid.h — \Device\Input0, the raw input stream (GUI-1, HACK-002).
 * The wire contract is drivers/hidproto.h. */
#ifndef PROSKRNL_DRIVERS_HID_H
#define PROSKRNL_DRIVERS_HID_H

/* Publish \Device\Input0 over the virtio-input device, if one came up.
 * Needs a handle table (IoPublishDevice), so it runs on the first kernel
 * thread. No input device means no \Device\Input0: an open then fails
 * STATUS_OBJECT_NAME_NOT_FOUND rather than blocking forever on an event
 * stream nothing will ever feed (Art. 12). */
void HidInitialize(void);

#endif /* PROSKRNL_DRIVERS_HID_H */
