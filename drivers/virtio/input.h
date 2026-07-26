/* drivers/virtio/input.h — virtio-input (GUI-1); see input.c. */
#ifndef PROSKRNL_DRIVERS_VIRTIO_INPUT_H
#define PROSKRNL_DRIVERS_VIRTIO_INPUT_H

#include "abi/ntdef.h"
#include "drivers/hidproto.h"

/* Bring the device up if one is attached. Maps MMIO, so it runs from
 * IoInitializeTransport (before the kernel PML4 is frozen). FALSE, loudly,
 * when there is no virtio-input function -- which is every image but the
 * gui one. */
BOOLEAN VioInputInitialize(void);
BOOLEAN VioInputIsPresent(void);

/* Take one event off the eventq if the device has published one, and
 * re-post its buffer. Returns 0 when nothing is pending -- never blocks;
 * the waiting belongs to the caller (drivers/hid.c). */
int VioInputTryReadEvent(HID_INPUT_EVENT *event);

#endif /* PROSKRNL_DRIVERS_VIRTIO_INPUT_H */
