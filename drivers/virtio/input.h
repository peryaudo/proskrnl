/* drivers/virtio/input.h — virtio-input (GUI-1; two instances at GUI-4);
 * see input.c. */
#ifndef PROSKRNL_DRIVERS_VIRTIO_INPUT_H
#define PROSKRNL_DRIVERS_VIRTIO_INPUT_H

#include "abi/ntdef.h"
#include "drivers/hid.h"
#include "drivers/hidproto.h"
#include "drivers/virtio/virtio.h"

/* struct virtio_input_absinfo, read verbatim from device config (virtio 1.2
 * cs01 §5.8.4; layout cross-checked against the pinned QEMU tree,
 * include/standard-headers/linux/virtio_input.h). */
typedef struct VIO_INPUT_ABS_INFO
{
    uint32_t min;
    uint32_t max;
    uint32_t fuzz;
    uint32_t flat;
    uint32_t res;
} VIO_INPUT_ABS_INFO;

/* One virtio-input function: the keyboard or the pointer (QEMU's tablet).
 * Which is which comes from the device's own EV_BITS config — never from
 * PCI enumeration order, so identity survives a reordered command line. */
typedef struct VIO_INPUT_INSTANCE
{
    BOOLEAN present;
    BOOLEAN isPointer; /* EV_BITS[EV_ABS] non-empty (input.c) */
    VIO_PCI_DEVICE device;
    VIO_VIRTQUEUE eventQueue;
    uint64_t slotsPhysical; /* one MiAllocatePage frame per instance */
    HID_INPUT_EVENT *slots;
    uint16_t slotCount;
    VIO_INPUT_ABS_INFO absX, absY; /* valid iff isPointer; cached at init */
} VIO_INPUT_INSTANCE;

/* Bring up every attached virtio-input function (at most one keyboard and
 * one pointer). Maps MMIO and reads device config, so it runs from
 * IoInitializeTransport (before the kernel PML4 is frozen) and nothing
 * touches MMIO after it. FALSE, loudly, when there is no virtio-input
 * function at all -- which is every image but the gui ones. */
BOOLEAN VioInputInitialize(void);

/* The classified instances; NULL when absent. */
VIO_INPUT_INSTANCE *VioInputKeyboard(void);
VIO_INPUT_INSTANCE *VioInputPointer(void);

/* The same two as event sources for drivers/hid.c (HID_SOURCE, with the
 * pointer's cached ABS_INFO range); FALSE when absent. */
BOOLEAN VioInputKeyboardSource(HID_SOURCE *source);
BOOLEAN VioInputPointerSource(HID_SOURCE *source);

/* Take one event off an instance's eventq if the device has published one,
 * and re-post its buffer. Returns 0 when nothing is pending -- never blocks;
 * the waiting belongs to the caller (drivers/hid.c). */
int VioInputTryReadEvent(VIO_INPUT_INSTANCE *input, HID_INPUT_EVENT *event);

#endif /* PROSKRNL_DRIVERS_VIRTIO_INPUT_H */
