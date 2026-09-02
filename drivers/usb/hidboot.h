/* drivers/usb/hidboot.h — USB HID boot-protocol keyboard and mouse over
 * xHCI (USB-1): the second event source behind \Device\Input0 and
 * \Device\Input1 (drivers/hid.c, HACK-002). See hidboot.c. */
#ifndef PROSKRNL_DRIVERS_USB_HIDBOOT_H
#define PROSKRNL_DRIVERS_USB_HIDBOOT_H

#include "abi/ntdef.h"
#include "drivers/hid.h"
#include "drivers/hidproto.h"

/* Phase 2, on the first kernel thread, before HidInitialize: enumerate the
 * xHCI's root ports (drivers/usb/xhci.c), keep the first boot-protocol
 * keyboard and the first boot-protocol mouse, put each in boot protocol
 * and arm its interrupt endpoint. Every other device is named on serial
 * and left alone. A no-op, loudly, without a controller. */
void UsbHidInitialize(void);

/* Fill a source descriptor for the keyboard / the pointer; FALSE when
 * there is none. Which is which is the device's own claim
 * (bInterfaceProtocol, HID 1.11 §4.3), never port order. */
BOOLEAN UsbHidKeyboardSource(HID_SOURCE *source);
BOOLEAN UsbHidPointerSource(HID_SOURCE *source);

#endif /* PROSKRNL_DRIVERS_USB_HIDBOOT_H */
