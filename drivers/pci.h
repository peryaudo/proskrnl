/* drivers/pci.h — minimal PCI configuration access (M6, for virtio-pci).
 *
 * Configuration Mechanism #1 only: CONFIG_ADDRESS/CONFIG_DATA at I/O ports
 * 0xCF8/0xCFC (PCI Local Bus Specification 3.0 §3.2.2.3.2). Enumeration is
 * a flat scan of bus 0 — every QEMU q35 virtio device the project runs
 * against sits there (cross-check: third_party/qemu, -drive if=virtio).
 * No PnP, no driver model (docs/03: WDM/PnP dropped); drivers are statically
 * linked and probe what they need at boot.
 */
#ifndef PROSKRNL_DRIVERS_PCI_H
#define PROSKRNL_DRIVERS_PCI_H

#include <stdint.h>

/* Standard Type 00h configuration-header offsets (PCI Local Bus Spec 3.0
 * §6.1 Figure 6-1; register semantics §6.2). */
#define PCI_CONFIG_VENDOR_ID   0x00
#define PCI_CONFIG_DEVICE_ID   0x02
#define PCI_CONFIG_COMMAND     0x04
#define PCI_CONFIG_STATUS      0x06
#define PCI_CONFIG_REVISION    0x08
#define PCI_CONFIG_HEADER_TYPE 0x0E
#define PCI_CONFIG_BAR0        0x10
#define PCI_CONFIG_CAP_POINTER 0x34

/* Command register bits (PCI 3.0 §6.2.2 Table 6-1). */
#define PCI_COMMAND_IO_SPACE     0x0001
#define PCI_COMMAND_MEMORY_SPACE 0x0002
#define PCI_COMMAND_BUS_MASTER   0x0004

/* Status register: capabilities-list valid (PCI 3.0 §6.2.3 Table 6-2 bit 4). */
#define PCI_STATUS_CAPABILITIES_LIST 0x0010

/* One discovered function on bus 0. */
typedef struct
{
    uint8_t device;
    uint8_t function;
    uint16_t vendorId;
    uint16_t deviceId;
} KI_PCI_FUNCTION;

uint32_t KiPciReadConfig32(const KI_PCI_FUNCTION *f, uint8_t offset);
uint16_t KiPciReadConfig16(const KI_PCI_FUNCTION *f, uint8_t offset);
uint8_t KiPciReadConfig8(const KI_PCI_FUNCTION *f, uint8_t offset);
void KiPciWriteConfig32(const KI_PCI_FUNCTION *f, uint8_t offset, uint32_t value);
void KiPciWriteConfig16(const KI_PCI_FUNCTION *f, uint8_t offset, uint16_t value);

/* Scan bus 0 for the first function matching vendor and a device-ID
 * predicate range [deviceLow, deviceHigh]. Returns 1 and fills `out`. */
int KiPciFindDevice(uint16_t vendor, uint16_t deviceLow, uint16_t deviceHigh, KI_PCI_FUNCTION *out);

/* Read a BAR as a 64-bit physical address (handles the 64-bit memory BAR
 * encoding; returns 0 for an I/O BAR or an unimplemented BAR). */
uint64_t KiPciReadMemoryBar(const KI_PCI_FUNCTION *f, uint8_t barIndex);

#endif /* PROSKRNL_DRIVERS_PCI_H */
