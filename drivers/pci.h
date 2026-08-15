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

/* Capability IDs (PCI 3.0 Appendix H; cross-check: pinned QEMU
 * include/standard-headers/linux/pci_regs.h PCI_CAP_ID_*). */
#define PCI_CAP_ID_VENDOR 0x09
#define PCI_CAP_ID_MSIX   0x11

/* MSI-X capability layout (PCI 3.0 §6.8.2; cross-check: pinned QEMU
 * pci_regs.h PCI_MSIX_FLAGS/PCI_MSIX_TABLE): message control word at cap+2
 * (table size N-1 in bits 10:0, Function Mask bit 14, Enable bit 15), table
 * offset/BIR dword at cap+4 (BIR in bits 2:0, offset in the rest). */
#define PCI_MSIX_CAP_OFF_MESSAGE_CONTROL 2
#define PCI_MSIX_CAP_OFF_TABLE           4
#define PCI_MSIX_CONTROL_TABLE_SIZE_MASK 0x07FF
#define PCI_MSIX_CONTROL_FUNCTION_MASK   0x4000
#define PCI_MSIX_CONTROL_ENABLE          0x8000
#define PCI_MSIX_TABLE_BIR_MASK          0x7

/* One MSI-X table entry (PCI 3.0 §6.8.2: message address low/high, message
 * data, vector control — per-entry mask is vector-control bit 0; entries
 * RESET MASKED, §6.8.2/§6.8.3). Fields are dword-wide on purpose: the
 * pinned QEMU device model rejects sub-dword table accesses
 * (hw/pci/msix.c msix_table_mmio_ops, min_access_size 4). */
typedef struct
{
    volatile uint32_t addressLow;
    volatile uint32_t addressHigh;
    volatile uint32_t data;
    volatile uint32_t vectorControl;
} KI_MSIX_TABLE_ENTRY;
_Static_assert(sizeof(KI_MSIX_TABLE_ENTRY) == 16, "MSI-X table entry (PCI 3.0 §6.8.2)");
#define PCI_MSIX_ENTRY_CONTROL_MASK_BIT 0x1

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

/* Scan bus 0 for the (nth+1)-th function matching vendor and a device-ID
 * predicate range [deviceLow, deviceHigh] (nth is a 0-based match index, so
 * two identical functions — e.g. two virtio-input devices — are both
 * reachable). Returns 1 and fills `out`. */
int KiPciFindDevice(uint16_t vendor, uint16_t deviceLow, uint16_t deviceHigh, unsigned nth,
                    KI_PCI_FUNCTION *out);

/* Read a BAR as a 64-bit physical address (handles the 64-bit memory BAR
 * encoding; returns 0 for an I/O BAR or an unimplemented BAR). */
uint64_t KiPciReadMemoryBar(const KI_PCI_FUNCTION *f, uint8_t barIndex);

/* Walk the capability list (PCI 3.0 §6.7) for the next capability with
 * `capabilityId` — the tree's ONE generic walker (Art. 11): virtio's
 * vendor-specific resolution layers on top of this rather than owning a
 * second copy of the walk. `previous` = 0 starts at the head; a previous
 * result resumes after it, so same-ID capabilities (vendor caps) are all
 * reachable. Returns the capability's config-space offset, or 0. */
uint8_t KiPciFindCapability(const KI_PCI_FUNCTION *f, uint8_t capabilityId, uint8_t previous);

#endif /* PROSKRNL_DRIVERS_PCI_H */
