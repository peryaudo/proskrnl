/* drivers/pci.c — minimal PCI configuration access (see pci.h). */
#include "drivers/pci.h"
#include "arch/x86_64/io.h"
#include "arch/x86_64/mmu.h"
#include "kernel/mm/phys.h"

/* Kernel VA window device MMIO is mapped into (a fresh PML4 slot; see
 * KiPciMapMmio in pci.h). One cursor for the whole tree. */
#define KI_PCI_MMIO_WINDOW_BASE 0xFFFFA10000000000ULL
static uint64_t KiPciMmioWindowCursor = KI_PCI_MMIO_WINDOW_BASE;

/* CONFIG_ADDRESS / CONFIG_DATA, PCI Local Bus Spec 3.0 §3.2.2.3.2: enable
 * bit 31, bus 23:16, device 15:11, function 10:8, DWORD register 7:2. */
#define PCI_CONFIG_ADDRESS_PORT 0xCF8
#define PCI_CONFIG_DATA_PORT    0xCFC

static uint32_t KipPciAddress(const KI_PCI_FUNCTION *f, uint8_t offset)
{
    return 0x80000000u | ((uint32_t)f->device << 11) | ((uint32_t)f->function << 8) |
           (offset & 0xFCu);
}

uint32_t KiPciReadConfig32(const KI_PCI_FUNCTION *f, uint8_t offset)
{
    KiOutLong(PCI_CONFIG_ADDRESS_PORT, KipPciAddress(f, offset));
    return KiInLong(PCI_CONFIG_DATA_PORT);
}

uint16_t KiPciReadConfig16(const KI_PCI_FUNCTION *f, uint8_t offset)
{
    return (uint16_t)(KiPciReadConfig32(f, offset) >> ((offset & 2) * 8));
}

uint8_t KiPciReadConfig8(const KI_PCI_FUNCTION *f, uint8_t offset)
{
    return (uint8_t)(KiPciReadConfig32(f, offset) >> ((offset & 3) * 8));
}

void KiPciWriteConfig32(const KI_PCI_FUNCTION *f, uint8_t offset, uint32_t value)
{
    KiOutLong(PCI_CONFIG_ADDRESS_PORT, KipPciAddress(f, offset));
    KiOutLong(PCI_CONFIG_DATA_PORT, value);
}

void KiPciWriteConfig16(const KI_PCI_FUNCTION *f, uint8_t offset, uint16_t value)
{
    uint32_t dword = KiPciReadConfig32(f, offset);
    unsigned shift = (offset & 2) * 8;
    dword = (dword & ~(0xFFFFu << shift)) | ((uint32_t)value << shift);
    KiPciWriteConfig32(f, offset, dword);
}

int KiPciFindDevice(uint16_t vendor, uint16_t deviceLow, uint16_t deviceHigh, unsigned nth,
                    KI_PCI_FUNCTION *out)
{
    for (uint8_t device = 0; device < 32; device++)
    {
        for (uint8_t function = 0; function < 8; function++)
        {
            KI_PCI_FUNCTION f = {device, function, 0, 0};
            uint32_t id = KiPciReadConfig32(&f, PCI_CONFIG_VENDOR_ID);
            if ((id & 0xFFFF) == 0xFFFF)
            {
                /* All-ones read: no device (PCI 3.0 §6.1). Function 0 absent
                 * means the whole slot is empty. */
                if (function == 0)
                {
                    break;
                }
                continue;
            }
            f.vendorId = (uint16_t)id;
            f.deviceId = (uint16_t)(id >> 16);
            if (f.vendorId == vendor && f.deviceId >= deviceLow && f.deviceId <= deviceHigh)
            {
                if (nth == 0)
                {
                    *out = f;
                    return 1;
                }
                nth--;
            }
            /* Single-function device: header type bit 7 clear (PCI §6.2.1). */
            if (function == 0 && (KiPciReadConfig8(&f, PCI_CONFIG_HEADER_TYPE) & 0x80) == 0)
            {
                break;
            }
        }
    }
    return 0;
}

int KiPciFindDeviceByClass(uint8_t baseClass, uint8_t subClass, uint8_t progIf, unsigned nth,
                           KI_PCI_FUNCTION *out)
{
    for (uint8_t device = 0; device < 32; device++)
    {
        for (uint8_t function = 0; function < 8; function++)
        {
            KI_PCI_FUNCTION f = {device, function, 0, 0};
            uint32_t id = KiPciReadConfig32(&f, PCI_CONFIG_VENDOR_ID);
            if ((id & 0xFFFF) == 0xFFFF)
            {
                if (function == 0)
                {
                    break; /* all-ones: no device (PCI 3.0 §6.1); slot empty */
                }
                continue;
            }
            f.vendorId = (uint16_t)id;
            f.deviceId = (uint16_t)(id >> 16);
            /* The dword at 08h is revision id | prog-if << 8 | sub-class
             * << 16 | base class << 24 (PCI 3.0 §6.1 Figure 6-1). */
            uint32_t classDword = KiPciReadConfig32(&f, PCI_CONFIG_REVISION);
            if ((uint8_t)(classDword >> 24) == baseClass &&
                (uint8_t)(classDword >> 16) == subClass && (uint8_t)(classDword >> 8) == progIf)
            {
                if (nth == 0)
                {
                    *out = f;
                    return 1;
                }
                nth--;
            }
            if (function == 0 && (KiPciReadConfig8(&f, PCI_CONFIG_HEADER_TYPE) & 0x80) == 0)
            {
                break; /* single-function device (PCI §6.2.1) */
            }
        }
    }
    return 0;
}

uint8_t KiPciFindCapability(const KI_PCI_FUNCTION *f, uint8_t capabilityId, uint8_t previous)
{
    if ((KiPciReadConfig16(f, PCI_CONFIG_STATUS) & PCI_STATUS_CAPABILITIES_LIST) == 0)
    {
        return 0;
    }
    /* Capabilities pointer / cap_next: low two bits reserved (PCI 3.0 §6.7). */
    uint8_t offset = previous == 0 ? (KiPciReadConfig8(f, PCI_CONFIG_CAP_POINTER) & 0xFC)
                                   : (KiPciReadConfig8(f, (uint8_t)(previous + 1)) & 0xFC);
    /* The list is device-supplied and a cyclic cap_next hung the boot
     * forever (docs/review-2026-07 §4). Config space is 256 bytes and every
     * capability is at least 4 of them, so 64 links is the most a
     * well-formed list can have (PCI 3.0 §6.7). */
    for (unsigned link = 0; offset != 0 && link < 64; link++)
    {
        if (KiPciReadConfig8(f, offset) == capabilityId)
        {
            return offset;
        }
        offset = KiPciReadConfig8(f, (uint8_t)(offset + 1)) & 0xFC;
    }
    return 0;
}

uint64_t KiPciReadMemoryBar(const KI_PCI_FUNCTION *f, uint8_t barIndex)
{
    uint8_t offset = (uint8_t)(PCI_CONFIG_BAR0 + barIndex * 4);
    uint32_t low = KiPciReadConfig32(f, offset);
    if (low & 0x1)
    {
        return 0; /* I/O space BAR (PCI 3.0 §6.2.5.1: bit 0 = 1 for I/O) */
    }
    /* Memory BAR type bits 2:1 — 10b = 64-bit (PCI 3.0 §6.2.5.1). */
    uint64_t address = low & ~0xFULL;
    if (((low >> 1) & 0x3) == 0x2)
    {
        address |= (uint64_t)KiPciReadConfig32(f, (uint8_t)(offset + 4)) << 32;
    }
    return address;
}

void *KiPciMapMmio(uint64_t physical, uint64_t length)
{
    uint64_t first = physical & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t last = (physical + length + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t base = KiPciMmioWindowCursor;
    for (uint64_t page = first; page < last; page += PAGE_SIZE)
    {
        /* MiMapDevicePage, not MiMapPage: these are device registers, and a
         * write-back cacheable mapping means the CPU may satisfy a read from
         * cache and hold a write in a store buffer -- `volatile` constrains
         * the compiler, not the cache (docs/review-2026-07 §8). This worked
         * only because firmware happens to leave the PCI hole UC in the
         * MTRRs, which nothing here establishes or checks. arch/x86_64/mmu.c
         * has the mapping for exactly this; lapic.c already uses it. */
        MiMapDevicePage(KiPciMmioWindowCursor, page);
        KiPciMmioWindowCursor += PAGE_SIZE;
    }
    return (void *)(uintptr_t)(base + (physical - first));
}
