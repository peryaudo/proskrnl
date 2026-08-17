/* drivers/virtio/pci.c — the modern virtio-pci transport shared by every
 * virtio driver in the tree (see virtio.h).
 *
 * Written from the OASIS virtio 1.2 cs01 specification (sections cited
 * inline) against the pinned third_party/qemu device model. Provenance:
 * public spec only (docs/11).
 *
 * This is the one authority for bringing a virtio function up (G10/Art. 11).
 * It exists as its own file because the BAR mapping window below is a single
 * kernel VA cursor: a driver carrying its own copy would hand out VAs that
 * overlap another driver's mappings.
 *
 * MMIO note: the virtio BARs live outside the Limine memmap, so their frames
 * are mapped explicitly into a dedicated kernel VA window. This happens
 * during Io initialization, BEFORE MiFreezeKernelPml4 (kernel/init/main.c
 * order), so the window may claim a fresh PML4 slot.
 */
#include "drivers/virtio/virtio.h"
#include "drivers/pci.h"
#include "arch/x86_64/lapic.h" /* KI_MSI_MESSAGE_* (SDM Vol. 3A §11.11) */
#include "arch/x86_64/mmu.h"
#include "kernel/mm/phys.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/string.h"

/* Kernel VA window the BAR structures are mapped into (fresh PML4 slot; see
 * the MMIO note above). One cursor for the whole tree. */
#define VIO_MMIO_WINDOW_BASE 0xFFFFA10000000000ULL
static uint64_t VioMmioWindowCursor = VIO_MMIO_WINDOW_BASE;

/* Map a BAR-relative MMIO region and return its kernel VA. */
static void *VioMapMmio(uint64_t physical, uint64_t length)
{
    uint64_t first = physical & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t last = (physical + length + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t base = VioMmioWindowCursor;
    for (uint64_t page = first; page < last; page += PAGE_SIZE)
    {
        /* MiMapDevicePage, not MiMapPage: these are device registers, and a
         * write-back cacheable mapping means the CPU may satisfy a read from
         * cache and hold a write in a store buffer -- `volatile` constrains
         * the compiler, not the cache (docs/review-2026-07 §8). This worked
         * only because firmware happens to leave the PCI hole UC in the
         * MTRRs, which nothing here establishes or checks. arch/x86_64/mmu.c
         * has the mapping for exactly this; lapic.c already uses it. */
        MiMapDevicePage(VioMmioWindowCursor, page);
        VioMmioWindowCursor += PAGE_SIZE;
    }
    return (void *)(uintptr_t)(base + (physical - first));
}

/* Resolve one virtio capability (virtio 1.2 cs01 §4.1.4) to a mapped VA.
 * Returns 0 when the capability type is absent. */
static void *VioFindCapability(const KI_PCI_FUNCTION *f, uint8_t wantedType,
                               uint32_t *notifyMultiplierOut, uint32_t *lengthOut)
{
    /* The walk itself is KiPciFindCapability (drivers/pci.c) — the tree's
     * one walker (Art. 11); this layer keeps only the virtio-specific
     * cfg_type/BAR/length interpretation. The outer loop stays bounded:
     * the walker bounds each resume, but a hostile 64-cycle of MATCHING
     * vendor caps whose cfg_type never fits would otherwise spin here
     * forever (docs/review-2026-07 §4). */
    uint8_t offset = 0;
    for (unsigned link = 0; link < 64; link++)
    {
        offset = KiPciFindCapability(f, PCI_CAP_ID_VENDOR, offset);
        if (offset == 0)
        {
            return 0;
        }
        if (KiPciReadConfig8(f, (uint8_t)(offset + VIRTIO_PCI_CAP_OFF_CFG_TYPE)) == wantedType)
        {
            uint8_t bar = KiPciReadConfig8(f, (uint8_t)(offset + VIRTIO_PCI_CAP_OFF_BAR));
            uint32_t barOffset =
                KiPciReadConfig32(f, (uint8_t)(offset + VIRTIO_PCI_CAP_OFF_OFFSET));
            uint32_t length = KiPciReadConfig32(f, (uint8_t)(offset + VIRTIO_PCI_CAP_OFF_LENGTH));
            /* The BAR index is device-supplied too. A PCI type-0 header has
             * six BARs (PCI 3.0 §6.1), so anything else would read config
             * registers that are not BARs at all and map whatever they
             * happen to hold. */
            if (bar >= 6)
            {
                return 0;
            }
            uint64_t barBase = KiPciReadMemoryBar(f, bar);
            if (barBase == 0)
            {
                return 0; /* I/O BAR: the legacy interface; we require modern */
            }
            if (length == 0 || barOffset + (uint64_t)length < barOffset)
            {
                return 0; /* an empty or wrapping window describes nothing */
            }
            if (notifyMultiplierOut != 0)
            {
                *notifyMultiplierOut =
                    KiPciReadConfig32(f, (uint8_t)(offset + VIRTIO_PCI_NOTIFY_CAP_OFF_MULTIPLIER));
            }
            if (lengthOut != 0)
            {
                *lengthOut = length;
            }
            return VioMapMmio(barBase + barOffset, length);
        }
    }
    return 0;
}

BOOLEAN VioPciSetupModernDevice(uint8_t deviceType, uint16_t transitionalId, const char *name,
                                unsigned instance, VIO_PCI_DEVICE *out)
{
    memset(out, 0, sizeof(*out));
    out->name = name;

    /* §4.1.2: vendor 0x1AF4; a device is either its transitional legacy id
     * (§4.1.2.1) or the modern 0x1040 + type. Transitional first, which is
     * what QEMU presents by default for the types that have one. */
    KI_PCI_FUNCTION found = {0};
    int haveDevice = 0;
    if (transitionalId != 0)
    {
        haveDevice =
            KiPciFindDevice(VIRTIO_PCI_VENDOR, transitionalId, transitionalId, instance, &found);
    }
    if (!haveDevice)
    {
        uint16_t modernId = (uint16_t)(VIRTIO_PCI_DEVICE_ID_MODERN_BASE + deviceType);
        haveDevice = KiPciFindDevice(VIRTIO_PCI_VENDOR, modernId, modernId, instance, &found);
    }
    if (!haveDevice)
    {
        DbgPrint("%s: no PCI function found\n", name);
        return FALSE;
    }
    out->function = found;

    /* Enable MMIO decoding + bus mastering (PCI 3.0 §6.2.2 Table 6-1). */
    uint16_t command = KiPciReadConfig16(&out->function, PCI_CONFIG_COMMAND);
    KiPciWriteConfig16(&out->function, PCI_CONFIG_COMMAND,
                       command | PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER);

    out->commonCfg = VioFindCapability(&out->function, VIRTIO_PCI_CAP_COMMON_CFG, 0, 0);
    out->notifyBase = VioFindCapability(&out->function, VIRTIO_PCI_CAP_NOTIFY_CFG,
                                        &out->notifyMultiplier, &out->notifyLength);
    out->deviceCfg = VioFindCapability(&out->function, VIRTIO_PCI_CAP_DEVICE_CFG, 0, 0);
    if (out->commonCfg == 0 || out->notifyBase == 0 || out->deviceCfg == 0)
    {
        DbgPrint("%s: modern capabilities missing\n", name);
        return FALSE;
    }

    /* §3.1.1 initialization sequence. Step 1: reset — write 0, wait for the
     * readback of 0 (§4.1.4.3.2). */
    out->commonCfg->deviceStatus = 0;
    while (out->commonCfg->deviceStatus != 0)
    {
    }
    /* Steps 2-3: ACKNOWLEDGE, DRIVER. */
    out->commonCfg->deviceStatus = VIRTIO_STATUS_ACKNOWLEDGE;
    out->commonCfg->deviceStatus |= VIRTIO_STATUS_DRIVER;

    /* Step 4 (read half): the device must offer VERSION_1 (§6.1 requires
     * accepting it when offered; a device that does not offer it is legacy,
     * which this transport does not drive). */
    out->commonCfg->deviceFeatureSelect = 1; /* bits 32..63 (§4.1.4.3) */
    uint32_t featuresHigh = out->commonCfg->deviceFeature;
    if ((featuresHigh & (1u << (VIRTIO_F_VERSION_1 - 32))) == 0)
    {
        DbgPrint("%s: device does not offer VERSION_1\n", name);
        VioPciSetFailed(out);
        return FALSE;
    }
    out->commonCfg->deviceFeatureSelect = 0;
    out->deviceFeaturesLow = out->commonCfg->deviceFeature;
    return TRUE;
}

BOOLEAN VioPciAcceptFeatures(VIO_PCI_DEVICE *device, uint32_t acceptedLowBits)
{
    /* Step 4 (write half): accept VERSION_1 plus the caller's low bits and
     * nothing else. Every unnamed device-specific feature — blk's
     * RO/FLUSH/topology, input's unused bits, net's offload family — is
     * left unnegotiated on its own Art. 3 grounds (no consumer convicts
     * one; MSI-X is a PCI capability, not a feature bit, and docs/19 §11c
     * keeps EVENT_IDX deliberately off). Masked against the offer: a
     * driver must not accept a feature the device did not offer (§3.1.1
     * step 4), and the caller checks the offer itself before asking. */
    device->commonCfg->driverFeatureSelect = 0;
    device->commonCfg->driverFeature = acceptedLowBits & device->deviceFeaturesLow;
    device->commonCfg->driverFeatureSelect = 1;
    device->commonCfg->driverFeature = 1u << (VIRTIO_F_VERSION_1 - 32);

    /* Steps 5-6: FEATURES_OK, re-read to confirm. */
    device->commonCfg->deviceStatus |= VIRTIO_STATUS_FEATURES_OK;
    if ((device->commonCfg->deviceStatus & VIRTIO_STATUS_FEATURES_OK) == 0)
    {
        DbgPrint("%s: FEATURES_OK rejected\n", device->name);
        VioPciSetFailed(device);
        return FALSE;
    }
    return TRUE;
}

BOOLEAN VioPciSetupQueue(VIO_PCI_DEVICE *device, VIO_VIRTQUEUE *queue, uint16_t queueIndex)
{
    device->commonCfg->queueSelect = queueIndex;
    uint16_t queueSize = device->commonCfg->queueSize;
    if (!VioInitializeVirtqueue(queue, queueIndex, queueSize))
    {
        DbgPrint("%s: queue %u unavailable\n", device->name, queueIndex);
        VioPciSetFailed(device);
        return FALSE;
    }
    if (queue->queueSize != queueSize)
    {
        device->commonCfg->queueSize = queue->queueSize; /* shrink: §4.1.4.3.2 allows */
    }
    device->commonCfg->queueDesc = queue->descPhysical;
    device->commonCfg->queueDriver = queue->availPhysical;
    device->commonCfg->queueDevice = queue->usedPhysical;
    /* Notify address = base + queue_notify_off * multiplier (§4.1.4.4).
     * Both factors are device-supplied, so the product is bounded against
     * the notify window the capability actually described -- unbounded, a
     * hostile device steered the driver's doorbell writes into another
     * device's register window (docs/review-2026-07 §4). */
    uint64_t notifyOffset = (uint64_t)device->commonCfg->queueNotifyOff * device->notifyMultiplier;
    if (notifyOffset + sizeof(uint16_t) > device->notifyLength)
    {
        DbgPrint("%s: queue %u notify offset %#lx outside the %#lx-byte notify window\n",
                 device->name, queueIndex, (unsigned long)notifyOffset,
                 (unsigned long)device->notifyLength);
        VioPciSetFailed(device);
        return FALSE;
    }
    queue->notify = (volatile uint16_t *)(device->notifyBase + notifyOffset);
    device->commonCfg->queueEnable = 1;
    return TRUE;
}

BOOLEAN VioPciSetupMsix(VIO_PCI_DEVICE *device, uint16_t msixEntry, uint8_t vector)
{
    const KI_PCI_FUNCTION *f = &device->function;
    uint8_t cap = KiPciFindCapability(f, PCI_CAP_ID_MSIX, 0);
    if (cap == 0)
    {
        DbgPrint("%s: no MSI-X capability\n", device->name);
        VioPciSetFailed(device);
        return FALSE;
    }
    uint16_t control = KiPciReadConfig16(f, (uint8_t)(cap + PCI_MSIX_CAP_OFF_MESSAGE_CONTROL));
    uint16_t tableSize = (uint16_t)((control & PCI_MSIX_CONTROL_TABLE_SIZE_MASK) + 1);
    /* Table location (PCI 3.0 §6.8.2): BIR in bits 2:0, offset above. The
     * BIR is device-supplied — same bound as VioFindCapability's BAR check. */
    uint32_t table = KiPciReadConfig32(f, (uint8_t)(cap + PCI_MSIX_CAP_OFF_TABLE));
    uint8_t bir = (uint8_t)(table & PCI_MSIX_TABLE_BIR_MASK);
    uint32_t tableOffset = table & ~(uint32_t)PCI_MSIX_TABLE_BIR_MASK;
    uint64_t barBase = bir < 6 ? KiPciReadMemoryBar(f, bir) : 0;
    if (msixEntry >= tableSize || barBase == 0)
    {
        DbgPrint("%s: MSI-X table unusable (entry %u of %u, BIR %u)\n", device->name, msixEntry,
                 tableSize, bir);
        VioPciSetFailed(device);
        return FALSE;
    }
    device->msixTable = VioMapMmio(barBase + tableOffset, (uint64_t)tableSize * 16);

    /* Program under mask (PCI 3.0 §6.8.3.5): Enable + Function Mask first,
     * so no entry can fire half-written; entries also reset per-entry
     * masked (§6.8.2, QEMU msix_mask_all). Only Enable and Function Mask
     * are config-writable (QEMU hw/pci/msix.c wmask), so the 16-bit RMW
     * cannot disturb the neighbouring read-only bytes. */
    KiPciWriteConfig16(
        f, (uint8_t)(cap + PCI_MSIX_CAP_OFF_MESSAGE_CONTROL),
        (uint16_t)(control | PCI_MSIX_CONTROL_ENABLE | PCI_MSIX_CONTROL_FUNCTION_MASK));
    volatile KI_MSIX_TABLE_ENTRY *entry = &device->msixTable[msixEntry];
    entry->addressLow = KI_MSI_MESSAGE_ADDRESS; /* SDM Vol. 3A §11.11.1 */
    entry->addressHigh = 0;
    entry->data = KI_MSI_MESSAGE_DATA(vector); /* SDM Vol. 3A §11.11.2 */
    entry->vectorControl = 0;                  /* unmask LAST: address/data are now valid */
    KiPciWriteConfig16(
        f, (uint8_t)(cap + PCI_MSIX_CAP_OFF_MESSAGE_CONTROL),
        (uint16_t)((control | PCI_MSIX_CONTROL_ENABLE) & ~PCI_MSIX_CONTROL_FUNCTION_MASK));

    /* Nothing consumes config-change interrupts (§4.1.4.3 config_msix_vector). */
    device->commonCfg->configMsixVector = VIRTIO_MSI_NO_VECTOR;
    return TRUE;
}

BOOLEAN VioPciSetQueueVector(VIO_PCI_DEVICE *device, uint16_t queueIndex, uint16_t msixEntry)
{
    /* queue_msix_vector applies to the selected queue (§4.1.4.3); the
     * device answers NO_VECTOR when it cannot seat the mapping
     * (§4.1.4.3.2), and a driver that skips the readback ships §11d.4's
     * masked regression — completions routed to INTx no one can see. */
    device->commonCfg->queueSelect = queueIndex;
    device->commonCfg->queueMsixVector = msixEntry;
    if (device->commonCfg->queueMsixVector != msixEntry)
    {
        DbgPrint("%s: queue %u refused MSI-X entry %u\n", device->name, queueIndex, msixEntry);
        VioPciSetFailed(device);
        return FALSE;
    }
    return TRUE;
}

void VioPciSetDriverOk(VIO_PCI_DEVICE *device)
{
    device->commonCfg->deviceStatus |= VIRTIO_STATUS_DRIVER_OK;
}

void VioPciSetFailed(VIO_PCI_DEVICE *device)
{
    device->commonCfg->deviceStatus |= VIRTIO_STATUS_FAILED;
}
