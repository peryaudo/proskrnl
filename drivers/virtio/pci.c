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
        MiMapPage(VioMmioWindowCursor, page, 1);
        VioMmioWindowCursor += PAGE_SIZE;
    }
    return (void *)(uintptr_t)(base + (physical - first));
}

/* Resolve one virtio capability (virtio 1.2 cs01 §4.1.4) to a mapped VA.
 * Returns 0 when the capability type is absent. */
static void *VioFindCapability(const KI_PCI_FUNCTION *f, uint8_t wantedType,
                               uint32_t *notifyMultiplierOut, uint32_t *lengthOut)
{
    if ((KiPciReadConfig16(f, PCI_CONFIG_STATUS) & PCI_STATUS_CAPABILITIES_LIST) == 0)
    {
        return 0;
    }
    /* Capabilities pointer: low two bits reserved (PCI 3.0 §6.7). */
    uint8_t offset = KiPciReadConfig8(f, PCI_CONFIG_CAP_POINTER) & 0xFC;
    while (offset != 0)
    {
        uint8_t id = KiPciReadConfig8(f, offset);
        if (id == VIRTIO_PCI_CAP_VNDR_ID &&
            KiPciReadConfig8(f, (uint8_t)(offset + VIRTIO_PCI_CAP_OFF_CFG_TYPE)) == wantedType)
        {
            uint8_t bar = KiPciReadConfig8(f, (uint8_t)(offset + VIRTIO_PCI_CAP_OFF_BAR));
            uint32_t barOffset =
                KiPciReadConfig32(f, (uint8_t)(offset + VIRTIO_PCI_CAP_OFF_OFFSET));
            uint32_t length = KiPciReadConfig32(f, (uint8_t)(offset + VIRTIO_PCI_CAP_OFF_LENGTH));
            uint64_t barBase = KiPciReadMemoryBar(f, bar);
            if (barBase == 0)
            {
                return 0; /* I/O BAR: the legacy interface; we require modern */
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
        offset = KiPciReadConfig8(f, (uint8_t)(offset + 1)) & 0xFC;
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
    out->notifyBase =
        VioFindCapability(&out->function, VIRTIO_PCI_CAP_NOTIFY_CFG, &out->notifyMultiplier, 0);
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

BOOLEAN VioPciAcceptFeatures(VIO_PCI_DEVICE *device)
{
    /* Step 4 (write half): accept VERSION_1 and nothing else. Every
     * device-specific feature — blk's RO/FLUSH/topology, input's unused
     * bits — is left unnegotiated; a polling driver needs none of them. */
    device->commonCfg->driverFeatureSelect = 0;
    device->commonCfg->driverFeature = 0;
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
    /* Notify address = base + queue_notify_off * multiplier (§4.1.4.4). */
    queue->notify =
        (volatile uint16_t *)(device->notifyBase + (uint64_t)device->commonCfg->queueNotifyOff *
                                                       device->notifyMultiplier);
    device->commonCfg->queueEnable = 1;
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
