/* drivers/virtio/blk.c — virtio-blk over the modern virtio-pci transport
 * (see blk.h, virtio.h).
 *
 * Written from the OASIS virtio 1.2 cs01 specification (sections cited
 * inline) against the pinned third_party/qemu device model. Polling, no
 * MSI-X, one request queue, one in-flight request — synchronous under the
 * hood exactly like the rest of the kernel (Art. 3).
 *
 * MMIO note: the virtio BARs live outside the Limine memmap, so their
 * frames are mapped explicitly into a dedicated kernel VA window. This
 * happens during Io initialization, BEFORE MiFreezeKernelPml4 (kernel/init/
 * main.c order), so the window may claim a fresh PML4 slot.
 */
#include "drivers/virtio/blk.h"
#include "drivers/virtio/virtio.h"
#include "drivers/pci.h"
#include "arch/x86_64/mmu.h"
#include "kernel/mm/phys.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "abi/ntstatus.h"

/* --- virtio-blk protocol (virtio 1.2 cs01 §5.2) ---------------------------- */

/* Request header (§5.2.6): le32 type, le32 reserved, le64 sector. */
typedef struct
{
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
} VIO_BLK_REQUEST_HEADER;
_Static_assert(sizeof(VIO_BLK_REQUEST_HEADER) == 16, "blk request header (§5.2.6)");

#define VIO_BLK_T_IN    0 /* §5.2.6: read */
#define VIO_BLK_T_OUT   1 /* §5.2.6: write */
#define VIO_BLK_S_OK    0 /* §5.2.6 status byte */
#define VIO_BLK_S_IOERR 1

#define VIO_BLK_F_RO 5ULL /* §5.2.3: device is read-only */

/* Device configuration (§5.2.4): le64 capacity in 512-byte sectors at 0. */

/* --- driver state ----------------------------------------------------------- */

/* Kernel VA window the BAR structures are mapped into (fresh PML4 slot;
 * see the MMIO note above). */
#define VIO_MMIO_WINDOW_BASE 0xFFFFA10000000000ULL
static uint64_t VioMmioWindowCursor = VIO_MMIO_WINDOW_BASE;

static BOOLEAN VioBlkPresent;
static VIRTIO_PCI_COMMON_CFG *VioBlkCommonCfg;
static volatile uint8_t *VioBlkDeviceCfg;
static VIO_VIRTQUEUE VioBlkQueue;
static uint64_t VioBlkCapacitySectors;

/* One-page bounce buffers: request payloads may live in physically
 * discontiguous pool/cache memory, so DMA goes through these. */
static uint64_t VioBlkDataBouncePhysical;
static char *VioBlkDataBounce;
static uint64_t VioBlkControlPhysical; /* header + status share one frame */
static VIO_BLK_REQUEST_HEADER *VioBlkHeader;
static volatile uint8_t *VioBlkStatus;

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

BOOLEAN VioBlkInitialize(void)
{
    KI_PCI_FUNCTION f;
    /* §4.1.2: vendor 0x1AF4, device 0x1000..0x107F is a virtio function;
     * blk is transitional 0x1001 or modern 0x1040+2 (§4.1.2.1, §5.2.1). */
    KI_PCI_FUNCTION found = {0};
    int haveDevice = 0;
    for (uint16_t id = VIRTIO_PCI_DEVICE_ID_MIN; !haveDevice && id <= VIRTIO_PCI_DEVICE_ID_MAX;
         id++)
    {
        if (id != VIRTIO_PCI_DEVICE_ID_BLK_TRANSITIONAL &&
            id != VIRTIO_PCI_DEVICE_ID_MODERN_BASE + 2)
        {
            continue;
        }
        haveDevice = KiPciFindDevice(VIRTIO_PCI_VENDOR, id, id, &found);
    }
    if (!haveDevice)
    {
        DbgPrint("virtio-blk: no PCI function found\n");
        return FALSE;
    }
    f = found;

    /* Enable MMIO decoding + bus mastering (PCI 3.0 §6.2.2 Table 6-1). */
    uint16_t command = KiPciReadConfig16(&f, PCI_CONFIG_COMMAND);
    KiPciWriteConfig16(&f, PCI_CONFIG_COMMAND,
                       command | PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER);

    uint32_t notifyMultiplier = 0;
    VioBlkCommonCfg = VioFindCapability(&f, VIRTIO_PCI_CAP_COMMON_CFG, 0, 0);
    volatile uint8_t *notifyBase =
        VioFindCapability(&f, VIRTIO_PCI_CAP_NOTIFY_CFG, &notifyMultiplier, 0);
    VioBlkDeviceCfg = VioFindCapability(&f, VIRTIO_PCI_CAP_DEVICE_CFG, 0, 0);
    if (VioBlkCommonCfg == 0 || notifyBase == 0 || VioBlkDeviceCfg == 0)
    {
        DbgPrint("virtio-blk: modern capabilities missing\n");
        return FALSE;
    }

    /* §3.1.1 initialization sequence. Step 1: reset — write 0, wait for the
     * readback of 0 (§4.1.4.3.2). */
    VioBlkCommonCfg->deviceStatus = 0;
    while (VioBlkCommonCfg->deviceStatus != 0)
    {
    }
    /* Steps 2-3: ACKNOWLEDGE, DRIVER. */
    VioBlkCommonCfg->deviceStatus = VIRTIO_STATUS_ACKNOWLEDGE;
    VioBlkCommonCfg->deviceStatus |= VIRTIO_STATUS_DRIVER;

    /* Step 4: features. Accept only VIRTIO_F_VERSION_1 (§6.1 requires
     * accepting it when offered; everything else — RO, FLUSH, topology — is
     * unneeded for a polling writeback driver). */
    VioBlkCommonCfg->deviceFeatureSelect = 1; /* bits 32..63 (§4.1.4.3) */
    uint32_t featuresHigh = VioBlkCommonCfg->deviceFeature;
    if ((featuresHigh & (1u << (VIRTIO_F_VERSION_1 - 32))) == 0)
    {
        DbgPrint("virtio-blk: device does not offer VERSION_1\n");
        VioBlkCommonCfg->deviceStatus |= VIRTIO_STATUS_FAILED;
        return FALSE;
    }
    VioBlkCommonCfg->deviceFeatureSelect = 0;
    uint32_t featuresLow = VioBlkCommonCfg->deviceFeature;
    if (featuresLow & (1u << VIO_BLK_F_RO))
    {
        DbgPrint("virtio-blk: device is read-only\n");
        VioBlkCommonCfg->deviceStatus |= VIRTIO_STATUS_FAILED;
        return FALSE;
    }
    VioBlkCommonCfg->driverFeatureSelect = 0;
    VioBlkCommonCfg->driverFeature = 0;
    VioBlkCommonCfg->driverFeatureSelect = 1;
    VioBlkCommonCfg->driverFeature = 1u << (VIRTIO_F_VERSION_1 - 32);

    /* Steps 5-6: FEATURES_OK, re-read to confirm. */
    VioBlkCommonCfg->deviceStatus |= VIRTIO_STATUS_FEATURES_OK;
    if ((VioBlkCommonCfg->deviceStatus & VIRTIO_STATUS_FEATURES_OK) == 0)
    {
        DbgPrint("virtio-blk: FEATURES_OK rejected\n");
        VioBlkCommonCfg->deviceStatus |= VIRTIO_STATUS_FAILED;
        return FALSE;
    }

    /* Step 7: virtqueue 0, the request queue ("0 requestq1", §5.2.2). */
    VioBlkCommonCfg->queueSelect = 0;
    uint16_t queueSize = VioBlkCommonCfg->queueSize;
    if (!VioInitializeVirtqueue(&VioBlkQueue, 0, queueSize))
    {
        VioBlkCommonCfg->deviceStatus |= VIRTIO_STATUS_FAILED;
        return FALSE;
    }
    if (VioBlkQueue.queueSize != queueSize)
    {
        VioBlkCommonCfg->queueSize = VioBlkQueue.queueSize; /* shrink: §4.1.4.3.2 allows */
    }
    VioBlkCommonCfg->queueDesc = VioBlkQueue.descPhysical;
    VioBlkCommonCfg->queueDriver = VioBlkQueue.availPhysical;
    VioBlkCommonCfg->queueDevice = VioBlkQueue.usedPhysical;
    /* Notify address = base + queue_notify_off * multiplier (§4.1.4.4). */
    VioBlkQueue.notify =
        (volatile uint16_t *)(notifyBase +
                              (uint64_t)VioBlkCommonCfg->queueNotifyOff * notifyMultiplier);
    VioBlkCommonCfg->queueEnable = 1;

    /* DMA buffers before going live. */
    VioBlkDataBouncePhysical = MiAllocatePage();
    VioBlkControlPhysical = MiAllocatePage();
    if (VioBlkDataBouncePhysical == 0 || VioBlkControlPhysical == 0)
    {
        VioBlkCommonCfg->deviceStatus |= VIRTIO_STATUS_FAILED;
        return FALSE;
    }
    VioBlkDataBounce = MiPhysicalToVirtual(VioBlkDataBouncePhysical);
    VioBlkHeader = MiPhysicalToVirtual(VioBlkControlPhysical);
    VioBlkStatus = (volatile uint8_t *)VioBlkHeader + sizeof(VIO_BLK_REQUEST_HEADER);

    /* Step 8: DRIVER_OK — the device is live. */
    VioBlkCommonCfg->deviceStatus |= VIRTIO_STATUS_DRIVER_OK;

    /* Capacity: le64 sector count at device-config offset 0 (§5.2.4), read
     * as two 32-bit halves (§4.1.3.1). */
    uint32_t capacityLow = *(volatile uint32_t *)(VioBlkDeviceCfg + 0);
    uint32_t capacityHigh = *(volatile uint32_t *)(VioBlkDeviceCfg + 4);
    VioBlkCapacitySectors = ((uint64_t)capacityHigh << 32) | capacityLow;

    VioBlkPresent = TRUE;
    DbgPrint("virtio-blk: %02x:%x id %04x, %lu sectors, queue %u\n", f.device, f.function,
             f.deviceId, (unsigned long)VioBlkCapacitySectors, VioBlkQueue.queueSize);
    return TRUE;
}

BOOLEAN VioBlkIsPresent(void)
{
    return VioBlkPresent;
}

uint64_t VioBlkSectorCount(void)
{
    return VioBlkCapacitySectors;
}

/* One bounced transfer of at most a page (8 sectors). */
static NTSTATUS VioBlkTransfer(uint32_t type, uint64_t sectorLba, uint32_t sectorCount,
                               void *buffer)
{
    ASSERT(VioBlkPresent);
    ASSERT(sectorCount * VIO_BLK_SECTOR_SIZE <= PAGE_SIZE);
    if (sectorLba + sectorCount > VioBlkCapacitySectors)
    {
        return STATUS_IO_DEVICE_ERROR;
    }

    VioBlkHeader->type = type;
    VioBlkHeader->reserved = 0;
    VioBlkHeader->sector = sectorLba;
    *VioBlkStatus = 0xFF;
    if (type == VIO_BLK_T_OUT)
    {
        memcpy(VioBlkDataBounce, buffer, (uint64_t)sectorCount * VIO_BLK_SECTOR_SIZE);
    }

    /* Classic 3-descriptor chain: device-readable header, data, then the
     * device-writable status byte last (§5.2.6 framing; §2.7.4.2 orders
     * device-writable descriptors after device-readable ones). */
    VIO_SEGMENT segments[3] = {
        {VioBlkControlPhysical, sizeof(VIO_BLK_REQUEST_HEADER), 0},
        {VioBlkDataBouncePhysical, sectorCount * VIO_BLK_SECTOR_SIZE, type == VIO_BLK_T_IN},
        {VioBlkControlPhysical + sizeof(VIO_BLK_REQUEST_HEADER), 1, 1},
    };
    if (!VioSubmitAndPoll(&VioBlkQueue, segments, 3))
    {
        KiPanic("virtio-blk: request timed out");
    }
    if (*VioBlkStatus != VIO_BLK_S_OK)
    {
        return STATUS_IO_DEVICE_ERROR;
    }
    if (type == VIO_BLK_T_IN)
    {
        memcpy(buffer, VioBlkDataBounce, (uint64_t)sectorCount * VIO_BLK_SECTOR_SIZE);
    }
    return STATUS_SUCCESS;
}

NTSTATUS VioBlkReadSectors(uint64_t sectorLba, uint32_t sectorCount, void *buffer)
{
    char *out = buffer;
    while (sectorCount != 0)
    {
        uint32_t chunk = sectorCount < 8 ? sectorCount : 8;
        NTSTATUS status = VioBlkTransfer(VIO_BLK_T_IN, sectorLba, chunk, out);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        sectorLba += chunk;
        sectorCount -= chunk;
        out += (uint64_t)chunk * VIO_BLK_SECTOR_SIZE;
    }
    return STATUS_SUCCESS;
}

NTSTATUS VioBlkWriteSectors(uint64_t sectorLba, uint32_t sectorCount, const void *buffer)
{
    const char *in = buffer;
    while (sectorCount != 0)
    {
        uint32_t chunk = sectorCount < 8 ? sectorCount : 8;
        NTSTATUS status = VioBlkTransfer(VIO_BLK_T_OUT, sectorLba, chunk, (void *)(uintptr_t)in);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        sectorLba += chunk;
        sectorCount -= chunk;
        in += (uint64_t)chunk * VIO_BLK_SECTOR_SIZE;
    }
    return STATUS_SUCCESS;
}
