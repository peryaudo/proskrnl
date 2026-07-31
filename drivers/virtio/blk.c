/* drivers/virtio/blk.c — virtio-blk over the modern virtio-pci transport
 * (see blk.h, virtio.h).
 *
 * Written from the OASIS virtio 1.2 cs01 specification (sections cited
 * inline) against the pinned third_party/qemu device model. Polling, no
 * MSI-X, one request queue, one in-flight request — so a transfer completes
 * before the submitting thread returns. The depth of 1 is structural here
 * (one global control header, one bounce buffer) and is the first thing
 * docs/19 §5a retires.
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

static BOOLEAN VioBlkPresent;
static VIO_PCI_DEVICE VioBlkDevice;
static VIO_VIRTQUEUE VioBlkQueue;
static uint64_t VioBlkCapacitySectors;

/* One-page bounce buffers: request payloads may live in physically
 * discontiguous pool/cache memory, so DMA goes through these. */
static uint64_t VioBlkDataBouncePhysical;
static char *VioBlkDataBounce;
static uint64_t VioBlkControlPhysical; /* header + status share one frame */
static VIO_BLK_REQUEST_HEADER *VioBlkHeader;
static volatile uint8_t *VioBlkStatus;

BOOLEAN VioBlkInitialize(void)
{
    /* §3.1.1 steps 1-4: blk is transitional 0x1001 or modern 0x1040+2
     * (§4.1.2.1, §5.2.1). */
    if (!VioPciSetupModernDevice(VIRTIO_DEVICE_TYPE_BLK, VIRTIO_PCI_DEVICE_ID_BLK_TRANSITIONAL,
                                 "virtio-blk", 0, &VioBlkDevice))
    {
        return FALSE;
    }
    /* A read-only device cannot back a writable FAT32 volume; refuse it
     * rather than discovering it one failed write at a time (§5.2.3). */
    if (VioBlkDevice.deviceFeaturesLow & (1u << VIO_BLK_F_RO))
    {
        DbgPrint("virtio-blk: device is read-only\n");
        VioPciSetFailed(&VioBlkDevice);
        return FALSE;
    }
    if (!VioPciAcceptFeatures(&VioBlkDevice))
    {
        return FALSE;
    }

    /* Step 7: virtqueue 0, the request queue ("0 requestq1", §5.2.2). */
    if (!VioPciSetupQueue(&VioBlkDevice, &VioBlkQueue, 0))
    {
        return FALSE;
    }

    /* DMA buffers before going live. */
    VioBlkDataBouncePhysical = MiAllocatePage();
    VioBlkControlPhysical = MiAllocatePage();
    if (VioBlkDataBouncePhysical == 0 || VioBlkControlPhysical == 0)
    {
        VioPciSetFailed(&VioBlkDevice);
        return FALSE;
    }
    VioBlkDataBounce = MiPhysicalToVirtual(VioBlkDataBouncePhysical);
    VioBlkHeader = MiPhysicalToVirtual(VioBlkControlPhysical);
    VioBlkStatus = (volatile uint8_t *)VioBlkHeader + sizeof(VIO_BLK_REQUEST_HEADER);

    /* Step 8: DRIVER_OK — the device is live. */
    VioPciSetDriverOk(&VioBlkDevice);

    /* Capacity: le64 sector count at device-config offset 0 (§5.2.4), read
     * as two 32-bit halves (§4.1.3.1). */
    uint32_t capacityLow = *(volatile uint32_t *)(VioBlkDevice.deviceCfg + 0);
    uint32_t capacityHigh = *(volatile uint32_t *)(VioBlkDevice.deviceCfg + 4);
    VioBlkCapacitySectors = ((uint64_t)capacityHigh << 32) | capacityLow;

    VioBlkPresent = TRUE;
    DbgPrint("virtio-blk: %02x:%x id %04x, %lu sectors, queue %u\n", VioBlkDevice.function.device,
             VioBlkDevice.function.function, VioBlkDevice.function.deviceId,
             (unsigned long)VioBlkCapacitySectors, VioBlkQueue.queueSize);
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
    /* Widen before multiplying: sectorCount is uint32_t, so the product was
     * computed in 32 bits and sectorCount == 0x800000 wrapped to 0 -- the
     * bound passed for a transfer eight million sectors long. Latent (every
     * caller chunks at 8 sectors) but the assert is the only bound the
     * bounce buffer has. */
    ASSERT((uint64_t)sectorCount * VIO_BLK_SECTOR_SIZE <= PAGE_SIZE);
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
