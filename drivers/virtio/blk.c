/* drivers/virtio/blk.c — virtio-blk over the modern virtio-pci transport
 * (see blk.h, virtio.h).
 *
 * Written from the OASIS virtio 1.2 cs01 specification (sections cited
 * inline) against the pinned third_party/qemu device model. Polling, no
 * MSI-X, one request queue, up to VIO_BLK_MAX_INFLIGHT requests in flight
 * (CUI-8, docs/19 §5a): each request owns a control slot (header + status)
 * out of one shared frame, and the head-descriptor cookie map routes each
 * used-ring completion back to its request — VioBlkDrain is the single
 * harvest authority (Art. 11), whether called from a thread-context poll
 * or (CUI-8's later drain points) the tick and idle paths.
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

/* Per-request control slot: the §5.2.6 device-readable header and the
 * device-writable status byte, padded so slots never share a descriptor.
 * All VIO_BLK_MAX_INFLIGHT slots live in one DMA frame. */
typedef struct
{
    VIO_BLK_REQUEST_HEADER header;
    volatile uint8_t status;
    uint8_t reserved[15];
} VIO_BLK_CONTROL_SLOT;
_Static_assert(sizeof(VIO_BLK_CONTROL_SLOT) == 32, "control slots pack into one frame");
_Static_assert(VIO_BLK_MAX_INFLIGHT * sizeof(VIO_BLK_CONTROL_SLOT) <= 4096,
               "control slots fit their one DMA frame");

static uint64_t VioBlkControlPhysical;
static VIO_BLK_CONTROL_SLOT *VioBlkControl;                      /* [VIO_BLK_MAX_INFLIGHT] */
static VIO_BLK_REQUEST *VioBlkSlotRequest[VIO_BLK_MAX_INFLIGHT]; /* slot -> owner */

/* head descriptor index -> in-flight request (the §2.7.8 used id is the
 * chain head). Sized for the largest ring VioInitializeVirtqueue allows. */
static VIO_BLK_REQUEST *VioBlkRequestByHead[256];
static ULONG VioBlkInFlight;

/* One-page bounce for the sector-API path (blk.h): those payloads may live
 * in physically discontiguous pool memory. The page-cache data path hands
 * the device its frames directly and never touches this. */
static uint64_t VioBlkDataBouncePhysical;
static char *VioBlkDataBounce;

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
    VioBlkControl = MiPhysicalToVirtual(VioBlkControlPhysical);
    memset(VioBlkControl, 0, PAGE_SIZE);

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

/* --- submit / drain --------------------------------------------------------- */

/* Harvest every completion the device has published and complete the owning
 * requests. THE single harvest authority (Art. 11): every path that waits —
 * the sync poll below today, the tick/idle drain points later — funnels
 * here, so a poller completing ANOTHER request's transfer is routine, not a
 * race. Does nothing but bookkeeping and the completion stores: no
 * allocation, no user memory (docs/20 R2). Caller serializes (thread
 * context today; the dispatcher lock once the drain points exist). */
static void VioBlkDrain(void)
{
    uint16_t head;
    uint32_t length;
    while (VioHarvestUsed(&VioBlkQueue, &head, &length))
    {
        VIO_BLK_REQUEST *request = VioBlkRequestByHead[head];
        ASSERT(request != 0); /* every chain out has exactly one owner */
        VioBlkRequestByHead[head] = 0;
        VIO_BLK_CONTROL_SLOT *slot = &VioBlkControl[request->controlSlot];
        ASSERT(VioBlkSlotRequest[request->controlSlot] == request);
        VioBlkSlotRequest[request->controlSlot] = 0;
        ASSERT(VioBlkInFlight != 0);
        VioBlkInFlight--;
        request->result = slot->status == VIO_BLK_S_OK ? STATUS_SUCCESS : STATUS_IO_DEVICE_ERROR;
        request->completed = TRUE; /* the owner may reuse the request now */
    }
}

/* Submit one prepared request: claim a control slot, chain header/data/
 * status, register the cookie. The whole path is non-blocking; when slots
 * or descriptors are exhausted it spins a drain — with only synchronous
 * callers today the retry never actually loops. NOTE (docs/20 F2): once
 * the tick drain exists, claim-submit-register must be one uninterruptible
 * step (dispatcher lock) so a completion cannot beat the cookie into the
 * map; today only thread context touches any of this. */
static void VioBlkSubmitRequest(VIO_BLK_REQUEST *request)
{
    ASSERT(VioBlkPresent);
    ASSERT(request->sectorCount != 0);
    /* Widen before multiplying: sectorCount is uint32_t, so a 32-bit product
     * would wrap (0x800000 sectors passed the old bound). One page per
     * request is the transfer unit (docs/19 §5a: page granularity). */
    ASSERT((uint64_t)request->sectorCount * VIO_BLK_SECTOR_SIZE <= PAGE_SIZE);

    request->completed = FALSE;
    request->result = STATUS_PENDING;

    /* Claim a control slot. */
    uint8_t slotIndex;
    for (;;)
    {
        for (slotIndex = 0; slotIndex < VIO_BLK_MAX_INFLIGHT; slotIndex++)
        {
            if (VioBlkSlotRequest[slotIndex] == 0)
            {
                break;
            }
        }
        if (slotIndex < VIO_BLK_MAX_INFLIGHT)
        {
            break;
        }
        VioBlkDrain(); /* all slots in flight: harvest and retry */
        __asm__ volatile("pause");
    }
    VIO_BLK_CONTROL_SLOT *slot = &VioBlkControl[slotIndex];
    slot->header.type = request->type;
    slot->header.reserved = 0;
    slot->header.sector = request->sectorLba;
    slot->status = 0xFF; /* sentinel the device must overwrite */

    /* Classic 3-descriptor chain: device-readable header, data, then the
     * device-writable status byte last (§5.2.6 framing; §2.7.4.2 orders
     * device-writable descriptors after device-readable ones). */
    uint64_t slotPhysical = VioBlkControlPhysical + (uint64_t)slotIndex * sizeof(*slot);
    VIO_SEGMENT segments[3] = {
        {slotPhysical, sizeof(VIO_BLK_REQUEST_HEADER), 0},
        {request->dataPhysical, request->sectorCount * VIO_BLK_SECTOR_SIZE,
         request->type == VIO_BLK_T_IN},
        {slotPhysical + offsetof(VIO_BLK_CONTROL_SLOT, status), 1, 1},
    };
    uint16_t head;
    while (!VioSubmitChain(&VioBlkQueue, segments, 3, &head))
    {
        VioBlkDrain(); /* ring full: harvest and retry */
        __asm__ volatile("pause");
    }
    request->descHead = head;
    request->controlSlot = slotIndex;
    ASSERT(VioBlkRequestByHead[head] == 0);
    VioBlkRequestByHead[head] = request;
    VioBlkSlotRequest[slotIndex] = request;
    VioBlkInFlight++;
}

/* Submit and poll to completion — the synchronous shape every caller has
 * today. The poll drains ALL completions, not just this request's, so it
 * coexists with other requests in flight. */
static NTSTATUS VioBlkSyncTransfer(uint32_t type, uint64_t sectorLba, uint32_t sectorCount,
                                   uint64_t dataPhysical)
{
    if (sectorLba + sectorCount > VioBlkCapacitySectors)
    {
        return STATUS_IO_DEVICE_ERROR;
    }
    VIO_BLK_REQUEST request;
    request.type = type;
    request.sectorLba = sectorLba;
    request.sectorCount = sectorCount;
    request.dataPhysical = dataPhysical;
    VioBlkSubmitRequest(&request);
    for (uint64_t spins = 0; spins < 1000000000ULL; spins++)
    {
        VioBlkDrain();
        if (request.completed)
        {
            return request.result;
        }
        __asm__ volatile("pause");
    }
    KiPanic("virtio-blk: request timed out");
}

/* One bounced transfer of at most a page (8 sectors). */
static NTSTATUS VioBlkTransfer(uint32_t type, uint64_t sectorLba, uint32_t sectorCount,
                               void *buffer)
{
    ASSERT((uint64_t)sectorCount * VIO_BLK_SECTOR_SIZE <= PAGE_SIZE);
    if (type == VIO_BLK_T_OUT)
    {
        memcpy(VioBlkDataBounce, buffer, (uint64_t)sectorCount * VIO_BLK_SECTOR_SIZE);
    }
    NTSTATUS status = VioBlkSyncTransfer(type, sectorLba, sectorCount, VioBlkDataBouncePhysical);
    if (NT_SUCCESS(status) && type == VIO_BLK_T_IN)
    {
        memcpy(buffer, VioBlkDataBounce, (uint64_t)sectorCount * VIO_BLK_SECTOR_SIZE);
    }
    return status;
}

NTSTATUS VioBlkReadSectorsPhysical(uint64_t sectorLba, uint32_t sectorCount, uint64_t physical)
{
    return VioBlkSyncTransfer(VIO_BLK_T_IN, sectorLba, sectorCount, physical);
}

NTSTATUS VioBlkWriteSectorsPhysical(uint64_t sectorLba, uint32_t sectorCount, uint64_t physical)
{
    return VioBlkSyncTransfer(VIO_BLK_T_OUT, sectorLba, sectorCount, physical);
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
