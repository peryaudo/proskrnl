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
#include "kernel/ob/ob.h" /* KPROCESSOR_MODE enum for the await park */
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

/* Depth statistics (docs/19 §8.4: the win must be a verdict, not an
 * inference — an implementation that never overlaps passes every semantic
 * test). Sampled at submit, after the increment. */
static ULONG VioBlkDepthMax;
static uint64_t VioBlkDepthSampleSum;
static uint64_t VioBlkDepthSamples;

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

/* --- submit / await / drain ------------------------------------------------- */

/* Harvest every completion the device has published and complete the owning
 * requests: result store, completed flag, event — nothing else. No
 * allocation, no user memory (docs/20 R2; IoDrainDeviceCompletions arms the
 * assert). Called with the dispatcher lock held everywhere — the tick holds
 * it implicitly, idle runs interrupts-off, thread-context waiters acquire
 * it — so a completion cannot interleave with a submit's bookkeeping. The
 * KeSetEvent wake is the same edge the tick's timer expiry already drives
 * (KiWaitTest readies, never switches). */
void VioBlkDrain(void)
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
        KeSetEvent(&request->done, 0, FALSE);
    }
}

ULONG VioBlkInFlightCount(void)
{
    return VioBlkInFlight;
}

void VioBlkQueryDepthStats(ULONG *maxDepthOut, ULONG *meanDepthTimes100Out)
{
    *maxDepthOut = VioBlkDepthMax;
    *meanDepthTimes100Out =
        VioBlkDepthSamples != 0 ? (ULONG)(VioBlkDepthSampleSum * 100 / VioBlkDepthSamples) : 0;
}

void VioBlkResetDepthStats(void)
{
    VioBlkDepthMax = 0;
    VioBlkDepthSampleSum = 0;
    VioBlkDepthSamples = 0;
}

static NTSTATUS VioBlkSubmitPrepared(VIO_BLK_REQUEST *request)
{
    ASSERT(VioBlkPresent);
    ASSERT(request->sectorCount != 0);
    /* Widen before multiplying: sectorCount is uint32_t, so a 32-bit product
     * would wrap (0x800000 sectors passed the old bound). One page per
     * request is the transfer unit (docs/19 §5a: page granularity). */
    ASSERT((uint64_t)request->sectorCount * VIO_BLK_SECTOR_SIZE <= PAGE_SIZE);
    /* The deliberate-wrap capacity check (sectorLba == ~0 wraps past it and
     * reaches the device's own range check — the pinned IOERR path,
     * tests/kmt/m6_blk.c). A refusal leaves nothing in flight. */
    if (request->sectorLba + request->sectorCount > VioBlkCapacitySectors)
    {
        return STATUS_IO_DEVICE_ERROR;
    }

    request->completed = FALSE;
    request->result = STATUS_PENDING;
    KeInitializeEvent(&request->done, NotificationEvent, FALSE);

    /* Claim-fill-submit-register is ONE lock hold (docs/20 F2): the tick
     * drain must not observe a submitted chain whose cookie is not yet in
     * the map, and the free lists it splices are the ones VioSubmitChain
     * consumes. The exhausted-retry drains inline under the same hold —
     * progress comes from the device, not from another thread. */
    uint64_t flags = KiAcquireDispatcherLock();

    /* The submit-side retry loops are bounded like VioBlkAwait's poll: a
     * wedged device that never completes anything would otherwise freeze
     * the machine SILENTLY in an interrupts-off spin — the await's 10 s
     * panic exists precisely so a dead disk is loud. Same order of
     * magnitude as the await's 1e9-pause bound. */
    uint8_t slotIndex;
    for (uint64_t spins = 0;; spins++)
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
        if (spins >= 1000000000ULL)
        {
            KiPanic("virtio-blk: submit stalled (no control slot freed)");
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
    for (uint64_t spins = 0; !VioSubmitChain(&VioBlkQueue, segments, 3, &head); spins++)
    {
        if (spins >= 1000000000ULL)
        {
            KiPanic("virtio-blk: submit stalled (ring full)");
        }
        VioBlkDrain(); /* ring full: harvest and retry */
        __asm__ volatile("pause");
    }
    request->descHead = head;
    request->controlSlot = slotIndex;
    ASSERT(VioBlkRequestByHead[head] == 0);
    VioBlkRequestByHead[head] = request;
    VioBlkSlotRequest[slotIndex] = request;
    VioBlkInFlight++;
    if (VioBlkInFlight > VioBlkDepthMax)
    {
        VioBlkDepthMax = VioBlkInFlight;
    }
    VioBlkDepthSampleSum += VioBlkInFlight;
    VioBlkDepthSamples++;

    KiReleaseDispatcherLock(flags);
    return STATUS_SUCCESS;
}

/* Pre-park drain-spin bound (default VIO_BLK_AWAIT_SPINS, blk.h). An
 * internal latency choice, not a spec value: QEMU typically serves a
 * host-page-cache transfer within microseconds of the notify MMIO exit, so
 * a bounded spin completes the common request without paying the park's
 * context-switch round trip — the difference between wineboot's thousands
 * of single-sector hive writes costing microseconds each and costing a
 * scheduler round trip each. A transfer that outlives the spin parks
 * below, which is the CUI-8 property: the machine's stall is bounded by
 * this spin, never by the device. The kmt suite zeroes the bound to make
 * the park itself a deterministic state (blk.h). */
static ULONG VioBlkAwaitSpinBound = VIO_BLK_AWAIT_SPINS;

ULONG VioBlkSetAwaitSpinBound(ULONG spins)
{
    ULONG previous = VioBlkAwaitSpinBound;
    VioBlkAwaitSpinBound = spins;
    return previous;
}

NTSTATUS VioBlkAwait(VIO_BLK_REQUEST *request)
{
    for (ULONG spins = 0; spins < VioBlkAwaitSpinBound && !request->completed; spins++)
    {
        uint64_t flags = KiAcquireDispatcherLock();
        VioBlkDrain();
        KiReleaseDispatcherLock(flags);
        __asm__ volatile("pause");
    }

    /* The park (docs/19 §5c): the issuer blocks and other threads run while
     * the device works; the tick/idle drain sets the event. The 10 s bound
     * keeps a wedged device as loud as the old spin's panic. */
    if (!request->completed)
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -100000000LL; /* 10 s, relative */
        NTSTATUS wait =
            KeWaitForSingleObject(&request->done, Executive, KernelMode, FALSE, &timeout);
        if (wait == STATUS_TIMEOUT && !request->completed)
        {
            KiPanic("virtio-blk: request timed out");
        }
        /* STATUS_THREAD_IS_TERMINATING: a dying thread cannot park (CUI-4),
         * but its frame still owns the request until the device is done with
         * it (docs/20 R4) — poll it home below. Progress needs no other
         * thread: the device completes on its own and this loop harvests. */
    }
    for (uint64_t spins = 0; !request->completed; spins++)
    {
        if (spins >= 1000000000ULL)
        {
            KiPanic("virtio-blk: request timed out");
        }
        uint64_t flags = KiAcquireDispatcherLock();
        VioBlkDrain();
        KiReleaseDispatcherLock(flags);
        __asm__ volatile("pause");
    }
    return request->result;
}

static NTSTATUS VioBlkSubmitTyped(VIO_BLK_REQUEST *request, uint32_t type, uint64_t sectorLba,
                                  uint32_t sectorCount, uint64_t dataPhysical)
{
    request->type = type;
    request->sectorLba = sectorLba;
    request->sectorCount = sectorCount;
    request->dataPhysical = dataPhysical;
    return VioBlkSubmitPrepared(request);
}

NTSTATUS VioBlkSubmitRead(VIO_BLK_REQUEST *request, uint64_t sectorLba, uint32_t sectorCount,
                          uint64_t physical)
{
    return VioBlkSubmitTyped(request, VIO_BLK_T_IN, sectorLba, sectorCount, physical);
}

NTSTATUS VioBlkSubmitWrite(VIO_BLK_REQUEST *request, uint64_t sectorLba, uint32_t sectorCount,
                           uint64_t physical)
{
    return VioBlkSubmitTyped(request, VIO_BLK_T_OUT, sectorLba, sectorCount, physical);
}

/* Submit and await — the synchronous shape the sector API keeps. */
static NTSTATUS VioBlkSyncTransfer(uint32_t type, uint64_t sectorLba, uint32_t sectorCount,
                                   uint64_t dataPhysical)
{
    VIO_BLK_REQUEST request;
    NTSTATUS status = VioBlkSubmitTyped(&request, type, sectorLba, sectorCount, dataPhysical);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    return VioBlkAwait(&request);
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
