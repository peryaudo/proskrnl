/* drivers/virtio/snd.c — virtio-snd over the shared modern-PCI transport
 * (virtio 1.2 cs01 §5.14; see snd.h, virtio.h, drivers/sndproto.h).
 *
 * Written from the OASIS virtio 1.2 cs01 specification (sections cited
 * inline) against the pinned third_party/qemu device model (hw/audio/
 * virtio-snd.c; wire structs cross-checked against include/standard-headers/
 * linux/virtio_snd.h). Provenance: public spec only (docs/11).
 *
 * The PCM transport behind \Device\Snd* (drivers/snd.c, HACK-007). AUD-1
 * consumes controlq + txq: control verbs are synchronous round trips (QEMU
 * serves the controlq at the notify), and each written period rides one txq
 * chain out of a per-stream slot set — up to buffer_bytes / period_bytes in
 * flight, writer parked on the slot set running dry (docs/23 §4a). eventq
 * is left unpopulated and rxq unconfigured: nothing consumes jack/xrun
 * events and capture is AUD-3's, said out loud rather than left as a silent
 * gap (Art. 12; the input.c statusq precedent).
 *
 * No MSI-X vector, deliberately (docs/19 §11f; docs/23 §4a): harvest joins
 * IoDrainDeviceCompletions, whose tick-tail call gives a 1 ms guest-clocked
 * completion bound against a 10 ms period — a cadence that convicts
 * nothing. Without MSI-X the function would signal INTx, which this kernel
 * cannot see (no IOAPIC/PIC path by design, docs/19 §11a) — a non-event for
 * a purely polled harvest, exactly virtio-input's situation.
 */
#include "drivers/virtio/snd.h"
#include "drivers/virtio/virtio.h"
#include "drivers/sndproto.h"
#include "kernel/ob/ob.h" /* KPROCESSOR_MODE enum for the parks */
#include "kernel/ke/ke.h"
#include "kernel/mm/phys.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "abi/ntstatus.h"

/* --- virtio-snd protocol (virtio 1.2 cs01 §5.14) --------------------------- */

/* Virtqueue indexes (§5.14.2: "0 controlq, 1 eventq, 2 txq, 3 rxq";
 * cross-check virtio_snd.h VIRTIO_SND_VQ_*). */
#define VIO_SND_VQ_CONTROL 0
#define VIO_SND_VQ_TX      2

/* Device configuration (§5.14.4 struct virtio_snd_config): le32 jacks at 0,
 * streams at 4, chmaps at 8. */
#define VIO_SND_CFG_OFF_STREAMS 4

/* PCM control request codes (§5.14.6.1; cross-check virtio_snd.h
 * VIRTIO_SND_R_PCM_*). NOTE the numbering: RELEASE sits between PREPARE
 * and START — the enum order, not the lifecycle order. */
#define VIO_SND_R_PCM_INFO       0x0100
#define VIO_SND_R_PCM_SET_PARAMS 0x0101
#define VIO_SND_R_PCM_PREPARE    0x0102
#define VIO_SND_R_PCM_RELEASE    0x0103
#define VIO_SND_R_PCM_START      0x0104
#define VIO_SND_R_PCM_STOP       0x0105

/* Common status codes (§5.14.6.1; cross-check virtio_snd.h VIRTIO_SND_S_*). */
#define VIO_SND_S_OK       0x8000
#define VIO_SND_S_BAD_MSG  0x8001
#define VIO_SND_S_NOT_SUPP 0x8002
#define VIO_SND_S_IO_ERR   0x8003

/* Common header (§5.14.6.1): le32 code — a request type out, a status back. */
typedef struct
{
    uint32_t code;
} VIO_SND_HDR;
_Static_assert(sizeof(VIO_SND_HDR) == 4, "virtio_snd_hdr (virtio 1.2 cs01 §5.14.6.1)");

/* Item-information query (§5.14.6.1 struct virtio_snd_query_info). */
typedef struct
{
    VIO_SND_HDR hdr;
    uint32_t startId;
    uint32_t count;
    uint32_t size;
} VIO_SND_QUERY_INFO;
_Static_assert(sizeof(VIO_SND_QUERY_INFO) == 16,
               "virtio_snd_query_info (virtio 1.2 cs01 §5.14.6.1)");

/* Stream-addressed request header (§5.14.6.6 struct virtio_snd_pcm_hdr). */
typedef struct
{
    VIO_SND_HDR hdr;
    uint32_t streamId;
} VIO_SND_PCM_HDR;
_Static_assert(sizeof(VIO_SND_PCM_HDR) == 8, "virtio_snd_pcm_hdr (virtio 1.2 cs01 §5.14.6.6)");

/* Stream parameters (§5.14.6.6.3 struct virtio_snd_pcm_set_params). The
 * payload past the header is byte-identical to sndproto.h's
 * SND_PCM_SET_PARAMS — that struct IS this wire layout minus the header. */
typedef struct
{
    VIO_SND_PCM_HDR hdr;
    SND_PCM_SET_PARAMS params;
} VIO_SND_PCM_SET_PARAMS_REQ;
_Static_assert(sizeof(VIO_SND_PCM_SET_PARAMS_REQ) == 24,
               "virtio_snd_pcm_set_params (virtio 1.2 cs01 §5.14.6.6.3)");

/* I/O request header / status footer (§5.14.6.8 struct virtio_snd_pcm_xfer /
 * virtio_snd_pcm_status). */
typedef struct
{
    uint32_t streamId;
} VIO_SND_PCM_XFER;
_Static_assert(sizeof(VIO_SND_PCM_XFER) == 4, "virtio_snd_pcm_xfer (virtio 1.2 cs01 §5.14.6.8)");

typedef struct
{
    uint32_t status; /* VIO_SND_S_* */
    uint32_t latencyBytes;
} VIO_SND_PCM_STATUS;
_Static_assert(sizeof(VIO_SND_PCM_STATUS) == 8,
               "virtio_snd_pcm_status (virtio 1.2 cs01 §5.14.6.8)");

/* --- driver state ----------------------------------------------------------- */

/* Per-period tx slot: the §5.14.6.8 device-readable xfer header and the
 * device-writable status footer live in a shared frame (32 bytes per slot,
 * the VIO_BLK_CONTROL_SLOT pattern); the payload owns a whole DMA frame,
 * which is why sndproto.h bounds period_bytes at PAGE_SIZE. */
typedef struct VIO_SND_TX_SLOT
{
    struct VIO_SND_STREAM *stream;
    uint64_t dataPhysical; /* one frame; 0 on a capture stream (no tx) */
    char *data;
    uint32_t payloadBytes; /* this flight's period size */
    BOOLEAN inFlight;
    uint8_t index; /* slot index within the stream, for the header frame */
} VIO_SND_TX_SLOT;

typedef struct VIO_SND_STREAM
{
    uint32_t id;
    SND_PCM_INFO info; /* the device's own PCM_INFO answer, cached at init */
    BOOLEAN paramsValid;
    uint32_t bufferBytes;
    uint32_t periodBytes;
    uint32_t slotCount; /* bufferBytes / periodBytes, capped at SND_MAX_PERIODS */
    VIO_SND_TX_SLOT slots[SND_MAX_PERIODS];
    ULONG txInFlight;
    uint64_t bytesCompleted; /* payload bytes the device consumed since PREPARE */
    uint64_t txErrors;
    KEVENT space; /* set by the tx harvest; the writer's park (docs/23 §4a) */
} VIO_SND_STREAM;

static BOOLEAN VioSndPresent;
static VIO_PCI_DEVICE VioSndDevice;
static VIO_VIRTQUEUE VioSndControlQueue;
static VIO_VIRTQUEUE VioSndTxQueue;
static uint32_t VioSndStreams;
static VIO_SND_STREAM VioSndStreamTable[VIO_SND_MAX_STREAMS];

/* head descriptor index -> in-flight tx slot (the §2.7.8 used id is the
 * chain head). Sized for the largest ring VioInitializeVirtqueue allows. */
static VIO_SND_TX_SLOT *VioSndTxSlotByHead[256];

/* One shared frame of 32-byte header/footer regions: per stream, per slot —
 * xfer header at +0, status footer at +8 within each region. */
#define VIO_SND_HDRSLOT_BYTES      32
#define VIO_SND_HDRSLOT_XFER_OFF   0
#define VIO_SND_HDRSLOT_STATUS_OFF 8
_Static_assert(VIO_SND_MAX_STREAMS *SND_MAX_PERIODS *VIO_SND_HDRSLOT_BYTES <= 4096,
               "tx header/footer regions fit their one DMA frame");
static uint64_t VioSndTxHdrPhysical;
static char *VioSndTxHdr;

/* The control round-trip state: one request in flight at a time, owned
 * through a real park-based gate rather than an ownership assert — unlike
 * blk's bounce (guarded by the distant volume gate), two threads holding
 * two different streams open can issue verbs concurrently. */
static KEVENT VioSndControlGate; /* SynchronizationEvent: TRUE = free */
static KEVENT VioSndControlDone;
static volatile BOOLEAN VioSndControlCompleted;
static ULONG VioSndControlInFlight; /* 0 or 1: the gate serializes round trips */
static uint64_t VioSndControlPhysical;
static char *VioSndControl; /* request at +0, response at +2048 */
#define VIO_SND_CTRL_RESPONSE_OFF 2048
_Static_assert(VIO_SND_CTRL_RESPONSE_OFF + sizeof(VIO_SND_HDR) +
                       (uint64_t)VIO_SND_MAX_STREAMS * sizeof(SND_PCM_INFO) <=
                   4096,
               "control request + largest response fit their one DMA frame");

/* Pre-park drain-spin bound, the VIO_BLK_AWAIT_SPINS rationale: QEMU serves
 * the controlq synchronously at the notify MMIO exit, so a bounded spin
 * completes every real round trip without paying a park. */
#define VIO_SND_CTRL_AWAIT_SPINS 4096

/* Test instrumentation (snd.h): while TRUE, the drain defers the TX harvest
 * so a parked writer provably stays parked. Control replies keep flowing —
 * the verbs that end a park test (START/STOP) must work while it is up. */
static BOOLEAN VioSndCompletionHold;

/* --- harvest ---------------------------------------------------------------- */

/* Both harvests: store, account, wake — nothing else (docs/20 R2;
 * IoDrainDeviceCompletions arms the assert). Dispatcher lock held by every
 * caller, so a completion cannot interleave with a submit's bookkeeping. */
static void VioSndHarvestControlLocked(void)
{
    uint16_t head;
    uint32_t length;
    while (VioHarvestUsed(&VioSndControlQueue, &head, &length))
    {
        ASSERT(!VioSndControlCompleted); /* one control request in flight */
        ASSERT(VioSndControlInFlight == 1);
        VioSndControlInFlight = 0;
        VioSndControlCompleted = TRUE;
        KeSetEvent(&VioSndControlDone, 0, FALSE);
    }
}

static void VioSndHarvestTxLocked(void)
{
    uint16_t head;
    uint32_t length;
    while (VioHarvestUsed(&VioSndTxQueue, &head, &length))
    {
        VIO_SND_TX_SLOT *slot = VioSndTxSlotByHead[head];
        ASSERT(slot != 0); /* every chain out has exactly one owner */
        ASSERT(slot->inFlight);
        VioSndTxSlotByHead[head] = 0;
        slot->inFlight = FALSE;
        VIO_SND_STREAM *stream = slot->stream;
        ASSERT(stream->txInFlight != 0);
        stream->txInFlight--;
        const volatile VIO_SND_PCM_STATUS *status =
            (const volatile VIO_SND_PCM_STATUS *)(VioSndTxHdr +
                                                  ((uint64_t)stream->id * SND_MAX_PERIODS +
                                                   slot->index) *
                                                      VIO_SND_HDRSLOT_BYTES +
                                                  VIO_SND_HDRSLOT_STATUS_OFF);
        if (status->status == VIO_SND_S_OK)
        {
            stream->bytesCompleted += slot->payloadBytes;
        }
        else
        {
            /* A flushed or failed period: not consumed, so the position
             * does not advance — but never silently (Art. 12). */
            stream->txErrors++;
            DbgPrint("virtio-snd: stream %lu tx status %#lx\n", (unsigned long)stream->id,
                     (unsigned long)status->status);
        }
        KeSetEvent(&stream->space, 0, FALSE);
    }
}

void VioSndDrain(void)
{
    VioSndHarvestControlLocked();
    if (!VioSndCompletionHold)
    {
        VioSndHarvestTxLocked();
    }
}

void VioSndSetCompletionHold(BOOLEAN hold)
{
    uint64_t flags = KiAcquireDispatcherLock();
    VioSndCompletionHold = hold;
    if (!hold)
    {
        /* Harvest is pull-based, so nothing was lost while held — but the
         * release itself must harvest or the parked writers stay parked
         * (the VioBlkSetCompletionHold rationale). */
        VioSndHarvestTxLocked();
    }
    KiReleaseDispatcherLock(flags);
}

void VioSndPumpCompletions(void)
{
    uint64_t flags = KiAcquireDispatcherLock();
    VioSndHarvestControlLocked();
    VioSndHarvestTxLocked();
    KiReleaseDispatcherLock(flags);
}

ULONG VioSndInFlightCount(void)
{
    ULONG total = VioSndControlInFlight;
    for (uint32_t id = 0; id < VioSndStreams; id++)
    {
        total += VioSndStreamTable[id].txInFlight;
    }
    return total;
}

ULONG VioSndTxInFlightCount(uint32_t streamId)
{
    ASSERT(streamId < VioSndStreams);
    return VioSndStreamTable[streamId].txInFlight;
}

/* --- the control round trip ------------------------------------------------- */

/* Map the device's own answer to the NT failure sndproto.h fixes. */
static NTSTATUS VioSndStatusToNt(uint32_t status)
{
    switch (status)
    {
    case VIO_SND_S_OK:
        return STATUS_SUCCESS;
    case VIO_SND_S_BAD_MSG:
        return STATUS_INVALID_PARAMETER;
    case VIO_SND_S_NOT_SUPP:
        return STATUS_INVALID_DEVICE_REQUEST;
    default: /* VIO_SND_S_IO_ERR and anything the spec grows later */
        return STATUS_IO_DEVICE_ERROR;
    }
}

/* One synchronous control round trip: copy the request into the control
 * frame, submit a 2-descriptor chain (device-readable request,
 * device-writable response, §2.7.4.2 ordering), await the reply with the
 * blk await shape, copy the response out. Serialized by the gate park.
 * `responseCapacity` includes the leading VIO_SND_HDR status. */
static NTSTATUS VioSndControlRoundTrip(const void *request, uint32_t requestLength, void *response,
                                       uint32_t responseCapacity)
{
    ASSERT(VioSndControl != 0); /* init runs round trips before VioSndPresent is set */
    /* Init's PCM_INFO query runs from IoInitializeTransport — before the
     * scheduler has a current thread — so it may neither take the gate nor
     * park below: it completes on the spin paths alone (QEMU serves the
     * controlq synchronously at the notify), single-threaded by
     * construction. Everything after VioSndPresent is thread context. */
    BOOLEAN threaded = VioSndPresent;
    if (threaded)
    {
        NTSTATUS gate = KeWaitForSingleObject(&VioSndControlGate, Executive, KernelMode, FALSE, 0);
        if (gate != STATUS_SUCCESS)
        {
            return gate; /* a terminating thread cannot park (CUI-4); nothing is in flight */
        }
    }

    memcpy(VioSndControl, request, requestLength);
    memset(VioSndControl + VIO_SND_CTRL_RESPONSE_OFF, 0, responseCapacity);

    uint64_t flags = KiAcquireDispatcherLock();
    VioSndControlCompleted = FALSE;
    VioSndControlInFlight = 1;
    KeInitializeEvent(&VioSndControlDone, NotificationEvent, FALSE);
    VIO_SEGMENT segments[2] = {
        {VioSndControlPhysical, requestLength, 0},
        {VioSndControlPhysical + VIO_SND_CTRL_RESPONSE_OFF, responseCapacity, 1},
    };
    uint16_t head;
    for (uint64_t spins = 0; !VioSubmitChain(&VioSndControlQueue, segments, 2, &head); spins++)
    {
        if (spins >= 1000000000ULL)
        {
            KiPanic("virtio-snd: control submit stalled (ring full)");
        }
        VioSndHarvestControlLocked();
        __asm__ volatile("pause");
    }
    KiReleaseDispatcherLock(flags);

    /* The blk await shape: bounded drain-spin for the QEMU-synchronous
     * common case, then the park with the 10 s wedged-device panic, then
     * the terminating thread's poll-home (the reply still lands in the
     * control frame, which the next round trip reuses — docs/20 R4). */
    for (ULONG spins = 0; spins < VIO_SND_CTRL_AWAIT_SPINS && !VioSndControlCompleted; spins++)
    {
        flags = KiAcquireDispatcherLock();
        VioSndHarvestControlLocked();
        KiReleaseDispatcherLock(flags);
        __asm__ volatile("pause");
    }
    if (threaded && !VioSndControlCompleted)
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -100000000LL; /* 10 s, relative */
        NTSTATUS wait =
            KeWaitForSingleObject(&VioSndControlDone, Executive, KernelMode, FALSE, &timeout);
        if (wait == STATUS_TIMEOUT && !VioSndControlCompleted)
        {
            KiPanic("virtio-snd: control request timed out");
        }
    }
    for (uint64_t spins = 0; !VioSndControlCompleted; spins++)
    {
        if (spins >= 1000000000ULL)
        {
            KiPanic("virtio-snd: control request timed out");
        }
        flags = KiAcquireDispatcherLock();
        VioSndHarvestControlLocked();
        KiReleaseDispatcherLock(flags);
        __asm__ volatile("pause");
    }

    memcpy(response, VioSndControl + VIO_SND_CTRL_RESPONSE_OFF, responseCapacity);
    if (threaded)
    {
        KeSetEvent(&VioSndControlGate, 0, FALSE); /* release the gate */
    }
    return STATUS_SUCCESS;
}

/* A stream-addressed verb whose reply is just the status header. */
static NTSTATUS VioSndSimpleVerb(uint32_t code, uint32_t streamId)
{
    ASSERT(streamId < VioSndStreams);
    VIO_SND_PCM_HDR request = {{code}, streamId};
    VIO_SND_HDR reply = {0};
    NTSTATUS status = VioSndControlRoundTrip(&request, sizeof(request), &reply, sizeof(reply));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    return VioSndStatusToNt(reply.code);
}

NTSTATUS VioSndPrepare(uint32_t streamId)
{
    NTSTATUS status = VioSndSimpleVerb(VIO_SND_R_PCM_PREPARE, streamId);
    if (NT_SUCCESS(status))
    {
        /* The position counter restarts with the stream (sndproto.h). */
        uint64_t flags = KiAcquireDispatcherLock();
        VioSndStreamTable[streamId].bytesCompleted = 0;
        KiReleaseDispatcherLock(flags);
    }
    return status;
}

NTSTATUS VioSndStart(uint32_t streamId)
{
    return VioSndSimpleVerb(VIO_SND_R_PCM_START, streamId);
}

NTSTATUS VioSndStop(uint32_t streamId)
{
    return VioSndSimpleVerb(VIO_SND_R_PCM_STOP, streamId);
}

NTSTATUS VioSndRelease(uint32_t streamId)
{
    return VioSndSimpleVerb(VIO_SND_R_PCM_RELEASE, streamId);
}

NTSTATUS VioSndSetParams(uint32_t streamId, const SND_PCM_SET_PARAMS *params)
{
    ASSERT(streamId < VioSndStreams);
    /* The kernel transport's own capacity, refused before the device sees
     * the request and stated in sndproto.h — one period per DMA frame, at
     * most SND_MAX_PERIODS in flight. Everything else is the device's own
     * decision, forwarded verbatim. */
    if (params->periodBytes == 0 || params->periodBytes > PAGE_SIZE ||
        params->bufferBytes < params->periodBytes ||
        params->bufferBytes / params->periodBytes > SND_MAX_PERIODS)
    {
        DbgPrint(
            "virtio-snd: stream %lu refused params buffer=%lu period=%lu (sndproto.h bounds)\n",
            (unsigned long)streamId, (unsigned long)params->bufferBytes,
            (unsigned long)params->periodBytes);
        return STATUS_INVALID_PARAMETER;
    }

    VIO_SND_PCM_SET_PARAMS_REQ request;
    request.hdr.hdr.code = VIO_SND_R_PCM_SET_PARAMS;
    request.hdr.streamId = streamId;
    request.params = *params;
    request.params.reserved = 0;
    VIO_SND_HDR reply = {0};
    NTSTATUS status = VioSndControlRoundTrip(&request, sizeof(request), &reply, sizeof(reply));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = VioSndStatusToNt(reply.code);
    if (NT_SUCCESS(status))
    {
        VIO_SND_STREAM *stream = &VioSndStreamTable[streamId];
        uint64_t flags = KiAcquireDispatcherLock();
        stream->paramsValid = TRUE;
        stream->bufferBytes = params->bufferBytes;
        stream->periodBytes = params->periodBytes;
        stream->slotCount = params->bufferBytes / params->periodBytes;
        KiReleaseDispatcherLock(flags);
    }
    return status;
}

BOOLEAN VioSndStreamParams(uint32_t streamId, uint32_t *periodBytesOut)
{
    ASSERT(streamId < VioSndStreams);
    VIO_SND_STREAM *stream = &VioSndStreamTable[streamId];
    if (!stream->paramsValid)
    {
        return FALSE;
    }
    *periodBytesOut = stream->periodBytes;
    return TRUE;
}

uint64_t VioSndPosition(uint32_t streamId)
{
    ASSERT(streamId < VioSndStreams);
    return VioSndStreamTable[streamId].bytesCompleted;
}

/* --- the data path ---------------------------------------------------------- */

NTSTATUS VioSndWritePeriod(uint32_t streamId, const void *buffer, ULONG length)
{
    ASSERT(VioSndPresent);
    ASSERT(streamId < VioSndStreams);
    VIO_SND_STREAM *stream = &VioSndStreamTable[streamId];
    ASSERT(stream->info.direction == SND_D_OUTPUT); /* drivers/snd.c only wires Write there */

    if (!stream->paramsValid)
    {
        return STATUS_INVALID_DEVICE_STATE; /* sndproto.h: no period to size against */
    }
    if (length != stream->periodBytes)
    {
        /* Exactly one period per call (sndproto.h). Saying so beats a
         * silent partial submit the pacing clock would drift on. */
        return STATUS_INVALID_PARAMETER;
    }

    for (;;)
    {
        uint64_t flags = KiAcquireDispatcherLock();
        /* Clear-then-check under the lock: a completion landing after the
         * full scan below sets the event and the park falls straight
         * through — no lost wakeup. */
        KeClearEvent(&stream->space);
        VIO_SND_TX_SLOT *slot = 0;
        for (uint32_t index = 0; index < stream->slotCount; index++)
        {
            if (!stream->slots[index].inFlight)
            {
                slot = &stream->slots[index];
                break;
            }
        }
        if (slot != 0)
        {
            /* Claim-fill-submit-register under one hold (docs/20 F2): the
             * drain must never observe a submitted chain whose cookie is
             * not in the head map. */
            memcpy(slot->data, buffer, length);
            slot->payloadBytes = length;
            uint64_t regionPhysical =
                VioSndTxHdrPhysical +
                ((uint64_t)stream->id * SND_MAX_PERIODS + slot->index) * VIO_SND_HDRSLOT_BYTES;
            VIO_SND_PCM_XFER *xfer =
                (VIO_SND_PCM_XFER *)(VioSndTxHdr +
                                     ((uint64_t)stream->id * SND_MAX_PERIODS + slot->index) *
                                         VIO_SND_HDRSLOT_BYTES +
                                     VIO_SND_HDRSLOT_XFER_OFF);
            xfer->streamId = stream->id;
            /* §5.14.6.8 framing, §2.7.4.2 ordering: device-readable xfer
             * header + frames, then the device-writable status footer. */
            VIO_SEGMENT segments[3] = {
                {regionPhysical + VIO_SND_HDRSLOT_XFER_OFF, sizeof(VIO_SND_PCM_XFER), 0},
                {slot->dataPhysical, length, 0},
                {regionPhysical + VIO_SND_HDRSLOT_STATUS_OFF, sizeof(VIO_SND_PCM_STATUS), 1},
            };
            uint16_t head;
            if (VioSubmitChain(&VioSndTxQueue, segments, 3, &head))
            {
                slot->inFlight = TRUE;
                ASSERT(VioSndTxSlotByHead[head] == 0);
                VioSndTxSlotByHead[head] = slot;
                stream->txInFlight++;
                KiReleaseDispatcherLock(flags);
                return STATUS_SUCCESS;
            }
            /* Ring exhausted with a free slot: only possible with chains
             * out — completions are owed, so the park below is fed. */
            ASSERT(stream->txInFlight != 0);
        }
        KiReleaseDispatcherLock(flags);

        /* THE new park (G14; docs/23 §4a): the buffer is full and the
         * pacing clock is the device returning a period. No timeout — a
         * stopped stream legitimately holds its writer indefinitely, the
         * NT full-pipe shape. A refused park (terminating thread, CUI-4)
         * returns as-is: the in-flight periods live in driver-owned
         * frames, so the dying caller owes the device nothing (R4). */
        NTSTATUS wait = KeWaitForSingleObject(&stream->space, Executive, KernelMode, FALSE, 0);
        if (wait != STATUS_SUCCESS)
        {
            return wait;
        }
    }
}

/* --- initialization --------------------------------------------------------- */

const SND_PCM_INFO *VioSndStreamInfo(uint32_t streamId)
{
    ASSERT(streamId < VioSndStreams);
    return &VioSndStreamTable[streamId].info;
}

BOOLEAN VioSndIsPresent(void)
{
    return VioSndPresent;
}

uint32_t VioSndStreamCount(void)
{
    return VioSndStreams;
}

/* Little-endian 32-bit device-config field (§4.1.3.1; byte reads keep the
 * MMIO access width simple — the input.c helper's rationale). */
static uint32_t VioSndReadConfigLe32(unsigned offset)
{
    volatile uint8_t *field = VioSndDevice.deviceCfg + offset;
    return (uint32_t)field[0] | ((uint32_t)field[1] << 8) | ((uint32_t)field[2] << 16) |
           ((uint32_t)field[3] << 24);
}

BOOLEAN VioSndInitialize(void)
{
    /* §4.1.2: snd is modern-only — no transitional id for a device type
     * introduced after the legacy interface (the input.c precedent). */
    if (!VioPciSetupModernDevice(VIRTIO_DEVICE_TYPE_SND, 0, "virtio-snd", 0, &VioSndDevice))
    {
        return FALSE;
    }
    if (!VioPciAcceptFeatures(&VioSndDevice))
    {
        return FALSE;
    }

    uint32_t streams = VioSndReadConfigLe32(VIO_SND_CFG_OFF_STREAMS);
    if (streams == 0)
    {
        DbgPrint("virtio-snd: device reports no PCM streams\n");
        VioPciSetFailed(&VioSndDevice);
        return FALSE;
    }
    if (streams > VIO_SND_MAX_STREAMS)
    {
        DbgPrint("virtio-snd: %lu streams reported, carrying the first %u\n",
                 (unsigned long)streams, VIO_SND_MAX_STREAMS);
        streams = VIO_SND_MAX_STREAMS;
    }

    /* §5.14.2 defines four virtqueues. We configure controlq and txq only:
     * a driver uses the queues it configures. eventq gets no buffers —
     * nothing consumes jack/xrun events — and rxq is AUD-3's capture path.
     * Said out loud rather than left as a silent gap (Art. 12; the
     * input.c statusq precedent). */
    if (!VioPciSetupQueue(&VioSndDevice, &VioSndControlQueue, VIO_SND_VQ_CONTROL) ||
        !VioPciSetupQueue(&VioSndDevice, &VioSndTxQueue, VIO_SND_VQ_TX))
    {
        return FALSE;
    }
    DbgPrint("virtio-snd: eventq/rxq unconfigured -- no event/capture path (AUD-1 scope)\n");

    /* DMA buffers before going live. */
    VioSndControlPhysical = MiAllocatePage();
    VioSndTxHdrPhysical = MiAllocatePage();
    if (VioSndControlPhysical == 0 || VioSndTxHdrPhysical == 0)
    {
        VioPciSetFailed(&VioSndDevice);
        return FALSE;
    }
    VioSndControl = MiPhysicalToVirtual(VioSndControlPhysical);
    VioSndTxHdr = MiPhysicalToVirtual(VioSndTxHdrPhysical);
    memset(VioSndControl, 0, PAGE_SIZE);
    memset(VioSndTxHdr, 0, PAGE_SIZE);

    KeInitializeEvent(&VioSndControlGate, SynchronizationEvent, TRUE);
    KeInitializeEvent(&VioSndControlDone, NotificationEvent, FALSE);

    /* Step 8: DRIVER_OK — the controlq is usable from here (§3.1.1). */
    VioPciSetDriverOk(&VioSndDevice);
    VioSndStreams = streams;

    /* Cache every stream's PCM_INFO in one §5.14.6.6.2 query — the
     * device's own claim (direction above all: first-half-output is the
     * pinned model's policy, never assumed here — the HACK-002 rule). */
    VIO_SND_QUERY_INFO query;
    query.hdr.code = VIO_SND_R_PCM_INFO;
    query.startId = 0;
    query.count = streams;
    query.size = sizeof(SND_PCM_INFO);
    /* The reply is the PACKED wire layout — the 4-byte status header
     * immediately followed by count 32-byte info entries (§5.14.6.6.2). A
     * C struct of {hdr; info[]} would pad the entries to offset 8 (the
     * u64 members' alignment), shifting every field it decodes by 4 —
     * so the reply is unpacked by explicit offsets instead. */
    char reply[sizeof(VIO_SND_HDR) + VIO_SND_MAX_STREAMS * sizeof(SND_PCM_INFO)];
    memset(reply, 0, sizeof(reply));
    NTSTATUS status = VioSndControlRoundTrip(
        &query, sizeof(query), reply,
        (uint32_t)(sizeof(VIO_SND_HDR) + (uint64_t)streams * sizeof(SND_PCM_INFO)));
    VIO_SND_HDR replyHdr;
    memcpy(&replyHdr, reply, sizeof(replyHdr));
    if (!NT_SUCCESS(status) || replyHdr.code != VIO_SND_S_OK)
    {
        DbgPrint("virtio-snd: PCM_INFO refused (%#lx)\n", (unsigned long)replyHdr.code);
        VioSndStreams = 0;
        VioPciSetFailed(&VioSndDevice);
        return FALSE;
    }

    for (uint32_t id = 0; id < streams; id++)
    {
        VIO_SND_STREAM *stream = &VioSndStreamTable[id];
        stream->id = id;
        memcpy(&stream->info, reply + sizeof(VIO_SND_HDR) + (uint64_t)id * sizeof(SND_PCM_INFO),
               sizeof(SND_PCM_INFO));
        KeInitializeEvent(&stream->space, NotificationEvent, FALSE);
        for (uint32_t index = 0; index < SND_MAX_PERIODS; index++)
        {
            stream->slots[index].stream = stream;
            stream->slots[index].index = (uint8_t)index;
        }
        if (stream->info.direction == SND_D_OUTPUT)
        {
            /* One frame per period slot, up front: the write path may not
             * allocate (it runs under the dispatcher lock at submit). */
            for (uint32_t index = 0; index < SND_MAX_PERIODS; index++)
            {
                uint64_t physical = MiAllocatePage();
                if (physical == 0)
                {
                    VioSndStreams = 0;
                    VioPciSetFailed(&VioSndDevice);
                    return FALSE;
                }
                stream->slots[index].dataPhysical = physical;
                stream->slots[index].data = MiPhysicalToVirtual(physical);
            }
        }
        DbgPrint("virtio-snd: stream %lu %s, ch %u-%u\n", (unsigned long)id,
                 stream->info.direction == SND_D_OUTPUT ? "output" : "input",
                 stream->info.channelsMin, stream->info.channelsMax);
    }

    VioSndPresent = TRUE;
    DbgPrint("virtio-snd: %02x:%x id %04x, %lu streams, ctrl queue %u, tx queue %u\n",
             VioSndDevice.function.device, VioSndDevice.function.function,
             VioSndDevice.function.deviceId, (unsigned long)streams, VioSndControlQueue.queueSize,
             VioSndTxQueue.queueSize);
    return TRUE;
}
