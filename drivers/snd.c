/* drivers/snd.c — \Device\Snd0..\Device\Snd<n>, the PCM stream devices
 * (AUD-1; HACK-007).
 *
 * One device node per PCM stream the virtio-snd device reports; each node's
 * direction is the stream's own PCM_INFO answer relayed verbatim, never
 * instance order (drivers/sndproto.h; the HACK-002 "the device's claim, not
 * PCI enumeration" rule). The ioctls mirror the virtio control verbs
 * one-to-one and forward untranslated — no format translation, no
 * resampling, no mixing, no volume here, ever: policy lives above the
 * boundary.
 *
 * HACK-007 (docs/10): on NT no Nt* call carries PCM — the audio surface is
 * user-mode WASAPI over audiodg and the kernel-streaming stack, and route
 * (a) has neither, so mmdevapi's seam needs a transport below it (docs/23
 * §1). Like \Device\Fb0 these are new devices at the OUTSIDE of the
 * boundary and nothing else — no Nt* call changes shape (Art. 2's audio
 * exception), and deleting drivers/snd.*, drivers/sndproto.h,
 * drivers/virtio/snd.*, the Makefile lines, the two init calls and the
 * drain arm restores the pre-audio kernel (Art. 7).
 *
 * Blocking-only, exclusive open per stream through the existing Io share
 * engine (G10/Art. 11 — no private flag). A render stream's NtWriteFile of
 * exactly period_bytes parks when the device buffer is full (drivers/
 * virtio/snd.c — THE park G14 declares); a capture stream has no Read op
 * until AUD-3 builds the rxq path, so the Io layer refuses reads with its
 * own status rather than fabricate silence (Art. 12).
 */
#include "drivers/snd.h"
#include "drivers/sndproto.h"
#include "drivers/virtio/snd.h"
#include "kernel/init/panic.h"
#include "kernel/io/io.h"
#include "kernel/io/vfs.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "abi/ntstatus.h"

/* One published stream node (the HID_STREAM shape): the FCB carries the
 * share-access slots for the one exclusive open; handlers find their
 * stream through file->device->context (one publication path, G10). */
typedef struct SND_STREAM
{
    IO_FCB fcb;
    uint32_t streamId;
    const WCHAR *queryName; /* the QueryName answer, L"\\Snd0" shape */
} SND_STREAM;

static SND_STREAM SndStreams[VIO_SND_MAX_STREAMS];

static SND_STREAM *SndStreamFromFile(PFILE_OBJECT file)
{
    return (SND_STREAM *)file->device->context;
}

static NTSTATUS SndCreate(PIO_DEVICE device, PFILE_OBJECT file, const UNICODE_STRING *path,
                          PFILE_OBJECT relativeTo, ACCESS_MASK grantedAccess, ULONG shareAccess,
                          ULONG fileAttributes, ULONG disposition, ULONG options,
                          ULONG_PTR *information)
{
    SND_STREAM *stream = (SND_STREAM *)device->context;
    (void)relativeTo;
    (void)fileAttributes;
    if (path->Length != 0)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND; /* the device has no namespace */
    }

    /* Exactly one owner per stream (sndproto.h): two writers interleaving
     * periods into one device buffer would be a data race dressed as
     * mixing, and mixing is user mode's. The existing share engine
     * enforces it (G10/Art. 11) and releases the slots on close. */
    NTSTATUS status =
        IoCheckShareAccess(grantedAccess, shareAccess, disposition, options, &stream->fcb);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    IoSetShareAccess(grantedAccess, shareAccess, &stream->fcb);
    file->shareCounted = TRUE;

    file->fsContext = &stream->fcb;
    file->fcb = &stream->fcb;
    file->isDirectory = FALSE;
    *information = FILE_OPENED;
    return STATUS_SUCCESS;
}

static void SndCleanup(PFILE_OBJECT file)
{
    (void)file;
}

static void SndClose(PFILE_OBJECT file)
{
    (void)file;
}

static NTSTATUS SndGetInfo(PFILE_OBJECT file, IO_FILE_INFO *info)
{
    (void)file;
    memset(info, 0, sizeof(*info));
    return STATUS_SUCCESS;
}

static NTSTATUS SndQueryName(PFILE_OBJECT file, WCHAR *buffer, ULONG capacity, ULONG *lengthOut)
{
    const WCHAR *name = SndStreamFromFile(file)->queryName;
    ULONG full = (ULONG)KiWideStringLength(name) * sizeof(WCHAR);
    *lengthOut = full;
    ULONG copy = full <= capacity ? full : capacity;
    memcpy(buffer, name, copy);
    return full <= capacity ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;
}

/* The control verbs, one ioctl per virtio verb (sndproto.h). Each forwards
 * verbatim and relays the device's own status; INFO and POSITION answer
 * from driver-cached/-counted state and never touch MMIO. */
static NTSTATUS SndDeviceControl(PFILE_OBJECT file, ULONG code, const void *input,
                                 ULONG inputLength, void *output, ULONG outputLength,
                                 ULONG_PTR *infoOut, IO_CONTROL_CONTEXT *request)
{
    SND_STREAM *stream = SndStreamFromFile(file);
    (void)request; /* the snd streams block rather than pend (docs/03 CUI-5) */

    switch (code)
    {
    case IOCTL_PRSSND_INFO:
    {
        if (outputLength < sizeof(SND_PCM_INFO))
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        memcpy(output, VioSndStreamInfo(stream->streamId), sizeof(SND_PCM_INFO));
        *infoOut = sizeof(SND_PCM_INFO);
        return STATUS_SUCCESS;
    }
    case IOCTL_PRSSND_SET_PARAMS:
    {
        if (inputLength < sizeof(SND_PCM_SET_PARAMS))
        {
            return STATUS_INVALID_PARAMETER;
        }
        SND_PCM_SET_PARAMS params;
        memcpy(&params, input, sizeof(params));
        return VioSndSetParams(stream->streamId, &params);
    }
    case IOCTL_PRSSND_PREPARE:
        return VioSndPrepare(stream->streamId);
    case IOCTL_PRSSND_START:
        return VioSndStart(stream->streamId);
    case IOCTL_PRSSND_STOP:
        return VioSndStop(stream->streamId);
    case IOCTL_PRSSND_RELEASE:
        return VioSndRelease(stream->streamId);
    case IOCTL_PRSSND_POSITION:
    {
        if (outputLength < sizeof(SND_POSITION))
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        SND_POSITION position;
        position.bytesConsumed = VioSndPosition(stream->streamId);
        memcpy(output, &position, sizeof(position));
        *infoOut = sizeof(position);
        return STATUS_SUCCESS;
    }
    default:
        /* Art. 12: name the refusal on serial and return the refusal
         * status — never a no-op success for a verb this device does
         * not have. */
        DbgPrint("snd: unimplemented ioctl %#lx\n", (unsigned long)code);
        return STATUS_NOT_IMPLEMENTED;
    }
}

/* Blocking write of exactly one period; the buffer is the Io layer's pool
 * bounce (kernel/io/rw.c), copied into a driver-owned DMA frame below. */
static NTSTATUS SndWrite(PFILE_OBJECT file, const void *buffer, ULONG length, ULONG_PTR *infoOut,
                         IO_CONTROL_CONTEXT *request)
{
    (void)request;
    SND_STREAM *stream = SndStreamFromFile(file);
    NTSTATUS status = VioSndWritePeriod(stream->streamId, buffer, length);
    *infoOut = NT_SUCCESS(status) ? length : 0;
    return status;
}

/* A render stream: the control verbs plus the period write. No Read — the
 * stream carries output, and the missing op makes the Io layer refuse with
 * its own distinct status (Art. 12). */
static const IO_VFS_OPS SndRenderOps = {
    .Create = SndCreate,
    .Cleanup = SndCleanup,
    .Close = SndClose,
    .GetInfo = SndGetInfo,
    .QueryName = SndQueryName,
    .Write = SndWrite,
    .DeviceControl = SndDeviceControl,
};

/* A capture stream: the control verbs only. No Write (wrong direction) and
 * no Read until AUD-3 builds the rxq path — both refusals are the Io
 * layer's own, never an accept-and-drop (Art. 12). */
static const IO_VFS_OPS SndCaptureOps = {
    .Create = SndCreate,
    .Cleanup = SndCleanup,
    .Close = SndClose,
    .GetInfo = SndGetInfo,
    .QueryName = SndQueryName,
    .DeviceControl = SndDeviceControl,
};

void SndInitialize(void)
{
    if (!VioSndIsPresent())
    {
        DbgPrint("snd: no virtio-snd device; \\Device\\Snd* not published\n");
        return;
    }

    /* Names are static storage: IoPublishDevice and QueryName keep the
     * pointers for the machine's lifetime. */
    static const WCHAR deviceNames[VIO_SND_MAX_STREAMS][14] = {
        WSTR("\\Device\\Snd0"),
        WSTR("\\Device\\Snd1"),
        WSTR("\\Device\\Snd2"),
        WSTR("\\Device\\Snd3"),
    };
    static const WCHAR queryNames[VIO_SND_MAX_STREAMS][6] = {
        WSTR("\\Snd0"),
        WSTR("\\Snd1"),
        WSTR("\\Snd2"),
        WSTR("\\Snd3"),
    };

    for (uint32_t id = 0; id < VioSndStreamCount(); id++)
    {
        SND_STREAM *stream = &SndStreams[id];
        IopInitializeFcb(&stream->fcb);
        stream->streamId = id;
        stream->queryName = queryNames[id];
        /* The ops table follows the stream's own direction claim
         * (sndproto.h; the HACK-002 rule). */
        const SND_PCM_INFO *info = VioSndStreamInfo(id);
        const IO_VFS_OPS *ops = info->direction == SND_D_OUTPUT ? &SndRenderOps : &SndCaptureOps;
        IoPublishDevice(deviceNames[id], ops, stream, FILE_DEVICE_SOUND);
        DbgPrint("snd: \\Device\\Snd%lu published (%s)\n", (unsigned long)id,
                 info->direction == SND_D_OUTPUT ? "render" : "capture");
    }
}
