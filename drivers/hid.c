/* drivers/hid.c — \Device\Input0 and \Device\Input1, the raw input streams
 * (GUI-1; the pointer joined at GUI-4; HACK-002).
 *
 * Reads deliver virtio-input events verbatim (drivers/hidproto.h). There is
 * no translation here on purpose: any mapping from scancode to character is
 * a keyboard layout, and a layout belongs in user32 above the boundary, not
 * in a driver below it. The same rule keeps pointer coordinates raw — the
 * one thing the pointer device answers beyond events is its own ABS_INFO
 * range, verbatim, through a single ioctl, so scaling lives in user mode
 * and no QEMU constant is baked on either side.
 *
 * HACK-002 (docs/10): NT routes raw input through win32k and csrss into the
 * input queue, and route (a) (docs/07) has neither, so the display backend
 * needs raw event sources. Like \Device\Fb0 these are new devices at the
 * OUTSIDE of the boundary and nothing else -- no Nt* call changes shape
 * (Art. 2's GUI exception), and deleting drivers/hid.*, drivers/hidproto.h,
 * the Makefile line and the HidInitialize() call restores the pre-GUI
 * kernel (Art. 7).
 *
 * Blocking is CondrvSerialRead's shape (drain, else nap a millisecond):
 * the kernel has no device IRQ, and this is the same "a human is typing"
 * problem the serial console already solved.
 */
#include "drivers/hid.h"
#include "drivers/hidproto.h"
#include "drivers/virtio/input.h"
#include "kernel/init/panic.h"
#include "kernel/io/io.h"
#include "kernel/io/vfs.h"
#include "kernel/ke/ke.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "abi/ntstatus.h"

/* One stream = one published device over one virtio-input instance. The
 * FCB is the CondrvSerialFcb shape: the Io close hooks key off a non-NULL
 * fsContext and a valid IO_FCB, and the share-access engine needs somewhere
 * to keep this device's one open's slots. Handlers find their stream
 * through file->device->context (one publication path, G10/Art. 11). */
typedef struct HID_STREAM
{
    IO_FCB fcb;
    VIO_INPUT_INSTANCE *source;
    const WCHAR *queryName; /* the QueryName answer, L"\\Input0" shape */
} HID_STREAM;

static HID_STREAM HidKeyboardStream;
static HID_STREAM HidPointerStream;

static HID_STREAM *HidStreamFromFile(PFILE_OBJECT file)
{
    return (HID_STREAM *)file->device->context;
}

static NTSTATUS HidInputCreate(PIO_DEVICE device, PFILE_OBJECT file, const UNICODE_STRING *path,
                               PFILE_OBJECT relativeTo, ACCESS_MASK grantedAccess,
                               ULONG shareAccess, ULONG fileAttributes, ULONG disposition,
                               ULONG options, ULONG_PTR *information)
{
    HID_STREAM *stream = (HID_STREAM *)device->context;
    (void)relativeTo;
    (void)fileAttributes;
    if (path->Length != 0)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND; /* the device has no namespace */
    }

    /* Exactly one reader per stream: two opens of one event stream would
     * each see an arbitrary half of it, which is a data race dressed as a
     * feature. Enforced through the existing share engine rather than a
     * private flag (G10/Art. 11) -- the Io layer releases the slots on
     * close (IopCloseFileObject), so this device inherits that for free. */
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

static void HidInputCleanup(PFILE_OBJECT file)
{
    (void)file;
}

static void HidInputClose(PFILE_OBJECT file)
{
    (void)file;
}

static NTSTATUS HidInputGetInfo(PFILE_OBJECT file, IO_FILE_INFO *info)
{
    (void)file;
    memset(info, 0, sizeof(*info));
    return STATUS_SUCCESS;
}

static NTSTATUS HidInputQueryName(PFILE_OBJECT file, WCHAR *buffer, ULONG capacity,
                                  ULONG *lengthOut)
{
    const WCHAR *name = HidStreamFromFile(file)->queryName;
    ULONG full = (ULONG)KiWideStringLength(name) * sizeof(WCHAR);
    *lengthOut = full;
    ULONG copy = full <= capacity ? full : capacity;
    memcpy(buffer, name, copy);
    return full <= capacity ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;
}

/* Blocking read: returns as soon as at least one event exists, with
 * whatever else the eventq already holds. Whole events only. */
static NTSTATUS HidInputRead(PFILE_OBJECT file, void *buffer, ULONG length, ULONG_PTR *infoOut,
                             IO_CONTROL_CONTEXT *request)
{
    HID_STREAM *stream = HidStreamFromFile(file);
    (void)request; /* the HID streams block rather than pend (docs/03 CUI-5) */
    if (length == 0)
    {
        *infoOut = 0;
        return STATUS_SUCCESS;
    }
    if (length < sizeof(HID_INPUT_EVENT))
    {
        /* A buffer too small for one event can never be satisfied. Saying
         * so beats a silent zero-length read the caller would spin on. */
        return STATUS_INVALID_PARAMETER;
    }

    HID_INPUT_EVENT *out = buffer;
    ULONG capacity = length / (ULONG)sizeof(HID_INPUT_EVENT);
    for (;;)
    {
        ULONG got = 0;
        while (got < capacity && VioInputTryReadEvent(stream->source, &out[got]))
        {
            got++;
        }
        if (got != 0)
        {
            *infoOut = got * sizeof(HID_INPUT_EVENT);
            return STATUS_SUCCESS;
        }
        /* Nap one clock tick between polls (relative 100 ns units). */
        LARGE_INTEGER interval;
        interval.QuadPart = -10000; /* 1 ms */
        NTSTATUS napStatus = KeDelayExecutionThread(KernelMode, FALSE, &interval);
        if (napStatus != STATUS_SUCCESS)
        {
            /* A foreign terminate broke the nap (CUI-4): stop polling and
             * let the thread unwind to its reaping edge. */
            *infoOut = 0;
            return napStatus;
        }
    }
}

/* The pointer's one verb: its ABS_INFO ranges, as the device published
 * them (cached at init; this path never touches MMIO). */
static NTSTATUS HidPointerDeviceControl(PFILE_OBJECT file, ULONG code, const void *input,
                                        ULONG inputLength, void *output, ULONG outputLength,
                                        ULONG_PTR *infoOut, IO_CONTROL_CONTEXT *request)
{
    HID_STREAM *stream = HidStreamFromFile(file);
    (void)input;
    (void)inputLength;
    (void)request;

    if (code == IOCTL_PRSHID_GET_ABS_INFO)
    {
        if (outputLength < sizeof(HID_ABS_INFO))
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        HID_ABS_INFO info;
        info.minX = stream->source->absX.min;
        info.maxX = stream->source->absX.max;
        info.minY = stream->source->absY.min;
        info.maxY = stream->source->absY.max;
        memcpy(output, &info, sizeof(info));
        *infoOut = sizeof(info);
        return STATUS_SUCCESS;
    }

    /* Art. 12: name the refusal on serial and return the refusal status —
     * never a no-op success for a verb this device does not have. */
    DbgPrint("hid: unimplemented pointer ioctl %#lx\n", (unsigned long)code);
    return STATUS_NOT_IMPLEMENTED;
}

/* No Write and no DeviceControl on the keyboard: the statusq that would
 * carry output to the device is unconfigured (drivers/virtio/input.c), and
 * there is no ioctl verb to implement. Their absence makes the Io layer
 * refuse with its own distinct status, which is the honest answer -- a stub
 * that accepted a write and dropped it would be the bug Art. 12 is about. */
static const IO_VFS_OPS HidInputOps = {
    .Create = HidInputCreate,
    .Cleanup = HidInputCleanup,
    .Close = HidInputClose,
    .GetInfo = HidInputGetInfo,
    .QueryName = HidInputQueryName,
    .Read = HidInputRead,
};

/* The pointer stream: the same contract plus the one abs-info verb. Still
 * no Write (the statusq argument holds for both devices). */
static const IO_VFS_OPS HidPointerOps = {
    .Create = HidInputCreate,
    .Cleanup = HidInputCleanup,
    .Close = HidInputClose,
    .GetInfo = HidInputGetInfo,
    .QueryName = HidInputQueryName,
    .Read = HidInputRead,
    .DeviceControl = HidPointerDeviceControl,
};

void HidInitialize(void)
{
    if (VioInputKeyboard())
    {
        static const WCHAR keyboardName[] = WSTR("\\Input0");
        IopInitializeFcb(&HidKeyboardStream.fcb);
        HidKeyboardStream.source = VioInputKeyboard();
        HidKeyboardStream.queryName = keyboardName;
        IoPublishDevice(WSTR("\\Device\\Input0"), &HidInputOps, &HidKeyboardStream,
                        FILE_DEVICE_KEYBOARD);
        DbgPrint("hid: \\Device\\Input0 published\n");
    }
    else
    {
        DbgPrint("hid: no virtio-input keyboard; \\Device\\Input0 not published\n");
    }

    if (VioInputPointer())
    {
        static const WCHAR pointerName[] = WSTR("\\Input1");
        IopInitializeFcb(&HidPointerStream.fcb);
        HidPointerStream.source = VioInputPointer();
        HidPointerStream.queryName = pointerName;
        IoPublishDevice(WSTR("\\Device\\Input1"), &HidPointerOps, &HidPointerStream,
                        FILE_DEVICE_MOUSE);
        DbgPrint("hid: \\Device\\Input1 published (pointer)\n");
    }
    else
    {
        DbgPrint("hid: no virtio-input pointer; \\Device\\Input1 not published\n");
    }
}
