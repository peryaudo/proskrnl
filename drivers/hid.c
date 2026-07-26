/* drivers/hid.c — \Device\Input0, the raw input stream (GUI-1, HACK-002).
 *
 * Reads deliver virtio-input events verbatim (drivers/hidproto.h). There is
 * no translation here on purpose: any mapping from scancode to character is
 * a keyboard layout, and a layout belongs in user32 above the boundary, not
 * in a driver below it.
 *
 * HACK-002 (docs/10): NT routes raw input through win32k and csrss into the
 * input queue, and route (a) (docs/07) has neither, so the display backend
 * needs a raw event source. Like \Device\Fb0 this is a new device at the
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
#include "kernel/io/io.h"
#include "kernel/io/vfs.h"
#include "kernel/ke/ke.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "abi/ntstatus.h"

/* One global open context (the CondrvSerialFcb shape): the Io close hooks
 * key off a non-NULL fsContext and a valid IO_FCB, and the share-access
 * engine needs somewhere to keep this device's one open's slots. */
static IO_FCB HidInputFcb;

static NTSTATUS HidInputCreate(PIO_DEVICE device, PFILE_OBJECT file, const UNICODE_STRING *path,
                               PFILE_OBJECT relativeTo, ACCESS_MASK grantedAccess,
                               ULONG shareAccess, ULONG fileAttributes, ULONG disposition,
                               ULONG options, ULONG_PTR *information)
{
    (void)device;
    (void)relativeTo;
    (void)fileAttributes;
    (void)disposition;
    (void)options;
    if (path->Length != 0)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND; /* the device has no namespace */
    }

    /* Exactly one reader: two opens of one event stream would each see an
     * arbitrary half of it, which is a data race dressed as a feature.
     * Enforced through the existing share engine rather than a private
     * flag (G10/Art. 11) -- the Io layer releases the slots on close
     * (IopCloseFileObject), so this device inherits that for free. */
    NTSTATUS status = IoCheckShareAccess(grantedAccess, shareAccess, &HidInputFcb);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    IoSetShareAccess(grantedAccess, shareAccess, &HidInputFcb);
    file->shareCounted = TRUE;

    file->fsContext = &HidInputFcb;
    file->fcb = &HidInputFcb;
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
    (void)file;
    static const WCHAR name[] = WSTR("\\Input0");
    ULONG full = sizeof(name) - sizeof(WCHAR);
    *lengthOut = full;
    ULONG copy = full <= capacity ? full : capacity;
    memcpy(buffer, name, copy);
    return full <= capacity ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;
}

/* Blocking read: returns as soon as at least one event exists, with
 * whatever else the eventq already holds. Whole events only. */
static NTSTATUS HidInputRead(PFILE_OBJECT file, void *buffer, ULONG length, ULONG_PTR *infoOut)
{
    (void)file;
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
        while (got < capacity && VioInputTryReadEvent(VioInputKeyboard(), &out[got]))
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

/* No Write and no DeviceControl: the statusq that would carry output to
 * the device is unconfigured (drivers/virtio/input.c), and there is no
 * ioctl verb to implement. Their absence makes the Io layer refuse with
 * its own distinct status, which is the honest answer -- a stub that
 * accepted a write and dropped it would be the bug Art. 12 is about. */
static const IO_VFS_OPS HidInputOps = {
    .Create = HidInputCreate,
    .Cleanup = HidInputCleanup,
    .Close = HidInputClose,
    .GetInfo = HidInputGetInfo,
    .QueryName = HidInputQueryName,
    .Read = HidInputRead,
};

void HidInitialize(void)
{
    if (!VioInputKeyboard())
    {
        DbgPrint("hid: no virtio-input keyboard; \\Device\\Input0 not published\n");
        return;
    }
    IopInitializeFcb(&HidInputFcb);
    /* GetFileType maps FILE_DEVICE_KEYBOARD to FILE_TYPE_CHAR (Wine
     * dlls/kernelbase/file.c switches on FileFsDeviceInformation). */
    IoPublishDevice(WSTR("\\Device\\Input0"), &HidInputOps, 0, FILE_DEVICE_KEYBOARD);
    DbgPrint("hid: \\Device\\Input0 published\n");
}
