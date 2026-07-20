/* drivers/condrv.c — the console driver (M9) + its serial transport.
 *
 * This file starts with \Device\Serial0: the COM1 UART published as a plain
 * stream device, both directions. That transport is HACK-004 (docs/10) — a
 * COM port is never real NT's interactive-console backend; it is subtracted
 * when the M11+ input/display path exists. The RX side polls: the blocking
 * Read drains the FIFO or naps 1 ms and retries (no IRQ4 routing exists,
 * and the clock already ticks at 1 kHz — Art. 3 simplest-correct; 16-byte
 * FIFO at 1 kHz sustains ~16 KB/s, far past interactive typing).
 *
 * The TX side is raw — no '\n' -> '\r\n' mangling here: conhost owns the
 * console's line discipline. DbgPrint keeps its own KiSerialPutString path
 * untouched; the two interleave on the wire, which the headless test loop
 * tolerates by grepping unique markers (docs/08).
 */
#include "drivers/condrv.h"
#include "kernel/io/io.h"
#include "kernel/ke/ke.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "arch/x86_64/serial.h"

#include "abi/ntcondrv.h"

/* --- \Device\Serial0 --------------------------------------------------------- */

/* One global open context: the device is stateless per-open (conhost is the
 * only intended opener) but the Io close hooks key off a non-NULL fsContext
 * and a valid IO_FCB (kernel/io/file.c). */
static IO_FCB CondrvSerialFcb;

static NTSTATUS CondrvSerialCreate(PIO_DEVICE device, PFILE_OBJECT file, const UNICODE_STRING *path,
                                   PFILE_OBJECT relativeTo, ACCESS_MASK grantedAccess,
                                   ULONG shareAccess, ULONG fileAttributes, ULONG disposition,
                                   ULONG options, ULONG_PTR *information)
{
    (void)device;
    (void)relativeTo;
    (void)grantedAccess;
    (void)shareAccess;
    (void)fileAttributes;
    (void)disposition;
    (void)options;
    if (path->Length != 0)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND; /* the device has no namespace */
    }
    file->fsContext = &CondrvSerialFcb;
    file->fcb = &CondrvSerialFcb;
    file->isDirectory = FALSE;
    *information = FILE_OPENED;
    return STATUS_SUCCESS;
}

static void CondrvSerialCleanup(PFILE_OBJECT file)
{
    (void)file;
}

static void CondrvSerialClose(PFILE_OBJECT file)
{
    (void)file;
}

static NTSTATUS CondrvSerialGetInfo(PFILE_OBJECT file, IO_FILE_INFO *info)
{
    (void)file;
    memset(info, 0, sizeof(*info));
    return STATUS_SUCCESS;
}

static NTSTATUS CondrvSerialQueryName(PFILE_OBJECT file, WCHAR *buffer, ULONG capacity,
                                      ULONG *lengthOut)
{
    (void)file;
    static const WCHAR name[] = WSTR("\\Serial0");
    ULONG full = sizeof(name) - sizeof(WCHAR);
    *lengthOut = full;
    ULONG copy = full <= capacity ? full : capacity;
    memcpy(buffer, name, copy);
    return full <= capacity ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;
}

/* Blocking tty-style read: returns as soon as at least one byte exists,
 * with whatever else the FIFO already holds (conhost's input thread feeds
 * single keystrokes through exactly this shape). */
static NTSTATUS CondrvSerialRead(PFILE_OBJECT file, void *buffer, ULONG length, ULONG_PTR *infoOut)
{
    (void)file;
    if (length == 0)
    {
        *infoOut = 0;
        return STATUS_SUCCESS;
    }
    unsigned char *out = buffer;
    for (;;)
    {
        ULONG got = 0;
        int ch;
        while (got < length && (ch = KiSerialTryGetChar()) >= 0)
        {
            out[got++] = (unsigned char)ch;
        }
        if (got != 0)
        {
            *infoOut = got;
            return STATUS_SUCCESS;
        }
        /* Nap one clock tick between polls (relative 100 ns units). */
        LARGE_INTEGER interval;
        interval.QuadPart = -10000; /* 1 ms */
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
}

static NTSTATUS CondrvSerialWrite(PFILE_OBJECT file, const void *buffer, ULONG length,
                                  ULONG_PTR *infoOut)
{
    (void)file;
    const unsigned char *in = buffer;
    for (ULONG i = 0; i < length; i++)
    {
        KiSerialPutChar((char)in[i]);
    }
    *infoOut = length;
    return STATUS_SUCCESS;
}

static const IO_VFS_OPS CondrvSerialOps = {
    .Create = CondrvSerialCreate,
    .Cleanup = CondrvSerialCleanup,
    .Close = CondrvSerialClose,
    .GetInfo = CondrvSerialGetInfo,
    .QueryName = CondrvSerialQueryName,
    .Read = CondrvSerialRead,
    .Write = CondrvSerialWrite,
};

/* --- initialization ---------------------------------------------------------- */

static void CondrvPublishDevice(const WCHAR *name, const IO_VFS_OPS *ops)
{
    UNICODE_STRING deviceName;
    OBJECT_ATTRIBUTES attributes;
    RtlInitUnicodeString(&deviceName, name);
    memset(&attributes, 0, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &deviceName;
    attributes.Attributes = OBJ_PERMANENT;

    PVOID body;
    HANDLE handle;
    NTSTATUS status = ObpCreateObjectWithHandle(&IoDeviceType, sizeof(IO_DEVICE), &attributes,
                                                FILE_ALL_ACCESS, &body, &handle);
    if (status != STATUS_SUCCESS)
    {
        KiPanic("CondrvInitialize: cannot create a console device");
    }
    PIO_DEVICE device = body;
    device->ops = ops;
    device->context = 0;
    NtClose(handle);
}

void CondrvInitialize(void)
{
    IopInitializeFcb(&CondrvSerialFcb);
    CondrvPublishDevice(WSTR("\\Device\\Serial0"), &CondrvSerialOps);
}
