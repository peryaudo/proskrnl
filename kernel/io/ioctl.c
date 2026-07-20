/* kernel/io/ioctl.c — NtDeviceIoControlFile / NtFsControlFile (M9).
 *
 * Both services funnel into the device's single DeviceControl op: NT routes
 * ioctls and fsctls through different IRP majors, but nothing an unprivileged
 * client can observe distinguishes them at this boundary, and proskrnl has no
 * IRP (docs/03). Buffers are bounced through pool because a verb may block
 * (FSCTL_PIPE_LISTEN, a console read) — the completion protocol is the same
 * as rw.c: everything finishes before the syscall returns, the IOSB is
 * written before the optional event fires (IopCompleteRequest).
 */
#include "kernel/io/io.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/string.h"

/* A user-mode ApcRoutine needs completion plumbing this path does not have;
 * refuse loudly rather than dropping the completion (as kernel/io/rw.c). */
static BOOLEAN IopIoctlApcUnsupported(PIO_APC_ROUTINE apcRoutine)
{
    return apcRoutine != 0 && ExGetPreviousMode() == UserMode;
}

static NTSTATUS IopDeviceControl(HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc,
                                 PIO_STATUS_BLOCK iosb, ULONG code, PVOID input, ULONG inputLength,
                                 PVOID output, ULONG outputLength)
{
    if (iosb == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(iosb, sizeof(*iosb), sizeof(void *));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (IopIoctlApcUnsupported(apc))
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    if (inputLength != 0)
    {
        status = KiProbeForRead(input, inputLength, 1);
    }
    if (NT_SUCCESS(status) && outputLength != 0)
    {
        status = KiProbeForWrite(output, outputLength, 1);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PFILE_OBJECT file;
    status = IopReferenceFileByHandle(handle, 0, &file);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (file->device->ops->DeviceControl == 0)
    {
        /* A disk file: no control verbs at this boundary. */
        ObDereferenceObject(file);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    void *inBounce = 0;
    void *outBounce = 0;
    if (inputLength != 0)
    {
        inBounce = MiAllocatePool(inputLength);
        if (inBounce == 0)
        {
            ObDereferenceObject(file);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memcpy(inBounce, input, inputLength); /* probed above */
    }
    if (outputLength != 0)
    {
        outBounce = MiAllocatePool(outputLength);
        if (outBounce == 0)
        {
            if (inBounce != 0)
            {
                MiFreePool(inBounce);
            }
            ObDereferenceObject(file);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memset(outBounce, 0, outputLength);
    }

    ULONG_PTR information = 0;
    status = file->device->ops->DeviceControl(file, code, inBounce, inputLength, outBounce,
                                              outputLength, &information);
    /* IOSB Information is not always an output-payload count (a console
     * WRITE_FILE reports bytes CONSUMED); copy back only what the output
     * buffer can hold. */
    ULONG copyOut = information > outputLength ? outputLength : (ULONG)information;
    if ((NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) && copyOut != 0)
    {
        memcpy(output, outBounce, copyOut); /* probed above */
    }
    if (inBounce != 0)
    {
        MiFreePool(inBounce);
    }
    if (outBounce != 0)
    {
        MiFreePool(outBounce);
    }
    if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW)
    {
        status = IopCompleteRequest(iosb, event, status, information);
    }
    ObDereferenceObject(file);
    return status;
}

NTSTATUS NtDeviceIoControlFile(HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, PVOID apcContext,
                               PIO_STATUS_BLOCK iosb, ULONG code, PVOID input, ULONG inputLength,
                               PVOID output, ULONG outputLength)
{
    (void)apcContext;
    return IopDeviceControl(handle, event, apc, iosb, code, input, inputLength, output,
                            outputLength);
}

NTSTATUS NtFsControlFile(HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, PVOID apcContext,
                         PIO_STATUS_BLOCK iosb, ULONG code, PVOID input, ULONG inputLength,
                         PVOID output, ULONG outputLength)
{
    (void)apcContext;
    return IopDeviceControl(handle, event, apc, iosb, code, input, inputLength, output,
                            outputLength);
}
