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

static NTSTATUS IopDeviceControl(HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, PVOID apcContext,
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
    /* Before the verb runs, not at completion time (io.h). */
    status = IopValidateEventHandle(event);
    if (!NT_SUCCESS(status))
    {
        return status;
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

    /* W4a: allocate the completion APC BEFORE the verb runs, through the one
     * engine (kernel/io/async.c) that rw.c and notify.c already use — so a
     * verb that pends cannot fail to complete later for want of memory, and
     * there is no second KAPC allocation site (Art. 11). A NULL routine or a
     * kernel-mode caller yields 0 and everything below is a no-op. */
    PKAPC apcBlock = 0;
    status = IopPrepareCompletionApc(apc, apcContext, iosb, &apcBlock);
    if (!NT_SUCCESS(status))
    {
        if (inBounce != 0)
        {
            MiFreePool(inBounce);
        }
        if (outBounce != 0)
        {
            MiFreePool(outBounce);
        }
        ObDereferenceObject(file);
        return status;
    }

    IO_CONTROL_CONTEXT request = {
        .eventHandle = event, .userIosb = iosb, .apcBlock = apcBlock, .apcContext = apcContext};
    /* The remaining members — the CUI-8 data legs and `pended` — are zeroed
     * by the designated initializer above; an ioctl carries no data leg (its
     * output travels in outBounce) and `pended` is the engine's answer. */
    ULONG_PTR information = 0;
    IopEnterSyncIo(iosb); /* CUI-5: a blocking verb (FSCTL_PIPE_WAIT) is cancellable */
    status = file->device->ops->DeviceControl(file, code, inBounce, inputLength, outBounce,
                                              outputLength, &information, &request);
    IopLeaveSyncIo();
    /* IOSB Information is not always an output-payload count (a console
     * WRITE_FILE reports bytes CONSUMED); copy back only what the output
     * buffer can hold. */
    ULONG copyOut = information > outputLength ? outputLength : (ULONG)information;
    if ((NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) && status != STATUS_PENDING &&
        copyOut != 0)
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
    if (request.pended)
    {
        /* The op parked an IOP_PENDING_REQUEST: the caller's IOSB stays
         * untouched until completion (pinned sem_pipe/async_listen), and the
         * APC block went WITH it — IopCompletePendingRequest queues it to
         * this thread whenever the park ends. Nothing to do here.
         *
         * The FLAG, not the status (vfs.h): STATUS_PENDING is also a legal
         * FINAL answer from a device — condrv's read path returns exactly
         * that — and a verb that answered it without parking would have its
         * APC block leaked here. No ioctl verb does today; keying on the
         * flag means none ever can. */
        ASSERT(status == STATUS_PENDING);
        ObDereferenceObject(file);
        return STATUS_PENDING;
    }
    if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW)
    {
        /* Through the SAME inline-completion tail the transfer paths use
         * (kernel/io/rw.c), not a hand-rolled one: an ioctl owes the same
         * three effects — the IOSB and event, then the completion PACKET if
         * the handle is bound to a port, then the APC. It used to call
         * IopCompleteRequest directly and so no ioctl ever produced a packet,
         * which is what ntdll:pipe:1539 convicts.
         *
         * reportsPending is FALSE: this branch returns `status` unchanged, so
         * the caller never sees STATUS_PENDING from here — the pended case
         * returned above. Pinned by sem_pipe/completion_packet.c. */
        status = IopCompleteTransfer(file, iosb, event, apcBlock, apcContext, status, information,
                                     /* reportsPending */ FALSE);
    }
    else
    {
        /* The caller's event still goes DOWN, through the same authority the
         * transfer paths use (IopAbandonRequest, kernel/io/file.c): a caller
         * that pre-signalled it sees it clear even though nothing completed
         * and the IOSB was never written. Measured on an immediate
         * STATUS_PIPE_CONNECTED listen — sem_pipe/ioctl_event.c — and
         * convicted by ntdll:pipe:413, which reads the event and the IOSB
         * together and so cannot be satisfied by the status alone. */
        IopAbandonRequest(event);
        /* A refusal that never wrote the IOSB completes nothing, so the
         * routine must NOT run — measured: an immediate STATUS_PIPE_CONNECTED
         * listen leaves the caller's IOSB poison intact and never calls back
         * (sem_pipe/listen_apc.c). Free the block rather than leak it; this
         * is the one path where the request neither pended nor completed.
         *
         * Reaching here after a device PREPARED a pending request would
         * double-free, since the request owns the same block — so that is an
         * invariant, not a coincidence: a device that calls
         * IopPreparePendingRequest must return STATUS_PENDING. npfs is the
         * only DeviceControl that pends and it does exactly that
         * (fs/npfs/pipe.c NpfsListen). */
        IopQueueCompletionApc(0, apcBlock);
    }
    ObDereferenceObject(file);
    return status;
}

NTSTATUS NtDeviceIoControlFile(HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, PVOID apcContext,
                               PIO_STATUS_BLOCK iosb, ULONG code, PVOID input, ULONG inputLength,
                               PVOID output, ULONG outputLength)
{
    return IopDeviceControl(handle, event, apc, apcContext, iosb, code, input, inputLength, output,
                            outputLength);
}

NTSTATUS NtFsControlFile(HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, PVOID apcContext,
                         PIO_STATUS_BLOCK iosb, ULONG code, PVOID input, ULONG inputLength,
                         PVOID output, ULONG outputLength)
{
    return IopDeviceControl(handle, event, apc, apcContext, iosb, code, input, inputLength, output,
                            outputLength);
}
