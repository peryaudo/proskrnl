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
    status = IopReferenceFileByHandle(handle, 0, &file, 0);
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

    IO_CONTROL_CONTEXT request = {.eventHandle = event,
                                  .userIosb = iosb,
                                  .apcBlock = apcBlock,
                                  .apcContext = apcContext,
                                  .userBuffer = output,
                                  .kernelBuffer = outBounce,
                                  .bufferLength = outputLength,
                                  .userInput = input,
                                  .charge = PsIoChargeOther};
    /* The CUI-8 data legs are the OUTPUT buffer and its bounce, because a verb
     * that PENDS still owes its caller a reply: FSCTL_PIPE_TRANSCEIVE parks for
     * the peer's message and the bytes are placed at completion, from a context
     * that is not this address space (kernel/io/async.c
     * IopCompletePendingRequest). They are the same pair rw.c's transfers hand
     * over and they carry the same ownership rule — the bounce belongs to the
     * request once, and only once, `pended` comes back TRUE, which is why the
     * free below is skipped exactly there. An ioctl that completes inline
     * ignores them and copies out through `copyOut` as it always did.
     * `pended` itself is the engine's answer, zeroed by the initializer. */
    ULONG_PTR information = 0;
    /* The signalled-state legs of a request that may PARK, through the same
     * engine the transfer paths use (kernel/io/async.c) — the caller's event
     * DOWN before the verb runs, and the FILE OBJECT down at the park.
     *
     * IopClearAtPark, where rw.c's transfers say IopClearAtIssue, and the
     * difference is the oracle's not a preference: an ioctl's verb is decided
     * ABOVE `queue_async` (server/named_pipe.c pipe_server_ioctl refuses
     * FSCTL_PIPE_LISTEN with STATUS_PIPE_CONNECTED before it, and
     * FSCTL_PIPE_PEEK never queues at all), while pipe_end_read queues every
     * request it SERVES — its own state refusals return above the queue too,
     * but it has no arm that answers a caller without queueing.
     * Measured both ways in sem_pipe/ioctl_signal.c: an
     * inline peek carrying an event leaves the handle UP, and a refused
     * listen leaves it exactly as it found it, neither of which a clear at
     * issue can do.
     *
     * Where the event's reset is measured: from a worker while a listen was
     * parked (sem_pipe/alertable_park.c case 2, ioctl_signal.c case 2), which
     * is the only sample that can tell "reset at issue" from "reset on the
     * way out". */
    IOP_BLOCKING_REQUEST blocking;
    status = IopBeginBlockingRequest(&blocking, file, event, apc, IopClearAtPark);
    if (!NT_SUCCESS(status))
    {
        /* A port-bound handle carrying an ApcRoutine (io.h
         * IopPortApcConflict). The refusal is made where the request is
         * CREATED, so it precedes every verb — an FSCTL_PIPE_PEEK that would
         * have been answered inline and never queued is refused just the
         * same. Nothing was issued: the event is down from the reset above,
         * the handle was never cleared (IopClearAtPark), the IOSB is
         * untouched and the completion routine must not run. */
        if (inBounce != 0)
        {
            MiFreePool(inBounce);
        }
        if (outBounce != 0)
        {
            MiFreePool(outBounce);
        }
        if (apcBlock != 0)
        {
            MiFreePool(apcBlock);
        }
        ObDereferenceObject(file);
        return status;
    }
    IopEnterSyncIo(file, iosb); /* CUI-5: a blocking verb (FSCTL_PIPE_WAIT) is cancellable */
    status = file->device->ops->DeviceControl(file, code, inBounce, inputLength, outBounce,
                                              outputLength, &information, &request);
    IopLeaveSyncIo();
    /* A user APC broke an alertable park (io.h IoSyncIoAlerted): the verb
     * completed nothing, so nothing below it may run. */
    BOOLEAN alerted = IoSyncIoAlerted();
    /* Did the verb reach the park — i.e. would the oracle have QUEUED it —
     * which is the only thing separating IopRequestRefused from
     * IopRequestFailedParked (io.h IoSyncIoParked). Read before anything
     * below can open a new span. */
    BOOLEAN parked = IoSyncIoParked();
    /* IOSB Information is not always an output-payload count (a console
     * WRITE_FILE reports bytes CONSUMED); copy back only what the output
     * buffer can hold. */
    ULONG copyOut = information > outputLength ? outputLength : (ULONG)information;
    if (!alerted && (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) &&
        status != STATUS_PENDING && copyOut != 0)
    {
        memcpy(output, outBounce, copyOut); /* probed above */
    }
    if (inBounce != 0)
    {
        /* The INPUT bounce is never the request's: a verb that pends has
         * already consumed it (FSCTL_PIPE_TRANSCEIVE queues its message before
         * it parks), so nothing after this point can read it. */
        MiFreePool(inBounce);
    }
    if (outBounce != 0 && !request.pended)
    {
        /* The OUTPUT bounce moved INTO the request when the verb parked, and
         * IopCompletePendingRequest is what frees it — exactly the rw.c rule
         * for the same buffer. */
        MiFreePool(outBounce);
    }
    if (alerted)
    {
        /* Neither completed nor pended: the caller's IOSB keeps whatever it
         * held, the event stays as the reset above left it, and the
         * completion routine must NOT run — the same "no IOSB write, no APC"
         * invariant the refusal arm below states, reached for a different
         * reason. The status is the wait's own, returned unchanged.
         *
         * A device that PENDED cannot also have parked this thread, so the
         * two branches are exclusive; the assert convicts the day one is. */
        ASSERT(!request.pended);
        ASSERT(status == STATUS_USER_APC || status == STATUS_ALERTED);
        /* The handle stays DOWN: the oracle's async is still queued and only
         * the client stopped waiting, so async_set_result never runs (io.h
         * IopRequestInterrupted). */
        IopEndBlockingRequest(&blocking, IopRequestInterrupted);
        IopQueueCompletionApc(0, apcBlock);
        ObDereferenceObject(file);
        return status;
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
         * flag means none ever can.
         *
         * No IopEndBlockingRequest either: the handle was taken down by
         * IopPreparePendingRequest and it is the COMPLETION that puts it back
         * (kernel/io/async.c IopCompletePendingRequest), from whatever context
         * ends the park. */
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
                                     /* reportsPending */ FALSE, PsIoChargeOther);
        /* IopCompleteTransfer took the EVENT arm of "exactly one"; this takes
         * the FILE-OBJECT arm when there was no event. An ioctl that completed
         * INLINE never cleared the handle, and signalling it here is still
         * right: the oracle's guard is `async->pending || !NT_ERROR( status )`
         * (server/async.c), so a success reaches the signal block whether or
         * not it was ever queued (sem_pipe/ioctl_signal.c case 5b). */
        IopEndBlockingRequest(&blocking, IopRequestCompleted);
    }
    else
    {
        /* The caller's event stays DOWN where the issue put it: a caller that
         * pre-signalled it sees it clear even though nothing completed and the
         * IOSB was never written (convicted by ntdll:pipe:413, which reads the
         * event and the IOSB together and so cannot be satisfied by the status
         * alone; measured on an immediate STATUS_PIPE_CONNECTED listen,
         * sem_pipe/ioctl_event.c).
         *
         * Which arm depends on whether the verb was QUEUED, and only the
         * engine knows: a listen refused above the queue reaches nothing and
         * leaves both the event and the handle exactly as it found them, while
         * one CANCELLED mid-park still reaches async_set_result and signals
         * the caller's event — or, with no event, puts the handle back up.
         * That second case is ntdll:pipe's test_cancelsynchronousio
         * (sem_pipe/ioctl_signal.c cases 6 and 7). */
        IopEndBlockingRequest(&blocking, parked ? IopRequestFailedParked : IopRequestRefused);
        /* The completion ROUTINE splits on the same question, because the
         * oracle decides all three inside one guard (io.h
         * IopEndFailedRequestApc): a refusal that never wrote the IOSB runs
         * nothing — measured on an immediate STATUS_PIPE_CONNECTED listen,
         * which leaves the caller's IOSB poison intact and never calls back
         * (sem_pipe/listen_apc.c) — while a listen CANCELLED mid-park does run
         * it, with that same untouched IOSB as its argument
         * (sem_pipe/ioctl_signal.c case 6). Either way the block leaves here;
         * this is the one path where the request neither pended nor completed.
         *
         * Reaching here after a device PREPARED a pending request would
         * double-free — the request owns the same APC block, and since this
         * item, the same output bounce — so that is an invariant, not a
         * coincidence: a device that calls IopPreparePendingRequest must return
         * STATUS_PENDING. npfs is the only DeviceControl that pends, and both
         * of its pending verbs do exactly that (fs/npfs/pipe.c NpfsListen and
         * NpfsTransceive, the latter through NpfsAwaitRead). */
        IopEndFailedRequestApc(apcBlock, parked);
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
