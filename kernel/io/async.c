/* kernel/io/async.c — the pending-request engine (CUI-3).
 *
 * Inline completion is the Io layer's current position, not a rule handed
 * down by Art. 3 (whose mandates are no-COW / no-eviction / one-lock-
 * uniprocessor-no-preemption / one-pool, and say nothing about I/O): NT
 * permits STATUS_PENDING and never requires it, so completing inside the
 * syscall is legal exactly while the device completes in bounded time
 * (docs/19 §1). DATA transfers still complete inline; FSCTL_PIPE_LISTEN on
 * an asynchronous handle genuinely pends (docs/03 "CUI-3 SCM notes") because
 * rpcrt4's ncacn_np server loop deadlocks on a blocking listen — it issues
 * listens on every endpoint while holding the protseq CS and only then
 * waits (dlls/rpcrt4/rpc_transport.c rpcrt4_protseq_np_get_wait_array).
 *
 * The shape: the issuer resolves everything context-dependent up front
 * (IopPreparePendingRequest — event body, owning process), the filesystem
 * parks the request, and whoever completes it later (a connecting client's
 * thread, a cancel, the owner's cleanup) writes the IOSB into the OWNER's
 * address space and only then signals the event. One dispatcher lock, no
 * preemption: park and completion never interleave mid-update.
 */
#include "kernel/io/io.h"
#include "kernel/mm/pool.h"
#include "kernel/mm/virtual.h"
#include "kernel/ps/ps.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

/* "The Io layer does not own this file object's signalled state." Two
 * reasons, and both belong in the transition rather than at its call sites —
 * the oracle puts the first one inside `set_fd_signaled` itself (server/fd.c:
 * `if (fd->comp_flags & FILE_SKIP_SET_EVENT_ON_HANDLE) return;`) so that
 * every producer inherits it instead of remembering it.
 *
 *  1. FILE_SKIP_SET_EVENT_ON_HANDLE freezes the state in BOTH directions,
 *     for the handle's whole life. The caller's own EVENT is unaffected: the
 *     flag is about the handle, and the oracle's event signal does not go
 *     through this path at all.
 *  2. The DEVICE drives `header` itself (io.h deviceManagedSignal) — condrv,
 *     whose server handle is conhost's wait handle. This used to be an
 *     unwritten exception that the Io layer paid for by never re-signalling a
 *     file object on an inline completion AT ALL; stating it here is what
 *     lets every other device get the NT rule.
 */
static BOOLEAN IopFileSignalSuppressed(PFILE_OBJECT file)
{
    return (file->completionFlags & FILE_SKIP_SET_EVENT_ON_HANDLE) != 0 ||
           file->deviceManagedSignal;
}

void IopSignalRequestCompletion(PKEVENT event, PFILE_OBJECT file)
{
    if (event != 0)
    {
        KeSetEvent(event, 0, FALSE);
    }
    else if (file != 0 && !IopFileSignalSuppressed(file))
    {
        KeSetEvent(&file->header, 0, FALSE);
    }
}

void IopMarkRequestOutstanding(PFILE_OBJECT file)
{
    if (file != 0 && !IopFileSignalSuppressed(file))
    {
        KeClearEvent(&file->header);
    }
}

BOOLEAN IopPortApcConflict(PFILE_OBJECT file, PIO_APC_ROUTINE apcRoutine)
{
    /* The rule and its citation are in io.h — one statement, applied at each
     * service's own issue point. */
    return file != 0 && file->completionPort != 0 && apcRoutine != 0;
}

NTSTATUS IopBeginBlockingRequest(IOP_BLOCKING_REQUEST *request, PFILE_OBJECT file,
                                 HANDLE eventHandle, PIO_APC_ROUTINE apcRoutine,
                                 IOP_BLOCKING_CLEAR when)
{
    request->file = file;
    request->eventHandle = eventHandle;
    request->clearedAtIssue = when == IopClearAtIssue;
    /* Read BEFORE the clear: IopRequestRefused restores this, and "was it up"
     * is not recoverable afterwards. A suppressed handle (io.h
     * deviceManagedSignal / FILE_SKIP_SET_EVENT_ON_HANDLE) is never touched
     * by either half, so the value is unused there rather than wrong. */
    request->handleWasSignalled = file != 0 && KeReadStateEvent(&file->header) != 0;
    IopResetRequestEvent(eventHandle);
    /* create_async's last statement, in create_async's place: the event above
     * is already down and the handle below has not been touched, which is
     * exactly what the oracle leaves behind (io.h IopPortApcConflict). */
    if (IopPortApcConflict(file, apcRoutine))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->clearedAtIssue)
    {
        IopMarkRequestOutstanding(file);
    }
    else
    {
        /* The clear waits for the park, which is the oracle's own position
         * (io.h). Handed to the ENGINE rather than to the device:
         * IoWaitCancellable is the one place the Io layer's blocking park
         * happens, and IopPreparePendingRequest already does the same thing
         * for the arm that pends instead. */
        KeGetCurrentThread()->syncIoParkFile = file;
    }
    return STATUS_SUCCESS;
}

void IopEndBlockingRequest(IOP_BLOCKING_REQUEST *request, IOP_BLOCKING_OUTCOME outcome)
{
    switch (outcome)
    {
    case IopRequestCompleted:
        /* The EVENT arm was taken by IopCompleteRequest, which had to write
         * the IOSB first; only the file-object arm is left. */
        if (request->eventHandle == 0)
        {
            IopSignalRequestCompletion(0, request->file);
        }
        break;
    case IopRequestFailedParked:
        /* Same exclusivity, no IOSB: a queued request that fails still
         * reaches the oracle's signal block. */
        if (request->eventHandle != 0)
        {
            IopSetRequestEvent(request->eventHandle);
        }
        else
        {
            IopSignalRequestCompletion(0, request->file);
        }
        break;
    case IopRequestRefused:
        /* The oracle's refusal is above queue_async, so the handle is exactly
         * as the caller found it — which is NOT the same as signalled: a read
         * that completed through an event left it down, and a refusal that
         * followed must leave it there. The event stays reset.
         *
         * Only an AtIssue request has anything to put back: an AtPark one
         * that never reached its park never cleared the handle, and
         * re-signalling it here would be this arm's own defect one direction
         * over (io.h). */
        if (request->clearedAtIssue && request->handleWasSignalled)
        {
            IopSignalRequestCompletion(0, request->file);
        }
        break;
    case IopRequestInterrupted:
        /* Nothing: the request is still outstanding as far as the device is
         * concerned, and the caller merely stopped waiting for it (io.h). */
        break;
    }
}

NTSTATUS IopPreparePendingRequest(PFILE_OBJECT file, IO_CONTROL_CONTEXT *request,
                                  PIOP_PENDING_REQUEST *out)
{
    PIOP_PENDING_REQUEST pending = MiAllocatePool(sizeof(*pending));
    if (pending == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memset(pending, 0, sizeof(*pending));

    if (request->eventHandle != 0)
    {
        /* Resolve the handle NOW: the completer runs in another process's
         * context where this handle means nothing. */
        PVOID eventBody;
        NTSTATUS status =
            ObReferenceObjectByHandle(request->eventHandle, EVENT_MODIFY_STATE, &ObpEventType,
                                      ExGetPreviousMode(), &eventBody, 0);
        if (!NT_SUCCESS(status))
        {
            MiFreePool(pending);
            return status;
        }
        pending->event = eventBody;
        /* NT resets the caller's event when the operation is submitted —
         * rpcrt4's server caches MANUAL-RESET events and relies on exactly
         * this (a stale signalled event would fire its accept loop against
         * a stale IOSB forever; pinned async_listen.c). */
        KeClearEvent(pending->event);
    }

    PEPROCESS owner = KeGetCurrentThread()->process;
    ObfReferenceObject(owner);
    pending->owner = owner;
    pending->userIosb = request->userIosb;
    pending->kernelIosb = ExGetPreviousMode() == KernelMode;
    pending->issuer = KeGetCurrentThread();
    /* W4a: the completion APC is queued to that thread, so the request must
     * keep it ALIVE — a parked listen outlives its issuer (docs/03 "CUI-3
     * SCM notes": nothing sweeps one at thread exit), and queueing into a
     * freed KTHREAD is the hazard. Mirrors IOP_DIR_WATCH (kernel/io/
     * notify.c), which needs the reference for the same reason. */
    pending->issuerObject = pending->issuer->threadObject;
    if (pending->issuerObject != 0)
    {
        ObfReferenceObject(pending->issuerObject);
    }
    /* The APC block moves INTO the request here. From this point the request
     * owns it, and IopCompletePendingRequest is the only place it leaves —
     * which is what makes "queued or freed exactly once" true for every way
     * a park can end (io.h). A device that prepares a request MUST then
     * return STATUS_PENDING; anything else would leave ioctl.c's failure
     * branch freeing a block this request also owns. */
    pending->apcBlock = request->apcBlock;
    pending->apcContext = request->apcContext;
    /* Captured, where the packet's port is read late — io.h says why the two
     * instants are different questions. */
    pending->portBoundAtIssue = file->completionPort != 0;
    /* The completion PACKET leg: the port is read off the file object at
     * completion (io.h says why it is late rather than captured), so the
     * request holds the handle open for exactly as long as it can complete —
     * the same statement issuerObject makes about the issuing thread. */
    pending->file = file;
    ObfReferenceObject(file);
    /* CUI-8: the data legs move in with the same "the request owns it now"
     * rule as the APC block (vfs.h). */
    pending->userBuffer = request->userBuffer;
    pending->kernelBuffer = request->kernelBuffer;
    pending->bufferLength = request->bufferLength;
    /* Which IO_COUNTERS pair this will charge `owner` when it completes —
     * captured here because the completer no longer knows the verb. */
    pending->charge = request->charge;
    /* A request is now OUTSTANDING on this handle, so the file object is
     * busy until it completes — unconditionally, event or not. */
    IopMarkRequestOutstanding(file);
    /* The engine marks the park, not the device (vfs.h): NT's
     * IoMarkIrpPending, and for NT's reason — STATUS_PENDING as a status is
     * ambiguous, since condrv answers it as a FINAL status. Set here, at the
     * one place a park can be created, so no device can park and forget. */
    request->pended = TRUE;
    *out = pending;
    return STATUS_SUCCESS;
}

void IopCompletePendingRequest(PIOP_PENDING_REQUEST request, NTSTATUS status, ULONG_PTR information)
{
    IO_STATUS_BLOCK iosb;
    iosb.Status = status;
    iosb.Information = information;
    /* CUI-8: the DATA before the IOSB, because the IOSB is what tells the
     * caller the bytes are there (docs/19 §1.2 one level down — the same
     * ordering argument, applied inside the completion). The count is the
     * FS's, and it can never exceed what the caller asked for: the bounce
     * itself is bufferLength bytes, so the clamp is a bound on the copy, not
     * a correction of the status.
     *
     * Checked, cross-address-space, and for the IOSB's reason: `owner` is
     * not the completing context (the peer's write, a cancel, the handle's
     * cleanup), and a caller that unmapped its own buffer while the read was
     * parked gets no bytes rather than a halted kernel. */
    if (request->kernelBuffer != 0 && information != 0)
    {
        ULONG bytes =
            information < request->bufferLength ? (ULONG)information : request->bufferLength;
        if (request->kernelIosb)
        {
            memcpy(request->userBuffer, request->kernelBuffer, bytes); /* a global buffer */
        }
        else
        {
            MiCopyToUserRangeChecked(&request->owner->addressSpace,
                                     (uint64_t)(uintptr_t)request->userBuffer,
                                     request->kernelBuffer, bytes);
        }
    }
    if (request->kernelIosb)
    {
        *request->userIosb = iosb; /* a kernel-mode issuer's IOSB is global */
    }
    else
    {
        /* The issue-time probe faulted the page in and required it writable,
         * and no eviction (Art. 3) keeps it resident -- but the owner may
         * have freed it while the request was parked, which is why this is
         * the CHECKED copy. MiCopyToUserRange asserts on a missing frame, so
         * NtNotifyChangeDirectoryFile + NtFreeVirtualMemory + touch the
         * directory used to halt the kernel (docs/review-2026-07 §2). A
         * caller that unmaps its own IOSB gets no IOSB; there is nobody left
         * to report a status to. */
        MiCopyToUserRangeChecked(&request->owner->addressSpace,
                                 (uint64_t)(uintptr_t)request->userIosb, &iosb, sizeof(iosb));
    }
    /* The owner's IO_COUNTERS, charged at the same point the inline tail
     * charges (kernel/io/rw.c IopCompleteTransfer) and against the same
     * process: the ISSUER, which is `owner` rather than whoever is
     * completing — a peer's write, a cancel, the handle's cleanup.
     *
     * Only a request that COMPLETED is an operation, and WHICH statuses
     * those are is io.h's predicate rather than a second opinion here — the
     * two tails disagreed about STATUS_END_OF_FILE while this arm spelled
     * the rule for itself. */
    if (IopChargesIoCounters(status))
    {
        PsChargeIoCounters(request->owner, request->charge, (uint64_t)information);
    }
    /* The event when there was one, the FILE OBJECT otherwise — never both,
     * through the one authority that states it (io.h
     * IopSignalRequestCompletion). */
    IopSignalRequestCompletion(request->event, request->file);
    if (request->event != 0)
    {
        ObDereferenceObject(request->event);
    }
    /* The completion PACKET, in the same position the inline tail puts it
     * (kernel/io/rw.c): after the IOSB and the event, before the APC.
     *
     * A request that PENDED always posts, and that is the whole point rather
     * than a detail: the oracle's guards read `req->async ||
     * !(comp_flags & SKIP…)` (server/fd.c add_fd_completion) and
     * `async->pending || !NT_ERROR(status)` (server/async.c async_set_result),
     * so neither FILE_SKIP_COMPLETION_PORT_ON_SUCCESS nor a failing status
     * withholds it — hence `suppressed` FALSE here, and hence a CANCELLED
     * listen posting its cancel. A caller holding ERROR_IO_PENDING has
     * nothing else to wait on, so a kernel that skips either case hangs
     * GetQueuedCompletionStatus forever. Pinned by
     * tests/ntapi/sem_pipe/pending_packet.c.
     *
     * The oracle posts BEFORE it signals (server/async.c async_set_result),
     * and the order here is the inline tail's instead. Not observable while
     * Art. 3's uniprocessor/no-preemption mandate holds — nothing runs
     * between these two statements — so it is written for consistency with
     * rw.c rather than against the oracle. Worth revisiting if docs/18's SMP
     * exit is ever taken. */
    IopPostRequestPacket(request->file, request->apcBlock, request->apcContext,
                         /* suppressed */ FALSE, status, information);
    /* W4a: the APC last, AFTER the IOSB is written and the event signalled —
     * the routine's only argument is a pointer to that IOSB, so it must be
     * final before the routine can run. Queued to the ISSUER, not to
     * whoever is completing: the completer is usually another thread
     * entirely (a connecting client, a canceller, the owner's cleanup).
     * IopQueueCompletionApc eats the block for a dead or dying issuer, so
     * this is also the free path — the request never owns it afterwards. */
    IopQueueCompletionApc(request->issuer, request->apcBlock);
    if (request->issuerObject != 0)
    {
        ObDereferenceObject(request->issuerObject);
    }
    /* Never the last reference, and that is structural rather than lucky:
     * the completing paths are a peer's syscall, a cancel, or the cleanup
     * hook — and the handle's own reference is dropped only AFTER
     * closeProcedure returns (kernel/ob/handle.c ObpCloseHandleEntryIn), so
     * even the cleanup case still has one outstanding. */
    ObDereferenceObject(request->file);
    ObDereferenceObject(request->owner);
    if (request->kernelBuffer != 0)
    {
        MiFreePool(request->kernelBuffer);
    }
    MiFreePool(request);
}

/* --- the cancel sweeps (CUI-3, and the handle-close one) -------------------- */

BOOLEAN IopCancelFilterMatches(const IOP_PENDING_REQUEST *request, const IOP_CANCEL_FILTER *filter)
{
    if (filter->issuer != 0 && request->issuer != filter->issuer)
    {
        return FALSE;
    }
    if (filter->userIosb != 0 && request->userIosb != filter->userIosb)
    {
        return FALSE;
    }
    if (filter->owner != 0 && request->owner != filter->owner)
    {
        return FALSE;
    }
    if (filter->portBoundApcNoEvent &&
        (!request->portBoundAtIssue || request->apcContext == 0 || request->event != 0))
    {
        return FALSE;
    }
    return TRUE;
}

void IopCancelProcessRequestsOnClose(PFILE_OBJECT file, PEPROCESS process)
{
    IOP_CANCEL_FILTER filter;
    memset(&filter, 0, sizeof(filter));
    filter.owner = process;
    filter.portBoundApcNoEvent = TRUE;
    /* Only a device that PARKS requests, and only through its own queues.
     * Directory watches are deliberately NOT swept here: the oracle hangs this
     * rule off the two pipe-end object types and off sockets
     * (server/named_pipe.c pipe_server_ops / pipe_client_ops close_handle,
     * server/sock.c sock_close_handle), while a change-notify directory has a
     * close_handle of its own that only releases a cache entry
     * (server/change.c dir_close_handle). So "which objects owe this sweep" is
     * exactly "which devices can park a request", and no branch here has to
     * name a device. */
    if (file->device->ops->CancelPending != 0)
    {
        file->device->ops->CancelPending(file, &filter);
    }
}

/* --- NtCancelIoFile / NtCancelIoFileEx (CUI-3) ----------------------------- */

/* services.exe's process_send_start_message drives CancelIo against a STACK
 * OVERLAPPED on its control-pipe timeout path (services.c) — a pending op
 * that could not be cancelled would complete into a dead stack frame later.
 * Oracle shape (wine/dlls/ntdll/unix/file.c cancel_io + server/async.c
 * cancel_async, pinned sem_pipe/async_listen.c): the thread-scoped verb
 * succeeds even when nothing pends; the Ex form answers STATUS_NOT_FOUND;
 * both write the cancel call's own IOSB with the verdict; an invalid handle
 * returns without touching it. */
static NTSTATUS IopCancelIo(HANDLE handle, PKTHREAD issuer, PIO_STATUS_BLOCK targetIosb,
                            PIO_STATUS_BLOCK ioStatus)
{
    if (ioStatus == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(ioStatus, sizeof(*ioStatus), sizeof(void *));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* ANY object resolves (wineserver's cancel_async takes any handle — a
     * cancel on an event simply finds nothing; pinned async_listen.c);
     * only files can carry pending requests. */
    PVOID body;
    status = ObReferenceObjectByHandle(handle, 0, 0, ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    ULONG cancelled = 0;
    if (ObpGetHeader(body)->type == &IoFileObjectType)
    {
        PFILE_OBJECT file = body;
        IOP_CANCEL_FILTER filter;
        memset(&filter, 0, sizeof(filter));
        filter.issuer = issuer;
        filter.userIosb = targetIosb;
        if (file->device->ops->CancelPending != 0)
        {
            cancelled = file->device->ops->CancelPending(file, &filter);
        }
        /* CUI-5: parked directory watches are kernel-owned — sweep them
         * here rather than through a second per-FS cancel path (Art. 11). */
        cancelled += IopCancelDirectoryWatches(file, issuer, targetIosb);
    }
    /* Thread-scoped (issuer != 0): success regardless; by-IOSB/all: the
     * count decides. */
    status = (issuer != 0 || cancelled != 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
    ioStatus->Status = status;
    ioStatus->Information = 0;
    ObDereferenceObject(body);
    return status;
}

NTSTATUS NtCancelIoFile(HANDLE handle, PIO_STATUS_BLOCK ioStatus)
{
    return IopCancelIo(handle, KeGetCurrentThread(), 0, ioStatus);
}

NTSTATUS NtCancelIoFileEx(HANDLE handle, PIO_STATUS_BLOCK targetIosb, PIO_STATUS_BLOCK ioStatus)
{
    /* `targetIosb` identifies the request (NULL = all on the handle); it is
     * compared against the parked VA, never dereferenced. */
    return IopCancelIo(handle, 0, targetIosb, ioStatus);
}

/* --- CUI-5: NtCancelSynchronousIoFile ---------------------------------------- */

/* Mark/unmark the current thread's in-flight synchronous I/O. The Io layer
 * wraps every potentially-blocking device op (kernel/io/rw.c, ioctl.c) so a
 * canceller can find the op by thread; the user IOSB VA is the filter key
 * the pinned Wine's cancel_sync compares (never dereferenced here). */
/* --- the completion-APC leg (one authority — io.h) ------------------------- */

NTSTATUS IopPrepareCompletionApc(PIO_APC_ROUTINE apcRoutine, PVOID apcContext,
                                 PIO_STATUS_BLOCK iosb, PKAPC *apcOut)
{
    *apcOut = 0;
    if (apcRoutine == 0 || ExGetPreviousMode() != UserMode)
    {
        return STATUS_SUCCESS;
    }
    PKAPC apc = MiAllocatePool(sizeof(KAPC));
    if (apc == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    apc->normalRoutine = (uint64_t)(uintptr_t)apcRoutine;
    apc->normalContext = (ULONG_PTR)apcContext;
    apc->systemArgument1 = (ULONG_PTR)iosb; /* the caller's very IOSB */
    apc->systemArgument2 = 0;               /* the reserved argument */
    *apcOut = apc;
    return STATUS_SUCCESS;
}

void IopEndFailedRequestApc(PKAPC apc, BOOLEAN parked)
{
    /* The completion ROUTINE's arm of a FAILED request, which is decided by
     * the same question IopEndBlockingRequest answers for the event and the
     * handle: server/async.c's async_set_result queues APC_USER, posts the
     * packet and signals all inside one guard, `async->pending ||
     * !NT_ERROR( status )`. So a request that was QUEUED runs its routine even
     * though it failed — with an IOSB nobody wrote, because the failing tail
     * leaves the caller's block alone — while one refused above the queue runs
     * nothing (sem_pipe/listen_apc.c). Measured on both tails
     * (sem_pipe/blocking_signal.c case 6, sem_pipe/ioctl_signal.c case 6).
     *
     * Queued to THIS thread: a blocking request's failure is reported on the
     * caller's own return, so the issuer is the current thread by
     * construction. */
    IopQueueCompletionApc(parked ? KeGetCurrentThread() : 0, apc);
}

void IopQueueCompletionApc(PKTHREAD issuer, PKAPC apc)
{
    if (apc == 0)
    {
        return;
    }
    if (issuer == 0 || issuer->terminating)
    {
        MiFreePool(apc); /* the dying issuer's next edge is the reaper */
        return;
    }
    KiInsertQueueUserApc(issuer, apc);
}

BOOLEAN IoSyncIoCancelled(void)
{
    PKTHREAD self = KeGetCurrentThread();
    return self->syncIoActive && self->syncIoCancelled;
}

BOOLEAN IoSyncIoParked(void)
{
    return KeGetCurrentThread()->syncIoParked;
}

BOOLEAN IoSyncIoAlerted(void)
{
    return KeGetCurrentThread()->syncIoAlerted;
}

void IopEnterSyncIo(PFILE_OBJECT file, void *userIosb)
{
    PKTHREAD self = KeGetCurrentThread();
    self->syncIoUserIosb = userIosb;
    self->syncIoCancelled = FALSE;
    self->syncIoParked = FALSE;
    /* The handle's word, read ONCE per request at the one place the span is
     * opened — the oracle asks the same question once per call, off the
     * create options it kept (dlls/ntdll/unix/file.c: `options &
     * FILE_SYNCHRONOUS_IO_ALERT` handed to wait_async by server_read_file,
     * server_write_file and server_ioctl_file). A 0 `file` means "this
     * service waits non-alertably whatever the handle says", which is the
     * FLUSH — NtFlushBuffersFileEx passes a literal FALSE (rw.c says so at
     * the site). */
    self->syncIoAlertable = file != 0 && (file->modeFlags & FILE_SYNCHRONOUS_IO_ALERT) != 0;
    self->syncIoAlerted = FALSE;
    KeClearEvent(&self->syncIoCancelEvent);
    self->syncIoActive = TRUE;
    /* An unclosed span leaves the thread advertising a cancellable request
     * that no longer exists, so a later NtCancelSynchronousIoFile matches it
     * and reports success against nothing (issue #96 B). */
    KiPushObligation(KI_OBLIGATION_SYNC_IO, userIosb);
}

void IopLeaveSyncIo(void)
{
    PKTHREAD self = KeGetCurrentThread();
    KiPopObligation(KI_OBLIGATION_SYNC_IO, self->syncIoUserIosb);
    self->syncIoActive = FALSE;
    self->syncIoUserIosb = 0;
    /* The span ends here on EVERY path, which is what makes this the one
     * place that can retire the park's file object: the arm that PENDS
     * returns without an IopEndBlockingRequest at all, so clearing it there
     * would leave a stale pointer for this thread's next request to unsignal
     * (ke.h syncIoParkFile). Not a reference — the caller holds the file
     * object for the whole span. */
    self->syncIoParkFile = 0;
}

/* A cancellable park for blocking device waits (npfs): the device's wake
 * event OR this thread's cancel event, whichever fires first (timeout
 * optional, the KeWaitFor* convention). */
NTSTATUS IoWaitCancellable(PKEVENT event, PLARGE_INTEGER timeout)
{
    PKTHREAD self = KeGetCurrentThread();
    /* The one place the Io layer's own blocking park happens, so the one
     * place that can answer "was this request queued" for the completion
     * (io.h IoSyncIoParked). */
    self->syncIoParked = TRUE;
    /* …and therefore the one place an IopClearAtPark request's handle can go
     * down at the oracle's own position — `queue_async` is reached only when
     * the verb could not be answered above it (io.h). Idempotent, so npfs's
     * listen loop re-entering the park costs nothing. */
    if (self->syncIoParkFile != 0)
    {
        IopMarkRequestOutstanding(self->syncIoParkFile);
    }
    void *objects[2] = {event, &self->syncIoCancelEvent};
    NTSTATUS status = KeWaitForMultipleObjects(2, objects, WaitAny, Executive, KernelMode,
                                               self->syncIoAlertable, timeout, 0);
    if (self->syncIoCancelled)
    {
        /* A landed cancel outranks an alert that arrived with it: the cancel
         * writes the caller's IOSB and the alert writes nothing, so reporting
         * the alert would lose a completion the canceller was promised. */
        return STATUS_CANCELLED;
    }
    if (status == STATUS_USER_APC || status == STATUS_ALERTED)
    {
        /* Recorded here, not inferred from the status by the tails (io.h
         * IoSyncIoAlerted): STATUS_USER_APC is an NT_SUCCESS value. */
        self->syncIoAlerted = TRUE;
    }
    return status;
}

/* The by-thread cancel (CancelSynchronousIo). Contract: pinned Wine
 * dlls/ntdll/unix/file.c + server/async.c cancel_sync (the thread handle
 * is resolved with THREAD_TERMINATE; `filterIosb` narrows to one request
 * by its user IOSB VA; nothing in flight is STATUS_NOT_FOUND; the result
 * IOSB receives {status, 0} either way). Pinned by sem_pipe/cancel_sync.c.
 * Only npfs's blocking waits are cancellable — every other blocking device
 * read (condrv/serial, hid) stays uncancellable (docs/03 "CUI-5 notes"). */
NTSTATUS NtCancelSynchronousIoFile(HANDLE threadHandle, PIO_STATUS_BLOCK filterIosb,
                                   PIO_STATUS_BLOCK ioStatus)
{
    if (ioStatus == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(ioStatus, sizeof(*ioStatus), sizeof(void *));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PKTHREAD target;
    PVOID body = 0;
    if (threadHandle == NtCurrentThread())
    {
        /* The pseudo-handle, as kernelbase's CancelSynchronousIo(self) spells
         * it (CUI-8 pin, sem_file/cancel_data_io.c): the caller itself, which
         * by construction is not parked in synchronous I/O right now — the
         * sweep below answers NOT_FOUND without a table lookup. */
        target = KeGetCurrentThread();
    }
    else
    {
        status = ObReferenceObjectByHandle(threadHandle, THREAD_TERMINATE, &PspThreadType,
                                           ExGetPreviousMode(), &body, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        target = ((PETHREAD)body)->tcb; /* freed only with the ETHREAD (thread.c) */
    }
    if (target != 0 && target->syncIoActive && !target->syncIoCancelled &&
        (filterIosb == 0 || (void *)filterIosb == target->syncIoUserIosb))
    {
        target->syncIoCancelled = TRUE;
        KeSetEvent(&target->syncIoCancelEvent, 0, FALSE);
        status = STATUS_SUCCESS;
    }
    else
    {
        status = STATUS_NOT_FOUND;
    }
    ioStatus->Status = status;
    ioStatus->Information = 0;
    if (body != 0)
    {
        ObDereferenceObject(body);
    }
    return status;
}
