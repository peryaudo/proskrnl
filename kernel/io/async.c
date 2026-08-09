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

NTSTATUS IopPreparePendingRequest(PFILE_OBJECT file, const IO_CONTROL_CONTEXT *request,
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
    /* The completion PACKET leg: the port is read off the file object at
     * completion (io.h says why it is late rather than captured), so the
     * request holds the handle open for exactly as long as it can complete —
     * the same statement issuerObject makes about the issuing thread. */
    pending->file = file;
    ObfReferenceObject(file);
    *out = pending;
    return STATUS_SUCCESS;
}

void IopCompletePendingRequest(PIOP_PENDING_REQUEST request, NTSTATUS status, ULONG_PTR information)
{
    IO_STATUS_BLOCK iosb;
    iosb.Status = status;
    iosb.Information = information;
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
    if (request->event != 0)
    {
        KeSetEvent(request->event, 0, FALSE);
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
    MiFreePool(request);
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
        if (file->device->ops->CancelPending != 0)
        {
            cancelled = file->device->ops->CancelPending(file, issuer, targetIosb);
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

void IopEnterSyncIo(void *userIosb)
{
    PKTHREAD self = KeGetCurrentThread();
    self->syncIoUserIosb = userIosb;
    self->syncIoCancelled = FALSE;
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
}

/* A cancellable park for blocking device waits (npfs): the device's wake
 * event OR this thread's cancel event, whichever fires first (timeout
 * optional, the KeWaitFor* convention). */
NTSTATUS IoWaitCancellable(PKEVENT event, PLARGE_INTEGER timeout)
{
    PKTHREAD self = KeGetCurrentThread();
    void *objects[2] = {event, &self->syncIoCancelEvent};
    NTSTATUS status =
        KeWaitForMultipleObjects(2, objects, WaitAny, Executive, KernelMode, FALSE, timeout, 0);
    if (self->syncIoCancelled)
    {
        return STATUS_CANCELLED;
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
