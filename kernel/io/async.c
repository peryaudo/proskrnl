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

NTSTATUS IopPreparePendingRequest(const IO_CONTROL_CONTEXT *request, PIOP_PENDING_REQUEST *out)
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
        /* The issue-time probe faulted the page in and required it writable;
         * no eviction (Art. 3) keeps it resident, and the owner's handles
         * close before its address space dies (G11 audit in io.h). */
        MiCopyToUserRange(&request->owner->addressSpace, (uint64_t)(uintptr_t)request->userIosb,
                          &iosb, sizeof(iosb));
    }
    if (request->event != 0)
    {
        KeSetEvent(request->event, 0, FALSE);
        ObDereferenceObject(request->event);
    }
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
void IopEnterSyncIo(void *userIosb)
{
    PKTHREAD self = KeGetCurrentThread();
    self->syncIoUserIosb = userIosb;
    self->syncIoCancelled = FALSE;
    KeClearEvent(&self->syncIoCancelEvent);
    self->syncIoActive = TRUE;
}

void IopLeaveSyncIo(void)
{
    PKTHREAD self = KeGetCurrentThread();
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
    PVOID body;
    status = ObReferenceObjectByHandle(threadHandle, THREAD_TERMINATE, &PspThreadType,
                                       ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PETHREAD thread = body;
    PKTHREAD target = thread->tcb; /* freed only with the ETHREAD (thread.c) */
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
    ObDereferenceObject(body);
    return status;
}
