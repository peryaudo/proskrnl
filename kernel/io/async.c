/* kernel/io/async.c — the pending-request engine (CUI-3).
 *
 * Art. 3's "everything completes before the syscall returns" narrows here,
 * not breaks: DATA transfers stay synchronous, but FSCTL_PIPE_LISTEN on an
 * asynchronous handle genuinely pends (docs/03 "CUI-3 SCM notes") because
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
