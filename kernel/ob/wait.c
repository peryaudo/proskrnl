/* kernel/ob/wait.c — handle -> object resolution for NtWaitFor* (M3).
 *
 * The Nt wait surface resolves handles (SYNCHRONIZE access, waitable type),
 * then defers entirely to the M2 Ke dispatcher: an executive object's body
 * begins with its DISPATCHER_HEADER. Parameter conventions (count 1..64 else
 * STATUS_INVALID_PARAMETER_1) are pinned by tests/ntapi/sem_ob/.
 */
#include "kernel/ob/ob.h"
#include "kernel/ke/ke.h"
#include "kernel/mm/pool.h"
#include "kernel/init/panic.h"
#include "kernel/syscall/uaccess.h"

/* Resolve one wait-source handle: needs SYNCHRONIZE and a waitable type. */
static NTSTATUS ObpReferenceWaitObject(HANDLE handle, PVOID *body)
{
    NTSTATUS status = ObReferenceObjectByHandle(handle, SYNCHRONIZE, 0, KernelMode, body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (!ObpGetHeader(*body)->type->waitable)
    {
        ObDereferenceObject(*body);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    return STATUS_SUCCESS;
}

/* KeWaitFor* dereferences `timeout` directly, so a ring-3 pointer has to be
 * validated before it is handed over -- an unmapped one faults with
 * CS.RPL == 0, which KiDispatchTrap does not contain. NULL means "wait
 * forever" and is not a pointer to check. */
static NTSTATUS ObpProbeTimeout(const LARGE_INTEGER *timeout)
{
    if (timeout == 0)
    {
        return STATUS_SUCCESS;
    }
    return KiProbeForRead(timeout, sizeof(*timeout), sizeof(uint64_t));
}

NTSTATUS NtWaitForSingleObject(HANDLE handle, BOOLEAN alertable, const LARGE_INTEGER *timeout)
{
    NTSTATUS probeStatus = ObpProbeTimeout(timeout);
    if (!NT_SUCCESS(probeStatus))
    {
        return probeStatus;
    }
    PVOID body;
    NTSTATUS status = ObpReferenceWaitObject(handle, &body);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status =
        KeWaitForSingleObject(body, UserRequest, KernelMode, alertable, (PLARGE_INTEGER)timeout);
    ObDereferenceObject(body);
    return status;
}

/* CUI-6: SignalObjectAndWait's back end. Order is the pinned server's
 * (server/thread.c select_on SELECT_SIGNAL_AND_WAIT): NULL signal refuses
 * first, the WAIT handle is resolved before the signal runs, and a failing
 * signal aborts without waiting. Atomicity needs no extra machinery here:
 * under Art. 3 (one dispatcher lock, no kernel preemption) no other thread
 * can run between the signal below and the wait's arming — the signal
 * readies waiters but never switches, so signalling the very object being
 * waited on satisfies our own wait exactly as the server's
 * "check if we woke ourselves up" does (sem_wait/signal_wait pins it). */
NTSTATUS NtSignalAndWaitForSingleObject(HANDLE signalHandle, HANDLE waitHandle, BOOLEAN alertable,
                                        const LARGE_INTEGER *timeout)
{
    if (signalHandle == 0)
    {
        return STATUS_INVALID_HANDLE;
    }
    NTSTATUS probeStatus = ObpProbeTimeout(timeout);
    if (!NT_SUCCESS(probeStatus))
    {
        return probeStatus;
    }
    PVOID waitBody;
    NTSTATUS status = ObpReferenceWaitObject(waitHandle, &waitBody);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PVOID signalBody;
    OBJECT_HANDLE_INFORMATION signalInfo;
    status = ObReferenceObjectByHandle(signalHandle, 0, 0, KernelMode, &signalBody, &signalInfo);
    if (NT_SUCCESS(status))
    {
        status = ObpSignalObjectForWait(signalBody, signalInfo.GrantedAccess);
        ObDereferenceObject(signalBody);
    }
    if (NT_SUCCESS(status))
    {
        status = KeWaitForSingleObject(waitBody, UserRequest, KernelMode, alertable,
                                       (PLARGE_INTEGER)timeout);
    }
    ObDereferenceObject(waitBody);
    return status;
}

NTSTATUS NtWaitForMultipleObjects(ULONG count, const HANDLE *handles, WAIT_TYPE waitType,
                                  BOOLEAN alertable, const LARGE_INTEGER *timeout)
{
    if (count == 0 || count > MAXIMUM_WAIT_OBJECTS)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    if (waitType != WaitAll && waitType != WaitAny)
    {
        return STATUS_INVALID_PARAMETER_3;
    }
    NTSTATUS probeStatus = ObpProbeTimeout(timeout);
    if (!NT_SUCCESS(probeStatus))
    {
        return probeStatus;
    }
    /* The handle array is read element by element below; validate the whole
     * span once, after the count has been bounded. */
    probeStatus = KiProbeForRead(handles, (uint64_t)count * sizeof(HANDLE), sizeof(HANDLE));
    if (!NT_SUCCESS(probeStatus))
    {
        return probeStatus;
    }

    PVOID objects[MAXIMUM_WAIT_OBJECTS];
    NTSTATUS status = STATUS_SUCCESS;
    ULONG referenced = 0;
    for (; referenced < count; referenced++)
    {
        /* Pseudo-handles are legal in the SINGLE-object wait and illegal
         * here. That asymmetry is the contract, not an oversight —
         * kernel32:sync states it in its own comment (sync.c:1483: "in
         * contrast to WaitForSingleObject, all pseudo-handles are not
         * allowed in WaitForMultipleObjects and NtWaitForMultipleObjects")
         * and asserts STATUS_INVALID_HANDLE for each of them.
         *
         * proskrnl reached this only recently: teaching
         * ObReferenceObjectByHandle to resolve -1 and -2 (the fix that
         * unblocked kernel32:thread) made them resolve HERE too, so the
         * call waited on a process or thread object instead of refusing —
         * and kernel32:sync then entered a wait it never left, burning the
         * pair's whole 300-second timeout. A capability added in one place
         * changed behaviour in another; this is the second half of that
         * change, and tests/ntapi/sem_wait/pseudo_handle_multi.c pins both
         * halves together so they cannot drift apart again.
         *
         * The refusal is by RANGE, not by naming -1 and -2. Naming them was
         * the first half of the same defect: the three TOKEN pseudo-handles
         * resolve through ObReferenceObjectByHandle too, and a wait that
         * lets them through finds a non-waitable object and answers
         * STATUS_OBJECT_TYPE_MISMATCH — a status that reads like a real
         * type error and is not one. kernel32:sync asserts the whole range
         * at sync.c:1496/:1511/:1513/:1530/:1532 and two of its six values
         * failed at each. */
        if (ObpIsPseudoHandle(handles[referenced]))
        {
            status = STATUS_INVALID_HANDLE;
            break;
        }
        status = ObpReferenceWaitObject(handles[referenced], &objects[referenced]);
        if (!NT_SUCCESS(status))
        {
            break;
        }
    }

    if (NT_SUCCESS(status))
    {
        /* The thread embeds KI_THREAD_WAIT_OBJECTS wait blocks; a wider wait
         * borrows a pool array, exactly as NT's WaitBlockArray callers do. */
        PKWAIT_BLOCK waitBlocks = 0;
        if (count > KI_THREAD_WAIT_OBJECTS)
        {
            waitBlocks = MiAllocatePool(count * sizeof(KWAIT_BLOCK));
            if (waitBlocks == 0)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        if (NT_SUCCESS(status))
        {
            status = KeWaitForMultipleObjects(count, objects, waitType, UserRequest, KernelMode,
                                              alertable, (PLARGE_INTEGER)timeout, waitBlocks);
        }
        if (waitBlocks != 0)
        {
            MiFreePool(waitBlocks);
        }
    }

    for (ULONG i = 0; i < referenced; i++)
    {
        ObDereferenceObject(objects[i]);
    }
    return status;
}
