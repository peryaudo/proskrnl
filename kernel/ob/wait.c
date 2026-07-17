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

NTSTATUS NtWaitForSingleObject(HANDLE handle, BOOLEAN alertable, const LARGE_INTEGER *timeout)
{
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

    PVOID objects[MAXIMUM_WAIT_OBJECTS];
    NTSTATUS status = STATUS_SUCCESS;
    ULONG referenced = 0;
    for (; referenced < count; referenced++)
    {
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
