/* kernel/ob/sync.c — M2's dispatcher objects moved under Ob (M3, docs/02).
 *
 * The executive event/mutant/semaphore are the M2 Ke objects as Ob object
 * BODIES: named, handle-referenced, and waitable through NtWaitFor* (the
 * body starts with the DISPATCHER_HEADER, so ob/wait.c can hand it straight
 * to Ke). The Nt semantics here — previous-state out-parameters, the
 * semaphore limit as an NTSTATUS instead of Ke's in-kernel panic, mutant
 * ownership errors — are pinned by tests/ntapi/sem_ob/sync_objects.c.
 *
 * Callers are kernel threads until M4 brings the syscall boundary, so
 * out-pointers are trusted (uaccess probing arrives with syscall/entry.S).
 */
#include "kernel/ob/ob.h"
#include "kernel/ke/ke.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/init/panic.h"

OBJECT_TYPE ObpEventType = {
    .name = "Event",
    .validAccess = EVENT_ALL_ACCESS,
    .waitable = TRUE,
    .deleteProcedure = 0,
};

/* A mutant can die while owned (last handle closed mid-hold): take it off
 * the owner's abandonment list or KiTerminateThread would walk freed pool. */
static void ObpDeleteMutant(PVOID body)
{
    PKMUTANT mutant = body;
    if (mutant->ownerThread != 0)
    {
        uint64_t flags = KiAcquireDispatcherLock();
        RemoveEntryList(&mutant->mutantListEntry);
        KiReleaseDispatcherLock(flags);
    }
}

OBJECT_TYPE ObpMutantType = {
    .name = "Mutant",
    .validAccess = MUTANT_ALL_ACCESS,
    .waitable = TRUE,
    .deleteProcedure = ObpDeleteMutant,
};

OBJECT_TYPE ObpSemaphoreType = {
    .name = "Semaphore",
    .validAccess = SEMAPHORE_ALL_ACCESS,
    .waitable = TRUE,
    .deleteProcedure = 0,
};

/* Probe an optional out-parameter for a UserMode caller (no-op in KernelMode);
 * every Nt* below funnels its writes through one of these before touching the
 * object, matching NT's ProbeForWrite-first discipline. */
static NTSTATUS ObpProbeOptional(void *pointer, ULONG size, ULONG alignment)
{
    if (pointer == 0)
    {
        return STATUS_SUCCESS;
    }
    return KiProbeForWrite(pointer, size, alignment);
}

/* --- events ---------------------------------------------------------------- */

NTSTATUS NtCreateEvent(PHANDLE handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                       EVENT_TYPE type, BOOLEAN initialState)
{
    if (handle == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if (type != NotificationEvent && type != SynchronizationEvent)
    {
        return STATUS_INVALID_PARAMETER;
    }
    PVOID body;
    NTSTATUS status =
        ObpCreateObjectWithHandle(&ObpEventType, sizeof(KEVENT), attr, access, &body, handle);
    if (status == STATUS_SUCCESS)
    {
        KeInitializeEvent(body, type, initialState);
    }
    return status;
}

NTSTATUS NtOpenEvent(PHANDLE handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr)
{
    if (handle == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    return ObpOpenObjectByName(&ObpEventType, attr, access, handle);
}

/* Shared body of NtSetEvent/NtResetEvent/NtClearEvent/NtPulseEvent. */
typedef LONG (*OBP_EVENT_OPERATION)(PRKEVENT event);

static LONG ObpSetEvent(PRKEVENT event)
{
    return KeSetEvent(event, 0, FALSE);
}

static LONG ObpResetEvent(PRKEVENT event)
{
    return KeResetEvent(event);
}

static NTSTATUS ObpEventStateOperation(HANDLE handle, OBP_EVENT_OPERATION operation,
                                       LONG *previousState)
{
    /* Probe the optional out-parameter before touching the object, as NT's
     * ProbeForWrite does — a bad user pointer is STATUS_ACCESS_VIOLATION and
     * the event is left unchanged (no-op for KernelMode callers). */
    if (previousState != 0)
    {
        NTSTATUS probe =
            KiProbeForWrite(previousState, sizeof(*previousState), sizeof(*previousState));
        if (!NT_SUCCESS(probe))
        {
            return probe;
        }
    }
    PVOID body;
    NTSTATUS status =
        ObReferenceObjectByHandle(handle, EVENT_MODIFY_STATE, &ObpEventType, KernelMode, &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    LONG previous = operation(body);
    if (previousState != 0)
    {
        *previousState = previous;
    }
    ObDereferenceObject(body);
    return STATUS_SUCCESS;
}

NTSTATUS NtSetEvent(HANDLE handle, LONG *previousState)
{
    return ObpEventStateOperation(handle, ObpSetEvent, previousState);
}

NTSTATUS NtResetEvent(HANDLE handle, LONG *previousState)
{
    return ObpEventStateOperation(handle, ObpResetEvent, previousState);
}

NTSTATUS NtClearEvent(HANDLE handle)
{
    return ObpEventStateOperation(handle, ObpResetEvent, 0);
}

NTSTATUS NtPulseEvent(HANDLE handle, LONG *previousState)
{
    return ObpEventStateOperation(handle, KiPulseEvent, previousState);
}

NTSTATUS NtQueryEvent(HANDLE handle, EVENT_INFORMATION_CLASS informationClass, PVOID buffer,
                      ULONG length, PULONG returnLength)
{
    if (informationClass != EventBasicInformation)
    {
        return STATUS_INVALID_INFO_CLASS;
    }
    if (length != sizeof(EVENT_BASIC_INFORMATION))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    NTSTATUS probe = ObpProbeOptional(buffer, sizeof(EVENT_BASIC_INFORMATION), sizeof(LONG));
    if (NT_SUCCESS(probe))
    {
        probe = ObpProbeOptional(returnLength, sizeof(*returnLength), sizeof(*returnLength));
    }
    if (!NT_SUCCESS(probe))
    {
        return probe;
    }
    PVOID body;
    NTSTATUS status =
        ObReferenceObjectByHandle(handle, EVENT_QUERY_STATE, &ObpEventType, KernelMode, &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PKEVENT event = body;
    PEVENT_BASIC_INFORMATION info = buffer;
    info->EventType = event->header.type == KI_OBJECT_NOTIFICATION_EVENT ? NotificationEvent
                                                                         : SynchronizationEvent;
    info->EventState = KeReadStateEvent(event);
    if (returnLength != 0)
    {
        *returnLength = sizeof(EVENT_BASIC_INFORMATION);
    }
    ObDereferenceObject(body);
    return STATUS_SUCCESS;
}

/* --- mutants ---------------------------------------------------------------- */

NTSTATUS NtCreateMutant(HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                        BOOLEAN initialOwner)
{
    if (handle == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    PVOID body;
    NTSTATUS status =
        ObpCreateObjectWithHandle(&ObpMutantType, sizeof(KMUTANT), attr, access, &body, handle);
    if (status == STATUS_SUCCESS)
    {
        KeInitializeMutex(body, 0);
        if (initialOwner)
        {
            /* A fresh free mutant: the zero-timeout acquire cannot fail. */
            LARGE_INTEGER zero = {.QuadPart = 0};
            NTSTATUS acquired = KeWaitForSingleObject(body, Executive, KernelMode, FALSE, &zero);
            ASSERT(acquired == STATUS_SUCCESS);
        }
    }
    return status;
}

NTSTATUS NtOpenMutant(PHANDLE handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr)
{
    if (handle == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    return ObpOpenObjectByName(&ObpMutantType, attr, access, handle);
}

NTSTATUS NtReleaseMutant(HANDLE handle, PLONG previousCount)
{
    NTSTATUS probe =
        ObpProbeOptional(previousCount, sizeof(*previousCount), sizeof(*previousCount));
    if (!NT_SUCCESS(probe))
    {
        return probe;
    }
    PVOID body;
    /* Releasing needs no specific access right: ownership IS the check. */
    NTSTATUS status = ObReferenceObjectByHandle(handle, 0, &ObpMutantType, KernelMode, &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PKMUTANT mutant = body;
    if (mutant->ownerThread != KeGetCurrentThread())
    {
        ObDereferenceObject(body);
        return STATUS_MUTANT_NOT_OWNED;
    }
    LONG previous = KeReleaseMutex(mutant, FALSE);
    if (previousCount != 0)
    {
        *previousCount = previous;
    }
    ObDereferenceObject(body);
    return STATUS_SUCCESS;
}

NTSTATUS NtQueryMutant(HANDLE handle, MUTANT_INFORMATION_CLASS informationClass, PVOID buffer,
                       ULONG length, PULONG returnLength)
{
    if (informationClass != MutantBasicInformation)
    {
        return STATUS_INVALID_INFO_CLASS;
    }
    if (length != sizeof(MUTANT_BASIC_INFORMATION))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    NTSTATUS probe = ObpProbeOptional(buffer, sizeof(MUTANT_BASIC_INFORMATION), sizeof(LONG));
    if (NT_SUCCESS(probe))
    {
        probe = ObpProbeOptional(returnLength, sizeof(*returnLength), sizeof(*returnLength));
    }
    if (!NT_SUCCESS(probe))
    {
        return probe;
    }
    PVOID body;
    NTSTATUS status =
        ObReferenceObjectByHandle(handle, MUTANT_QUERY_STATE, &ObpMutantType, KernelMode, &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PKMUTANT mutant = body;
    PMUTANT_BASIC_INFORMATION info = buffer;
    info->CurrentCount = mutant->header.signalState;
    info->OwnedByCaller = mutant->ownerThread == KeGetCurrentThread();
    info->AbandonedState = mutant->abandoned;
    if (returnLength != 0)
    {
        *returnLength = sizeof(MUTANT_BASIC_INFORMATION);
    }
    ObDereferenceObject(body);
    return STATUS_SUCCESS;
}

/* --- semaphores ------------------------------------------------------------- */

NTSTATUS NtCreateSemaphore(PHANDLE handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                           LONG initialCount, LONG maximumCount)
{
    if (handle == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if (maximumCount <= 0 || initialCount < 0 || initialCount > maximumCount)
    {
        return STATUS_INVALID_PARAMETER;
    }
    PVOID body;
    NTSTATUS status = ObpCreateObjectWithHandle(&ObpSemaphoreType, sizeof(KSEMAPHORE), attr, access,
                                                &body, handle);
    if (status == STATUS_SUCCESS)
    {
        KeInitializeSemaphore(body, initialCount, maximumCount);
    }
    return status;
}

NTSTATUS NtOpenSemaphore(PHANDLE handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr)
{
    if (handle == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    return ObpOpenObjectByName(&ObpSemaphoreType, attr, access, handle);
}

NTSTATUS NtReleaseSemaphore(HANDLE handle, ULONG releaseCount, PULONG previousCount)
{
    /* The handle is resolved BEFORE ReleaseCount is examined: a bad, wrong-type
     * or under-privileged handle reports the handle error regardless of the
     * count. ReleaseCount == 0 is a legal no-op (returns the current count),
     * never STATUS_INVALID_PARAMETER; a count that would exceed the limit is
     * STATUS_SEMAPHORE_LIMIT_EXCEEDED. Matches the pinned third_party/wine
     * (dlls/ntdll -> server release_semaphore); docs/09 Art. 6. */
    NTSTATUS probe =
        ObpProbeOptional(previousCount, sizeof(*previousCount), sizeof(*previousCount));
    if (!NT_SUCCESS(probe))
    {
        return probe;
    }
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(handle, SEMAPHORE_MODIFY_STATE, &ObpSemaphoreType,
                                                KernelMode, &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PKSEMAPHORE semaphore = body;
    /* Ke panics on over-release (kernel callers are in-tree); the Nt surface
     * reports it. No preemption: the check cannot go stale before the call.
     * Unsigned compare so a high-bit count reads as "huge" -> limit exceeded,
     * as the server's unsigned arithmetic does, not as a negative LONG. */
    LONG previous = semaphore->header.signalState;
    if (releaseCount > (ULONG)(semaphore->limit - previous))
    {
        ObDereferenceObject(body);
        return STATUS_SEMAPHORE_LIMIT_EXCEEDED;
    }
    if (releaseCount != 0)
    {
        KeReleaseSemaphore(semaphore, 0, (LONG)releaseCount, FALSE);
    }
    if (previousCount != 0)
    {
        *previousCount = (ULONG)previous;
    }
    ObDereferenceObject(body);
    return STATUS_SUCCESS;
}

NTSTATUS NtQuerySemaphore(HANDLE handle, SEMAPHORE_INFORMATION_CLASS informationClass, PVOID buffer,
                          ULONG length, PULONG returnLength)
{
    if (informationClass != SemaphoreBasicInformation)
    {
        return STATUS_INVALID_INFO_CLASS;
    }
    if (length != sizeof(SEMAPHORE_BASIC_INFORMATION))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    NTSTATUS probe = ObpProbeOptional(buffer, sizeof(SEMAPHORE_BASIC_INFORMATION), sizeof(ULONG));
    if (NT_SUCCESS(probe))
    {
        probe = ObpProbeOptional(returnLength, sizeof(*returnLength), sizeof(*returnLength));
    }
    if (!NT_SUCCESS(probe))
    {
        return probe;
    }
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(handle, SEMAPHORE_QUERY_STATE, &ObpSemaphoreType,
                                                KernelMode, &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PKSEMAPHORE semaphore = body;
    PSEMAPHORE_BASIC_INFORMATION info = buffer;
    info->CurrentCount = (ULONG)semaphore->header.signalState;
    info->MaximumCount = (ULONG)semaphore->limit;
    if (returnLength != 0)
    {
        *returnLength = sizeof(SEMAPHORE_BASIC_INFORMATION);
    }
    ObDereferenceObject(body);
    return STATUS_SUCCESS;
}
