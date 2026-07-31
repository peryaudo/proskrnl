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
#include "kernel/lib/string.h"
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

/* The oracle's shape verbatim: a boost-priority set IS a set (Wine
 * dlls/ntdll/unix/sync.c NtSetEventBoostPriority -> NtSetEvent; priority
 * boosting does not exist on the no-preemption kernel). Consumer:
 * ntdll:sync test_event. */
NTSTATUS NtSetEventBoostPriority(HANDLE handle)
{
    return NtSetEvent(handle, 0);
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

/* --- waitable timers (M10) ------------------------------------------------- */

/* Ob-visible KTIMER objects: kernelbase's CreateWaitableTimer/
 * SetWaitableTimer are direct wrappers and ntdll's timer queues arm one
 * (third_party/wine dlls/kernelbase/sync.c, dlls/ntdll/threadpool.c).
 * Contract pinned by tests/ntapi/sem_port/timers.c; the notification vs
 * synchronization signalling mirrors events, carried by the M2 KTIMER
 * machinery unchanged. */

OBJECT_TYPE ObpTimerType = {
    .name = "Timer",
    .validAccess = TIMER_ALL_ACCESS,
    .waitable = TRUE,
};

NTSTATUS NtCreateTimer(HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                       TIMER_TYPE type)
{
    if (handle == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if (type != NotificationTimer && type != SynchronizationTimer)
    {
        return STATUS_INVALID_PARAMETER;
    }
    PVOID body;
    NTSTATUS status =
        ObpCreateObjectWithHandle(&ObpTimerType, sizeof(KTIMER), attr, access, &body, handle);
    if (status == STATUS_SUCCESS)
    {
        KeInitializeTimerEx(body, type);
    }
    return status;
}

NTSTATUS NtSetTimer(HANDLE handle, const LARGE_INTEGER *dueTime, PTIMER_APC_ROUTINE apcRoutine,
                    PVOID apcContext, BOOLEAN resume, ULONG period, BOOLEAN *previousState)
{
    (void)apcContext;
    (void)resume; /* no power management to resume from */
    if (dueTime == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if (apcRoutine != 0)
    {
        /* Timer APCs are unbuilt: nothing on the CUI path arms one (the
         * threadpool and kernelbase wait on the object). Refused loudly,
         * never faked (docs/03). */
        return STATUS_NOT_IMPLEMENTED;
    }
    NTSTATUS status = KiProbeForRead(dueTime, sizeof(*dueTime), sizeof(uint64_t));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    LARGE_INTEGER due = *dueTime;

    PVOID body;
    status = ObReferenceObjectByHandle(handle, TIMER_MODIFY_STATE, &ObpTimerType,
                                       ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* The out-parameter is validated BEFORE the timer is armed, and its
     * failure is the call's failure. Probing after the side effect and
     * swallowing the result reported success while the caller's
     * PreviousState was never written -- and the timer WAS armed
     * (docs/review-2026-07 §5). Optional means "may be NULL", not "may be
     * unwritable". */
    if (previousState != 0)
    {
        NTSTATUS probe = KiProbeForWrite(previousState, sizeof(*previousState), 1);
        if (!NT_SUCCESS(probe))
        {
            ObDereferenceObject(body);
            return probe;
        }
    }
    PKTIMER timer = body;
    BOOLEAN wasSignaled = timer->header.signalState != 0;
    KeSetTimerEx(timer, due, (LONG)period, 0);
    ObDereferenceObject(body);

    if (previousState != 0)
    {
        *previousState = wasSignaled;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtCancelTimer(HANDLE handle, BOOLEAN *currentState)
{
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(handle, TIMER_MODIFY_STATE, &ObpTimerType,
                                                ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* As NtSetTimer: probe before the cancel, and let the failure be the
     * call's. */
    if (currentState != 0)
    {
        NTSTATUS probe = KiProbeForWrite(currentState, sizeof(*currentState), 1);
        if (!NT_SUCCESS(probe))
        {
            ObDereferenceObject(body);
            return probe;
        }
    }
    PKTIMER timer = body;
    BOOLEAN wasSignaled = timer->header.signalState != 0;
    KeCancelTimer(timer);
    ObDereferenceObject(body);

    if (currentState != 0)
    {
        *currentState = wasSignaled;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtQueryTimer(HANDLE handle, TIMER_INFORMATION_CLASS informationClass, PVOID buffer,
                      ULONG length, PULONG returnLength)
{
    if (informationClass != TimerBasicInformation)
    {
        return STATUS_INVALID_INFO_CLASS;
    }
    if (length < sizeof(TIMER_BASIC_INFORMATION))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    NTSTATUS probe = KiProbeForWrite(buffer, sizeof(TIMER_BASIC_INFORMATION), sizeof(uint64_t));
    if (NT_SUCCESS(probe) && returnLength != 0)
    {
        probe = KiProbeForWrite(returnLength, sizeof(ULONG), sizeof(ULONG));
    }
    if (!NT_SUCCESS(probe))
    {
        return probe;
    }
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(handle, TIMER_QUERY_STATE, &ObpTimerType,
                                                ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PKTIMER timer = body;
    TIMER_BASIC_INFORMATION info;
    uint64_t flags = KiAcquireDispatcherLock();
    info.TimerState = timer->header.signalState != 0;
    /* Remaining = due - now in 100 ns (negative once past due — the NT
     * shape); an unarmed timer reports 0. */
    info.RemainingTime.QuadPart =
        timer->header.inserted != 0
            ? timer->dueTime.QuadPart - (LONGLONG)KeTickCount * (LONGLONG)KI_100NS_PER_TICK
            : 0;
    KiReleaseDispatcherLock(flags);
    ObDereferenceObject(body);

    memcpy(buffer, &info, sizeof(info));
    if (returnLength != 0)
    {
        *returnLength = sizeof(info); /* probed above, with the buffer */
    }
    return STATUS_SUCCESS;
}

/* --- keyed events (M10 winetest) ------------------------------------------- */

/* The keyed event is a rendezvous broker: a waiter and a releaser meet on a
 * (process, key) pair and both complete; there is no state to signal, and a
 * PLAIN wait on the handle satisfies immediately (wineserver
 * server/event.c keyed_event_signaled returns 1 for non-keyed selects — the
 * body here is a permanently-set notification event for the same effect).
 * Access split, the odd-key STATUS_INVALID_PARAMETER_1 precheck, and the
 * NULL-handle implicit instance (real NT's CritSecOutOfMemoryEvent) follow
 * the oracle (dlls/ntdll/unix/sync.c NtWaitForKeyedEvent/NtReleaseKeyedEvent
 * + server/event.c), all pinned by ntdll:sync test_keyed_events. Access
 * masks are the documented NT values (MS ntifs.h KEYEDEVENT_*; also
 * dlls/ntdll/tests/sync.c): */
#define OBP_KEYEDEVENT_WAIT       0x0001
#define OBP_KEYEDEVENT_WAKE       0x0002
#define OBP_KEYEDEVENT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x0003)

typedef struct OBP_KEYED_EVENT
{
    KEVENT alwaysSignaled; /* the waitable body (leads with the header) */
    LIST_ENTRY waiters;
} OBP_KEYED_EVENT;

typedef struct OBP_KEYED_WAITER
{
    LIST_ENTRY entry;
    void *process; /* pair-matching identity only (server/event.c) */
    const void *key;
    BOOLEAN release; /* queued by NtReleaseKeyedEvent */
    KEVENT wake;
} OBP_KEYED_WAITER;

static OBJECT_TYPE ObpKeyedEventType = {
    .name = "KeyedEvent",
    /* SYNCHRONIZE is grantable — an explicit ALL|SYNCHRONIZE create can
     * plain-wait the handle, bare ALL cannot (ntdll:sync pins both). */
    .validAccess = OBP_KEYEDEVENT_ALL_ACCESS | SYNCHRONIZE,
    .waitable = TRUE,
    .deleteProcedure = 0,
    /* The NT generic mapping the oracle enforces: reading waits, writing
     * wakes (wineserver server/event.c keyed_event type). */
    .genericRead = STANDARD_RIGHTS_READ | OBP_KEYEDEVENT_WAIT,
    .genericWrite = STANDARD_RIGHTS_WRITE | OBP_KEYEDEVENT_WAKE,
    .genericExecute = STANDARD_RIGHTS_EXECUTE,
    .genericAll = OBP_KEYEDEVENT_ALL_ACCESS,
};

static void ObpInitializeKeyedEvent(OBP_KEYED_EVENT *keyed)
{
    KeInitializeEvent(&keyed->alwaysSignaled, NotificationEvent, TRUE);
    InitializeListHead(&keyed->waiters);
}

/* The NULL-handle instance, created on first use (the dispatcher lock makes
 * the check-and-init atomic on the one CPU). */
static OBP_KEYED_EVENT ObpCritSecKeyedEvent;
static BOOLEAN ObpCritSecKeyedEventReady;

NTSTATUS NtCreateKeyedEvent(HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                            ULONG flags)
{
    if (handle == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if (flags != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    PVOID body;
    NTSTATUS status = ObpCreateObjectWithHandle(&ObpKeyedEventType, sizeof(OBP_KEYED_EVENT), attr,
                                                access, &body, handle);
    if (status == STATUS_SUCCESS)
    {
        ObpInitializeKeyedEvent(body);
    }
    return status;
}

NTSTATUS NtOpenKeyedEvent(HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr)
{
    if (handle == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    return ObpOpenObjectByName(&ObpKeyedEventType, attr, access, handle);
}

/* The shared wait/release engine: find the opposite party on (process, key)
 * and wake it, else park until woken or timed out. On a timeout that races
 * a concurrent wake the rendezvous HAS happened — the parked entry is
 * already unlinked — and the result is success. */
static NTSTATUS ObpKeyedEventOperation(HANDLE handle, const void *key, BOOLEAN alertable,
                                       const LARGE_INTEGER *timeout, BOOLEAN release)
{
    if (((uintptr_t)key & 1) != 0)
    {
        return STATUS_INVALID_PARAMETER_1;
    }
    OBP_KEYED_EVENT *keyed;
    BOOLEAN referenced = FALSE;
    if (handle == 0)
    {
        uint64_t flags = KiAcquireDispatcherLock();
        if (!ObpCritSecKeyedEventReady)
        {
            ObpInitializeKeyedEvent(&ObpCritSecKeyedEvent);
            ObpCritSecKeyedEventReady = TRUE;
        }
        KiReleaseDispatcherLock(flags);
        keyed = &ObpCritSecKeyedEvent;
    }
    else
    {
        PVOID body;
        NTSTATUS status =
            ObReferenceObjectByHandle(handle, release ? OBP_KEYEDEVENT_WAKE : OBP_KEYEDEVENT_WAIT,
                                      &ObpKeyedEventType, ExGetPreviousMode(), &body, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        keyed = body;
        referenced = TRUE;
    }

    void *process = KeGetCurrentThread()->process;
    NTSTATUS status = STATUS_SUCCESS;
    OBP_KEYED_WAITER self;
    BOOLEAN parked = FALSE;

    uint64_t flags = KiAcquireDispatcherLock();
    PLIST_ENTRY entry;
    OBP_KEYED_WAITER *other = 0;
    for (entry = keyed->waiters.Flink; entry != &keyed->waiters; entry = entry->Flink)
    {
        OBP_KEYED_WAITER *waiter = CONTAINING_RECORD(entry, OBP_KEYED_WAITER, entry);
        if (waiter->process == process && waiter->key == key && waiter->release != release)
        {
            other = waiter;
            break;
        }
    }
    if (other != 0)
    {
        RemoveEntryList(&other->entry);
        KeSetEvent(&other->wake, 0, FALSE);
    }
    else
    {
        self.process = process;
        self.key = key;
        self.release = release;
        KeInitializeEvent(&self.wake, SynchronizationEvent, FALSE);
        InsertTailList(&keyed->waiters, &self.entry);
        parked = TRUE;
    }
    KiReleaseDispatcherLock(flags);

    if (parked)
    {
        status = KeWaitForSingleObject(&self.wake, UserRequest, KernelMode, alertable,
                                       (PLARGE_INTEGER)timeout);
        flags = KiAcquireDispatcherLock();
        if (status == STATUS_SUCCESS)
        {
            /* woken by the opposite party, already unlinked */
        }
        else
        {
            /* Timed out (or alerted): unlink unless a waker got there in
             * the same instant — then the rendezvous happened. */
            BOOLEAN stillQueued = FALSE;
            for (entry = keyed->waiters.Flink; entry != &keyed->waiters; entry = entry->Flink)
            {
                if (entry == &self.entry)
                {
                    stillQueued = TRUE;
                    break;
                }
            }
            if (stillQueued)
            {
                RemoveEntryList(&self.entry);
            }
            else
            {
                status = STATUS_SUCCESS;
            }
        }
        KiReleaseDispatcherLock(flags);
    }

    if (referenced)
    {
        ObDereferenceObject(keyed);
    }
    return status;
}

NTSTATUS NtWaitForKeyedEvent(HANDLE handle, const void *key, BOOLEAN alertable,
                             const LARGE_INTEGER *timeout)
{
    return ObpKeyedEventOperation(handle, key, alertable, timeout, FALSE);
}

NTSTATUS NtReleaseKeyedEvent(HANDLE handle, const void *key, BOOLEAN alertable,
                             const LARGE_INTEGER *timeout)
{
    return ObpKeyedEventOperation(handle, key, alertable, timeout, TRUE);
}
