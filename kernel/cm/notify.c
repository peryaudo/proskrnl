/* kernel/cm/notify.c — registry change notification (CUI-7, docs/02).
 *
 * A transcription of wineserver's per-key notify records onto the Cm tree
 * (wine server/registry.c set_registry_notification / touch_key /
 * check_notify / do_notification / key_close_handle; the ntdll shape is
 * dlls/ntdll/unix/registry.c NtNotifyChangeMultipleKeys). The observable
 * contract is pinned by tests/ntapi/sem_reg/notify.c:
 *
 *   - One record per arming open, on the watched node; subtree/filter stick
 *     from the FIRST arm, later arms only append their event.
 *   - Firing signals and releases every accumulated event and KEEPS the
 *     record; closing the arming handle fires-and-frees it.
 *   - A mutation fires the node's own matching records unconditionally and
 *     ancestors' records only when armed with subtree=TRUE.
 *   - The IOSB/APC/buffer/subordinate-key arguments are accepted and
 *     ignored, exactly as the oracle FIXME-ignores them (docs/03 "CUI-7"
 *     notes); the kernel never writes the IOSB.
 *   - The synchronous form blocks in the kernel on an internal, handle-less
 *     event — on the oracle ntdll emulates this with a private event over
 *     the same server record, so the boundary behaviour is identical.
 */
#include "kernel/cm/cm.h"

#include "kernel/init/panic.h"
#include "kernel/ke/ke.h"
#include "kernel/lib/string.h"
#include "kernel/mm/pool.h"
#include "kernel/syscall/uaccess.h"

static PCMP_NOTIFY CmpFindNotify(PCMP_KEY_NODE node, const CM_KEY_BODY *body)
{
    for (PLIST_ENTRY e = node->notifyListHead.Flink; e != &node->notifyListHead; e = e->Flink)
    {
        PCMP_NOTIFY notify = CONTAINING_RECORD(e, CMP_NOTIFY, entry);
        if (notify->body == body)
        {
            return notify;
        }
    }
    return 0;
}

/* Signal + release every accumulated event (wineserver do_notification);
 * `unlink` additionally removes and frees the record (the del=1 arm). */
static void CmpFireNotify(PCMP_NOTIFY notify, BOOLEAN unlink)
{
    for (ULONG i = 0; i < notify->eventCount; i++)
    {
        KeSetEvent(notify->events[i], 0, FALSE);
        ObDereferenceObject(notify->events[i]);
    }
    if (notify->events != 0)
    {
        MiFreePool(notify->events);
    }
    notify->events = 0;
    notify->eventCount = 0;
    if (unlink)
    {
        RemoveEntryList(&notify->entry);
        MiFreePool(notify);
    }
}

/* Fire matching records on one node; not_subtree mirrors wineserver
 * check_notify (the mutated node fires everything, an ancestor only
 * subtree-armed records). */
static void CmpCheckNotify(PCMP_KEY_NODE node, ULONG change, BOOLEAN notSubtree)
{
    PLIST_ENTRY e = node->notifyListHead.Flink;
    while (e != &node->notifyListHead)
    {
        PCMP_NOTIFY notify = CONTAINING_RECORD(e, CMP_NOTIFY, entry);
        e = e->Flink; /* firing never unlinks (del=0), but stay safe */
        if ((notSubtree || notify->subtree) && (change & notify->filter) != 0)
        {
            CmpFireNotify(notify, FALSE);
        }
    }
}

void CmpNotifyChange(PCMP_KEY_NODE node, ULONG change)
{
    if (node == 0)
    {
        return;
    }
    CmpCheckNotify(node, change, TRUE);
    for (PCMP_KEY_NODE ancestor = node->parent; ancestor != 0; ancestor = ancestor->parent)
    {
        CmpCheckNotify(ancestor, change, FALSE);
    }
}

void CmpCloseKeyBody(struct EPROCESS *process, PVOID bodyPointer, ULONG processHandleCount,
                     ULONG systemHandleCount)
{
    PCM_KEY_BODY body = bodyPointer;
    /* The arming open's LAST handle in the system — a second process
     * letting go of a duplicate is not what fires a notification (ob.h). */
    (void)process;
    (void)processHandleCount;
    if (systemHandleCount != 1)
    {
        return;
    }
    if (body->node == 0)
    {
        return; /* creation failed before binding */
    }
    PCMP_NOTIFY notify = CmpFindNotify(body->node, body);
    if (notify != 0)
    {
        CmpFireNotify(notify, TRUE);
    }
}

/* Find-or-create the body's record and append one referenced event body to
 * it. Ownership of the event reference transfers on success; the caller
 * keeps it on failure. */
static NTSTATUS CmpArmNotify(PCM_KEY_BODY body, PVOID eventBody, ULONG filter, BOOLEAN subtree)
{
    PCMP_KEY_NODE node = body->node;
    PCMP_NOTIFY notify = CmpFindNotify(node, body);
    if (notify == 0)
    {
        notify = MiAllocatePool(sizeof(*notify));
        if (notify == 0)
        {
            return STATUS_NO_MEMORY;
        }
        notify->body = body;
        notify->subtree = subtree;
        notify->filter = filter;
        notify->eventCount = 0;
        notify->events = 0;
        InsertHeadList(&node->notifyListHead, &notify->entry);
    }
    /* Grow-by-one, as the server does; the array is tiny in practice. */
    PVOID *events = MiAllocatePool((notify->eventCount + 1) * sizeof(PVOID));
    if (events == 0)
    {
        /* A freshly created empty record may stay: it holds no references
         * and dies with the body (the server leaves the same state). */
        return STATUS_NO_MEMORY;
    }
    if (notify->eventCount != 0)
    {
        memcpy(events, notify->events, notify->eventCount * sizeof(PVOID));
    }
    if (notify->events != 0)
    {
        MiFreePool(notify->events);
    }
    notify->events = events;
    notify->events[notify->eventCount++] = eventBody;
    /* NT resets the caller's event at registration (wineserver
     * reset_event; the IopPreparePendingRequest precedent). */
    KeClearEvent(eventBody);
    return STATUS_SUCCESS;
}

NTSTATUS NtNotifyChangeMultipleKeys(HANDLE keyHandle, ULONG count,
                                    OBJECT_ATTRIBUTES *subordinateObjects, HANDLE eventHandle,
                                    PIO_APC_ROUTINE apcRoutine, PVOID apcContext,
                                    PIO_STATUS_BLOCK ioStatusBlock, ULONG completionFilter,
                                    BOOLEAN watchTree, PVOID buffer, ULONG bufferSize,
                                    BOOLEAN asynchronous)
{
    /* The subordinate-key/APC/buffer/IOSB arguments are accepted and ignored
     * — the pinned oracle FIXME-ignores them and proceeds on the primary key
     * (docs/03 "CUI-7" notes). The IOSB is never written. */
    (void)count;
    (void)subordinateObjects;
    (void)apcRoutine;
    (void)apcContext;
    (void)ioStatusBlock;
    (void)buffer;
    (void)bufferSize;

    /* Key first, then event (the server's DECL_HANDLER order — a NULL event
     * on a good key is the event's STATUS_INVALID_HANDLE). KEY_NOTIFY and
     * the stale-handle KEY_DELETED rule come from the shared reference
     * engine. */
    PCM_KEY_BODY body;
    NTSTATUS status = CmpReferenceKey(keyHandle, KEY_NOTIFY, FALSE, &body);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (asynchronous)
    {
        PVOID eventBody;
        status = ObReferenceObjectByHandle(eventHandle, SYNCHRONIZE, &ObpEventType,
                                           ExGetPreviousMode(), &eventBody, 0);
        if (NT_SUCCESS(status))
        {
            status = CmpArmNotify(body, eventBody, completionFilter, watchTree);
            if (NT_SUCCESS(status))
            {
                status = STATUS_PENDING;
            }
            else
            {
                ObDereferenceObject(eventBody);
            }
        }
        ObDereferenceObject(body);
        return status;
    }

    /* Synchronous: an internal, handle-less event carried by the same record
     * machinery, waited on right here. No Cm state is held across the wait —
     * the record owns its reference and the arming body stays alive through
     * the caller's handle. */
    PVOID eventBody;
    status = ObpAllocateObject(&ObpEventType, sizeof(KEVENT), &eventBody);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(body);
        return status;
    }
    KeInitializeEvent(eventBody, SynchronizationEvent, FALSE);
    ObfReferenceObject(eventBody); /* the record's reference */
    status = CmpArmNotify(body, eventBody, completionFilter, watchTree);
    ObDereferenceObject(body);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(eventBody); /* the record's would-be reference */
        ObDereferenceObject(eventBody); /* ours */
        return status;
    }
    status = KeWaitForSingleObject(eventBody, Executive, ExGetPreviousMode(), FALSE, 0);
    ObDereferenceObject(eventBody);
    return status;
}

NTSTATUS NtNotifyChangeKey(HANDLE keyHandle, HANDLE eventHandle, PIO_APC_ROUTINE apcRoutine,
                           PVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, ULONG completionFilter,
                           BOOLEAN watchTree, PVOID buffer, ULONG bufferSize, BOOLEAN asynchronous)
{
    /* The single-key form is the multiple-keys form with no subordinates
     * (wine dlls/ntdll/unix/registry.c NtNotifyChangeKey). */
    return NtNotifyChangeMultipleKeys(keyHandle, 0, 0, eventHandle, apcRoutine, apcContext,
                                      ioStatusBlock, completionFilter, watchTree, buffer,
                                      bufferSize, asynchronous);
}
