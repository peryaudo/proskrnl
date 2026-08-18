/* kernel/io/completion.c — I/O completion ports (M10; the docs/04 Io slot).
 *
 * The consumer that forces this surface is ntdll's own threadpool
 * (third_party/wine dlls/ntdll/threadpool.c): RtlQueueWorkItem and every
 * Tp* dispatch through one NtCreateIoCompletion / NtRemoveIoCompletion(Ex)
 * loop fed by NtSetIoCompletion; kernelbase re-exports the same object as
 * CreateIoCompletionPort. Contract pinned by tests/ntapi/sem_port/ports.c
 * on the pinned oracle (wineserver's completion object, server/completion.c).
 *
 * Shape (Art. 3 — stupidly correct): a FIFO packet list guarded by the one
 * dispatcher lock, and the server's TWO wait channels kept apart, because
 * they answer different questions and a caller can see the difference
 * (ntdll:sync test_completion_port_scheduling; pinned by
 * tests/ntapi/sem_port/port_wait.c):
 *
 *   - the port HANDLE's signal state is `queued`, the server's
 *     `completion->sync` — created MANUAL-reset and clear
 *     (`create_internal_sync( 1, 0 )`, server/event.c), set when a packet is
 *     left UNCLAIMED, cleared when the queue empties, set on the last handle
 *     close. A handle wait therefore wakes EVERY waiter and consumes
 *     nothing.
 *
 *   - a parked NtRemoveIoCompletion(Ex) is the server's `completion_wait`:
 *     an entry on `waiters`, pushed at the HEAD (remove_completion's
 *     list_add_head) and served head-first by the poster (add_completion's
 *     forward iteration), i.e. LIFO. A parked remover takes the packet
 *     BEFORE the handle's signal state ever sees it.
 *
 * The body BEGINS with `queued`, so a handle wait on the port lands there.
 */
#include "kernel/io/io.h"
#include "kernel/ob/ob.h"
#include "kernel/ke/ke.h"
#include "kernel/mm/pool.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

typedef struct IOP_COMPLETION_PACKET
{
    LIST_ENTRY entry;
    ULONG_PTR key;
    ULONG_PTR value;
    NTSTATUS status;
    ULONG_PTR information;
} IOP_COMPLETION_PACKET;

/* One parked NtRemoveIoCompletion(Ex) — the server's `completion_wait`. It
 * lives on the PARKED THREAD'S KERNEL STACK and is unlinked before that frame
 * returns, so it needs no allocation and carries no lifetime rule of its own:
 * the parked syscall is holding the port reference that keeps the object
 * alive around it (G11). */
typedef struct IOP_COMPLETION_WAITER
{
    LIST_ENTRY entry;
    KEVENT wake; /* synchronization event, initially clear */
    /* The poster's hand-off, valid iff `served` — and a VALUE copy, so its
     * inherited `entry` links back into a pool block that is already freed.
     * Only key/value/status/information are ever read from it. */
    IOP_COMPLETION_PACKET packet;
    BOOLEAN linked;    /* still on IO_COMPLETION.waiters */
    BOOLEAN served;    /* a poster handed this waiter `packet` */
    BOOLEAN abandoned; /* the port's last handle closed under it */
} IOP_COMPLETION_WAITER;

struct IO_COMPLETION
{
    KEVENT queued;      /* FIRST: handle waits land here (the server's `sync`) */
    LIST_ENTRY queue;   /* IOP_COMPLETION_PACKET FIFO, dispatcher-lock guarded */
    LIST_ENTRY waiters; /* IOP_COMPLETION_WAITER, MOST RECENTLY PARKED FIRST */
};

static void IopDeleteCompletion(PVOID body)
{
    PIO_COMPLETION port = body;
    /* Every parked remover holds a reference, so none can be left here. */
    ASSERT(IsListEmpty(&port->waiters));
    while (!IsListEmpty(&port->queue))
    {
        PLIST_ENTRY head = RemoveHeadList(&port->queue);
        MiFreePool(CONTAINING_RECORD(head, IOP_COMPLETION_PACKET, entry));
    }
}

/* NT's OB_CLOSE_METHOD moment, and the server's `completion_close_handle`:
 * only the LAST handle in the system does anything, and then every parked
 * remover is abandoned (make_wait_abandoned -> STATUS_ABANDONED_WAIT_0) and
 * the handle's own signal state goes up, so a thread waiting on the HANDLE
 * comes back signalled rather than abandoned. */
static void IopCloseCompletion(PEPROCESS process, PVOID body, ULONG processHandleCount,
                               ULONG systemHandleCount)
{
    (void)process;
    (void)processHandleCount;
    if (systemHandleCount != 1)
    {
        return;
    }
    PIO_COMPLETION port = body;
    uint64_t flags = KiAcquireDispatcherLock();
    while (!IsListEmpty(&port->waiters))
    {
        PLIST_ENTRY head = RemoveHeadList(&port->waiters);
        IOP_COMPLETION_WAITER *waiter = CONTAINING_RECORD(head, IOP_COMPLETION_WAITER, entry);
        waiter->linked = FALSE;
        waiter->abandoned = TRUE;
        KiSetEventLocked(&waiter->wake);
    }
    KiSetEventLocked(&port->queued);
    KiReleaseDispatcherLock(flags);
}

OBJECT_TYPE IoCompletionType = {
    .name = "IoCompletion",
    .validAccess = IO_COMPLETION_ALL_ACCESS,
    .waitable = TRUE,
    .deleteProcedure = IopDeleteCompletion,
    .closeProcedure = IopCloseCompletion,
};

NTSTATUS NtCreateIoCompletion(PHANDLE handle, ACCESS_MASK access, POBJECT_ATTRIBUTES attr,
                              ULONG concurrentThreads)
{
    (void)concurrentThreads; /* a scheduler hint; uniprocessor (Art. 3) */
    NTSTATUS clearStatus = ObpClearOutHandle(handle);
    if (!NT_SUCCESS(clearStatus))
    {
        return clearStatus;
    }
    PVOID body;
    NTSTATUS status = ObpCreateObjectWithHandle(&IoCompletionType, sizeof(IO_COMPLETION), attr,
                                                access, &body, handle);
    if (status == STATUS_SUCCESS)
    {
        PIO_COMPLETION port = body;
        KeInitializeEvent(&port->queued, NotificationEvent, FALSE);
        InitializeListHead(&port->queue);
        InitializeListHead(&port->waiters);
    }
    return status;
}

/* Take the head packet, and drop the HANDLE's signal state when that empties
 * the queue — the server's `if (list_empty( &completion->queue )) reset_sync(
 * completion->sync )`. THE one dequeue site (Art. 11): the inline remove, the
 * batch drain and the poster's hand-off to a parked remover all come here, so
 * "signalled == an unclaimed packet is queued" is stated once. Returns the
 * pool block, for the caller to free once the lock is down. */
static IOP_COMPLETION_PACKET *IopTakePacketLocked(PIO_COMPLETION port)
{
    if (IsListEmpty(&port->queue))
    {
        return 0;
    }
    PLIST_ENTRY head = RemoveHeadList(&port->queue);
    if (IsListEmpty(&port->queue))
    {
        KiClearEventLocked(&port->queued);
    }
    return CONTAINING_RECORD(head, IOP_COMPLETION_PACKET, entry);
}

/* The one packet-posting engine (G10): NtSetIoCompletion resolves the
 * handle and lands here; kernel-internal producers with a referenced port
 * body (Ps job objects, CUI-3) call it directly. */
NTSTATUS IopPostCompletionPacket(PIO_COMPLETION port, ULONG_PTR key, ULONG_PTR value,
                                 NTSTATUS packetStatus, ULONG_PTR information)
{
    IOP_COMPLETION_PACKET *packet = MiAllocatePool(sizeof(*packet));
    if (packet == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    packet->key = key;
    packet->value = value;
    packet->status = packetStatus;
    packet->information = information;

    /* server/completion.c add_completion: the packet joins the queue, the
     * parked removers get first refusal head-first, and the HANDLE's signal
     * state is only touched by a packet none of them took ("if
     * (!list_empty( &completion->queue )) signal_sync( completion->sync )").
     * The decision and the transition are one step, which is why this holds
     * the lock across both (ke/event.c KiSetEventLocked). */
    IOP_COMPLETION_PACKET *handed = 0;
    uint64_t flags = KiAcquireDispatcherLock();
    InsertTailList(&port->queue, &packet->entry);
    if (!IsListEmpty(&port->waiters))
    {
        PLIST_ENTRY head = RemoveHeadList(&port->waiters);
        IOP_COMPLETION_WAITER *waiter = CONTAINING_RECORD(head, IOP_COMPLETION_WAITER, entry);
        /* Whatever is at the HEAD of the queue, not necessarily the packet
         * just posted — completion_wait_satisfied takes list_head() too. */
        handed = IopTakePacketLocked(port);
        ASSERT(handed != 0);
        waiter->packet = *handed;
        waiter->linked = FALSE;
        waiter->served = TRUE;
        KiSetEventLocked(&waiter->wake);
    }
    else
    {
        KiSetEventLocked(&port->queued);
    }
    KiReleaseDispatcherLock(flags);
    if (handed != 0)
    {
        MiFreePool(handed);
    }
    return STATUS_SUCCESS;
}

/* THE post-by-handle path, shared by both entry points (Art. 11). The ORDER
 * is the observable part and it is the server's: add_completion resolves the
 * PORT first and the reserve second (server/completion.c), so two bad handles
 * report the port's error. `reserveHandle == 0` is the plain form. */
static NTSTATUS IopSetCompletionByHandle(HANDLE handle, HANDLE reserveHandle, ULONG_PTR key,
                                         ULONG_PTR value, NTSTATUS packetStatus, SIZE_T information)
{
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(handle, IO_COMPLETION_MODIFY_STATE,
                                                &IoCompletionType, ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PVOID reserveBody = 0;
    if (reserveHandle != 0)
    {
        status = ObReferenceObjectByHandle(reserveHandle, 0, &ObpIoCompletionReserveType,
                                           ExGetPreviousMode(), &reserveBody, 0);
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(body);
            return status;
        }
    }
    status = IopPostCompletionPacket(body, key, value, packetStatus, information);
    if (reserveBody != 0)
    {
        ObDereferenceObject(reserveBody);
    }
    ObDereferenceObject(body);
    return status;
}

NTSTATUS NtSetIoCompletion(HANDLE handle, ULONG_PTR key, ULONG_PTR value, NTSTATUS packetStatus,
                           SIZE_T information)
{
    return IopSetCompletionByHandle(handle, 0, key, value, packetStatus, information);
}

/* CUI-5: open-by-name over the one Ob open engine (Art. 11), the
 * NtOpenDirectoryObject shape. Pinned by sem_port/ports.c. */
NTSTATUS NtOpenIoCompletion(PHANDLE handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr)
{
    NTSTATUS clearStatus = ObpClearOutHandle(handle);
    if (!NT_SUCCESS(clearStatus))
    {
        return clearStatus;
    }
    return ObpOpenObjectByName(&IoCompletionType, attr, access, handle);
}

/* CUI-5: the reserve-object post. A NULL reserve handle refuses before the
 * request is even built (dlls/ntdll/unix/sync.c NtSetIoCompletionEx), and a
 * non-NULL one must be an IoCompletionReserve specifically — the server
 * resolves it through get_completion_reserve_obj, whose ops argument makes
 * any other object a type mismatch (server/completion.c add_completion).
 * docs/21 W10 built the reserve objects; the reserve is NOT consumed by the
 * post (nothing binds it), so the same handle serves every packet. Pinned by
 * sem_port/ports.c. */
NTSTATUS NtSetIoCompletionEx(HANDLE handle, HANDLE reserveHandle, ULONG_PTR key, ULONG_PTR value,
                             NTSTATUS packetStatus, SIZE_T information)
{
    if (reserveHandle == 0)
    {
        return STATUS_INVALID_HANDLE;
    }
    return IopSetCompletionByHandle(handle, reserveHandle, key, value, packetStatus, information);
}

/* Take one packet FIFO, parking (bounded by `timeout`) if there is none.
 * Mirrors the server's remove_completion: the queue is checked first and the
 * caller only joins `waiters` when it is empty, so a remover that never has
 * to park never appears in the fan-out at all. */
static NTSTATUS IopRemoveOnePacket(PIO_COMPLETION port, PLARGE_INTEGER timeout,
                                   IOP_COMPLETION_PACKET *packetOut)
{
    uint64_t flags = KiAcquireDispatcherLock();
    IOP_COMPLETION_PACKET *packet = IopTakePacketLocked(port);
    if (packet != 0)
    {
        KiReleaseDispatcherLock(flags);
        *packetOut = *packet;
        MiFreePool(packet);
        return STATUS_SUCCESS;
    }
    IOP_COMPLETION_WAITER waiter;
    KeInitializeEvent(&waiter.wake, SynchronizationEvent, FALSE);
    waiter.linked = TRUE;
    waiter.served = FALSE;
    waiter.abandoned = FALSE;
    InsertHeadList(&port->waiters, &waiter.entry); /* LIFO: list_add_head */
    KiReleaseDispatcherLock(flags);

    NTSTATUS status = KeWaitForSingleObject(&waiter.wake, UserRequest, KernelMode, FALSE, timeout);

    flags = KiAcquireDispatcherLock();
    if (waiter.linked)
    {
        RemoveEntryList(&waiter.entry);
        waiter.linked = FALSE;
    }
    KiReleaseDispatcherLock(flags);

    /* A hand-off that raced the deadline still owns the packet: the poster
     * already took it off the queue, so there is nothing to give it back to
     * and the wait's own status cannot be the answer. */
    if (waiter.served)
    {
        *packetOut = waiter.packet;
        return STATUS_SUCCESS;
    }
    if (waiter.abandoned)
    {
        return STATUS_ABANDONED_WAIT_0;
    }
    /* `wake` starts clear and its only two setters — the poster's hand-off
     * and the close — set their flag first, under the same lock. So a wait
     * this reaches was NOT satisfied, and `packetOut` is untouched on
     * purpose rather than by omission. */
    ASSERT(status != STATUS_SUCCESS);
    return status; /* STATUS_TIMEOUT */
}

NTSTATUS NtRemoveIoCompletion(HANDLE handle, PULONG_PTR keyOut, PULONG_PTR valueOut,
                              PIO_STATUS_BLOCK ioStatusBlock, PLARGE_INTEGER timeout)
{
    if (keyOut == 0 || valueOut == 0 || ioStatusBlock == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(keyOut, sizeof(*keyOut), sizeof(ULONG_PTR));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(valueOut, sizeof(*valueOut), sizeof(ULONG_PTR));
    }
    if (NT_SUCCESS(status))
    {
        status = IopProbeIosb(ioStatusBlock);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    LARGE_INTEGER capturedTimeout;
    PLARGE_INTEGER deadline;
    status = KiCaptureTimeout(timeout, &capturedTimeout, &deadline);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PVOID body;
    status = ObReferenceObjectByHandle(handle, IO_COMPLETION_MODIFY_STATE, &IoCompletionType,
                                       ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PIO_COMPLETION port = body;
    IOP_COMPLETION_PACKET packet;
    status = IopRemoveOnePacket(port, deadline, &packet);
    if (status == STATUS_SUCCESS)
    {
        *keyOut = packet.key;
        *valueOut = packet.value;
        IopWriteIosb(ioStatusBlock, packet.status, packet.information);
    }
    ObDereferenceObject(port);
    return status;
}

NTSTATUS NtRemoveIoCompletionEx(HANDLE handle, FILE_IO_COMPLETION_INFORMATION *information,
                                ULONG count, PULONG writtenOut, PLARGE_INTEGER timeout,
                                BOOLEAN alertable)
{
    (void)alertable; /* the CUI path never removes alertably */
    if (information == 0 || writtenOut == 0 || count == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = KiProbeForWrite(information, count * sizeof(*information), sizeof(ULONG_PTR));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(writtenOut, sizeof(*writtenOut), sizeof(ULONG));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* Captured, and not merely probed, because the drain below waits MORE
     * THAN ONCE: re-reading the caller's LARGE_INTEGER after a park is the
     * stale-probe shape (uaccess.h KiCaptureTimeout). */
    LARGE_INTEGER capturedTimeout;
    PLARGE_INTEGER deadline;
    status = KiCaptureTimeout(timeout, &capturedTimeout, &deadline);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PVOID body;
    status = ObReferenceObjectByHandle(handle, IO_COMPLETION_MODIFY_STATE, &IoCompletionType,
                                       ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PIO_COMPLETION port = body;

    /* One bounded wait for the first packet, then drain (never wait again)
     * up to `count` — the batch is whatever is ready. */
    ULONG written = 0;
    IOP_COMPLETION_PACKET packet;
    status = IopRemoveOnePacket(port, deadline, &packet);
    while (status == STATUS_SUCCESS)
    {
        information[written].CompletionKey = packet.key;
        information[written].CompletionValue = packet.value;
        information[written].IoStatusBlock.Status = packet.status;
        information[written].IoStatusBlock.Information = packet.information;
        written++;
        if (written == count)
        {
            break;
        }
        LARGE_INTEGER zero;
        zero.QuadPart = 0;
        status = IopRemoveOnePacket(port, &zero, &packet);
    }
    if (written != 0)
    {
        status = STATUS_SUCCESS; /* a partial batch is a success */
    }
    *writtenOut = written;
    ObDereferenceObject(port);
    return status;
}

NTSTATUS NtQueryIoCompletion(HANDLE handle, IO_COMPLETION_INFORMATION_CLASS informationClass,
                             PVOID buffer, ULONG length, PULONG returnLength)
{
    if (buffer == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (informationClass != IoCompletionBasicInformation)
    {
        return STATUS_INVALID_PARAMETER;
    }
    /* The class is one exact-length ULONG depth (Wine
     * dlls/ntdll/unix/sync.c NtQueryIoCompletion; ret_len is written even
     * on the length mismatch). */
    if (returnLength != 0 &&
        NT_SUCCESS(KiProbeForWrite(returnLength, sizeof(ULONG), sizeof(ULONG))))
    {
        *returnLength = sizeof(ULONG);
    }
    if (length != sizeof(ULONG))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    NTSTATUS status = KiProbeForWrite(buffer, sizeof(ULONG), sizeof(ULONG));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PVOID body;
    status = ObReferenceObjectByHandle(handle, IO_COMPLETION_QUERY_STATE, &IoCompletionType,
                                       ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PIO_COMPLETION port = body;
    uint64_t flags = KiAcquireDispatcherLock();
    ULONG depth = 0;
    for (PLIST_ENTRY entry = port->queue.Flink; entry != &port->queue; entry = entry->Flink)
    {
        depth++;
    }
    KiReleaseDispatcherLock(flags);
    *(ULONG *)buffer = depth;
    ObDereferenceObject(port);
    return STATUS_SUCCESS;
}
