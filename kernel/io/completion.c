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
 * dispatcher lock, with a counting semaphore carrying the wakeups; a
 * blocking remove is KeWaitForSingleObject on the semaphore. The port body
 * BEGINS with the KSEMAPHORE, so a handle wait on the port degenerates to a
 * semaphore wait — nothing on the CUI path waits on port handles.
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

struct IO_COMPLETION
{
    KSEMAPHORE semaphore; /* count == queued packets; FIRST: handle waits land here */
    LIST_ENTRY queue;     /* IOP_COMPLETION_PACKET FIFO, dispatcher-lock guarded */
};

static void IopDeleteCompletion(PVOID body)
{
    PIO_COMPLETION port = body;
    while (!IsListEmpty(&port->queue))
    {
        PLIST_ENTRY head = RemoveHeadList(&port->queue);
        MiFreePool(CONTAINING_RECORD(head, IOP_COMPLETION_PACKET, entry));
    }
}

OBJECT_TYPE IoCompletionType = {
    .name = "IoCompletion",
    .validAccess = IO_COMPLETION_ALL_ACCESS,
    .waitable = TRUE,
    .deleteProcedure = IopDeleteCompletion,
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
        KeInitializeSemaphore(&port->semaphore, 0, 0x7fffffff);
        InitializeListHead(&port->queue);
    }
    return status;
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

    uint64_t flags = KiAcquireDispatcherLock();
    InsertTailList(&port->queue, &packet->entry);
    KiReleaseDispatcherLock(flags);
    KeReleaseSemaphore(&port->semaphore, 0, 1, FALSE);
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

/* Wait for one packet (bounded by `timeout`), pop it FIFO. */
static NTSTATUS IopRemoveOnePacket(PIO_COMPLETION port, PLARGE_INTEGER timeout,
                                   IOP_COMPLETION_PACKET *packetOut)
{
    NTSTATUS status =
        KeWaitForSingleObject(&port->semaphore, UserRequest, KernelMode, FALSE, timeout);
    if (status != STATUS_SUCCESS)
    {
        return status; /* STATUS_TIMEOUT */
    }
    uint64_t flags = KiAcquireDispatcherLock();
    ASSERT(!IsListEmpty(&port->queue)); /* the semaphore counts the queue */
    PLIST_ENTRY head = RemoveHeadList(&port->queue);
    KiReleaseDispatcherLock(flags);
    IOP_COMPLETION_PACKET *packet = CONTAINING_RECORD(head, IOP_COMPLETION_PACKET, entry);
    *packetOut = *packet;
    MiFreePool(packet);
    return STATUS_SUCCESS;
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
