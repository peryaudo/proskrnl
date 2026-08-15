/* fs/npfs/pipe.c — the named-pipe filesystem (M9; see npfs.h).
 *
 * Semantics pinned by tests/ntapi/sem_pipe/ on the Wine oracle. The shape:
 *
 *   NPFS_PIPE          one per name under \Device\NamedPipe
 *     NPFS_INSTANCE    one per NtCreateNamedPipeFile (embeds IO_FCB first);
 *                      owns two NPFS_QUEUEs (inbound = client->server) and
 *                      the connect event; carries the FILE_PIPE_*_STATE
 *       NPFS_END       one per open end (file->fsContext); read/completion
 *                      modes live here (they are per-handle-end on NT)
 *
 * Blocking (reads on empty, writes over quota, FSCTL_PIPE_LISTEN) parks on
 * notification KEVENTs with a clear-then-wait loop: with one CPU and no
 * kernel preemption (Art. 3) nothing can slip between the condition check
 * and the clear, so no wakeup is ever lost. Every state transition wakes
 * every event (the peer may be parked on any of them) — the classic
 * missed-wake hang is structural, not lucky.
 */
#include "fs/npfs/npfs.h"
#include "kernel/io/io.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/lib/list.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/init/panic.h"

#include "abi/ntioapi.h"

/* --- structures ------------------------------------------------------------- */

typedef struct NPFS_BUFFER
{
    LIST_ENTRY listEntry;
    ULONG length;   /* payload bytes (0 = a zero-byte message) */
    ULONG consumed; /* read cursor within the payload */
    unsigned char data[];
} NPFS_BUFFER, *PNPFS_BUFFER;

typedef struct NPFS_QUEUE
{
    LIST_ENTRY bufferList; /* NPFS_BUFFER, oldest first */
    ULONG bytesAvailable;  /* unread payload bytes across the list */
    ULONG quota;           /* creation quota this direction */
    /* Bumped by every READ that leaves this queue empty. That instant — not
     * the queue merely BEING empty — is when a parked NpfsFlush completes,
     * and the two differ because a disconnect empties the queue too
     * (NpfsFlushQueue) while owing the flush a different status. */
    ULONG drainSeq;
    KEVENT dataEvent;  /* notification: data arrived / state changed */
    KEVENT spaceEvent; /* notification: space freed / state changed */
} NPFS_QUEUE, *PNPFS_QUEUE;

typedef struct NPFS_PIPE
{
    LIST_ENTRY listEntry; /* on NpfsPipeList */
    UNICODE_STRING name;  /* pool copy, no leading backslash */
    ULONG pipeType;       /* FILE_PIPE_TYPE_* */

    /* The create's SHARE mask, stored raw rather than as the
     * FILE_PIPE_{INBOUND,OUTBOUND,FULL_DUPLEX} it renders to. It is the fact
     * two later rules read back — a further instance must present the SAME
     * mask (NtCreateNamedPipeFile) and a client's access is bounded by it
     * (NpfsVfsCreate) — so it has one home and NpfsConfigurationFromShare is
     * a view of it, not a second copy. */
    ULONG sharing;
    ULONG maxInstances;
    ULONG inQuota;
    ULONG outQuota;
    LIST_ENTRY instanceList; /* NPFS_INSTANCE */
    ULONG instanceCount;

    /* CUI-3: NtCreateNamedPipeFile's timeout parameter — the default an
     * FSCTL_PIPE_WAIT with TimeoutSpecified == FALSE falls back to
     * (wine/server/named_pipe.c: `when = ... : pipe->timeout`). */
    LARGE_INTEGER defaultTimeout;
} NPFS_PIPE, *PNPFS_PIPE;

typedef struct NPFS_INSTANCE
{
    IO_FCB header; /* embedded FIRST (kernel/io/vfs.h contract) */
    LIST_ENTRY listEntry;
    PNPFS_PIPE pipe;            /* 0 once unlinked (server end closed) */
    ULONG state;                /* FILE_PIPE_*_STATE */
    struct NPFS_END *serverEnd; /* 0 after that end's cleanup */
    struct NPFS_END *clientEnd;
    LONG endCount;       /* live NPFS_ENDs; instance freed at 0 */
    NPFS_QUEUE inbound;  /* client -> server */
    NPFS_QUEUE outbound; /* server -> client */
    KEVENT connectEvent; /* notification: connect / state changed */

    /* CUI-3: the parked async listens (kernel/io/async.c), in submission
     * order. Owned here: completed by client attach, NtCancelIoFile(Ex), or
     * the server end's cleanup — whichever comes first (G11).
     *
     * A QUEUE, not one slot. A second concurrent async listen used to
     * refuse with STATUS_NOT_IMPLEMENTED, which under the (default-on)
     * arming flag is a kernel panic — reached by the standard accept-loop
     * idiom, which submits the next listen before the previous one
     * completes, and which the oracle supports by queueing
     * (docs/review-2026-07 §5). */
    LIST_ENTRY pendingListenHead;
} NPFS_INSTANCE, *PNPFS_INSTANCE;

typedef struct NPFS_END
{
    PNPFS_INSTANCE instance;
    BOOLEAN isServer;
    BOOLEAN orphaned;     /* disconnected out from under this end */
    ULONG readMode;       /* FILE_PIPE_{BYTE_STREAM,MESSAGE}_MODE */
    ULONG completionMode; /* FILE_PIPE_{QUEUE,COMPLETE}_OPERATION */

    /* CUI-8: the parked async READS (kernel/io/async.c), in issue order.
     * Per END rather than per instance, because a read consumes from this
     * end's INCOMING queue and the two directions are independent.
     *
     * Owned here, and every way one can end reaches a completer (G11): the
     * peer's write or state change (NpfsServicePendingReads, driven from
     * NpfsWakeAll and from the append), NtCancelIoFile, and this handle's
     * own cleanup. Each request holds a reference to the FILE_OBJECT, so an
     * abandoned one would never be freed either — which is why the cleanup
     * arm is not optional. */
    LIST_ENTRY pendingReadHead;
} NPFS_END, *PNPFS_END;

/* The flat pipe namespace (one dispatcher lock, no preemption: plain lists
 * mutated only between blocking points are already atomic — Art. 3). */
static LIST_ENTRY NpfsPipeList;
static PIO_DEVICE NpfsDevice;

/* CUI-3: FCB for opens of the device ROOT ("\??\PIPE\" — the WaitNamedPipe
 * handle, kernelbase/sync.c WaitNamedPipeW). Root FILE_OBJECTs carry
 * fsContext == 0 as their marker. */
static IO_FCB NpfsRootFcb;

/* Signalled whenever a listening instance may have APPEARED (instance
 * creation, disconnect->listening) — the wake FSCTL_PIPE_WAIT parks on
 * (mirrors wineserver's async_wake_up(&pipe->waiters), named_pipe.c). One
 * GLOBAL event, not per-pipe: waiters re-look the pipe up per wake, which
 * sidesteps the pipe-lifetime hazard at the cost of spurious re-checks. */
static KEVENT NpfsListenersChangedEvent;

/* --- helpers ---------------------------------------------------------------- */

static PNPFS_QUEUE NpfsIncomingQueue(PNPFS_END end)
{
    return end->isServer ? &end->instance->inbound : &end->instance->outbound;
}

static PNPFS_QUEUE NpfsOutgoingQueue(PNPFS_END end)
{
    return end->isServer ? &end->instance->outbound : &end->instance->inbound;
}

static void NpfsServiceInstance(PNPFS_INSTANCE instance);

/* Wake every waiter on the instance — any state transition may unblock a
 * read, a write, or a listen parked on the other side — and then COMPLETE
 * every parked async read the new state can answer.
 *
 * The two belong together and that is why the service call is here rather
 * than at the four call sites: a parked THREAD re-checks its condition when
 * its event fires, while a parked REQUEST has no thread to do that, so the
 * transition itself has to complete it. Every caller reaches this at a
 * clean point — the state word and the end pointers are final before it is
 * called — which is what makes completing from inside the wake safe. */
static void NpfsWakeAll(PNPFS_INSTANCE instance)
{
    KeSetEvent(&instance->inbound.dataEvent, 0, FALSE);
    KeSetEvent(&instance->inbound.spaceEvent, 0, FALSE);
    KeSetEvent(&instance->outbound.dataEvent, 0, FALSE);
    KeSetEvent(&instance->outbound.spaceEvent, 0, FALSE);
    KeSetEvent(&instance->connectEvent, 0, FALSE);
    NpfsServiceInstance(instance);
}

/* Clear-then-wait: safe against lost wakeups because nothing runs between
 * the caller's condition check and this park (uniprocessor, no preemption).
 * Returns the wait status so a foreign terminate (CUI-4,
 * STATUS_THREAD_IS_TERMINATING) breaks the caller's re-park loop instead of
 * trapping a dying thread. */
static NTSTATUS NpfsWait(PKEVENT event)
{
    KeClearEvent(event);
    /* CUI-5: the park is cancellable — NtCancelSynchronousIoFile against
     * the parked thread breaks it with STATUS_CANCELLED. */
    return IoWaitCancellable(event, 0);
}

static void NpfsFlushQueue(PNPFS_QUEUE queue)
{
    while (!IsListEmpty(&queue->bufferList))
    {
        PLIST_ENTRY entry = RemoveHeadList(&queue->bufferList);
        MiFreePool(CONTAINING_RECORD(entry, NPFS_BUFFER, listEntry));
    }
    queue->bytesAvailable = 0;
}

static void NpfsInitializeQueue(PNPFS_QUEUE queue, ULONG quota)
{
    InitializeListHead(&queue->bufferList);
    queue->bytesAvailable = 0;
    queue->quota = quota;
    queue->drainSeq = 0;
    KeInitializeEvent(&queue->dataEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&queue->spaceEvent, NotificationEvent, FALSE);
}

static PNPFS_PIPE NpfsFindPipe(const UNICODE_STRING *name)
{
    for (PLIST_ENTRY entry = NpfsPipeList.Flink; entry != &NpfsPipeList; entry = entry->Flink)
    {
        PNPFS_PIPE pipe = CONTAINING_RECORD(entry, NPFS_PIPE, listEntry);
        if (RtlEqualUnicodeString(&pipe->name, name, TRUE))
        {
            return pipe;
        }
    }
    return 0;
}

/* An end whose instance was disconnected/relinked out from under it (or the
 * whole-instance disconnect state) answers PIPE_DISCONNECTED to data ops. */
static BOOLEAN NpfsEndDisconnected(PNPFS_END end)
{
    return end->orphaned || end->instance->state == FILE_PIPE_DISCONNECTED_STATE;
}

/* Render the pipe's share mask as the configuration FilePipeLocalInformation
 * reports, the way Wine's kernelbase spells the PIPE_ACCESS_* modes
 * (dlls/kernelbase/sync.c CreateNamedPipeW: INBOUND -> FILE_SHARE_WRITE,
 * OUTBOUND -> FILE_SHARE_READ, DUPLEX -> both). A VIEW of NPFS_PIPE.sharing,
 * computed on demand — the mask is the stored fact. */
static ULONG NpfsConfigurationFromShare(ULONG sharing)
{
    if ((sharing & (FILE_SHARE_READ | FILE_SHARE_WRITE)) == (FILE_SHARE_READ | FILE_SHARE_WRITE))
    {
        return FILE_PIPE_FULL_DUPLEX;
    }
    return (sharing & FILE_SHARE_WRITE) ? FILE_PIPE_INBOUND : FILE_PIPE_OUTBOUND;
}

/* --- the data path ---------------------------------------------------------- */

/* CAN a read on `end` be answered right now? STATUS_SUCCESS means there are
 * bytes to drain; STATUS_PENDING means there is nothing to report yet;
 * anything else is the read's final answer.
 *
 * One statement of the rule for all three consumers (Art. 11): the blocking
 * loop's re-check, the asynchronous issue path's decision to park, and the
 * sweep that completes parked requests. `queuedAhead` says an OLDER request
 * on this end is still parked — NT serves a handle's asyncs in issue order,
 * so an arriving read must not overtake one (pinned pended_read.c case 7).
 * Only the data arm consults it: the failure arms consume nothing, so every
 * request on the queue is about to get the same answer anyway.
 *
 * FILE_PIPE_COMPLETE_OPERATION is deliberately NOT here. It is not a fact
 * about the stream, it is what the ISSUER does when the answer is "nothing
 * yet" — so it lives in NpfsRead, and a request that parked while the end
 * was in wait mode stays parked if the mode is switched under it. */
static NTSTATUS NpfsReadReady(PNPFS_END end, BOOLEAN queuedAhead)
{
    PNPFS_INSTANCE instance = end->instance;
    PNPFS_QUEUE queue = NpfsIncomingQueue(end);

    if (NpfsEndDisconnected(end))
    {
        return STATUS_PIPE_DISCONNECTED;
    }
    if (instance->state == FILE_PIPE_LISTENING_STATE)
    {
        return STATUS_PIPE_LISTENING;
    }
    if (!IsListEmpty(&queue->bufferList))
    {
        return queuedAhead ? STATUS_PENDING : STATUS_SUCCESS;
    }
    if (instance->state == FILE_PIPE_CLOSING_STATE)
    {
        return STATUS_PIPE_BROKEN; /* peer gone, nothing buffered */
    }
    return STATUS_PENDING;
}

/* Move bytes out of the end's incoming queue. Precondition: NpfsReadReady
 * just answered STATUS_SUCCESS, so the queue is non-empty. */
static NTSTATUS NpfsReadDrain(PNPFS_END end, void *buffer, ULONG length, ULONG_PTR *infoOut)
{
    PNPFS_QUEUE queue = NpfsIncomingQueue(end);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG copied = 0;
    if (end->readMode == FILE_PIPE_MESSAGE_MODE)
    {
        /* One message per read; a short buffer keeps the tail as the SAME
         * message and answers BUFFER_OVERFLOW (sem_pipe/message_mode). */
        PNPFS_BUFFER message = CONTAINING_RECORD(queue->bufferList.Flink, NPFS_BUFFER, listEntry);
        ULONG remaining = message->length - message->consumed;
        copied = remaining < length ? remaining : length;
        if (copied != 0)
        {
            /* `buffer` is 0 for a zero-length read, which reaches here as a
             * legitimate request (a message-mode caller probing for the next
             * message's size gets BUFFER_OVERFLOW and 0 bytes). */
            memcpy(buffer, message->data + message->consumed, copied);
        }
        message->consumed += copied;
        if (message->consumed == message->length)
        {
            RemoveHeadList(&queue->bufferList);
            MiFreePool(message);
        }
        else
        {
            status = STATUS_BUFFER_OVERFLOW;
        }
    }
    else
    {
        /* Byte stream: drain across buffers up to the request. */
        while (copied < length && !IsListEmpty(&queue->bufferList))
        {
            PNPFS_BUFFER chunk = CONTAINING_RECORD(queue->bufferList.Flink, NPFS_BUFFER, listEntry);
            ULONG take = chunk->length - chunk->consumed;
            if (take > length - copied)
            {
                take = length - copied;
            }
            memcpy((unsigned char *)buffer + copied, chunk->data + chunk->consumed, take);
            chunk->consumed += take;
            copied += take;
            if (chunk->consumed == chunk->length)
            {
                RemoveHeadList(&queue->bufferList);
                MiFreePool(chunk);
            }
        }
    }
    ASSERT(queue->bytesAvailable >= copied);
    queue->bytesAvailable -= copied;
    if (IsListEmpty(&queue->bufferList))
    {
        queue->drainSeq++; /* the instant a parked NpfsFlush is satisfied */
    }
    /* A parked writer re-checks its quota, and a parked NpfsFlush re-checks
     * the sequence above. The wake cannot be keyed on `copied` for the
     * flush's sake: a zero-byte message consumes no bytes and still leaves
     * the queue drained. The loop above only breaks with a buffer present,
     * so every read that reaches here made progress. */
    KeSetEvent(&queue->spaceEvent, 0, FALSE);
    *infoOut = copied;
    return status;
}

/* Complete every read parked on `end` that the CURRENT state can answer.
 * Runs in whatever context changed that state — the peer's NtWriteFile, a
 * disconnect, a close — never in the issuer's.
 *
 * Oldest first, and it STOPS at the first request that must still wait,
 * which is what makes the queue order observable rather than incidental:
 * one write that only covers the head request leaves the rest parked. */
static void NpfsServicePendingReads(PNPFS_END end)
{
    while (!IsListEmpty(&end->pendingReadHead))
    {
        NTSTATUS status = NpfsReadReady(end, /* queuedAhead */ FALSE);
        if (status == STATUS_PENDING)
        {
            return;
        }
        PIOP_PENDING_REQUEST pending =
            CONTAINING_RECORD(end->pendingReadHead.Flink, IOP_PENDING_REQUEST, queueEntry);
        ULONG_PTR transferred = 0;
        if (status == STATUS_SUCCESS)
        {
            /* Into the request's OWN bounce (the buffer rw.c allocated and
             * handed over), never the caller's VA: this is not the owner's
             * address space. kernel/io/async.c places the bytes. */
            status = NpfsReadDrain(end, pending->kernelBuffer, pending->bufferLength, &transferred);
        }
        RemoveEntryList(&pending->queueEntry);
        IopCompletePendingRequest(pending, status, transferred);
    }
}

static void NpfsServiceInstance(PNPFS_INSTANCE instance)
{
    if (instance->serverEnd != 0)
    {
        NpfsServicePendingReads(instance->serverEnd);
    }
    if (instance->clientEnd != 0)
    {
        NpfsServicePendingReads(instance->clientEnd);
    }
}

static NTSTATUS NpfsRead(PFILE_OBJECT file, void *buffer, ULONG length, ULONG_PTR *infoOut,
                         IO_CONTROL_CONTEXT *request)
{
    PNPFS_END end = file->fsContext;

    for (;;)
    {
        NTSTATUS status = NpfsReadReady(end, !IsListEmpty(&end->pendingReadHead));
        if (status == STATUS_SUCCESS)
        {
            return NpfsReadDrain(end, buffer, length, infoOut);
        }
        if (status != STATUS_PENDING)
        {
            return status;
        }
        /* Nothing to report yet, so what happens next is the ISSUER's
         * property, not the stream's. */
        if (end->completionMode == FILE_PIPE_COMPLETE_OPERATION)
        {
            return STATUS_PIPE_EMPTY; /* PIPE_NOWAIT: never waits, never pends */
        }
        if (!file->synchronousIo)
        {
            /* CUI-8: an ASYNCHRONOUS handle genuinely pends rather than
             * parking this thread, and the difference is a deadlock rather
             * than a latency: the standard overlapped idiom issues the read
             * and then satisfies it FROM THE SAME THREAD (ntdll:pipe
             * pipe.c:1578/:1583, kernel32:virtual's test_write_watch,
             * kernel32:pipe's overlapped server). A thread parked inside the
             * read never reaches the write it is waiting for. Pinned by
             * sem_pipe/pended_read.c; docs/03 "CUI-8 async notes".
             *
             * A QUEUE, not one slot — the same shape the listen queue took
             * for the same reason (an accept loop submits the next request
             * before the previous one completes). */
            PIOP_PENDING_REQUEST pending = 0;
            status = IopPreparePendingRequest(file, request, &pending);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            InsertTailList(&end->pendingReadHead, &pending->queueEntry);
            return STATUS_PENDING;
        }
        NTSTATUS waitStatus = NpfsWait(&NpfsIncomingQueue(end)->dataEvent);
        if (waitStatus != STATUS_SUCCESS)
        {
            return waitStatus; /* CUI-4: foreign terminate breaks the read park */
        }
    }
}

/* NtFlushBuffersFile on a pipe end (kernel/io/rw.c IopFlushBuffers): park
 * until the PEER has consumed everything this end wrote. Transcribed from
 * wine/server/named_pipe.c pipe_end_flush, whose whole body is
 *
 *     if (!pipe_end->pipe) { set_error( STATUS_PIPE_DISCONNECTED ); return; }
 *     if (pipe_end->connection && !list_empty( &pipe_end->connection->message_queue ))
 *         { fd_queue_async( ..., ASYNC_TYPE_WAIT ); set_error( STATUS_PENDING ); }
 *
 * — three facts, none of which follows from the verb's name:
 *
 *   - the queue it waits on is the PEER's (this end's OUTGOING), so a flush
 *     never waits for data somebody sent US;
 *   - `!pipe_end->pipe` is exactly the end a server DISCONNECTED out from
 *     under, i.e. end->orphaned. The server's OWN end keeps its pipe, so the
 *     same disconnect leaves it answering STATUS_SUCCESS while its client
 *     answers STATUS_PIPE_DISCONNECTED;
 *   - with no `connection` there is nothing to drain the queue, so a
 *     listening instance and a closed peer are both immediate successes,
 *     buffered bytes or not. Waiting on the queue alone hangs there.
 *
 * The PARKED case is a fourth answer, and it is the one that stops a caller
 * waiting forever: pipe_end_disconnect wakes the fd's wait queue with its own
 * status (fd_async_wake_up(pipe_end->fd, ASYNC_TYPE_WAIT, status)), so a
 * flush that was already waiting reports STATUS_PIPE_DISCONNECTED when the
 * server disconnects and STATUS_PIPE_BROKEN when the peer closes — where a
 * flush issued after either event reports success. Pinned both ways by
 * tests/ntapi/sem_pipe/flush_buffers.c.
 *
 * Which makes the ORDER of the re-check load-bearing, and it is why the drain
 * is a SEQUENCE rather than a look at the queue. The oracle decides a parked
 * flush's status at the transition — reselect_read_queue terminates the async
 * the moment the read empties the queue — so a later disconnect cannot change
 * an answer that has already been given. A re-check that merely asked "is the
 * queue empty now" cannot tell a drain from a disconnect's own
 * NpfsFlushQueue, and cannot see the drain at all once the peer has closed:
 * kernel32:pipe's echo servers read and CLOSE before the flusher is next
 * scheduled, so all 24 of their flushes answered STATUS_PIPE_BROKEN. */
static NTSTATUS NpfsFlush(PFILE_OBJECT file)
{
    PNPFS_END end = file->fsContext;
    if (end == 0)
    {
        return STATUS_SUCCESS; /* a device-root open carries no stream */
    }
    PNPFS_INSTANCE instance = end->instance;
    PNPFS_QUEUE queue = NpfsOutgoingQueue(end);
    ULONG drainSeq = queue->drainSeq;
    BOOLEAN parked = FALSE;

    for (;;)
    {
        if (parked && queue->drainSeq != drainSeq)
        {
            return STATUS_SUCCESS; /* a read emptied it: already completed */
        }
        if (end->orphaned)
        {
            return STATUS_PIPE_DISCONNECTED;
        }
        if (instance->state != FILE_PIPE_CONNECTED_STATE)
        {
            if (!parked)
            {
                return STATUS_SUCCESS;
            }
            return instance->state == FILE_PIPE_DISCONNECTED_STATE ? STATUS_PIPE_DISCONNECTED
                                                                   : STATUS_PIPE_BROKEN;
        }
        if (IsListEmpty(&queue->bufferList))
        {
            return STATUS_SUCCESS;
        }
        NTSTATUS waitStatus = NpfsWait(&queue->spaceEvent);
        if (waitStatus != STATUS_SUCCESS)
        {
            return waitStatus; /* CUI-4: foreign terminate breaks the flush park */
        }
        parked = TRUE;
    }
}

/* Append one pooled buffer to `queue` and wake its reader — a parked THREAD
 * through the data event, and a parked async REQUEST by completing it here
 * and now (CUI-8). Both legs live in this one function so that "data
 * arrived" and "whoever was waiting for it hears about it" cannot come
 * apart: a caller that appended without servicing would leave a pended read
 * parked on bytes that are already in the queue. */
static NTSTATUS NpfsAppendBuffer(PNPFS_INSTANCE instance, PNPFS_QUEUE queue, const void *data,
                                 ULONG length)
{
    PNPFS_BUFFER buffer = MiAllocatePool(sizeof(NPFS_BUFFER) + length);
    if (buffer == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    buffer->length = length;
    buffer->consumed = 0;
    if (length != 0)
    {
        memcpy(buffer->data, data, length);
    }
    InsertTailList(&queue->bufferList, &buffer->listEntry);
    queue->bytesAvailable += length;
    KeSetEvent(&queue->dataEvent, 0, FALSE);
    NpfsServiceInstance(instance);
    return STATUS_SUCCESS;
}

/* The shared "is this end allowed to move data" gate for writes. */
static NTSTATUS NpfsCheckWritableState(PNPFS_END end)
{
    if (NpfsEndDisconnected(end))
    {
        return STATUS_PIPE_DISCONNECTED;
    }
    switch (end->instance->state)
    {
    case FILE_PIPE_LISTENING_STATE:
        return STATUS_PIPE_LISTENING;
    case FILE_PIPE_CLOSING_STATE:
        return STATUS_PIPE_CLOSING; /* peer gone (sem_pipe/create_pipe) */
    default:
        return STATUS_SUCCESS;
    }
}

static NTSTATUS NpfsWrite(PFILE_OBJECT file, const void *buffer, ULONG length, ULONG_PTR *infoOut)
{
    PNPFS_END end = file->fsContext;
    PNPFS_PIPE pipe = end->instance->pipe;
    PNPFS_QUEUE queue = NpfsOutgoingQueue(end);
    ULONG pipeType = pipe != 0 ? pipe->pipeType : FILE_PIPE_TYPE_BYTE;

    NTSTATUS status = NpfsCheckWritableState(end);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (pipeType == FILE_PIPE_TYPE_MESSAGE)
    {
        /* A message is framed whole. Park until it fits under the quota —
         * or the queue is fully drained, which admits an oversized message
         * (the reader then drains it across several reads). */
        for (;;)
        {
            status = NpfsCheckWritableState(end);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            if (queue->bytesAvailable == 0 || queue->bytesAvailable + length <= queue->quota)
            {
                break;
            }
            status = NpfsWait(&queue->spaceEvent);
            if (status != STATUS_SUCCESS)
            {
                return status; /* CUI-4: foreign terminate breaks the write park */
            }
        }
        status = NpfsAppendBuffer(end->instance, queue, buffer, length);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        *infoOut = length;
        return STATUS_SUCCESS;
    }

    /* Byte stream: a zero-length write is a no-op; longer writes chunk into
     * whatever quota space exists and park for the reader to drain the rest
     * (sem_pipe/pipe_blocking's quota-crossing write). */
    ULONG written = 0;
    while (written < length)
    {
        status = NpfsCheckWritableState(end);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        ULONG space =
            queue->quota > queue->bytesAvailable ? queue->quota - queue->bytesAvailable : 0;
        if (space == 0)
        {
            status = NpfsWait(&queue->spaceEvent);
            if (status != STATUS_SUCCESS)
            {
                return status; /* CUI-4: foreign terminate breaks the write park */
            }
            continue;
        }
        ULONG chunk = length - written;
        if (chunk > space)
        {
            chunk = space;
        }
        status =
            NpfsAppendBuffer(end->instance, queue, (const unsigned char *)buffer + written, chunk);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        written += chunk;
    }
    *infoOut = written;
    return STATUS_SUCCESS;
}

/* --- FSCTL verbs ------------------------------------------------------------ */

/* Does `pipe` have an instance a client could attach to right now? (The
 * same test NpfsVfsCreate's attach loop applies.) */
static BOOLEAN NpfsHasListener(PNPFS_PIPE pipe)
{
    for (PLIST_ENTRY entry = pipe->instanceList.Flink; entry != &pipe->instanceList;
         entry = entry->Flink)
    {
        PNPFS_INSTANCE candidate = CONTAINING_RECORD(entry, NPFS_INSTANCE, listEntry);
        if (candidate->state == FILE_PIPE_LISTENING_STATE && candidate->serverEnd != 0)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/* FSCTL_PIPE_WAIT on the device root: the WaitNamedPipe path both rpcrt4's
 * ncacn_np client open and sechost's service_open_pipe take. Semantics
 * transcribed from wine/server/named_pipe.c named_pipe_dir_ioctl
 * FSCTL_PIPE_WAIT + kernelbase/sync.c WaitNamedPipeW; pinned by
 * sem_pipe/pipe_wait.c. */
static NTSTATUS NpfsWaitForPipe(const void *input, ULONG inputLength)
{
    const FILE_PIPE_WAIT_FOR_BUFFER *wait = input;
    if (inputLength < sizeof(*wait) ||
        inputLength < offsetof(FILE_PIPE_WAIT_FOR_BUFFER, Name) + wait->NameLength)
    {
        return STATUS_INVALID_PARAMETER;
    }
    UNICODE_STRING name;
    name.Buffer = (PWSTR)wait->Name;
    name.Length = (USHORT)((wait->NameLength / sizeof(WCHAR)) * sizeof(WCHAR));
    name.MaximumLength = name.Length;

    BOOLEAN deadlineSet = FALSE;
    LARGE_INTEGER deadline;
    for (;;)
    {
        /* Re-look the pipe up each pass: the global-event park means the
         * pipe may have died meanwhile. An unknown name answers immediately
         * — waiting for pipe CREATION is not part of the contract (pinned);
         * a pipe deleted MID-wait also answers NAME_NOT_FOUND here, where
         * wineserver would run the timeout out (docs/03, unpinned edge). */
        PNPFS_PIPE pipe = NpfsFindPipe(&name);
        if (pipe == 0)
        {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        if (NpfsHasListener(pipe))
        {
            return STATUS_SUCCESS;
        }
        if (!deadlineSet)
        {
            /* One absolute deadline across every re-check. Relative NT
             * times are negative; positive values (including
             * WaitNamedPipeW's NMPWAIT_WAIT_FOREVER encoding) are already
             * absolute system time (kernel/ke/timer.c). */
            LARGE_INTEGER timeout = wait->TimeoutSpecified ? wait->Timeout : pipe->defaultTimeout;
            if (timeout.QuadPart < 0)
            {
                LARGE_INTEGER now;
                KeQuerySystemTime(&now);
                deadline.QuadPart = now.QuadPart - timeout.QuadPart;
            }
            else
            {
                deadline = timeout;
            }
            deadlineSet = TRUE;
        }
        /* Clear-then-wait: safe against lost wakeups for the same reason
         * NpfsWait is — nothing runs between the listener check above and
         * this park (uniprocessor, no preemption). */
        KeClearEvent(&NpfsListenersChangedEvent);
        NTSTATUS status = IoWaitCancellable(&NpfsListenersChangedEvent, &deadline);
        if (status == STATUS_TIMEOUT)
        {
            return STATUS_IO_TIMEOUT;
        }
        if (status != STATUS_SUCCESS)
        {
            return status; /* CUI-4: foreign terminate breaks the FSCTL_PIPE_WAIT park */
        }
    }
}

static NTSTATUS NpfsListen(PNPFS_END end, PFILE_OBJECT file, IO_CONTROL_CONTEXT *request)
{
    PNPFS_INSTANCE instance = end->instance;
    if (!end->isServer)
    {
        /* Listening is a verb the CLIENT end does not have, which is what
         * ILLEGAL_FUNCTION says — not INVALID_PARAMETER, which would claim
         * the arguments were wrong (wine server/named_pipe.c
         * pipe_client_ioctl: FSCTL_PIPE_LISTEN -> STATUS_ILLEGAL_FUNCTION;
         * pinned sem_pipe/create_refusals.c). */
        return STATUS_ILLEGAL_FUNCTION;
    }
    if (instance->state == FILE_PIPE_DISCONNECTED_STATE)
    {
        /* Return to listening: queues were flushed at disconnect. */
        instance->state = FILE_PIPE_LISTENING_STATE;
        NpfsWakeAll(instance);
        /* A listener appeared: wake FSCTL_PIPE_WAIT parkers. */
        KeSetEvent(&NpfsListenersChangedEvent, 0, FALSE);
    }
    for (;;)
    {
        switch (instance->state)
        {
        case FILE_PIPE_CONNECTED_STATE:
            /* A client is already attached (connect-before-listen — the
             * pinned sem_pipe/create_pipe answer). */
            return STATUS_PIPE_CONNECTED;
        case FILE_PIPE_CLOSING_STATE:
            return STATUS_PIPE_CLOSING;
        case FILE_PIPE_LISTENING_STATE:
            if (end->completionMode == FILE_PIPE_COMPLETE_OPERATION)
            {
                return STATUS_PIPE_LISTENING;
            }
            if (!file->synchronousIo)
            {
                /* Asynchronous handle: genuinely pend (pinned
                 * async_listen.c — rpcrt4's server loop deadlocks on a
                 * blocking listen). One slot: no baked caller stacks two
                 * listens on one instance; a second is refused loudly, not
                 * given a made-up answer (Art. 12). */
                PIOP_PENDING_REQUEST pending = 0;
                /* Only the CURRENT server end may park here. NpfsVfsCleanup
                 * drains this queue and clears serverEnd, so a request parked
                 * after that point would never be completed — and since the
                 * request now holds a FILE_OBJECT reference (kernel/io/io.h),
                 * never freed either. Nothing between the state read above and
                 * this line can block, and the Io layer holds a reference for
                 * the whole call, so it cannot happen today; the assert is
                 * here to convict the day something between them can. */
                ASSERT(instance->serverEnd == end);
                NTSTATUS status = IopPreparePendingRequest(file, request, &pending);
                if (!NT_SUCCESS(status))
                {
                    return status;
                }
                InsertTailList(&instance->pendingListenHead, &pending->queueEntry);
                return STATUS_PENDING;
            }
            {
                NTSTATUS waitStatus = NpfsWait(&instance->connectEvent);
                if (waitStatus != STATUS_SUCCESS)
                {
                    return waitStatus; /* CUI-4: foreign terminate breaks the listen park */
                }
            }
            break;
        default:
            return STATUS_PIPE_DISCONNECTED;
        }
        if (instance->state == FILE_PIPE_CONNECTED_STATE)
        {
            return STATUS_SUCCESS; /* the blocking listen satisfied */
        }
    }
}

static NTSTATUS NpfsDisconnect(PNPFS_END end)
{
    PNPFS_INSTANCE instance = end->instance;
    if (!end->isServer)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (instance->state != FILE_PIPE_CONNECTED_STATE && instance->state != FILE_PIPE_CLOSING_STATE)
    {
        return STATUS_PIPE_DISCONNECTED;
    }
    /* A listen can pend only in the listening state, which the guard above
     * rejects — nothing to cancel here. */
    ASSERT(IsListEmpty(&instance->pendingListenHead));
    /* Unread bytes are DISCARDED (pinned) and the client end is orphaned. */
    NpfsFlushQueue(&instance->inbound);
    NpfsFlushQueue(&instance->outbound);
    PNPFS_END orphaned = instance->clientEnd;
    if (orphaned != 0)
    {
        orphaned->orphaned = TRUE;
        instance->clientEnd = 0;
    }
    instance->state = FILE_PIPE_DISCONNECTED_STATE;
    NpfsWakeAll(instance);
    /* The ONE place an end leaves the instance while its handle lives on, so
     * the ONE place NpfsWakeAll's sweep cannot reach it: the orphaned client
     * is no longer instance->clientEnd, and any read it left parked would sit
     * there forever. It is answered here, with the status its state now gives
     * (STATUS_PIPE_DISCONNECTED, NpfsReadReady's first arm). */
    if (orphaned != 0)
    {
        NpfsServicePendingReads(orphaned);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS NpfsPeek(PNPFS_END end, void *output, ULONG outputLength, ULONG_PTR *infoOut)
{
    PNPFS_INSTANCE instance = end->instance;
    PNPFS_QUEUE queue = NpfsIncomingQueue(end);
    ULONG fixed = (ULONG)offsetof(FILE_PIPE_PEEK_BUFFER, Data);
    if (outputLength < fixed)
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    if (NpfsEndDisconnected(end))
    {
        return STATUS_PIPE_DISCONNECTED;
    }

    FILE_PIPE_PEEK_BUFFER *peek = output;
    memset(peek, 0, fixed);
    peek->NamedPipeState = instance->state;
    peek->ReadDataAvailable = queue->bytesAvailable;
    if (instance->pipe != 0 && instance->pipe->pipeType == FILE_PIPE_TYPE_MESSAGE)
    {
        for (PLIST_ENTRY entry = queue->bufferList.Flink; entry != &queue->bufferList;
             entry = entry->Flink)
        {
            peek->NumberOfMessages++;
        }
        if (!IsListEmpty(&queue->bufferList))
        {
            PNPFS_BUFFER first = CONTAINING_RECORD(queue->bufferList.Flink, NPFS_BUFFER, listEntry);
            peek->MessageLength = first->length - first->consumed;
        }
    }

    /* Preview without consuming: copy from the head of the stream. */
    ULONG capacity = outputLength - fixed;
    ULONG copied = 0;
    for (PLIST_ENTRY entry = queue->bufferList.Flink;
         entry != &queue->bufferList && copied < capacity; entry = entry->Flink)
    {
        PNPFS_BUFFER chunk = CONTAINING_RECORD(entry, NPFS_BUFFER, listEntry);
        ULONG take = chunk->length - chunk->consumed;
        if (take > capacity - copied)
        {
            take = capacity - copied;
        }
        memcpy(peek->Data + copied, chunk->data + chunk->consumed, take);
        copied += take;
        if (end->readMode == FILE_PIPE_MESSAGE_MODE)
        {
            break; /* preview stops at the first message */
        }
    }
    *infoOut = fixed + copied;
    /* Only a truncated MESSAGE overflows. On a byte-mode read there is no
     * message to truncate, so leaving data behind is ordinary -- reporting
     * STATUS_BUFFER_OVERFLOW whenever anything remained made the normal
     * 1-byte PeekNamedPipe poll fail (docs/review-2026-07 §9). */
    if (end->readMode == FILE_PIPE_MESSAGE_MODE && copied < queue->bytesAvailable)
    {
        return STATUS_BUFFER_OVERFLOW;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS NpfsDeviceControl(PFILE_OBJECT file, ULONG code, const void *input,
                                  ULONG inputLength, void *output, ULONG outputLength,
                                  ULONG_PTR *infoOut, IO_CONTROL_CONTEXT *request)
{
    PNPFS_END end = file->fsContext;
    if (end == 0)
    {
        /* The device root serves exactly FSCTL_PIPE_WAIT; the per-instance
         * verbs on it are illegal (wine/server/named_pipe.c
         * named_pipe_device_ioctl: WAIT/LISTEN/IMPERSONATE ->
         * STATUS_ILLEGAL_FUNCTION on the wrong object). */
        switch (code)
        {
        case FSCTL_PIPE_WAIT:
            return NpfsWaitForPipe(input, inputLength);
        case FSCTL_PIPE_LISTEN:
        case FSCTL_PIPE_DISCONNECT:
        case FSCTL_PIPE_PEEK:
            return STATUS_ILLEGAL_FUNCTION;
        default:
            DbgPrint("npfs: unimplemented root fsctl %#lx\n", (unsigned long)code);
            return STATUS_NOT_SUPPORTED;
        }
    }
    (void)input;
    (void)inputLength;
    switch (code)
    {
    case FSCTL_PIPE_LISTEN:
        return NpfsListen(end, file, request);
    case FSCTL_PIPE_DISCONNECT:
        return NpfsDisconnect(end);
    case FSCTL_PIPE_PEEK:
        return NpfsPeek(end, output, outputLength, infoOut);
    default:
        /* Unbuilt verbs (TRANSCEIVE/IMPERSONATE/... — and WAIT, which an
         * instance handle answers NOT_SUPPORTED, pinned pipe_wait.c) are
         * refused loudly, never faked (docs/03). */
        DbgPrint("npfs: unimplemented fsctl %#lx\n", (unsigned long)code);
        return STATUS_NOT_SUPPORTED;
    }
}

/* --- info classes ----------------------------------------------------------- */

static NTSTATUS NpfsQueryPipeInfo(PFILE_OBJECT file, FILE_INFORMATION_CLASS informationClass,
                                  void *buffer, ULONG length, ULONG_PTR *infoOut)
{
    PNPFS_END end = file->fsContext;
    if (end == 0)
    {
        return STATUS_INVALID_DEVICE_REQUEST; /* the root is not a pipe end */
    }
    PNPFS_INSTANCE instance = end->instance;

    /* The class's fixed size was checked by NtQueryInformationFile before the
     * handle was even resolved (kernel/io/query.c, the oracle's own ordering —
     * pinned sem_pipe/create_refusals.c), so the length is a precondition
     * here, not a case to answer. */
    if (informationClass == FilePipeInformation)
    {
        ASSERT(length >= sizeof(FILE_PIPE_INFORMATION));
        FILE_PIPE_INFORMATION *info = buffer;
        info->ReadMode = end->readMode;
        info->CompletionMode = end->completionMode;
        *infoOut = sizeof(*info);
        return STATUS_SUCCESS;
    }

    ASSERT(informationClass == FilePipeLocalInformation);
    ASSERT(length >= sizeof(FILE_PIPE_LOCAL_INFORMATION));
    FILE_PIPE_LOCAL_INFORMATION *info = buffer;
    memset(info, 0, sizeof(*info));
    PNPFS_PIPE pipe = instance->pipe;
    if (pipe != 0)
    {
        info->NamedPipeType = pipe->pipeType;
        info->NamedPipeConfiguration = NpfsConfigurationFromShare(pipe->sharing);
        info->MaximumInstances = pipe->maxInstances;
        info->CurrentInstances = pipe->instanceCount;
        info->InboundQuota = pipe->inQuota;
        info->OutboundQuota = pipe->outQuota;
    }
    info->NamedPipeState = end->orphaned ? FILE_PIPE_DISCONNECTED_STATE : instance->state;
    info->NamedPipeEnd = end->isServer ? FILE_PIPE_SERVER_END : FILE_PIPE_CLIENT_END;
    info->ReadDataAvailable = NpfsIncomingQueue(end)->bytesAvailable;
    PNPFS_QUEUE outgoing = NpfsOutgoingQueue(end);
    info->WriteQuotaAvailable =
        outgoing->quota > outgoing->bytesAvailable ? outgoing->quota - outgoing->bytesAvailable : 0;
    *infoOut = sizeof(*info);
    return STATUS_SUCCESS;
}

static NTSTATUS NpfsSetPipeInfo(PFILE_OBJECT file, const FILE_PIPE_INFORMATION *info)
{
    PNPFS_END end = file->fsContext;
    if (end == 0)
    {
        return STATUS_INVALID_DEVICE_REQUEST; /* the root is not a pipe end */
    }
    /* A BYTE-type pipe may not be put into message READ mode. The oracle
     * refuses it at set-info as well as at create (wine
     * server/named_pipe.c: a byte pipe with message read mode is
     * STATUS_INVALID_PARAMETER); accepting it made the read path fabricate
     * message framing at whatever quota boundary the data happened to land
     * on (docs/review-2026-07 §9). */
    if (info->ReadMode == FILE_PIPE_MESSAGE_MODE && end->instance->pipe != 0 &&
        end->instance->pipe->pipeType != FILE_PIPE_TYPE_MESSAGE)
    {
        return STATUS_INVALID_PARAMETER;
    }
    end->readMode = info->ReadMode;
    end->completionMode = info->CompletionMode;
    return STATUS_SUCCESS;
}

static NTSTATUS NpfsGetInfo(PFILE_OBJECT file, IO_FILE_INFO *info)
{
    (void)file;
    /* Pipes have no on-disk facts; zeros keep the mechanical query classes
     * (FileBasicInformation etc.) harmless. */
    memset(info, 0, sizeof(*info));
    return STATUS_SUCCESS;
}

static NTSTATUS NpfsQueryName(PFILE_OBJECT file, WCHAR *buffer, ULONG capacity, ULONG *lengthOut)
{
    PNPFS_END end = file->fsContext;
    if (end == 0)
    {
        /* The root's volume-relative name is the bare backslash. */
        *lengthOut = sizeof(WCHAR);
        if (capacity >= sizeof(WCHAR))
        {
            buffer[0] = '\\';
            return STATUS_SUCCESS;
        }
        return STATUS_BUFFER_OVERFLOW;
    }
    PNPFS_PIPE pipe = end->instance->pipe;
    ULONG nameBytes = pipe != 0 ? pipe->name.Length : 0;
    ULONG full = (ULONG)sizeof(WCHAR) + nameBytes; /* "\" + name */
    *lengthOut = full;
    ULONG copy = full <= capacity ? full : capacity;
    if (copy >= sizeof(WCHAR))
    {
        buffer[0] = '\\';
        memcpy(buffer + 1, pipe != 0 ? pipe->name.Buffer : 0, copy - sizeof(WCHAR));
    }
    return full <= capacity ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;
}

/* --- open/close lifecycle --------------------------------------------------- */

/* The client-side NtCreateFile path: attach to a listening instance. */
static NTSTATUS NpfsVfsCreate(PIO_DEVICE device, PFILE_OBJECT file, const UNICODE_STRING *path,
                              PFILE_OBJECT relativeTo, ACCESS_MASK grantedAccess, ULONG shareAccess,
                              ULONG fileAttributes, ULONG disposition, ULONG options,
                              ULONG_PTR *information)
{
    (void)device;
    (void)relativeTo;
    (void)grantedAccess; /* the RAW request is what this FS's rule reads:
                          * file->desiredAccess, below */
    (void)shareAccess;
    (void)fileAttributes;
    (void)options;
    if (path->Length == 0)
    {
        /* The device ROOT open ("\??\PIPE\") — the WaitNamedPipe handle
         * (kernelbase/sync.c WaitNamedPipeW; wineserver models it as the
         * named-pipe directory object). fsContext == 0 marks it; the
         * directory shape keeps NtRead/WriteFile off it (kernel/io/rw.c). */
        file->fsContext = 0;
        file->fcb = &NpfsRootFcb;
        file->isDirectory = TRUE;
        *information = FILE_OPENED;
        return STATUS_SUCCESS;
    }
    if (disposition != FILE_OPEN && disposition != FILE_OPEN_IF && disposition != FILE_CREATE)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PNPFS_PIPE pipe = NpfsFindPipe(path);
    if (pipe == 0)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    PNPFS_INSTANCE instance = 0;
    for (PLIST_ENTRY entry = pipe->instanceList.Flink; entry != &pipe->instanceList;
         entry = entry->Flink)
    {
        PNPFS_INSTANCE candidate = CONTAINING_RECORD(entry, NPFS_INSTANCE, listEntry);
        if (candidate->state == FILE_PIPE_LISTENING_STATE && candidate->serverEnd != 0)
        {
            instance = candidate;
            break;
        }
    }
    if (instance == 0)
    {
        return STATUS_PIPE_NOT_AVAILABLE; /* every instance busy (pinned) */
    }

    /* The pipe's own SHARE mask bounds what the CLIENT may ask for — the
     * inverse of the usual reading, where a share mask bounds what OTHERS may
     * do. A FILE_SHARE_READ pipe is FILE_PIPE_OUTBOUND: readable by the
     * client, never writable (wine server/named_pipe.c named_pipe_open_file,
     * the guard between the listener search and create_pipe_client).
     *
     * BELOW the listener search, and that position is the content. The oracle
     * answers STATUS_PIPE_NOT_AVAILABLE for a pipe whose instances are all
     * taken even when the access would also have been refused, and the
     * difference is not cosmetic: PIPE_BUSY is what drives a
     * WaitNamedPipe-and-retry loop, where ACCESS_DENIED ends it. Measured, in
     * sem_pipe/create_refusals.c's test_client_open_precedence.
     *
     * Tested on the caller's OWN word rather than on grantedAccess: the rule
     * is about a client that EXPLICITLY names a direction, and mapping folds
     * GENERIC_ALL and MAXIMUM_ALLOWED — which name none — into a mask
     * carrying both data bits. Both of those open an OUTBOUND pipe
     * successfully on the oracle, and reading the mapped mask would refuse
     * them (same pin). */
    ULONG wants = file->desiredAccess;
    if (((wants & GENERIC_READ) && !(pipe->sharing & FILE_SHARE_READ)) ||
        ((wants & GENERIC_WRITE) && !(pipe->sharing & FILE_SHARE_WRITE)))
    {
        return STATUS_ACCESS_DENIED;
    }

    PNPFS_END end = MiAllocatePool(sizeof(NPFS_END));
    if (end == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memset(end, 0, sizeof(*end));
    end->instance = instance;
    end->isServer = FALSE;
    InitializeListHead(&end->pendingReadHead);
    end->readMode = FILE_PIPE_BYTE_STREAM_MODE; /* client default (pinned:
                                                 * message framing needs the
                                                 * explicit switch) */
    end->completionMode = FILE_PIPE_QUEUE_OPERATION;

    instance->clientEnd = end;
    instance->endCount++;
    instance->state = FILE_PIPE_CONNECTED_STATE;
    NpfsWakeAll(instance); /* satisfy a parked FSCTL_PIPE_LISTEN */
    while (!IsListEmpty(&instance->pendingListenHead))
    {
        /* Complete EVERY pended async listen: IOSB {SUCCESS, 0} in the
         * server's address space, then its event (pinned async_listen.c).
         * All of them, not just the oldest -- the instance is connected now,
         * and a listen submitted against a connected instance answers
         * STATUS_PIPE_CONNECTED anyway, so leaving one queued would park it
         * forever. This is the oracle's own behaviour: wineserver wakes the
         * whole listen queue (server/named_pipe.c, async_wake_up on the
         * server's listen queue). */
        PIOP_PENDING_REQUEST pending =
            CONTAINING_RECORD(instance->pendingListenHead.Flink, IOP_PENDING_REQUEST, queueEntry);
        RemoveEntryList(&pending->queueEntry);
        IopCompletePendingRequest(pending, STATUS_SUCCESS, 0);
    }

    file->fsContext = end;
    file->fcb = &instance->header;
    file->isDirectory = FALSE;
    *information = FILE_OPENED;
    return STATUS_SUCCESS;
}

static void NpfsVfsCleanup(PFILE_OBJECT file)
{
    PNPFS_END end = file->fsContext;
    if (end == 0)
    {
        return; /* a device-root open holds no pipe state */
    }
    PNPFS_INSTANCE instance = end->instance;

    /* CUI-8: the handle is going away, so every read it left parked is
     * cancel-completed FIRST — before the state moves and before the end
     * leaves the instance's reach (G11: a request never outlives the handle
     * that issued it, and each one holds a FILE_OBJECT reference, so an
     * abandoned one would never be freed either). Same answer and same
     * position as the parked listens below. */
    while (!IsListEmpty(&end->pendingReadHead))
    {
        PIOP_PENDING_REQUEST pending =
            CONTAINING_RECORD(end->pendingReadHead.Flink, IOP_PENDING_REQUEST, queueEntry);
        RemoveEntryList(&pending->queueEntry);
        IopCompletePendingRequest(pending, STATUS_CANCELLED, 0);
    }

    /* The peer sees a half-closed pipe: drains what is buffered, then
     * BROKEN on read / CLOSING on write (pinned sem_pipe/create_pipe). */
    if (!end->orphaned && instance->state == FILE_PIPE_CONNECTED_STATE)
    {
        instance->state = FILE_PIPE_CLOSING_STATE;
    }
    if (instance->serverEnd == end)
    {
        while (!IsListEmpty(&instance->pendingListenHead))
        {
            /* The owning handle is going away: cancel-complete every parked
             * listen before the instance loses its server end (G11 — a
             * request never outlives the handle that issued it). */
            PIOP_PENDING_REQUEST pending = CONTAINING_RECORD(instance->pendingListenHead.Flink,
                                                             IOP_PENDING_REQUEST, queueEntry);
            RemoveEntryList(&pending->queueEntry);
            IopCompletePendingRequest(pending, STATUS_CANCELLED, 0);
        }
        instance->serverEnd = 0;
        /* The instance leaves the pipe's accounting when its server handle
         * goes away; the pipe itself dies with its last instance. */
        PNPFS_PIPE pipe = instance->pipe;
        if (pipe != 0)
        {
            RemoveEntryList(&instance->listEntry);
            ASSERT(pipe->instanceCount > 0);
            pipe->instanceCount--;
            instance->pipe = 0;
            if (pipe->instanceCount == 0)
            {
                RemoveEntryList(&pipe->listEntry);
                MiFreePool(pipe->name.Buffer);
                MiFreePool(pipe);
            }
        }
    }
    else if (instance->clientEnd == end)
    {
        instance->clientEnd = 0;
    }
    NpfsWakeAll(instance);
}

static void NpfsVfsClose(PFILE_OBJECT file)
{
    PNPFS_END end = file->fsContext;
    if (end == 0)
    {
        return; /* a device-root open holds no pipe state */
    }
    PNPFS_INSTANCE instance = end->instance;
    if (instance->serverEnd == end || instance->clientEnd == end)
    {
        /* Deleted without ever holding a handle (a failed ObpCreateHandle):
         * the cleanup hook never fired — detach now so nothing dangles. */
        NpfsVfsCleanup(file);
    }
    /* Cleanup has run for every end that reaches here (the hook above, or
     * the handle's own close), and it drains this queue — so the end can
     * never be freed with a request still pointing into it.
     *
     * AFTER the fallback above on purpose: that arm runs cleanup from inside
     * the DELETE procedure, with the refcount already at zero, and a request
     * completing there would drop a FILE_OBJECT reference that no longer
     * exists. It cannot carry one — parking a read needs a user handle, and a
     * handle guarantees the cleanup hook fired the ordinary way — so the
     * assert is placed to convict the day that stops being true. */
    ASSERT(IsListEmpty(&end->pendingReadHead));
    MiFreePool(end);
    ASSERT(instance->endCount > 0);
    if (--instance->endCount == 0)
    {
        NpfsFlushQueue(&instance->inbound);
        NpfsFlushQueue(&instance->outbound);
        MiFreePool(instance);
    }
}

/* Cancel-complete every request on `head` the filter matches, oldest first
 * — one NtCancelIoFile cancels all of that thread's pending I/O on the
 * handle, not just the first. One statement of the filter for both queues
 * (Art. 11): `issuer` non-0 narrows to that thread, `userIosb` non-0 to the
 * one request with that IOSB VA. */
static ULONG NpfsCancelQueue(PLIST_ENTRY head, PKTHREAD issuer, PIO_STATUS_BLOCK userIosb)
{
    ULONG cancelled = 0;
    PLIST_ENTRY entry = head->Flink;
    while (entry != head)
    {
        PIOP_PENDING_REQUEST pending = CONTAINING_RECORD(entry, IOP_PENDING_REQUEST, queueEntry);
        entry = entry->Flink;
        if ((issuer != 0 && pending->issuer != issuer) ||
            (userIosb != 0 && pending->userIosb != userIosb))
        {
            continue;
        }
        RemoveEntryList(&pending->queueEntry);
        IopCompletePendingRequest(pending, STATUS_CANCELLED, 0);
        cancelled++;
    }
    return cancelled;
}

/* Cancel this file object's parked requests (kernel/io/async.c IopCancelIo):
 * the reads it left on its own end (CUI-8), and — only for a server handle,
 * since a client end never issues one — the instance's parked listens. */
static ULONG NpfsCancelPending(PFILE_OBJECT file, PKTHREAD issuer, PIO_STATUS_BLOCK userIosb)
{
    PNPFS_END end = file->fsContext;
    if (end == 0)
    {
        return 0; /* a device-root open holds no pipe state */
    }
    ULONG cancelled = NpfsCancelQueue(&end->pendingReadHead, issuer, userIosb);
    if (end->isServer)
    {
        cancelled += NpfsCancelQueue(&end->instance->pendingListenHead, issuer, userIosb);
    }
    return cancelled;
}

const IO_VFS_OPS NpfsVfsOps = {
    .Create = NpfsVfsCreate,
    .Cleanup = NpfsVfsCleanup,
    .Close = NpfsVfsClose,
    .GetInfo = NpfsGetInfo,
    .QueryName = NpfsQueryName,
    .Read = NpfsRead,
    .Write = NpfsWrite,
    .Flush = NpfsFlush,
    .DeviceControl = NpfsDeviceControl,
    .CancelPending = NpfsCancelPending,
    .QueryPipeInfo = NpfsQueryPipeInfo,
    .SetPipeInfo = NpfsSetPipeInfo,
};

/* --- NtCreateNamedPipeFile --------------------------------------------------- */

NTSTATUS NtCreateNamedPipeFile(PHANDLE handleOut, ULONG desiredAccess,
                               POBJECT_ATTRIBUTES attributes, PIO_STATUS_BLOCK iosb, ULONG sharing,
                               ULONG disposition, ULONG options, ULONG pipeType, ULONG readMode,
                               ULONG completionMode, ULONG maxInstances, ULONG inboundQuota,
                               ULONG outboundQuota, PLARGE_INTEGER timeout)
{
    NTSTATUS status = ObpClearOutHandle(handleOut);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (iosb == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    status = KiProbeForWrite(iosb, sizeof(*iosb), sizeof(void *));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* The name is the caller's, and reading it is the first thing below.
     * The shared probe is the one authority for the question (G11) and the
     * Io create path already asks it (kernel/io/file.c IopCreateFile); this
     * site did not, so a misaligned block reached a ring-0 load and tripped
     * a UBSan trap — a #UD, which the dispatcher's fault-recovery frame
     * cannot convert into a status. Found by the pointer-torture matrix
     * (issue #32 A1); pinned by tests/ntapi/sem_pipe/pipe_hostile_name.c. */
    status = ObProbeObjectAttributes(attributes);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (attributes == 0 || attributes->ObjectName == 0)
    {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }
    /* The oracle's request guard, in ITS order — the sharing word first, the
     * access word second, and BOTH ahead of the disposition, so a request
     * wrong in two ways reports the earlier one (wine server/named_pipe.c,
     * DECL_HANDLER(create_named_pipe), whose guard block precedes its
     * disposition switch; the whole ordering is pinned by
     * sem_pipe/create_refusals.c, which measures zero-access-with-a-bad-
     * disposition as ACCESS_DENIED rather than INVALID_PARAMETER).
     *
     * A pipe must NAME a direction: zero sharing is not "share nothing", it
     * is a malformed request, and a bit outside {READ, WRITE} is refused even
     * alongside a legal one. The oracle spells the third clause in its own
     * NAMED_PIPE_MESSAGE_STREAM_* flags; at this boundary the same rule is
     * that a BYTE-type pipe may not be born in message READ mode, which
     * NpfsSetPipeInfo already refuses after the fact. */
    if (sharing == 0 || (sharing & ~(ULONG)(FILE_SHARE_READ | FILE_SHARE_WRITE)) != 0 ||
        ((readMode & FILE_PIPE_MESSAGE_MODE) && !(pipeType & FILE_PIPE_TYPE_MESSAGE)))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (desiredAccess == 0)
    {
        return STATUS_ACCESS_DENIED;
    }
    if (disposition != FILE_OPEN && disposition != FILE_OPEN_IF && disposition != FILE_CREATE)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (maxInstances == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    /* The create-time timeout is the default an unspecified FSCTL_PIPE_WAIT
     * uses (pinned pipe_wait.c); it binds at PIPE creation — later
     * instances of an existing pipe do not rewrite it (wineserver stores it
     * on the named_pipe object once). */
    LARGE_INTEGER defaultTimeout = {.QuadPart = 0};
    if (timeout != 0)
    {
        status = KiCopyFromUser(&defaultTimeout, timeout, sizeof(defaultTimeout));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    /* Resolve \??\pipe\<name> (or \Device\NamedPipe\<name>) to OUR device. */
    PVOID deviceBody;
    UNICODE_STRING fsPath;
    PWSTR reparseBuffer = 0;
    status =
        ObpLookupParseObject(attributes, &IoDeviceType, 0, &deviceBody, &fsPath, &reparseBuffer);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PIO_DEVICE device = deviceBody;
    if (device->ops != &NpfsVfsOps || fsPath.Length == 0)
    {
        status = STATUS_OBJECT_NAME_INVALID;
        goto out_device;
    }

    /* Find-or-create the pipe, then add an instance under its limit. */
    PNPFS_PIPE pipe = NpfsFindPipe(&fsPath);
    ULONG_PTR information = FILE_OPENED;
    if (pipe == 0 && disposition == FILE_OPEN)
    {
        /* Only FILE_CREATE and FILE_OPEN_IF may MINT a pipe; FILE_OPEN opens
         * an existing one or nothing (the oracle's disposition switch:
         * FILE_OPEN takes open_named_object, the other two
         * create_named_object). */
        status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto out_device;
    }
    if (pipe == 0)
    {
        pipe = MiAllocatePool(sizeof(NPFS_PIPE));
        WCHAR *nameCopy = pipe != 0 ? MiAllocatePool(fsPath.Length) : 0;
        if (pipe == 0 || nameCopy == 0)
        {
            if (pipe != 0)
            {
                MiFreePool(pipe);
            }
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto out_device;
        }
        memset(pipe, 0, sizeof(*pipe));
        memcpy(nameCopy, fsPath.Buffer, fsPath.Length);
        pipe->name.Buffer = nameCopy;
        pipe->name.Length = fsPath.Length;
        pipe->name.MaximumLength = fsPath.Length;
        pipe->pipeType = pipeType & FILE_PIPE_TYPE_MESSAGE;
        pipe->sharing = sharing;
        pipe->maxInstances = maxInstances;
        pipe->inQuota = inboundQuota != 0 ? inboundQuota : 4096;
        pipe->outQuota = outboundQuota != 0 ? outboundQuota : 4096;
        pipe->defaultTimeout = defaultTimeout;
        InitializeListHead(&pipe->instanceList);
        InsertTailList(&NpfsPipeList, &pipe->listEntry);
        information = FILE_CREATED;
    }
    else if (pipe->instanceCount >= pipe->maxInstances)
    {
        status = STATUS_INSTANCE_NOT_AVAILABLE; /* pinned create_pipe */
        goto out_device;
    }
    else if (pipe->sharing != sharing || disposition == FILE_CREATE)
    {
        /* A further instance must present the SAME direction as the first,
         * and FILE_CREATE never opens an existing pipe — the answer is
         * ACCESS_DENIED, not the OBJECT_NAME_COLLISION a file create gives.
         * Ordered AFTER the instance limit, so a pipe at its limit still
         * reports INSTANCE_NOT_AVAILABLE (wine server/named_pipe.c,
         * DECL_HANDLER(create_named_pipe)'s existing-pipe arm; pinned
         * sem_pipe/create_refusals.c). */
        status = STATUS_ACCESS_DENIED;
        goto out_device;
    }

    PNPFS_INSTANCE instance = MiAllocatePool(sizeof(NPFS_INSTANCE));
    PNPFS_END end = instance != 0 ? MiAllocatePool(sizeof(NPFS_END)) : 0;
    if (instance == 0 || end == 0)
    {
        if (instance != 0)
        {
            MiFreePool(instance);
        }
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out_empty_pipe;
    }
    memset(instance, 0, sizeof(*instance));
    IopInitializeFcb(&instance->header);
    instance->pipe = pipe;
    instance->state = FILE_PIPE_LISTENING_STATE;
    InitializeListHead(&instance->pendingListenHead);
    NpfsInitializeQueue(&instance->inbound, pipe->inQuota);
    NpfsInitializeQueue(&instance->outbound, pipe->outQuota);
    KeInitializeEvent(&instance->connectEvent, NotificationEvent, FALSE);
    memset(end, 0, sizeof(*end));
    end->instance = instance;
    end->isServer = TRUE;
    InitializeListHead(&end->pendingReadHead);
    end->readMode = readMode & FILE_PIPE_MESSAGE_MODE;
    end->completionMode = completionMode & FILE_PIPE_COMPLETE_OPERATION;
    instance->serverEnd = end;
    instance->endCount = 1;
    InsertTailList(&pipe->instanceList, &instance->listEntry);
    pipe->instanceCount++;
    /* A listener appeared: wake FSCTL_PIPE_WAIT parkers (pipe_wait.c's
     * appearing-listener case; wineserver wakes pipe->waiters here too). */
    KeSetEvent(&NpfsListenersChangedEvent, 0, FALSE);

    /* Build the File object exactly as IopCreateFile does. */
    PVOID body;
    status = ObpAllocateObject(&IoFileObjectType, sizeof(FILE_OBJECT), &body);
    if (!NT_SUCCESS(status))
    {
        goto out_undo_instance;
    }
    PFILE_OBJECT file = body;
    KeInitializeEvent(&file->header, NotificationEvent, TRUE);
    file->device = device; /* the lookup reference moves into the object */
    device = 0;
    file->fsContext = end;
    file->fcb = &instance->header;
    file->synchronousIo =
        (options & (FILE_SYNCHRONOUS_IO_NONALERT | FILE_SYNCHRONOUS_IO_ALERT)) != 0;
    file->grantedAccess = ObpMapDesiredAccess(&IoFileObjectType, desiredAccess);
    file->desiredAccess = desiredAccess;
    file->shareAccess = sharing;

    status = ObpCreateHandle(file, file->grantedAccess, attributes->Attributes, handleOut);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(file); /* cleanup/close run via the type hooks */
        iosb->Status = status;
        iosb->Information = 0;
        goto out;
    }
    ObDereferenceObject(file); /* the handle keeps it alive */
    iosb->Status = STATUS_SUCCESS;
    iosb->Information = information;
    status = STATUS_SUCCESS;
    goto out;

out_undo_instance:
    RemoveEntryList(&instance->listEntry);
    pipe->instanceCount--;
    MiFreePool(end);
    MiFreePool(instance);
out_empty_pipe:
    /* A pipe this call just created must not linger with zero instances —
     * a later client would find it and see PIPE_NOT_AVAILABLE instead of
     * OBJECT_NAME_NOT_FOUND. */
    if (information == FILE_CREATED && pipe->instanceCount == 0)
    {
        RemoveEntryList(&pipe->listEntry);
        MiFreePool(pipe->name.Buffer);
        MiFreePool(pipe);
    }
out_device:
    if (device != 0)
    {
        ObDereferenceObject(device);
    }
out:
    if (reparseBuffer != 0)
    {
        MiFreePool(reparseBuffer);
    }
    return status;
}

/* --- initialization ---------------------------------------------------------- */

void NpfsInitialize(void)
{
    InitializeListHead(&NpfsPipeList);
    IopInitializeFcb(&NpfsRootFcb);
    KeInitializeEvent(&NpfsListenersChangedEvent, NotificationEvent, FALSE);

    /* GetFileType(pipe) == FILE_TYPE_PIPE (Wine dlls/kernelbase/file.c
     * switches on FileFsDeviceInformation.DeviceType). */
    NpfsDevice =
        IoPublishDevice(WSTR("\\Device\\NamedPipe"), &NpfsVfsOps, 0, FILE_DEVICE_NAMED_PIPE);

    HANDLE handle;
    OBJECT_ATTRIBUTES attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.Attributes = OBJ_PERMANENT;
    UNICODE_STRING linkName, target;
    RtlInitUnicodeString(&linkName, WSTR("\\??\\pipe"));
    RtlInitUnicodeString(&target, WSTR("\\Device\\NamedPipe"));
    attributes.ObjectName = &linkName;
    NTSTATUS status =
        NtCreateSymbolicLinkObject(&handle, SYMBOLIC_LINK_ALL_ACCESS, &attributes, &target);
    if (!NT_SUCCESS(status))
    {
        KiPanic("NpfsInitialize: cannot create \\??\\pipe");
    }
    NtClose(handle);
}
