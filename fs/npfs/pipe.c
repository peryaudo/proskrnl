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
    KEVENT dataEvent;      /* notification: data arrived / state changed */
    KEVENT spaceEvent;     /* notification: space freed / state changed */
} NPFS_QUEUE, *PNPFS_QUEUE;

typedef struct NPFS_PIPE
{
    LIST_ENTRY listEntry; /* on NpfsPipeList */
    UNICODE_STRING name;  /* pool copy, no leading backslash */
    ULONG pipeType;       /* FILE_PIPE_TYPE_* */
    ULONG configuration;  /* FILE_PIPE_{INBOUND,OUTBOUND,FULL_DUPLEX} */
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

/* Wake every waiter on the instance — any state transition may unblock a
 * read, a write, or a listen parked on the other side. */
static void NpfsWakeAll(PNPFS_INSTANCE instance)
{
    KeSetEvent(&instance->inbound.dataEvent, 0, FALSE);
    KeSetEvent(&instance->inbound.spaceEvent, 0, FALSE);
    KeSetEvent(&instance->outbound.dataEvent, 0, FALSE);
    KeSetEvent(&instance->outbound.spaceEvent, 0, FALSE);
    KeSetEvent(&instance->connectEvent, 0, FALSE);
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

/* --- the data path ---------------------------------------------------------- */

static NTSTATUS NpfsRead(PFILE_OBJECT file, void *buffer, ULONG length, ULONG_PTR *infoOut)
{
    PNPFS_END end = file->fsContext;
    PNPFS_INSTANCE instance = end->instance;
    PNPFS_QUEUE queue = NpfsIncomingQueue(end);

    for (;;)
    {
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
            break;
        }
        if (instance->state == FILE_PIPE_CLOSING_STATE)
        {
            return STATUS_PIPE_BROKEN; /* peer gone, nothing buffered */
        }
        if (end->completionMode == FILE_PIPE_COMPLETE_OPERATION)
        {
            return STATUS_PIPE_EMPTY;
        }
        NTSTATUS waitStatus = NpfsWait(&queue->dataEvent);
        if (waitStatus != STATUS_SUCCESS)
        {
            return waitStatus; /* CUI-4: foreign terminate breaks the read park */
        }
    }

    NTSTATUS status = STATUS_SUCCESS;
    ULONG copied = 0;
    if (end->readMode == FILE_PIPE_MESSAGE_MODE)
    {
        /* One message per read; a short buffer keeps the tail as the SAME
         * message and answers BUFFER_OVERFLOW (sem_pipe/message_mode). */
        PNPFS_BUFFER message = CONTAINING_RECORD(queue->bufferList.Flink, NPFS_BUFFER, listEntry);
        ULONG remaining = message->length - message->consumed;
        copied = remaining < length ? remaining : length;
        memcpy(buffer, message->data + message->consumed, copied);
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
    if (copied != 0)
    {
        KeSetEvent(&queue->spaceEvent, 0, FALSE); /* a parked writer re-checks */
    }
    *infoOut = copied;
    return status;
}

/* Append one pooled buffer to `queue` and wake its reader. */
static NTSTATUS NpfsAppendBuffer(PNPFS_QUEUE queue, const void *data, ULONG length)
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
        status = NpfsAppendBuffer(queue, buffer, length);
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
        status = NpfsAppendBuffer(queue, (const unsigned char *)buffer + written, chunk);
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

static NTSTATUS NpfsListen(PNPFS_END end, PFILE_OBJECT file, const IO_CONTROL_CONTEXT *request)
{
    PNPFS_INSTANCE instance = end->instance;
    if (!end->isServer)
    {
        return STATUS_INVALID_PARAMETER;
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
                NTSTATUS status = IopPreparePendingRequest(request, &pending);
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
    if (instance->clientEnd != 0)
    {
        instance->clientEnd->orphaned = TRUE;
        instance->clientEnd = 0;
    }
    instance->state = FILE_PIPE_DISCONNECTED_STATE;
    NpfsWakeAll(instance);
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
                                  ULONG_PTR *infoOut, const IO_CONTROL_CONTEXT *request)
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

    if (informationClass == FilePipeInformation)
    {
        if (length < sizeof(FILE_PIPE_INFORMATION))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        FILE_PIPE_INFORMATION *info = buffer;
        info->ReadMode = end->readMode;
        info->CompletionMode = end->completionMode;
        *infoOut = sizeof(*info);
        return STATUS_SUCCESS;
    }

    ASSERT(informationClass == FilePipeLocalInformation);
    if (length < sizeof(FILE_PIPE_LOCAL_INFORMATION))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    FILE_PIPE_LOCAL_INFORMATION *info = buffer;
    memset(info, 0, sizeof(*info));
    PNPFS_PIPE pipe = instance->pipe;
    if (pipe != 0)
    {
        info->NamedPipeType = pipe->pipeType;
        info->NamedPipeConfiguration = pipe->configuration;
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
    (void)grantedAccess;
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

    PNPFS_END end = MiAllocatePool(sizeof(NPFS_END));
    if (end == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memset(end, 0, sizeof(*end));
    end->instance = instance;
    end->isServer = FALSE;
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
    MiFreePool(end);
    ASSERT(instance->endCount > 0);
    if (--instance->endCount == 0)
    {
        NpfsFlushQueue(&instance->inbound);
        NpfsFlushQueue(&instance->outbound);
        MiFreePool(instance);
    }
}

/* Cancel the instance's parked listen if this file object's end issued it
 * and the filter matches (kernel/io/async.c IopCancelIo). Only the server
 * end can have issued one — a client handle never cancels it. */
static ULONG NpfsCancelPending(PFILE_OBJECT file, PKTHREAD issuer, PIO_STATUS_BLOCK userIosb)
{
    PNPFS_END end = file->fsContext;
    if (end == 0 || !end->isServer)
    {
        return 0;
    }
    PNPFS_INSTANCE instance = end->instance;
    /* Cancel EVERY queued listen the filter matches, oldest first -- one
     * NtCancelIoFile cancels all of that thread's pending I/O on the handle,
     * not just the first. */
    int cancelled = 0;
    PLIST_ENTRY entry = instance->pendingListenHead.Flink;
    while (entry != &instance->pendingListenHead)
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
        cancelled = 1;
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
    .DeviceControl = NpfsDeviceControl,
    .CancelPending = NpfsCancelPending,
    .QueryPipeInfo = NpfsQueryPipeInfo,
    .SetPipeInfo = NpfsSetPipeInfo,
};

/* --- NtCreateNamedPipeFile --------------------------------------------------- */

/* Map the create's share mask to the pipe's configuration, the way Wine's
 * kernelbase spells the PIPE_ACCESS_* modes (dlls/kernelbase/sync.c
 * CreateNamedPipeW: INBOUND -> FILE_SHARE_WRITE, OUTBOUND -> FILE_SHARE_READ,
 * DUPLEX -> both), observable through FilePipeLocalInformation. */
static ULONG NpfsConfigurationFromShare(ULONG sharing)
{
    if ((sharing & (FILE_SHARE_READ | FILE_SHARE_WRITE)) == (FILE_SHARE_READ | FILE_SHARE_WRITE))
    {
        return FILE_PIPE_FULL_DUPLEX;
    }
    return (sharing & FILE_SHARE_WRITE) ? FILE_PIPE_INBOUND : FILE_PIPE_OUTBOUND;
}

NTSTATUS NtCreateNamedPipeFile(PHANDLE handleOut, ULONG desiredAccess,
                               POBJECT_ATTRIBUTES attributes, PIO_STATUS_BLOCK iosb, ULONG sharing,
                               ULONG disposition, ULONG options, ULONG pipeType, ULONG readMode,
                               ULONG completionMode, ULONG maxInstances, ULONG inboundQuota,
                               ULONG outboundQuota, PLARGE_INTEGER timeout)
{
    if (handleOut == 0 || iosb == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(iosb, sizeof(*iosb), sizeof(void *));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (attributes == 0 || attributes->ObjectName == 0)
    {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
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
    status = ObpLookupParseObject(attributes, &IoDeviceType, &deviceBody, &fsPath, &reparseBuffer);
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
        pipe->configuration = NpfsConfigurationFromShare(sharing);
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
    KiInitializeDispatcherHeader(&file->header, KI_OBJECT_NOTIFICATION_EVENT, 1);
    file->device = device; /* the lookup reference moves into the object */
    device = 0;
    file->fsContext = end;
    file->fcb = &instance->header;
    file->synchronousIo =
        (options & (FILE_SYNCHRONOUS_IO_NONALERT | FILE_SYNCHRONOUS_IO_ALERT)) != 0;
    file->grantedAccess = ObpMapDesiredAccess(&IoFileObjectType, desiredAccess);
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
