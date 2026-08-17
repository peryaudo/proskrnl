/* drivers/afd.c — \Device\Afd: the socket boundary Wine's ws2_32 issues
 * (Net-2, docs/24 §5; milestone docs/02 "Net-2").
 *
 * The device serves the AFD ioctl surface — the 7 native codes plus the
 * IOCTL_AFD_WINE_* family from abi/afd.h (G4: generated, never recalled) —
 * over lwIP's raw API (third_party/lwip; drivers/net/netd.c owns the
 * stack's one mainloop thread). Semantics are pinned by tests/ntapi/
 * sem_net/ against the Wine oracle measured from OUTSIDE (docs/24 §1b —
 * wine/server/sock.c is never read); condrv's shape for the device itself:
 * trailing names swallowed at open, per-open state in fsContext, one
 * DeviceControl dispatcher.
 *
 * CONTEXTS AND THE LOCK THAT ISN'T (docs/24 §4b; drivers/net/netd.c's
 * single-threading invariant, extended here): socket state is mutated from
 * exactly two contexts — AFD verbs in syscall context (bracketed by
 * NetdEnterLwip/NetdLeaveLwip around every raw-API touch), and lwIP
 * callbacks on the netd thread (already inside the stack). Neither blocks
 * mid-update, so under Article 3's machine (uniprocessor, no kernel
 * preemption) they never interleave inside AFD state: atomic under the
 * no-preemption model, the same greppable sentence netd.c states for the
 * stack itself. This is the docs/18 §5 audit row's newest instance; CUI-10's
 * giant lock preserves it verbatim.
 *
 * PENDING rides the CUI-8 engine (kernel/io/io.h IOP_PENDING_REQUEST)
 * exactly as io.h promised since CUI-8 — nothing new is invented here:
 * IopPreparePendingRequest in the issuer's context, IopCompletePendingRequest
 * from whichever context completes (a netd callback, a cancel, the handle's
 * cleanup), IOSB-before-signal, event-XOR-file-object, packet and APC legs
 * all inherited. AFD's own AFD_REQUEST wrapper only carries what the engine
 * deliberately does not: the captured WSABUF scatter list, a parked send's
 * bytes, and the recvmsg address-writeback pointers.
 *
 * The one kernel-side park (the blocking frontier's Net-2 row, G14): a
 * SYNCHRONOUS handle's NtReadFile/NtWriteFile loops on IoWaitCancellable
 * against the socket's wake event — the npfs shape, cancellable by
 * NtCancelSynchronousIoFile, inside the IopEnterSyncIo span rw.c already
 * wraps around the ops. docs/20 §13 records the §8.4 re-check.
 *
 * OWNERSHIP AUDIT (G11): every parked AFD_REQUEST owns an
 * IOP_PENDING_REQUEST, which holds the FILE_OBJECT, the owner process, the
 * issuer thread and the event alive (io.h §5d); the request leaves a
 * socket's park list only through AfdCompleteRequest, which is the single
 * completer for every exit — data, error, cancel, close (Cleanup cancels
 * every park before the pcb dies, so a callback can never find a freed
 * request). An accepted-but-unclaimed connection is a bare AFD_SOCKET in
 * the listener's acceptQueue owned by the listener: claimed by an accept,
 * or aborted and freed by the listener's Cleanup — if every handle closes
 * at the earliest legal moment, the queue dies with the listener and no
 * pcb leaks. The accept-minted FILE_OBJECT is created with one reference
 * that ObpCreateHandleInTable's handle inherits; a mint failure closes the
 * object before the completion reports it.
 */
#include "drivers/afd.h"
#include "drivers/net/netd.h"
#include "kernel/io/io.h"
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h"
#include "kernel/ps/ps.h"
#include "kernel/mm/pool.h"
#include "kernel/mm/virtual.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/lib/list.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/init/panic.h"

#include "abi/afd.h"
#include "abi/ntstatus.h"

#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"

/* --- the wire-format address (G8) ------------------------------------------ *
 * Win32 sockaddr_in, hand-typed because abi/afd.h carries only the generic
 * sockaddr: 2-byte family, 2-byte big-endian port, 4-byte big-endian
 * address, 8 zero bytes. Re-verify against wine/include/winsock2.h
 * struct WS(sockaddr_in) / ws2def.h. */
typedef struct AFD_SOCKADDR_IN
{
    USHORT family;
    USHORT port;   /* network byte order */
    ULONG address; /* network byte order */
    UCHAR zero[8];
} AFD_SOCKADDR_IN;
_Static_assert(sizeof(AFD_SOCKADDR_IN) == 16, "Win32 sockaddr_in is 16 bytes");

#define AFD_AF_INET     2
#define AFD_SOCK_STREAM 1
#define AFD_SOCK_DGRAM  2

static USHORT AfdSwap16(USHORT value)
{
    return (USHORT)((value << 8) | (value >> 8));
}

/* --- per-open state --------------------------------------------------------- */

/* One parked operation. The engine request owns every cross-context
 * resource (io.h §5d); this wrapper owns only its own pool. */
typedef enum AFD_REQUEST_KIND
{
    AfdReqRecv,   /* IOCTL_AFD_RECV / WINE_RECVMSG: scatter segs */
    AfdReqRead,   /* ops->Read: the engine's own data legs carry it */
    AfdReqSend,   /* WINE_SENDMSG / ops->Write: parked bytes */
    AfdReqAccept, /* WINE_ACCEPT (mint) / WINE_ACCEPT_INTO (graft) */
    AfdReqConnect,
} AFD_REQUEST_KIND;

typedef struct AFD_SEG
{
    uint64_t base; /* user VA in the owner's space */
    ULONG length;
} AFD_SEG;

typedef struct AFD_REQUEST
{
    LIST_ENTRY entry;
    AFD_REQUEST_KIND kind;
    PIOP_PENDING_REQUEST pending;
    struct AFD_SOCKET *socket;

    /* recv legs */
    AFD_SEG *segs; /* pool, freed with the request */
    ULONG segCount;
    ULONG msgFlags;      /* AFD_MSG_* (PEEK already served inline) */
    uint64_t addrPtr;    /* WINE_RECVMSG source-address writeback, or 0 */
    uint64_t addrLenPtr; /* its length word, or 0 */

    /* send legs */
    UCHAR *data; /* the send run (pool) */
    ULONG dataLength;
    ULONG dataDone;          /* bytes lwIP has accepted so far */
    BOOLEAN dataEngineOwned; /* the run IS the engine's kernelBuffer bounce
                              * (a pended ops->Write): freed by
                              * IopCompletePendingRequest, never here */

    /* accept legs */
    struct AFD_SOCKET *acceptInto; /* WINE_ACCEPT_INTO's acceptor, or 0 */
} AFD_REQUEST, *PAFD_REQUEST;

/* A queued-but-unclaimed inbound connection, or a received UDP datagram. */
typedef struct AFD_DGRAM
{
    LIST_ENTRY entry;
    ULONG length;
    AFD_SOCKADDR_IN from;
    UCHAR data[];
} AFD_DGRAM;

/* The receive ring: sized to hold everything lwIP can have in flight
 * (TCP_WND) plus a full extra window so tcp_recved backpressure engages
 * before the ring can overflow — an ASSERT, not a drop, guards it. */
#define AFD_RING_CAPACITY (4 * TCP_WND)
/* UDP queue bound: datagrams past this many buffered bytes are dropped
 * (datagram semantics; loud, counted). */
#define AFD_DGRAM_CAPACITY 65536

typedef struct AFD_SOCKET
{
    IO_FCB fcb; /* embedded first: the Io close hooks key off file->fcb */
    PFILE_OBJECT file;

    int family, type, protocol;
    unsigned int createFlags;
    BOOLEAN created; /* WINE_CREATE ran */
    BOOLEAN bound;
    BOOLEAN listening;
    BOOLEAN connecting;
    BOOLEAN connected;
    BOOLEAN peerClosed;   /* orderly FIN from the peer */
    BOOLEAN shutdownRecv; /* WINE_SHUTDOWN how=0/2 */
    BOOLEAN shutdownSend;
    BOOLEAN dead;     /* Cleanup ran: the pcb is gone */
    NTSTATUS soError; /* the tcp_err latch (0 = none) */

    union
    {
        struct tcp_pcb *tcp;
        struct udp_pcb *udp;
    } pcb;

    /* TCP receive ring (pool, allocated at WINE_CREATE for streams). */
    UCHAR *ring;
    ULONG ringHead; /* consume index */
    ULONG ringCount;
    ULONG recvedOwed; /* consumed bytes not yet returned via tcp_recved
                       * (folded back inside the next lwIP seam) */

    /* UDP datagram queue (AFD_DGRAM), and its byte total. */
    LIST_ENTRY dgramQueue;
    ULONG dgramBytes;
    ULONG dgramDrops;

    /* Inbound connections not yet claimed (AFD_SOCKET shells, via
     * acceptEntry below). */
    LIST_ENTRY acceptQueue;
    LIST_ENTRY acceptEntry; /* this socket's place in its listener's queue */

    /* Parked operations, issue order. */
    LIST_ENTRY recvRequests;   /* AfdReqRecv + AfdReqRead */
    LIST_ENTRY sendRequests;   /* AfdReqSend */
    LIST_ENTRY acceptRequests; /* AfdReqAccept */
    PAFD_REQUEST connectRequest;

    /* The synchronous-handle park target (the frontier row): every
     * readiness edge sets it; the blocking read/write loop consumes it. */
    KEVENT syncWait;

    /* The 13-bit readiness machine (commit 7). pendingEvents is the EDGE
     * latch WSAEventSelect/GET_EVENTS consume (reported once); the
     * per-bit statuses persist past consumption (the CONNECT_ERR latch —
     * pinned afd_event_select.c). POLL reads LEVEL state instead
     * (AfdPollLevel), plus the CLOSE/RESET/CONNECT_ERR latches. */
    ULONG pendingEvents;
    NTSTATUS statusPerBit[AFD_POLL_BIT_COUNT];
    PKEVENT selectEvent; /* referenced body, or 0 (no selection) */
    int selectMask;
    BOOLEAN nonBlocking; /* FIONBIO / implicit via event select */
    BOOLEAN resetLatch;  /* an RST arrived (AFD_POLL_RESET's level) */

    /* The sockopt store (the get-as-output/set-as-input verbs). The
     * knobs lwIP carries are applied (nodelay, keepalive, reuse,
     * broadcast, linger-zero's abortive close); the rest are recorded
     * and reported truthfully — a caller reading its own option back
     * gets what was STORED, never a fabricated default (Art. 12's
     * spirit; pinned afd_sockopt.c). */
    int optKeepalive;
    int optOobinline;
    int optReuseaddr;
    int optExclusiveaddruse;
    int optBroadcast;
    int optNodelay;
    int optRcvbuf;
    int optSndbuf;
    int optRcvtimeoMs;
    int optSndtimeoMs;
    USHORT lingerOnoff;
    USHORT lingerSeconds;
    LARGE_INTEGER connectStamp; /* NT time at connect; 0 = never connected */

    /* The thread-exit sweep's walk (AfdCancelThreadIo): every
     * FILE_OBJECT-backed socket is on AfdSocketList from create/mint to
     * Close. Accept-queue shells never join — they can hold no parked
     * request. */
    LIST_ENTRY allSocketsEntry;
} AFD_SOCKET, *PAFD_SOCKET;

/* One parked IOCTL_AFD_POLL: the engine request plus the resolved,
 * REFERENCED entry sockets (io.h §5d: resolved at issue in the issuer's
 * context). On AfdPollList until its single completer AfdCompletePoll
 * unlinks it — satisfied, expired, displaced, cancelled or closed. */
typedef struct AFD_POLL_ENTRY
{
    PFILE_OBJECT file; /* referenced */
    PAFD_SOCKET sock;
    ULONG_PTR handleValue; /* echoed back in the output */
    int mask;
} AFD_POLL_ENTRY;

typedef struct AFD_POLL_WAIT
{
    LIST_ENTRY listEntry;
    PIOP_PENDING_REQUEST pending;
    PFILE_OBJECT issuingFile; /* == pending->file; the exclusive key */
    LONGLONG inputTimeout;    /* echoed */
    LONGLONG deadline;        /* absolute NT time; INT64_MAX = never */
    BOOLEAN exclusive;
    ULONG count;
    AFD_POLL_ENTRY entries[];
} AFD_POLL_WAIT, *PAFD_POLL_WAIT;

static PIO_DEVICE AfdDevice;

/* Every live FILE_OBJECT-backed socket, for the thread-exit sweep. Walked
 * and mutated from syscall/thread context only — atomic under the
 * no-preemption model like the rest of AFD state. */
static LIST_ENTRY AfdSocketList;

/* Every parked poll, oldest first. Evaluated on each readiness edge and
 * expired by netd's tick (AfdPollTick). */
static LIST_ENTRY AfdPollList;

/* --- err_t -> NTSTATUS ------------------------------------------------------ *
 * Statuses chosen to survive ws2_32's NtStatusToWSAError mapping
 * (dlls/ws2_32/socket.c) and pinned per case in tests/ntapi/sem_net/. */
static NTSTATUS AfdStatusFromLwip(err_t err)
{
    switch (err)
    {
    case ERR_OK:
        return STATUS_SUCCESS;
    case ERR_MEM:
    case ERR_BUF:
        return STATUS_INSUFFICIENT_RESOURCES;
    case ERR_USE:
        return STATUS_SHARING_VIOLATION; /* the bind-conflict pin */
    case ERR_VAL:
    case ERR_ARG:
        return STATUS_INVALID_PARAMETER;
    case ERR_RTE:
        return STATUS_INVALID_ADDRESS_COMPONENT;
    case ERR_RST:
        return STATUS_CONNECTION_RESET;
    case ERR_ABRT:
    case ERR_CONN:
        return STATUS_CONNECTION_REFUSED;
    default:
        return STATUS_UNSUCCESSFUL;
    }
}

/* --- small helpers ---------------------------------------------------------- */

static PAFD_SOCKET AfdFromFile(PFILE_OBJECT file)
{
    return (PAFD_SOCKET)file->fsContext;
}

/* Copy into the request OWNER's address space — the completer may be netd
 * or a peer's syscall, never assumed to share the space (io.h §5d). */
static void AfdCopyToOwner(PIOP_PENDING_REQUEST pending, uint64_t userVa, const void *source,
                           ULONG bytes)
{
    if (pending->kernelIosb)
    {
        memcpy((void *)(uintptr_t)userVa, source, bytes);
    }
    else
    {
        MiCopyToUserRangeChecked(&pending->owner->addressSpace, userVa, source, bytes);
    }
}

/* Fill a caller-shaped sockaddr_in from lwIP identity (ports come back to
 * network order here). */
static void AfdFillSockaddr(AFD_SOCKADDR_IN *out, const ip_addr_t *address, USHORT hostPort)
{
    memset(out, 0, sizeof(*out));
    out->family = AFD_AF_INET;
    out->port = AfdSwap16(hostPort);
    out->address = ip_addr_isany(address) ? 0 : ip_addr_get_ip4_u32(address);
}

/* --- the receive ring ------------------------------------------------------- */

static ULONG AfdRingSpace(PAFD_SOCKET sock)
{
    return AFD_RING_CAPACITY - sock->ringCount;
}

static void AfdRingPush(PAFD_SOCKET sock, const void *data, ULONG length)
{
    ASSERT(length <= AfdRingSpace(sock)); /* tcp_recved backpressure holds */
    const UCHAR *in = data;
    ULONG tail = (sock->ringHead + sock->ringCount) % AFD_RING_CAPACITY;
    for (ULONG i = 0; i < length; i++)
    {
        sock->ring[(tail + i) % AFD_RING_CAPACITY] = in[i];
    }
    sock->ringCount += length;
}

/* Copy up to the segment list's total from the ring into the OWNER's
 * space; consumes unless `peek`. Returns bytes delivered. */
static ULONG AfdRingConsume(PAFD_SOCKET sock, PIOP_PENDING_REQUEST pending, const AFD_SEG *segs,
                            ULONG segCount, BOOLEAN peek)
{
    ULONG delivered = 0;
    ULONG cursor = sock->ringHead;
    ULONG remaining = sock->ringCount;
    UCHAR chunk[512];
    for (ULONG i = 0; i < segCount && remaining != 0; i++)
    {
        ULONG segDone = 0;
        while (segDone < segs[i].length && remaining != 0)
        {
            ULONG take = segs[i].length - segDone;
            if (take > sizeof(chunk))
            {
                take = sizeof(chunk);
            }
            if (take > remaining)
            {
                take = remaining;
            }
            for (ULONG b = 0; b < take; b++)
            {
                chunk[b] = sock->ring[(cursor + b) % AFD_RING_CAPACITY];
            }
            AfdCopyToOwner(pending, segs[i].base + segDone, chunk, take);
            cursor = (cursor + take) % AFD_RING_CAPACITY;
            remaining -= take;
            segDone += take;
            delivered += take;
        }
    }
    if (!peek && delivered != 0)
    {
        sock->ringHead = (sock->ringHead + delivered) % AFD_RING_CAPACITY;
        sock->ringCount -= delivered;
        /* The consumed window is returned to the peer inside the next lwIP
         * seam (recvedOwed): this may run OUTSIDE the seam for an inline
         * verb, and tcp_recved is a raw-API call. */
        sock->recvedOwed += delivered;
    }
    return delivered;
}

/* Fold the owed window back to lwIP. Call INSIDE the seam, with a live
 * connected pcb. */
static void AfdFlushRecved(PAFD_SOCKET sock)
{
    if (sock->type == AFD_SOCK_STREAM && sock->pcb.tcp != 0 && sock->recvedOwed != 0)
    {
        ULONG owed = sock->recvedOwed;
        sock->recvedOwed = 0;
        while (owed != 0)
        {
            u16_t step = owed > 0xffff ? 0xffff : (u16_t)owed;
            tcp_recved(sock->pcb.tcp, step);
            owed -= step;
        }
    }
}

/* --- request bookkeeping ---------------------------------------------------- */

static void AfdFreeRequest(PAFD_REQUEST request)
{
    if (request->segs != 0)
    {
        MiFreePool(request->segs);
    }
    if (request->data != 0 && !request->dataEngineOwned)
    {
        MiFreePool(request->data);
    }
    MiFreePool(request);
}

/* The single completer (G11): unlink, complete through the engine, free. */
static void AfdCompleteRequest(PAFD_REQUEST request, NTSTATUS status, ULONG_PTR information)
{
    if (request->kind == AfdReqConnect)
    {
        ASSERT(request->socket->connectRequest == request);
        request->socket->connectRequest = 0;
    }
    else
    {
        RemoveEntryList(&request->entry);
    }
    IopCompletePendingRequest(request->pending, status, information);
    AfdFreeRequest(request);
}

/* Park one operation: engine request in the ISSUER's context, wrapper on
 * the socket's list. On failure nothing is parked and the caller answers
 * the status inline. */
static NTSTATUS AfdParkRequest(PAFD_SOCKET sock, PFILE_OBJECT file, IO_CONTROL_CONTEXT *context,
                               AFD_REQUEST_KIND kind, PAFD_REQUEST *out)
{
    PAFD_REQUEST request = MiAllocatePool(sizeof(*request));
    if (request == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memset(request, 0, sizeof(*request));
    request->kind = kind;
    request->socket = sock;
    NTSTATUS status = IopPreparePendingRequest(file, context, &request->pending);
    if (!NT_SUCCESS(status))
    {
        MiFreePool(request);
        return status;
    }
    switch (kind)
    {
    case AfdReqRecv:
    case AfdReqRead:
        InsertTailList(&sock->recvRequests, &request->entry);
        break;
    case AfdReqSend:
        InsertTailList(&sock->sendRequests, &request->entry);
        break;
    case AfdReqAccept:
        InsertTailList(&sock->acceptRequests, &request->entry);
        break;
    case AfdReqConnect:
        ASSERT(sock->connectRequest == 0);
        sock->connectRequest = request;
        break;
    }
    *out = request;
    return STATUS_SUCCESS;
}

/* --- the accepted-socket mint ----------------------------------------------- */

static void AfdInitializeSocketLists(PAFD_SOCKET sock)
{
    InitializeListHead(&sock->dgramQueue);
    InitializeListHead(&sock->acceptQueue);
    InitializeListHead(&sock->recvRequests);
    InitializeListHead(&sock->sendRequests);
    InitializeListHead(&sock->acceptRequests);
    KeInitializeEvent(&sock->syncWait, SynchronizationEvent, FALSE);
    IopInitializeFcb(&sock->fcb);
}

static PAFD_SOCKET AfdAllocateSocket(void)
{
    PAFD_SOCKET sock = MiAllocatePool(sizeof(*sock));
    if (sock == 0)
    {
        return 0;
    }
    memset(sock, 0, sizeof(*sock));
    AfdInitializeSocketLists(sock);
    return sock;
}

/* Mint a FILE_OBJECT + handle for an accepted connection, in the accept
 * ISSUER's table (`owner`), from whatever context completes the accept —
 * the file.c create path's field discipline, minus the namespace walk.
 * On success *handleOut is a handle in `owner`; the object's creation
 * reference has moved into it. */
static NTSTATUS AfdMintSocketHandle(PAFD_SOCKET sock, PEPROCESS owner, ACCESS_MASK granted,
                                    PHANDLE handleOut)
{
    PVOID body;
    NTSTATUS status = ObpAllocateObject(&IoFileObjectType, sizeof(FILE_OBJECT), &body);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PFILE_OBJECT file = body;
    KeInitializeEvent(&file->header, NotificationEvent, TRUE);
    ObfReferenceObject(AfdDevice);
    file->device = AfdDevice;
    KeInitializeEvent(&file->syncIoLock, SynchronizationEvent, TRUE);
    file->synchronousIo = FALSE; /* accepted sockets are asynchronous (ws2_32
                                  * wraps its own sync event around them) */
    file->grantedAccess = granted;
    file->desiredAccess = granted;
    file->fsContext = sock;
    file->fcb = &sock->fcb;
    sock->file = file;
    status = ObpCreateHandleInTable(&owner->handleTable, file, granted, 0, handleOut);
    if (!NT_SUCCESS(status))
    {
        sock->file = 0;
        file->fsContext = 0;       /* the caller still owns (and frees) the shell */
        ObDereferenceObject(file); /* runs the delete path; Cleanup never ran
                                    * and nothing pends on a fresh mint */
        return status;
    }
    InsertTailList(&AfdSocketList, &sock->allSocketsEntry);
    ObDereferenceObject(file); /* the handle's reference remains */
    return status;
}

/* Detach a queued connection's shell socket and graft its live pcb onto
 * `target` (WINE_ACCEPT_INTO), or claim it whole (WINE_ACCEPT — target is
 * the shell itself, nothing to graft). Inside the lwIP seam. */
static PAFD_SOCKET AfdClaimQueuedConnection(PAFD_SOCKET listener)
{
    ASSERT(!IsListEmpty(&listener->acceptQueue));
    PLIST_ENTRY entry = RemoveHeadList(&listener->acceptQueue);
    return CONTAINING_RECORD(entry, AFD_SOCKET, acceptEntry);
}

/* --- readiness -------------------------------------------------------------- *
 * The one edge authority (Art. 11): called after every state change from
 * BOTH contexts — lwIP callbacks on netd, verb tails in syscall context —
 * with the caller inside the lwIP seam whenever a live pcb is touched.
 * Completes every parked request the new state satisfies, re-evaluates
 * every parked poll, then wakes the synchronous-handle park. */
static void AfdCompleteRecvLocked(PAFD_SOCKET sock, PAFD_REQUEST request);
static void AfdContinueSendLocked(PAFD_SOCKET sock, PAFD_REQUEST request);
static void AfdCompleteAcceptLocked(PAFD_SOCKET sock, PAFD_REQUEST request);
static void AfdEvaluatePolls(void);

/* One EDGE: latch the bit (and its status word), fire the armed select
 * event when the mask covers it. The GET_EVENTS latch consumes bits; the
 * statuses persist (pinned afd_event_select.c). */
static void AfdRaiseEvent(PAFD_SOCKET sock, ULONG bit, NTSTATUS bitStatus)
{
    sock->pendingEvents |= 1u << bit;
    if (bitStatus != STATUS_SUCCESS)
    {
        sock->statusPerBit[bit] = bitStatus;
    }
    if (sock->selectEvent != 0 && (sock->selectMask & (1 << bit)) != 0)
    {
        KeSetEvent(sock->selectEvent, 0, FALSE);
    }
}

/* The LEVEL state IOCTL_AFD_POLL reads (masked by each entry; CLOSE is
 * reported mask or not — ws2_32:afd test_poll's own comment). */
static int AfdPollLevel(PAFD_SOCKET sock)
{
    int level = 0;
    if (sock->dead)
    {
        return AFD_POLL_CLOSE;
    }
    if (sock->type == AFD_SOCK_DGRAM)
    {
        if (!IsListEmpty(&sock->dgramQueue))
        {
            level |= AFD_POLL_READ;
        }
        level |= AFD_POLL_WRITE; /* a datagram socket can always send */
        return level;
    }
    if (sock->ringCount != 0)
    {
        level |= AFD_POLL_READ;
    }
    if (sock->listening)
    {
        if (!IsListEmpty(&sock->acceptQueue))
        {
            level |= AFD_POLL_ACCEPT;
        }
        return level;
    }
    if (sock->connected)
    {
        level |= AFD_POLL_CONNECT;
        if (sock->pcb.tcp != 0 && tcp_sndbuf(sock->pcb.tcp) != 0 && !sock->shutdownSend)
        {
            level |= AFD_POLL_WRITE;
        }
    }
    if (sock->peerClosed)
    {
        level |= AFD_POLL_HUP;
    }
    if (sock->resetLatch)
    {
        level |= AFD_POLL_RESET;
    }
    if (sock->statusPerBit[AFD_POLL_BIT_CONNECT_ERR] != 0)
    {
        level |= AFD_POLL_CONNECT_ERR;
    }
    return level;
}

/* The single poll completer: unlink, write the packed output into the
 * request's kernel bounce (the engine copies it — information > 0
 * always: the params HEAD travels even for a timeout), release the entry
 * references, complete, free. */
static void AfdCompletePoll(PAFD_POLL_WAIT wait, NTSTATUS status, BOOLEAN reportReady)
{
    struct afd_poll_params *out = wait->pending->kernelBuffer;
    ULONG ready = 0;

    RemoveEntryList(&wait->listEntry);
    memset(out, 0, sizeof(*out));
    out->timeout = wait->inputTimeout;
    out->exclusive = wait->exclusive;
    if (reportReady)
    {
        for (ULONG i = 0; i < wait->count; i++)
        {
            int flags = AfdPollLevel(wait->entries[i].sock);
            int visible = (flags & wait->entries[i].mask) | (flags & AFD_POLL_CLOSE);
            if (visible == 0)
            {
                continue;
            }
            struct afd_poll_socket *slot = &out->sockets[ready];
            slot->socket = wait->entries[i].handleValue;
            slot->flags = visible;
            slot->status = (visible & AFD_POLL_CONNECT_ERR) != 0
                               ? wait->entries[i].sock->statusPerBit[AFD_POLL_BIT_CONNECT_ERR]
                               : 0;
            ready++;
        }
    }
    out->count = ready;
    for (ULONG i = 0; i < wait->count; i++)
    {
        ObDereferenceObject(wait->entries[i].file);
    }
    IopCompletePendingRequest(wait->pending, status,
                              offsetof(struct afd_poll_params, sockets) +
                                  ready * sizeof(struct afd_poll_socket));
    MiFreePool(wait);
}

/* Re-evaluate every parked poll against current levels. Cheap at this
 * kernel's scale; called from every readiness edge. */
static void AfdEvaluatePolls(void)
{
    PLIST_ENTRY entry = AfdPollList.Flink;
    while (entry != 0 && entry != &AfdPollList)
    {
        PAFD_POLL_WAIT wait = CONTAINING_RECORD(entry, AFD_POLL_WAIT, listEntry);
        entry = entry->Flink;
        BOOLEAN ready = FALSE;
        for (ULONG i = 0; i < wait->count && !ready; i++)
        {
            int flags = AfdPollLevel(wait->entries[i].sock);
            if (((flags & wait->entries[i].mask) | (flags & AFD_POLL_CLOSE)) != 0)
            {
                ready = TRUE;
            }
        }
        if (ready)
        {
            AfdCompletePoll(wait, STATUS_SUCCESS, TRUE);
        }
    }
}

static BOOLEAN AfdRecvSatisfiable(PAFD_SOCKET sock)
{
    if (sock->type == AFD_SOCK_DGRAM)
    {
        return !IsListEmpty(&sock->dgramQueue);
    }
    return sock->ringCount != 0 || sock->peerClosed || sock->soError != 0 || sock->dead;
}

static void AfdSocketReady(PAFD_SOCKET sock)
{
    while (!IsListEmpty(&sock->recvRequests) && AfdRecvSatisfiable(sock))
    {
        PAFD_REQUEST request = CONTAINING_RECORD(sock->recvRequests.Flink, AFD_REQUEST, entry);
        AfdCompleteRecvLocked(sock, request);
    }
    while (!IsListEmpty(&sock->sendRequests))
    {
        PAFD_REQUEST request = CONTAINING_RECORD(sock->sendRequests.Flink, AFD_REQUEST, entry);
        ULONG before = request->dataDone;
        AfdContinueSendLocked(sock, request);
        if (sock->connectRequest == 0 && !IsListEmpty(&sock->sendRequests) &&
            sock->sendRequests.Flink == &request->entry && request->dataDone == before)
        {
            break; /* window still full; wait for the next tcp_sent edge */
        }
    }
    while (!IsListEmpty(&sock->acceptRequests) && !IsListEmpty(&sock->acceptQueue))
    {
        PAFD_REQUEST request = CONTAINING_RECORD(sock->acceptRequests.Flink, AFD_REQUEST, entry);
        AfdCompleteAcceptLocked(sock, request);
    }
    AfdEvaluatePolls();
    KeSetEvent(&sock->syncWait, 0, FALSE);
}

/* --- lwIP callbacks (netd context, inside the stack) ------------------------ */

static err_t AfdTcpRecvCallback(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    PAFD_SOCKET sock = arg;
    (void)err;
    if (sock == 0)
    {
        if (p != 0)
        {
            pbuf_free(p);
        }
        return ERR_OK;
    }
    if (p == 0)
    {
        sock->peerClosed = TRUE; /* orderly FIN */
        AfdRaiseEvent(sock, AFD_POLL_BIT_HUP, STATUS_SUCCESS);
        AfdSocketReady(sock);
        return ERR_OK;
    }
    if (p->tot_len > AfdRingSpace(sock))
    {
        /* The window math guarantees space (ring = 4 windows, recved only
         * on consume); reaching here is a bug, not load. */
        pbuf_free(p);
        KiPanic("afd: receive ring overflow");
    }
    for (struct pbuf *q = p; q != 0; q = q->next)
    {
        AfdRingPush(sock, q->payload, q->len);
    }
    /* tcp_recved deliberately NOT called here: the window closes until the
     * application consumes (AfdRingConsume -> recvedOwed -> AfdFlushRecved),
     * which is the backpressure that bounds the ring. */
    (void)pcb;
    pbuf_free(p);
    AfdRaiseEvent(sock, AFD_POLL_BIT_READ, STATUS_SUCCESS);
    AfdSocketReady(sock);
    return ERR_OK;
}

static err_t AfdTcpSentCallback(void *arg, struct tcp_pcb *pcb, u16_t length)
{
    PAFD_SOCKET sock = arg;
    (void)pcb;
    (void)length;
    if (sock != 0)
    {
        AfdRaiseEvent(sock, AFD_POLL_BIT_WRITE, STATUS_SUCCESS);
        AfdSocketReady(sock);
    }
    return ERR_OK;
}

static void AfdTcpErrCallback(void *arg, err_t err)
{
    PAFD_SOCKET sock = arg;
    if (sock == 0)
    {
        return;
    }
    /* The pcb is already freed (tcp_err contract). */
    sock->pcb.tcp = 0;
    sock->recvedOwed = 0;
    NTSTATUS status = AfdStatusFromLwip(err);
    if (sock->connecting)
    {
        /* A refused/reset connect answers CONNECTION_REFUSED whatever the
         * segment was (the dead-port pin). */
        status = STATUS_CONNECTION_REFUSED;
        sock->connecting = FALSE;
        AfdRaiseEvent(sock, AFD_POLL_BIT_CONNECT_ERR, status);
    }
    else
    {
        sock->resetLatch = TRUE;
        AfdRaiseEvent(sock, AFD_POLL_BIT_RESET, STATUS_SUCCESS);
    }
    sock->soError = status;
    if (sock->connectRequest != 0)
    {
        AfdCompleteRequest(sock->connectRequest, status, 0);
    }
    AfdSocketReady(sock);
}

static err_t AfdTcpConnectedCallback(void *arg, struct tcp_pcb *pcb, err_t err)
{
    PAFD_SOCKET sock = arg;
    (void)pcb;
    (void)err; /* ERR_OK by contract; failures arrive at the err callback */
    if (sock == 0)
    {
        return ERR_OK;
    }
    sock->connecting = FALSE;
    sock->connected = TRUE;
    sock->bound = TRUE; /* tcp_connect auto-binds */
    KeQuerySystemTime(&sock->connectStamp);
    AfdRaiseEvent(sock, AFD_POLL_BIT_CONNECT, STATUS_SUCCESS);
    AfdRaiseEvent(sock, AFD_POLL_BIT_WRITE, STATUS_SUCCESS);
    if (sock->connectRequest != 0)
    {
        AfdCompleteRequest(sock->connectRequest, STATUS_SUCCESS, 0);
    }
    AfdSocketReady(sock);
    return ERR_OK;
}

static void AfdWireTcpCallbacks(PAFD_SOCKET sock)
{
    tcp_arg(sock->pcb.tcp, sock);
    tcp_recv(sock->pcb.tcp, AfdTcpRecvCallback);
    tcp_sent(sock->pcb.tcp, AfdTcpSentCallback);
    tcp_err(sock->pcb.tcp, AfdTcpErrCallback);
}

static err_t AfdTcpAcceptCallback(void *arg, struct tcp_pcb *newPcb, err_t err)
{
    PAFD_SOCKET listener = arg;
    if (listener == 0 || newPcb == 0 || err != ERR_OK)
    {
        return ERR_VAL;
    }
    /* A shell socket for the connection, ready to buffer data before any
     * accept claims it. Allocation on the netd thread is ordinary pool in
     * thread context (the drain allocates nothing; netd may). */
    PAFD_SOCKET sock = AfdAllocateSocket();
    if (sock == 0)
    {
        return ERR_MEM; /* lwIP aborts the connection */
    }
    sock->ring = MiAllocatePool(AFD_RING_CAPACITY);
    if (sock->ring == 0)
    {
        MiFreePool(sock);
        return ERR_MEM;
    }
    sock->created = TRUE;
    sock->family = listener->family;
    sock->type = listener->type;
    sock->protocol = listener->protocol;
    sock->bound = TRUE;
    sock->connected = TRUE;
    sock->pcb.tcp = newPcb;
    AfdWireTcpCallbacks(sock);
    KeQuerySystemTime(&sock->connectStamp);
    /* An ACCEPTED socket's pending edge is WRITE alone — CONNECT is the
     * connect()or's edge (measured: ws2_32:afd test_get_events reads
     * WRITE, not WRITE|CONNECT, on the accepted end). */
    AfdRaiseEvent(sock, AFD_POLL_BIT_WRITE, STATUS_SUCCESS);
    InsertTailList(&listener->acceptQueue, &sock->acceptEntry);
    AfdRaiseEvent(listener, AFD_POLL_BIT_ACCEPT, STATUS_SUCCESS);
    AfdSocketReady(listener);
    return ERR_OK;
}

static void AfdUdpRecvCallback(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                               const ip_addr_t *address, u16_t port)
{
    PAFD_SOCKET sock = arg;
    (void)pcb;
    if (sock == 0 || p == 0)
    {
        if (p != 0)
        {
            pbuf_free(p);
        }
        return;
    }
    if (sock->dgramBytes + p->tot_len > AFD_DGRAM_CAPACITY)
    {
        sock->dgramDrops++; /* datagram semantics: full queue drops, loudly
                             * counted (the [KTEST] net stats line) */
        pbuf_free(p);
        return;
    }
    AFD_DGRAM *dgram = MiAllocatePool(sizeof(*dgram) + p->tot_len);
    if (dgram == 0)
    {
        sock->dgramDrops++;
        pbuf_free(p);
        return;
    }
    dgram->length = p->tot_len;
    AfdFillSockaddr(&dgram->from, address, port);
    pbuf_copy_partial(p, dgram->data, p->tot_len, 0);
    pbuf_free(p);
    InsertTailList(&sock->dgramQueue, &dgram->entry);
    sock->dgramBytes += dgram->length;
    AfdRaiseEvent(sock, AFD_POLL_BIT_READ, STATUS_SUCCESS);
    AfdSocketReady(sock);
}

/* --- parked-request completion (inside the seam) ---------------------------- */

/* One TCP/UDP recv completion against the CURRENT state; the caller
 * guaranteed AfdRecvSatisfiable. */
static void AfdCompleteRecvLocked(PAFD_SOCKET sock, PAFD_REQUEST request)
{
    if (sock->type == AFD_SOCK_DGRAM)
    {
        ASSERT(!IsListEmpty(&sock->dgramQueue));
        AFD_DGRAM *dgram = CONTAINING_RECORD(sock->dgramQueue.Flink, AFD_DGRAM, entry);
        RemoveEntryList(&dgram->entry);
        sock->dgramBytes -= dgram->length;
        ULONG capacity = 0;
        for (ULONG i = 0; i < request->segCount; i++)
        {
            capacity += request->segs[i].length;
        }
        ULONG deliver = dgram->length < capacity ? dgram->length : capacity;
        ULONG at = 0;
        for (ULONG i = 0; i < request->segCount && at < deliver; i++)
        {
            ULONG take = request->segs[i].length;
            if (take > deliver - at)
            {
                take = deliver - at;
            }
            AfdCopyToOwner(request->pending, request->segs[i].base, dgram->data + at, take);
            at += take;
        }
        if (request->addrPtr != 0)
        {
            AfdCopyToOwner(request->pending, request->addrPtr, &dgram->from, sizeof(dgram->from));
            if (request->addrLenPtr != 0)
            {
                int addrLen = sizeof(dgram->from);
                AfdCopyToOwner(request->pending, request->addrLenPtr, &addrLen, sizeof(addrLen));
            }
        }
        NTSTATUS status = dgram->length > capacity ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
        MiFreePool(dgram);
        AfdCompleteRequest(request, status, deliver);
        return;
    }

    /* Streams: data first; a parked read completes with what arrived. */
    if (sock->ringCount != 0)
    {
        if (request->kind == AfdReqRead)
        {
            /* The engine's data legs: fill the request's kernel bounce and
             * let IopCompletePendingRequest place the bytes. */
            PIOP_PENDING_REQUEST pending = request->pending;
            ULONG take =
                sock->ringCount < pending->bufferLength ? sock->ringCount : pending->bufferLength;
            for (ULONG i = 0; i < take; i++)
            {
                ((UCHAR *)pending->kernelBuffer)[i] =
                    sock->ring[(sock->ringHead + i) % AFD_RING_CAPACITY];
            }
            sock->ringHead = (sock->ringHead + take) % AFD_RING_CAPACITY;
            sock->ringCount -= take;
            sock->recvedOwed += take;
            AfdFlushRecved(sock);
            AfdCompleteRequest(request, STATUS_SUCCESS, take);
            return;
        }
        ULONG delivered =
            AfdRingConsume(sock, request->pending, request->segs, request->segCount, FALSE);
        AfdFlushRecved(sock);
        AfdCompleteRequest(request, STATUS_SUCCESS, delivered);
        return;
    }
    if (sock->soError != 0 && sock->soError != STATUS_CONNECTION_REFUSED)
    {
        AfdCompleteRequest(request, sock->soError, 0);
        return;
    }
    /* Orderly close (or a dead socket) with nothing buffered: zero bytes. */
    AfdCompleteRequest(request, STATUS_SUCCESS, 0);
}

/* Push more of a parked send into the pcb; complete when everything has
 * been ACCEPTED by lwIP (NT reports a stream send complete when the bytes
 * are queued, not when acked — ws2_32's own contract). */
static void AfdContinueSendLocked(PAFD_SOCKET sock, PAFD_REQUEST request)
{
    if (sock->pcb.tcp == 0 || sock->dead)
    {
        AfdCompleteRequest(request, sock->soError != 0 ? sock->soError : STATUS_CONNECTION_RESET,
                           request->dataDone);
        return;
    }
    while (request->dataDone < request->dataLength)
    {
        ULONG remaining = request->dataLength - request->dataDone;
        ULONG room = tcp_sndbuf(sock->pcb.tcp);
        if (room == 0)
        {
            return; /* still parked; the next tcp_sent edge retries */
        }
        ULONG push = remaining < room ? remaining : room;
        if (push > 0xffff)
        {
            push = 0xffff;
        }
        err_t err = tcp_write(sock->pcb.tcp, request->data + request->dataDone, (u16_t)push,
                              TCP_WRITE_FLAG_COPY);
        if (err == ERR_MEM)
        {
            return; /* parked until tcp_sent frees segments */
        }
        if (err != ERR_OK)
        {
            AfdCompleteRequest(request, AfdStatusFromLwip(err), request->dataDone);
            return;
        }
        request->dataDone += push;
    }
    tcp_output(sock->pcb.tcp);
    AfdCompleteRequest(request, STATUS_SUCCESS, request->dataLength);
}

/* Claim a queued connection for a parked accept: mint (WINE_ACCEPT) or
 * graft (WINE_ACCEPT_INTO), then complete. */
static void AfdCompleteAcceptLocked(PAFD_SOCKET listener, PAFD_REQUEST request)
{
    PAFD_SOCKET sock = AfdClaimQueuedConnection(listener);
    PIOP_PENDING_REQUEST pending = request->pending;

    if (request->acceptInto != 0)
    {
        /* Graft the live pcb onto the caller's pre-created acceptor. */
        PAFD_SOCKET target = request->acceptInto;
        if (target->pcb.tcp != 0)
        {
            tcp_arg(target->pcb.tcp, 0);
            if (tcp_close(target->pcb.tcp) != ERR_OK)
            {
                tcp_abort(target->pcb.tcp);
            }
        }
        target->pcb.tcp = sock->pcb.tcp;
        sock->pcb.tcp = 0;
        tcp_arg(target->pcb.tcp, target);
        target->bound = TRUE;
        target->connected = TRUE;
        /* Move anything that already buffered on the shell. */
        UCHAR *shellRing = target->ring;
        target->ring = sock->ring;
        target->ringHead = sock->ringHead;
        target->ringCount = sock->ringCount;
        target->peerClosed = sock->peerClosed;
        sock->ring = shellRing;
        MiFreePool(sock->ring);
        sock->ring = 0;
        MiFreePool(sock);
        AfdCompleteRequest(request, STATUS_SUCCESS, 0);
        AfdSocketReady(target);
        return;
    }

    HANDLE handle = 0;
    NTSTATUS status =
        AfdMintSocketHandle(sock, pending->owner, pending->file->grantedAccess, &handle);
    if (!NT_SUCCESS(status))
    {
        /* The owner is exiting or its table is full: the connection dies
         * (aborted), the accept reports the mint's failure — the
         * earliest-legal-close audit's answer. */
        if (sock->pcb.tcp != 0)
        {
            tcp_arg(sock->pcb.tcp, 0);
            tcp_abort(sock->pcb.tcp);
        }
        MiFreePool(sock->ring);
        MiFreePool(sock);
        AfdCompleteRequest(request, status, 0);
        return;
    }
    /* The handle word travels through the OUTPUT buffer with Information 0
     * (the oracle pin) — the engine's copy keys on information, so the
     * word goes out by hand here, into the owner's space. */
    ULONG handleWord = (ULONG)(ULONG_PTR)handle;
    AfdCopyToOwner(pending, (uint64_t)(uintptr_t)pending->userBuffer, &handleWord,
                   sizeof(handleWord));
    AfdCompleteRequest(request, STATUS_SUCCESS, 0);
}

/* --- verb helpers (syscall context) ----------------------------------------- */

/* Parse + capture a caller WSABUF array (issuer context, probed) into an
 * AFD_SEG pool array. */
static NTSTATUS AfdCaptureSegments(uint64_t buffersPtr, ULONG count, AFD_SEG **segsOut)
{
    if (count == 0 || count > 64)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ULONG bytes = count * sizeof(WSABUF);
    NTSTATUS status = KiProbeForRead((const void *)(uintptr_t)buffersPtr, bytes, 1);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    AFD_SEG *segs = MiAllocatePool(count * sizeof(AFD_SEG));
    if (segs == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    const WSABUF *wsabufs = (const WSABUF *)(uintptr_t)buffersPtr;
    for (ULONG i = 0; i < count; i++)
    {
        segs[i].base = (uint64_t)(uintptr_t)wsabufs[i].buf;
        segs[i].length = wsabufs[i].len;
    }
    *segsOut = segs;
    return STATUS_SUCCESS;
}

/* Validate + convert a caller sockaddr (already bounced to kernel). */
static NTSTATUS AfdReadSockaddr(const void *addr, ULONG length, ip_addr_t *addressOut,
                                u16_t *portOut)
{
    if (length < 2)
    {
        return STATUS_INVALID_PARAMETER; /* cuts into the header */
    }
    const AFD_SOCKADDR_IN *in = addr;
    if (length < sizeof(AFD_SOCKADDR_IN) || in->family != AFD_AF_INET)
    {
        return STATUS_INVALID_ADDRESS;
    }
    ip_addr_set_ip4_u32(addressOut, in->address);
    *portOut = AfdSwap16(in->port);
    return STATUS_SUCCESS;
}

/* Is this a local address the socket may bind? INADDR_ANY, loopback, or a
 * configured interface address. Inside the seam. */
static BOOLEAN AfdAddressIsLocal(const ip_addr_t *address)
{
    if (ip_addr_isany(address) || ip_addr_isloopback(address))
    {
        return TRUE;
    }
    struct netif *netif;
    NETIF_FOREACH(netif)
    {
        if (ip_addr_eq(netif_ip_addr4(netif), address))
        {
            return TRUE;
        }
    }
    return FALSE;
}

/* The synchronous-handle cancellable park (the frontier's Net-2 row): wait
 * for the next readiness edge OUTSIDE the seam. Returns STATUS_CANCELLED
 * when NtCancelSynchronousIoFile landed. */
static NTSTATUS AfdWaitReadable(PAFD_SOCKET sock)
{
    return IoWaitCancellable(&sock->syncWait, 0);
}

/* --- the verbs -------------------------------------------------------------- */

static NTSTATUS AfdCreateSocket(PFILE_OBJECT file, PAFD_SOCKET sock, const void *input,
                                ULONG inputLength)
{
    if (input == 0 || inputLength < sizeof(struct afd_create_params))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (sock->created)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const struct afd_create_params *params = input;
    if (params->family != AFD_AF_INET)
    {
        /* The staged surface: AF_INET6 (and everything else) refuses until
         * its own pins exist — a real caller's refusal, so a specific
         * status, recorded in docs/03 ("Net-2 staged AF_INET6"). */
        return STATUS_NOT_SUPPORTED;
    }
    if (params->type != AFD_SOCK_STREAM && params->type != AFD_SOCK_DGRAM)
    {
        return STATUS_NOT_SUPPORTED;
    }
    sock->family = params->family;
    sock->type = params->type;
    sock->protocol = params->protocol;
    sock->createFlags = params->flags;
    if (sock->type == AFD_SOCK_STREAM)
    {
        sock->ring = MiAllocatePool(AFD_RING_CAPACITY);
        if (sock->ring == 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    NetdEnterLwip();
    if (sock->type == AFD_SOCK_STREAM)
    {
        sock->pcb.tcp = tcp_new();
        if (sock->pcb.tcp != 0)
        {
            AfdWireTcpCallbacks(sock);
        }
    }
    else
    {
        sock->pcb.udp = udp_new();
        if (sock->pcb.udp != 0)
        {
            udp_recv(sock->pcb.udp, AfdUdpRecvCallback, sock);
        }
    }
    NetdLeaveLwip();
    if (sock->pcb.tcp == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    sock->created = TRUE;
    (void)file;
    return STATUS_SUCCESS;
}

static NTSTATUS AfdBind(PAFD_SOCKET sock, const void *input, ULONG inputLength, void *output,
                        ULONG outputLength, ULONG_PTR *infoOut)
{
    if (!sock->created)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (input == 0 || inputLength < sizeof(int) + 2)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ip_addr_t address;
    u16_t port;
    NTSTATUS status = AfdReadSockaddr((const UCHAR *)input + sizeof(int), inputLength - sizeof(int),
                                      &address, &port);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* The output must hold the materialized name (the pinned
     * INVALID_PARAMETER when it cannot). */
    if (outputLength < sizeof(AFD_SOCKADDR_IN))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (sock->bound)
    {
        return STATUS_ADDRESS_ALREADY_ASSOCIATED;
    }

    NetdEnterLwip();
    if (!AfdAddressIsLocal(&address))
    {
        NetdLeaveLwip();
        return STATUS_INVALID_ADDRESS_COMPONENT;
    }
    err_t err;
    u16_t boundPort;
    ip_addr_t boundAddress;
    if (sock->type == AFD_SOCK_STREAM)
    {
        err = tcp_bind(sock->pcb.tcp, &address, port);
        boundPort = sock->pcb.tcp->local_port;
        boundAddress = sock->pcb.tcp->local_ip;
    }
    else
    {
        err = udp_bind(sock->pcb.udp, &address, port);
        boundPort = sock->pcb.udp->local_port;
        boundAddress = sock->pcb.udp->local_ip;
    }
    NetdLeaveLwip();
    if (err != ERR_OK)
    {
        return AfdStatusFromLwip(err); /* ERR_USE -> SHARING_VIOLATION (pin) */
    }
    sock->bound = TRUE;
    /* An ANY bind reports the loopback-or-wildcard it got; the pinned
     * cases bind 127.0.0.1 and read it back. */
    AFD_SOCKADDR_IN *name = output;
    AfdFillSockaddr(name, &boundAddress, boundPort);
    if (ip_addr_isany_val(boundAddress) && !ip_addr_isany(&address))
    {
        name->address = ip_addr_get_ip4_u32(&address);
    }
    *infoOut = sizeof(*name);
    return STATUS_SUCCESS;
}

static NTSTATUS AfdListen(PAFD_SOCKET sock, const void *input, ULONG inputLength)
{
    if (!sock->created || sock->type != AFD_SOCK_STREAM || !sock->bound)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (input == 0 || inputLength < sizeof(struct afd_listen_params))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (sock->listening)
    {
        return STATUS_SUCCESS; /* re-listen is idempotent (pinned) */
    }
    const struct afd_listen_params *params = input;
    int backlog = params->backlog;
    if (backlog <= 0)
    {
        backlog = 1;
    }
    NetdEnterLwip();
    struct tcp_pcb *listenPcb = tcp_listen_with_backlog(sock->pcb.tcp, (u8_t)backlog);
    if (listenPcb != 0)
    {
        sock->pcb.tcp = listenPcb;
        tcp_arg(listenPcb, sock);
        tcp_accept(listenPcb, AfdTcpAcceptCallback);
    }
    NetdLeaveLwip();
    if (listenPcb == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    sock->listening = TRUE;
    return STATUS_SUCCESS;
}

static NTSTATUS AfdGetSockName(PAFD_SOCKET sock, void *output, ULONG outputLength,
                               ULONG_PTR *infoOut)
{
    if (!sock->created || !sock->bound)
    {
        return STATUS_INVALID_PARAMETER; /* state before length (pinned) */
    }
    if (outputLength < sizeof(AFD_SOCKADDR_IN))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    AFD_SOCKADDR_IN name;
    NetdEnterLwip();
    if (sock->type == AFD_SOCK_STREAM && sock->pcb.tcp != 0)
    {
        AfdFillSockaddr(&name, &sock->pcb.tcp->local_ip, sock->pcb.tcp->local_port);
    }
    else if (sock->type == AFD_SOCK_DGRAM && sock->pcb.udp != 0)
    {
        AfdFillSockaddr(&name, &sock->pcb.udp->local_ip, sock->pcb.udp->local_port);
    }
    else
    {
        NetdLeaveLwip();
        return STATUS_INVALID_PARAMETER;
    }
    NetdLeaveLwip();
    memcpy(output, &name, sizeof(name));
    *infoOut = sizeof(name);
    return STATUS_SUCCESS;
}

static NTSTATUS AfdGetPeerName(PAFD_SOCKET sock, void *output, ULONG outputLength,
                               ULONG_PTR *infoOut)
{
    if (!sock->created || !sock->connected)
    {
        return STATUS_INVALID_CONNECTION;
    }
    if (outputLength < sizeof(AFD_SOCKADDR_IN))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    AFD_SOCKADDR_IN name;
    NetdEnterLwip();
    if (sock->type != AFD_SOCK_STREAM || sock->pcb.tcp == 0)
    {
        NetdLeaveLwip();
        return STATUS_INVALID_CONNECTION;
    }
    AfdFillSockaddr(&name, &sock->pcb.tcp->remote_ip, sock->pcb.tcp->remote_port);
    NetdLeaveLwip();
    memcpy(output, &name, sizeof(name));
    *infoOut = sizeof(name);
    return STATUS_SUCCESS;
}

static NTSTATUS AfdConnect(PAFD_SOCKET sock, PFILE_OBJECT file, IO_CONTROL_CONTEXT *context,
                           const void *input, ULONG inputLength)
{
    if (!sock->created || sock->type != AFD_SOCK_STREAM)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (input == 0 || inputLength < sizeof(struct afd_connect_params))
    {
        return STATUS_INVALID_PARAMETER;
    }
    const struct afd_connect_params *params = input;
    if (params->addr_len < 0 ||
        inputLength < sizeof(struct afd_connect_params) + (ULONG)params->addr_len)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (sock->connected || sock->connecting)
    {
        return STATUS_CONNECTION_ACTIVE;
    }
    ip_addr_t address;
    u16_t port;
    NTSTATUS status = AfdReadSockaddr(params + 1, (ULONG)params->addr_len, &address, &port);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* Nonblocking: initiate and answer would-block inline; the outcome
     * arrives as the CONNECT/CONNECT_ERR edge (WSAEventSelect's shape). */
    if (sock->nonBlocking)
    {
        sock->connecting = TRUE;
        sock->soError = 0;
        NetdEnterLwip();
        err_t err = tcp_connect(sock->pcb.tcp, &address, port, AfdTcpConnectedCallback);
        NetdLeaveLwip();
        NetdWake();
        if (err != ERR_OK)
        {
            sock->connecting = FALSE;
            return AfdStatusFromLwip(err);
        }
        return STATUS_DEVICE_NOT_READY;
    }

    PAFD_REQUEST request = 0;
    status = AfdParkRequest(sock, file, context, AfdReqConnect, &request);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    sock->connecting = TRUE;
    sock->soError = 0;
    NetdEnterLwip();
    err_t err = tcp_connect(sock->pcb.tcp, &address, port, AfdTcpConnectedCallback);
    NetdLeaveLwip();
    NetdWake(); /* the SYN is queued; netd services the loopback promptly */
    if (err != ERR_OK)
    {
        sock->connecting = FALSE;
        AfdCompleteRequest(request, AfdStatusFromLwip(err), 0);
    }
    return STATUS_PENDING;
}

static NTSTATUS AfdAccept(PAFD_SOCKET sock, PFILE_OBJECT file, IO_CONTROL_CONTEXT *context,
                          ULONG outputLength, PAFD_SOCKET acceptInto)
{
    if (!sock->created || !sock->listening)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (acceptInto == 0 && outputLength < sizeof(ULONG))
    {
        return STATUS_INVALID_PARAMETER;
    }
    PAFD_REQUEST request = 0;
    NTSTATUS status = AfdParkRequest(sock, file, context, AfdReqAccept, &request);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    request->acceptInto = acceptInto;
    /* Ready already? Complete from this same call (the oracle answers
     * PENDING either way — pinned test_ready_accept). */
    NetdEnterLwip();
    if (!IsListEmpty(&sock->acceptQueue))
    {
        AfdCompleteAcceptLocked(sock, request);
    }
    NetdLeaveLwip();
    return STATUS_PENDING;
}

/* The RECV core shared by IOCTL_AFD_RECV, WINE_RECVMSG and ops->Read:
 * satisfy inline when possible, park otherwise. `context` may be 0 for a
 * probe-only caller (none today). */
static NTSTATUS AfdRecvCommon(PAFD_SOCKET sock, PFILE_OBJECT file, IO_CONTROL_CONTEXT *context,
                              AFD_SEG *segs, ULONG segCount, ULONG msgFlags, BOOLEAN forceAsync,
                              uint64_t addrPtr, uint64_t addrLenPtr, ULONG_PTR *infoOut)
{
    if (sock->shutdownRecv)
    {
        MiFreePool(segs);
        return STATUS_PIPE_DISCONNECTED;
    }
    if (sock->type == AFD_SOCK_STREAM && !sock->connected && !sock->peerClosed)
    {
        MiFreePool(segs);
        return STATUS_INVALID_CONNECTION;
    }
    /* Nonblocking: an unsatisfiable recv answers would-block INLINE, IOSB
     * untouched — unless AFD_RECV_FORCE_ASYNC/force_async overrides
     * (pinned afd_nonblock.c). */
    if (sock->nonBlocking && !forceAsync && !AfdRecvSatisfiable(sock))
    {
        MiFreePool(segs);
        return STATUS_DEVICE_NOT_READY;
    }

    /* Inline when satisfiable NOW (the non-PENDING return is the caller's
     * discrimination — docs/19 §1). */
    NetdEnterLwip();
    if (sock->type == AFD_SOCK_STREAM && sock->ringCount != 0)
    {
        /* PEEK and ordinary consumption share the ring walk. A current-
         * process caller: the checked copy against our own space. */
        IOP_PENDING_REQUEST inlineShape = {.owner = KeGetCurrentThread()->process,
                                           .kernelIosb = ExGetPreviousMode() == KernelMode};
        ULONG delivered =
            AfdRingConsume(sock, &inlineShape, segs, segCount, (msgFlags & AFD_MSG_PEEK) != 0);
        AfdFlushRecved(sock);
        NetdLeaveLwip();
        MiFreePool(segs);
        *infoOut = delivered;
        return STATUS_SUCCESS;
    }
    if (sock->type == AFD_SOCK_DGRAM && !IsListEmpty(&sock->dgramQueue) &&
        (msgFlags & AFD_MSG_PEEK) == 0)
    {
        /* Complete through the parked path against a temporary request so
         * datagram truncation stays in one place: park then satisfy. */
        NetdLeaveLwip();
        goto park;
    }
    if (sock->type == AFD_SOCK_STREAM && (sock->peerClosed || sock->soError != 0))
    {
        NTSTATUS status = sock->soError != 0 ? sock->soError : STATUS_SUCCESS;
        NetdLeaveLwip();
        MiFreePool(segs);
        *infoOut = 0;
        return status;
    }
    NetdLeaveLwip();

park:;
    PAFD_REQUEST request = 0;
    NTSTATUS status = AfdParkRequest(sock, file, context, AfdReqRecv, &request);
    if (!NT_SUCCESS(status))
    {
        MiFreePool(segs);
        return status;
    }
    request->segs = segs;
    request->segCount = segCount;
    request->msgFlags = msgFlags;
    request->addrPtr = addrPtr;
    request->addrLenPtr = addrLenPtr;
    NetdEnterLwip();
    if (AfdRecvSatisfiable(sock))
    {
        AfdSocketReady(sock); /* completes this (and any earlier) request */
    }
    NetdLeaveLwip();
    return STATUS_PENDING;
}

static NTSTATUS AfdRecvIoctl(PAFD_SOCKET sock, PFILE_OBJECT file, IO_CONTROL_CONTEXT *context,
                             const void *input, ULONG inputLength, ULONG_PTR *infoOut)
{
    if (!sock->created)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (input == 0 || inputLength < sizeof(struct afd_recv_params))
    {
        return STATUS_INVALID_PARAMETER;
    }
    const struct afd_recv_params *params = input;
    /* Exactly one OOB disposition (pinned): OOB itself is unbuilt — lwIP
     * carries no urgent data (docs/03 "Net-2 urgent data") — but the flag
     * VALIDATION is NT surface and refuses the same way. */
    ULONG disposition = (ULONG)params->msg_flags & (AFD_MSG_OOB | AFD_MSG_NOT_OOB);
    if (disposition != AFD_MSG_OOB && disposition != AFD_MSG_NOT_OOB)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if ((params->msg_flags & AFD_MSG_OOB) != 0)
    {
        return STATUS_INVALID_PARAMETER; /* no urgent data on this stack */
    }
    AFD_SEG *segs = 0;
    NTSTATUS status =
        AfdCaptureSegments((uint64_t)(uintptr_t)params->buffers, params->count, &segs);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    return AfdRecvCommon(sock, file, context, segs, params->count, (ULONG)params->msg_flags,
                         (params->recv_flags & AFD_RECV_FORCE_ASYNC) != 0, 0, 0, infoOut);
}

static NTSTATUS AfdRecvMsg(PAFD_SOCKET sock, PFILE_OBJECT file, IO_CONTROL_CONTEXT *context,
                           const void *input, ULONG inputLength, ULONG_PTR *infoOut)
{
    if (!sock->created)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (input == 0 || inputLength < sizeof(struct afd_recvmsg_params))
    {
        return STATUS_INVALID_PARAMETER;
    }
    const struct afd_recvmsg_params *params = input;
    AFD_SEG *segs = 0;
    NTSTATUS status = AfdCaptureSegments(params->buffers_ptr, params->count, &segs);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    return AfdRecvCommon(sock, file, context, segs, params->count, AFD_MSG_NOT_OOB,
                         params->force_async != 0, params->addr_ptr, params->addr_len_ptr, infoOut);
}

/* Gather a caller's WSABUF payload into one pool run (issuer context). */
static NTSTATUS AfdGatherSend(uint64_t buffersPtr, ULONG count, UCHAR **dataOut, ULONG *lengthOut)
{
    AFD_SEG *segs = 0;
    NTSTATUS status = AfdCaptureSegments(buffersPtr, count, &segs);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t total = 0;
    for (ULONG i = 0; i < count; i++)
    {
        total += segs[i].length;
    }
    if (total > (16u << 20))
    {
        MiFreePool(segs);
        return STATUS_INVALID_PARAMETER;
    }
    UCHAR *data = total != 0 ? MiAllocatePool((ULONG)total) : 0;
    if (total != 0 && data == 0)
    {
        MiFreePool(segs);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ULONG at = 0;
    for (ULONG i = 0; data != 0 && i < count; i++)
    {
        if (segs[i].length == 0)
        {
            continue;
        }
        status = KiProbeForRead((const void *)(uintptr_t)segs[i].base, segs[i].length, 1);
        if (!NT_SUCCESS(status))
        {
            MiFreePool(segs);
            MiFreePool(data);
            return status;
        }
        memcpy(data + at, (const void *)(uintptr_t)segs[i].base, segs[i].length);
        at += segs[i].length;
    }
    MiFreePool(segs);
    *dataOut = data;
    *lengthOut = (ULONG)total;
    return STATUS_SUCCESS;
}

/* The SEND core shared by WINE_SENDMSG and ops->Write: `data` is pool the
 * caller hands over (freed here or by the parked request). */
static NTSTATUS AfdSendCommon(PAFD_SOCKET sock, PFILE_OBJECT file, IO_CONTROL_CONTEXT *context,
                              UCHAR *data, ULONG length, const AFD_SOCKADDR_IN *to,
                              ULONG_PTR *infoOut)
{
    if (sock->shutdownSend)
    {
        if (data != 0)
        {
            MiFreePool(data);
        }
        return STATUS_PIPE_DISCONNECTED;
    }
    if (sock->type == AFD_SOCK_DGRAM)
    {
        ip_addr_t address;
        u16_t port = 0;
        BOOLEAN haveAddress = FALSE;
        if (to != 0)
        {
            if (to->family != AFD_AF_INET)
            {
                if (data != 0)
                {
                    MiFreePool(data);
                }
                return STATUS_INVALID_ADDRESS;
            }
            ip_addr_set_ip4_u32(&address, to->address);
            port = AfdSwap16(to->port);
            haveAddress = TRUE;
        }
        struct pbuf *p;
        err_t err = ERR_MEM;
        NetdEnterLwip();
        p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)length, PBUF_RAM);
        if (p != 0)
        {
            if (length != 0)
            {
                pbuf_take(p, data, (u16_t)length);
            }
            err = haveAddress ? udp_sendto(sock->pcb.udp, p, &address, port)
                              : udp_send(sock->pcb.udp, p);
            pbuf_free(p);
        }
        sock->bound = sock->bound || err == ERR_OK; /* sendto auto-binds */
        NetdLeaveLwip();
        NetdWake();
        if (data != 0)
        {
            MiFreePool(data);
        }
        if (err != ERR_OK)
        {
            return AfdStatusFromLwip(err);
        }
        *infoOut = length;
        return STATUS_SUCCESS;
    }

    if (!sock->connected || sock->pcb.tcp == 0)
    {
        if (data != 0)
        {
            MiFreePool(data);
        }
        return sock->soError != 0 ? sock->soError : STATUS_INVALID_CONNECTION;
    }

    /* Try inline; park the remainder when the window is full. */
    ULONG done = 0;
    err_t err = ERR_OK;
    NetdEnterLwip();
    while (done < length)
    {
        ULONG room = tcp_sndbuf(sock->pcb.tcp);
        if (room == 0)
        {
            break;
        }
        ULONG push = length - done < room ? length - done : room;
        if (push > 0xffff)
        {
            push = 0xffff;
        }
        err = tcp_write(sock->pcb.tcp, data + done, (u16_t)push, TCP_WRITE_FLAG_COPY);
        if (err != ERR_OK)
        {
            break;
        }
        done += push;
    }
    if (done != 0)
    {
        tcp_output(sock->pcb.tcp);
    }
    NetdLeaveLwip();
    NetdWake();
    if (done == length)
    {
        if (data != 0)
        {
            MiFreePool(data);
        }
        *infoOut = length;
        return STATUS_SUCCESS;
    }
    if (err != ERR_OK && err != ERR_MEM)
    {
        MiFreePool(data);
        return AfdStatusFromLwip(err);
    }
    /* Nonblocking: report the partial inline, or would-block when
     * nothing at all fit. */
    if (sock->nonBlocking)
    {
        MiFreePool(data);
        if (done != 0)
        {
            *infoOut = done;
            return STATUS_SUCCESS;
        }
        return STATUS_DEVICE_NOT_READY;
    }
    /* Window full: park the whole run (dataDone tracks progress). */
    PAFD_REQUEST request = 0;
    NTSTATUS status = AfdParkRequest(sock, file, context, AfdReqSend, &request);
    if (!NT_SUCCESS(status))
    {
        MiFreePool(data);
        return status;
    }
    request->data = data;
    request->dataLength = length;
    request->dataDone = done;
    return STATUS_PENDING;
}

static NTSTATUS AfdSendMsg(PAFD_SOCKET sock, PFILE_OBJECT file, IO_CONTROL_CONTEXT *context,
                           const void *input, ULONG inputLength, ULONG_PTR *infoOut)
{
    if (!sock->created)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (input == 0 || inputLength < sizeof(struct afd_sendmsg_params))
    {
        return STATUS_INVALID_PARAMETER;
    }
    const struct afd_sendmsg_params *params = input;
    AFD_SOCKADDR_IN to;
    const AFD_SOCKADDR_IN *toPtr = 0;
    if (params->addr_ptr != 0 && params->addr_len >= sizeof(AFD_SOCKADDR_IN))
    {
        NTSTATUS status = KiProbeForRead((const void *)(uintptr_t)params->addr_ptr, sizeof(to), 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        memcpy(&to, (const void *)(uintptr_t)params->addr_ptr, sizeof(to));
        toPtr = &to;
    }
    UCHAR *data = 0;
    ULONG length = 0;
    NTSTATUS status = AfdGatherSend(params->buffers_ptr, params->count, &data, &length);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    return AfdSendCommon(sock, file, context, data, length, toPtr, infoOut);
}

static NTSTATUS AfdShutdown(PAFD_SOCKET sock, const void *input, ULONG inputLength)
{
    if (!sock->created)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (input == 0 || inputLength < sizeof(int))
    {
        return STATUS_INVALID_PARAMETER;
    }
    int how = *(const int *)input; /* SD_RECEIVE=0 / SD_SEND=1 / SD_BOTH=2 */
    if (how < 0 || how > 2)
    {
        return STATUS_INVALID_PARAMETER;
    }
    BOOLEAN shutRx = how == 0 || how == 2;
    BOOLEAN shutTx = how == 1 || how == 2;
    if (sock->type == AFD_SOCK_STREAM && sock->pcb.tcp != 0)
    {
        NetdEnterLwip();
        AfdFlushRecved(sock);
        err_t err = tcp_shutdown(sock->pcb.tcp, shutRx ? 1 : 0, shutTx ? 1 : 0);
        if (shutRx && shutTx)
        {
            /* Both directions: the pcb is gone after tcp_shutdown. */
            sock->pcb.tcp = 0;
        }
        NetdLeaveLwip();
        NetdWake();
        if (err != ERR_OK && err != ERR_CONN)
        {
            return AfdStatusFromLwip(err);
        }
    }
    sock->shutdownRecv = sock->shutdownRecv || shutRx;
    sock->shutdownSend = sock->shutdownSend || shutTx;
    return STATUS_SUCCESS;
}

/* Refuse WITH the IOSB written ({status, 0}) — the EVENT_SELECT family's
 * refusal shape (measured: those verbs write their IOSB where the RECV
 * family's refusals leave it poisoned; pinned afd_event_select.c). The
 * pended tail delivers the write; the return is the status inline. */
static NTSTATUS AfdRefuseWithIosb(PFILE_OBJECT file, IO_CONTROL_CONTEXT *context, NTSTATUS status)
{
    PIOP_PENDING_REQUEST pending = 0;
    NTSTATUS prepared = IopPreparePendingRequest(file, context, &pending);
    if (!NT_SUCCESS(prepared))
    {
        return prepared;
    }
    IopCompletePendingRequest(pending, status, 0);
    return status;
}

static NTSTATUS AfdEventSelect(PAFD_SOCKET sock, PFILE_OBJECT file, IO_CONTROL_CONTEXT *context,
                               const void *input, ULONG inputLength)
{
    if (!sock->created)
    {
        return AfdRefuseWithIosb(file, context, STATUS_INVALID_PARAMETER);
    }
    if (input == 0 || inputLength < sizeof(struct afd_event_select_params))
    {
        return AfdRefuseWithIosb(file, context, STATUS_INVALID_PARAMETER);
    }
    const struct afd_event_select_params *params = input;
    if (params->event == 0 && params->mask != 0)
    {
        return AfdRefuseWithIosb(file, context, STATUS_INVALID_PARAMETER);
    }

    PKEVENT eventBody = 0;
    if (params->event != 0)
    {
        PVOID body;
        NTSTATUS status = ObReferenceObjectByHandle(params->event, EVENT_MODIFY_STATE,
                                                    &ObpEventType, ExGetPreviousMode(), &body, 0);
        if (!NT_SUCCESS(status))
        {
            return AfdRefuseWithIosb(file, context, status);
        }
        eventBody = body;
    }
    if (sock->selectEvent != 0)
    {
        ObDereferenceObject(sock->selectEvent);
    }
    sock->selectEvent = eventBody;
    sock->selectMask = eventBody != 0 ? params->mask : 0;
    if (eventBody != 0)
    {
        /* WSAEventSelect implies nonblocking (ws2_32's own contract; the
         * FIONBIO interlock below is its other half). */
        sock->nonBlocking = TRUE;
        if ((sock->pendingEvents & (ULONG)sock->selectMask) != 0)
        {
            KeSetEvent(sock->selectEvent, 0, FALSE);
        }
    }
    return STATUS_SUCCESS; /* inline success writes the IOSB (ioctl.c tail) */
}

static NTSTATUS AfdGetEvents(PAFD_SOCKET sock, IO_CONTROL_CONTEXT *context, void *output,
                             ULONG outputLength, ULONG_PTR *infoOut)
{
    if (!sock->created)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (output == 0 || outputLength < sizeof(struct afd_get_events_params))
    {
        return STATUS_INVALID_PARAMETER;
    }
    /* The sic convention: the raw INPUT POINTER is an event HANDLE (length
     * 0 — nothing to bounce) to reset atomically with the report. */
    if (context->userInput != 0)
    {
        PVOID body;
        NTSTATUS status = ObReferenceObjectByHandle((HANDLE)context->userInput, EVENT_MODIFY_STATE,
                                                    &ObpEventType, ExGetPreviousMode(), &body, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        KeClearEvent((PKEVENT)body);
        ObDereferenceObject(body);
    }
    struct afd_get_events_params *out = output;
    memset(out, 0, sizeof(*out));
    out->flags = (int)(sock->pendingEvents & (ULONG)sock->selectMask);
    sock->pendingEvents &= ~(ULONG)out->flags; /* reported once (the latch) */
    for (ULONG i = 0; i < AFD_POLL_BIT_COUNT; i++)
    {
        out->status[i] = sock->statusPerBit[i]; /* persists past the latch */
    }
    *infoOut = sizeof(*out);
    return STATUS_SUCCESS;
}

static NTSTATUS AfdFionbio(PAFD_SOCKET sock, const void *input, ULONG inputLength)
{
    if (!sock->created)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (input == 0 || inputLength < sizeof(int))
    {
        return STATUS_INVALID_PARAMETER;
    }
    int on = *(const int *)input;
    if (on == 0 && sock->selectMask != 0)
    {
        /* The interlock (pinned afd_nonblock.c): a socket cannot leave
         * nonblocking mode while an event mask is armed. */
        return STATUS_INVALID_PARAMETER;
    }
    sock->nonBlocking = on != 0;
    return STATUS_SUCCESS;
}

static NTSTATUS AfdPoll(PAFD_SOCKET sock, PFILE_OBJECT file, IO_CONTROL_CONTEXT *context,
                        const void *input, ULONG inputLength, void *output, ULONG outputLength,
                        ULONG_PTR *infoOut)
{
    (void)sock; /* a bare device handle may poll (pinned) */
    if (input == 0 || output == 0 || inputLength < offsetof(struct afd_poll_params, sockets) ||
        outputLength < inputLength)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const struct afd_poll_params *in = input;
    ULONG count = in->count;
    if (count == 0 || count > 64 ||
        inputLength <
            offsetof(struct afd_poll_params, sockets) + count * sizeof(struct afd_poll_socket))
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* Resolve every entry in the ISSUER's context (io.h §5d). */
    PAFD_POLL_WAIT wait = MiAllocatePool(sizeof(AFD_POLL_WAIT) + count * sizeof(AFD_POLL_ENTRY));
    if (wait == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memset(wait, 0, sizeof(AFD_POLL_WAIT) + count * sizeof(AFD_POLL_ENTRY));
    wait->inputTimeout = in->timeout;
    wait->exclusive = in->exclusive;
    wait->count = count;
    for (ULONG i = 0; i < count; i++)
    {
        PFILE_OBJECT entryFile;
        NTSTATUS status =
            IopReferenceFileByHandle((HANDLE)(ULONG_PTR)in->sockets[i].socket, 0, &entryFile, 0);
        if (NT_SUCCESS(status) && (entryFile->device != AfdDevice || AfdFromFile(entryFile) == 0 ||
                                   !AfdFromFile(entryFile)->created))
        {
            ObDereferenceObject(entryFile);
            status = STATUS_INVALID_HANDLE;
        }
        if (!NT_SUCCESS(status))
        {
            for (ULONG j = 0; j < i; j++)
            {
                ObDereferenceObject(wait->entries[j].file);
            }
            MiFreePool(wait);
            return status == STATUS_INVALID_HANDLE ? STATUS_INVALID_HANDLE : status;
        }
        wait->entries[i].file = entryFile;
        wait->entries[i].sock = AfdFromFile(entryFile);
        wait->entries[i].handleValue = in->sockets[i].socket;
        wait->entries[i].mask = in->sockets[i].flags;
    }

    /* Ready now — or a zero-timeout snapshot: answer inline through the
     * ordinary output bounce. */
    ULONG ready = 0;
    for (ULONG i = 0; i < count; i++)
    {
        int flags = AfdPollLevel(wait->entries[i].sock);
        if (((flags & wait->entries[i].mask) | (flags & AFD_POLL_CLOSE)) != 0)
        {
            ready++;
        }
    }
    if (ready != 0 || in->timeout == 0)
    {
        struct afd_poll_params *out = output;
        ULONG at = 0;
        memset(out, 0, offsetof(struct afd_poll_params, sockets));
        out->timeout = in->timeout;
        out->exclusive = in->exclusive;
        for (ULONG i = 0; i < count; i++)
        {
            int flags = AfdPollLevel(wait->entries[i].sock);
            int visible = (flags & wait->entries[i].mask) | (flags & AFD_POLL_CLOSE);
            if (visible == 0)
            {
                continue;
            }
            struct afd_poll_socket *slot = &out->sockets[at];
            slot->socket = wait->entries[i].handleValue;
            slot->flags = visible;
            slot->status = (visible & AFD_POLL_CONNECT_ERR) != 0
                               ? wait->entries[i].sock->statusPerBit[AFD_POLL_BIT_CONNECT_ERR]
                               : 0;
            at++;
        }
        out->count = at;
        for (ULONG i = 0; i < count; i++)
        {
            ObDereferenceObject(wait->entries[i].file);
        }
        MiFreePool(wait);
        *infoOut = offsetof(struct afd_poll_params, sockets) + at * sizeof(struct afd_poll_socket);
        return STATUS_SUCCESS;
    }

    /* The park. Exclusive displacement first (pinned afd_poll.c): a new
     * EXCLUSIVE poll terminates the oldest parked poll on the same
     * issuing handle iff that main poll is itself exclusive. */
    if (in->exclusive)
    {
        for (PLIST_ENTRY entry = AfdPollList.Flink; entry != &AfdPollList; entry = entry->Flink)
        {
            PAFD_POLL_WAIT main = CONTAINING_RECORD(entry, AFD_POLL_WAIT, listEntry);
            if (main->issuingFile == file)
            {
                if (main->exclusive)
                {
                    AfdCompletePoll(main, STATUS_SUCCESS, FALSE);
                }
                break; /* only the main (oldest) poll is considered */
            }
        }
    }
    NTSTATUS status = IopPreparePendingRequest(file, context, &wait->pending);
    if (!NT_SUCCESS(status))
    {
        for (ULONG i = 0; i < count; i++)
        {
            ObDereferenceObject(wait->entries[i].file);
        }
        MiFreePool(wait);
        return status;
    }
    wait->issuingFile = wait->pending->file;
    if (in->timeout == 0x7fffffffffffffffLL)
    {
        wait->deadline = 0x7fffffffffffffffLL;
    }
    else if (in->timeout < 0)
    {
        LARGE_INTEGER now;
        KeQuerySystemTime(&now);
        wait->deadline = now.QuadPart + (-in->timeout);
    }
    else
    {
        wait->deadline = in->timeout; /* absolute NT time */
    }
    InsertTailList(&AfdPollList, &wait->listEntry);
    NetdWake(); /* re-derive the netd park deadline for the expiry sweep */
    return STATUS_PENDING;
}

/* --- the poll expiry tick (netd's mainloop) --------------------------------- */

/* Milliseconds until the nearest parked-poll deadline (0 = one is already
 * due; the netd park bounds itself with this beside lwIP's own timers).
 * 0xffffffff = nothing parked with a finite deadline. */
ULONG AfdNextPollDelayMs(void)
{
    if (AfdPollList.Flink == 0 || IsListEmpty(&AfdPollList))
    {
        return 0xffffffffu;
    }
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    LONGLONG nearest = 0x7fffffffffffffffLL;
    for (PLIST_ENTRY entry = AfdPollList.Flink; entry != &AfdPollList; entry = entry->Flink)
    {
        PAFD_POLL_WAIT wait = CONTAINING_RECORD(entry, AFD_POLL_WAIT, listEntry);
        if (wait->deadline < nearest)
        {
            nearest = wait->deadline;
        }
    }
    if (nearest == 0x7fffffffffffffffLL)
    {
        return 0xffffffffu;
    }
    if (nearest <= now.QuadPart)
    {
        return 0;
    }
    LONGLONG delta100ns = nearest - now.QuadPart;
    ULONGLONG ms = (ULONGLONG)delta100ns / 10000u;
    return ms >= 0xffffffffu ? 0xfffffffeu : (ULONG)(ms + 1);
}

/* Complete every parked poll whose deadline has passed (STATUS_TIMEOUT,
 * the empty head — pinned afd_poll.c). Thread context (netd's mainloop,
 * outside the lwIP seam). */
void AfdPollTick(void)
{
    if (AfdPollList.Flink == 0 || IsListEmpty(&AfdPollList))
    {
        return;
    }
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    PLIST_ENTRY entry = AfdPollList.Flink;
    while (entry != &AfdPollList)
    {
        PAFD_POLL_WAIT wait = CONTAINING_RECORD(entry, AFD_POLL_WAIT, listEntry);
        entry = entry->Flink;
        if (wait->deadline != 0x7fffffffffffffffLL && wait->deadline <= now.QuadPart)
        {
            AfdCompletePoll(wait, STATUS_TIMEOUT, FALSE);
        }
    }
}

/* --- the sockopt verbs (one get/set pair per option) ------------------------ */

/* One int-valued GET: state before length (the GETSOCKNAME order). */
static NTSTATUS AfdOptGetInt(PAFD_SOCKET sock, void *output, ULONG outputLength, int value,
                             ULONG_PTR *infoOut)
{
    if (!sock->created)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (output == 0 || outputLength < sizeof(int))
    {
        return STATUS_INVALID_PARAMETER;
    }
    *(int *)output = value;
    *infoOut = sizeof(int);
    return STATUS_SUCCESS;
}

static NTSTATUS AfdOptReadInt(PAFD_SOCKET sock, const void *input, ULONG inputLength, int *valueOut)
{
    if (!sock->created)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (input == 0 || inputLength < sizeof(int))
    {
        return STATUS_INVALID_PARAMETER;
    }
    *valueOut = *(const int *)input;
    return STATUS_SUCCESS;
}

/* Fold a boolean option into the live pcb's so_options bit (inside the
 * seam); a socket whose pcb is already gone keeps the stored value. */
static void AfdApplySoOption(PAFD_SOCKET sock, u8_t optionBit, int on)
{
    NetdEnterLwip();
    if (sock->type == AFD_SOCK_STREAM && sock->pcb.tcp != 0)
    {
        if (on)
        {
            ip_set_option(sock->pcb.tcp, optionBit);
        }
        else
        {
            ip_reset_option(sock->pcb.tcp, optionBit);
        }
    }
    else if (sock->type == AFD_SOCK_DGRAM && sock->pcb.udp != 0)
    {
        if (on)
        {
            ip_set_option(sock->pcb.udp, optionBit);
        }
        else
        {
            ip_reset_option(sock->pcb.udp, optionBit);
        }
    }
    NetdLeaveLwip();
}

/* IOCTL_AFD_WINE_COMPLETE_ASYNC: complete THIS call with the
 * caller-supplied status through the full async legs — ws2_32's
 * fabrication verb (and its is-this-a-socket probe). The pended tail is
 * the only path that posts a packet for an error status, so the request
 * pends and completes in one motion; ioctl.c returns the status the op
 * answers (pinned sem_net/afd_refusal.c). */
static NTSTATUS AfdCompleteAsync(PAFD_SOCKET sock, PFILE_OBJECT file, IO_CONTROL_CONTEXT *context,
                                 const void *input, ULONG inputLength)
{
    if (!sock->created)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (input == 0 || inputLength < sizeof(NTSTATUS))
    {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS callerStatus = *(const NTSTATUS *)input;
    PIOP_PENDING_REQUEST pending = 0;
    NTSTATUS status = IopPreparePendingRequest(file, context, &pending);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    IopCompletePendingRequest(pending, callerStatus, 0);
    return callerStatus;
}

/* --- vfs ops ---------------------------------------------------------------- */

static NTSTATUS AfdVfsCreate(PIO_DEVICE device, PFILE_OBJECT file, const UNICODE_STRING *path,
                             PFILE_OBJECT relativeTo, ACCESS_MASK grantedAccess, ULONG shareAccess,
                             ULONG fileAttributes, ULONG disposition, ULONG options,
                             ULONG_PTR *information)
{
    (void)device;
    (void)path; /* the trailing-name swallow: \Device\Afd\anything opens */
    (void)relativeTo;
    (void)grantedAccess;
    (void)shareAccess;
    (void)fileAttributes;
    (void)disposition;
    (void)options;
    PAFD_SOCKET sock = AfdAllocateSocket();
    if (sock == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    sock->file = file;
    file->fsContext = sock;
    file->fcb = &sock->fcb;
    file->isDirectory = FALSE;
    InsertTailList(&AfdSocketList, &sock->allSocketsEntry);
    *information = FILE_OPENED;
    return STATUS_SUCCESS;
}

/* Cancel-complete every park on this socket the filter matches. The
 * filter's TERMS are the Io layer's (kernel/io/io.h IOP_CANCEL_FILTER,
 * decided by IopCancelFilterMatches — this walks, it does not decide);
 * `status` is the completion the sweep stamps: CANCELLED for
 * NtCancelIoFile, HANDLES_CLOSED for the handle's own close (both
 * oracle-pinned). */
static ULONG AfdSweepRequests(PAFD_SOCKET sock, const IOP_CANCEL_FILTER *filter, NTSTATUS status)
{
    ULONG cancelled = 0;
    LIST_ENTRY *lists[3] = {&sock->recvRequests, &sock->sendRequests, &sock->acceptRequests};
    for (int i = 0; i < 3; i++)
    {
        PLIST_ENTRY entry = lists[i]->Flink;
        while (entry != lists[i])
        {
            PAFD_REQUEST request = CONTAINING_RECORD(entry, AFD_REQUEST, entry);
            entry = entry->Flink;
            if (!IopCancelFilterMatches(request->pending, filter))
            {
                continue;
            }
            AfdCompleteRequest(request, status, 0);
            cancelled++;
        }
    }
    if (sock->connectRequest != 0 && IopCancelFilterMatches(sock->connectRequest->pending, filter))
    {
        AfdCompleteRequest(sock->connectRequest, status, 0);
        cancelled++;
    }
    /* Parked polls ISSUED on this socket's file (they may WATCH any
     * socket — the issuing handle is the cancel scope, like every other
     * request). */
    if (sock->file != 0 && AfdPollList.Flink != 0)
    {
        PLIST_ENTRY entry = AfdPollList.Flink;
        while (entry != &AfdPollList)
        {
            PAFD_POLL_WAIT wait = CONTAINING_RECORD(entry, AFD_POLL_WAIT, listEntry);
            entry = entry->Flink;
            if (wait->issuingFile != sock->file)
            {
                continue;
            }
            if (!IopCancelFilterMatches(wait->pending, filter))
            {
                continue;
            }
            AfdCompletePoll(wait, status, FALSE);
            cancelled++;
        }
    }
    return cancelled;
}

static ULONG AfdVfsCancelPending(PFILE_OBJECT file, const IOP_CANCEL_FILTER *filter)
{
    PAFD_SOCKET sock = AfdFromFile(file);
    if (sock == 0)
    {
        return 0;
    }
    return AfdSweepRequests(sock, filter, STATUS_CANCELLED);
}

static void AfdVfsCleanup(PFILE_OBJECT file)
{
    PAFD_SOCKET sock = AfdFromFile(file);
    if (sock == 0)
    {
        return;
    }
    /* Every park dies with the handle — STATUS_HANDLES_CLOSED, the
     * oracle's close-completion status (pinned afd_cancel_close.c). An
     * all-zero filter matches every request (io.h). */
    IOP_CANCEL_FILTER all = {0};
    AfdSweepRequests(sock, &all, STATUS_HANDLES_CLOSED);

    NetdEnterLwip();
    /* Unclaimed inbound connections die with their listener. */
    while (!IsListEmpty(&sock->acceptQueue))
    {
        PAFD_SOCKET queued = AfdClaimQueuedConnection(sock);
        if (queued->pcb.tcp != 0)
        {
            tcp_arg(queued->pcb.tcp, 0);
            tcp_abort(queued->pcb.tcp);
        }
        if (queued->ring != 0)
        {
            MiFreePool(queued->ring);
        }
        MiFreePool(queued);
    }
    if (sock->created)
    {
        if (sock->type == AFD_SOCK_STREAM && sock->pcb.tcp != 0)
        {
            tcp_arg(sock->pcb.tcp, 0);
            if (sock->listening)
            {
                /* A LISTEN pcb has only the accept callback — setting the
                 * data callbacks on one trips lwIP's own assert. */
                tcp_accept(sock->pcb.tcp, 0);
            }
            else
            {
                AfdFlushRecved(sock);
                tcp_recv(sock->pcb.tcp, 0);
                tcp_sent(sock->pcb.tcp, 0);
                tcp_err(sock->pcb.tcp, 0);
            }
            if (sock->lingerOnoff != 0 && sock->lingerSeconds == 0)
            {
                /* Linger-zero: the ABORTIVE close — RST, not FIN (the
                 * peer sees AFD_POLL_RESET; pinned afd_sockopt.c). */
                tcp_abort(sock->pcb.tcp);
            }
            else if (tcp_close(sock->pcb.tcp) != ERR_OK)
            {
                tcp_abort(sock->pcb.tcp);
            }
            sock->pcb.tcp = 0;
        }
        else if (sock->type == AFD_SOCK_DGRAM && sock->pcb.udp != 0)
        {
            udp_remove(sock->pcb.udp);
            sock->pcb.udp = 0;
        }
    }
    NetdLeaveLwip();
    NetdWake(); /* let the close handshake flow */
    if (sock->selectEvent != 0)
    {
        ObDereferenceObject(sock->selectEvent);
        sock->selectEvent = 0;
        sock->selectMask = 0;
    }
    sock->dead = TRUE;
    /* Polls WATCHING this socket see the close: AFD_POLL_CLOSE is
     * reported whether or not it was asked for (pinned afd_poll.c via
     * the level function). */
    AfdEvaluatePolls();
}

static void AfdVfsClose(PFILE_OBJECT file)
{
    PAFD_SOCKET sock = AfdFromFile(file);
    if (sock == 0)
    {
        return;
    }
    RemoveEntryList(&sock->allSocketsEntry);
    while (!IsListEmpty(&sock->dgramQueue))
    {
        PLIST_ENTRY entry = RemoveHeadList(&sock->dgramQueue);
        MiFreePool(CONTAINING_RECORD(entry, AFD_DGRAM, entry));
    }
    if (sock->ring != 0)
    {
        MiFreePool(sock->ring);
    }
    MiFreePool(sock);
    file->fsContext = 0;
}

static NTSTATUS AfdVfsGetInfo(PFILE_OBJECT file, IO_FILE_INFO *info)
{
    (void)file;
    memset(info, 0, sizeof(*info));
    return STATUS_SUCCESS;
}

/* NtReadFile on a socket handle: recv with one flat segment. A synchronous
 * handle BLOCKS here (never answers PENDING) — the frontier's Net-2 row:
 * IoWaitCancellable inside rw.c's IopEnterSyncIo span, cancelled by
 * NtCancelSynchronousIoFile (pinned afd_read_write.c / npfs's shape). */
static NTSTATUS AfdVfsRead(PFILE_OBJECT file, void *buffer, ULONG length, ULONG_PTR *infoOut,
                           IO_CONTROL_CONTEXT *request)
{
    PAFD_SOCKET sock = AfdFromFile(file);
    if (sock == 0 || !sock->created)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (sock->type != AFD_SOCK_STREAM)
    {
        return STATUS_INVALID_DEVICE_REQUEST; /* dgram I/O rides the ioctls */
    }
    for (;;)
    {
        if (sock->shutdownRecv)
        {
            return STATUS_PIPE_DISCONNECTED;
        }
        NetdEnterLwip();
        if (sock->ringCount != 0)
        {
            ULONG take = sock->ringCount < length ? sock->ringCount : length;
            for (ULONG i = 0; i < take; i++)
            {
                ((UCHAR *)buffer)[i] = sock->ring[(sock->ringHead + i) % AFD_RING_CAPACITY];
            }
            sock->ringHead = (sock->ringHead + take) % AFD_RING_CAPACITY;
            sock->ringCount -= take;
            sock->recvedOwed += take;
            AfdFlushRecved(sock);
            NetdLeaveLwip();
            *infoOut = take;
            return STATUS_SUCCESS;
        }
        if (sock->peerClosed || sock->dead ||
            (sock->soError != 0 && sock->soError != STATUS_CONNECTION_REFUSED))
        {
            NTSTATUS status = sock->soError != 0 ? sock->soError : STATUS_SUCCESS;
            NetdLeaveLwip();
            *infoOut = 0;
            return status;
        }
        if (!sock->connected)
        {
            NetdLeaveLwip();
            return STATUS_INVALID_CONNECTION;
        }
        NetdLeaveLwip();

        if (!file->synchronousIo)
        {
            /* Asynchronous handle: pend on the engine's own data legs —
             * the bounce IS the request's kernelBuffer (rw.c wired it). */
            PAFD_REQUEST parked = 0;
            NTSTATUS status = AfdParkRequest(sock, file, request, AfdReqRead, &parked);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            NetdEnterLwip();
            if (AfdRecvSatisfiable(sock))
            {
                AfdSocketReady(sock);
            }
            NetdLeaveLwip();
            return STATUS_PENDING;
        }
        NTSTATUS wait = AfdWaitReadable(sock);
        if (wait == STATUS_CANCELLED)
        {
            return STATUS_CANCELLED;
        }
    }
}

static NTSTATUS AfdVfsWrite(PFILE_OBJECT file, const void *buffer, ULONG length, ULONG_PTR *infoOut,
                            IO_CONTROL_CONTEXT *request)
{
    PAFD_SOCKET sock = AfdFromFile(file);
    if (sock == 0 || !sock->created)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (sock->type != AFD_SOCK_STREAM)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    if (!file->synchronousIo)
    {
        /* The bounce is the engine's kernelBuffer; hand it a pool COPY to
         * park with... no — ownership of rw.c's bounce passes on pend, so
         * the parked send reuses it directly as its data run. */
        if (sock->shutdownSend)
        {
            return STATUS_PIPE_DISCONNECTED;
        }
        if (!sock->connected || sock->pcb.tcp == 0)
        {
            return sock->soError != 0 ? sock->soError : STATUS_INVALID_CONNECTION;
        }
        ULONG done = 0;
        err_t err = ERR_OK;
        NetdEnterLwip();
        while (done < length)
        {
            ULONG room = tcp_sndbuf(sock->pcb.tcp);
            if (room == 0)
            {
                break;
            }
            ULONG push = length - done < room ? length - done : room;
            if (push > 0xffff)
            {
                push = 0xffff;
            }
            err = tcp_write(sock->pcb.tcp, (const UCHAR *)buffer + done, (u16_t)push,
                            TCP_WRITE_FLAG_COPY);
            if (err != ERR_OK)
            {
                break;
            }
            done += push;
        }
        if (done != 0)
        {
            tcp_output(sock->pcb.tcp);
        }
        NetdLeaveLwip();
        NetdWake();
        if (done == length)
        {
            *infoOut = length;
            return STATUS_SUCCESS;
        }
        if (err != ERR_OK && err != ERR_MEM)
        {
            return AfdStatusFromLwip(err);
        }
        PAFD_REQUEST parked = 0;
        NTSTATUS status = AfdParkRequest(sock, file, request, AfdReqSend, &parked);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        /* The engine bounce (request->kernelBuffer == buffer) moved into
         * the pending request on park and doubles as the send run —
         * engine-owned, so AfdFreeRequest leaves the free to
         * IopCompletePendingRequest. */
        parked->data = (UCHAR *)request->kernelBuffer;
        parked->dataLength = length;
        parked->dataDone = done;
        parked->dataEngineOwned = TRUE;
        return STATUS_PENDING;
    }
    /* Synchronous handle: block until everything is queued. */
    ULONG done = 0;
    for (;;)
    {
        if (sock->shutdownSend)
        {
            return STATUS_PIPE_DISCONNECTED;
        }
        if (!sock->connected || sock->pcb.tcp == 0)
        {
            return sock->soError != 0 ? sock->soError : STATUS_INVALID_CONNECTION;
        }
        err_t err = ERR_OK;
        NetdEnterLwip();
        while (done < length)
        {
            ULONG room = tcp_sndbuf(sock->pcb.tcp);
            if (room == 0)
            {
                break;
            }
            ULONG push = length - done < room ? length - done : room;
            if (push > 0xffff)
            {
                push = 0xffff;
            }
            err = tcp_write(sock->pcb.tcp, (const UCHAR *)buffer + done, (u16_t)push,
                            TCP_WRITE_FLAG_COPY);
            if (err != ERR_OK)
            {
                break;
            }
            done += push;
        }
        if (done != 0)
        {
            tcp_output(sock->pcb.tcp);
        }
        NetdLeaveLwip();
        NetdWake();
        if (done == length)
        {
            *infoOut = length;
            return STATUS_SUCCESS;
        }
        if (err != ERR_OK && err != ERR_MEM)
        {
            return AfdStatusFromLwip(err);
        }
        NTSTATUS wait = IoWaitCancellable(&sock->syncWait, 0);
        if (wait == STATUS_CANCELLED)
        {
            return STATUS_CANCELLED;
        }
    }
}

static NTSTATUS AfdDeviceControl(PFILE_OBJECT file, ULONG code, const void *input,
                                 ULONG inputLength, void *output, ULONG outputLength,
                                 ULONG_PTR *infoOut, IO_CONTROL_CONTEXT *request)
{
    PAFD_SOCKET sock = AfdFromFile(file);
    if (sock == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    switch (code)
    {
    case IOCTL_AFD_WINE_CREATE:
        return AfdCreateSocket(file, sock, input, inputLength);
    case IOCTL_AFD_WINE_GET_INFO:
    {
        if (!sock->created)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (outputLength < sizeof(struct afd_get_info_params))
        {
            return STATUS_INVALID_PARAMETER;
        }
        struct afd_get_info_params *info = output;
        info->family = sock->family;
        info->type = sock->type;
        info->protocol = sock->protocol;
        *infoOut = sizeof(*info);
        return STATUS_SUCCESS;
    }
    case IOCTL_AFD_BIND:
        return AfdBind(sock, input, inputLength, output, outputLength, infoOut);
    case IOCTL_AFD_LISTEN:
        return AfdListen(sock, input, inputLength);
    case IOCTL_AFD_GETSOCKNAME:
        return AfdGetSockName(sock, output, outputLength, infoOut);
    case IOCTL_AFD_WINE_GETPEERNAME:
        return AfdGetPeerName(sock, output, outputLength, infoOut);
    case IOCTL_AFD_WINE_CONNECT:
        return AfdConnect(sock, file, request, input, inputLength);
    case IOCTL_AFD_WINE_ACCEPT:
        return AfdAccept(sock, file, request, outputLength, 0);
    case IOCTL_AFD_WINE_ACCEPT_INTO:
    {
        if (input == 0 || inputLength < sizeof(struct afd_accept_into_params))
        {
            return STATUS_INVALID_PARAMETER;
        }
        const struct afd_accept_into_params *params = input;
        /* Resolve the acceptor handle in the ISSUER's context. */
        PFILE_OBJECT acceptorFile;
        NTSTATUS status =
            IopReferenceFileByHandle((HANDLE)(ULONG_PTR)params->accept_handle, 0, &acceptorFile, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (acceptorFile->device != AfdDevice || AfdFromFile(acceptorFile) == 0 ||
            !AfdFromFile(acceptorFile)->created)
        {
            ObDereferenceObject(acceptorFile);
            return STATUS_INVALID_PARAMETER;
        }
        PAFD_SOCKET acceptor = AfdFromFile(acceptorFile);
        status = AfdAccept(sock, file, request, outputLength, acceptor);
        /* The park holds no reference to the acceptor FILE_OBJECT: ws2_32
         * keeps the handle alive across AcceptEx by contract, and a close
         * of the acceptor cancels nothing here — the graft then completes
         * into a dead socket body, which Cleanup already emptied. Accepted
         * risk for Net-2, matching the oracle's own unguarded window. */
        ObDereferenceObject(acceptorFile);
        return status;
    }
    case IOCTL_AFD_POLL:
        return AfdPoll(sock, file, request, input, inputLength, output, outputLength, infoOut);
    case IOCTL_AFD_EVENT_SELECT:
        return AfdEventSelect(sock, file, request, input, inputLength);
    case IOCTL_AFD_GET_EVENTS:
        return AfdGetEvents(sock, request, output, outputLength, infoOut);
    case IOCTL_AFD_WINE_FIONBIO:
        return AfdFionbio(sock, input, inputLength);
    case IOCTL_AFD_RECV:
        return AfdRecvIoctl(sock, file, request, input, inputLength, infoOut);
    case IOCTL_AFD_WINE_RECVMSG:
        return AfdRecvMsg(sock, file, request, input, inputLength, infoOut);
    case IOCTL_AFD_WINE_SENDMSG:
        return AfdSendMsg(sock, file, request, input, inputLength, infoOut);
    case IOCTL_AFD_WINE_SHUTDOWN:
        return AfdShutdown(sock, input, inputLength);
    case IOCTL_AFD_WINE_FIONREAD:
    {
        if (!sock->created)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (outputLength < sizeof(int))
        {
            return STATUS_INVALID_PARAMETER;
        }
        int available;
        if (sock->type == AFD_SOCK_STREAM)
        {
            available = (int)sock->ringCount;
        }
        else
        {
            available =
                IsListEmpty(&sock->dgramQueue)
                    ? 0
                    : (int)CONTAINING_RECORD(sock->dgramQueue.Flink, AFD_DGRAM, entry)->length;
        }
        *(int *)output = available;
        *infoOut = sizeof(int);
        return STATUS_SUCCESS;
    }
    case IOCTL_AFD_WINE_GET_SO_ACCEPTCONN:
    {
        if (!sock->created)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (outputLength < sizeof(int))
        {
            return STATUS_INVALID_PARAMETER;
        }
        *(int *)output = sock->listening ? 1 : 0;
        *infoOut = sizeof(int);
        return STATUS_SUCCESS;
    }
    case IOCTL_AFD_WINE_GET_SO_ERROR:
        /* SO_ERROR is a WSA-error-valued option; Net-2 pins only the
         * no-error answer (afd_sockopt.c) — an NTSTATUS-to-WSA table
         * lands when a consumer pins the error case. */
        return AfdOptGetInt(sock, output, outputLength, 0, infoOut);
    case IOCTL_AFD_WINE_GET_SO_KEEPALIVE:
        return AfdOptGetInt(sock, output, outputLength, sock->optKeepalive, infoOut);
    case IOCTL_AFD_WINE_SET_SO_KEEPALIVE:
    {
        int value;
        NTSTATUS status = AfdOptReadInt(sock, input, inputLength, &value);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        sock->optKeepalive = value;
        AfdApplySoOption(sock, SOF_KEEPALIVE, value);
        return STATUS_SUCCESS;
    }
    case IOCTL_AFD_WINE_GET_SO_OOBINLINE:
        return AfdOptGetInt(sock, output, outputLength, sock->optOobinline, infoOut);
    case IOCTL_AFD_WINE_SET_SO_OOBINLINE:
    {
        /* Stored and reported; OOB data itself is out of scope (docs/03
         * "Net-2 urgent data"). */
        int value;
        NTSTATUS status = AfdOptReadInt(sock, input, inputLength, &value);
        if (NT_SUCCESS(status))
        {
            sock->optOobinline = value;
        }
        return status;
    }
    case IOCTL_AFD_WINE_GET_SO_REUSEADDR:
        return AfdOptGetInt(sock, output, outputLength, sock->optReuseaddr, infoOut);
    case IOCTL_AFD_WINE_SET_SO_REUSEADDR:
    {
        int value;
        NTSTATUS status = AfdOptReadInt(sock, input, inputLength, &value);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (value != 0 && sock->optExclusiveaddruse != 0)
        {
            return STATUS_INVALID_PARAMETER; /* mutually exclusive (pinned) */
        }
        sock->optReuseaddr = value;
        AfdApplySoOption(sock, SOF_REUSEADDR, value);
        return STATUS_SUCCESS;
    }
    case IOCTL_AFD_WINE_GET_SO_EXCLUSIVEADDRUSE:
        return AfdOptGetInt(sock, output, outputLength, sock->optExclusiveaddruse, infoOut);
    case IOCTL_AFD_WINE_SET_SO_EXCLUSIVEADDRUSE:
    {
        int value;
        NTSTATUS status = AfdOptReadInt(sock, input, inputLength, &value);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (value != 0 && sock->optReuseaddr != 0)
        {
            return STATUS_INVALID_PARAMETER; /* the pinned direction */
        }
        sock->optExclusiveaddruse = value;
        return STATUS_SUCCESS;
    }
    case IOCTL_AFD_WINE_GET_SO_BROADCAST:
        return AfdOptGetInt(sock, output, outputLength, sock->optBroadcast, infoOut);
    case IOCTL_AFD_WINE_SET_SO_BROADCAST:
    {
        int value;
        NTSTATUS status = AfdOptReadInt(sock, input, inputLength, &value);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        sock->optBroadcast = value;
        AfdApplySoOption(sock, SOF_BROADCAST, value);
        return STATUS_SUCCESS;
    }
    case IOCTL_AFD_WINE_GET_TCP_NODELAY:
        return AfdOptGetInt(sock, output, outputLength, sock->optNodelay, infoOut);
    case IOCTL_AFD_WINE_SET_TCP_NODELAY:
    {
        int value;
        NTSTATUS status = AfdOptReadInt(sock, input, inputLength, &value);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        sock->optNodelay = value;
        NetdEnterLwip();
        if (sock->type == AFD_SOCK_STREAM && sock->pcb.tcp != 0)
        {
            if (value)
            {
                tcp_nagle_disable(sock->pcb.tcp);
            }
            else
            {
                tcp_nagle_enable(sock->pcb.tcp);
            }
        }
        NetdLeaveLwip();
        return STATUS_SUCCESS;
    }
    case IOCTL_AFD_WINE_GET_SO_RCVBUF:
        return AfdOptGetInt(sock, output, outputLength,
                            sock->optRcvbuf != 0 ? sock->optRcvbuf : (int)AFD_RING_CAPACITY,
                            infoOut);
    case IOCTL_AFD_WINE_SET_SO_RCVBUF:
    {
        /* Recorded and reported; the ring's actual capacity is fixed
         * (TCP_WND bounds what lwIP buffers regardless). */
        int value;
        NTSTATUS status = AfdOptReadInt(sock, input, inputLength, &value);
        if (NT_SUCCESS(status))
        {
            sock->optRcvbuf = value;
        }
        return status;
    }
    case IOCTL_AFD_WINE_GET_SO_SNDBUF:
        return AfdOptGetInt(sock, output, outputLength,
                            sock->optSndbuf != 0 ? sock->optSndbuf : (int)TCP_SND_BUF, infoOut);
    case IOCTL_AFD_WINE_SET_SO_SNDBUF:
    {
        int value;
        NTSTATUS status = AfdOptReadInt(sock, input, inputLength, &value);
        if (NT_SUCCESS(status))
        {
            sock->optSndbuf = value;
        }
        return status;
    }
    case IOCTL_AFD_WINE_GET_SO_RCVTIMEO:
        return AfdOptGetInt(sock, output, outputLength, sock->optRcvtimeoMs, infoOut);
    case IOCTL_AFD_WINE_SET_SO_RCVTIMEO:
    {
        int value;
        NTSTATUS status = AfdOptReadInt(sock, input, inputLength, &value);
        if (NT_SUCCESS(status))
        {
            sock->optRcvtimeoMs = value;
        }
        return status;
    }
    case IOCTL_AFD_WINE_GET_SO_SNDTIMEO:
        return AfdOptGetInt(sock, output, outputLength, sock->optSndtimeoMs, infoOut);
    case IOCTL_AFD_WINE_SET_SO_SNDTIMEO:
    {
        int value;
        NTSTATUS status = AfdOptReadInt(sock, input, inputLength, &value);
        if (NT_SUCCESS(status))
        {
            sock->optSndtimeoMs = value;
        }
        return status;
    }
    case IOCTL_AFD_WINE_GET_SO_LINGER:
    {
        if (!sock->created)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (output == 0 || outputLength < 4)
        {
            return STATUS_INVALID_PARAMETER;
        }
        USHORT *out16 = output;
        out16[0] = sock->lingerOnoff;
        out16[1] = sock->lingerSeconds;
        *infoOut = 4;
        return STATUS_SUCCESS;
    }
    case IOCTL_AFD_WINE_SET_SO_LINGER:
    {
        if (!sock->created)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (input == 0 || inputLength < 4)
        {
            return STATUS_INVALID_PARAMETER;
        }
        const USHORT *in16 = input;
        sock->lingerOnoff = in16[0];
        sock->lingerSeconds = in16[1];
        return STATUS_SUCCESS;
    }
    case IOCTL_AFD_WINE_GET_SO_CONNECT_TIME:
    {
        if (!sock->created)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (output == 0 || outputLength < sizeof(unsigned int))
        {
            return STATUS_INVALID_PARAMETER;
        }
        unsigned int seconds = 0xffffffffu; /* not connected */
        if (sock->connected && sock->connectStamp.QuadPart != 0)
        {
            LARGE_INTEGER now;
            KeQuerySystemTime(&now);
            seconds = (unsigned int)((now.QuadPart - sock->connectStamp.QuadPart) / 10000000LL);
        }
        *(unsigned int *)output = seconds;
        *infoOut = sizeof(unsigned int);
        return STATUS_SUCCESS;
    }
    case IOCTL_AFD_WINE_COMPLETE_ASYNC:
        return AfdCompleteAsync(sock, file, request, input, inputLength);
    default:
        break;
    }
    /* The default arm (G12 by way of the ORACLE's shape, pinned
     * sem_net/afd_refusal.c): an unknown — or unbuilt — verb refuses
     * INLINE with STATUS_NOT_SUPPORTED, the IOSB untouched, and names
     * itself on serial (the KI_SYSCALL_MISSING pattern at device level).
     * Never STATUS_NOT_IMPLEMENTED: that means unbuilt-and-silent, which
     * the armed panic exists to catch. The unbuilt-verb tail answering
     * the unknown-code shape (where the oracle implements the verb) is
     * the recorded docs/03 divergence "Net-2 unbuilt verb tail". */
    DbgPrint("afd: unimplemented ioctl %08lx\n", (unsigned long)code);
    return STATUS_NOT_SUPPORTED;
}

static const IO_VFS_OPS AfdOps = {
    .Create = AfdVfsCreate,
    .Cleanup = AfdVfsCleanup,
    .Close = AfdVfsClose,
    .GetInfo = AfdVfsGetInfo,
    .Read = AfdVfsRead,
    .Write = AfdVfsWrite,
    .DeviceControl = AfdDeviceControl,
    .CancelPending = AfdVfsCancelPending,
};

/* The thread-exit sweep (kernel/ps/thread.c PspExitCurrentThread): a dying
 * thread's parked SOCKET I/O completes STATUS_CANCELLED — pinned
 * sem_net/afd_cancel_close.c, the ws2_32:afd test_async_thread_termination
 * contract ("asyncs without completion port are always cancelled on thread
 * exit"). Per-DEVICE deliberately: npfs keeps its measured don't-sweep
 * behavior (docs/03 "CUI-3 SCM notes"), so the sweep lives here rather
 * than in the engine. */
void AfdCancelThreadIo(struct KTHREAD *thread)
{
    if (AfdSocketList.Flink == 0)
    {
        return; /* before AfdInitialize: nothing exists to sweep */
    }
    IOP_CANCEL_FILTER byIssuer = {.issuer = thread};
    for (PLIST_ENTRY entry = AfdSocketList.Flink; entry != &AfdSocketList; entry = entry->Flink)
    {
        PAFD_SOCKET sock = CONTAINING_RECORD(entry, AFD_SOCKET, allSocketsEntry);
        AfdSweepRequests(sock, &byIssuer, STATUS_CANCELLED);
    }
}

void AfdInitialize(void)
{
    InitializeListHead(&AfdSocketList);
    InitializeListHead(&AfdPollList);
    /* FILE_DEVICE_NAMED_PIPE, not NETWORK: sockets report the pipe device
     * type (measured on the oracle; sem_net/afd_open.c) — which is what
     * makes kernelbase's GetFileType answer FILE_TYPE_PIPE for them. */
    AfdDevice = IoPublishDevice(WSTR("\\Device\\Afd"), &AfdOps, 0, FILE_DEVICE_NAMED_PIPE);
    if (AfdDevice == 0)
    {
        KiPanic("afd: device publication failed");
    }
    DbgPrint("afd: \\Device\\Afd up\n");
}
