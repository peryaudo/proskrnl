/*
 * transport.h - the wineserver-lite wire, shared by both ends.
 *
 * GUI-3 gives the GUI object model a process boundary (HACK-003). docs/06
 * fixes the mechanism: "a shared section + two kernel events (both already
 * exist)" -- deliberately NOT npfs, which is what kept the first-pixels path
 * off the pipe critical path. This header is the whole contract between the
 * client half (win32u.dll) and the server (wineserver-lite.exe); everything
 * else about the transport is private to one side or the other.
 *
 * The payload is Wine's own wire format, unchanged: a fixed 64-byte
 * union generic_request in, a fixed union generic_reply out, plus up to
 * request_size bytes of request data and reply_size bytes of reply data.
 * That is exactly what the in-process build already hands to
 * dispatch_request, so the state machine underneath sees no difference
 * between the two modes -- which is the point of route (a).
 *
 * Shape: one section holding a fixed array of SLOTS, one doorbell event
 * (client -> server, "some slot has work") and one done event per slot
 * (server -> client, "your reply is ready"). A client thread claims a slot
 * on its first call and holds it until the thread detaches, so a call is
 * two event signals and no allocation.
 *
 * Why a slot array rather than a section per client thread: the server
 * would then have to wait on one event per client thread, and
 * NtWaitForMultipleObjects tops out at 64 handles (MAXIMUM_WAIT_OBJECTS) --
 * the wait set has to hold client PROCESS handles instead, which is how the
 * server learns a client died. One doorbell keeps the wait set proportional
 * to processes, not threads.
 *
 * Nothing here is NT-absent: NT itself carries win32k state in sections
 * shared with user mode, and the events are ordinary ones. The logged hack
 * is only wineserver-lite's EXISTENCE as a separate process (docs/10
 * HACK-003), not this.
 */
#ifndef PRSK_TRANSPORT_H
#define PRSK_TRANSPORT_H

/* Object names. The server creates all of them; a client only ever opens.
 * One allocation site per name (Art. 11) -- if a client could create them,
 * a client that started first would silently become the owner of a ring the
 * server then adopts. */
#define PRSK_SRV_RING     L"\\BaseNamedObjects\\__prsk_srv_ring"
#define PRSK_SRV_DOORBELL L"\\BaseNamedObjects\\__prsk_srv_doorbell"
#define PRSK_SRV_READY    L"\\BaseNamedObjects\\__prsk_srv_ready"
/* Per-slot completion events: __prsk_srv_done_<index>, decimal, no padding. */
#define PRSK_SRV_DONE_FMT L"\\BaseNamedObjects\\__prsk_srv_done_%u"

/* The server image. Every image carrying win32u.dll carries it, so nothing
 * probes for it to decide how to talk to the server -- there is one way.
 * conhost reads it to tell a GUI image from a CUI one (proskrnl_glue.c),
 * which is a question about the IMAGE, not about the transport. */
#define PRSK_SRV_IMAGE L"\\??\\C:\\windows\\system32\\wineserver-lite.exe"

/* Serial diagnostics for both links (srv_glue.c). [KTEST]/[PANIC] prefixes,
 * human text after -- the kernel's own convention (docs/08). */
extern void prsk_log( const char *format, ... );

/* One slot per client THREAD, not per process: a thread blocks in its own
 * call, so two threads of one process must not share a slot. 64 is the
 * number of GUI threads the server can serve at once; the 65th claim
 * refuses loudly rather than corrupting a neighbour's slot. */
#define PRSK_SLOT_COUNT 64

/* Request and reply data ride in the slot. 64 KB is far above anything the
 * GUI path moves (the largest are window lists and region data), and a
 * payload over it refuses BY REQUEST NAME rather than truncating -- a
 * truncated request is a wrong answer, which Art. 12 forbids. Clipboard
 * contents (GUI-5) are the first plausible consumer of a bigger slot. */
#define PRSK_SLOT_DATA 65536

/* Everything below is the wire itself and needs Wine's protocol types
 * (union generic_request/reply). A NAMES-ONLY consumer — the conhost glue
 * takes PRSK_SRV_IMAGE from here so the server image has one authority
 * (Art. 11) — defines PRSK_TRANSPORT_NAMES_ONLY and stops here. */
#ifndef PRSK_TRANSPORT_NAMES_ONLY

/* Slot states. The client owns the transitions on the way in, the server on
 * the way out; each is published with a release store and read with an
 * acquire load, so the data next to it is visible when the state is. */
enum prsk_slot_state
{
    PRSK_SLOT_FREE = 0,  /* unclaimed                                    */
    PRSK_SLOT_IDLE,      /* claimed by a thread, no call in flight       */
    PRSK_SLOT_REQUEST,   /* client published a request (doorbell rung)   */
    PRSK_SLOT_BUSY,      /* server took it                               */
    PRSK_SLOT_DONE       /* server published the reply (done event set)  */
};

enum prsk_slot_op
{
    PRSK_OP_CALL = 0, /* an ordinary wine_server_call                    */
    PRSK_OP_ATTACH,   /* first contact from a client thread              */
    PRSK_OP_DETACH    /* the thread is going away; reap its records      */
};

/* Kept 8-byte aligned and free of pointers: the section is mapped at
 * different addresses in different processes, so nothing in here may be an
 * address. */
struct prsk_slot
{
    volatile LONG state;      /* enum prsk_slot_state                     */
    volatile LONG op;         /* enum prsk_slot_op                        */
    volatile LONG pid;        /* claiming thread's process id             */
    volatile LONG tid;        /* claiming thread's id                     */
    unsigned int  status;     /* the call's NTSTATUS, server -> client    */
    unsigned int  data_size;  /* request data bytes in `data`             */
    unsigned int  reply_size; /* reply data bytes in `data`               */
    unsigned int  reply_max;  /* reply data the client will accept        */
    union generic_request req;
    union generic_reply   reply;
    char data[PRSK_SLOT_DATA];
};

struct prsk_ring
{
    volatile LONG    version;
    /* A claimer that found every slot taken sets this and rings the
     * doorbell: the server sweeps slots whose claiming THREAD is dead and
     * frees them, then the claimer retries. Needed because a WOW64 process
     * never delivers DLL_THREAD_DETACH to the 64-bit win32u (32-bit
     * RtlExitUserThread runs only the 32-bit LdrShutdownThread before the
     * NtTerminateThread syscall; wow64_NtTerminateThread forwards straight
     * to the kernel), so every exited 32-bit GUI thread would otherwise
     * hold its slot until process death -- SAFlashPlayer's audio-retry
     * thread churn drained 58 of 64 slots in one playback. */
    volatile LONG    gc_request;
    struct prsk_slot slots[PRSK_SLOT_COUNT];
};

/* Bumped only if the layout above changes incompatibly; both ends check it,
 * so a stale client meets a refusal rather than a silent misparse. */
#define PRSK_RING_VERSION 2

#endif /* PRSK_TRANSPORT_NAMES_ONLY */

#endif /* PRSK_TRANSPORT_H */
