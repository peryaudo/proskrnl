/*
 * main.c - wineserver-lite, the process (HACK-003, GUI-3).
 *
 * The GUI object model this serves is the pinned wineserver's own
 * (server/{object,handle,user,atom,class,winstation,window,queue,region,
 * clipboard,hook}.c, unmodified) with user/wine/wineserver-lite/common/shim.c as its
 * environment -- the SAME objects win32u.dll links in its in-process mode,
 * compiled once and linked into both. That is what docs/06 means by a
 * keep-list build: this is a new link of the pinned tree's files, never an
 * in-place stripping of server/, which would mutate the oracle's wineserver
 * and corrupt the spec.
 *
 * What this file adds is the loop: create the transport, then serve
 * requests and reap clients until killed. Two threads enter the state
 * machine -- this one and the timeout service thread shim.c starts -- and
 * both take the same server lock, so the state machine is single-threaded
 * exactly as it is in wineserver's own poll loop.
 *
 * How a client's death is learned: not from a closing socket (there is no
 * socket) but from its PROCESS handle going signalled, which the same wait
 * that watches the doorbell watches too. That is why the wait set is one
 * doorbell plus one handle per client process rather than per client
 * thread: NtWaitForMultipleObjects takes at most 64 handles.
 */

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"

#include "object.h"
#include "thread.h"
#include "request.h"
#include "wine/server_protocol.h"
#include "wine/server.h"

#include "transport.h"
#include "shim.h"

/* One doorbell + up to this many client processes must fit in one
 * NtWaitForMultipleObjects (MAXIMUM_WAIT_OBJECTS is 64, and the kernel
 * enforces it in kernel/ke/wait.c). The 63rd client is refused by name
 * rather than silently unwatched -- an unwatched client is one whose death
 * never reaps its windows. */
#define PRSK_MAX_CLIENTS (64 - 1)

struct client_slot
{
    struct prsk_client *client;
    HANDLE              process;
    unsigned int        pid;
};

static struct prsk_ring *ring;
static HANDLE ring_section, doorbell, ready_event, done_events[PRSK_SLOT_COUNT];
static struct client_slot client_slots[PRSK_MAX_CLIENTS];
static unsigned int client_count;

static void init_unicode( UNICODE_STRING *str, const WCHAR *name )
{
    str->Buffer = (WCHAR *)name;
    str->Length = (USHORT)(wcslen( name ) * sizeof(WCHAR));
    str->MaximumLength = str->Length;
}

static void fatal( const char *what )
{
    prsk_log( "[PANIC] wineserver-lite: %s\n", what );
    NtTerminateProcess( GetCurrentProcess(), STATUS_UNSUCCESSFUL );
}

static int create_transport(void)
{
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING name;
    LARGE_INTEGER size;
    SIZE_T view = 0;
    void *base = NULL;
    unsigned int i;

    init_unicode( &name, PRSK_SRV_RING );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    size.QuadPart = sizeof(struct prsk_ring);
    if (NtCreateSection( &ring_section, SECTION_ALL_ACCESS, &attr, &size, PAGE_READWRITE,
                         SEC_COMMIT, NULL ))
        return 0;
    if (NtMapViewOfSection( ring_section, GetCurrentProcess(), &base, 0, 0, NULL, &view, 1, 0,
                            PAGE_READWRITE ))
        return 0;
    ring = base;
    memset( ring, 0, sizeof(*ring) );

    init_unicode( &name, PRSK_SRV_DOORBELL );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    if (NtCreateEvent( &doorbell, EVENT_ALL_ACCESS, &attr, SynchronizationEvent, FALSE )) return 0;

    for (i = 0; i < PRSK_SLOT_COUNT; i++)
    {
        WCHAR buffer[64];
        char narrow[64];
        int len, c;

        len = snprintf( narrow, sizeof(narrow), "\\BaseNamedObjects\\__prsk_srv_done_%u", i );
        for (c = 0; c < len; c++) buffer[c] = (unsigned char)narrow[c];
        buffer[len] = 0;
        init_unicode( &name, buffer );
        InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
        if (NtCreateEvent( &done_events[i], EVENT_ALL_ACCESS, &attr, SynchronizationEvent, FALSE ))
            return 0;
    }

    /* Published last and left signalled: its existence AND its state are
     * the client's "everything above is ready". */
    init_unicode( &name, PRSK_SRV_READY );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    if (NtCreateEvent( &ready_event, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE )) return 0;

    __atomic_store_n( &ring->version, PRSK_RING_VERSION, __ATOMIC_RELEASE );
    NtSetEvent( ready_event, NULL );
    return 1;
}

/* Find the client record for a pid, opening the process the first time it
 * is seen so its death can be waited on. */
static struct client_slot *client_for_pid( unsigned int pid )
{
    OBJECT_ATTRIBUTES attr;
    CLIENT_ID id;
    HANDLE process = NULL;
    unsigned int i;

    for (i = 0; i < client_count; i++)
        if (client_slots[i].pid == pid) return &client_slots[i];

    if (client_count == PRSK_MAX_CLIENTS)
    {
        prsk_log( "[KTEST] wineserver-lite: %u client processes is the wait-set limit\n",
                  PRSK_MAX_CLIENTS );
        return NULL;
    }

    InitializeObjectAttributes( &attr, NULL, 0, NULL, NULL );
    id.UniqueProcess = ULongToHandle( pid );
    id.UniqueThread = 0;
    if (NtOpenProcess( &process, SYNCHRONIZE | PROCESS_DUP_HANDLE, &attr, &id ))
    {
        prsk_log( "[KTEST] wineserver-lite: cannot open client process %u\n", pid );
        return NULL;
    }

    client_slots[client_count].client = prsk_attach_client( pid, process );
    if (!client_slots[client_count].client)
    {
        NtClose( process );
        return NULL;
    }
    client_slots[client_count].process = process;
    client_slots[client_count].pid = pid;
    prsk_log( "[KTEST] gui3 client attached pid=%u\n", pid );
    return &client_slots[client_count++];
}

static void drop_client( unsigned int index )
{
    unsigned int last = client_count - 1;

    prsk_log( "[KTEST] gui3 client gone pid=%u\n", client_slots[index].pid );
    prsk_reap_client( client_slots[index].client ); /* closes the process handle */
    client_slots[index] = client_slots[last];
    client_count--;
}

/* Serve every slot that has a published request. Rescanned in full after
 * every doorbell: the doorbell is auto-reset and several clients may ring
 * it between two wakes, so counting signals would lose work. */
static void serve_ready_slots(void)
{
    struct __server_request_info info;
    unsigned int i;

    for (i = 0; i < PRSK_SLOT_COUNT; i++)
    {
        struct prsk_slot *slot = &ring->slots[i];
        struct client_slot *owner;
        unsigned int status;

        if (__atomic_load_n( &slot->state, __ATOMIC_ACQUIRE ) != PRSK_SLOT_REQUEST) continue;
        __atomic_store_n( &slot->state, PRSK_SLOT_BUSY, __ATOMIC_RELEASE );

        owner = client_for_pid( slot->pid );
        if (!owner)
        {
            slot->status = STATUS_UNSUCCESSFUL;
            slot->reply_size = 0;
        }
        else switch (slot->op)
        {
        case PRSK_OP_ATTACH:
            /* The client record already exists; the thread's own records are
             * minted lazily by the first dispatch, exactly as they are in
             * process. Nothing else to do. */
            slot->status = STATUS_SUCCESS;
            slot->reply_size = 0;
            break;
        case PRSK_OP_DETACH:
            prsk_reap_thread( owner->client, slot->tid );
            slot->status = STATUS_SUCCESS;
            slot->reply_size = 0;
            break;
        case PRSK_OP_CALL:
        default:
            memset( &info, 0, sizeof(info) );
            info.u.req = slot->req;
            info.u.req.request_header.request_size = slot->data_size;
            info.u.req.request_header.reply_size = slot->reply_max;
            info.data_count = slot->data_size ? 1 : 0;
            info.data[0].ptr = slot->data;
            info.data[0].size = slot->data_size;
            /* The reply data lands back in the slot: the handler writes
             * through current->reply_data, which dispatch_request copies
             * here. */
            info.reply_data = slot->data;
            status = prsk_server_dispatch( owner->client, slot->tid, &info );
            slot->status = status;
            /* Reply and reply data go back even on error, exactly as
             * wineserver's send_reply writes them (server/request.c): the
             * dispatch already copied the data into the slot, and callers
             * read reply fields beside an error (see call.c slot_call). */
            slot->reply = info.u.reply;
            slot->reply_size = info.u.reply.reply_header.reply_size;
            break;
        }

        __atomic_store_n( &slot->state, PRSK_SLOT_DONE, __ATOMIC_RELEASE );
        NtSetEvent( done_events[i], NULL );
    }
}

static void serve_forever(void)
{
    for (;;)
    {
        HANDLE waits[1 + PRSK_MAX_CLIENTS];
        NTSTATUS status;
        unsigned int i, count = 0;

        waits[count++] = doorbell;
        for (i = 0; i < client_count; i++) waits[count++] = client_slots[i].process;

        status = NtWaitForMultipleObjects( count, waits, WaitAny, FALSE, NULL );
        if (status == STATUS_WAIT_0)
        {
            serve_ready_slots();
            continue;
        }
        if (status > STATUS_WAIT_0 && status < (NTSTATUS)(STATUS_WAIT_0 + count))
        {
            /* A client process exited: everything it owns goes with it.
             * This is the ONLY authority on client death -- a thread that
             * dies violently is reaped here rather than by DETACH. */
            drop_client( status - STATUS_WAIT_0 - 1 );
            continue;
        }
        fatal( "wait failed" );
    }
}

void WINAPI prsk_server_start(void)
{
    prsk_log( "[KTEST] gui3 server starting\n" );
    if (!prsk_server_init()) fatal( "server bringup failed" );
    if (!create_transport()) fatal( "transport bringup failed" );
    prsk_log( "[KTEST] gui3 server READY\n" );
    serve_forever();
}
