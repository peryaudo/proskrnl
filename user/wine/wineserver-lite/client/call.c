/*
 * call.c - wine_server_call: the client half.
 *
 * This file is linked into win32u.dll ONLY. wineserver-lite.exe compiles
 * shim.c (the state machine's environment) but never this, which is what
 * keeps the server from carrying a client of itself.
 *
 * win32u fills a struct __server_request_info and calls wine_server_call.
 * Under real Wine that marshals down a unix socket. Here it publishes the
 * request into a shared-section slot, rings the doorbell and waits for the
 * reply (GUI-3, HACK-003).
 *
 * Until GUI-2's image was re-pointed at the server there was a SECOND mode:
 * the DLL dispatched into its own copy of the state machine when no
 * wineserver-lite.exe was on the boot volume. It is gone and stays gone. A
 * silent fall back would be the worst outcome available -- a second process
 * would quietly become a second writer of the session mapping and a second
 * owner of the window tree, and the damage would surface as corrupted
 * windows much later (Art. 12: refuse loudly) -- and keeping a mode no
 * shipping image selected meant every GUI change had to be correct in an
 * arrangement nothing ran.
 *
 * What decides whether there IS a server is the BOOT, not the image. One
 * image carries both win32u.dll and wineserver-lite.exe, so "is the server
 * on the volume" stopped distinguishing anything; `Gui` does (HACK-006,
 * kernel/cm/registry.c). The two regimes:
 *
 *   Gui=1   the desktop boot. A server is expected, this waits for it, and
 *           its absence is a loud bringup failure on the first client.
 *   Gui=0   the CUI-only boot. There is no server BY DESIGN -- smss does not
 *           start one (user/smss/launch.c) -- so this does not wait for one
 *           and does not look for one. wine_server_call answers
 *           STATUS_UNSUCCESSFUL, i.e. a user32 call that would create a
 *           window FAILS at runtime, which is what CUI-only means. It is not
 *           headless: nothing draws anywhere, and nothing pretends to.
 *
 * Neither regime falls back in-process. The difference is only whether the
 * absence of a server is a defect or the arrangement.
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

#include "proskrnl_bootflag.h"

#include "prsk_request_table.h"
#include "transport.h"
#include "cursorshape.h"

/* glue.c keeps the per-thread block in TEB->Win32ThreadInfo; the claimed
 * slot rides there so a call costs no lookup. 0 means unclaimed, so the
 * zeroed block starts out right. */
extern unsigned int *prsk_thread_slot(void);

/* Set once transport_init has the ring, the doorbell and a server that
 * answered; every entry point below refuses while it is 0. */
static LONG connected;
static struct prsk_ring *ring;
static HANDLE ring_section, doorbell, done_events[PRSK_SLOT_COUNT];
/* The published cursor image: the server's section, mapped read-only here
 * (transport.h PRSK_SRV_CURSOR). Read lock-free by every scanout writer
 * (cursorshape.h prsk_cursor_read), written only through PRSK_OP_SET_CURSOR. */
static HANDLE cursor_section;
static const volatile struct prsk_cursor_image *cursor_image;

static void init_unicode( UNICODE_STRING *str, const WCHAR *name )
{
    str->Buffer = (WCHAR *)name;
    str->Length = (USHORT)(wcslen( name ) * sizeof(WCHAR));
    str->MaximumLength = str->Length;
}

/* The server publishes __prsk_srv_ready last, so waiting for it is waiting
 * for the whole transport to exist. It is opened rather than waited on
 * first: the client may well start before the server has created it. */
static int wait_for_server( void )
{
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING name;
    LARGE_INTEGER delay;
    HANDLE ready = NULL;
    int tries;

    init_unicode( &name, PRSK_SRV_READY );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    delay.QuadPart = -500000ll; /* 50 ms */
    for (tries = 0; tries < 400; tries++) /* up to ~20s of TCG-speed boot */
    {
        if (!NtOpenEvent( &ready, SYNCHRONIZE, &attr )) break;
        NtDelayExecution( FALSE, &delay );
    }
    if (!ready) return 0;
    /* Created signalled-when-ready; a zero timeout would race the setter. */
    if (NtWaitForSingleObject( ready, FALSE, NULL )) { NtClose( ready ); return 0; }
    NtClose( ready );
    return 1;
}

static int open_transport(void)
{
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING name;
    LARGE_INTEGER offset;
    SIZE_T size = 0;
    void *base = NULL;

    init_unicode( &name, PRSK_SRV_RING );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    if (NtOpenSection( &ring_section, SECTION_MAP_READ | SECTION_MAP_WRITE, &attr )) return 0;
    offset.QuadPart = 0;
    if (NtMapViewOfSection( ring_section, GetCurrentProcess(), &base, 0, 0, &offset, &size, 1,
                            0, PAGE_READWRITE ))
        return 0;
    ring = base;
    if (ring->version != PRSK_RING_VERSION)
    {
        prsk_log( "[KTEST] wineserver-lite: ring version %d, expected %d\n", (int)ring->version,
                  PRSK_RING_VERSION );
        return 0;
    }

    init_unicode( &name, PRSK_SRV_DOORBELL );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    if (NtOpenEvent( &doorbell, EVENT_MODIFY_STATE, &attr )) return 0;

    /* The cursor image, read-only: this process never writes it, and a
     * process that dies mid-write would leave the seqlock odd for every
     * other writer's flush. It is created before the ring (shim.c
     * server_bringup), so its absence is a bring-up defect, not a race. */
    init_unicode( &name, PRSK_SRV_CURSOR );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    if (NtOpenSection( &cursor_section, SECTION_MAP_READ, &attr )) return 0;
    base = NULL;
    size = 0;
    if (NtMapViewOfSection( cursor_section, GetCurrentProcess(), &base, 0, 0, &offset, &size, 1,
                            0, PAGE_READONLY ))
        return 0;
    cursor_image = base;
    return 1;
}

/* The published cursor image, for the scanout writers (cursor.c); NULL on
 * a boot with no server. Never written through: the view is read-only. */
const volatile struct prsk_cursor_image *prsk_client_cursor_image(void)
{
    if (!connected) return NULL;
    return cursor_image;
}

static HANDLE done_event( unsigned int index )
{
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING name;
    WCHAR buffer[64];
    char narrow[64];
    int i, len;

    if (done_events[index]) return done_events[index];
    len = snprintf( narrow, sizeof(narrow), "\\BaseNamedObjects\\__prsk_srv_done_%u", index );
    for (i = 0; i < len; i++) buffer[i] = (unsigned char)narrow[i];
    buffer[len] = 0;
    init_unicode( &name, buffer );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    if (NtOpenEvent( &done_events[index], SYNCHRONIZE | EVENT_MODIFY_STATE, &attr )) return NULL;
    return done_events[index];
}

static unsigned int slot_call( unsigned int index, enum prsk_slot_op op,
                               struct __server_request_info *info );

/* Claim a slot for this thread and introduce the thread to the server. The
 * claim is an interlocked FREE -> IDLE so two starting threads cannot take
 * the same one; the ATTACH that follows is what makes the server mint the
 * thread's records, so the caller's slot index is only remembered once both
 * have succeeded. Returns index + 1, or 0. */
static unsigned int claim_slot(void)
{
    unsigned int *slot = prsk_thread_slot();
    unsigned int i, attempt;

    if (!slot) return 0;
    if (*slot) return *slot;

    /* A full ring is usually not full: threads that died without a DETACH
     * (every WOW64 thread does -- see gc_request in transport.h) still hold
     * their slots. Ask the server to sweep the dead and retry; the loud
     * refusal below is only for a ring 64 LIVE threads hold. */
    for (attempt = 0; attempt < 20; attempt++)
    {
        for (i = 0; i < PRSK_SLOT_COUNT; i++)
        {
            LONG expected = PRSK_SLOT_FREE;
            if (!__atomic_compare_exchange_n( &ring->slots[i].state, &expected, PRSK_SLOT_IDLE,
                                              FALSE, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE ))
                continue;
            ring->slots[i].pid = HandleToULong( NtCurrentTeb()->ClientId.UniqueProcess );
            ring->slots[i].tid = HandleToULong( NtCurrentTeb()->ClientId.UniqueThread );
            if (done_event( i ) && !slot_call( i, PRSK_OP_ATTACH, NULL ))
            {
                *slot = i + 1;
                return *slot;
            }
            ring->slots[i].pid = 0;
            ring->slots[i].tid = 0;
            __atomic_store_n( &ring->slots[i].state, PRSK_SLOT_FREE, __ATOMIC_RELEASE );
            return 0;
        }
        {
            LARGE_INTEGER delay;
            __atomic_store_n( &ring->gc_request, 1, __ATOMIC_RELEASE );
            NtSetEvent( doorbell, NULL );
            delay.QuadPart = -500000ll; /* 50 ms for the server's sweep */
            NtDelayExecution( FALSE, &delay );
        }
    }
    /* Art. 12: say which limit was hit, do not silently share a slot. */
    prsk_log( "[KTEST] wineserver-lite: all %d transport slots are claimed\n", PRSK_SLOT_COUNT );
    return 0;
}

/* One round trip on a claimed slot. */
static unsigned int slot_call( unsigned int index, enum prsk_slot_op op,
                               struct __server_request_info *info )
{
    struct prsk_slot *slot = &ring->slots[index];
    data_size_t pos = 0;
    unsigned int i, status;

    if (info)
    {
        if (info->u.req.request_header.request_size > PRSK_SLOT_DATA)
        {
            prsk_log( "[KTEST] wineserver-lite: %s request data %u exceeds the slot\n",
                      prsk_req_names[info->u.req.request_header.req],
                      (unsigned)info->u.req.request_header.request_size );
            return STATUS_BUFFER_OVERFLOW;
        }
        slot->req = info->u.req;
        slot->data_size = info->u.req.request_header.request_size;
        slot->reply_max = info->u.req.request_header.reply_size;
        for (i = 0; i < info->data_count; i++)
        {
            memcpy( slot->data + pos, info->data[i].ptr, info->data[i].size );
            pos += info->data[i].size;
        }
    }
    else
    {
        slot->data_size = 0;
        slot->reply_max = 0;
    }
    slot->op = op;
    slot->status = STATUS_PENDING;

    __atomic_store_n( &slot->state, PRSK_SLOT_REQUEST, __ATOMIC_RELEASE );
    NtSetEvent( doorbell, NULL );

    /* Not alertable: the server always answers, refusals included, and an
     * APC interrupting the wait would leave the slot half-consumed. */
    if (NtWaitForSingleObject( done_events[index], FALSE, NULL )) return STATUS_UNSUCCESSFUL;

    /* The reply comes back WHETHER OR NOT the request failed: wineserver
     * writes the full reply plus its data unconditionally (server/request.c
     * send_reply) and the client copies both before it even looks at the
     * error (dlls/ntdll/unix/server.c wait_reply), because callers read
     * reply fields beside an error -- win32u's NtUserCreateDesktopEx takes
     * reply->handle from a create_desktop that failed, which is how the
     * FIRST process to connect gets its desktop at all. Dropping the reply
     * on error here is what stalled GUI-3 while the transport was new. */
    status = slot->status;
    if (info)
    {
        info->u.reply = slot->reply;
        if (slot->reply_size && info->reply_data)
            memcpy( info->reply_data, slot->data, slot->reply_size );
    }
    __atomic_store_n( &slot->state, PRSK_SLOT_IDLE, __ATOMIC_RELEASE );
    return status;
}

/* Attach to the server once, for the whole process. */
static int transport_init(void)
{
    /* Asked BEFORE wait_for_server, and this is the whole reason the flag has
     * to reach the client rather than only smss: waiting is 400 x 50 ms, so a
     * CUI boot that merely failed to start a server would stall EVERY
     * win32u-linking process for twenty seconds before failing anyway. A boot
     * that says Gui=0 is not missing its server, it has none. */
    if (!prsk_qemu_boot_flag( L"Gui", 1 ))
    {
        /* No [KTEST]: that prefix is for machine verdicts (docs/15), and this
         * is a statement about the arrangement, printed once per process. */
        prsk_log( "wineserver-lite: CUI-only boot; no desktop, window calls will fail\n" );
        return 0;
    }
    if (!wait_for_server() || !open_transport())
    {
        prsk_log( "[KTEST] gui3 server ABSENT FAIL\n" );
        return 0;
    }
    connected = 1;
    return 1;
}

static int ensure_connected(void)
{
    static LONG state; /* 0 untouched, 1 building, 2 done */
    LONG expected = 0;

    if (__atomic_compare_exchange_n( &state, &expected, 1, FALSE, __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE ))
    {
        transport_init();
        __atomic_store_n( &state, 2, __ATOMIC_RELEASE );
    }
    while (__atomic_load_n( &state, __ATOMIC_ACQUIRE ) == 1) YieldProcessor();
    return connected;
}

/* Called from win32u's DLL_PROCESS_ATTACH, before win32u's own init: the
 * state machine must be reachable before shared_session_init opens the
 * session mapping by name, so the wait for the server process to publish it
 * happens here rather than on the first request. */
int prsk_transport_startup(void)
{
    return ensure_connected();
}

unsigned int CDECL wine_server_call( void *req_ptr )
{
    struct __server_request_info * const info = req_ptr;
    unsigned int index;

    if (!ensure_connected()) return STATUS_UNSUCCESSFUL;

    if (!(index = claim_slot())) return STATUS_INSUFFICIENT_RESOURCES;
    return slot_call( index - 1, PRSK_OP_CALL, info );
}

/* Hand the server a decoded cursor image (cursor.c winefb_set_cursor):
 * the one slot op that is not a Wine request. The payload rides the slot
 * data like request varargs; the server answers STATUS_INVALID_HANDLE for
 * a window the pointer has since left (shim.c prsk_cursor_publish), which
 * the caller treats as the ordinary race it is. */
unsigned int prsk_client_publish_cursor( const struct prsk_cursor_publish *publish )
{
    struct __server_request_info info;
    unsigned int index;

    if (!ensure_connected()) return STATUS_UNSUCCESSFUL;
    if (!(index = claim_slot())) return STATUS_INSUFFICIENT_RESOURCES;

    memset( &info, 0, sizeof(info) );
    info.u.req.request_header.request_size = sizeof(*publish);
    info.data_count = 1;
    info.data[0].ptr = publish;
    info.data[0].size = sizeof(*publish);
    return slot_call( index - 1, PRSK_OP_SET_CURSOR, &info );
}

/* A thread is going away while its process lives on: hand the slot back and
 * let the server retire the records now rather than at process death. */
void prsk_client_thread_detach(void)
{
    unsigned int *slot = prsk_thread_slot();
    unsigned int index;

    if (!connected || !slot || !*slot) return;
    index = *slot - 1;
    slot_call( index, PRSK_OP_DETACH, NULL );
    if (done_events[index]) { NtClose( done_events[index] ); done_events[index] = NULL; }
    ring->slots[index].pid = 0;
    ring->slots[index].tid = 0;
    __atomic_store_n( &ring->slots[index].state, PRSK_SLOT_FREE, __ATOMIC_RELEASE );
    *slot = 0;
}
