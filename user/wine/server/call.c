/*
 * call.c - wine_server_call: the client half, in both of its modes.
 *
 * This file is linked into win32u.dll ONLY. wineserver-lite.exe compiles
 * shim.c (the state machine's environment) but never this, which is what
 * keeps the server from carrying a client of itself.
 *
 * win32u fills a struct __server_request_info and calls wine_server_call.
 * Under real Wine that marshals down a unix socket. Here it does one of two
 * things, decided once at start-up:
 *
 *   in-process   call prsk_server_dispatch on the spot -- GUI-2's
 *                arrangement, still what the gui2 image runs;
 *   client       publish the request into a shared-section slot, ring the
 *                doorbell, wait for the reply (GUI-3, HACK-003).
 *
 * The MODE IS PROBED, not configured: if the server image is on the boot
 * volume a server is expected, and failing to reach it is fatal rather than
 * a fall back to in-process. Falling back would be the worst outcome
 * available -- a second process would quietly become a second writer of the
 * session mapping and a second owner of the window tree, and the damage
 * would surface as corrupted windows much later (Art. 12: refuse loudly).
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

#include "prsk_request_table.h"
#include "transport.h"
#include "shim.h"

/* glue.c keeps the per-thread block in TEB->Win32ThreadInfo; the claimed
 * slot rides there so a call costs no lookup. 0 means unclaimed, so the
 * zeroed block starts out right. */
extern unsigned int *prsk_thread_slot(void);

enum prsk_mode
{
    PRSK_MODE_UNSET = 0,
    PRSK_MODE_INPROC,
    PRSK_MODE_CLIENT,
    PRSK_MODE_FAILED
};

static LONG mode = PRSK_MODE_UNSET;
static struct prsk_ring *ring;
static HANDLE ring_section, doorbell, done_events[PRSK_SLOT_COUNT];

static void init_unicode( UNICODE_STRING *str, const WCHAR *name )
{
    str->Buffer = (WCHAR *)name;
    str->Length = (USHORT)(wcslen( name ) * sizeof(WCHAR));
    str->MaximumLength = str->Length;
}

/* Is a server expected at all? The gui2 image has no such file and stays
 * in-process; the gui3 image has one. */
static int server_image_present(void)
{
    OBJECT_ATTRIBUTES attr;
    FILE_NETWORK_OPEN_INFORMATION info;
    UNICODE_STRING name;

    init_unicode( &name, PRSK_SRV_IMAGE );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    return !NtQueryFullAttributesFile( &attr, &info );
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
    return 1;
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
    unsigned int i;

    if (!slot) return 0;
    if (*slot) return *slot;

    for (i = 0; i < PRSK_SLOT_COUNT; i++)
    {
        LONG expected = PRSK_SLOT_FREE;
        if (!__atomic_compare_exchange_n( &ring->slots[i].state, &expected, PRSK_SLOT_IDLE, FALSE,
                                          __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE ))
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

    status = slot->status;
    if (info && !status)
    {
        info->u.reply = slot->reply;
        if (slot->reply_size && info->reply_data)
            memcpy( info->reply_data, slot->data, slot->reply_size );
    }
    __atomic_store_n( &slot->state, PRSK_SLOT_IDLE, __ATOMIC_RELEASE );
    return status;
}

/* Decide the mode once, for the whole process. */
static int transport_init(void)
{
    if (!server_image_present())
    {
        mode = PRSK_MODE_INPROC;
        return prsk_server_init();
    }
    if (!wait_for_server() || !open_transport())
    {
        prsk_log( "[KTEST] gui3 server ABSENT FAIL\n" );
        mode = PRSK_MODE_FAILED;
        return 0;
    }
    mode = PRSK_MODE_CLIENT;
    return 1;
}

static int ensure_mode(void)
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
    return mode == PRSK_MODE_INPROC || mode == PRSK_MODE_CLIENT;
}

/* Called from win32u's DLL_PROCESS_ATTACH, before win32u's own init: the
 * state machine must be reachable before shared_session_init opens the
 * session mapping by name. Decides the mode and, in-process, brings the
 * server up. */
int prsk_transport_startup(void)
{
    return ensure_mode();
}

unsigned int CDECL wine_server_call( void *req_ptr )
{
    struct __server_request_info * const info = req_ptr;
    unsigned int index;

    if (!ensure_mode()) return STATUS_UNSUCCESSFUL;

    if (mode == PRSK_MODE_INPROC)
        return prsk_server_dispatch( prsk_local_client(),
                                     HandleToULong( NtCurrentTeb()->ClientId.UniqueThread ),
                                     info );

    if (!(index = claim_slot())) return STATUS_INSUFFICIENT_RESOURCES;
    return slot_call( index - 1, PRSK_OP_CALL, info );
}

/* A thread is going away while its process lives on: hand the slot back and
 * let the server retire the records now rather than at process death. */
void prsk_client_thread_detach(void)
{
    unsigned int *slot = prsk_thread_slot();
    unsigned int index;

    if (mode != PRSK_MODE_CLIENT || !slot || !*slot) return;
    index = *slot - 1;
    slot_call( index, PRSK_OP_DETACH, NULL );
    if (done_events[index]) { NtClose( done_events[index] ); done_events[index] = NULL; }
    ring->slots[index].pid = 0;
    ring->slots[index].tid = 0;
    __atomic_store_n( &ring->slots[index].state, PRSK_SLOT_FREE, __ATOMIC_RELEASE );
    *slot = 0;
}
