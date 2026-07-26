/*
 * shim.c - wineserver's GUI object model, running inside the GUI process.
 *
 * GUI-2 keeps desktop state in-process (docs/02, docs/07 route (a)): there is
 * one GUI process, so the window tree, classes, atoms, message queues, hooks
 * and clipboard can be plain data in that process's own heap. What they must
 * NOT be is a second implementation. Wine already has exactly this state
 * machine, debugged over decades, in server/{user,atom,class,winstation,
 * window,queue,region,clipboard,hook}.c, and win32u already talks to it
 * through one function. So those files are compiled unmodified into
 * win32u.dll and this file supplies the environment they expect:
 *
 *   - wine_server_call, which normally marshals a request down a socket,
 *     here binds `current` and calls the handler on the spot;
 *   - one process and one thread record per Win32 thread, standing in for
 *     server/process.c and server/thread.c (which are unix-process
 *     machinery: ptrace, sockets, signals - nothing this build can host);
 *   - the session shared mapping, a real NT section under
 *     \KernelObjects\__wine_session, which win32u then opens read-only by
 *     name exactly as it does under Wine;
 *   - queue wake-ups as real kernel events, so that win32u's existing
 *     NtWaitForMultipleObjects in wait_message blocks and wakes correctly.
 *     This is docs/07's "message queue backed by a kernel event", arriving
 *     one milestone early because it is also the simplest thing that works;
 *   - a timeout service thread for the fd-layer timers the queue uses to
 *     expire WM_TIMER.
 *
 * What is deliberately absent refuses loudly. The dispatch table is
 * generated (tools/gen_server_table.py) from the pinned tree's own request
 * list, so a request whose handler is not linked in gets named on serial and
 * STATUS_NOT_IMPLEMENTED, never an empty success (Art. 12).
 *
 * GUI-3 turns this library back into a process (HACK-003, wineserver-lite);
 * the state machine underneath it does not change, which is the point of
 * reusing it rather than rewriting it (Art. 11: one authority).
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
#include "ddk/wdm.h"

#include "object.h"
#include "file.h"
#include "handle.h"
#include "process.h"
#include "thread.h"
#include "request.h"
#include "security.h"
#include "user.h"
#include "wine/server_protocol.h"
#include "wine/server.h"

#include "prsk_request_table.h"
#include "shim.h"

/* --- serial diagnostics ----------------------------------------------------
 *
 * The kernel's own convention (docs/08): machine-readable prefixes, human
 * text after. NtDisplayString is the transport the kernel's [KTEST] lines
 * use, so a refusal from in here lands in the same log the harness greps. */

void prsk_log( const char *format, ... )
{
    char text[512];
    WCHAR wide[512];
    UNICODE_STRING str;
    va_list args;
    int len, i;

    va_start( args, format );
    len = vsnprintf( text, sizeof(text) - 1, format, args );
    va_end( args );
    if (len < 0) return;
    if (len > (int)sizeof(text) - 1) len = sizeof(text) - 1;

    for (i = 0; i < len; i++) wide[i] = (unsigned char)text[i];
    str.Buffer = wide;
    str.Length = len * sizeof(WCHAR);
    str.MaximumLength = str.Length;
    NtDisplayString( &str );
}

/* --- server globals --------------------------------------------------------
 *
 * In wineserver these live in request.c/main.c, which are the unix event
 * loop. Same declarations, same meanings. */

struct thread *current = NULL;
unsigned int global_error = 0;
int debug_level = 0;
timeout_t server_start_time = 0;

/* current_time and monotonic_time are refreshed by wineserver's poll loop;
 * here every entry point refreshes them, which is the same guarantee: they
 * are correct whenever a handler reads them. */
timeout_t current_time = 0;
timeout_t monotonic_time = 0;

void set_current_time(void)
{
    LARGE_INTEGER now;

    NtQuerySystemTime( &now );
    current_time = now.QuadPart;
    monotonic_time = now.QuadPart - server_start_time;
}

timeout_t monotonic_counter(void)
{
    return monotonic_time;
}

/* --- the one process and its threads ---------------------------------------
 *
 * server/process.c and server/thread.c model unix processes; nothing in them
 * would survive being compiled here, and nothing in them is needed - GUI-2
 * is a single process by definition. What the GUI handlers actually touch is
 * a dozen fields (winstation, desktop, classes, rawinput_*, thread_list, id)
 * plus the object header, so those are set up by hand.
 *
 * The object headers are real: alloc_object from server/object.c, with ops
 * tables that refuse everything the GUI path never asks for. That keeps
 * grab_object/release_object honest instead of special-casing them. */

static void prsk_process_dump( struct object *obj, int verbose ) { }
static void prsk_thread_dump( struct object *obj, int verbose ) { }

static const struct object_ops prsk_process_ops =
{
    sizeof(struct process),    /* size */
    &no_type,                  /* type */
    prsk_process_dump,         /* dump */
    NULL,                      /* add_queue */
    NULL,                      /* remove_queue */
    NULL,                      /* signaled */
    NULL,                      /* satisfied */
    no_signal,                 /* signal */
    no_get_fd,                 /* get_fd */
    default_get_sync,          /* get_sync */
    default_map_access,        /* map_access */
    default_get_sd,            /* get_sd */
    default_set_sd,            /* set_sd */
    no_get_full_name,          /* get_full_name */
    no_lookup_name,            /* lookup_name */
    no_link_name,              /* link_name */
    NULL,                      /* unlink_name */
    no_open_file,              /* open_file */
    no_kernel_obj_list,        /* get_kernel_obj_list */
    no_close_handle,           /* close_handle */
    no_destroy                 /* destroy */
};

static const struct object_ops prsk_thread_ops =
{
    sizeof(struct thread),     /* size */
    &no_type,                  /* type */
    prsk_thread_dump,          /* dump */
    NULL,                      /* add_queue */
    NULL,                      /* remove_queue */
    NULL,                      /* signaled */
    NULL,                      /* satisfied */
    no_signal,                 /* signal */
    no_get_fd,                 /* get_fd */
    default_get_sync,          /* get_sync */
    default_map_access,        /* map_access */
    default_get_sd,            /* get_sd */
    default_set_sd,            /* set_sd */
    no_get_full_name,          /* get_full_name */
    no_lookup_name,            /* lookup_name */
    no_link_name,              /* link_name */
    NULL,                      /* unlink_name */
    no_open_file,              /* open_file */
    no_kernel_obj_list,        /* get_kernel_obj_list */
    no_close_handle,           /* close_handle */
    no_destroy                 /* destroy */
};

static struct process *the_process;
static struct list thread_records = LIST_INIT( thread_records );

struct prsk_thread_record
{
    struct list    entry;
    struct thread *thread;
    DWORD          tid;
};

static struct thread *find_thread_record( DWORD tid )
{
    struct prsk_thread_record *record;

    LIST_FOR_EACH_ENTRY( record, &thread_records, struct prsk_thread_record, entry )
        if (record->tid == tid) return record->thread;
    return NULL;
}

static struct thread *create_thread_record( DWORD tid )
{
    struct prsk_thread_record *record;
    struct thread *thread;

    if (!(thread = alloc_object( &prsk_thread_ops ))) return NULL;
    memset( (char *)thread + sizeof(thread->obj), 0, sizeof(*thread) - sizeof(thread->obj) );
    thread->process = the_process;
    thread->id = tid;
    thread->state = RUNNING;
    thread->desktop_users = 0;
    thread->creation_time = current_time;
    list_init( &thread->mutex_list );
    list_init( &thread->d3dkmt_mutexes );
    list_init( &thread->system_apc );
    list_init( &thread->user_apc );
    list_init( &thread->kernel_object );
    list_add_tail( &the_process->thread_list, &thread->proc_entry );
    list_init( &thread->desktop_entry );

    if (!(record = malloc( sizeof(*record) ))) return NULL;
    record->thread = thread;
    record->tid = tid;
    list_add_tail( &thread_records, &record->entry );
    return thread;
}

/* --- the session shared mapping --------------------------------------------
 *
 * win32u reads desktop, queue, input, class and window state straight out of
 * a read-only view of \KernelObjects\__wine_session; only the writes come
 * through a request. The section is created here, once, at a fixed size:
 * growth (wineserver ftruncates and mmaps more) would move nothing but adds
 * a whole failure mode, and Art. 3 says pick the stupidly correct one. The
 * table alone is ~1 MB; the rest is object storage, and exhausting it says
 * so rather than corrupting a neighbour. */

#define PRSK_SESSION_SIZE (8 * 1024 * 1024)

session_shm_t *srv_shared_session;   /* renamed: win32u has its own reader */

static char *session_base;
static mem_size_t session_used;
static object_id_t session_last_id;

struct session_object
{
    struct list     entry;
    mem_size_t      offset;
    mem_size_t      size;
    shared_object_t obj;
};

static struct list session_free_objects = LIST_INIT( session_free_objects );

static int prsk_create_session_mapping(void)
{
    static const WCHAR nameW[] =
        {'\\','K','e','r','n','e','l','O','b','j','e','c','t','s','\\',
         '_','_','w','i','n','e','_','s','e','s','s','i','o','n',0};
    UNICODE_STRING name = RTL_CONSTANT_STRING( nameW );
    OBJECT_ATTRIBUTES attr;
    LARGE_INTEGER size;
    SIZE_T view_size = 0;
    HANDLE section;
    void *view = NULL;
    NTSTATUS status;

    InitializeObjectAttributes( &attr, &name, OBJ_OPENIF, NULL, NULL );
    size.QuadPart = PRSK_SESSION_SIZE;
    if ((status = NtCreateSection( &section, SECTION_ALL_ACCESS, &attr, &size, PAGE_READWRITE,
                                   SEC_COMMIT, NULL )))
    {
        prsk_log( "[PANIC] wineserver-lite: session section -> %08x\n", (unsigned)status );
        return 0;
    }
    if ((status = NtMapViewOfSection( section, GetCurrentProcess(), &view, 0, 0, NULL, &view_size,
                                      ViewShare, 0, PAGE_READWRITE )))
    {
        prsk_log( "[PANIC] wineserver-lite: session map -> %08x\n", (unsigned)status );
        return 0;
    }
    /* The handle is dropped: the name keeps the section alive for the
     * readers, and this view is the only one the writer needs. */
    NtClose( section );

    session_base = view;
    session_used = sizeof(session_shm_t);
    srv_shared_session = (session_shm_t *)session_base;
    return 1;
}

volatile void *alloc_shared_object( mem_size_t shm_size )
{
    struct session_object *object;
    mem_size_t size = sizeof(*object) - sizeof(object_shm_t) + max( shm_size, sizeof(object_shm_t) );

    LIST_FOR_EACH_ENTRY( object, &session_free_objects, struct session_object, entry )
    {
        if (size <= object->size)
        {
            list_remove( &object->entry );
            goto found;
        }
    }

    size = (size + 15) & ~(mem_size_t)15;
    if (session_used + size > PRSK_SESSION_SIZE)
    {
        prsk_log( "[PANIC] wineserver-lite: session mapping full (%u bytes)\n",
                  (unsigned)PRSK_SESSION_SIZE );
        return NULL;
    }
    object = (struct session_object *)(session_base + session_used);
    object->offset = session_used + ((char *)&object->obj - (char *)object);
    object->size = size;
    session_used += size;

found:
    SHARED_WRITE_BEGIN( &object->obj.shm, object_shm_t )
    {
        CONTAINING_RECORD( shared, shared_object_t, shm )->id = ++session_last_id;
    }
    SHARED_WRITE_END;
    return &object->obj.shm;
}

void free_shared_object( volatile void *object_shm )
{
    struct session_object *object = CONTAINING_RECORD( object_shm, struct session_object, obj.shm );

    SHARED_WRITE_BEGIN( &object->obj.shm, object_shm_t )
    {
        CONTAINING_RECORD( shared, shared_object_t, shm )->id = 0;
    }
    SHARED_WRITE_END;
    list_add_tail( &session_free_objects, &object->entry );
}

void invalidate_shared_object( volatile void *object_shm )
{
    struct session_object *object = CONTAINING_RECORD( object_shm, struct session_object, obj.shm );

    SHARED_WRITE_BEGIN( &object->obj.shm, object_shm_t )
    {
        CONTAINING_RECORD( shared, shared_object_t, shm )->id = ++session_last_id;
    }
    SHARED_WRITE_END;
}

struct obj_locator get_shared_object_locator( volatile void *object_shm )
{
    struct session_object *object = CONTAINING_RECORD( object_shm, struct session_object, obj.shm );
    struct obj_locator locator = { .offset = object->offset, .id = object->obj.id };
    return locator;
}

/* --- sync objects as kernel events -----------------------------------------
 *
 * A message queue's signalled state is a `struct object *sync` the server
 * creates with create_internal_sync and drives with signal_sync/reset_sync.
 * Backing that object with a real NT event is the whole trick that makes
 * blocking work: win32u's wait_message already waits on the queue handle
 * with NtWaitForMultipleObjects, so once the handle IS the event, the
 * unmodified message loop blocks and wakes with no further help. */

struct prsk_sync
{
    struct object obj;
    HANDLE        event;
    int           manual;
};

static void prsk_sync_dump( struct object *obj, int verbose ) { }

static void prsk_sync_destroy( struct object *obj )
{
    struct prsk_sync *sync = (struct prsk_sync *)obj;
    if (sync->event) NtClose( sync->event );
}

static int prsk_sync_signal( struct object *obj, unsigned int access, int signal )
{
    struct prsk_sync *sync = (struct prsk_sync *)obj;

    if (signal) NtSetEvent( sync->event, NULL );
    else NtResetEvent( sync->event, NULL );
    return 1;
}

static const struct object_ops prsk_sync_ops =
{
    sizeof(struct prsk_sync),  /* size */
    &no_type,                  /* type */
    prsk_sync_dump,            /* dump */
    NULL,                      /* add_queue */
    NULL,                      /* remove_queue */
    NULL,                      /* signaled */
    NULL,                      /* satisfied */
    prsk_sync_signal,          /* signal */
    no_get_fd,                 /* get_fd */
    default_get_sync,          /* get_sync */
    default_map_access,        /* map_access */
    default_get_sd,            /* get_sd */
    default_set_sd,            /* set_sd */
    no_get_full_name,          /* get_full_name */
    no_lookup_name,            /* lookup_name */
    no_link_name,              /* link_name */
    NULL,                      /* unlink_name */
    no_open_file,              /* open_file */
    no_kernel_obj_list,        /* get_kernel_obj_list */
    no_close_handle,           /* close_handle */
    prsk_sync_destroy          /* destroy */
};

struct object *create_internal_sync( int manual, int signaled )
{
    struct prsk_sync *sync;

    if (!(sync = alloc_object( &prsk_sync_ops ))) return NULL;
    sync->manual = manual;
    sync->event = NULL;
    if (NtCreateEvent( &sync->event, EVENT_ALL_ACCESS, NULL,
                       manual ? NotificationEvent : SynchronizationEvent, signaled ))
    {
        release_object( sync );
        return NULL;
    }
    return &sync->obj;
}

void signal_sync( struct object *obj )
{
    obj->ops->signal( obj, 0, 1 );
}

void reset_sync( struct object *obj )
{
    obj->ops->signal( obj, 0, 0 );
}

/* The kernel handle behind a sync object, duplicated for the caller. Used to
 * answer get_msg_queue_handle with something NtWaitForMultipleObjects
 * understands (see the dispatch fix-ups below). */
static HANDLE dup_sync_handle( struct object *obj )
{
    struct prsk_sync *sync = (struct prsk_sync *)obj;
    HANDLE dup = NULL;

    if (!obj || obj->ops != &prsk_sync_ops) return NULL;
    NtDuplicateObject( GetCurrentProcess(), sync->event, GetCurrentProcess(), &dup,
                       SYNCHRONIZE | EVENT_MODIFY_STATE, 0, 0 );
    return dup;
}

/* --- timeouts --------------------------------------------------------------
 *
 * server/fd.c owns wineserver's timer wheel; the queue uses it to expire
 * WM_TIMER. Reimplemented here as a sorted list plus one service thread,
 * because fd.c is the poll loop and cannot come along. The service thread is
 * the only other thread that enters the server, and it does so under the
 * same lock as everyone else. */

struct timeout_user
{
    struct list          entry;
    timeout_t            when;
    timeout_callback     callback;
    void                *private;
};

static struct list timeout_list = LIST_INIT( timeout_list );
static HANDLE timeout_wakeup;        /* the service thread's reconfigure event */
static HANDLE server_mutex;          /* one lock for the whole state machine */

struct timeout_user *add_timeout_user( timeout_t when, timeout_callback func, void *private )
{
    struct timeout_user *user, *pos;

    if (!(user = malloc( sizeof(*user) ))) return NULL;
    user->when = (when > 0) ? when : current_time - when;
    user->callback = func;
    user->private = private;

    LIST_FOR_EACH_ENTRY( pos, &timeout_list, struct timeout_user, entry )
        if (pos->when >= user->when) break;
    list_add_before( &pos->entry, &user->entry );

    NtSetEvent( timeout_wakeup, NULL );
    return user;
}

void remove_timeout_user( struct timeout_user *user )
{
    list_remove( &user->entry );
    free( user );
}

static void server_lock(void)
{
    NtWaitForSingleObject( server_mutex, FALSE, NULL );
    set_current_time();
}

static void server_unlock(void)
{
    NtReleaseMutant( server_mutex, NULL );
}

static DWORD WINAPI timeout_thread( void *arg )
{
    for (;;)
    {
        LARGE_INTEGER timeout, *timeout_ptr = NULL;
        timeout_t next = 0;

        server_lock();
        for (;;)
        {
            struct timeout_user *user;

            if (list_empty( &timeout_list )) break;
            user = LIST_ENTRY( list_head( &timeout_list ), struct timeout_user, entry );
            if (user->when > current_time)
            {
                next = user->when;
                break;
            }
            list_remove( &user->entry );
            user->callback( user->private );
            free( user );
            set_current_time();
        }
        current = NULL;
        server_unlock();

        if (next)
        {
            /* Absolute NT time, the same base NtQuerySystemTime returns. */
            timeout.QuadPart = next;
            timeout_ptr = &timeout;
        }
        NtWaitForSingleObject( timeout_wakeup, FALSE, timeout_ptr );
    }
    return 0;
}

/* --- bring-up --------------------------------------------------------------
 *
 * Everything reaches the state machine through wine_server_call, so the
 * first call is a sufficient and race-free place to build it. */

static LONG init_state;   /* 0 untouched, 1 building, 2 ready, 3 failed */

static int prsk_create_winstation_dir(void);

static int server_bringup(void)
{
    LARGE_INTEGER now;
    HANDLE thread;
    OBJECT_ATTRIBUTES attr;

    NtQuerySystemTime( &now );
    server_start_time = now.QuadPart;
    set_current_time();

    InitializeObjectAttributes( &attr, NULL, 0, NULL, NULL );
    if (NtCreateMutant( &server_mutex, MUTANT_ALL_ACCESS, &attr, FALSE )) return 0;
    if (NtCreateEvent( &timeout_wakeup, EVENT_ALL_ACCESS, &attr, SynchronizationEvent, FALSE ))
        return 0;
    if (!prsk_create_session_mapping()) return 0;
    if (!prsk_create_winstation_dir()) return 0;

    if (!(the_process = alloc_object( &prsk_process_ops ))) return 0;
    memset( (char *)the_process + sizeof(the_process->obj), 0,
            sizeof(*the_process) - sizeof(the_process->obj) );
    the_process->id = HandleToULong( NtCurrentTeb()->ClientId.UniqueProcess );
    the_process->parent_id = 0;
    the_process->machine = IMAGE_FILE_MACHINE_AMD64;
    the_process->running_threads = 1;
    list_init( &the_process->thread_list );
    list_init( &the_process->classes );
    list_init( &the_process->rawinput_entry );
    list_init( &the_process->kernel_object );
    if (!alloc_handle_table( the_process, 0 )) return 0;

    if (NtCreateThreadEx( &thread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(),
                          timeout_thread, NULL, 0, 0, 0, 0, NULL ))
        return 0;
    NtClose( thread );
    return 1;
}

int prsk_server_init(void)
{
    LONG expected = 0;

    if (__atomic_compare_exchange_n( &init_state, &expected, 1, FALSE, __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE ))
    {
        __atomic_store_n( &init_state, server_bringup() ? 2 : 3, __ATOMIC_RELEASE );
    }
    while (__atomic_load_n( &init_state, __ATOMIC_ACQUIRE ) == 1) YieldProcessor();
    return __atomic_load_n( &init_state, __ATOMIC_ACQUIRE ) == 2;
}

/* --- the call ---------------------------------------------------------------
 *
 * The client half of this is unchanged Wine: win32u fills a
 * struct __server_request_info and calls wine_server_call. Here that means
 * copying the varargs into current->req_data, running the handler, and
 * copying the reply back - the same three steps read_request/send_reply do
 * across the socket, minus the socket. */

static unsigned int dispatch_request( struct __server_request_info *info, struct thread *thread )
{
    enum request req = info->u.req.request_header.req;
    union generic_reply reply;
    data_size_t pos = 0;
    unsigned int i;

    thread->req = info->u.req;
    thread->req_data = NULL;
    thread->reply_data = NULL;
    thread->reply_size = 0;

    if (info->u.req.request_header.request_size)
    {
        if (!(thread->req_data = malloc( info->u.req.request_header.request_size )))
            return STATUS_NO_MEMORY;
        for (i = 0; i < info->data_count; i++)
        {
            memcpy( (char *)thread->req_data + pos, info->data[i].ptr, info->data[i].size );
            pos += info->data[i].size;
        }
    }

    current = thread;
    current->error = 0;
    memset( &reply, 0, sizeof(reply) );

    if (req >= prsk_req_count || !prsk_req_handlers[req])
    {
        /* Unbuilt, not unsupported: the handler exists in wineserver, it is
         * simply not linked into this build. Naming it is how the next
         * milestone finds out what it needs (Art. 12). */
        prsk_log( "[KTEST] wineserver-lite: unbuilt request %s\n",
                  req < prsk_req_count ? prsk_req_names[req] : "<out of range>" );
        set_error( STATUS_NOT_IMPLEMENTED );
    }
    else prsk_req_handlers[req]( &current->req, &reply );

    reply.reply_header.error = current->error;
    reply.reply_header.reply_size = current->reply_size;
    info->u.reply = reply;
    if (current->reply_size && info->reply_data)
        memcpy( info->reply_data, current->reply_data, current->reply_size );

    free( current->req_data );
    free( current->reply_data );
    current->req_data = NULL;
    current->reply_data = NULL;
    current->reply_size = 0;
    current = NULL;
    return reply.reply_header.error;
}

/* Two replies name something only this build can answer.
 *
 * get_msg_queue_handle hands out a server handle to the queue, which the
 * client then waits on. On Wine that handle reaches the wineserver socket;
 * here the wait is a real NtWaitForMultipleObjects, so the handle has to be
 * the queue's kernel event.
 *
 * get_desktop_window without `force` returns nothing until some other
 * process has created the desktop, and win32u answers that by launching
 * explorer.exe. There is exactly one GUI process here and explorer is GUI-6,
 * so the desktop is created on the spot - the same code path the server
 * takes for the forcing caller. */
static void fixup_request( struct __server_request_info *info, enum request req )
{
    if (!strcmp( prsk_req_names[req], "get_msg_queue_handle" ))
    {
        /* current->queue is a struct object at offset 0; its get_sync op is
         * the queue's own accessor, so the sync object comes out of Wine's
         * code rather than out of a guess about the struct's layout (which
         * is private to queue.c). */
        struct object *queue = (struct object *)current->queue, *sync;
        HANDLE event = NULL;

        if (queue && (sync = get_obj_sync( queue )))
        {
            event = dup_sync_handle( sync );
            release_object( sync );
        }
        info->u.reply.get_msg_queue_handle_reply.handle = wine_server_obj_handle( event );
    }
}

unsigned int CDECL wine_server_call( void *req_ptr )
{
    struct __server_request_info * const info = req_ptr;
    enum request req = info->u.req.request_header.req;
    struct thread *thread;
    unsigned int ret;
    DWORD tid;

    if (!prsk_server_init()) return STATUS_UNSUCCESSFUL;

    tid = HandleToULong( NtCurrentTeb()->ClientId.UniqueThread );
    server_lock();
    if (!(thread = find_thread_record( tid )) && !(thread = create_thread_record( tid )))
    {
        server_unlock();
        return STATUS_NO_MEMORY;
    }
    ret = dispatch_request( info, thread );
    if (!ret && req < prsk_req_count) fixup_request( info, req );
    server_unlock();
    return ret;
}

/* --- what wineserver's unix half would have provided -------------------------
 *
 * Everything below is a boundary this build does not cross: file
 * descriptors, unix credentials, the process/thread lifecycle. Each refuses
 * in the shape its callers already handle - and says so once, by name, so
 * that a GUI path quietly depending on one is visible rather than silently
 * degraded. */

void wine_server_send_fd( int fd )
{
    prsk_log( "[KTEST] wineserver-lite: wine_server_send_fd is unbuilt\n" );
}

NTSTATUS CDECL wine_server_fd_to_handle( int fd, unsigned int access, unsigned int attributes,
                                         HANDLE *handle )
{
    prsk_log( "[KTEST] wineserver-lite: wine_server_fd_to_handle is unbuilt\n" );
    *handle = NULL;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS CDECL wine_server_handle_to_fd( HANDLE handle, unsigned int access, int *unix_fd,
                                         unsigned int *options )
{
    prsk_log( "[KTEST] wineserver-lite: wine_server_handle_to_fd is unbuilt\n" );
    return STATUS_NOT_IMPLEMENTED;
}

/* --- a namespace root for window stations -----------------------------------
 *
 * NtUserCreateWindowStation names "WinSta0" RELATIVE to
 * \Sessions\<n>\Windows\WindowStations, so the server needs a directory to
 * hang it under. server/directory.c cannot come along - its init_directories
 * builds the whole NT namespace, devices and sessions included - so the
 * directory OBJECT is built here, out of object.c's own namespace engine
 * (create_namespace/find_object/namespace_add). The lookup and link
 * behaviour is object.c's; only the type is local.
 *
 * There is exactly one such directory, because there is exactly one process
 * and one session (GUI-2 is the single-process milestone). get_directory_obj
 * therefore answers with it for any live directory handle rather than
 * resolving the handle in a table it does not own: win32u's handle comes
 * from the KERNEL namespace (NtOpenDirectoryObject on
 * \Sessions\1\Windows\WindowStations), which this server has no view of.
 * The handle is still probed, so a bogus one fails. Recorded in docs/03 as a
 * GUI-2 single-process deviation; GUI-3 gets a real namespace with the
 * server. */

struct prsk_directory
{
    struct object     obj;
    struct namespace *entries;
};

static void prsk_directory_dump( struct object *obj, int verbose ) { }

static struct object *prsk_directory_lookup_name( struct object *obj, struct unicode_str *name,
                                                  unsigned int attr, struct object *root )
{
    struct prsk_directory *dir = (struct prsk_directory *)obj;
    struct object *found;
    struct unicode_str tmp;

    if (!name) return NULL;   /* open the directory itself */

    tmp.str = name->str;
    tmp.len = name->len;
    if (!(found = find_object( dir->entries, &tmp, attr ))) return NULL;
    name->str = NULL;
    name->len = 0;
    return found;
}

static const struct object_ops prsk_directory_ops =
{
    sizeof(struct prsk_directory), /* size */
    &no_type,                      /* type */
    prsk_directory_dump,           /* dump */
    no_add_queue,                  /* add_queue */
    NULL,                          /* remove_queue */
    NULL,                          /* signaled */
    NULL,                          /* satisfied */
    no_signal,                     /* signal */
    no_get_fd,                     /* get_fd */
    default_get_sync,              /* get_sync */
    default_map_access,            /* map_access */
    default_get_sd,                /* get_sd */
    default_set_sd,                /* set_sd */
    default_get_full_name,         /* get_full_name */
    prsk_directory_lookup_name,    /* lookup_name */
    directory_link_name,           /* link_name */
    default_unlink_name,           /* unlink_name */
    no_open_file,                  /* open_file */
    no_kernel_obj_list,            /* get_kernel_obj_list */
    no_close_handle,               /* close_handle */
    no_destroy                     /* destroy */
};

static struct prsk_directory *winstation_dir;

int directory_link_name( struct object *obj, struct object_name *name, struct object *parent )
{
    struct prsk_directory *dir = (struct prsk_directory *)parent;

    if (parent->ops != &prsk_directory_ops)
    {
        set_error( STATUS_OBJECT_TYPE_MISMATCH );
        return 0;
    }
    namespace_add( dir->entries, name );
    name->parent = grab_object( parent );
    return 1;
}

struct object *get_root_directory(void)
{
    return grab_object( winstation_dir );
}

struct object *get_directory_obj( struct process *process, obj_handle_t handle )
{
    static int reported;
    OBJECT_BASIC_INFORMATION info;

    if (NtQueryObject( wine_server_ptr_handle( handle ), ObjectBasicInformation, &info,
                       sizeof(info), NULL ))
    {
        set_error( STATUS_INVALID_HANDLE );
        return NULL;
    }
    if (!reported++)
        prsk_log( "[KTEST] wineserver-lite: window stations live in the one session directory\n" );
    return grab_object( winstation_dir );
}

static int prsk_create_winstation_dir(void)
{
    if (!(winstation_dir = alloc_object( &prsk_directory_ops ))) return 0;
    winstation_dir->obj.name = NULL;
    if (!(winstation_dir->entries = create_namespace( 7 ))) return 0;
    return 1;
}

/* --- security --------------------------------------------------------------
 *
 * proskrnl's Se department already decides access at the kernel boundary
 * (docs/02 M8); a second, in-process check over descriptors nobody sets
 * would be a parallel authority (Art. 11) and would answer differently.
 * The GUI objects here are reachable only from this process, so the checks
 * pass and the token queries answer "no token" - the same shape a server
 * with no impersonation returns. */

int check_object_access( struct token *token, struct object *obj, unsigned int *access )
{
    return 1;
}

int sd_is_valid( const struct security_descriptor *sd, data_size_t size )
{
    return size >= sizeof(*sd);
}

struct token *thread_get_impersonation_token( struct thread *thread ) { return NULL; }
const struct sid *token_get_owner( struct token *token ) { return NULL; }
const struct sid *token_get_primary_group( struct token *token ) { return NULL; }
const struct acl *token_get_default_dacl( struct token *token ) { return NULL; }

const struct security_descriptor *extract_security_labels( const struct security_descriptor *sd,
                                                           data_size_t *size )
{
    return sd;
}

const struct security_descriptor *replace_security_labels( const struct security_descriptor *old,
                                                           const struct security_descriptor *sd,
                                                           data_size_t *size )
{
    return sd;
}

/* --- the request plumbing request.c would have provided ---------------------
 *
 * Two helpers live in wineserver's socket loop rather than in an object
 * file, so they come across with it. Both are byte-for-byte the same
 * contract: set_reply_data_size hands out the reply buffer,
 * get_req_object_attributes validates the attribute blob a create request
 * carries. */

void *set_reply_data_size( data_size_t size )
{
    assert( size <= get_reply_max_size() );
    if (size && !(current->reply_data = mem_alloc( size ))) size = 0;
    current->reply_size = size;
    return current->reply_data;
}

static const struct object_attributes empty_attributes;

const struct object_attributes *get_req_object_attributes( const struct security_descriptor **sd,
                                                           struct unicode_str *name,
                                                           struct object **root )
{
    const struct object_attributes *attr = get_req_data();
    data_size_t size = get_req_data_size();

    if (root) *root = NULL;

    if (!size)
    {
        *sd = NULL;
        name->len = 0;
        return &empty_attributes;
    }
    if ((size < sizeof(*attr)) || (size - sizeof(*attr) < attr->sd_len) ||
        (size - sizeof(*attr) - attr->sd_len < attr->name_len))
    {
        set_error( STATUS_ACCESS_VIOLATION );
        return NULL;
    }
    if ((attr->name_len & (sizeof(WCHAR) - 1)) || attr->name_len >= 65534)
    {
        set_error( STATUS_OBJECT_NAME_INVALID );
        return NULL;
    }
    if (root && attr->rootdir && attr->name_len)
    {
        if (!(*root = get_directory_obj( current->process, attr->rootdir )))
            return NULL;
    }
    *sd = attr->sd_len ? (const struct security_descriptor *)(attr + 1) : NULL;
    name->str = (const WCHAR *)((const char *)(attr + 1) + attr->sd_len);
    name->len = (attr->name_len / sizeof(WCHAR)) * sizeof(WCHAR);
    return attr;
}

/* --- the boundaries this build does not cross -------------------------------
 *
 * Descriptors, unix processes, kernel-object back-references: each is a
 * wineserver subsystem that is not compiled here. They are referenced from
 * ops tables and error paths the GUI never takes, so each says its own name
 * once and refuses (Art. 12) rather than returning something a caller could
 * mistake for a result. */

#define PRSK_UNBUILT(what) \
    do { \
        static int said; \
        if (!said++) prsk_log( "[KTEST] wineserver-lite: %s is unbuilt\n", (what) ); \
    } while (0)

void fatal_error( const char *err, ... )
{
    prsk_log( "[PANIC] wineserver-lite: fatal_error\n" );
    NtTerminateProcess( GetCurrentProcess(), STATUS_UNSUCCESSFUL );
}

void file_set_error(void)
{
    PRSK_UNBUILT( "the fd layer" );
    set_error( STATUS_NOT_IMPLEMENTED );
}

struct fd *create_anonymous_fd( const struct fd_ops *ops, int unix_fd, struct object *user,
                                unsigned int options )
{
    PRSK_UNBUILT( "create_anonymous_fd" );
    return NULL;
}

struct fd *open_fd( struct fd *root, const char *name, struct unicode_str nt_name, int flags,
                    mode_t *mode, unsigned int access, unsigned int sharing, unsigned int options )
{
    PRSK_UNBUILT( "open_fd" );
    return NULL;
}

void set_fd_events( struct fd *fd, int events ) { PRSK_UNBUILT( "set_fd_events" ); }
void *get_fd_user( struct fd *fd ) { PRSK_UNBUILT( "get_fd_user" ); return NULL; }
int get_unix_fd( struct fd *fd ) { PRSK_UNBUILT( "get_unix_fd" ); return -1; }

struct file *get_file_obj( struct process *process, obj_handle_t handle, unsigned int access )
{
    PRSK_UNBUILT( "file objects" );
    set_error( STATUS_OBJECT_TYPE_MISMATCH );
    return NULL;
}

int get_file_unix_fd( struct file *file ) { PRSK_UNBUILT( "get_file_unix_fd" ); return -1; }

struct list *no_kernel_obj_list( struct object *obj ) { return NULL; }
void free_kernel_objects( struct object *obj ) { }

struct process *get_process_from_handle( obj_handle_t handle, unsigned int access )
{
    /* One process: any handle a GUI request carries names it. */
    return (struct process *)grab_object( the_process );
}

struct process *get_process_from_id( process_id_t id )
{
    if (id && id != the_process->id) { set_error( STATUS_INVALID_PARAMETER ); return NULL; }
    return (struct process *)grab_object( the_process );
}

struct thread *get_thread_from_id( thread_id_t id )
{
    struct thread *thread = find_thread_record( id );

    if (!thread) { set_error( STATUS_INVALID_PARAMETER ); return NULL; }
    return (struct thread *)grab_object( thread );
}

void enum_processes( int (*cb)(struct process *, void *), void *user )
{
    cb( the_process, user );
}

const char *server_argv0 = "win32u.dll";
