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

/* Every request, its payload size and its status on serial. Off by default
 * -- it is the first thing to turn on when a GUI path goes wrong, and it is
 * how every bug in this file so far was found. Requests that FAIL are
 * reported either way, because an error a caller swallows is exactly what
 * is hard to find later (Art. 12). */
int prsk_trace_requests = 0;

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

/* One client == one process that talks to this server. GUI-2 had exactly
 * one and could call it `the_process`; GUI-3 keeps a list, because the
 * lookups below (get_process_from_id, enum_processes, get_thread_from_id)
 * are the ones that answered "the only process there is" and have to answer
 * truthfully once there are two. The in-process build registers itself as
 * the single client at bringup, so this is the same shape either way and
 * there is one code path rather than two (Art. 11).
 *
 * `handle` is the client's NT process handle, held for as long as the
 * client is known: it is what a duplicate INTO the client names, and what
 * the server waits on to learn the client died. The local client's is
 * GetCurrentProcess(), the pseudo handle, which needs no closing. */
struct prsk_client
{
    struct list     entry;
    struct process *process;
    HANDLE          handle;
    DWORD           pid;
    ULONG           session;
    struct object  *idle_sync; /* the process idle event (GUI-5); see
                                * req_get_process_idle_event below */
};

static struct list clients = LIST_INIT( clients );
static struct prsk_client *local_client;
static struct list thread_records = LIST_INIT( thread_records );

struct prsk_thread_record
{
    struct list         entry;
    struct thread      *thread;
    struct prsk_client *client;
    DWORD               tid;
};

static struct prsk_client *find_client( DWORD pid )
{
    struct prsk_client *client;

    LIST_FOR_EACH_ENTRY( client, &clients, struct prsk_client, entry )
        if (client->pid == pid) return client;
    return NULL;
}

static struct prsk_client *find_client_by_process( struct process *process )
{
    struct prsk_client *client;

    LIST_FOR_EACH_ENTRY( client, &clients, struct prsk_client, entry )
        if (client->process == process) return client;
    return NULL;
}

/* Does `handle` name a live directory object in the CLIENT's handle table?
 *
 * The server has no view of another process's table, so the handle is
 * brought over with a cross-process NtDuplicateObject (pinned by
 * sem_ob/dup_cross_process) and queried here, then dropped. For the local
 * client the duplicate is same-process and the code path is identical --
 * one authority for both modes rather than a branch that drifts (Art. 11). */
static int prsk_client_handle_is_directory( struct prsk_client *client, obj_handle_t handle )
{
    HANDLE local = NULL;
    char buffer[128];
    OBJECT_TYPE_INFORMATION *type = (OBJECT_TYPE_INFORMATION *)buffer;
    ULONG len = 0;
    int ok;

    if (!handle) return 0;
    if (NtDuplicateObject( client->handle, wine_server_ptr_handle( handle ), GetCurrentProcess(),
                           &local, 0, 0, DUPLICATE_SAME_ACCESS ))
        return 0;
    ok = !NtQueryObject( local, ObjectTypeInformation, type, sizeof(buffer), &len ) &&
         type->TypeName.Length == sizeof(L"Directory") - sizeof(WCHAR) &&
         !memcmp( type->TypeName.Buffer, L"Directory", type->TypeName.Length );
    NtClose( local );
    return ok;
}

/* The NT session a process runs in. It decides which window-station
 * directory the client's create requests resolve against, so it comes from
 * the kernel rather than from an assumption that there is only one. */
static ULONG prsk_process_session( HANDLE process )
{
    ULONG session = 0;

    /* ProcessSessionInformation is an EXACT-ULONG class -- that is the shape
     * both the oracle (dlls/ntdll/unix/process.c) and the kernel
     * (kernel/ps/query.c, pinned by sem_ps/system_processes) implement, and
     * a larger buffer is refused rather than truncated. */
    if (NtQueryInformationProcess( process, ProcessSessionInformation, &session, sizeof(session),
                                   NULL ))
        return 0;
    return session;
}

/* Is the client a GUI process? wineserver asks the same question of the
 * same fact -- server/process.c creates the idle event at init_process_done
 * only when image_info.subsystem != IMAGE_SUBSYSTEM_WINDOWS_CUI -- but it
 * learns the subsystem from the client's own init_process_done request,
 * which this build's attach does not carry. The kernel kept the main
 * image's SECTION_IMAGE_INFORMATION at process creation and answers
 * ProcessImageInformation from it (kernel/ps/query.c, pinned by
 * sem_ps/process_query), so the fact comes from one authority either way.
 * A failed query reads as CUI: the conservative half (no idle event is
 * wineserver's answer for every console process). */
static int prsk_process_is_gui( HANDLE process )
{
    SECTION_IMAGE_INFORMATION image;

    if (NtQueryInformationProcess( process, ProcessImageInformation, &image, sizeof(image), NULL ))
        return 0;
    return image.SubSystemType != IMAGE_SUBSYSTEM_WINDOWS_CUI;
}

static struct prsk_client *create_client( DWORD pid, HANDLE handle )
{
    struct prsk_client *client;
    struct process *process;

    if (!(process = alloc_object( &prsk_process_ops ))) return NULL;
    memset( (char *)process + sizeof(process->obj), 0, sizeof(*process) - sizeof(process->obj) );
    process->id = pid;
    process->parent_id = 0;
    process->machine = IMAGE_FILE_MACHINE_AMD64;
    process->running_threads = 1;
    list_init( &process->thread_list );
    list_init( &process->classes );
    list_init( &process->rawinput_entry );
    list_init( &process->kernel_object );
    /* alloc_handle_table RETURNS the table; process.c assigns it. */
    if (!(process->handles = alloc_handle_table( process, 0 ))) return NULL;

    if (!(client = malloc( sizeof(*client) ))) return NULL;
    client->process = process;
    client->handle = handle;
    client->pid = pid;
    client->session = prsk_process_session( handle );
    /* The process idle event, for a GUI process only -- wineserver's own
     * rule (server/process.c init_process_done), and NOT "every client here
     * is a GUI process" as this once assumed: a console program that loads
     * user32 is a client too, and user32:msg is exactly that program.
     * Manual-reset, born unsignalled; only CLIENTS ever signal or wait on
     * it, through the handles get_msg_queue_handle and
     * get_process_idle_event duplicate out (win32u's NtSetEvent when its
     * queue idles - message.c). NULL here is not a failure: the handlers
     * answer no-event, which is what makes WaitForInputIdle on a console
     * process fail the way it does on Wine and on Windows. */
    client->idle_sync = prsk_process_is_gui( handle ) ? create_internal_sync( 1, 0 ) : NULL;
    list_add_tail( &clients, &client->entry );
    return client;
}

static struct thread *find_thread_record( DWORD tid )
{
    struct prsk_thread_record *record;

    LIST_FOR_EACH_ENTRY( record, &thread_records, struct prsk_thread_record, entry )
        if (record->tid == tid) return record->thread;
    return NULL;
}

static struct prsk_client *find_thread_client( DWORD tid )
{
    struct prsk_thread_record *record;

    LIST_FOR_EACH_ENTRY( record, &thread_records, struct prsk_thread_record, entry )
        if (record->tid == tid) return record->client;
    return NULL;
}

static struct thread *create_thread_record( struct prsk_client *client, DWORD tid )
{
    struct prsk_thread_record *record;
    struct thread *thread;
    struct desktop *desktop;

    if (!(thread = alloc_object( &prsk_thread_ops ))) return NULL;
    memset( (char *)thread + sizeof(thread->obj), 0, sizeof(*thread) - sizeof(thread->obj) );
    thread->process = client->process;
    thread->id = tid;
    thread->state = RUNNING;
    thread->desktop_users = 0;
    thread->creation_time = current_time;
    list_init( &thread->mutex_list );
    list_init( &thread->d3dkmt_mutexes );
    list_init( &thread->system_apc );
    list_init( &thread->user_apc );
    list_init( &thread->kernel_object );
    list_add_tail( &client->process->thread_list, &thread->proc_entry );
    list_init( &thread->desktop_entry );

    /* A new thread starts on its process's default desktop -- the same block
     * wineserver's create_thread runs (server/thread.c). The FIRST thread of
     * a client still has no desktop (its process has none yet, exactly like
     * the oracle's first process, whose connect_process_winstation finds no
     * parent to inherit from); win32u's winstation_init then creates
     * WinSta0/Default and set_thread_desktop sets the process default, which
     * is what every LATER thread inherits here. */
    if (client->process->desktop)
    {
        if (!(desktop = get_desktop_obj( client->process, client->process->desktop, 0 )))
            clear_error();  /* ignore errors */
        else
        {
            set_thread_default_desktop( thread, desktop, client->process->desktop );
            release_object( desktop );
        }
    }

    if (!(record = malloc( sizeof(*record) ))) return NULL;
    record->thread = thread;
    record->client = client;
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

static HANDLE session_section;
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
        NtClose( section );
        return 0;
    }
    /* The handle is HELD, for the life of the process. A name does not keep
     * an NT section alive -- the object dies with its last handle unless it
     * is permanent -- so closing this would leave win32u's NtOpenSection
     * looking for a section that no longer exists (which it does, quietly,
     * as STATUS_OBJECT_NAME_NOT_FOUND). */
    session_section = section;

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
static HANDLE dup_sync_handle( struct object *obj, HANDLE target_process )
{
    struct prsk_sync *sync = (struct prsk_sync *)obj;
    HANDLE dup = NULL;

    if (!obj || obj->ops != &prsk_sync_ops) return NULL;
    /* The reply carries a handle that must be valid IN THE CLIENT, which is
     * how NT hands a win32k handle out too. In-process that target is our
     * own process and this is the same call it always was. */
    NtDuplicateObject( GetCurrentProcess(), sync->event, target_process, &dup,
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

static DWORD WINAPI timeout_thread( void *arg );

/* Started on the first timer rather than at bring-up: bring-up happens in
 * win32u's DLL attach, under the loader lock, and a new thread would want
 * that lock back for its own DLL_THREAD_ATTACH. The first timer is a
 * SetTimer from application code, long past the loader. */
static void ensure_timeout_thread(void)
{
    static int started;
    HANDLE thread;

    if (started) return;
    started = 1;
    if (NtCreateThreadEx( &thread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), timeout_thread,
                          NULL, 0, 0, 0, 0, NULL ))
    {
        prsk_log( "[KTEST] wineserver-lite: no timeout thread; timers will not fire\n" );
        return;
    }
    NtClose( thread );
}

struct timeout_user *add_timeout_user( timeout_t when, timeout_callback func, void *private )
{
    struct timeout_user *user, *pos;

    ensure_timeout_thread();
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

/* A first-chance report of any access violation, with the faulting address
 * relative to this DLL. The Wine loader catches these and reports only
 * "failed to initialize", which names the DLL but not the instruction; this
 * names the instruction, which is the difference between an afternoon and a
 * minute (Art. 9: the dump is the debugger). Continues the search, so it
 * changes nothing about how the exception is handled. */
static LONG CALLBACK report_exception( EXCEPTION_POINTERS *info )
{
    void *base = NtCurrentTeb()->Peb->ImageBaseAddress;

    if (info->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
        prsk_log( "[KTEST] wineserver-lite: access violation at %p (image %p), rip %p\n",
                  info->ExceptionRecord->ExceptionAddress, base,
                  (void *)info->ContextRecord->Rip );
    return EXCEPTION_CONTINUE_SEARCH;
}

static int server_bringup(void)
{
    LARGE_INTEGER now;
    OBJECT_ATTRIBUTES attr;
    struct object *atoms;

    NtQuerySystemTime( &now );
    server_start_time = now.QuadPart;
    set_current_time();

    RtlAddVectoredExceptionHandler( TRUE, report_exception );

    InitializeObjectAttributes( &attr, NULL, 0, NULL, NULL );
    if (NtCreateMutant( &server_mutex, MUTANT_ALL_ACCESS, &attr, FALSE )) return 0;
    if (NtCreateEvent( &timeout_wakeup, EVENT_ALL_ACCESS, &attr, SynchronizationEvent, FALSE ))
        return 0;
    if (!prsk_create_session_mapping()) return 0;

    /* The process running this library is the first client. In the
     * in-process build it is the only one; when the server is its own
     * process the clients that attach over the transport join the same
     * list through the same constructor. */
    if (!(local_client = create_client( HandleToULong( NtCurrentTeb()->ClientId.UniqueProcess ),
                                        GetCurrentProcess() )))
        return 0;

    /* The two process-wide atom tables wineserver's init_directories makes.
     * RegisterClass and the window-property calls add to the user one, and
     * add_atom dereferences it without checking. */
    if (!(atoms = create_atom_table())) return 0;
    set_global_atom_table( atoms );
    release_object( atoms );
    if (!(atoms = create_atom_table())) return 0;
    set_user_atom_table( atoms );
    release_object( atoms );

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

    if (prsk_trace_requests)
    {
        const unsigned int *body = (const unsigned int *)((const char *)&info->u.req + 12);
        prsk_log( "[TRACE] wineserver-lite: %s data=%u req=%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x\n",
                  req < prsk_req_count ? prsk_req_names[req] : "<out of range>",
                  (unsigned)info->u.req.request_header.request_size, body[0], body[1], body[2],
                  body[3], body[4], body[5], body[6], body[7] );
    }

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

    if (prsk_trace_requests)
    {
        const unsigned int *body = (const unsigned int *)((const char *)&reply + 8);
        prsk_log( "[TRACE] wineserver-lite: %s -> %08x reply=%08x,%08x\n", prsk_req_names[req],
                  current->error, body[0], body[1] );
    }
    else if (current->error && current->error != STATUS_PENDING)
        /* PENDING is not a swallowed failure: it is get_message's ordinary
         * empty-queue reply (server/queue.c), and reporting it printed one
         * line per message-loop iteration.
         *
         * The pid/tid are here because with more than one client "which
         * process asked" is the first question every failure raises, and
         * without it the log says a request failed without saying whose. */
        prsk_log( "[KTEST] wineserver-lite: %s failed %08x (pid=%u tid=%u)\n", prsk_req_names[req],
                  current->error, (unsigned)current->process->id, (unsigned)current->id );

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

/* A few requests name something only this build can answer.
 *
 * get_desktop_window without `force` returns nothing until some other
 * process has created the desktop, and win32u answers that by launching
 * explorer.exe. There is exactly one GUI process here and explorer is GUI-6,
 * so every caller gets `force`: the desktop is created on the spot - the
 * same code path the server takes for the forcing caller - and win32u
 * never goes looking for an explorer.exe the image does not carry. */
static void fixup_request_before( struct __server_request_info *info, enum request req )
{
    if (!strcmp( prsk_req_names[req], "get_desktop_window" ))
        info->u.req.get_desktop_window_request.force = 1;

}

/* On Wine the desktop and HWND_MESSAGE windows belong to EXPLORER, so every
 * app process sees their user entries with a foreign pid and takes win32u's
 * WND_DESKTOP paths (dlls/win32u/window.c get_user_handle_ptr ->
 * OBJ_OTHER_PROCESS). Here the force-create runs inside the app's own
 * process: the entry keeps our pid, win32u goes looking for a client-side
 * WND that was never made, GetWindowLong on the desktop answers style 0,
 * and the first ShowWindow takes the invisible-parent shortcut - the window
 * turns visible without ever being exposed, so nothing paints. Clearing the
 * owner ids makes the entries look foreign, which is exactly how they look
 * to a Wine app. The server side is already detached
 * (server/window.c detach_window_thread). */
static void detach_user_entry( user_handle_t handle )
{
    volatile struct user_entry *entry;
    unsigned int index;

    if (!handle) return;
    index = ((handle & 0xffff) - FIRST_USER_HANDLE) >> 1;
    if (index >= MAX_USER_HANDLES) return;
    entry = &srv_shared_session->user_entries[index];
    entry->pid = 0;
    entry->tid = 0;
}

/* get_msg_queue_handle hands out a server handle to the queue, which the
 * client then waits on. On Wine that handle reaches the wineserver socket;
 * here the wait is a real NtWaitForMultipleObjects, so the handle has to be
 * the queue's kernel event. */
static void fixup_request( struct __server_request_info *info, enum request req,
                           struct thread *thread )
{
    if (!strcmp( prsk_req_names[req], "get_desktop_window" ))
    {
        detach_user_entry( info->u.reply.get_desktop_window_reply.top_window );
        detach_user_entry( info->u.reply.get_desktop_window_reply.msg_window );
    }
    if (!strcmp( prsk_req_names[req], "get_msg_queue_handle" ))
    {
        /* thread->queue is a struct object at offset 0; its get_sync op is
         * the queue's own accessor, so the sync object comes out of Wine's
         * code rather than out of a guess about the struct's layout (which
         * is private to queue.c). The thread comes in as a parameter because
         * dispatch_request has already cleared `current` by the time this
         * runs - reading current->queue here was a NULL deref. */
        struct object *queue = (struct object *)thread->queue, *sync;
        struct prsk_client *client = find_client_by_process( thread->process );
        HANDLE event = NULL, idle = NULL;

        if (client && queue && (sync = get_obj_sync( queue )))
        {
            event = dup_sync_handle( sync, client->handle );
            release_object( sync );
        }
        info->u.reply.get_msg_queue_handle_reply.handle = wine_server_obj_handle( event );
        /* The reply's second handle is the caller's own process idle event
         * (queue.c fills it from process->idle_event on Wine). win32u
         * stashes it as thread_info->idle_event and SIGNALS it from the
         * client side whenever its queue goes idle (message.c NtSetEvent) -
         * that signalling is the whole input-idle protocol, so without this
         * handle WaitForInputIdle on this process could never wake. */
        if (client && client->idle_sync)
            idle = dup_sync_handle( client->idle_sync, client->handle );
        info->u.reply.get_msg_queue_handle_reply.idle_event = wine_server_obj_handle( idle );
    }
}

/* WaitForInputIdle's server half. server/process.c (where wineserver keeps
 * this handler) is not compiled - it is the unix process model - but the
 * request itself is pure bookkeeping over records this build does keep, so
 * it lives here rather than leaving a NULL slot msg.c trips over.
 *
 * The caller hands over ITS OWN handle to the target process; the kernel
 * says which process that names (a cross-process duplicate + a pid query,
 * the prsk_client_handle_is_directory pattern), and the client list says
 * whether that process is one of ours. The reply is a handle - valid in
 * the CALLER - to the target's idle event; the event is only ever
 * signalled by the TARGET's own win32u (see the get_msg_queue_handle
 * fix-up above), never by the server: wineserver's exact split. */
DECL_HANDLER(get_process_idle_event)
{
    struct prsk_client *caller = find_client_by_process( current->process );
    struct prsk_client *target;
    PROCESS_BASIC_INFORMATION info;
    HANDLE local = NULL;

    reply->event = 0;
    if (!caller)
    {
        set_error( STATUS_INVALID_HANDLE );
        return;
    }
    if (NtDuplicateObject( caller->handle, wine_server_ptr_handle( req->handle ),
                           GetCurrentProcess(), &local, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0 ) ||
        NtQueryInformationProcess( local, ProcessBasicInformation, &info, sizeof(info), NULL ))
    {
        if (local) NtClose( local );
        set_error( STATUS_INVALID_HANDLE );
        return;
    }
    NtClose( local );
    if (!(target = find_client( (DWORD)(ULONG_PTR)info.UniqueProcessId )))
    {
        set_error( STATUS_INVALID_HANDLE );
        return;
    }
    if (target->idle_sync)
        reply->event =
            wine_server_obj_handle( dup_sync_handle( target->idle_sync, caller->handle ) );
}

/* Run one request on behalf of `client`'s thread `tid`. This is the whole
 * server side of a call, and BOTH modes reach the state machine through it:
 * the in-process build calls it directly (user/wine/server/call.c), the
 * server process calls it from its transport loop. One authority, so the
 * two modes cannot drift (Art. 11). */
unsigned int prsk_server_dispatch( struct prsk_client *client, DWORD tid,
                                   struct __server_request_info *info )
{
    enum request req = info->u.req.request_header.req;
    struct thread *thread;
    unsigned int ret;

    server_lock();
    if (!(thread = find_thread_record( tid )) && !(thread = create_thread_record( client, tid )))
    {
        server_unlock();
        return STATUS_NO_MEMORY;
    }
    if (req < prsk_req_count) fixup_request_before( info, req );
    ret = dispatch_request( info, thread );
    if (!ret && req < prsk_req_count) fixup_request( info, req, thread );
    server_unlock();
    return ret;
}

struct prsk_client *prsk_local_client(void)
{
    return local_client;
}

void *prsk_client_process_handle( struct prsk_client *client )
{
    return client ? client->handle : NULL;
}

struct prsk_client *prsk_attach_client( unsigned int pid, void *processHandle )
{
    struct prsk_client *client;

    server_lock();
    if (!(client = find_client( pid ))) client = create_client( pid, processHandle );
    server_unlock();
    return client;
}

/* Retire one thread's records, in wineserver's own order
 * (server/thread.c cleanup_thread): clipboard first, then the windows it
 * owns, then its message queue, then its hold on the desktop. Doing it in a
 * different order is how a window ends up on a freed queue. */
static void reap_thread_locked( struct prsk_thread_record *record )
{
    struct thread *thread = record->thread;
    struct thread *previous = current;

    /* The teardown helpers read `current` (they set errors and touch the
     * calling thread's desktop), so bind the thread being reaped. */
    current = thread;
    cleanup_clipboard_thread( thread );
    srv_destroy_thread_windows( thread );
    if (thread->queue)
    {
        free_msg_queue( thread );
        thread->queue = NULL;
    }
    /* Unconditional, as in cleanup_thread (server/thread.c) -- the helper
     * guards itself on thread->desktop. Gating it on desktop_users (usually
     * 0; it counts temporary desktop references) skipped the removal, and a
     * freed thread stayed linked on desktop->threads for the next reap's
     * remove_desktop_thread to walk into. */
    release_thread_desktop( thread, 1 );
    current = previous == thread ? NULL : previous;

    list_remove( &thread->proc_entry );
    list_remove( &record->entry );
    release_object( thread );
    free( record );
}

void prsk_reap_thread( struct prsk_client *client, unsigned int tid )
{
    struct prsk_thread_record *record, *next;

    server_lock();
    LIST_FOR_EACH_ENTRY_SAFE( record, next, &thread_records, struct prsk_thread_record, entry )
        if (record->client == client && record->tid == tid)
        {
            reap_thread_locked( record );
            break;
        }
    server_unlock();
}

/* A client process died. Everything it still owns goes, threads first (a
 * window is owned by a thread, and destroy_thread_windows is what unlinks
 * it) and then the process-wide state, which is the subset of wineserver's
 * process_killed that applies to the files compiled here. */
void prsk_reap_client( struct prsk_client *client )
{
    struct prsk_thread_record *record, *next;

    server_lock();
    LIST_FOR_EACH_ENTRY_SAFE( record, next, &thread_records, struct prsk_thread_record, entry )
        if (record->client == client) reap_thread_locked( record );

    close_process_desktop( client->process );
    destroy_process_classes( client->process );
    free_process_user_handles( client->process );
    /* The subset of process_destroy (server/process.c) that applies here,
     * because this build's process ops end in no_destroy: the rawinput list
     * is GLOBAL, and a freed process left on it is a dangling entry the next
     * set_rawinput_process walks into. */
    list_remove( &client->process->rawinput_entry );
    free( client->process->rawinput_devices );
    if (client->process->handles)
    {
        release_object( client->process->handles );
        client->process->handles = NULL;
    }
    list_remove( &client->entry );
    release_object( client->process );
    /* The idle event: this reference is the OWNING one (wineserver's
     * process_destroy releases idle_event the same way); handles clients
     * hold on it die with their handle tables. */
    if (client->idle_sync)
    {
        release_object( client->idle_sync );
        client->idle_sync = NULL;
    }
    if (client->handle && client->handle != GetCurrentProcess()) NtClose( client->handle );
    free( client );
    server_unlock();
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

/* --- case-insensitive names ------------------------------------------------
 *
 * The server's namespace hashes and compares names case-insensitively, and
 * server/unicode.c does that through a lowercase table it reads out of
 * l_intl.nls with pread() on a unix descriptor. That file is not compiled
 * here for exactly that reason - it is a unix-fd reader, not a state
 * machine - so the three functions the GUI sources want are expressed over
 * the case table ntdll ALREADY has, mapped from the same l_intl.nls the
 * image bakes (Makefile WINFILES). One table, reached a different way.
 *
 * The hash itself is Wine's (multiply by 65599), because it must stay
 * consistent with nothing but itself: it indexes a namespace this process
 * owns. What must be right is the pairing - two names equal under
 * memicmp_strW must land in the same bucket - and both go through the same
 * RtlDowncaseUnicodeChar. */

static WCHAR to_lower_char( WCHAR ch )
{
    return RtlDowncaseUnicodeChar( ch );
}

unsigned int hash_strW( const WCHAR *str, data_size_t len, unsigned int hash_size )
{
    unsigned int i, hash = 0;

    for (i = 0; i < len / sizeof(WCHAR); i++) hash = hash * 65599 + to_lower_char( str[i] );
    return hash % hash_size;
}

int memicmp_strW( const WCHAR *str1, const WCHAR *str2, data_size_t len )
{
    int ret = 0;

    for (len /= sizeof(WCHAR); len; str1++, str2++, len--)
        if ((ret = to_lower_char( *str1 ) - to_lower_char( *str2 ))) break;
    return ret;
}

/* The server's object dumper writes to stderr, which does not exist here. */
int dump_strW( const WCHAR *str, data_size_t len, FILE *file, const char escape[2] ) { return 0; }

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

/* One station directory PER SESSION, made on demand. GUI-2 had a single one
 * and handed it to every caller, which was the right answer while there was
 * one session and one process and stopped being one the moment there were
 * two of either (docs/03 "GUI-2 notes"). The session a request resolves
 * against is the calling client's, which came from the kernel
 * (NtQueryInformationProcess) when the client attached -- not from an
 * assumption about how many there are. */
struct prsk_station_dir
{
    struct list            entry;
    ULONG                  session;
    struct prsk_directory *dir;
};

static struct list station_dirs = LIST_INIT( station_dirs );

static struct prsk_directory *station_dir_for_session( ULONG session )
{
    struct prsk_station_dir *entry;
    struct prsk_directory *dir;

    LIST_FOR_EACH_ENTRY( entry, &station_dirs, struct prsk_station_dir, entry )
        if (entry->session == session) return entry->dir;

    if (!(dir = alloc_object( &prsk_directory_ops ))) return NULL;
    dir->obj.name = NULL;
    if (!(dir->entries = create_namespace( 7 ))) return NULL;
    if (!(entry = malloc( sizeof(*entry) ))) return NULL;
    entry->session = session;
    entry->dir = dir;
    list_add_tail( &station_dirs, &entry->entry );
    return dir;
}

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

/* The session of whichever client is making the current request. */
static ULONG current_session(void)
{
    struct prsk_client *client = current ? find_client_by_process( current->process ) : NULL;

    return client ? client->session : 0;
}

struct object *get_root_directory(void)
{
    struct prsk_directory *dir = station_dir_for_session( current_session() );

    return dir ? grab_object( dir ) : NULL;
}

struct object *get_directory_obj( struct process *process, obj_handle_t handle )
{
    struct prsk_client *client = find_client_by_process( process );
    struct prsk_directory *dir;

    /* The handle names a directory in the CLIENT's table, which this server
     * cannot read; what it decides is only which station directory the
     * relative name resolves under, and that follows from the client's
     * session. So: check the handle really is a live directory over there,
     * then answer with that session's directory. */
    if (!client || !prsk_client_handle_is_directory( client, handle ))
    {
        set_error( STATUS_INVALID_HANDLE );
        return NULL;
    }
    if (!(dir = station_dir_for_session( client->session ))) return NULL;
    return grab_object( dir );
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
    /* Only req_dup_handle asks (server/handle.c), and that is not on the GUI
     * path. Resolving it would mean reading a handle table this server does
     * not own; answering "the process I know about" was true while there was
     * one and would be a fabricated answer now (Art. 12). */
    PRSK_UNBUILT( "get_process_from_handle" );
    set_error( STATUS_NOT_IMPLEMENTED );
    return NULL;
}

struct process *get_process_from_id( process_id_t id )
{
    struct prsk_client *client;

    if (!id) return (struct process *)grab_object( current->process );
    if (!(client = find_client( id ))) { set_error( STATUS_INVALID_PARAMETER ); return NULL; }
    return (struct process *)grab_object( client->process );
}

struct thread *get_thread_from_id( thread_id_t id )
{
    struct thread *thread = find_thread_record( id );

    if (!thread) { set_error( STATUS_INVALID_PARAMETER ); return NULL; }
    return (struct thread *)grab_object( thread );
}

void enum_processes( int (*cb)(struct process *, void *), void *user )
{
    struct prsk_client *client, *next;

    LIST_FOR_EACH_ENTRY_SAFE( client, next, &clients, struct prsk_client, entry )
        if (cb( client->process, user )) break;
}

const char *server_argv0 = "win32u.dll";
