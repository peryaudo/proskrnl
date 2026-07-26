/*
 * glue.c - what win32u's unix half got from ntdll's unix half, over PE ntdll.
 *
 * Compiled as PE (GUI-2), win32u's sources still reference a handful of
 * things that only existed inside Wine's libwine/ntdll.so: pthreads, the
 * user-mode callback pair, the per-thread info block, a couple of path
 * helpers. All of them are re-expressed here over what PE ntdll already
 * exports; none of it changes win32u's own code, which is the point (Art. 10
 * - the Wine tree is not patched for this).
 *
 * The interesting one is the callback pair. On Wine, KeUserModeCallback
 * switches to the PE stack and enters KiUserCallbackDispatcher, and the
 * callback's tail call to NtCallbackReturn unwinds the syscall frame back.
 * In-process there is one stack and no syscall frame: KeUserModeCallback
 * calls Peb->KernelCallbackTable[id] directly, and NtCallbackReturn simply
 * records the reply and RETURNS - user32 spells every callback's exit as
 * `return NtCallbackReturn( ... )`, so the recorded reply arrives back at
 * KeUserModeCallback as that function's own return value. No stack switch,
 * no longjmp, nothing to unwind. The reply bytes are copied while the
 * callback's frame is still live, because it is that frame they usually
 * point into.
 */

#include <pthread.h>
#include <corecrt_stdio_config.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ntstatus.h"
#include "win32u_private.h"
#include "ntuser_private.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(win32u);

NTSTATUS WINAPI prsk_NtCallbackReturn( void *ret_ptr, ULONG ret_len, NTSTATUS status );
extern void winefb_init(void);
extern int prsk_server_init(void);
extern void winefb_report( const char *format, ... );
extern void *prsk_freetype_handle( const char *name );
extern void *prsk_freetype_symbol( void *handle, const char *symbol );

/* --- 1. pthreads over Rtl -------------------------------------------------- */

static DWORD current_tid(void)
{
    return HandleToULong( NtCurrentTeb()->ClientId.UniqueThread );
}

int pthread_mutexattr_init( pthread_mutexattr_t *attr )
{
    attr->type = PTHREAD_MUTEX_NORMAL;
    return 0;
}

int pthread_mutexattr_settype( pthread_mutexattr_t *attr, int type )
{
    attr->type = type;
    return 0;
}

int pthread_mutexattr_destroy( pthread_mutexattr_t *attr )
{
    (void)attr;
    return 0;
}

int pthread_mutex_init( pthread_mutex_t *mutex, const pthread_mutexattr_t *attr )
{
    memset( mutex, 0, sizeof(*mutex) );
    if (attr) mutex->recursive = (attr->type == PTHREAD_MUTEX_RECURSIVE);
    return 0;
}

int pthread_mutex_destroy( pthread_mutex_t *mutex )
{
    (void)mutex;
    return 0;
}

int pthread_mutex_lock( pthread_mutex_t *mutex )
{
    DWORD self = current_tid();

    if (mutex->owner == self)
    {
        /* Wine declared this lock non-recursive; on glibc the same path
         * would deadlock. Say so rather than quietly allowing it - a
         * re-entered lock is a bug wherever it happens (Art. 12). */
        if (!mutex->recursive)
            ERR( "re-entering non-recursive mutex %p from thread %04lx\n", mutex, (long)self );
        mutex->depth++;
        return 0;
    }
    RtlAcquireSRWLockExclusive( (RTL_SRWLOCK *)&mutex->lock );
    mutex->owner = self;
    mutex->depth = 1;
    return 0;
}

int pthread_mutex_unlock( pthread_mutex_t *mutex )
{
    if (--mutex->depth) return 0;
    mutex->owner = 0;
    RtlReleaseSRWLockExclusive( (RTL_SRWLOCK *)&mutex->lock );
    return 0;
}

int pthread_once( pthread_once_t *once, void (*init)(void) )
{
    /* 0 = untouched, 1 = running, 2 = done. */
    int expected = 0;
    if (__atomic_compare_exchange_n( once, &expected, 1, FALSE, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE ))
    {
        init();
        __atomic_store_n( once, 2, __ATOMIC_RELEASE );
        return 0;
    }
    while (__atomic_load_n( once, __ATOMIC_ACQUIRE ) != 2) YieldProcessor();
    return 0;
}

int pthread_rwlock_init( pthread_rwlock_t *lock, const pthread_rwlockattr_t *attr )
{
    (void)attr;
    memset( lock, 0, sizeof(*lock) );
    return 0;
}

int pthread_rwlock_destroy( pthread_rwlock_t *lock )
{
    (void)lock;
    return 0;
}

int pthread_rwlock_rdlock( pthread_rwlock_t *lock )
{
    /* see pthread.h: exclusive both ways */
    RtlAcquireSRWLockExclusive( (RTL_SRWLOCK *)&lock->lock );
    return 0;
}

int pthread_rwlock_wrlock( pthread_rwlock_t *lock )
{
    RtlAcquireSRWLockExclusive( (RTL_SRWLOCK *)&lock->lock );
    return 0;
}

int pthread_rwlock_unlock( pthread_rwlock_t *lock )
{
    RtlReleaseSRWLockExclusive( (RTL_SRWLOCK *)&lock->lock );
    return 0;
}

/* --- 2. the per-thread info block ------------------------------------------
 *
 * Wine keeps it in a pthread key; NT keeps the win32k thread block in
 * TEB->Win32ThreadInfo, which is exactly what this is, so that is where it
 * goes. The struct is wrapped so the callback frame stack can ride along
 * without touching Wine's own layout. */

struct prsk_thread_data
{
    struct user_thread_info  info;          /* first: get_user_thread_info returns &info */
    struct callback_frame   *callback_top;
    struct arena_chunk      *arena;         /* callback replies, see NtCallbackReturn */
};

struct arena_chunk
{
    struct arena_chunk *next;
    SIZE_T              size;
    SIZE_T              used;
    char                data[];
};

static struct prsk_thread_data *thread_data(void)
{
    TEB *teb = NtCurrentTeb();
    struct prsk_thread_data *data = teb->Win32ThreadInfo;

    if (!data)
    {
        if (!(data = calloc( 1, sizeof(*data) ))) return NULL;
        list_init( &data->info.known_pointers );
        data->info.client_info = (struct ntuser_thread_info *)teb->Win32ClientInfo;
        teb->Win32ThreadInfo = data;
    }
    return data;
}

struct user_thread_info *get_user_thread_info(void)
{
    struct prsk_thread_data *data = thread_data();
    return data ? &data->info : NULL;
}

/* --- 3. the user-mode callback pair ---------------------------------------- */

struct callback_frame
{
    struct callback_frame *prev;
    void                  *reply;       /* arena copy of the callback's reply */
    ULONG                  reply_size;
    BOOL                   returned;    /* NtCallbackReturn was reached */
};

/* Replies live in a per-thread arena rather than in individual allocations,
 * so that a reply outlives the callback that produced it (its caller reads
 * it right after KeUserModeCallback returns) without anyone having to own a
 * free. Chunks are never reallocated - an outer frame's reply must not move
 * while an inner callback runs - and the whole arena is released when a
 * callback starts at depth 0, by which point the previous top-level reply
 * has been consumed. */
static void *arena_alloc( struct prsk_thread_data *data, SIZE_T size )
{
    struct arena_chunk *chunk = data->arena;
    SIZE_T aligned = (size + 15) & ~(SIZE_T)15;

    if (!chunk || chunk->used + aligned > chunk->size)
    {
        SIZE_T want = 4096;

        while (want - sizeof(*chunk) < aligned) want *= 2;
        if (!(chunk = malloc( want ))) return NULL;
        chunk->next = data->arena;
        chunk->size = want - sizeof(*chunk);
        chunk->used = 0;
        data->arena = chunk;
    }
    chunk->used += aligned;
    return chunk->data + chunk->used - aligned;
}

static void arena_release( struct prsk_thread_data *data )
{
    struct arena_chunk *chunk = data->arena;

    while (chunk)
    {
        struct arena_chunk *next = chunk->next;
        free( chunk );
        chunk = next;
    }
    data->arena = NULL;
}

/* Bind every loaded module's `ntdll!NtCallbackReturn` import to ours.
 *
 * The callback exit is the one half of the pair that cannot be provided by
 * defining a symbol: user32 reaches it through its import table, and on
 * proskrnl that entry lands in the kernel, where a callback frame is exactly
 * what does not exist. Rewriting the IAT entry is the smallest change that
 * keeps the fix on this side of the boundary - the alternative is a Wine
 * patch (Art. 10 says no) or a kernel syscall for a user-mode-only concept
 * (Art. 2 says no).
 *
 * Deferred to the first callback rather than done at attach: by then user32
 * has published KernelCallbackTable, which is proof it is loaded and
 * initialised. */
static void bind_callback_return(void)
{
    PEB *peb = NtCurrentTeb()->Peb;
    LIST_ENTRY *head = &peb->LdrData->InMemoryOrderModuleList, *entry;

    for (entry = head->Flink; entry != head; entry = entry->Flink)
    {
        LDR_DATA_TABLE_ENTRY *mod = CONTAINING_RECORD( entry, LDR_DATA_TABLE_ENTRY,
                                                       InMemoryOrderLinks );
        const IMAGE_IMPORT_DESCRIPTOR *imports;
        char *base = mod->DllBase;
        ULONG size = 0;

        if (base == (char *)peb->ImageBaseAddress) continue;    /* the .exe imports none of this */
        if (!(imports = RtlImageDirectoryEntryToData( base, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT,
                                                      &size )))
            continue;

        for ( ; imports->Name && imports->FirstThunk; imports++)
        {
            const IMAGE_THUNK_DATA *orig;
            IMAGE_THUNK_DATA *thunk;

            if (_stricmp( base + imports->Name, "ntdll.dll" )) continue;
            if (!imports->OriginalFirstThunk) continue;

            orig = (const IMAGE_THUNK_DATA *)(base + imports->OriginalFirstThunk);
            thunk = (IMAGE_THUNK_DATA *)(base + imports->FirstThunk);
            for ( ; orig->u1.Function; orig++, thunk++)
            {
                const IMAGE_IMPORT_BY_NAME *name;
                void *slot = &thunk->u1.Function;
                SIZE_T slot_size = sizeof(thunk->u1.Function);
                ULONG old_protect;

                if (IMAGE_SNAP_BY_ORDINAL( orig->u1.Ordinal )) continue;
                name = (const IMAGE_IMPORT_BY_NAME *)(base + orig->u1.AddressOfData);
                if (strcmp( (const char *)name->Name, "NtCallbackReturn" )) continue;

                if (NtProtectVirtualMemory( GetCurrentProcess(), &slot, &slot_size, PAGE_READWRITE,
                                            &old_protect ))
                    break;
                thunk->u1.Function = (ULONG_PTR)prsk_NtCallbackReturn;
                NtProtectVirtualMemory( GetCurrentProcess(), &slot, &slot_size, old_protect,
                                        &old_protect );
                TRACE( "bound NtCallbackReturn in %s\n", debugstr_w(mod->BaseDllName.Buffer) );
                break;
            }
        }
    }
}

NTSTATUS KeUserModeCallback( ULONG id, const void *args, ULONG len, void **ret_ptr, ULONG *ret_len )
{
    static BOOL bound;
    struct prsk_thread_data *data = thread_data();
    KERNEL_CALLBACK_PROC *table = NtCurrentTeb()->Peb->KernelCallbackTable;
    struct callback_frame frame = { 0 };
    NTSTATUS status;

    *ret_ptr = NULL;
    *ret_len = 0;

    if (!data) return STATUS_NO_MEMORY;
    if (!table)
    {
        /* user32 installs the table in its process attach; a callback before
         * that is a load-order bug, not something to paper over. */
        ERR( "callback %u with no KernelCallbackTable\n", (unsigned)id );
        return STATUS_NO_CALLBACK_ACTIVE;
    }

    if (!bound)
    {
        bind_callback_return();
        bound = TRUE;
    }
    if (!data->callback_top) arena_release( data );

    frame.prev = data->callback_top;
    data->callback_top = &frame;
    status = table[id]( (void *)args, len );
    data->callback_top = frame.prev;

    if (frame.returned)
    {
        *ret_ptr = frame.reply;
        *ret_len = frame.reply_size;
    }
    return status;
}

NTSTATUS WINAPI prsk_NtCallbackReturn( void *ret_ptr, ULONG ret_len, NTSTATUS status )
{
    struct prsk_thread_data *data = thread_data();
    struct callback_frame *frame = data ? data->callback_top : NULL;

    if (!frame) return STATUS_NO_CALLBACK_ACTIVE;

    if (ret_len)
    {
        /* Copy now: ret_ptr almost always points into the callback's own
         * frame, which dies the moment it returns to KeUserModeCallback. */
        if (!(frame->reply = arena_alloc( data, ret_len ))) return STATUS_NO_MEMORY;
        memcpy( frame->reply, ret_ptr, ret_len );
    }
    frame->reply_size = ret_len;
    frame->returned = TRUE;
    return status;
}

/* --- 4. ntdll unix-side helpers -------------------------------------------- */

int ntdll_wcsicmp( const WCHAR *str1, const WCHAR *str2 )
{
    return wcsicmp( str1, str2 );
}

int ntdll_wcsnicmp( const WCHAR *str1, const WCHAR *str2, int n )
{
    return wcsnicmp( str1, str2, n );
}

DWORD ntdll_umbstowcs( const char *src, DWORD srclen, WCHAR *dst, DWORD dstlen )
{
    DWORD ret = 0;
    RtlUTF8ToUnicodeN( dst, dstlen * sizeof(WCHAR), &ret, src, srclen );
    return ret / sizeof(WCHAR);
}

int ntdll_wcstoumbs( const WCHAR *src, DWORD srclen, char *dst, DWORD dstlen, BOOL strict )
{
    DWORD ret = 0;
    NTSTATUS status = RtlUnicodeToUTF8N( dst, dstlen, &ret, src, srclen * sizeof(WCHAR) );
    if (strict && status) return -1;
    return ret;
}

const WCHAR *ntdll_get_build_dir(void)
{
    return NULL;    /* never a build tree here */
}

const WCHAR *ntdll_get_data_dir(void)
{
    /* font.c composes <data dir>\fonts; the fonts the image bakes live in
     * the NT namespace, so hand it an NT path and let the same code build
     * \??\C:\windows\fonts. */
    static const WCHAR windowsW[] = {'\\','?','?','\\','C',':','\\','w','i','n','d','o','w','s',0};
    return windowsW;
}

/* --- 5. what WINE_UNIX_LIB expects ntdll.so to export ----------------------
 *
 * Under WINE_UNIX_LIB these are real calls into ntdll.so rather than the
 * inline TEB reads the PE headers use (winnt.h, processthreadsapi.h). The
 * definitions are the inline ones, spelled once here. */

struct _TEB * WINAPI NtCurrentTeb(void)
{
    struct _TEB *teb;

    __asm__( "movq %%gs:0x30,%0" : "=r" (teb) );
    return teb;
}

HANDLE WINAPI PsGetCurrentProcessId(void)
{
    return NtCurrentTeb()->ClientId.UniqueProcess;
}

HANDLE WINAPI PsGetCurrentThreadId(void)
{
    return NtCurrentTeb()->ClientId.UniqueThread;
}

/* win32u/syscall.c narrows allocations for a WoW64 client; there is no
 * 32-bit client here (x86_64 only, ADR 0006), so the whole address space is
 * available - the same value Wine uses for a pure 64-bit process. */
ULONG_PTR zero_bits = 0;

/* musl's error hook: Wine's PE build leaves errno alone too. */
void math_error( int type, const char *name, double x, double y, double result ) { }

/* --- 6. the last few libc corners ------------------------------------------
 *
 * ucrtbase covers everything win32u actually calls except these. strdup is
 * real (opentype.c and the server's atom code use it); the descriptor calls
 * are reachable only from wineserver paths this build refuses elsewhere, so
 * they refuse here too rather than pretending to have a file system. The
 * font backend's own file calls are NOT here -- they are implemented, over
 * Nt*, in font_unix.c. */

char *strdup( const char *str )
{
    size_t size = strlen( str ) + 1;
    char *copy = malloc( size );

    if (copy) memcpy( copy, str, size );
    return copy;
}

int dup( int fd )
{
    ERR( "no unix descriptors in this build\n" );
    return -1;
}

ssize_t pread( int fd, void *buffer, size_t count, off_t offset )
{
    ERR( "no unix descriptors in this build\n" );
    return -1;
}

char *realpath( const char *path, char *resolved )
{
    ERR( "no unix paths in this build\n" );
    return NULL;
}

/* --- 7. dlopen ------------------------------------------------------------
 *
 * opengl.c and vulkan.c load their backends this way and degrade by
 * themselves when there is none - the same path Wine takes on a host with no
 * libGL, so it is upstream-exercised rather than invented here. freetype.c
 * is the one caller with a real library to find; it is linked statically, so
 * the "handle" is a cookie and the symbols come from a table
 * (user/wine/win32u/freetype_link.c). */

void *prsk_dlopen( const char *name, int flags )
{
    void *handle = prsk_freetype_handle( name );

    if (!handle) TRACE( "no backend for %s\n", debugstr_a(name) );
    return handle;
}

void *prsk_dlsym( void *handle, const char *symbol )
{
    return prsk_freetype_symbol( handle, symbol );
}

int prsk_dlclose( void *handle )
{
    return 0;
}

char *prsk_dlerror(void)
{
    return (char *)"not available in this build";
}

/* --- 7b. the printf family -------------------------------------------------
 *
 * mingw's stdio.h routes the v*printf family through its own ANSI-conforming
 * copies in libmingwex, which this DLL does not link (it would bring a
 * second CRT alongside ucrtbase). The mingw spellings are therefore defined
 * here, over ucrtbase's real entry points.
 *
 * Over __stdio_common_vsprintf, NOT over vsnprintf: mingw's stdio.h defines
 * vsnprintf AS __mingw_vsnprintf, so a definition that calls vsnprintf calls
 * itself. (It compiles, links, and tail-calls into `jmp .`; the guest sat
 * there spinning at CPL=3 until QEMU's registers said which symbol it was.)
 * __stdio_common_vsprintf is UCRT's actual ABI underneath all of them and no
 * macro rewrites it.
 */

int __cdecl __stdio_common_vsprintf( unsigned __int64 options, char *buffer, size_t count,
                                     const char *format, void *locale, va_list args );
int __cdecl __stdio_common_vsscanf( unsigned __int64 options, const char *input, size_t count,
                                    const char *format, void *locale, va_list args );

/* Ask for C99 truncation semantics (return the length that WOULD have been
 * written, always NUL-terminate) rather than MSVC's -1. The flag is UCRT's,
 * so it comes from UCRT's header rather than being typed here (G8). */
static int prsk_vsnprintf( char *buffer, size_t count, const char *format, va_list args )
{
    return __stdio_common_vsprintf( _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR, buffer, count,
                                    format, NULL, args );
}

int __mingw_vsnprintf( char *buffer, size_t count, const char *format, va_list args )
{
    return prsk_vsnprintf( buffer, count, format, args );
}

int __ms_vsnprintf( char *buffer, size_t count, const char *format, va_list args )
{
    return prsk_vsnprintf( buffer, count, format, args );
}

int __mingw_vsscanf( const char *input, const char *format, va_list args )
{
    return __stdio_common_vsscanf( 0, input, (size_t)-1, format, NULL, args );
}

int __ms_vsscanf( const char *input, const char *format, va_list args )
{
    return __mingw_vsscanf( input, format, args );
}

int __mingw_vasprintf( char **out, const char *format, va_list args )
{
    va_list copy;
    int len;

    va_copy( copy, args );
    len = prsk_vsnprintf( NULL, 0, format, copy );
    va_end( copy );
    if (len < 0 || !(*out = malloc( len + 1 ))) return -1;
    return prsk_vsnprintf( *out, len + 1, format, args );
}

int asprintf( char **out, const char *format, ... )
{
    va_list args;
    int ret;

    va_start( args, format );
    ret = __mingw_vasprintf( out, format, args );
    va_end( args );
    return ret;
}

/* Only wineserver's dump helpers print to a FILE*, and there is no stderr
 * here - diagnostics go to serial (user/wine/server/shim.c prsk_log). */
int __mingw_vfprintf( FILE *file, const char *format, va_list args ) { return 0; }
int __mingw_vfscanf( FILE *file, const char *format, va_list args ) { return -1; }
int __ms_vfscanf( FILE *file, const char *format, va_list args ) { return -1; }
int fprintf( FILE *file, const char *format, ... ) { return 0; }
int fscanf( FILE *file, const char *format, ... ) { return -1; }

/* --- 8. the DLL entry ------------------------------------------------------
 *
 * Not winecrt0's DllMainCRTStartup: that one runs the C++ static-init
 * sections and calls DisableThreadLibraryCalls, neither of which this DLL
 * has any use for, and both of which drag in a CRT this build does not
 * link. win32u's own DllMain lives in main.c, which is the syscall-thunk
 * half that this build replaces. */

BOOL WINAPI prsk_win32u_entry( HINSTANCE instance, DWORD reason, void *reserved )
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        /* The state machine has to exist before win32u's own init runs:
         * shared_session_init opens \KernelObjects\__wine_session by name
         * as the FIRST thing init_user does, before any request is sent, so
         * a server that only wakes up on its first request is too late. */
        if (!prsk_server_init()) winefb_report( "[KTEST] gui2 server FAIL\n" );
        winefb_init();
    }
    return TRUE;
}
