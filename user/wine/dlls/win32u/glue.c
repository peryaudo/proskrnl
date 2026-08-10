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
extern int prsk_transport_startup(void);
extern void prsk_client_thread_detach(void);
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
    unsigned int             server_slot;   /* transport slot + 1; 0 = unclaimed */
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

/* Where user/wine/wineserver-lite/client/call.c keeps this thread's transport slot. It
 * belongs in the per-thread block rather than in a TLS index of its own:
 * this build links no kernel32, so there is no TlsAlloc, and the block is
 * already the thread-local store everything else here uses. */
unsigned int *prsk_thread_slot(void)
{
    struct prsk_thread_data *data = thread_data();
    return data ? &data->server_slot : NULL;
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
        /* base stays char * for the offset arithmetic below; the cast is only
         * to spell the HMODULE this one call declares. */
        if (!(imports = RtlImageDirectoryEntryToData( (HMODULE)base, TRUE,
                                                      IMAGE_DIRECTORY_ENTRY_IMPORT, &size )))
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

/* The 64-bit ntdll's NLS case table, when nobody else will initialize it.
 *
 * In a WOW64 process the 64-bit ntdll deliberately does NOT finish its
 * process init: loader_init calls init_wow64, which loads wow64.dll and hands
 * control to Wow64LdrpInitialize and never comes back — so locale_init, three
 * lines further down, never runs (third_party/wine dlls/ntdll/loader.c). Its
 * `nls_info` therefore keeps the static initializer, whose UpperCaseTable is
 * NULL, and RtlUpcaseUnicodeChar dereferences it. Upstream that is harmless:
 * the only 64-bit code in a WOW64 process is the wow64*.dll thunk set, which
 * never asks ntdll to fold case.
 *
 * proskrnl puts one more 64-bit DLL there — this one, because wow64win.dll
 * calls the real NtUser/NtGdi entry points rather than a syscall — so the gap becomes
 * ours to close. A 32-bit GUI applet died on it before its window appeared,
 * inside the ntdll_wcsicmp below.
 *
 * Only the CASE tables are installed. The code-page halves stay what the
 * 64-bit ntdll already has (CP_UTF8, its static default): choosing the
 * system's real ANSI/OEM pages would mean walking the locale table the way
 * locale_init does, and nothing here converts multibyte text. In a 64-bit
 * process locale_init has already run and this is a no-op — the PEB field it
 * publishes is the flag. */
static void prsk_init_nls_case_tables(void)
{
    PEB *peb = NtCurrentTeb()->Peb;
    USHORT utf8[2] = { 0, CP_UTF8 };
    NLSTABLEINFO info;
    void *casePtr = NULL;
    SIZE_T size = 0;

    if (peb->UnicodeCaseTableData) return; /* locale_init got here first */
    /* Section type 10 = the case table, the argument locale_init passes
     * (dlls/ntdll/locale.c; kernel/ps/query.c NtGetNlsSectionPtr serves it). */
    /* Loud, because the failure is not: with no casemap the very next
     * RtlUpcaseUnicodeChar dereferences NULL somewhere deep inside a window
     * class lookup, which reads as a win32u bug rather than as a missing
     * table. */
    if (NtGetNlsSectionPtr( 10, 0, NULL, &casePtr, &size ))
    {
        winefb_report( "[KTEST] gui2 nls case table FAIL\n" );
        return;
    }
    RtlInitNlsTables( utf8, utf8, casePtr, &info );
    RtlResetRtlTranslations( &info );
    peb->UnicodeCaseTableData = casePtr;
}

/* Spelled as loops over RtlUpcaseUnicodeChar, NOT as calls to wcsicmp:
 * wine/unixlib.h #defines wcsicmp/wcsnicmp AS these two functions, so a
 * definition that calls the libc name calls itself (same trap as the
 * __mingw_vsnprintf story below - it compiled to `jmp .` and the first
 * caller spun forever). RtlUpcaseUnicodeChar reads the same NLS casemap
 * ntdll_towupper does (dlls/ntdll/unix/env.c), so the semantics match. */
int ntdll_wcsicmp( const WCHAR *str1, const WCHAR *str2 )
{
    int ret;
    for (;;)
    {
        if ((ret = RtlUpcaseUnicodeChar( *str1 ) - RtlUpcaseUnicodeChar( *str2 )) || !*str1)
            return ret;
        str1++;
        str2++;
    }
}

int ntdll_wcsnicmp( const WCHAR *str1, const WCHAR *str2, int n )
{
    int ret;
    for (ret = 0; n > 0; n--, str1++, str2++)
        if ((ret = RtlUpcaseUnicodeChar( *str1 ) - RtlUpcaseUnicodeChar( *str2 )) || !*str1) break;
    return ret;
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

/* --- 7. dlopen ------------------------------------------------------------
 *
 * opengl.c and vulkan.c load their backends this way and degrade by
 * themselves when there is none - the same path Wine takes on a host with no
 * libGL, so it is upstream-exercised rather than invented here. freetype.c
 * is the one caller with a real library to find; it is linked statically, so
 * the "handle" is a cookie and the symbols come from a table
 * (user/wine/dlls/win32u/freetype_link.c). */

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
        /* The state machine has to be REACHABLE before win32u's own init
         * runs: shared_session_init opens \KernelObjects\__wine_session by
         * name as the FIRST thing init_user does, before any request is
         * sent, so a server that only wakes up on its first request is too
         * late. prsk_transport_startup does that wait, once: it returns when
         * the server process has published the mapping, or fails. */
        /* Before anything else in this DLL folds case (the transport's own
         * name lookups included): see prsk_init_nls_case_tables. */
        prsk_init_nls_case_tables();
        if (!prsk_transport_startup()) winefb_report( "[KTEST] gui2 server FAIL\n" );
        winefb_init();
    }
    else if (reason == DLL_THREAD_DETACH)
    {
        /* Hand the transport slot back and let the server retire this
         * thread's windows and queue now. It is not the only path that
         * does so -- a thread that dies without detaching is reaped when
         * its process does -- but it is the one that keeps a long-lived
         * process from accumulating dead threads' records. */
        prsk_client_thread_detach();
    }
    return TRUE;
}
