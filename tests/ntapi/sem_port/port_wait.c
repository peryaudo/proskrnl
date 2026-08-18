/*
 * sem_port/port_wait.c — what a completion PORT is as a waitable object, and
 * what a parked NtRemoveIoCompletion is (docs/21 W10, ntdll:sync).
 *
 * sem_port/ports.c pins the packet surface: fields, FIFO, depth, the batch
 * remove. It never waits on a port HANDLE and never parks two removers, and
 * that is the whole of what ntdll:sync's test_completion_port_scheduling
 * does. The two channels are separate in the pinned server
 * (third_party/wine server/completion.c) and they behave differently:
 *
 *   - the HANDLE's signal state is `completion->sync`, an internal sync
 *     created MANUAL-reset and clear (`create_internal_sync( 1, 0 )`,
 *     server/event.c). add_completion signals it only when the new packet
 *     survives the remover fan-out; remove_completion resets it when the
 *     queue empties; completion_close_handle signals it on the last handle.
 *     So a handle wait is NON-CONSUMING and wakes EVERY waiter.
 *
 *   - a parked NtRemoveIoCompletion is a `completion_wait` object on
 *     `completion->wait_queue`, added at the HEAD (remove_completion's
 *     list_add_head) and served by add_completion's forward iteration — so
 *     the fan-out is LIFO, and a parked remover takes the packet BEFORE the
 *     handle's signal state ever sees it.
 *
 * Every wait here is bounded. A wrong kernel must fail an assertion, not
 * cost the leg its timeout (docs/21 W10's second lesson).
 */
#include "../ntapi.h"

NTSYSAPI NTSTATUS NTAPI NtCreateIoCompletion(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
NTSYSAPI NTSTATUS NTAPI NtSetIoCompletion(HANDLE, ULONG_PTR, ULONG_PTR, NTSTATUS, SIZE_T);
NTSYSAPI NTSTATUS NTAPI NtRemoveIoCompletion(HANDLE, PULONG_PTR, PULONG_PTR, PIO_STATUS_BLOCK,
                                             PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

typedef struct _FILE_IO_COMPLETION_INFORMATION
{
    ULONG_PTR CompletionKey;
    ULONG_PTR CompletionValue;
    IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION;
NTSYSAPI NTSTATUS NTAPI NtRemoveIoCompletionEx(HANDLE, FILE_IO_COMPLETION_INFORMATION *, ULONG,
                                               ULONG *, LARGE_INTEGER *, BOOLEAN);

typedef enum _IO_COMPLETION_INFORMATION_CLASS
{
    IoCompletionBasicInformation = 0
} IO_COMPLETION_INFORMATION_CLASS;
typedef struct _IO_COMPLETION_BASIC_INFORMATION
{
    LONG Depth;
} IO_COMPLETION_BASIC_INFORMATION;
NTSYSAPI NTSTATUS NTAPI NtQueryIoCompletion(HANDLE, IO_COMPLETION_INFORMATION_CLASS, PVOID, ULONG,
                                            PULONG);

#ifndef IO_COMPLETION_ALL_ACCESS
#define IO_COMPLETION_ALL_ACCESS 0x001F0003 /* wine/include/winternl.h */
#endif

/* Relative NT timeouts are negative 100ns units. */
static LARGE_INTEGER relative_ms(int ms)
{
    LARGE_INTEGER t;
    t.QuadPart = -(LONGLONG)ms * 10000;
    return t;
}

static NTSTATUS wait_port(HANDLE port, int ms)
{
    LARGE_INTEGER t = relative_ms(ms);
    return NtWaitForSingleObject(port, FALSE, &t);
}

static LONG port_depth(HANDLE port)
{
    IO_COMPLETION_BASIC_INFORMATION basic;
    basic.Depth = -1;
    if (NtQueryIoCompletion(port, IoCompletionBasicInformation, &basic, sizeof(basic), NULL) !=
        STATUS_SUCCESS)
        return -1;
    return basic.Depth;
}

/* ---- the parked-remover threads ---------------------------------------- */

/* One remover per thread, each recording what its park answered. `started`
 * is set before the park so the driver can tell "parked" from "not yet
 * scheduled" without sleeping blind. */
struct remover
{
    HANDLE port;
    HANDLE started;
    NTSTATUS status;
    ULONG_PTR key;
    ULONG_PTR value;
    int use_ex; /* NtRemoveIoCompletionEx instead of NtRemoveIoCompletion */
};

static DWORD WINAPI remover_thread(void *param)
{
    struct remover *r = param;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER timeout = relative_ms(5000);

    SetEvent(r->started);
    if (r->use_ex)
    {
        FILE_IO_COMPLETION_INFORMATION info;
        ULONG count = 0;
        memset(&info, 0, sizeof(info));
        r->status = NtRemoveIoCompletionEx(r->port, &info, 1, &count, &timeout, FALSE);
        if (r->status == STATUS_SUCCESS && count == 1)
        {
            r->key = info.CompletionKey;
            r->value = info.CompletionValue;
        }
    }
    else
    {
        r->status = NtRemoveIoCompletion(r->port, &r->key, &r->value, &iosb, &timeout);
    }
    return 0;
}

/* A handle waiter, for the close case. */
struct waiter
{
    HANDLE port;
    HANDLE started;
    NTSTATUS status;
};

static DWORD WINAPI waiter_thread(void *param)
{
    struct waiter *w = param;
    SetEvent(w->started);
    w->status = wait_port(w->port, 5000);
    return 0;
}

/* Start a thread and give it long enough to reach its park. `started` says
 * it entered the body; the sleep covers the syscall itself. */
static HANDLE start_thread(LPTHREAD_START_ROUTINE proc, void *arg, HANDLE started)
{
    HANDLE thread = CreateThread(NULL, 0, proc, arg, 0, NULL);
    if (thread == NULL)
        return NULL;
    WaitForSingleObject(started, 5000);
    Sleep(200);
    return thread;
}

START_TEST(port_wait)
{
    NTSTATUS status;
    HANDLE port = NULL;
    ULONG_PTR key, value;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER zero;

    zero.QuadPart = 0;

    status = NtCreateIoCompletion(&port, IO_COMPLETION_ALL_ACCESS, NULL, 0);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);

    /* ---- 1. the handle's signal state IS "an unclaimed packet is queued" -- */

    /* create_internal_sync( 1, 0 ): a fresh port is CLEAR. */
    ok(wait_port(port, 0) == STATUS_TIMEOUT, "empty port must not be signalled");

    status = NtSetIoCompletion(port, 0x11, 0x22, STATUS_SUCCESS, 0);
    ok(status == STATUS_SUCCESS, "set -> %08lx", (unsigned long)status);

    /* MANUAL reset, and the wait consumes nothing: signalled twice over, and
     * the packet is still queued afterwards. An implementation that lets a
     * handle wait eat a packet passes the first of these three and fails the
     * other two. */
    ok(wait_port(port, 0) == STATUS_SUCCESS, "queued packet must signal the handle");
    ok(wait_port(port, 0) == STATUS_SUCCESS, "the handle signal must be manual-reset");
    ok(port_depth(port) == 1, "a handle wait must not consume the packet (depth %ld)",
       (long)port_depth(port));

    /* ...and the reset is the QUEUE emptying, not the remove happening. */
    status = NtSetIoCompletion(port, 0x33, 0x44, STATUS_SUCCESS, 0);
    ok(status == STATUS_SUCCESS, "set second -> %08lx", (unsigned long)status);
    status = NtRemoveIoCompletion(port, &key, &value, &iosb, &zero);
    ok(status == STATUS_SUCCESS && key == 0x11, "first remove -> %08lx key %lx",
       (unsigned long)status, (unsigned long)key);
    ok(wait_port(port, 0) == STATUS_SUCCESS, "one packet left must keep the handle signalled");
    status = NtRemoveIoCompletion(port, &key, &value, &iosb, &zero);
    ok(status == STATUS_SUCCESS && key == 0x33, "second remove -> %08lx key %lx",
       (unsigned long)status, (unsigned long)key);
    ok(wait_port(port, 0) == STATUS_TIMEOUT, "a drained port must go clear again");

    /* ---- 2. a parked remover takes the packet before the handle sees it --- */
    {
        struct remover r;
        HANDLE thread;

        memset(&r, 0, sizeof(r));
        r.port = port;
        r.status = STATUS_PENDING;
        r.started = CreateEventA(NULL, TRUE, FALSE, NULL);
        ok(r.started != NULL, "CreateEvent");
        thread = start_thread(remover_thread, &r, r.started);
        ok(thread != NULL, "CreateThread");

        status = NtSetIoCompletion(port, 0x55, 0x66, STATUS_SUCCESS, 0);
        ok(status == STATUS_SUCCESS, "set for parked remover -> %08lx", (unsigned long)status);

        /* add_completion hands the msg to the wait_queue entry and only
         * signals `sync` "if (!list_empty( &completion->queue ))" — which it
         * now is. So the handle is never signalled at all. */
        ok(wait_port(port, 0) == STATUS_TIMEOUT,
           "a packet claimed by a parked remover must not signal the handle");

        ok(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0, "remover did not return");
        ok(r.status == STATUS_SUCCESS, "parked remove -> %08lx", (unsigned long)r.status);
        ok(r.key == 0x55 && r.value == 0x66, "parked remover packet %lx/%lx", (unsigned long)r.key,
           (unsigned long)r.value);
        ok(port_depth(port) == 0, "port must be empty after the parked remove (depth %ld)",
           (long)port_depth(port));
        CloseHandle(thread);
        CloseHandle(r.started);
    }

    /* ---- 3. two parked removers are served LIFO -------------------------- */
    {
        struct remover r[2];
        HANDLE thread[2];
        unsigned i;

        for (i = 0; i < 2; i++)
        {
            memset(&r[i], 0, sizeof(r[i]));
            r[i].port = port;
            r[i].status = STATUS_PENDING;
            r[i].started = CreateEventA(NULL, TRUE, FALSE, NULL);
            /* r[1] uses the Ex entry point: both park through the same
             * server request, so the ordering rule must not depend on which
             * syscall asked. */
            r[i].use_ex = (i == 1);
            thread[i] = start_thread(remover_thread, &r[i], r[i].started);
            ok(thread[i] != NULL, "CreateThread %u", i);
        }

        /* r[1] parked LAST, so it sits at the head of wait_queue and takes
         * the FIRST packet. */
        NtSetIoCompletion(port, 0x71, 0, STATUS_SUCCESS, 0);
        NtSetIoCompletion(port, 0x72, 0, STATUS_SUCCESS, 0);

        for (i = 0; i < 2; i++)
            ok(WaitForSingleObject(thread[i], 5000) == WAIT_OBJECT_0, "remover %u did not return",
               i);
        ok(r[0].status == STATUS_SUCCESS && r[1].status == STATUS_SUCCESS,
           "parked removes -> %08lx %08lx", (unsigned long)r[0].status, (unsigned long)r[1].status);
        ok(r[1].key == 0x71, "the LAST remover to park takes the first packet (got %lx)",
           (unsigned long)r[1].key);
        ok(r[0].key == 0x72, "the FIRST remover to park takes the second packet (got %lx)",
           (unsigned long)r[0].key);

        for (i = 0; i < 2; i++)
        {
            CloseHandle(thread[i]);
            CloseHandle(r[i].started);
        }
    }

    /* ---- 4. closing the last handle wakes the handle waiters -------------- */
    {
        struct waiter w;
        HANDLE thread, closing = NULL;

        status = NtCreateIoCompletion(&closing, IO_COMPLETION_ALL_ACCESS, NULL, 0);
        ok(status == STATUS_SUCCESS, "create closing -> %08lx", (unsigned long)status);

        memset(&w, 0, sizeof(w));
        w.port = closing;
        w.status = STATUS_PENDING;
        w.started = CreateEventA(NULL, TRUE, FALSE, NULL);
        thread = start_thread(waiter_thread, &w, w.started);
        ok(thread != NULL, "CreateThread");

        /* completion_close_handle's trailing signal_sync( completion->sync ).
         * It fires on the LAST handle, so the waiter comes back SIGNALLED —
         * not abandoned, and not timed out. */
        status = NtClose(closing);
        ok(status == STATUS_SUCCESS, "close with a waiter -> %08lx", (unsigned long)status);
        ok(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0, "handle waiter did not return");
        ok(w.status == STATUS_SUCCESS, "closing the port must wake a handle wait (-> %08lx)",
           (unsigned long)w.status);
        CloseHandle(thread);
        CloseHandle(w.started);
    }

    /* ---- 5. closing the last handle ABANDONS the parked removers ---------- */
    {
        struct remover r[2];
        HANDLE thread[2], closing = NULL;
        unsigned i;

        status = NtCreateIoCompletion(&closing, IO_COMPLETION_ALL_ACCESS, NULL, 0);
        ok(status == STATUS_SUCCESS, "create closing -> %08lx", (unsigned long)status);

        for (i = 0; i < 2; i++)
        {
            memset(&r[i], 0, sizeof(r[i]));
            r[i].port = closing;
            r[i].status = STATUS_PENDING;
            r[i].started = CreateEventA(NULL, TRUE, FALSE, NULL);
            r[i].use_ex = (i == 1);
            thread[i] = start_thread(remover_thread, &r[i], r[i].started);
            ok(thread[i] != NULL, "CreateThread %u", i);
        }

        /* completion_close_handle walks the whole wait_queue and
         * make_wait_abandoned()s every entry — both entry points, and both
         * removers, not just the one at the head. */
        status = NtClose(closing);
        ok(status == STATUS_SUCCESS, "close with parked removers -> %08lx", (unsigned long)status);
        for (i = 0; i < 2; i++)
        {
            ok(WaitForSingleObject(thread[i], 5000) == WAIT_OBJECT_0, "remover %u did not return",
               i);
            ok(r[i].status == STATUS_ABANDONED_WAIT_0,
               "closing the port must abandon parked remover %u (-> %08lx)", i,
               (unsigned long)r[i].status);
            CloseHandle(thread[i]);
            CloseHandle(r[i].started);
        }
    }

    NtClose(port);
}
