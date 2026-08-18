/*
 * sem_pipe/close_cancel.c — closing the LAST handle a PROCESS holds on a pipe
 * end cancels the requests that process left parked on it.
 *
 * Every cancel pinned so far is one a caller ASKED for (sem_pipe/async_listen.c
 * and cancel_sync.c drive NtCancelIoFile / NtCancelSynchronousIoFile), plus the
 * sweep the filesystem's cleanup makes when the last handle in the SYSTEM goes.
 * This file pins the third one, which is neither: a process that still has a
 * request outstanding, and closes the only handle it can reach it through, has
 * the request cancelled for it — while another process's duplicate keeps the
 * pipe end itself alive.
 *
 * The rule is `async_close_obj_handle` (third_party/wine server/async.c), the
 * `close_handle` op of both pipe-end object types (server/named_pipe.c
 * pipe_server_ops / pipe_client_ops):
 *
 *   if (obj->handle_count == 1 || get_obj_handle_count( process, obj ) != 1) return 1;
 *   LIST_FOR_EACH_ENTRY( async, &process->asyncs, ... )
 *   {
 *       if (async->terminated || async->canceled || get_fd_user( async->fd ) != obj) continue;
 *       if (!async->completion || !async->data.apc_context || async->event) continue;
 *       cancel_async( async );
 *   }
 *
 * — two counts and a three-term predicate, and every one of the five terms is a
 * way an implementation that reads only the first sentence diverges:
 *
 *   * `obj->handle_count == 1` — the LAST handle in the system is not this
 *     rule's business at all; the object is about to be destroyed and its own
 *     teardown answers the requests. Both counts INCLUDE the handle being
 *     closed, which is also NT's convention for ObjectCloseMethod's
 *     ProcessHandleCount / SystemHandleCount (MS "ObjectCloseMethod routine").
 *   * `get_obj_handle_count( process, obj ) != 1` — a second handle in THIS
 *     process leaves the request alone, so a duplicate made into the caller's
 *     own process behaves nothing like one made into a child.
 *   * `!async->completion` — a request issued on a handle with no completion
 *     port bound is not swept.
 *   * `!async->data.apc_context` — nor one with no ApcContext, which is also
 *     the value a packet would carry.
 *   * `async->event` — nor one the caller gave an event, even with the other
 *     two satisfied. That term is the surprising one: an event is the thing a
 *     caller is most likely to be waiting on, and it is exactly what disarms
 *     the sweep.
 *
 * `async->completion` is captured by `create_async` when the request is ISSUED
 * (`async->completion = fd_get_completion( fd, &async->comp_key )`) and this
 * predicate reads that captured value — where the PACKET's port is re-read at
 * completion time (`add_async_completion`'s `if (async->fd &&
 * !async->completion)`, pinned by sem_pipe/pending_packet.c case 4). So "which
 * port gets the packet" and "was this request port-bound" are two different
 * questions asked of two different instants, and §6 measures the case that
 * separates them.
 *
 * ntdll:pipe's test_async_cancel_on_handle_close runs sixteen rows over this
 * rule and exactly one of them reaches the cancel; the fifteen that do not are
 * as much of the contract as the one that does, which is why most of the cases
 * below are negative.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtCreateIoCompletion(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
NTSYSAPI NTSTATUS NTAPI NtRemoveIoCompletion(HANDLE, PULONG_PTR, PULONG_PTR, PIO_STATUS_BLOCK,
                                             PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
/* As sem_ob/util.h declares them (winternl.h omits both). */
NTSYSAPI NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG,
                                          ULONG);
#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif

typedef struct
{
    HANDLE CompletionPort;
    ULONG_PTR CompletionKey;
} SEM_FILE_COMPLETION_INFORMATION;

#ifndef FileCompletionInformation
#define FileCompletionInformation 30
#endif

#define TEST_KEY ((ULONG_PTR)0xc0ffee05)

/* The child is this same binary re-run with a marker; all it has to do is stay
 * alive holding a duplicate, which is what makes the system handle count 2
 * while this process's own count is 1. */
#define CHILD_MARKER L"--closecancel-child"

static const WCHAR *wstr_find(const WCHAR *haystack, const WCHAR *needle)
{
    size_t nlen = 0;
    while (needle[nlen])
        nlen++;
    for (; *haystack; haystack++)
    {
        size_t i = 0;
        while (i < nlen && haystack[i] == needle[i])
            i++;
        if (i == nlen)
            return haystack;
    }
    return NULL;
}

static HANDLE spawn_child(void)
{
    WCHAR self[512], cmdline[700];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    int n = 0;

    if (GetModuleFileNameW(NULL, self, 512) == 0)
        return NULL;
    cmdline[n++] = '"';
    for (int i = 0; self[i]; i++)
        cmdline[n++] = self[i];
    cmdline[n++] = '"';
    cmdline[n++] = ' ';
    for (const WCHAR *m = CHILD_MARKER; *m; m++)
        cmdline[n++] = *m;
    cmdline[n] = 0;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        return NULL;
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

/* --- one rig per case ------------------------------------------------------ */

struct rig
{
    HANDLE server; /* ASYNCHRONOUS — the reader, and the handle under test */
    HANDLE client; /* synchronous — the peer, so a case can complete its own read */
    HANDLE port;   /* bound to `server`, or NULL */
    IO_STATUS_BLOCK io;
    char buffer[16];
};

static NTSTATUS bind_port(HANDLE file, HANDLE port)
{
    SEM_FILE_COMPLETION_INFORMATION info;
    IO_STATUS_BLOCK iosb;
    info.CompletionPort = port;
    info.CompletionKey = TEST_KEY;
    return NtSetInformationFile(file, &iosb, &info, sizeof(info), FileCompletionInformation);
}

static BOOLEAN rig_open(struct rig *rig, const void *name, BOOLEAN bindNow)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    rig->server = NULL;
    rig->client = NULL;
    rig->port = NULL;
    memset(rig->buffer, 0, sizeof(rig->buffer));
    poison_iosb(&rig->io);

    status = create_pipe_instance_async(&rig->server, name, 1, &iosb);
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return FALSE;
    status = open_pipe_client(&rig->client, name, &iosb);
    ok(status == STATUS_SUCCESS, "client open -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(rig->server);
        return FALSE;
    }
    status = NtCreateIoCompletion(&rig->port, IO_COMPLETION_ALL_ACCESS, NULL, 0);
    ok(status == STATUS_SUCCESS, "create port -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return FALSE;
    if (bindNow)
    {
        status = bind_port(rig->server, rig->port);
        ok(status == STATUS_SUCCESS, "bind -> %08lx", (unsigned long)status);
    }
    return TRUE;
}

/* The read every case parks: on an EMPTY pipe through an asynchronous handle,
 * so it answers STATUS_PENDING and leaves the caller running (pinned by
 * sem_pipe/pended_read.c). `apcContext` chooses whether an ApcContext travels
 * with it — the predicate's second term, and a packet's VALUE. */
static void rig_park_read(struct rig *rig, HANDLE event, BOOLEAN apcContext)
{
    NTSTATUS status = NtReadFile(rig->server, event, NULL, apcContext ? &rig->io : NULL, &rig->io,
                                 rig->buffer, sizeof(rig->buffer), NULL, NULL);
    ok(status == STATUS_PENDING, "read on an empty async pipe -> %08lx", (unsigned long)status);
}

/* Is a packet there RIGHT NOW? Zero timeout everywhere: the cancel happens
 * inside NtClose on this very thread, so a packet that is owed is already
 * posted by the time the call returns, and a packet that is not owed would
 * never appear however long the case waited. */
static BOOLEAN take_packet(HANDLE port, ULONG_PTR *keyOut, ULONG_PTR *valueOut,
                           IO_STATUS_BLOCK *iosbOut)
{
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    *keyOut = 0;
    *valueOut = 0;
    poison_iosb(iosbOut);
    return NtRemoveIoCompletion(port, keyOut, valueOut, iosbOut, &zero) == STATUS_SUCCESS;
}

static BOOLEAN is_signaled(HANDLE handle)
{
    return WaitForSingleObject(handle, 0) == WAIT_OBJECT_0;
}

/* Give the child a second handle to the same pipe end, so this process's own
 * close is its LAST while the system's is not. */
static HANDLE dup_into(HANDLE child, HANDLE handle)
{
    HANDLE duplicate = NULL;
    NTSTATUS status = NtDuplicateObject(NtCurrentProcess(), handle, child, &duplicate, 0, 0,
                                        DUPLICATE_SAME_ACCESS);
    ok(status == STATUS_SUCCESS, "duplicate into the child -> %08lx", (unsigned long)status);
    return duplicate;
}

/* Pull the child's duplicate back and close it, so every case retires its own
 * parked request before its IOSB and buffer (both locals) go out of scope. */
static void reclaim_and_close(HANDLE child, HANDLE duplicate)
{
    HANDLE back = NULL;
    if (duplicate == NULL)
        return;
    if (NT_SUCCESS(NtDuplicateObject(child, duplicate, NtCurrentProcess(), &back, 0, 0,
                                     DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE)))
        NtClose(back);
}

static void rig_close(struct rig *rig)
{
    if (rig->client)
        NtClose(rig->client);
    if (rig->port)
        NtClose(rig->port);
}

/* §1 — THE RULE. Port bound, ApcContext, no event, and a duplicate living in
 * another process: closing this process's only handle cancels the read and
 * posts its packet. The packet is an ordinary completion — the bind's KEY and
 * the caller's ApcContext as its VALUE — carrying STATUS_CANCELLED, which is
 * sem_pipe/pending_packet.c's "a pended request posts for EVERY outcome" seen
 * from the one producer no caller asked for. */
static void test_the_process_last_handle_cancels(HANDLE child)
{
    ULONG_PTR key, value;
    IO_STATUS_BLOCK packet;
    struct rig rig;
    HANDLE duplicate;

    if (!rig_open(&rig, W("\\??\\pipe\\prstest_cc_hit"), TRUE))
        return;
    rig_park_read(&rig, NULL, TRUE);

    duplicate = dup_into(child, rig.server);
    NtClose(rig.server);

    ok(take_packet(rig.port, &key, &value, &packet),
       "no packet: the process's last handle closed with a port-bound read parked");
    ok(key == TEST_KEY, "packet key %llx", (unsigned long long)key);
    ok(value == (ULONG_PTR)&rig.io, "packet value %llx want %llx", (unsigned long long)value,
       (unsigned long long)(ULONG_PTR)&rig.io);
    ok(packet.Status == STATUS_CANCELLED, "packet status %08lx", (unsigned long)packet.Status);
    ok(packet.Information == 0, "packet information %llx", (unsigned long long)packet.Information);
    /* The caller's own block is written too, exactly as any other cancel of a
     * pended request writes it (sem_pipe/pending_packet.c §3). Windows defers
     * this one until NtRemoveIoCompletion — ntdll:pipe:3111 wraps the
     * assertion in todo_wine_if — so this is the oracle's answer where the two
     * differ, and docs/03 carries the trade. */
    ok(rig.io.Status == STATUS_CANCELLED, "cancelled read iosb status %08lx",
       (unsigned long)rig.io.Status);
    ok(rig.io.Information == 0, "cancelled read iosb information %llx",
       (unsigned long long)rig.io.Information);

    reclaim_and_close(child, duplicate);
    rig_close(&rig);
}

/* §2 — the count is PER PROCESS. The same shape with the duplicate made into
 * this process instead: two handles here, so nothing is cancelled. The read is
 * then completed through the surviving handle by an ordinary peer write, which
 * is what proves it was still outstanding rather than merely un-reported. */
static void test_a_second_handle_here_leaves_it_alone(HANDLE child)
{
    ULONG_PTR key, value;
    IO_STATUS_BLOCK packet, writeIosb;
    HANDLE duplicate = NULL;
    struct rig rig;
    NTSTATUS status;

    (void)child;
    if (!rig_open(&rig, W("\\??\\pipe\\prstest_cc_self"), TRUE))
        return;
    rig_park_read(&rig, NULL, TRUE);

    status = NtDuplicateObject(NtCurrentProcess(), rig.server, NtCurrentProcess(), &duplicate, 0, 0,
                               DUPLICATE_SAME_ACCESS);
    ok(status == STATUS_SUCCESS, "duplicate into self -> %08lx", (unsigned long)status);
    NtClose(rig.server);

    ok(!take_packet(rig.port, &key, &value, &packet),
       "a duplicate in the SAME process did not stop the close-cancel");
    ok(rig.io.Status == IOSB_POISON_STATUS, "the read was completed anyway: %08lx",
       (unsigned long)rig.io.Status);

    status = pipe_write(rig.client, "hello", 5, &writeIosb);
    ok(status == STATUS_SUCCESS, "peer write -> %08lx", (unsigned long)status);
    ok(rig.io.Status == STATUS_SUCCESS, "the surviving handle's read did not complete: %08lx",
       (unsigned long)rig.io.Status);
    ok(rig.io.Information == 5, "completed read information %llx",
       (unsigned long long)rig.io.Information);

    if (duplicate)
        NtClose(duplicate);
    rig_close(&rig);
}

/* §3 — AN EVENT DISARMS IT. Port bound, ApcContext supplied, and an event as
 * well: the predicate's third term refuses the sweep. Both the packet and the
 * event are checked, because "no packet" alone would also be true of a cancel
 * that simply forgot to post one. */
static void test_an_event_disarms_the_sweep(HANDLE child)
{
    ULONG_PTR key, value;
    IO_STATUS_BLOCK packet;
    HANDLE duplicate, event;
    struct rig rig;

    if (!rig_open(&rig, W("\\??\\pipe\\prstest_cc_ev"), TRUE))
        return;
    event = CreateEventW(NULL, TRUE, FALSE, NULL); /* manual reset, clear */
    ok(event != NULL, "CreateEventW");
    rig_park_read(&rig, event, TRUE);

    duplicate = dup_into(child, rig.server);
    NtClose(rig.server);

    ok(!take_packet(rig.port, &key, &value, &packet),
       "a read carrying an EVENT was cancelled by the close");
    ok(!is_signaled(event), "the event was signalled, so the read was cancelled");
    ok(rig.io.Status == IOSB_POISON_STATUS, "the read's IOSB was written: %08lx",
       (unsigned long)rig.io.Status);

    reclaim_and_close(child, duplicate);
    if (event)
        NtClose(event);
    rig_close(&rig);
}

/* §4 — NO ApcContext, NO SWEEP. The event is there only so the case has
 * something to watch: with no ApcContext there could be no packet either way,
 * so an implementation that swept here would show up as a signalled event and
 * a written IOSB rather than as a missing assertion. */
static void test_no_apc_context_no_sweep(HANDLE child)
{
    HANDLE duplicate, event;
    struct rig rig;

    if (!rig_open(&rig, W("\\??\\pipe\\prstest_cc_noctx"), TRUE))
        return;
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(event != NULL, "CreateEventW");
    rig_park_read(&rig, event, FALSE);

    duplicate = dup_into(child, rig.server);
    NtClose(rig.server);

    ok(!is_signaled(event), "a read with no ApcContext was cancelled by the close");
    ok(rig.io.Status == IOSB_POISON_STATUS, "the read's IOSB was written: %08lx",
       (unsigned long)rig.io.Status);

    reclaim_and_close(child, duplicate);
    if (event)
        NtClose(event);
    rig_close(&rig);
}

/* §5 — NO PORT, NO SWEEP. ApcContext and no event, i.e. the two terms §1
 * satisfies, on a handle that was never bound to a completion port. Nothing
 * observes a cancel here but the caller's own IOSB, and that is the point:
 * this is the shape of every overlapped read a program issues without a port. */
static void test_an_unbound_handle_is_not_swept(HANDLE child)
{
    HANDLE duplicate;
    struct rig rig;

    if (!rig_open(&rig, W("\\??\\pipe\\prstest_cc_noport"), FALSE))
        return;
    rig_park_read(&rig, NULL, TRUE);

    duplicate = dup_into(child, rig.server);
    NtClose(rig.server);

    ok(rig.io.Status == IOSB_POISON_STATUS,
       "a read on a port-less handle was cancelled by the close: %08lx",
       (unsigned long)rig.io.Status);

    reclaim_and_close(child, duplicate);
    rig_close(&rig);
}

/* §6 — THE INSTANT THE PORT IS READ. The read pends on an UNBOUND handle and
 * the port is bound while it is still parked; the packet a later completion
 * posts WOULD go to that port (sem_pipe/pending_packet.c §4 pins the late
 * re-read), and yet this sweep does not take the request — because it reads
 * `async->completion`, the value captured at ISSUE.
 *
 * An implementation that answers "is this request port-bound" the same way it
 * answers "which port gets the packet" passes §1 through §5 and fails only
 * here. */
static void test_a_port_bound_after_the_park_does_not_arm_it(HANDLE child)
{
    ULONG_PTR key, value;
    IO_STATUS_BLOCK packet;
    HANDLE duplicate;
    struct rig rig;
    NTSTATUS status;

    if (!rig_open(&rig, W("\\??\\pipe\\prstest_cc_late"), FALSE))
        return;
    rig_park_read(&rig, NULL, TRUE);

    status = bind_port(rig.server, rig.port);
    ok(status == STATUS_SUCCESS, "bind after the park -> %08lx", (unsigned long)status);

    duplicate = dup_into(child, rig.server);
    NtClose(rig.server);

    ok(!take_packet(rig.port, &key, &value, &packet),
       "a port bound AFTER the park armed the close-cancel");
    ok(rig.io.Status == IOSB_POISON_STATUS, "the read's IOSB was written: %08lx",
       (unsigned long)rig.io.Status);

    reclaim_and_close(child, duplicate);
    rig_close(&rig);
}

/* §7 — THE PARKED LISTEN takes the same rule. The sweep is over the process's
 * asyncs on the object, not over one queue, so a pended FSCTL_PIPE_LISTEN is
 * cancelled by exactly the same close under exactly the same three terms — and
 * an implementation that hung the sweep off the read path alone answers §1 and
 * nothing here. */
static void test_a_parked_listen_takes_the_same_rule(HANDLE child)
{
    IO_STATUS_BLOCK iosb, createIosb, packet;
    HANDLE server = NULL, port = NULL, duplicate;
    ULONG_PTR key, value;
    NTSTATUS status;

    status = NtCreateIoCompletion(&port, IO_COMPLETION_ALL_ACCESS, NULL, 0);
    ok(status == STATUS_SUCCESS, "create port -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status =
        create_pipe_instance_async(&server, W("\\??\\pipe\\prstest_cc_listen"), 1, &createIosb);
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(port);
        return;
    }
    status = bind_port(server, port);
    ok(status == STATUS_SUCCESS, "bind -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    status = NtFsControlFile(server, NULL, NULL, &iosb, &iosb, FSCTL_PIPE_LISTEN, NULL, 0, NULL, 0);
    ok(status == STATUS_PENDING, "async listen -> %08lx", (unsigned long)status);

    duplicate = dup_into(child, server);
    NtClose(server);

    ok(take_packet(port, &key, &value, &packet), "no packet for a swept parked LISTEN");
    ok(key == TEST_KEY, "packet key %llx", (unsigned long long)key);
    ok(value == (ULONG_PTR)&iosb, "packet value %llx", (unsigned long long)value);
    ok(packet.Status == STATUS_CANCELLED, "packet status %08lx", (unsigned long)packet.Status);
    ok(iosb.Status == STATUS_CANCELLED, "cancelled listen iosb %08lx", (unsigned long)iosb.Status);

    reclaim_and_close(child, duplicate);
    NtClose(port);
}

START_TEST(close_cancel)
{
    HANDLE child;

    if (wstr_find(GetCommandLineW(), CHILD_MARKER))
    {
        /* Nothing to do but hold whatever the parent duplicates in. The parent
         * kills it when the last case is done; the sleep is only a ceiling for
         * a parent that died first. */
        Sleep(60000);
        ntapi_exit(0);
    }

    child = spawn_child();
    ok(child != NULL, "spawn the handle-holding child");
    if (child == NULL)
        return;

    test_the_process_last_handle_cancels(child);
    test_a_second_handle_here_leaves_it_alone(child);
    test_an_event_disarms_the_sweep(child);
    test_no_apc_context_no_sweep(child);
    test_an_unbound_handle_is_not_swept(child);
    test_a_port_bound_after_the_park_does_not_arm_it(child);
    test_a_parked_listen_takes_the_same_rule(child);

    NtTerminateProcess(child, 0);
    WaitForSingleObject(child, 10000);
    NtClose(child);
}
