/*
 * sem_pipe/alertable_park.c — what FILE_SYNCHRONOUS_IO_ALERT does to a
 * request that PARKS its caller.
 *
 * sem_pipe/blocking_signal.c pinned what a blocking request owes the event
 * and the file object; this pins the other half of "blocking" — HOW the
 * caller waits. The oracle states it in one argument:
 *
 *   dlls/ntdll/unix/file.c  server_ioctl_file:
 *       if (wait_handle) status = wait_async( wait_handle,
 *                                             (options & FILE_SYNCHRONOUS_IO_ALERT) );
 *   dlls/ntdll/unix/unix_private.h  wait_async:
 *       return server_wait_for_object( handle, alertable, NULL );
 *
 * — i.e. the park is an ALERTABLE wait exactly when the handle carries
 * FILE_SYNCHRONOUS_IO_ALERT, and the identical line sits on the read and
 * write paths too (server_read_file file.c:5746, server_write_file :5781,
 * server_ioctl_file :5823). So a user APC breaks the park of every
 * synchronous request on such a handle and none on a
 * FILE_SYNCHRONOUS_IO_NONALERT one. NtFlushBuffersFileEx is the oracle's own
 * exception — it passes a literal FALSE (:6876) — so a flush is NOT covered
 * here and proskrnl matches that at the site (kernel/io/rw.c).
 *
 * What the interrupted request leaves behind is the half that does not
 * follow from "the wait was alertable", and it is what the cases below
 * actually measure: the client stopped waiting, so NOTHING completed — the
 * IOSB is untouched, the completion APC never runs, and the caller's event
 * is left where the ISSUE put it rather than signalled.
 *
 * ntdll:pipe's test_alertable (pipe.c:457) is the winetest consumer, and it
 * is where the pair wedged: a listen parked non-alertably on a
 * FILE_SYNCHRONOUS_IO_ALERT handle with no client coming never returns.
 *
 * EVERY case here starts a rescue worker that eventually performs the peer
 * operation the park is waiting for, so a kernel that never breaks the park
 * FAILS AN ASSERTION rather than costing the leg its timeout (docs/21 W10
 * lesson 2). The corollary is that the state each case reads must be read
 * BEFORE the rescue lands — and, on the oracle, an interrupted async stays
 * QUEUED in the server and completes into the caller's IOSB when the rescue
 * connects, so every block that can be written late is a per-case STATIC
 * rather than a stack local (a dead frame would be written otherwise).
 */
#include "util.h"

typedef VOID(NTAPI *pipe_apcfunc)(ULONG_PTR, ULONG_PTR, ULONG_PTR);
NTSYSAPI NTSTATUS NTAPI NtQueueApcThread(HANDLE, pipe_apcfunc, ULONG_PTR, ULONG_PTR, ULONG_PTR);

/* The current-thread pseudo-handle, spelled here because mingw's headers
 * define it as a macro only for the Win32 spelling. The value is NT's, cited
 * to Microsoft's NtCurrentThread documentation ((HANDLE)-2) — the same
 * citation sem_wait/pseudo_handle_multi.c carries for the whole family. */
#ifndef NtCurrentThread
#define NtCurrentThread() ((HANDLE)(LONG_PTR) - 2)
#endif

/* How long a rescue worker waits before releasing the park. Long enough that
 * a correct kernel has answered the APC and read every state below it — a
 * handful of cheap assertions, i.e. microseconds — and short enough that a
 * wrong kernel still ends in an assertion. Kept DOWN on purpose: every case
 * here is a SLEEPING case, and the oracle leg fans its tests out one worker
 * each, so a slow test does not merely cost its own seconds, it reshards what
 * runs beside it. A first draft at 1200 ms reliably reddened sem_ps/times (an
 * idle-time assertion) in the full sweep while passing on its own — a
 * perturbation with no semantic content whatever. */
#define RESCUE_MS 500
/* When a worker has to queue the APC into an already-parked main thread; the
 * main thread reaches that park in well under a millisecond. */
#define APC_DELAY_MS   150
#define WORKER_WAIT_MS 10000

static BOOLEAN is_signaled(HANDLE handle)
{
    return WaitForSingleObject(handle, 0) == WAIT_OBJECT_0;
}

/* One server-end instance on a handle whose synchronous option is the
 * caller's, which is the whole subject. Otherwise util.h's defaults. */
static NTSTATUS create_pipe_instance_mode(HANDLE *handle, const void *wide_name, ULONG options,
                                          IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    LARGE_INTEGER timeout;

    init_ustr(&name, wide_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    timeout.QuadPart = -100 * 10000; /* 100 ms, relative */
    *handle = NULL;
    return NtCreateNamedPipeFile(handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr, iosb,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, options,
                                 FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
                                 FILE_PIPE_QUEUE_OPERATION, 1, 4096, 4096, &timeout);
}

static NTSTATUS open_pipe_client_mode(HANDLE *handle, const void *wide_name, ULONG options,
                                      IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    init_ustr(&name, wide_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    *handle = NULL;
    return NtCreateFile(handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr, iosb, NULL,
                        FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE | options,
                        NULL, 0);
}

/* The mode word a handle reports, which is the ONE thing separating the two
 * synchronous options below the park. It is pinned here rather than left to
 * the narrative because npfs used not to record it at all: every pipe handle
 * answered 0, and an implementation that fixed only the park would keep
 * answering 0 while passing every other case in this file.
 * sem_file/async_inline.c pins the same class on DISK handles; a pipe reaches
 * it through a different construction site, which is exactly the drift
 * (kernel/io/file.c IopCaptureCreateOptions). */
static ULONG query_mode(HANDLE handle)
{
    FILE_MODE_INFORMATION mode;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    mode.Mode = 0;
    status = NtQueryInformationFile(handle, &iosb, &mode, sizeof(mode), FileModeInformation);
    ok(status == STATUS_SUCCESS, "query FileModeInformation -> %08lx", (unsigned long)status);
    return mode.Mode;
}

/* --- the rescue worker ---------------------------------------------------- */

typedef struct
{
    const void *name; /* pipe to connect to, or NULL for the write rescue */
    HANDLE peer;      /* the end to write on, for the read cases          */
    HANDLE apcTarget; /* queue the user APC here first, or NULL           */
    HANDLE sampled;   /* sample this event's state mid-park, or NULL      */
    HANDLE thread;
    NTSTATUS openStatus;
    HANDLE opened;
    BOOLEAN sawSampledSignaled;
} RESCUE;

static VOID NTAPI rescue_apc(ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3);

static DWORD WINAPI rescue_thread(void *param)
{
    RESCUE *job = param;
    IO_STATUS_BLOCK iosb;

    if (job->apcTarget != NULL)
    {
        Sleep(APC_DELAY_MS);
        /* Sampled BEFORE the APC lands, so it describes the park rather than
         * its end. */
        if (job->sampled != NULL)
            job->sawSampledSignaled = is_signaled(job->sampled);
        NtQueueApcThread(job->apcTarget, rescue_apc, 0, 0, 0);
    }
    Sleep(RESCUE_MS);
    if (job->name != NULL)
    {
        job->openStatus =
            open_pipe_client_mode(&job->opened, job->name, FILE_SYNCHRONOUS_IO_NONALERT, &iosb);
    }
    else if (job->peer != NULL)
    {
        job->openStatus = pipe_write(job->peer, "r", 1, &iosb);
    }
    return 0;
}

static RESCUE rescues[8];
static unsigned rescueCount;

static RESCUE *start_rescue(const void *name, HANDLE peer, HANDLE apcTarget, HANDLE sampled)
{
    RESCUE *job = &rescues[rescueCount++];
    job->name = name;
    job->peer = peer;
    job->apcTarget = apcTarget;
    job->sampled = sampled;
    job->sawSampledSignaled = TRUE;
    job->openStatus = (NTSTATUS)IOSB_POISON_STATUS;
    job->opened = NULL;
    job->thread = CreateThread(NULL, 0, rescue_thread, job, 0, NULL);
    return job;
}

static BOOLEAN finish_rescue(RESCUE *job)
{
    BOOLEAN done =
        job->thread != NULL && WaitForSingleObject(job->thread, WORKER_WAIT_MS) == WAIT_OBJECT_0;
    if (done)
    {
        CloseHandle(job->thread);
        job->thread = NULL;
    }
    if (job->opened != NULL)
    {
        NtClose(job->opened);
        job->opened = NULL;
    }
    return done;
}

/* A REAL handle to the calling thread, which is what a worker needs to queue
 * an APC into it — the pseudo-handle would name the WORKER. OpenThread by id
 * rather than NtDuplicateObject of the pseudo-handle, because that is the
 * idiom the winetest consumer uses (dlls/ntdll/tests/pipe.c test_alertable:
 * `pOpenThread(MAXIMUM_ALLOWED, FALSE, GetCurrentThreadId())`), so the pin
 * exercises the path the pair will. */
static HANDLE open_self(void)
{
    return OpenThread(THREAD_SET_CONTEXT, FALSE, GetCurrentThreadId());
}

/* --- the user APC and the completion APC ---------------------------------- */

static volatile LONG userApcCalls;
static VOID NTAPI rescue_apc(ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3)
{
    (void)a1;
    (void)a2;
    (void)a3;
    InterlockedIncrement(&userApcCalls);
}

/* One counter per case: on the oracle an interrupted async stays queued and
 * fires its completion routine when the rescue lands, which is INSIDE a
 * later case if the counter is shared. */
static volatile LONG ioApcCalls[4];

static VOID NTAPI io_apc_0(PVOID ctx, PIO_STATUS_BLOCK iosb, ULONG reserved)
{
    (void)ctx;
    (void)iosb;
    (void)reserved;
    InterlockedIncrement(&ioApcCalls[0]);
}
static VOID NTAPI io_apc_1(PVOID ctx, PIO_STATUS_BLOCK iosb, ULONG reserved)
{
    (void)ctx;
    (void)iosb;
    (void)reserved;
    InterlockedIncrement(&ioApcCalls[1]);
}
static VOID NTAPI io_apc_2(PVOID ctx, PIO_STATUS_BLOCK iosb, ULONG reserved)
{
    (void)ctx;
    (void)iosb;
    (void)reserved;
    InterlockedIncrement(&ioApcCalls[2]);
}

/* Run every APC the interrupted request left pending, so nothing this case
 * queued is delivered inside the next one. */
static void drain_apcs(void)
{
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    NtDelayExecution(TRUE, &zero);
}

/* Case 1: the APC is queued BEFORE the listen, so the park is never entered
 * — the alertable wait's entry check answers it. The IOSB, the completion
 * routine and the event are the measurement: an implementation that reported
 * the wait's status through the normal completion tail would write all three.
 *
 * The IOSB is static because the oracle's server keeps the async queued and
 * completes it into this very block when the rescue connects. */
static IO_STATUS_BLOCK case1Iosb;
static void test_alert_listen_with_apc_already_queued(void)
{
    IO_STATUS_BLOCK createIosb;
    HANDLE pipe = NULL, event;
    RESCUE *rescue;
    NTSTATUS status;
    ULONG mode;

    status = create_pipe_instance_mode(&pipe, W("\\??\\pipe\\prstest_alrt1"),
                                       FILE_SYNCHRONOUS_IO_ALERT, &createIosb);
    ok(status == STATUS_SUCCESS, "ALERT server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    mode = query_mode(pipe);
    ok(mode == FILE_SYNCHRONOUS_IO_ALERT, "ALERT pipe handle reports mode %08lx",
       (unsigned long)mode);

    event = CreateEventW(NULL, TRUE, FALSE, NULL); /* manual reset, born down */
    ok(event != NULL, "CreateEventW");

    rescue = start_rescue(W("\\??\\pipe\\prstest_alrt1"), NULL, NULL, NULL);
    ok(rescue->thread != NULL, "CreateThread");

    userApcCalls = 0;
    status = NtQueueApcThread(NtCurrentThread(), rescue_apc, 0, 0, 0);
    ok(status == STATUS_SUCCESS, "NtQueueApcThread -> %08lx", (unsigned long)status);

    poison_iosb(&case1Iosb);
    status = NtFsControlFile(pipe, event, io_apc_0, &case1Iosb, &case1Iosb, FSCTL_PIPE_LISTEN, NULL,
                             0, NULL, 0);
    ok(status == STATUS_USER_APC, "listen broken by a pending user APC -> %08lx",
       (unsigned long)status);
    ok(userApcCalls == 1, "the user APC ran %ld times", (long)userApcCalls);
    ok(case1Iosb.Status == (NTSTATUS)IOSB_POISON_STATUS,
       "an interrupted listen wrote the IOSB (%08lx)", (unsigned long)case1Iosb.Status);
    ok(ioApcCalls[0] == 0, "the completion routine ran for an interrupted listen");
    ok(!is_signaled(event), "an interrupted listen signalled the caller's event");

    ok(finish_rescue(rescue), "the rescue finished");
    drain_apcs();
    CloseHandle(event);
    NtClose(pipe);
}

/* Case 2: the APC arrives while the caller is ALREADY parked, which is the
 * case that measures the park itself rather than its entry check. The event
 * is born SIGNALLED, so what the ISSUE does to it is observable: the oracle
 * resets it in create_async (server/async.c) a frame above the queue, and
 * the interruption never puts it back up. */
static IO_STATUS_BLOCK case2Iosb;
static void test_alert_listen_interrupted_while_parked(void)
{
    IO_STATUS_BLOCK createIosb;
    HANDLE pipe = NULL, event, self;
    RESCUE *rescue;
    NTSTATUS status;

    status = create_pipe_instance_mode(&pipe, W("\\??\\pipe\\prstest_alrt2"),
                                       FILE_SYNCHRONOUS_IO_ALERT, &createIosb);
    ok(status == STATUS_SUCCESS, "ALERT server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    event = CreateEventW(NULL, TRUE, TRUE, NULL); /* manual reset, born signalled */
    ok(event != NULL, "CreateEventW");

    self = open_self();
    ok(self != NULL, "OpenThread on the current thread");

    rescue = start_rescue(W("\\??\\pipe\\prstest_alrt2"), NULL, self, event);
    ok(rescue->thread != NULL, "CreateThread");

    userApcCalls = 0;
    poison_iosb(&case2Iosb);
    status = NtFsControlFile(pipe, event, io_apc_1, &case2Iosb, &case2Iosb, FSCTL_PIPE_LISTEN, NULL,
                             0, NULL, 0);
    ok(status == STATUS_USER_APC, "parked listen broken by a user APC -> %08lx",
       (unsigned long)status);
    ok(userApcCalls == 1, "the user APC ran %ld times", (long)userApcCalls);
    ok(case2Iosb.Status == (NTSTATUS)IOSB_POISON_STATUS,
       "an interrupted listen wrote the IOSB (%08lx)", (unsigned long)case2Iosb.Status);
    ok(ioApcCalls[1] == 0, "the completion routine ran for an interrupted listen");
    ok(!is_signaled(event), "an interrupted listen left the caller's event signalled");

    ok(finish_rescue(rescue), "the rescue finished");
    /* WHERE the reset happens, sampled from the worker a whole second before
     * the interruption: the oracle's create_async resets the event at ISSUE
     * (server/async.c), so it is already down while the caller is still
     * parked. An implementation that only reset it on the way out of the
     * interrupted call passes every assertion above and fails this one. */
    ok(!rescue->sawSampledSignaled, "the caller's event was still signalled mid-park");
    drain_apcs();
    if (self != NULL)
        NtClose(self);
    CloseHandle(event);
    NtClose(pipe);
}

/* Case 3: the same APC against a FILE_SYNCHRONOUS_IO_NONALERT handle, which
 * is the discriminating half — the park is NOT alertable, so the listen runs
 * to its real completion and the APC waits for the caller's next alertable
 * point. An implementation that made every blocking park alertable passes
 * cases 1 and 2 and fails this one. */
static IO_STATUS_BLOCK case3Iosb;
static void test_nonalert_listen_ignores_the_apc(void)
{
    IO_STATUS_BLOCK createIosb;
    HANDLE pipe = NULL, event;
    RESCUE *rescue;
    NTSTATUS status;
    ULONG mode;

    status = create_pipe_instance_mode(&pipe, W("\\??\\pipe\\prstest_alrt3"),
                                       FILE_SYNCHRONOUS_IO_NONALERT, &createIosb);
    ok(status == STATUS_SUCCESS, "NONALERT server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    mode = query_mode(pipe);
    ok(mode == FILE_SYNCHRONOUS_IO_NONALERT, "NONALERT pipe handle reports mode %08lx",
       (unsigned long)mode);

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(event != NULL, "CreateEventW");

    rescue = start_rescue(W("\\??\\pipe\\prstest_alrt3"), NULL, NULL, NULL);
    ok(rescue->thread != NULL, "CreateThread");

    userApcCalls = 0;
    status = NtQueueApcThread(NtCurrentThread(), rescue_apc, 0, 0, 0);
    ok(status == STATUS_SUCCESS, "NtQueueApcThread -> %08lx", (unsigned long)status);

    poison_iosb(&case3Iosb);
    status = NtFsControlFile(pipe, event, io_apc_2, &case3Iosb, &case3Iosb, FSCTL_PIPE_LISTEN, NULL,
                             0, NULL, 0);
    ok(status == STATUS_SUCCESS, "NONALERT listen -> %08lx", (unsigned long)status);
    ok(userApcCalls == 0, "the user APC ran during a NONALERT park (%ld)", (long)userApcCalls);
    ok(case3Iosb.Status == STATUS_SUCCESS, "listen iosb.Status %08lx",
       (unsigned long)case3Iosb.Status);
    ok(is_signaled(event), "a completed listen did not signal the caller's event");
    /* The completion ROUTINE is a user APC too, so a listen that completes on
     * a NONALERT handle has not run it either when the syscall returns — the
     * first draft asserted it had, and the oracle refuted that. Both are
     * pending here and both are delivered by the poll below, which is why
     * this case can state the ordering rather than just the counts. */
    ok(ioApcCalls[2] == 0, "the completion routine ran before an alertable point (%ld)",
       (long)ioApcCalls[2]);

    /* Still pending, and delivered at the very next alertable point. */
    drain_apcs();
    ok(userApcCalls == 1, "the user APC did not run at the next alertable point (%ld)",
       (long)userApcCalls);
    ok(ioApcCalls[2] == 1, "the completion routine ran %ld times", (long)ioApcCalls[2]);

    ok(finish_rescue(rescue), "the rescue finished");
    CloseHandle(event);
    NtClose(pipe);
}

/* Case 4: the rule is the HANDLE's, not the verb's — a blocking READ on a
 * FILE_SYNCHRONOUS_IO_ALERT client handle is interrupted exactly as the
 * listen is (dlls/ntdll/unix/file.c:5746 carries the same argument as
 * :5823). An implementation that put the alertable park only under the ioctl
 * passes cases 1-3 and fails this one. */
static IO_STATUS_BLOCK case4Iosb;
static void test_alert_read_with_apc_already_queued(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    static char buffer[16];
    RESCUE *rescue;
    NTSTATUS status;
    ULONG mode;

    status = create_pipe_instance_mode(&server, W("\\??\\pipe\\prstest_alrt4"),
                                       FILE_SYNCHRONOUS_IO_NONALERT, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client_mode(&client, W("\\??\\pipe\\prstest_alrt4"),
                                   FILE_SYNCHRONOUS_IO_ALERT, &iosb);
    ok(status == STATUS_SUCCESS, "ALERT client open -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    /* The CLIENT end comes through IopCreateFile and the SERVER end through
     * NtCreateNamedPipeFile — the two construction sites — so asserting both
     * here is what says they agree. */
    mode = query_mode(client);
    ok(mode == FILE_SYNCHRONOUS_IO_ALERT, "ALERT client handle reports mode %08lx",
       (unsigned long)mode);

    rescue = start_rescue(NULL, server, NULL, NULL);
    ok(rescue->thread != NULL, "CreateThread");

    userApcCalls = 0;
    status = NtQueueApcThread(NtCurrentThread(), rescue_apc, 0, 0, 0);
    ok(status == STATUS_SUCCESS, "NtQueueApcThread -> %08lx", (unsigned long)status);

    poison_iosb(&case4Iosb);
    status = NtReadFile(client, NULL, NULL, NULL, &case4Iosb, buffer, sizeof(buffer), NULL, NULL);
    ok(status == STATUS_USER_APC, "ALERT read broken by a pending user APC -> %08lx",
       (unsigned long)status);
    ok(userApcCalls == 1, "the user APC ran %ld times", (long)userApcCalls);
    ok(case4Iosb.Status == (NTSTATUS)IOSB_POISON_STATUS,
       "an interrupted read wrote the IOSB (%08lx)", (unsigned long)case4Iosb.Status);

    ok(finish_rescue(rescue), "the rescue finished");
    drain_apcs();
    NtClose(client);
    NtClose(server);
}

START_TEST(alertable_park)
{
    test_alert_listen_with_apc_already_queued();
    test_alert_listen_interrupted_while_parked();
    test_nonalert_listen_ignores_the_apc();
    test_alert_read_with_apc_already_queued();
}
