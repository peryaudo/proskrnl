/*
 * sem_pipe/pending_packet.c — a request that PENDED posts its completion
 * packet when it completes, from whichever context completes it.
 *
 * sem_pipe/completion_packet.c pins the INLINE tail: an operation that
 * finishes inside the syscall posts a packet, and
 * FILE_SKIP_COMPLETION_PORT_ON_SUCCESS suppresses it. This file pins the
 * other half of that same axis — the one the flag's name gets wrong. The
 * oracle's guards are
 *
 *   dlls/ntdll/unix/file.c   add_completion( ..., ret_status == STATUS_PENDING )
 *   server/fd.c    add_fd_completion:  `req->async ||  !(comp_flags & SKIP…)`
 *   server/async.c async_set_result:   `async->pending || !(comp_flags & SKIP…)`
 *
 * so a request that reported STATUS_PENDING to its caller posts
 * unconditionally: the flag term is on the OTHER side of the `||`. That is
 * not a nicety — a caller holding ERROR_IO_PENDING has nothing else to wait
 * on, so a kernel that skips here hangs GetQueuedCompletionStatus forever.
 *
 * And the outer guard in async_set_result is `async->pending || !NT_ERROR(
 * status)`, so a pended request posts for EVERY outcome, a cancel included —
 * the packet reports the failure rather than being withheld by it.
 *
 * The only thing that pends at this boundary today is FSCTL_PIPE_LISTEN on
 * an asynchronous handle (kernel/io/async.c; sem_pipe/async_listen.c pins the
 * park itself), so that is the verb every case below drives.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtCreateIoCompletion(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
NTSYSAPI NTSTATUS NTAPI NtRemoveIoCompletion(HANDLE, PULONG_PTR, PULONG_PTR, PIO_STATUS_BLOCK,
                                             PLARGE_INTEGER);

typedef struct
{
    HANDLE CompletionPort;
    ULONG_PTR CompletionKey;
} SEM_FILE_COMPLETION_INFORMATION;

typedef struct
{
    ULONG Flags;
} SEM_FILE_IO_COMPLETION_NOTIFICATION_INFORMATION;

#ifndef FileCompletionInformation
#define FileCompletionInformation 30
#endif
#ifndef FileIoCompletionNotificationInformation
#define FileIoCompletionNotificationInformation 41
#endif
#ifndef FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
#define FILE_SKIP_COMPLETION_PORT_ON_SUCCESS 0x1
#endif

#define TEST_KEY ((ULONG_PTR)0xc0ffee01)

static DWORD WINAPI connect_after_delay(void *param)
{
    IO_STATUS_BLOCK iosb;
    HANDLE client = NULL;

    Sleep(300);
    ok(open_pipe_client(&client, param, &iosb) == STATUS_SUCCESS, "thread connect");
    return (DWORD)(ULONG_PTR)client; /* only null-checked by the callers */
}

static NTSTATUS bind_port(HANDLE file, HANDLE port)
{
    SEM_FILE_COMPLETION_INFORMATION info;
    IO_STATUS_BLOCK iosb;
    info.CompletionPort = port;
    info.CompletionKey = TEST_KEY;
    return NtSetInformationFile(file, &iosb, &info, sizeof(info), FileCompletionInformation);
}

/* Is a packet there RIGHT NOW? Zero timeout: used only where the answer must
 * be "no", so waiting would prove nothing. */
static BOOLEAN packet_waiting(HANDLE port)
{
    IO_STATUS_BLOCK iosb;
    ULONG_PTR key = 0, value = 0;
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    return NtRemoveIoCompletion(port, &key, &value, &iosb, &zero) == STATUS_SUCCESS;
}

/* Wait up to 10 s for one packet — the completion here happens on ANOTHER
 * thread (the connector's open, or a cancel), so unlike the inline file this
 * one has to wait rather than poll once. */
static BOOLEAN take_packet(HANDLE port, ULONG_PTR *keyOut, ULONG_PTR *valueOut,
                           IO_STATUS_BLOCK *iosbOut)
{
    LARGE_INTEGER timeout;
    timeout.QuadPart = -10000LL * 10000; /* 10 s, relative */
    *keyOut = 0;
    *valueOut = 0;
    return NtRemoveIoCompletion(port, keyOut, valueOut, iosbOut, &timeout) == STATUS_SUCCESS;
}

/* Case 1: the plain shape. A listen parks, a client connects on another
 * thread, and the packet appears with the bind's KEY and the caller's
 * ApcContext as its VALUE — the same two fields an inline completion carries,
 * produced from a context that is not the issuer's. */
static void test_pended_listen_posts(void)
{
    IO_STATUS_BLOCK iosb, createIosb, packetIosb;
    HANDLE server = NULL, port = NULL, thread;
    ULONG_PTR key, value;
    NTSTATUS status;
    DWORD wait, client = 0;

    status = NtCreateIoCompletion(&port, IO_COMPLETION_ALL_ACCESS, NULL, 0);
    ok(status == STATUS_SUCCESS, "create port -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    status = create_pipe_instance_async(&server, W("\\??\\pipe\\prstest_ppend"), 1, &createIosb);
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = bind_port(server, port);
    ok(status == STATUS_SUCCESS, "bind -> %08lx", (unsigned long)status);

    thread = CreateThread(NULL, 0, connect_after_delay, W("\\??\\pipe\\prstest_ppend"), 0, NULL);
    ok(thread != NULL, "CreateThread");

    /* No event: the port IS the completion signal here, which is the shape
     * ntdll:pipe's test_completion drives. ApcContext is the IOSB, as every
     * Win32 OVERLAPPED caller passes it — a NULL context would mean "post
     * nothing" (the cvalue rule, sem_pipe/completion_packet.c). */
    poison_iosb(&iosb);
    status = NtFsControlFile(server, NULL, NULL, &iosb, &iosb, FSCTL_PIPE_LISTEN, NULL, 0, NULL, 0);
    ok(status == STATUS_PENDING, "async listen -> %08lx", (unsigned long)status);
    ok(!packet_waiting(port), "a packet was posted while the request was still parked");

    ok(take_packet(port, &key, &value, &packetIosb), "no packet for a completed pended listen");
    ok(key == TEST_KEY, "packet key %llx", (unsigned long long)key);
    ok(value == (ULONG_PTR)&iosb, "packet value %llx want %llx", (unsigned long long)value,
       (unsigned long long)(ULONG_PTR)&iosb);
    ok(packetIosb.Status == STATUS_SUCCESS, "packet status %08lx",
       (unsigned long)packetIosb.Status);
    ok(packetIosb.Information == 0, "packet information %llx",
       (unsigned long long)packetIosb.Information);
    /* The IOSB is written too: the packet is an ADDITIONAL completion signal,
     * not a substitute for the block the caller passed. */
    ok(iosb.Status == STATUS_SUCCESS, "completed listen iosb -> %08lx", (unsigned long)iosb.Status);

    wait = WaitForSingleObject(thread, 10000);
    ok(wait == WAIT_OBJECT_0, "connector join");
    GetExitCodeThread(thread, &client);
    CloseHandle(thread);
    if (client)
        NtClose((HANDLE)(ULONG_PTR)client);
    NtClose(server);
    NtClose(port);
}

/* Case 2: THE AXIS. Same shape with FILE_SKIP_COMPLETION_PORT_ON_SUCCESS set
 * on the handle. The flag does NOT apply, because the call reported
 * STATUS_PENDING — read as "skip when it succeeded", this case posts nothing
 * and the caller waits forever. */
static void test_skip_flag_does_not_apply_to_a_pended_request(void)
{
    SEM_FILE_IO_COMPLETION_NOTIFICATION_INFORMATION notify;
    IO_STATUS_BLOCK iosb, createIosb, packetIosb;
    HANDLE server = NULL, port = NULL, thread;
    ULONG_PTR key, value;
    NTSTATUS status;
    DWORD wait, client = 0;

    status = NtCreateIoCompletion(&port, IO_COMPLETION_ALL_ACCESS, NULL, 0);
    ok(status == STATUS_SUCCESS, "create port -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    status = create_pipe_instance_async(&server, W("\\??\\pipe\\prstest_pskip"), 1, &createIosb);
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = bind_port(server, port);
    ok(status == STATUS_SUCCESS, "bind -> %08lx", (unsigned long)status);

    notify.Flags = FILE_SKIP_COMPLETION_PORT_ON_SUCCESS;
    status = NtSetInformationFile(server, &createIosb, &notify, sizeof(notify),
                                  FileIoCompletionNotificationInformation);
    ok(status == STATUS_SUCCESS, "set skip -> %08lx", (unsigned long)status);

    thread = CreateThread(NULL, 0, connect_after_delay, W("\\??\\pipe\\prstest_pskip"), 0, NULL);
    ok(thread != NULL, "CreateThread");

    poison_iosb(&iosb);
    status = NtFsControlFile(server, NULL, NULL, &iosb, &iosb, FSCTL_PIPE_LISTEN, NULL, 0, NULL, 0);
    ok(status == STATUS_PENDING, "async listen under the skip flag -> %08lx",
       (unsigned long)status);

    ok(take_packet(port, &key, &value, &packetIosb),
       "the skip flag suppressed a PENDED request's packet");
    ok(key == TEST_KEY, "packet key %llx", (unsigned long long)key);
    ok(value == (ULONG_PTR)&iosb, "packet value %llx", (unsigned long long)value);
    ok(packetIosb.Status == STATUS_SUCCESS, "packet status %08lx",
       (unsigned long)packetIosb.Status);

    wait = WaitForSingleObject(thread, 10000);
    ok(wait == WAIT_OBJECT_0, "connector join");
    GetExitCodeThread(thread, &client);
    CloseHandle(thread);
    if (client)
        NtClose((HANDLE)(ULONG_PTR)client);
    NtClose(server);
    NtClose(port);
}

/* Case 3: a CANCELLED pended request posts too, carrying the failure. The
 * outer guard is `async->pending || !NT_ERROR(status)` — pendedness alone
 * satisfies it, so the error does not withhold the packet. A kernel that
 * posts only on success leaves a cancelling caller waiting on a port for a
 * request it has already torn down. */
static void test_cancelled_pended_request_posts(void)
{
    IO_STATUS_BLOCK iosb, createIosb, cancelIosb, packetIosb;
    HANDLE server = NULL, port = NULL;
    ULONG_PTR key, value;
    NTSTATUS status;

    status = NtCreateIoCompletion(&port, IO_COMPLETION_ALL_ACCESS, NULL, 0);
    ok(status == STATUS_SUCCESS, "create port -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    status = create_pipe_instance_async(&server, W("\\??\\pipe\\prstest_pcancel"), 1, &createIosb);
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = bind_port(server, port);
    ok(status == STATUS_SUCCESS, "bind -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    status = NtFsControlFile(server, NULL, NULL, &iosb, &iosb, FSCTL_PIPE_LISTEN, NULL, 0, NULL, 0);
    ok(status == STATUS_PENDING, "async listen -> %08lx", (unsigned long)status);

    poison_iosb(&cancelIosb);
    status = NtCancelIoFile(server, &cancelIosb);
    ok(status == STATUS_SUCCESS, "cancel -> %08lx", (unsigned long)status);

    ok(take_packet(port, &key, &value, &packetIosb), "no packet for a CANCELLED pended listen");
    ok(key == TEST_KEY, "packet key %llx", (unsigned long long)key);
    ok(value == (ULONG_PTR)&iosb, "packet value %llx", (unsigned long long)value);
    ok(packetIosb.Status == STATUS_CANCELLED, "packet status %08lx",
       (unsigned long)packetIosb.Status);

    NtClose(server);
    NtClose(port);
}

/* Case 4: the port is resolved LATE. A listen pends on an unbound handle,
 * the port is bound while it is still parked, and the packet arrives anyway —
 * so "which port" is answered at completion, not at issue. The oracle says
 * both: `create_async` takes the fd's port up front, and
 * `add_async_completion` looks again when there was none
 * (`if (async->fd && !async->completion)`, server/async.c). Since a bind is
 * once-only, the late read subsumes the early capture. This case is why
 * IOP_PENDING_REQUEST holds a referenced FILE_OBJECT rather than a captured
 * port: a request that captured nothing at issue has nowhere to look later. */
static void test_port_bound_after_the_request_pended(void)
{
    IO_STATUS_BLOCK iosb, createIosb, packetIosb;
    HANDLE server = NULL, port = NULL, thread;
    ULONG_PTR key, value;
    NTSTATUS status;
    DWORD wait, client = 0;

    status = NtCreateIoCompletion(&port, IO_COMPLETION_ALL_ACCESS, NULL, 0);
    ok(status == STATUS_SUCCESS, "create port -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    status = create_pipe_instance_async(&server, W("\\??\\pipe\\prstest_plate"), 1, &createIosb);
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    thread = CreateThread(NULL, 0, connect_after_delay, W("\\??\\pipe\\prstest_plate"), 0, NULL);
    ok(thread != NULL, "CreateThread");

    poison_iosb(&iosb);
    status = NtFsControlFile(server, NULL, NULL, &iosb, &iosb, FSCTL_PIPE_LISTEN, NULL, 0, NULL, 0);
    ok(status == STATUS_PENDING, "async listen on an unbound handle -> %08lx",
       (unsigned long)status);

    /* The bind lands while the request is parked. */
    status = bind_port(server, port);
    ok(status == STATUS_SUCCESS, "bind after the pend -> %08lx", (unsigned long)status);

    ok(take_packet(port, &key, &value, &packetIosb),
       "no packet for a request that pended BEFORE the bind");
    ok(key == TEST_KEY, "packet key %llx", (unsigned long long)key);
    ok(value == (ULONG_PTR)&iosb, "packet value %llx", (unsigned long long)value);
    ok(packetIosb.Status == STATUS_SUCCESS, "packet status %08lx",
       (unsigned long)packetIosb.Status);

    wait = WaitForSingleObject(thread, 10000);
    ok(wait == WAIT_OBJECT_0, "connector join");
    GetExitCodeThread(thread, &client);
    CloseHandle(thread);
    if (client)
        NtClose((HANDLE)(ULONG_PTR)client);
    NtClose(server);
    NtClose(port);
}

START_TEST(pending_packet)
{
    test_pended_listen_posts();
    test_skip_flag_does_not_apply_to_a_pended_request();
    test_cancelled_pended_request_posts();
    test_port_bound_after_the_request_pended();
}
