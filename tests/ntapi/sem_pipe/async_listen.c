/*
 * sem_pipe/async_listen.c — FSCTL_PIPE_LISTEN on an asynchronous handle
 * genuinely pends (CUI-3), and NtCancelIoFile(Ex) tears a pending listen
 * down. This is the exact shape rpcrt4's ncacn_np server loop drives
 * (dlls/rpcrt4/rpc_transport.c rpcrt4_protseq_np_get_wait_array): issue the
 * listen with an event, expect STATUS_PENDING with the IOSB untouched, wait
 * on the event, read the verdict from the IOSB. Data reads/writes on the
 * same overlapped handles pass a NULL ByteOffset (streams have no
 * position), which must not be rejected.
 */
#include "util.h"

static DWORD WINAPI connect_after_delay(void *param)
{
    IO_STATUS_BLOCK iosb;
    HANDLE client = NULL;
    NTSTATUS status;

    Sleep(300);
    status = open_pipe_client(&client, param, &iosb);
    ok(status == STATUS_SUCCESS, "thread connect -> %08lx", (unsigned long)status);
    return (DWORD)(ULONG_PTR)client; /* handle values fit 32 bits in practice;
                                      * the callers only null-check */
}

static void test_pending_listen(void)
{
    IO_STATUS_BLOCK iosb, iosb2;
    HANDLE server = NULL, event, thread;
    NTSTATUS status;
    DWORD wait, client;

    status = create_pipe_instance_async(&server, W("\\??\\pipe\\prstest_alisten"), 1, &iosb);
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);

    /* The event goes in PRE-SIGNALLED: submission must reset it (the NT
     * contract rpcrt4's server leans on — it caches MANUAL-RESET events and
     * never resets them itself, get_np_event/release_np_event in
     * dlls/rpcrt4/rpc_transport.c; a stale signalled event would fire the
     * accept loop against a stale IOSB forever). */
    event = CreateEventW(NULL, TRUE, TRUE, NULL);
    ok(event != NULL, "CreateEventW");

    thread = CreateThread(NULL, 0, connect_after_delay, W("\\??\\pipe\\prstest_alisten"), 0, NULL);
    ok(thread != NULL, "CreateThread");

    /* The listen pends: PENDING comes back immediately, the IOSB is not
     * written until completion, and the pre-set event was RESET at submit. */
    poison_iosb(&iosb);
    status = NtFsControlFile(server, event, NULL, NULL, &iosb, FSCTL_PIPE_LISTEN, NULL, 0, NULL, 0);
    ok(status == STATUS_PENDING, "async listen -> %08lx", (unsigned long)status);
    ok(iosb.Status == IOSB_POISON_STATUS, "iosb untouched while pending, got %08lx",
       (unsigned long)iosb.Status);
    ok(iosb.Information == (ULONG_PTR)~0ULL, "iosb length untouched while pending");
    wait = WaitForSingleObject(event, 0);
    todo_proskrnl
    {
        ok(wait == WAIT_TIMEOUT, "event reset at submission -> %lu", (unsigned long)wait);
    }

    /* The client's connect completes the listen: event signalled, IOSB
     * carries the verdict (same on both sides — a blocking kernel signals
     * the event at synchronous completion too). */
    wait = WaitForSingleObject(event, 10000);
    ok(wait == WAIT_OBJECT_0, "listen completion wait -> %lu", (unsigned long)wait);
    ok(iosb.Status == STATUS_SUCCESS, "completed listen iosb -> %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 0, "completed listen length %lu", (unsigned long)iosb.Information);

    wait = WaitForSingleObject(thread, 10000);
    ok(wait == WAIT_OBJECT_0, "connector join");
    ok(GetExitCodeThread(thread, &client) && client != 0, "connector had a handle");
    CloseHandle(thread);

    /* Listening again while connected answers synchronously. */
    poison_iosb(&iosb2);
    status =
        NtFsControlFile(server, event, NULL, NULL, &iosb2, FSCTL_PIPE_LISTEN, NULL, 0, NULL, 0);
    ok(status == STATUS_PIPE_CONNECTED, "listen-when-connected -> %08lx", (unsigned long)status);

    if (client)
        NtClose((HANDLE)(ULONG_PTR)client);
    CloseHandle(event);
    NtClose(server);
}

static void test_overlapped_rw(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL, event;
    char buffer[8];
    NTSTATUS status;
    DWORD wait;

    status = create_pipe_instance_async(&server, W("\\??\\pipe\\prstest_arw"), 1, &iosb);
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_arw"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(event != NULL, "CreateEventW");

    /* rpcrt4's writes/reads on the overlapped handle pass NULL ByteOffset
     * (rpc_transport.c rpcrt4_conn_np_read/write): tolerated on a stream
     * device, synchronous completion allowed. */
    status = pipe_write(client, "ping", 4, &iosb);
    ok(status == STATUS_SUCCESS, "client write -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    status = NtReadFile(server, event, NULL, NULL, &iosb, buffer, 4, NULL, NULL);
    ok(status == STATUS_SUCCESS || status == STATUS_PENDING, "overlapped NULL-offset read -> %08lx",
       (unsigned long)status);
    if (status == STATUS_PENDING)
    {
        wait = WaitForSingleObject(event, 10000);
        ok(wait == WAIT_OBJECT_0, "read completion wait -> %lu", (unsigned long)wait);
    }
    ok(iosb.Status == STATUS_SUCCESS, "read iosb -> %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 4, "read length %lu", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "ping", 4) == 0, "read bytes");

    poison_iosb(&iosb);
    status = NtWriteFile(server, event, NULL, NULL, &iosb, "pong", 4, NULL, NULL);
    ok(status == STATUS_SUCCESS || status == STATUS_PENDING,
       "overlapped NULL-offset write -> %08lx", (unsigned long)status);
    if (status == STATUS_PENDING)
    {
        wait = WaitForSingleObject(event, 10000);
        ok(wait == WAIT_OBJECT_0, "write completion wait -> %lu", (unsigned long)wait);
    }
    ok(iosb.Status == STATUS_SUCCESS, "write iosb -> %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 4, "write length %lu", (unsigned long)iosb.Information);
    status = pipe_read(client, buffer, 4, &iosb);
    ok(status == STATUS_SUCCESS, "client read-back -> %08lx", (unsigned long)status);
    ok(memcmp(buffer, "pong", 4) == 0, "read-back bytes");

    CloseHandle(event);
    NtClose(client);
    NtClose(server);
}

/* Cancel a pending listen with the thread-scoped verb; the connector thread
 * is a safety net so an unimplemented cancel cannot hang the blocking-listen
 * kernel (the pin still convicts through the CANCELLED assertions). */
static void test_cancel(const void *pipe_name, BOOLEAN use_ex)
{
    IO_STATUS_BLOCK iosb, cancel_iosb;
    HANDLE server = NULL, event, thread;
    NTSTATUS status;
    DWORD wait, client;

    status = create_pipe_instance_async(&server, pipe_name, 1, &iosb);
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(event != NULL, "CreateEventW");
    thread = CreateThread(NULL, 0, connect_after_delay, (void *)pipe_name, 0, NULL);
    ok(thread != NULL, "CreateThread");

    poison_iosb(&iosb);
    status = NtFsControlFile(server, event, NULL, NULL, &iosb, FSCTL_PIPE_LISTEN, NULL, 0, NULL, 0);
    ok(status == STATUS_PENDING, "async listen -> %08lx", (unsigned long)status);

    poison_iosb(&cancel_iosb);
    if (use_ex)
        status = NtCancelIoFileEx(server, &iosb, &cancel_iosb);
    else
        status = NtCancelIoFile(server, &cancel_iosb);
    ok(status == STATUS_SUCCESS, "cancel -> %08lx", (unsigned long)status);
    ok(cancel_iosb.Status == STATUS_SUCCESS, "cancel iosb -> %08lx",
       (unsigned long)cancel_iosb.Status);
    ok(cancel_iosb.Information == 0, "cancel iosb length");

    wait = WaitForSingleObject(event, 10000);
    ok(wait == WAIT_OBJECT_0, "cancelled listen wait -> %lu", (unsigned long)wait);
    ok(iosb.Status == STATUS_CANCELLED, "cancelled listen iosb -> %08lx",
       (unsigned long)iosb.Status);

    /* The connector still lands: a canceled listen leaves the instance
     * accepting (connect-before-listen semantics). */
    wait = WaitForSingleObject(thread, 10000);
    ok(wait == WAIT_OBJECT_0, "connector join");
    ok(GetExitCodeThread(thread, &client) && client != 0, "connector had a handle");
    CloseHandle(thread);
    if (client)
        NtClose((HANDLE)(ULONG_PTR)client);
    CloseHandle(event);
    NtClose(server);
}

static void test_cancel_nothing_pending(void)
{
    IO_STATUS_BLOCK iosb, cancel_iosb;
    HANDLE server = NULL;
    NTSTATUS status;

    status = create_pipe_instance_async(&server, W("\\??\\pipe\\prstest_acnone"), 1, &iosb);
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);

    /* Thread-scoped cancel with nothing pending still succeeds; the Ex form
     * (all threads / by IOSB) answers NOT_FOUND — both through the cancel
     * call's own IOSB (wine/dlls/ntdll/unix/file.c cancel_io +
     * server/async.c DECL_HANDLER(cancel_async)). */
    poison_iosb(&cancel_iosb);
    status = NtCancelIoFile(server, &cancel_iosb);
    ok(status == STATUS_SUCCESS, "cancel-nothing -> %08lx", (unsigned long)status);
    ok(cancel_iosb.Status == STATUS_SUCCESS, "cancel-nothing iosb -> %08lx",
       (unsigned long)cancel_iosb.Status);
    poison_iosb(&cancel_iosb);
    status = NtCancelIoFileEx(server, NULL, &cancel_iosb);
    ok(status == STATUS_NOT_FOUND, "cancel-ex-nothing -> %08lx", (unsigned long)status);
    ok(cancel_iosb.Status == STATUS_NOT_FOUND, "cancel-ex-nothing iosb -> %08lx",
       (unsigned long)cancel_iosb.Status);
    NtClose(server);
}

START_TEST(async_listen)
{
    test_pending_listen();
    test_overlapped_rw();
    test_cancel(W("\\??\\pipe\\prstest_acancel"), FALSE);
    test_cancel(W("\\??\\pipe\\prstest_acancel2"), TRUE);
    test_cancel_nothing_pending();
}
