/* tests/kmt/condrv_unwind.c — the condrv terminate-unwind state machine.
 *
 * WHAT THIS CONVICTS. A client verb parked in the console driver lives on the
 * PARKING THREAD'S KERNEL STACK (drivers/condrv.c CONDRV_REQUEST), so when
 * that thread's wait is aborted for termination (CUI-4), the unwind has to
 * make sure nothing conhost still owns points at it. The unwind therefore has
 * to answer "where is my request right now?", and the states are not two but
 * THREE: queued, delivered, and ALREADY COMPLETED — because the abort readies
 * the client without touching the console queues, and on this uniprocessor the
 * client does not run again until conhost parks, so conhost can fetch AND
 * complete the request inside that window. The unwind used to treat
 * not-`current` as still-linked and unlink unconditionally, which in the
 * completed state is a double-remove: the GUI-5 msg leg died there
 * (kernel/lib/list.h RemoveEntryList's neighbour assert, inside
 * test_WaitForInputIdle where the parent TerminateProcess's each child while
 * its console read is in flight — docs/03 "GUI-5 winetest notes").
 *
 * WHY IT IS DETERMINISTIC AND NOT A RACE HUNT. The kernel is cooperative
 * (Art. 3): a readied thread runs only once the running one parks. So the
 * window the defect lives in is not a lottery — it is reachable by
 * construction, and this test drives conhost's side itself over the real
 * \Device\ConDrv\Server transport (the kmt suites run before smss starts
 * conhost, so the single server slot is free). The abort is the same engine
 * KiAbortThreadWait uses (KiUnwaitThreadWithStatus, Art. 11: one authority),
 * so the client sees exactly the status a foreign TerminateProcess produces.
 *
 * AND WHY IT CANNOT GO INERT. A test that let the client resume before the
 * completion would exercise the queued state and pass on the broken kernel
 * too (docs/19 §8.4's correct-but-inert shape), so the ordering it depends on
 * is itself asserted: the client must still be un-resumed when the completion
 * has landed.
 */
#include "tests/kmt/kmt.h"
#include "kernel/ke/ke.h"
#include "kernel/io/io.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "drivers/condrvproto.h"

#include "abi/ntstatus.h"
#include "abi/ntioapi.h"
#include "abi/ntcondrv.h"

static void init_attr(OBJECT_ATTRIBUTES *attr, UNICODE_STRING *name, const WCHAR *path)
{
    RtlInitUnicodeString(name, path);
    attr->Length = sizeof(*attr);
    attr->RootDirectory = 0;
    attr->ObjectName = name;
    attr->Attributes = OBJ_CASE_INSENSITIVE;
    attr->SecurityDescriptor = 0;
    attr->SecurityQualityOfService = 0;
}

static NTSTATUS condrv_open(const WCHAR *path, HANDLE *handleOut)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;

    init_attr(&attr, &name, path);
    return NtCreateFile(handleOut, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &attr, &iosb, 0,
                        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                        FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
}

/* --- the client half: one blocking read verb, parked in the driver -------- */

typedef struct CONDRV_CLIENT
{
    HANDLE handle;
    volatile LONG resumed; /* set the instant the ioctl returns */
    NTSTATUS status;
} CONDRV_CLIENT;

static void condrv_client_thread(void *context)
{
    CONDRV_CLIENT *client = context;
    IO_STATUS_BLOCK iosb;
    char reply[32];

    /* The exact frame the msg leg panicked in: NtDeviceIoControlFile ->
     * IopDeviceControl -> CondrvConsoleDeviceControl -> CondrvForward. */
    NTSTATUS status = NtDeviceIoControlFile(client->handle, 0, 0, 0, &iosb, IOCTL_CONDRV_READ_FILE,
                                            0, 0, reply, (ULONG)sizeof(reply));
    client->resumed = 1;
    client->status = status;
}

/* conhost's fetch. Returns the delivered request's code, 0 if none is
 * deliverable yet — the client is READY but has not parked, so yield to it. */
static ULONG condrv_server_fetch(HANDLE server, uint64_t *idOut)
{
    static char buffer[CONDRV_SERVER_BUFFER_SIZE];
    IO_STATUS_BLOCK iosb;

    for (unsigned spin = 0; spin < 1000; spin++)
    {
        NTSTATUS status = NtReadFile(server, 0, 0, 0, &iosb, buffer, (ULONG)sizeof(buffer), 0, 0);
        if (status == STATUS_SUCCESS)
        {
            const CONDRV_SERVER_MSG *message = (const CONDRV_SERVER_MSG *)buffer;
            *idOut = message->id;
            return message->code;
        }
        if (status != STATUS_PENDING)
        {
            ok(0, "server fetch %#x", (unsigned)status);
            return 0;
        }
        KiYield();
    }
    return 0;
}

/* conhost's reply. read = 1 completes the oldest delivered blocking read
 * (condrvproto.h: the read_complete shape). */
static NTSTATUS condrv_server_reply(HANDLE server, uint64_t id, ULONG read, NTSTATUS status)
{
    static char buffer[sizeof(CONDRV_SERVER_REPLY) + 8];
    IO_STATUS_BLOCK iosb;
    CONDRV_SERVER_REPLY *reply = (CONDRV_SERVER_REPLY *)buffer;

    memset(buffer, 0, sizeof(buffer));
    reply->id = id;
    reply->status = status;
    reply->read = read;
    reply->outSize = 0;
    return NtWriteFile(server, 0, 0, 0, &iosb, buffer, (ULONG)sizeof(*reply), 0, 0);
}

/* Pull a parked client out of its wait exactly as a foreign terminate does
 * (kernel/ke/wait.c KiAbortThreadWait), leaving the console queues alone. The
 * state check is the same one the real abort makes: a client that already
 * returned is not parked, and every join below has to stay finite even when an
 * earlier assertion in this file has already failed. */
static void condrv_abort_wait(PKTHREAD thread)
{
    uint64_t flags = KiAcquireDispatcherLock();
    if (thread->state == KI_THREAD_STATE_WAITING)
    {
        KiUnwaitThreadWithStatus(thread, STATUS_THREAD_IS_TERMINATING);
    }
    KiReleaseDispatcherLock(flags);
}

static void join_and_delete(PKTHREAD thread)
{
    NTSTATUS status = KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, 0);
    ok(status == STATUS_SUCCESS, "join: got %#x", (unsigned)status);
    KiDeleteThread(thread);
}

/* --- the completed state: aborted, then completed before it ran ----------- */

static void test_condrv_unwind_after_completion(void)
{
    HANDLE server = 0;
    HANDLE input = 0;
    NTSTATUS status = condrv_open(WSTR("\\Device\\ConDrv\\Server"), &server);
    ok(status == STATUS_SUCCESS, "open server: %#x", (unsigned)status);
    if (status != STATUS_SUCCESS)
        return;
    status = condrv_open(WSTR("\\Device\\ConDrv\\Input"), &input);
    ok(status == STATUS_SUCCESS, "open input: %#x", (unsigned)status);
    if (status != STATUS_SUCCESS)
    {
        NtClose(server);
        return;
    }

    CONDRV_CLIENT client = {.handle = input, .resumed = 0, .status = STATUS_SUCCESS};
    PKTHREAD worker = KiCreateThread(8, condrv_client_thread, &client);

    /* Deliver it: a blocking-read code parks on the driver's read queue. */
    uint64_t id = 0;
    ULONG code = condrv_server_fetch(server, &id);
    ok(code == IOCTL_CONDRV_READ_FILE, "delivered code %#x", (unsigned)code);
    ok(client.resumed == 0, "client resumed before its request was delivered");

    if (code == IOCTL_CONDRV_READ_FILE)
    {
        /* The window: abort the wait, then complete the request. Both happen
         * before the client runs again — nothing here parks. */
        condrv_abort_wait(worker);
        status = condrv_server_reply(server, id, 1, STATUS_SUCCESS);
        ok(status == STATUS_SUCCESS, "read_complete: %#x", (unsigned)status);

        /* The inertness guard: if the client had already resumed, this test
         * would be exercising the QUEUED state and would pass on a kernel
         * whose unwind double-removes. */
        ok(client.resumed == 0, "client resumed before the completion landed — test is inert");
    }
    else
    {
        condrv_abort_wait(worker);
    }

    join_and_delete(worker);
    ok(client.status == STATUS_THREAD_IS_TERMINATING, "client saw %#x", (unsigned)client.status);

    /* The queues survived: a second round trip still works end to end. This
     * is what a double-remove would have destroyed had it not panicked. */
    CONDRV_CLIENT again = {.handle = input, .resumed = 0, .status = STATUS_SUCCESS};
    PKTHREAD second = KiCreateThread(8, condrv_client_thread, &again);
    id = 0;
    code = condrv_server_fetch(server, &id);
    ok(code == IOCTL_CONDRV_READ_FILE, "second delivered code %#x", (unsigned)code);
    if (code == IOCTL_CONDRV_READ_FILE)
    {
        status = condrv_server_reply(server, id, 1, STATUS_SUCCESS);
        ok(status == STATUS_SUCCESS, "second read_complete: %#x", (unsigned)status);
    }
    else
    {
        condrv_abort_wait(second);
    }
    join_and_delete(second);
    ok(again.status == STATUS_SUCCESS, "second client saw %#x", (unsigned)again.status);

    /* Give the console back: closing the server file runs CondrvServerGone,
     * so conhost can take the one server slot when smss starts it. */
    NtClose(input);
    NtClose(server);
}

/* --- the delivered state: aborted while conhost owns it as `current` ------ */

static void condrv_client_nonread_thread(void *context)
{
    CONDRV_CLIENT *client = context;
    IO_STATUS_BLOCK iosb;
    ULONG mode = 0;

    NTSTATUS status = NtDeviceIoControlFile(client->handle, 0, 0, 0, &iosb, IOCTL_CONDRV_GET_MODE,
                                            0, 0, &mode, (ULONG)sizeof(mode));
    client->resumed = 1;
    client->status = status;
}

static void test_condrv_unwind_while_delivered(void)
{
    HANDLE server = 0;
    HANDLE input = 0;
    NTSTATUS status = condrv_open(WSTR("\\Device\\ConDrv\\Server"), &server);
    ok(status == STATUS_SUCCESS, "open server: %#x", (unsigned)status);
    if (status != STATUS_SUCCESS)
        return;
    status = condrv_open(WSTR("\\Device\\ConDrv\\Input"), &input);
    ok(status == STATUS_SUCCESS, "open input: %#x", (unsigned)status);
    if (status != STATUS_SUCCESS)
    {
        NtClose(server);
        return;
    }

    CONDRV_CLIENT client = {.handle = input, .resumed = 0, .status = STATUS_SUCCESS};
    PKTHREAD worker = KiCreateThread(8, condrv_client_nonread_thread, &client);

    uint64_t id = 0;
    ULONG code = condrv_server_fetch(server, &id);
    ok(code == IOCTL_CONDRV_GET_MODE, "delivered code %#x", (unsigned)code);

    /* Abort with the request still `current` (a fetched non-read verb is off
     * both queues), and never reply: the unwind must disown it. */
    condrv_abort_wait(worker);
    join_and_delete(worker);
    ok(client.status == STATUS_THREAD_IS_TERMINATING, "client saw %#x", (unsigned)client.status);

    /* `current` was released, so conhost can fetch the next verb at all. */
    CONDRV_CLIENT again = {.handle = input, .resumed = 0, .status = STATUS_SUCCESS};
    PKTHREAD second = KiCreateThread(8, condrv_client_nonread_thread, &again);
    id = 0;
    code = condrv_server_fetch(server, &id);
    ok(code == IOCTL_CONDRV_GET_MODE, "second delivered code %#x", (unsigned)code);
    if (code == IOCTL_CONDRV_GET_MODE)
    {
        status = condrv_server_reply(server, id, 0, STATUS_SUCCESS);
        ok(status == STATUS_SUCCESS, "reply: %#x", (unsigned)status);
    }
    else
    {
        condrv_abort_wait(second);
    }
    join_and_delete(second);
    ok(again.status == STATUS_SUCCESS, "second client saw %#x", (unsigned)again.status);

    NtClose(input);
    NtClose(server);
}

/* --- the queued state: aborted before conhost ever fetched it ------------- */

static void test_condrv_unwind_while_queued(void)
{
    HANDLE server = 0;
    HANDLE input = 0;
    NTSTATUS status = condrv_open(WSTR("\\Device\\ConDrv\\Server"), &server);
    ok(status == STATUS_SUCCESS, "open server: %#x", (unsigned)status);
    if (status != STATUS_SUCCESS)
        return;
    status = condrv_open(WSTR("\\Device\\ConDrv\\Input"), &input);
    ok(status == STATUS_SUCCESS, "open input: %#x", (unsigned)status);
    if (status != STATUS_SUCCESS)
    {
        NtClose(server);
        return;
    }

    CONDRV_CLIENT client = {.handle = input, .resumed = 0, .status = STATUS_SUCCESS};
    PKTHREAD worker = KiCreateThread(8, condrv_client_nonread_thread, &client);

    /* Let it park without ever fetching: yield until it is queued and waiting.
     * Bounded, and the bound is asserted — a join on a client nothing will
     * serve would otherwise hang the boot rather than fail a test. */
    unsigned spin = 0;
    while (worker->state != KI_THREAD_STATE_WAITING && spin < 1000)
    {
        KiYield();
        spin++;
    }
    ok(worker->state == KI_THREAD_STATE_WAITING, "client never parked (state %u)",
       (unsigned)worker->state);
    condrv_abort_wait(worker);
    join_and_delete(worker);
    ok(client.status == STATUS_THREAD_IS_TERMINATING, "client saw %#x", (unsigned)client.status);

    /* Nothing is left queued: the fetch finds the queue empty. */
    static char buffer[CONDRV_SERVER_BUFFER_SIZE];
    IO_STATUS_BLOCK iosb;
    status = NtReadFile(server, 0, 0, 0, &iosb, buffer, (ULONG)sizeof(buffer), 0, 0);
    ok(status == STATUS_PENDING, "queue not empty after the unwind: %#x", (unsigned)status);

    NtClose(input);
    NtClose(server);
}

int kmt_run_condrv(void)
{
    int before = kmt_failures;
    KMT_RUN(test_condrv_unwind_while_queued);
    KMT_RUN(test_condrv_unwind_while_delivered);
    KMT_RUN(test_condrv_unwind_after_completion);
    return kmt_failures - before;
}
