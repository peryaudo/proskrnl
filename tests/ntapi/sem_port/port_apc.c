/*
 * sem_port/port_apc.c — a completion PORT and a completion APC ROUTINE are
 * mutually exclusive on the same request, and the refusal is the SERVER's.
 *
 * sem_port/file_completion.c pins the binding; sem_pipe/completion_packet.c
 * pins what the binding then produces. This pins what the binding FORBIDS,
 * and it exists because proskrnl accepted the combination and delivered the
 * APC — a plausible answer to a request NT refuses outright.
 *
 * The oracle's rule is the last statement of create_async
 * (third_party/wine server/async.c):
 *
 *     if (event) reset_event( event );
 *
 *     if (async->completion && data->apc)
 *     {
 *         release_object( async );
 *         set_error( STATUS_INVALID_PARAMETER );
 *         return NULL;
 *     }
 *
 * — where `async->completion` is `fd_get_completion( fd, ... )`, the port
 * bound to the handle's fd, and `data->apc` is the ApcROUTINE. Three things
 * about that placement are the content of this file, and none of them is
 * readable off the status:
 *
 *   - the caller's EVENT is already RESET when the refusal is made. The
 *     reset is the statement above the guard, so a refused request leaves
 *     the event down even though nothing was ever issued;
 *   - the FILE OBJECT is NOT cleared, because the clear is `queue_async`'s
 *     (`set_fd_signaled( async->fd, 0 )`) and the refusal returns above it.
 *     proskrnl merges the two into one IopBeginBlockingRequest, so this is
 *     the case that says which half applies;
 *   - the HANDLE and its ACCESS are decided FIRST — `get_handle_fd_obj(
 *     ..., FILE_READ_DATA )` in DECL_HANDLER(read) (server/fd.c) runs above
 *     create_async — so a read through an unentitled handle reports
 *     ACCESS_DENIED and never reaches this rule.
 *
 * And one thing about its REACH: it is the rule of the requests the SERVER
 * queues, not of the syscall. A regular DISK file's read never goes to the
 * server at all (dlls/ntdll/unix/file.c NtReadFile pread()s it locally),
 * so the same combination on a disk handle is admitted — and there ntdll
 * resolves the conflict the other way instead, with
 * `cvalue = apc ? 0 : (ULONG_PTR)apc_user`: the APC runs and no packet is
 * posted. Both arms are measured below, because an implementation that put
 * the refusal in the syscall would pass every pipe case here and refuse a
 * disk read the oracle serves.
 *
 * ntdll:pipe's test_async_cancel_on_handle_close (pipe.c:3094, eight
 * assertions) is the winetest consumer.
 *
 * Oracle-first (G5).
 */
#include "../ntapi.h"

#define W(s) u##s

#include <string.h>   /* declarations only: the .exe links no CRT */
#include <winioctl.h> /* CTL_CODE, FILE_DEVICE_NAMED_PIPE */

NTSYSAPI NTSTATUS NTAPI NtCreateIoCompletion(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
NTSYSAPI NTSTATUS NTAPI NtRemoveIoCompletion(HANDLE, PULONG_PTR, PULONG_PTR, PIO_STATUS_BLOCK,
                                             PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtCreateNamedPipeFile(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                              ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG,
                                              ULONG, ULONG, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtFsControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
                                        ULONG, PVOID, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtReadFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID,
                                   ULONG, PLARGE_INTEGER, PULONG);
NTSYSAPI NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
                                    const void *, ULONG, PLARGE_INTEGER, PULONG);
NTSYSAPI NTSTATUS NTAPI NtNotifyChangeDirectoryFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                                    PIO_STATUS_BLOCK, PVOID, ULONG, ULONG, BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtCancelIoFile(HANDLE, PIO_STATUS_BLOCK);
NTSYSAPI NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG,
                                          ULONG);
NTSYSAPI NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

/* wine/include/winternl.h; mingw's omits it. */
typedef struct
{
    HANDLE CompletionPort;
    ULONG_PTR CompletionKey;
} SEM_FILE_COMPLETION_INFORMATION;

#ifndef FileCompletionInformation
#define FileCompletionInformation 30
#endif
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0) /* wine/include/winternl.h */
#ifndef FSCTL_PIPE_PEEK
#define FSCTL_PIPE_PEEK CTL_CODE(FILE_DEVICE_NAMED_PIPE, 3, METHOD_BUFFERED, FILE_READ_DATA)
#endif
#ifndef FILE_PIPE_TYPE_BYTE
#define FILE_PIPE_TYPE_BYTE 0x00000000
#endif
#ifndef FILE_PIPE_BYTE_STREAM_MODE
#define FILE_PIPE_BYTE_STREAM_MODE 0x00000000
#endif
#ifndef FILE_PIPE_QUEUE_OPERATION
#define FILE_PIPE_QUEUE_OPERATION 0x00000000
#endif

#define TEST_KEY    ((ULONG_PTR)0x9e77c0de)
#define IOSB_POISON ((NTSTATUS)0x0BADF00D)

/* ---- harness ------------------------------------------------------------ */

static int apc_calls;

static void NTAPI count_apc(PVOID context, PIO_STATUS_BLOCK iosb, ULONG reserved)
{
    (void)context;
    (void)iosb;
    (void)reserved;
    apc_calls++;
}

/* An alertable sleep: the delivery edge for a queued user APC. A refused
 * request must not produce one, and only an alertable wait can tell the
 * difference between "not queued" and "not yet delivered". */
static void alertable_pause(void)
{
    LARGE_INTEGER timeout;
    timeout.QuadPart = -10 * 10000; /* 10 ms, relative */
    NtDelayExecution(TRUE, &timeout);
}

static void init_ustr(UNICODE_STRING *str, const void *wide)
{
    const unsigned short *p = (const unsigned short *)wide;
    unsigned len = 0;
    while (p[len])
        len++;
    str->Length = (USHORT)(len * 2);
    str->MaximumLength = (USHORT)(len * 2 + 2);
    str->Buffer = (PWSTR)(void *)p;
}

static void init_attr(OBJECT_ATTRIBUTES *attr, UNICODE_STRING *name)
{
    attr->Length = sizeof(*attr);
    attr->RootDirectory = NULL;
    attr->ObjectName = name;
    attr->Attributes = OBJ_CASE_INSENSITIVE;
    attr->SecurityDescriptor = NULL;
    attr->SecurityQualityOfService = NULL;
}

static NTSTATUS bind_port(HANDLE file, HANDLE port)
{
    SEM_FILE_COMPLETION_INFORMATION info;
    IO_STATUS_BLOCK iosb;
    info.CompletionPort = port;
    info.CompletionKey = TEST_KEY;
    return NtSetInformationFile(file, &iosb, &info, sizeof(info), FileCompletionInformation);
}

/* Drain one packet, or report that none is there. */
static BOOLEAN take_packet(HANDLE port)
{
    IO_STATUS_BLOCK packet;
    LARGE_INTEGER zero;
    ULONG_PTR key = 0, value = 0;
    zero.QuadPart = 0;
    return NtRemoveIoCompletion(port, &key, &value, &packet, &zero) == STATUS_SUCCESS;
}

/* One asynchronous (overlapped) server-end instance: a port bind needs an
 * overlapped handle, and only a device-backed handle takes the server path
 * this rule lives on. */
static NTSTATUS make_async_pipe(HANDLE *server, const void *wide_name)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER timeout;

    init_ustr(&name, wide_name);
    init_attr(&attr, &name);
    timeout.QuadPart = -100 * 10000; /* 100 ms, relative */
    *server = NULL;
    return NtCreateNamedPipeFile(server, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr, &iosb,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, 0,
                                 FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
                                 FILE_PIPE_QUEUE_OPERATION, 1, 4096, 4096, &timeout);
}

static NTSTATUS open_client(HANDLE *client, const void *wide_name)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;

    init_ustr(&name, wide_name);
    init_attr(&attr, &name);
    *client = NULL;
    return NtCreateFile(client, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr, &iosb, NULL,
                        FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

static NTSTATUS make_dir(const void *path)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE dir = NULL;
    NTSTATUS status;

    init_ustr(&name, path);
    init_attr(&attr, &name);
    status =
        NtCreateFile(&dir, FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_TRAVERSE | SYNCHRONIZE, &attr,
                     &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                     FILE_OPEN_IF, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (NT_SUCCESS(status))
        NtClose(dir);
    return status;
}

/* ---- §1 the rule, on the three services that reach create_async --------- */

static void test_device_refusals(HANDLE port)
{
    HANDLE server = NULL, client = NULL;
    IO_STATUS_BLOCK iosb;
    char buf[8] = "abcdefg";
    char peek[64];
    NTSTATUS status;

    status = make_async_pipe(&server, W("\\??\\pipe\\prstest_portapc1"));
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_client(&client, W("\\??\\pipe\\prstest_portapc1"));
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);
    status = bind_port(server, port);
    ok(status == STATUS_SUCCESS, "bind -> %08lx", (unsigned long)status);

    /* A READ. The IOSB is poisoned first: a refusal above the queue writes
     * nothing into it, which is a separate promise from the status. */
    apc_calls = 0;
    iosb.Status = IOSB_POISON;
    iosb.Information = (ULONG_PTR)~0ULL;
    status = NtReadFile(server, NULL, count_apc, (PVOID)&iosb, &iosb, buf, sizeof(buf), NULL, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "read with an apc on a bound handle -> %08lx",
       (unsigned long)status);
    ok(iosb.Status == IOSB_POISON, "refused read wrote the IOSB: %08lx",
       (unsigned long)iosb.Status);
    alertable_pause();
    ok(apc_calls == 0, "refused read ran %d apc(s)", apc_calls);
    ok(!take_packet(port), "refused read posted a packet");

    /* A WRITE, same rule. There is data room, so a kernel without the rule
     * completes it and the assertion sees a success rather than a hang. */
    apc_calls = 0;
    iosb.Status = IOSB_POISON;
    status =
        NtWriteFile(server, NULL, count_apc, (PVOID)&iosb, &iosb, buf, sizeof(buf), NULL, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "write with an apc on a bound handle -> %08lx",
       (unsigned long)status);
    ok(iosb.Status == IOSB_POISON, "refused write wrote the IOSB: %08lx",
       (unsigned long)iosb.Status);
    alertable_pause();
    ok(apc_calls == 0, "refused write ran %d apc(s)", apc_calls);
    ok(!take_packet(port), "refused write posted a packet");

    /* An IOCTL. FSCTL_PIPE_PEEK is answered INLINE and never queues, which
     * is exactly why it belongs here: the refusal is made when the request
     * is CREATED, above every verb, so a verb that would never have parked
     * is refused just the same. */
    apc_calls = 0;
    iosb.Status = IOSB_POISON;
    status = NtFsControlFile(server, NULL, count_apc, (PVOID)&iosb, &iosb, FSCTL_PIPE_PEEK, NULL, 0,
                             peek, sizeof(peek));
    ok(status == STATUS_INVALID_PARAMETER, "peek with an apc on a bound handle -> %08lx",
       (unsigned long)status);
    ok(iosb.Status == IOSB_POISON, "refused ioctl wrote the IOSB: %08lx",
       (unsigned long)iosb.Status);
    alertable_pause();
    ok(apc_calls == 0, "refused ioctl ran %d apc(s)", apc_calls);
    ok(!take_packet(port), "refused ioctl posted a packet");

    NtClose(client);
    NtClose(server);
}

/* ---- §2 what the rule is NOT keyed on ----------------------------------- */

static void test_not_the_context_nor_the_port_alone(HANDLE port)
{
    HANDLE server = NULL, client = NULL, unbound = NULL, unboundClient = NULL;
    IO_STATUS_BLOCK iosb;
    char buf[8] = "abcdefg";
    NTSTATUS status;

    status = make_async_pipe(&server, W("\\??\\pipe\\prstest_portapc2"));
    ok(status == STATUS_SUCCESS, "second server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_client(&client, W("\\??\\pipe\\prstest_portapc2"));
    ok(status == STATUS_SUCCESS, "second client connect -> %08lx", (unsigned long)status);
    status = bind_port(server, port);
    ok(status == STATUS_SUCCESS, "second bind -> %08lx", (unsigned long)status);

    /* The guard reads `data->apc`, the ROUTINE. An ApcCONTEXT with no
     * routine is the ordinary port-driven shape — it IS the packet's value
     * — and must go through. An implementation keyed on the context refuses
     * every overlapped Win32 caller there is. */
    iosb.Status = IOSB_POISON;
    status = NtWriteFile(server, NULL, NULL, (PVOID)&iosb, &iosb, buf, sizeof(buf), NULL, NULL);
    ok(status == STATUS_SUCCESS || status == STATUS_PENDING,
       "write with a context and no routine -> %08lx", (unsigned long)status);
    ok(take_packet(port), "no packet for a context-only write");

    /* And a routine with NO port bound is the ordinary APC-driven shape. */
    status = make_async_pipe(&unbound, W("\\??\\pipe\\prstest_portapc3"));
    ok(status == STATUS_SUCCESS, "unbound server create -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = open_client(&unboundClient, W("\\??\\pipe\\prstest_portapc3"));
        ok(status == STATUS_SUCCESS, "unbound client connect -> %08lx", (unsigned long)status);

        apc_calls = 0;
        iosb.Status = IOSB_POISON;
        status = NtWriteFile(unbound, NULL, count_apc, (PVOID)&iosb, &iosb, buf, sizeof(buf), NULL,
                             NULL);
        ok(status == STATUS_SUCCESS || status == STATUS_PENDING,
           "write with a routine and no port -> %08lx", (unsigned long)status);
        alertable_pause();
        ok(apc_calls == 1, "unbound write ran %d apc(s), expected 1", apc_calls);

        NtClose(unboundClient);
        NtClose(unbound);
    }

    NtClose(client);
    NtClose(server);
}

/* ---- §3 the ORDER around the refusal ------------------------------------ */

static void test_order(HANDLE port)
{
    HANDLE server = NULL, client = NULL, event = NULL, weak = NULL;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER zero;
    char buf[8] = "abcdefg";
    NTSTATUS status;

    zero.QuadPart = 0;

    status = make_async_pipe(&server, W("\\??\\pipe\\prstest_portapc4"));
    ok(status == STATUS_SUCCESS, "order server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_client(&client, W("\\??\\pipe\\prstest_portapc4"));
    ok(status == STATUS_SUCCESS, "order client connect -> %08lx", (unsigned long)status);
    status = bind_port(server, port);
    ok(status == STATUS_SUCCESS, "order bind -> %08lx", (unsigned long)status);

    /* The FILE OBJECT is left exactly as it was found: the clear belongs to
     * queue_async, which the refusal returns above. A fresh handle is born
     * signalled, so "still signalled" is the whole statement. */
    ok(NtWaitForSingleObject(server, FALSE, &zero) == STATUS_SUCCESS,
       "a fresh pipe handle is signalled");

    /* The caller's EVENT is reset by the refusal — create_async's
     * `if (event) reset_event( event )` sits ABOVE the guard. Created
     * signalled so the reset is the only thing that can have moved it. */
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, TRUE);
    ok(status == STATUS_SUCCESS, "create event -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ok(NtWaitForSingleObject(event, FALSE, &zero) == STATUS_SUCCESS,
           "the event starts signalled");
        status =
            NtReadFile(server, event, count_apc, (PVOID)&iosb, &iosb, buf, sizeof(buf), NULL, NULL);
        ok(status == STATUS_INVALID_PARAMETER, "refused read with an event -> %08lx",
           (unsigned long)status);
        ok(NtWaitForSingleObject(event, FALSE, &zero) == STATUS_TIMEOUT,
           "the refusal left the caller's event signalled");
        NtClose(event);
    }

    /* ...and the file object is STILL up afterwards. Both halves in one
     * place, because proskrnl states them with one call and only a case
     * that separates them says which half a refusal owes. */
    ok(NtWaitForSingleObject(server, FALSE, &zero) == STATUS_SUCCESS,
       "the refusal took the pipe handle down");

    /* The HANDLE's ACCESS is decided first. A duplicate without
     * FILE_READ_DATA names the same file object through a weaker handle, so
     * only the access word differs. */
    status = NtDuplicateObject(NtCurrentProcess(), server, NtCurrentProcess(), &weak,
                               FILE_WRITE_DATA | SYNCHRONIZE, 0, 0);
    ok(status == STATUS_SUCCESS, "weaken the handle -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status =
            NtReadFile(weak, NULL, count_apc, (PVOID)&iosb, &iosb, buf, sizeof(buf), NULL, NULL);
        ok(status == STATUS_ACCESS_DENIED, "read through an unentitled handle -> %08lx",
           (unsigned long)status);
        NtClose(weak);
    }

    NtClose(client);
    NtClose(server);
}

/* ---- §4 the arm the oracle serves ITSELF --------------------------------- */

static void test_disk_file(HANDLE port)
{
    HANDLE file = NULL;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    char buf[8] = "abcdefg";
    char readBuf[8];
    NTSTATUS status;

    status = make_dir(W("\\??\\C:\\prstest"));
    ok(status == STATUS_SUCCESS, "create prstest -> %08lx", (unsigned long)status);
    status = make_dir(W("\\??\\C:\\prstest\\portapc"));
    ok(status == STATUS_SUCCESS, "create portapc -> %08lx", (unsigned long)status);

    init_ustr(&name, W("\\??\\C:\\prstest\\portapc\\f.bin"));
    init_attr(&attr, &name);
    status = NtCreateFile(&file, FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE, &attr, &iosb,
                          NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, NULL, 0);
    ok(status == STATUS_SUCCESS, "open async disk file -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = bind_port(file, port);
    ok(status == STATUS_SUCCESS, "bind disk file -> %08lx", (unsigned long)status);

    offset.QuadPart = 0;
    status = NtWriteFile(file, NULL, NULL, NULL, &iosb, buf, sizeof(buf), &offset, NULL);
    ok(status == STATUS_SUCCESS || status == STATUS_PENDING, "seed the file -> %08lx",
       (unsigned long)status);

    /* A DISK read never reaches the server, so the guard above never runs.
     * ntdll resolves the same conflict the other way instead — the APC runs
     * and the packet is suppressed (`cvalue = apc ? 0 : apc_user`). An
     * implementation that hoisted the refusal into the syscall fails
     * exactly here and passes every case above. */
    apc_calls = 0;
    offset.QuadPart = 0;
    status = NtReadFile(file, NULL, count_apc, (PVOID)&iosb, &iosb, readBuf, sizeof(readBuf),
                        &offset, NULL);
    ok(status == STATUS_SUCCESS || status == STATUS_PENDING,
       "disk read with an apc on a bound handle -> %08lx", (unsigned long)status);
    alertable_pause();
    ok(apc_calls == 1, "disk read ran %d apc(s), expected 1", apc_calls);
    ok(!take_packet(port), "disk read posted a packet as well as running the apc");

    NtClose(file);
}

/* ---- §5 the watch, which is a server request whatever backs it ----------- */

static void test_notify(HANDLE port)
{
    HANDLE dir = NULL, event = NULL;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb, cancelIosb;
    LARGE_INTEGER zero;
    static UCHAR notifyBuffer[512];
    NTSTATUS status;

    zero.QuadPart = 0;

    init_ustr(&name, W("\\??\\C:\\prstest\\portapc"));
    init_attr(&attr, &name);
    status = NtCreateFile(&dir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attr, &iosb, NULL,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                          FILE_DIRECTORY_FILE, NULL, 0);
    ok(status == STATUS_SUCCESS, "open async directory -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = bind_port(dir, port);
    ok(status == STATUS_SUCCESS, "bind directory -> %08lx", (unsigned long)status);

    /* A watch is a server request whatever backs the directory, so the rule
     * reaches it — and it carries an EVENT so the reset's position is
     * measured here too rather than argued from the transfer paths. */
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, TRUE);
    ok(status == STATUS_SUCCESS, "create watch event -> %08lx", (unsigned long)status);

    apc_calls = 0;
    iosb.Status = IOSB_POISON;
    status = NtNotifyChangeDirectoryFile(dir, event, count_apc, (PVOID)&iosb, &iosb, notifyBuffer,
                                         sizeof(notifyBuffer), FILE_NOTIFY_CHANGE_FILE_NAME, FALSE);
    ok(status == STATUS_INVALID_PARAMETER, "watch with an apc on a bound handle -> %08lx",
       (unsigned long)status);
    if (status == STATUS_PENDING)
        NtCancelIoFile(dir, &cancelIosb);
    ok(iosb.Status == IOSB_POISON, "refused watch wrote the IOSB: %08lx",
       (unsigned long)iosb.Status);
    ok(NtWaitForSingleObject(event, FALSE, &zero) == STATUS_TIMEOUT,
       "the refused watch left the caller's event signalled");
    alertable_pause();
    ok(apc_calls == 0, "refused watch ran %d apc(s)", apc_calls);
    ok(!take_packet(port), "refused watch posted a packet");

    if (event != NULL)
        NtClose(event);
    NtClose(dir);
}

START_TEST(port_apc)
{
    HANDLE port = NULL;
    NTSTATUS status;

    status = NtCreateIoCompletion(&port, IO_COMPLETION_ALL_ACCESS, NULL, 0);
    ok(status == STATUS_SUCCESS, "create port -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    test_device_refusals(port);
    test_not_the_context_nor_the_port_alone(port);
    test_order(port);
    test_disk_file(port);
    test_notify(port);

    NtClose(port);
}
