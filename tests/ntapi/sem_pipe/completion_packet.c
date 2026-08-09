/*
 * sem_pipe/completion_packet.c — WHEN a completion packet is posted, and the
 * one axis FILE_SKIP_COMPLETION_PORT_ON_SUCCESS turns on.
 *
 * sem_port/file_completion.c pins the BINDING. This pins what the binding
 * then produces, and it exists because the obvious reading of the skip flag
 * is wrong in a way whose failure mode is a HANG rather than an assertion.
 *
 * The oracle's rule, in three places that agree:
 *
 *   dlls/ntdll/unix/file.c   add_completion( handle, cvalue, status, total,
 *                                            ret_status == STATUS_PENDING )
 *   server/fd.c   add_fd_completion: `req->async || !(comp_flags & SKIP…)`
 *   server/async.c async_set_result: `async->pending || !(comp_flags & SKIP…)`
 *
 * — post iff the request PENDED, or the flag is not set. Note what those
 * guards do NOT carry: a status term. The discriminator is whether the call
 * RETURNED STATUS_PENDING, NOT whether it succeeded, and the `!NT_ERROR`
 * that sits beside the second one is the separate outer question of whether
 * to signal completion at all. A request that pends always posts, flag or
 * no flag; that is the whole point, since a caller that got
 * ERROR_IO_PENDING has nothing else to wait on. The flag's NAME is the
 * misleading part of the contract.
 *
 * Reading it as "skip on success" instead makes an asynchronous port-bound
 * handle answer STATUS_PENDING and post nothing, i.e. hang
 * GetQueuedCompletionStatus forever — so each case below states which side
 * of the axis it is on.
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

#define TEST_KEY ((ULONG_PTR)0xfeed1234)

/* Drain one packet, or report that none is there. Zero timeout: the packet
 * is either already queued (every completion in this file is inline) or it
 * is never coming. */
static BOOLEAN take_packet(HANDLE port, ULONG_PTR *keyOut, ULONG_PTR *valueOut,
                           IO_STATUS_BLOCK *iosbOut)
{
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    *keyOut = 0;
    *valueOut = 0;
    return NtRemoveIoCompletion(port, keyOut, valueOut, iosbOut, &zero) == STATUS_SUCCESS;
}

static NTSTATUS bind_port(HANDLE file, HANDLE port)
{
    SEM_FILE_COMPLETION_INFORMATION info;
    IO_STATUS_BLOCK iosb;
    info.CompletionPort = port;
    info.CompletionKey = TEST_KEY;
    return NtSetInformationFile(file, &iosb, &info, sizeof(info), FileCompletionInformation);
}

static NTSTATUS set_skip(HANDLE file)
{
    SEM_FILE_IO_COMPLETION_NOTIFICATION_INFORMATION info;
    IO_STATUS_BLOCK iosb;
    info.Flags = FILE_SKIP_COMPLETION_PORT_ON_SUCCESS;
    return NtSetInformationFile(file, &iosb, &info, sizeof(info),
                                FileIoCompletionNotificationInformation);
}

START_TEST(completion_packet)
{
    IO_STATUS_BLOCK iosb, clientIosb, packetIosb;
    HANDLE server = NULL, client = NULL, port = NULL;
    ULONG_PTR key, value;
    char buf[8] = "abcdefg";
    char readBuf[8];
    NTSTATUS status;

    status = NtCreateIoCompletion(&port, IO_COMPLETION_ALL_ACCESS, NULL, 0);
    ok(status == STATUS_SUCCESS, "create port -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* ASYNCHRONOUS (a port bind needs an overlapped handle) and MESSAGE type
     * (so the short read below is STATUS_BUFFER_OVERFLOW — the warning-status
     * arm of the axis). create_pipe_instance_async is byte-mode, so this one
     * is spelled out. */
    {
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        LARGE_INTEGER timeout;
        init_ustr(&name, W("\\??\\pipe\\prstest_cpacket"));
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        timeout.QuadPart = -100 * 10000;
        status = NtCreateNamedPipeFile(&server, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr,
                                       &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, 0,
                                       FILE_PIPE_TYPE_MESSAGE, FILE_PIPE_MESSAGE_MODE,
                                       FILE_PIPE_QUEUE_OPERATION, 1, 4096, 4096, &timeout);
    }
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_cpacket"), &clientIosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    status = bind_port(server, port);
    ok(status == STATUS_SUCCESS, "bind -> %08lx", (unsigned long)status);

    /* --- an IOCTL posts a packet. This is the half proskrnl never had:
     * kernel/io/ioctl.c completed without going through the site that
     * posts, so no ioctl ever produced one. The VALUE is the caller's
     * ApcContext (here the IOSB pointer, as every Win32 OVERLAPPED caller
     * passes) and the KEY is the one the bind carried. */
    {
        char peek[64];
        memset(&iosb, 0, sizeof(iosb));
        status = NtFsControlFile(server, NULL, NULL, &iosb, &iosb, FSCTL_PIPE_PEEK, NULL, 0, peek,
                                 sizeof(peek));
        ok(status == STATUS_SUCCESS, "peek -> %08lx", (unsigned long)status);

        ok(take_packet(port, &key, &value, &packetIosb), "no packet for an ioctl");
        ok(key == TEST_KEY, "packet key %llx", (unsigned long long)key);
        ok(value == (ULONG_PTR)&iosb, "packet value %llx want %llx", (unsigned long long)value,
           (unsigned long long)(ULONG_PTR)&iosb);
    }

    /* --- a WRITE posts one too (this half already worked). */
    memset(&iosb, 0, sizeof(iosb));
    status = NtWriteFile(server, NULL, NULL, &iosb, &iosb, buf, sizeof(buf), NULL, NULL);
    ok(status == STATUS_SUCCESS, "write -> %08lx", (unsigned long)status);
    ok(take_packet(port, &key, &value, &packetIosb), "no packet for a write");

    /* --- now the flag. THE AXIS: these completions are INLINE (the call
     * did not report pending to the caller), so the flag suppresses them. */
    status = set_skip(server);
    ok(status == STATUS_SUCCESS, "set skip -> %08lx", (unsigned long)status);

    memset(&iosb, 0, sizeof(iosb));
    status = NtWriteFile(server, NULL, NULL, &iosb, &iosb, buf, sizeof(buf), NULL, NULL);
    ok(status == STATUS_SUCCESS, "write with skip -> %08lx", (unsigned long)status);
    ok(!take_packet(port, &key, &value, &packetIosb), "packet posted despite the skip flag");

    /* An ioctl under the flag is suppressed the same way. */
    {
        char peek[64];
        memset(&iosb, 0, sizeof(iosb));
        status = NtFsControlFile(server, NULL, NULL, &iosb, &iosb, FSCTL_PIPE_PEEK, NULL, 0, peek,
                                 sizeof(peek));
        ok(status == STATUS_SUCCESS, "peek with skip -> %08lx", (unsigned long)status);
        ok(!take_packet(port, &key, &value, &packetIosb), "ioctl packet despite the skip flag");
    }

    /* --- and the NON-success side of the same axis. The skip has no status
     * term at all, so a WARNING status is suppressed exactly like a success:
     * a short read of a MESSAGE-mode pipe is STATUS_BUFFER_OVERFLOW, and it
     * posts nothing. An implementation that wrote the rule as "skip on
     * NT_SUCCESS" gets this one wrong in the other direction — it posts. */
    memset(&clientIosb, 0, sizeof(clientIosb));
    status = NtWriteFile(client, NULL, NULL, NULL, &clientIosb, buf, sizeof(buf), NULL, NULL);
    ok(status == STATUS_SUCCESS, "client write -> %08lx", (unsigned long)status);

    memset(&iosb, 0, sizeof(iosb));
    status = NtReadFile(server, NULL, NULL, &iosb, &iosb, readBuf, 1, NULL, NULL);
    ok(status == STATUS_BUFFER_OVERFLOW, "short read -> %08lx", (unsigned long)status);
    ok(!take_packet(port, &key, &value, &packetIosb),
       "packet for a BUFFER_OVERFLOW under the skip flag");

    NtClose(client);
    NtClose(server);
    NtClose(port);
}
