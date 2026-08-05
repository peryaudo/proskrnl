/*
 * sem_port/file_completion.c — binding a file handle to a completion port
 * (NtSetInformationFile, FileCompletionInformation).
 *
 * The single highest-leverage gap the winetest sweep found: four pairs
 * (kernel32:file, kernel32:pipe, kernel32:sync, ntdll:threadpool) all died
 * in NtSetInformationFile on class 30, which is this one. It is what
 * CreateIoCompletionPort(file, port, key, 0) and BindIoCompletionCallback
 * are, so nothing that does overlapped I/O against a port can work without
 * it.
 *
 * The pinned oracle's rules are its server's, in four lines
 * (third_party/wine server/fd.c set_completion_info):
 *
 *     if (is_fd_overlapped( fd ) && !fd->completion) {
 *         fd->completion = get_completion_obj( ..., IO_COMPLETION_MODIFY_STATE );
 *         fd->comp_key   = req->ckey;
 *         set_fd_signaled( fd, 1 );
 *     }
 *     else set_error( STATUS_INVALID_PARAMETER );
 *
 * — so a SYNCHRONOUS handle is refused, a SECOND bind is refused, and both
 * with the same flat STATUS_INVALID_PARAMETER. The length check sits one
 * layer up in ntdll (unix/file.c:5302) and answers
 * STATUS_INVALID_PARAMETER_3, which is a different status for a different
 * mistake and is pinned separately.
 *
 * Oracle-first (G5).
 */
#include "../ntapi.h"

#define W(s) u##s

NTSYSAPI NTSTATUS NTAPI NtCreateIoCompletion(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
NTSYSAPI NTSTATUS NTAPI NtRemoveIoCompletion(HANDLE, PULONG_PTR, PULONG_PTR, PIO_STATUS_BLOCK,
                                             PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtReadFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID,
                                   ULONG, PLARGE_INTEGER, PULONG);
NTSYSAPI NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
                                    const void *, ULONG, PLARGE_INTEGER, PULONG);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

/* wine/include/winternl.h; mingw's omits it. */
typedef struct _FILE_COMPLETION_INFORMATION
{
    HANDLE CompletionPort;
    ULONG_PTR CompletionKey;
} FILE_COMPLETION_INFORMATION;

#ifndef FileCompletionInformation
#define FileCompletionInformation 30
#endif

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

/* Open \??\C:\prstest\fcomp\f.bin, asynchronous or synchronous. */
static NTSTATUS open_data_file(HANDLE *handle, BOOLEAN async)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;

    init_ustr(&name, W("\\??\\C:\\prstest\\fcomp\\f.bin"));
    init_attr(&attr, &name);
    *handle = NULL;
    return NtCreateFile(
        handle, FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE, &attr, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
        FILE_NON_DIRECTORY_FILE | (async ? 0 : FILE_SYNCHRONOUS_IO_NONALERT), NULL, 0);
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

static NTSTATUS bind_port(HANDLE file, HANDLE port, ULONG_PTR key, ULONG length)
{
    FILE_COMPLETION_INFORMATION info;
    IO_STATUS_BLOCK iosb;

    info.CompletionPort = port;
    info.CompletionKey = key;
    return NtSetInformationFile(file, &iosb, &info, length, FileCompletionInformation);
}

START_TEST(file_completion)
{
    NTSTATUS status;
    HANDLE port = NULL, file = NULL, other = NULL;

    status = make_dir(W("\\??\\C:\\prstest"));
    ok(status == STATUS_SUCCESS, "create prstest -> %08lx", (unsigned long)status);
    status = make_dir(W("\\??\\C:\\prstest\\fcomp"));
    ok(status == STATUS_SUCCESS, "create fcomp -> %08lx", (unsigned long)status);

    status = NtCreateIoCompletion(&port, IO_COMPLETION_ALL_ACCESS, NULL, 0);
    ok(status == STATUS_SUCCESS, "create port -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* --- a SYNCHRONOUS handle cannot be bound ---------------------------- */
    status = open_data_file(&file, FALSE);
    ok(status == STATUS_SUCCESS, "open sync file -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = bind_port(file, port, 0x5150, sizeof(FILE_COMPLETION_INFORMATION));
        ok(status == STATUS_INVALID_PARAMETER, "bind sync handle -> %08lx", (unsigned long)status);
        NtClose(file);
    }

    /* --- an ASYNCHRONOUS handle binds ------------------------------------ */
    status = open_data_file(&file, TRUE);
    ok(status == STATUS_SUCCESS, "open async file -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(port);
        return;
    }
    status = bind_port(file, port, 0x5150, sizeof(FILE_COMPLETION_INFORMATION));
    ok(status == STATUS_SUCCESS, "bind async handle -> %08lx", (unsigned long)status);

    /* --- ...once. A second bind on the same handle is refused ------------- */
    status = bind_port(file, port, 0x9999, sizeof(FILE_COMPLETION_INFORMATION));
    ok(status == STATUS_INVALID_PARAMETER, "second bind -> %08lx", (unsigned long)status);

    /* --- a short buffer is a DIFFERENT status, from ntdll rather than the
     * server: STATUS_INVALID_PARAMETER_3 (unix/file.c:5302). */
    status = open_data_file(&other, TRUE);
    ok(status == STATUS_SUCCESS, "open second async file -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = bind_port(other, port, 0x1234, sizeof(FILE_COMPLETION_INFORMATION) - 1);
        ok(status == STATUS_INVALID_PARAMETER_3, "short buffer -> %08lx", (unsigned long)status);
        NtClose(other);
    }

    /* --- a completed I/O on the bound handle posts a packet carrying the
     * KEY the bind supplied and the APC CONTEXT as its value. This is the
     * whole point of the class, and the part an accept-and-forget stub
     * would silently skip.
     *
     * The ApcContext is load-bearing, not decoration: with a NULL
     * ApcRoutine it IS the completion value, and the oracle posts NOTHING
     * when it is zero — measured, STATUS_TIMEOUT out of
     * NtRemoveIoCompletion. (dlls/ntdll/unix/file.c NtWriteFile:
     * `send_completion = cvalue != 0`, and cvalue is that context.) Win32
     * never hits the quiet case because the OVERLAPPED pointer is always
     * the context. */
    {
        IO_STATUS_BLOCK iosb;
        LARGE_INTEGER offset;
        ULONG_PTR key = 0, value = 0;
        IO_STATUS_BLOCK packet;
        LARGE_INTEGER timeout;
        char data[8] = "abcdefgh";

        offset.QuadPart = 0;
        iosb.Status = (NTSTATUS)0x0BADF00D;
        status = NtWriteFile(file, NULL, NULL, (PVOID)(ULONG_PTR)0xC0FFEE, &iosb, data,
                             sizeof(data), &offset, NULL);
        ok(status == STATUS_SUCCESS || status == STATUS_PENDING, "async write -> %08lx",
           (unsigned long)status);

        timeout.QuadPart = -50000000; /* 5 s: generous, this must not hang */
        status = NtRemoveIoCompletion(port, &key, &value, &packet, &timeout);
        ok(status == STATUS_SUCCESS, "remove packet -> %08lx", (unsigned long)status);
        if (status == STATUS_SUCCESS)
        {
            ok(key == 0x5150, "packet key %p, expected 5150", (void *)key);
            ok(value == 0xC0FFEE, "packet value %p, expected c0ffee", (void *)value);
            ok(packet.Information == sizeof(data), "packet moved %lu of %lu",
               (unsigned long)packet.Information, (unsigned long)sizeof(data));
        }
    }

    NtClose(file);
    NtClose(port);
}
