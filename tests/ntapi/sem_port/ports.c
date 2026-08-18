/*
 * sem_port/ports.c — I/O completion ports (M10).
 *
 * ntdll's own threadpool is the load-bearing consumer: RtlQueueWorkItem and
 * every Tp* wait dispatch through one NtCreateIoCompletion /
 * NtRemoveIoCompletion(Ex) loop fed by NtSetIoCompletion
 * (dlls/ntdll/threadpool.c), and kernelbase re-exports the same object as
 * CreateIoCompletionPort. Pinned here: create, the packet fields
 * (key/value/IOSB), FIFO order, zero-timeout vs blocking removes, the batch
 * remove, depth queries — and the threadpool itself observed end-to-end.
 */
#include "../ntapi.h"

NTSYSAPI NTSTATUS NTAPI NtCreateIoCompletion(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
NTSYSAPI NTSTATUS NTAPI NtSetIoCompletion(HANDLE, ULONG_PTR, ULONG_PTR, NTSTATUS, SIZE_T);
NTSYSAPI NTSTATUS NTAPI NtRemoveIoCompletion(HANDLE, PULONG_PTR, PULONG_PTR, PIO_STATUS_BLOCK,
                                             PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

/* wine/include/winternl.h shapes mingw's winternl.h omits. */
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
NTSYSAPI DWORD NTAPI RtlQueueWorkItem(WORKERCALLBACKFUNC, PVOID, ULONG);

/* char16_t (2-byte) string literal, as Wine's tests spell it. */
#define W(s) u##s

/* CUI-5 additions. */
NTSYSAPI NTSTATUS NTAPI NtOpenIoCompletion(PHANDLE, ACCESS_MASK, const OBJECT_ATTRIBUTES *);
NTSYSAPI NTSTATUS NTAPI NtSetIoCompletionEx(HANDLE, HANDLE, ULONG_PTR, ULONG_PTR, NTSTATUS, SIZE_T);

/* docs/21 W10: the reserve object NtSetIoCompletionEx's second argument
 * actually names. wine/include/winternl.h MEMORY_RESERVE_OBJECT_TYPE,
 * spelled as constants so this compiles against either header set. */
NTSYSAPI NTSTATUS NTAPI NtAllocateReserveObject(PHANDLE, const OBJECT_ATTRIBUTES *, ULONG);
#define RSV_USER_APC      0
#define RSV_IO_COMPLETION 1

static void init_name(UNICODE_STRING *name, OBJECT_ATTRIBUTES *attr, const void *wide)
{
    const unsigned short *p = (const unsigned short *)wide;
    unsigned len = 0;
    while (p[len])
        len++;
    name->Length = (USHORT)(len * 2);
    name->MaximumLength = (USHORT)(len * 2 + 2);
    name->Buffer = (PWSTR)(void *)p;
    attr->Length = sizeof(*attr);
    attr->RootDirectory = NULL;
    attr->ObjectName = name;
    attr->Attributes = OBJ_CASE_INSENSITIVE;
    attr->SecurityDescriptor = NULL;
    attr->SecurityQualityOfService = NULL;
}

#ifndef IO_COMPLETION_ALL_ACCESS
#define IO_COMPLETION_ALL_ACCESS 0x001F0003 /* wine/include/winternl.h */
#endif

static HANDLE late_port;

static DWORD WINAPI late_poster(void *param)
{
    (void)param;
    Sleep(50);
    NtSetIoCompletion(late_port, 7, 8, STATUS_SUCCESS, 9);
    return 0;
}

static HANDLE work_event;

static void NTAPI work_callback(void *param)
{
    (void)param;
    SetEvent(work_event);
}

START_TEST(ports)
{
    NTSTATUS status;
    HANDLE port = NULL;
    ULONG_PTR key, value;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER timeout;

    status = NtCreateIoCompletion(&port, IO_COMPLETION_ALL_ACCESS, NULL, 0);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);

    /* Empty + zero timeout: straight STATUS_TIMEOUT. */
    timeout.QuadPart = 0;
    status = NtRemoveIoCompletion(port, &key, &value, &iosb, &timeout);
    ok(status == STATUS_TIMEOUT, "remove on empty -> %08lx", (unsigned long)status);

    /* One packet: every field travels. */
    status = NtSetIoCompletion(port, 0x11, 0x22, STATUS_END_OF_FILE, 33);
    ok(status == STATUS_SUCCESS, "set -> %08lx", (unsigned long)status);

    IO_COMPLETION_BASIC_INFORMATION basic;
    ULONG returned = 0;
    basic.Depth = -1;
    status =
        NtQueryIoCompletion(port, IoCompletionBasicInformation, &basic, sizeof(basic), &returned);
    ok(status == STATUS_SUCCESS, "query -> %08lx", (unsigned long)status);
    ok(basic.Depth == 1, "depth %ld", (long)basic.Depth);

    key = value = 0;
    memset(&iosb, 0xcc, sizeof(iosb));
    status = NtRemoveIoCompletion(port, &key, &value, &iosb, &timeout);
    ok(status == STATUS_SUCCESS, "remove -> %08lx", (unsigned long)status);
    ok(key == 0x11 && value == 0x22, "packet %lx/%lx", (unsigned long)key, (unsigned long)value);
    ok(iosb.Status == STATUS_END_OF_FILE, "packet status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 33, "packet information %lu", (unsigned long)iosb.Information);

    /* FIFO across three, then a batch remove of two. */
    NtSetIoCompletion(port, 1, 100, STATUS_SUCCESS, 0);
    NtSetIoCompletion(port, 2, 200, STATUS_SUCCESS, 0);
    NtSetIoCompletion(port, 3, 300, STATUS_SUCCESS, 0);
    FILE_IO_COMPLETION_INFORMATION batch[4];
    ULONG written = 0;
    memset(batch, 0, sizeof(batch));
    status = NtRemoveIoCompletionEx(port, batch, 2, &written, &timeout, FALSE);
    ok(status == STATUS_SUCCESS, "remove ex -> %08lx", (unsigned long)status);
    ok(written == 2, "remove ex count %lu", (unsigned long)written);
    ok(batch[0].CompletionKey == 1 && batch[1].CompletionKey == 2, "remove ex order %lu,%lu",
       (unsigned long)batch[0].CompletionKey, (unsigned long)batch[1].CompletionKey);
    status = NtRemoveIoCompletion(port, &key, &value, &iosb, &timeout);
    ok(status == STATUS_SUCCESS && key == 3, "third packet -> %08lx key %lu", (unsigned long)status,
       (unsigned long)key);

    /* --- CUI-5: open-by-name and the Ex post -------------------------------- */
    {
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        HANDLE named = NULL, opened = NULL;
        init_name(&name, &attr, W("\\BaseNamedObjects\\prs_ports_cui5"));
        status = NtCreateIoCompletion(&named, IO_COMPLETION_ALL_ACCESS, &attr, 0);
        ok(status == STATUS_SUCCESS, "create named -> %08lx", (unsigned long)status);
        status = NtOpenIoCompletion(&opened, IO_COMPLETION_ALL_ACCESS, &attr);
        ok(status == STATUS_SUCCESS, "open named -> %08lx", (unsigned long)status);

        /* One object behind both handles: post through the created handle,
         * drain through the opened one. */
        status = NtSetIoCompletion(named, 0x51, 0x52, STATUS_SUCCESS, 53);
        ok(status == STATUS_SUCCESS, "set named -> %08lx", (unsigned long)status);
        timeout.QuadPart = 0;
        key = value = 0;
        status = NtRemoveIoCompletion(opened, &key, &value, &iosb, &timeout);
        ok(status == STATUS_SUCCESS && key == 0x51 && value == 0x52,
           "cross-handle packet -> %08lx %lx/%lx", (unsigned long)status, (unsigned long)key,
           (unsigned long)value);

        /* A missing name refuses. */
        {
            HANDLE absent = NULL;
            init_name(&name, &attr, W("\\BaseNamedObjects\\prs_ports_absent"));
            status = NtOpenIoCompletion(&absent, IO_COMPLETION_ALL_ACCESS, &attr);
            ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "open absent -> %08lx",
               (unsigned long)status);
        }

        /* NtSetIoCompletionEx: a NULL reserve handle refuses up front
         * (dlls/ntdll/unix/sync.c, before the request is even built) and a
         * bogus one must be a real handle. The reserve is an
         * IoCompletionReserve specifically — server/completion.c
         * add_completion resolves it through get_completion_reserve_obj,
         * whose ops argument makes any other object a type mismatch (docs/21
         * W10 built the reserve objects; sem_ps/apc_reserve.c owns the APC
         * half). */
        status = NtSetIoCompletionEx(opened, NULL, 1, 2, STATUS_SUCCESS, 3);
        ok(status == STATUS_INVALID_HANDLE, "set-ex NULL reserve -> %08lx", (unsigned long)status);
        status = NtSetIoCompletionEx(opened, (HANDLE)(ULONG_PTR)0xdead0, 1, 2, STATUS_SUCCESS, 3);
        ok(status == STATUS_INVALID_HANDLE, "set-ex bogus reserve -> %08lx", (unsigned long)status);

        /* The PORT is resolved before the reserve, so a bad port beats a bad
         * reserve (add_completion's get_completion_obj comes first). */
        status = NtSetIoCompletionEx((HANDLE)(ULONG_PTR)0xdead0, (HANDLE)(ULONG_PTR)0xdead0, 1, 2,
                                     STATUS_SUCCESS, 3);
        ok(status == STATUS_INVALID_HANDLE, "set-ex both bogus -> %08lx", (unsigned long)status);

        {
            HANDLE reserve = NULL;
            status = NtAllocateReserveObject(&reserve, NULL, RSV_USER_APC);
            ok(status == STATUS_SUCCESS, "alloc user-apc reserve -> %08lx", (unsigned long)status);
            status = NtSetIoCompletionEx(opened, reserve, 1, 2, STATUS_SUCCESS, 3);
            ok(status == STATUS_OBJECT_TYPE_MISMATCH, "set-ex user-apc reserve -> %08lx",
               (unsigned long)status);
            NtClose(reserve);

            /* ...and the right kind posts a packet like the plain set does. */
            reserve = NULL;
            status = NtAllocateReserveObject(&reserve, NULL, RSV_IO_COMPLETION);
            ok(status == STATUS_SUCCESS, "alloc io-completion reserve -> %08lx",
               (unsigned long)status);
            status = NtSetIoCompletionEx(opened, reserve, 0x61, 0x62, STATUS_SUCCESS, 0x63);
            ok(status == STATUS_SUCCESS, "set-ex with reserve -> %08lx", (unsigned long)status);
            key = value = 0;
            timeout.QuadPart = 0;
            status = NtRemoveIoCompletion(named, &key, &value, &iosb, &timeout);
            ok(status == STATUS_SUCCESS && key == 0x61 && value == 0x62 && iosb.Information == 0x63,
               "reserve packet -> %08lx %lx/%lx/%lx", (unsigned long)status, (unsigned long)key,
               (unsigned long)value, (unsigned long)iosb.Information);

            /* A completion reserve is NOT consumed the way an APC reserve is:
             * add_completion never binds it, so the same handle posts again. */
            status = NtSetIoCompletionEx(opened, reserve, 0x64, 0x65, STATUS_SUCCESS, 0x66);
            ok(status == STATUS_SUCCESS, "set-ex reserve reused -> %08lx", (unsigned long)status);
            key = value = 0;
            status = NtRemoveIoCompletion(named, &key, &value, &iosb, &timeout);
            ok(status == STATUS_SUCCESS && key == 0x64, "reused reserve packet -> %08lx %lx",
               (unsigned long)status, (unsigned long)key);
            NtClose(reserve);
        }

        NtClose(named);
        NtClose(opened);
    }

    /* A blocking remove satisfied by a later set from another thread. */
    late_port = port;
    HANDLE thread = CreateThread(NULL, 0, late_poster, NULL, 0, NULL);
    ok(thread != NULL, "CreateThread");
    timeout.QuadPart = -50000000; /* 5 s bound */
    key = value = 0;
    status = NtRemoveIoCompletion(port, &key, &value, &iosb, &timeout);
    ok(status == STATUS_SUCCESS, "blocking remove -> %08lx", (unsigned long)status);
    ok(key == 7 && value == 8 && iosb.Information == 9, "blocking packet %lu/%lu/%lu",
       (unsigned long)key, (unsigned long)value, (unsigned long)iosb.Information);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    NtClose(port);

    /* The consumer that matters: ntdll's threadpool runs a work item
     * (internally: a completion port fed by NtSetIoCompletion, drained by
     * worker threads in NtRemoveIoCompletion — dlls/ntdll/threadpool.c). */
    work_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(work_event != NULL, "CreateEvent");
    DWORD queued = RtlQueueWorkItem(work_callback, NULL, 0 /* WT_EXECUTEDEFAULT */);
    ok(queued == 0, "RtlQueueWorkItem -> %08lx", (unsigned long)queued);
    ok(WaitForSingleObject(work_event, 10000) == WAIT_OBJECT_0, "work item never ran");
    CloseHandle(work_event);
}
