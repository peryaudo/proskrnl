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
