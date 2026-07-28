/*
 * sem_pipe/cancel_sync.c — NtCancelSynchronousIoFile (CUI-5).
 *
 * kernelbase's CancelSynchronousIo(thread) is a straight call
 * (dlls/kernelbase/file.c). The contract (pinned Wine dlls/ntdll/unix/
 * file.c + server/async.c cancel_sync): the first argument is a THREAD
 * handle (resolved with THREAD_TERMINATE access); a thread blocked in
 * synchronous I/O has that I/O completed with STATUS_CANCELLED; a thread
 * with nothing in flight answers STATUS_NOT_FOUND; the result IOSB (third
 * argument) receives {status, 0} either way. The blocking I/O here is a
 * pipe read parked on an empty pipe — the one kind of cancellable
 * synchronous wait both backends share.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtCancelSynchronousIoFile(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK);

static HANDLE cancel_read_end;
static volatile NTSTATUS reader_status;

static DWORD WINAPI blocked_reader(void *param)
{
    IO_STATUS_BLOCK iosb;
    char buffer[16];
    (void)param;
    reader_status = pipe_read(cancel_read_end, buffer, sizeof(buffer), &iosb);
    return 0;
}

static DWORD WINAPI idle_thread(void *param)
{
    (void)param;
    Sleep(400);
    return 0;
}

START_TEST(cancel_sync)
{
    IO_STATUS_BLOCK iosb, result;
    HANDLE server = NULL, client = NULL, thread;
    NTSTATUS status;

    /* --- nothing in flight: NOT_FOUND, result IOSB written ------------------ */
    /* (An idle-but-alive thread: a Sleep is a delay, not synchronous I/O.) */
    thread = CreateThread(NULL, 0, idle_thread, NULL, 0, NULL);
    ok(thread != NULL, "CreateThread idle");
    Sleep(50);
    poison_iosb(&result);
    status = NtCancelSynchronousIoFile(thread, NULL, &result);
    ok(status == STATUS_NOT_FOUND, "cancel idle thread -> %08lx", (unsigned long)status);
    ok(result.Status == STATUS_NOT_FOUND, "result iosb.Status %08lx", (unsigned long)result.Status);
    ok(result.Information == 0, "result iosb.Information %lu", (unsigned long)result.Information);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    /* --- a blocked pipe read is cancelled ----------------------------------- */
    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_cancel"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_cancel"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    cancel_read_end = server;
    reader_status = STATUS_PENDING;
    thread = CreateThread(NULL, 0, blocked_reader, NULL, 0, NULL);
    ok(thread != NULL, "CreateThread reader");
    Sleep(100); /* let the reader park on the empty pipe */

    poison_iosb(&result);
    status = NtCancelSynchronousIoFile(thread, NULL, &result);
    ok(status == STATUS_SUCCESS, "cancel blocked reader -> %08lx", (unsigned long)status);
    ok(result.Status == STATUS_SUCCESS, "cancel result iosb.Status %08lx",
       (unsigned long)result.Status);

    ok(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0, "reader never returned");
    ok(reader_status == STATUS_CANCELLED, "cancelled read -> %08lx", (unsigned long)reader_status);

    /* --- the thread is idle again: NOT_FOUND -------------------------------- */
    poison_iosb(&result);
    status = NtCancelSynchronousIoFile(thread, NULL, &result);
    ok(status == STATUS_NOT_FOUND, "cancel after return -> %08lx", (unsigned long)status);
    CloseHandle(thread);

    /* --- the pipe still works after the cancelled read ---------------------- */
    status = pipe_write(client, "ping", 4, &iosb);
    ok(status == STATUS_SUCCESS, "write after cancel -> %08lx", (unsigned long)status);
    {
        char buffer[8];
        poison_iosb(&iosb);
        status = pipe_read(server, buffer, sizeof(buffer), &iosb);
        ok(status == STATUS_SUCCESS && iosb.Information == 4, "read after cancel -> %08lx (%lu)",
           (unsigned long)status, (unsigned long)iosb.Information);
        ok(memcmp(buffer, "ping", 4) == 0, "bytes after cancel");
    }

    NtClose(client);
    NtClose(server);
}
