/*
 * sem_pipe/byte_mode.c — byte-stream data flow (M9).
 *
 * The byte-mode contract: writes coalesce into one stream per direction,
 * reads drain whatever is buffered up to the request, and the nonblocking
 * completion mode (FILE_PIPE_COMPLETE_OPERATION) turns an empty-pipe read
 * into an immediate STATUS_PIPE_EMPTY — the single-threaded probe for the
 * blocking behaviour the threaded tests exercise for real.
 */
#include "util.h"

static void test_round_trip(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    char buffer[32];
    NTSTATUS status;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_bytes"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_bytes"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    /* server -> client, two writes coalesce into one stream. */
    poison_iosb(&iosb);
    status = pipe_write(server, "hello", 5, &iosb);
    ok(status == STATUS_SUCCESS, "write 1 -> %08lx", (unsigned long)status);
    ok(iosb.Information == 5, "write 1 length %lu", (unsigned long)iosb.Information);
    status = pipe_write(server, "world", 5, &iosb);
    ok(status == STATUS_SUCCESS, "write 2 -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    status = pipe_read(client, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_SUCCESS, "coalesced read -> %08lx", (unsigned long)status);
    ok(iosb.Information == 10, "coalesced read length %lu", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "helloworld", 10) == 0, "coalesced read bytes");

    /* client -> server, short reads leave the remainder buffered. */
    status = pipe_write(client, "abcdef", 6, &iosb);
    ok(status == STATUS_SUCCESS, "reverse write -> %08lx", (unsigned long)status);
    poison_iosb(&iosb);
    status = pipe_read(server, buffer, 4, &iosb);
    ok(status == STATUS_SUCCESS, "short read -> %08lx", (unsigned long)status);
    ok(iosb.Information == 4, "short read length %lu", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "abcd", 4) == 0, "short read bytes");
    poison_iosb(&iosb);
    status = pipe_read(server, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_SUCCESS, "remainder read -> %08lx", (unsigned long)status);
    ok(iosb.Information == 2, "remainder length %lu", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "ef", 2) == 0, "remainder bytes");

    NtClose(client);
    NtClose(server);
}

static void test_nonblocking_and_available(void)
{
    IO_STATUS_BLOCK iosb;
    FILE_PIPE_LOCAL_INFORMATION info;
    SEM_FILE_PIPE_INFORMATION mode;
    HANDLE server = NULL, client = NULL;
    char buffer[8];
    NTSTATUS status;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_nb"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_nb"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    /* Switch the server end to nonblocking (complete) mode. */
    mode.ReadMode = FILE_PIPE_BYTE_STREAM_MODE;
    mode.CompletionMode = FILE_PIPE_COMPLETE_OPERATION;
    status = NtSetInformationFile(server, &iosb, &mode, sizeof(mode), FilePipeInformation);
    ok(status == STATUS_SUCCESS, "set complete mode -> %08lx", (unsigned long)status);

    status = NtQueryInformationFile(server, &iosb, &mode, sizeof(mode), FilePipeInformation);
    ok(status == STATUS_SUCCESS, "query pipe info -> %08lx", (unsigned long)status);
    ok(mode.ReadMode == FILE_PIPE_BYTE_STREAM_MODE, "read mode %lu", (unsigned long)mode.ReadMode);
    ok(mode.CompletionMode == FILE_PIPE_COMPLETE_OPERATION, "completion mode %lu",
       (unsigned long)mode.CompletionMode);

    /* An empty nonblocking read returns immediately. */
    status = pipe_read(server, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_PIPE_EMPTY, "empty nonblocking read -> %08lx", (unsigned long)status);

    /* ReadDataAvailable tracks the reader's unread bytes. */
    status = pipe_write(client, "abc", 3, &iosb);
    ok(status == STATUS_SUCCESS, "write -> %08lx", (unsigned long)status);
    status = query_pipe_local(server, &info);
    ok(status == STATUS_SUCCESS, "query local -> %08lx", (unsigned long)status);
    ok(info.ReadDataAvailable == 3, "read available %lu", (unsigned long)info.ReadDataAvailable);

    status = pipe_read(server, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_SUCCESS, "read -> %08lx", (unsigned long)status);
    ok(iosb.Information == 3, "read length %lu", (unsigned long)iosb.Information);

    /* A zero-length byte-mode write completes with nothing to read. */
    poison_iosb(&iosb);
    status = pipe_write(client, buffer, 0, &iosb);
    ok(status == STATUS_SUCCESS, "zero write -> %08lx", (unsigned long)status);
    ok(iosb.Information == 0, "zero write length %lu", (unsigned long)iosb.Information);
    status = pipe_read(server, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_PIPE_EMPTY, "read after zero write -> %08lx", (unsigned long)status);

    NtClose(client);
    NtClose(server);
}

START_TEST(byte_mode)
{
    test_round_trip();
    test_nonblocking_and_available();
}
