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

/* --- a byte-mode PEEK with a short buffer is not an overflow --------------
 *
 * proskrnl reported STATUS_BUFFER_OVERFLOW from FSCTL_PIPE_PEEK whenever any
 * data was left behind. Only a truncated MESSAGE overflows; in byte mode
 * there is no message to truncate, so leaving data behind is ordinary -- and
 * the normal 1-byte PeekNamedPipe poll, which asks for one byte precisely
 * because it only wants to know whether anything is there, failed.
 *
 * And a byte-type pipe may not be put into message READ mode at all: the
 * oracle refuses at set-info as well as at create, and accepting it made the
 * read path fabricate message framing at arbitrary quota boundaries.
 */
static void test_peek_and_read_mode(void)
{
    HANDLE server = NULL, client = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    unsigned char reply[sizeof(SEM_FILE_PIPE_PEEK_BUFFER) + 8];
    SEM_FILE_PIPE_PEEK_BUFFER *peek = (SEM_FILE_PIPE_PEEK_BUFFER *)reply;
    SEM_FILE_PIPE_INFORMATION pipeInfo;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_bytepeek"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, 0 /* FILE_PIPE_BYTE_STREAM_TYPE */,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "peek pipe server -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_bytepeek"), &iosb);
    ok(status == STATUS_SUCCESS, "peek pipe client -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(server);
        return;
    }

    status = pipe_write(client, "abcdefgh", 8, &iosb);
    ok(status == STATUS_SUCCESS, "seed the peek pipe -> %08lx", (unsigned long)status);

    /* A one-byte peek with seven bytes still queued: SUCCESS, not overflow. */
    memset(reply, 0, sizeof(reply));
    poison_iosb(&iosb);
    status = NtFsControlFile(server, NULL, NULL, NULL, &iosb, FSCTL_PIPE_PEEK, NULL, 0, reply,
                             sizeof(SEM_FILE_PIPE_PEEK_BUFFER) + 1);
    ok(status == STATUS_SUCCESS, "byte-mode peek with a short buffer -> %08lx",
       (unsigned long)status);
    ok(peek->ReadDataAvailable == 8, "peek reports %lu bytes available",
       (unsigned long)peek->ReadDataAvailable);

    /* Message READ mode on a byte-type pipe is refused. */
    pipeInfo.ReadMode = FILE_PIPE_MESSAGE_MODE;
    pipeInfo.CompletionMode = FILE_PIPE_QUEUE_OPERATION;
    poison_iosb(&iosb);
    status = NtSetInformationFile(server, &iosb, &pipeInfo, sizeof(pipeInfo), FilePipeInformation);
    ok(status == STATUS_INVALID_PARAMETER, "message read mode on a byte pipe -> %08lx",
       (unsigned long)status);

    /* Byte read mode is of course fine. */
    pipeInfo.ReadMode = FILE_PIPE_BYTE_STREAM_MODE;
    poison_iosb(&iosb);
    status = NtSetInformationFile(server, &iosb, &pipeInfo, sizeof(pipeInfo), FilePipeInformation);
    ok(status == STATUS_SUCCESS, "byte read mode on a byte pipe -> %08lx", (unsigned long)status);

    NtClose(client);
    NtClose(server);
}

START_TEST(byte_mode)
{
    test_round_trip();
    test_nonblocking_and_available();
    test_peek_and_read_mode();
}
