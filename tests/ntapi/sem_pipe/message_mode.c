/*
 * sem_pipe/message_mode.c — message-type pipes (M9): THE rpcrt4 gate.
 *
 * rpcrt4's ncacn_np transport frames every PDU as one pipe message and
 * depends on: one message per read, a too-small read returning
 * STATUS_BUFFER_OVERFLOW with the buffer filled and the tail delivered by
 * the next read, zero-byte messages being real messages, and a message-type
 * pipe read in byte mode crossing message boundaries.
 */
#include "util.h"

static void make_message_pair(const void *wide_name, HANDLE *server, HANDLE *client)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    status = create_pipe_instance(server, wide_name, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  FILE_PIPE_TYPE_MESSAGE, FILE_PIPE_MESSAGE_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(client, wide_name, &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* The client end starts in byte read mode; message-framed reads need
     * an explicit switch (what SetNamedPipeHandleState does for rpcrt4). */
    if (*client)
    {
        SEM_FILE_PIPE_INFORMATION mode;
        mode.ReadMode = FILE_PIPE_MESSAGE_MODE;
        mode.CompletionMode = FILE_PIPE_QUEUE_OPERATION;
        status = NtSetInformationFile(*client, &iosb, &mode, sizeof(mode), FilePipeInformation);
        ok(status == STATUS_SUCCESS, "client message mode -> %08lx", (unsigned long)status);
    }
}

static void test_message_boundaries(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    char buffer[32];
    NTSTATUS status;

    make_message_pair(W("\\??\\pipe\\prstest_msg"), &server, &client);

    /* Two writes stay two messages: a large read returns only the first. */
    status = pipe_write(server, "hello", 5, &iosb);
    ok(status == STATUS_SUCCESS, "write 1 -> %08lx", (unsigned long)status);
    status = pipe_write(server, "ab", 2, &iosb);
    ok(status == STATUS_SUCCESS, "write 2 -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    status = pipe_read(client, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_SUCCESS, "read 1 -> %08lx", (unsigned long)status);
    ok(iosb.Information == 5, "read 1 length %lu", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "hello", 5) == 0, "read 1 bytes");

    poison_iosb(&iosb);
    status = pipe_read(client, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_SUCCESS, "read 2 -> %08lx", (unsigned long)status);
    ok(iosb.Information == 2, "read 2 length %lu", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "ab", 2) == 0, "read 2 bytes");

    /* The reverse direction frames independently. */
    status = pipe_write(client, "pong", 4, &iosb);
    ok(status == STATUS_SUCCESS, "reverse write -> %08lx", (unsigned long)status);
    poison_iosb(&iosb);
    status = pipe_read(server, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_SUCCESS, "reverse read -> %08lx", (unsigned long)status);
    ok(iosb.Information == 4, "reverse read length %lu", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "pong", 4) == 0, "reverse read bytes");

    NtClose(client);
    NtClose(server);
}

static void test_partial_message(void)
{
    IO_STATUS_BLOCK iosb;
    FILE_PIPE_LOCAL_INFORMATION info;
    HANDLE server = NULL, client = NULL;
    char buffer[16];
    NTSTATUS status;

    make_message_pair(W("\\??\\pipe\\prstest_partial"), &server, &client);

    status = pipe_write(server, "abcdefgh", 8, &iosb);
    ok(status == STATUS_SUCCESS, "write -> %08lx", (unsigned long)status);
    status = query_pipe_local(client, &info);
    ok(status == STATUS_SUCCESS, "query local -> %08lx", (unsigned long)status);
    ok(info.ReadDataAvailable == 8, "read available %lu", (unsigned long)info.ReadDataAvailable);

    /* A short read fills the buffer and keeps the tail as the SAME message:
     * STATUS_BUFFER_OVERFLOW, Information = what was copied. */
    poison_iosb(&iosb);
    status = pipe_read(client, buffer, 3, &iosb);
    ok(status == STATUS_BUFFER_OVERFLOW, "partial read -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_BUFFER_OVERFLOW, "partial iosb.Status %08lx",
       (unsigned long)iosb.Status);
    ok(iosb.Information == 3, "partial length %lu", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "abc", 3) == 0, "partial bytes");

    poison_iosb(&iosb);
    status = pipe_read(client, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_SUCCESS, "tail read -> %08lx", (unsigned long)status);
    ok(iosb.Information == 5, "tail length %lu", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "defgh", 5) == 0, "tail bytes");

    NtClose(client);
    NtClose(server);
}

static void test_zero_byte_message(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    char buffer[8];
    NTSTATUS status;

    make_message_pair(W("\\??\\pipe\\prstest_zero"), &server, &client);

    /* A zero-byte message is a real message: the read completes (with 0
     * bytes) instead of blocking, and the next message follows intact. */
    poison_iosb(&iosb);
    status = pipe_write(server, buffer, 0, &iosb);
    ok(status == STATUS_SUCCESS, "zero write -> %08lx", (unsigned long)status);
    ok(iosb.Information == 0, "zero write length %lu", (unsigned long)iosb.Information);
    status = pipe_write(server, "next", 4, &iosb);
    ok(status == STATUS_SUCCESS, "next write -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    status = pipe_read(client, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_SUCCESS, "zero read -> %08lx", (unsigned long)status);
    ok(iosb.Information == 0, "zero read length %lu", (unsigned long)iosb.Information);

    poison_iosb(&iosb);
    status = pipe_read(client, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_SUCCESS, "next read -> %08lx", (unsigned long)status);
    ok(iosb.Information == 4, "next read length %lu", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "next", 4) == 0, "next read bytes");

    NtClose(client);
    NtClose(server);
}

static void test_byte_read_of_messages(void)
{
    IO_STATUS_BLOCK iosb;
    SEM_FILE_PIPE_INFORMATION mode;
    HANDLE server = NULL, client = NULL;
    char buffer[16];
    NTSTATUS status;

    make_message_pair(W("\\??\\pipe\\prstest_bmr"), &server, &client);

    /* Drop the client back to byte read mode: reads now cross message
     * boundaries (rpcrt4 does the opposite switch; both must work). */
    mode.ReadMode = FILE_PIPE_BYTE_STREAM_MODE;
    mode.CompletionMode = FILE_PIPE_QUEUE_OPERATION;
    status = NtSetInformationFile(client, &iosb, &mode, sizeof(mode), FilePipeInformation);
    ok(status == STATUS_SUCCESS, "byte read mode -> %08lx", (unsigned long)status);

    status = pipe_write(server, "one", 3, &iosb);
    ok(status == STATUS_SUCCESS, "write 1 -> %08lx", (unsigned long)status);
    status = pipe_write(server, "two", 3, &iosb);
    ok(status == STATUS_SUCCESS, "write 2 -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    status = pipe_read(client, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_SUCCESS, "merged read -> %08lx", (unsigned long)status);
    ok(iosb.Information == 6, "merged read length %lu", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "onetwo", 6) == 0, "merged read bytes");

    NtClose(client);
    NtClose(server);
}

START_TEST(message_mode)
{
    test_message_boundaries();
    test_partial_message();
    test_zero_byte_message();
    test_byte_read_of_messages();
}
