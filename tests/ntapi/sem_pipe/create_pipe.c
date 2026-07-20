/*
 * sem_pipe/create_pipe.c — NtCreateNamedPipeFile + client connect (M9).
 *
 * Pins the instance lifecycle rpcrt4's endpoint mapper leans on: create,
 * instance accounting against MaximumInstances, the client NtCreateFile
 * connect (legal before the server ever listens — FSCTL_PIPE_LISTEN on an
 * already-connected instance answers STATUS_PIPE_CONNECTED), disconnect and
 * re-listen, and the FilePipeLocalInformation view of all of it.
 */
#include "util.h"

static void test_create_and_info(void)
{
    IO_STATUS_BLOCK iosb;
    FILE_PIPE_LOCAL_INFORMATION info;
    HANDLE server = NULL;
    NTSTATUS status;

    poison_iosb(&iosb);
    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_create"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 2, &iosb);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "create iosb.Status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == FILE_CREATED, "create iosb.Information %lu",
       (unsigned long)iosb.Information);

    status = query_pipe_local(server, &info);
    ok(status == STATUS_SUCCESS, "query local -> %08lx", (unsigned long)status);
    ok(info.NamedPipeType == FILE_PIPE_TYPE_BYTE, "type %lu", (unsigned long)info.NamedPipeType);
    ok(info.NamedPipeConfiguration == FILE_PIPE_FULL_DUPLEX, "config %lu",
       (unsigned long)info.NamedPipeConfiguration);
    ok(info.MaximumInstances == 2, "max instances %lu", (unsigned long)info.MaximumInstances);
    ok(info.CurrentInstances == 1, "current instances %lu", (unsigned long)info.CurrentInstances);
    ok(info.NamedPipeState == FILE_PIPE_LISTENING_STATE, "state %lu",
       (unsigned long)info.NamedPipeState);
    ok(info.NamedPipeEnd == FILE_PIPE_SERVER_END, "end %lu", (unsigned long)info.NamedPipeEnd);
    ok(info.ReadDataAvailable == 0, "read available %lu", (unsigned long)info.ReadDataAvailable);

    NtClose(server);
}

static void test_instances(void)
{
    IO_STATUS_BLOCK iosb;
    FILE_PIPE_LOCAL_INFORMATION info;
    HANDLE first = NULL, second = NULL, third = NULL;
    NTSTATUS status;

    status = create_pipe_instance(&first, W("\\??\\pipe\\prstest_instances"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 2, &iosb);
    ok(status == STATUS_SUCCESS, "first instance -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    status = create_pipe_instance(&second, W("\\??\\pipe\\prstest_instances"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 2, &iosb);
    ok(status == STATUS_SUCCESS, "second instance -> %08lx", (unsigned long)status);
    ok(iosb.Information == FILE_OPENED, "second iosb.Information %lu",
       (unsigned long)iosb.Information);

    status = query_pipe_local(second, &info);
    ok(status == STATUS_SUCCESS, "query second -> %08lx", (unsigned long)status);
    ok(info.CurrentInstances == 2, "current instances %lu", (unsigned long)info.CurrentInstances);

    status = create_pipe_instance(&third, W("\\??\\pipe\\prstest_instances"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 2, &iosb);
    ok(status == STATUS_INSTANCE_NOT_AVAILABLE, "third instance -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(third);

    NtClose(second);
    NtClose(first);
}

static void test_connect(void)
{
    IO_STATUS_BLOCK iosb;
    FILE_PIPE_LOCAL_INFORMATION info;
    HANDLE server = NULL, client = NULL, busy = NULL;
    NTSTATUS status;

    /* A client connect with no pipe of that name at all. */
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_nosuch"), &iosb);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "connect to missing -> %08lx",
       (unsigned long)status);

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_connect"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);

    /* The client may connect BEFORE the server ever listens: a fresh
     * instance is listening from birth. */
    poison_iosb(&iosb);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_connect"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);
    ok(iosb.Information == FILE_OPENED, "client iosb.Information %lu",
       (unsigned long)iosb.Information);

    status = query_pipe_local(client, &info);
    ok(status == STATUS_SUCCESS, "query client -> %08lx", (unsigned long)status);
    ok(info.NamedPipeState == FILE_PIPE_CONNECTED_STATE, "client state %lu",
       (unsigned long)info.NamedPipeState);
    ok(info.NamedPipeEnd == FILE_PIPE_CLIENT_END, "client end %lu",
       (unsigned long)info.NamedPipeEnd);

    status = query_pipe_local(server, &info);
    ok(status == STATUS_SUCCESS, "query server -> %08lx", (unsigned long)status);
    ok(info.NamedPipeState == FILE_PIPE_CONNECTED_STATE, "server state %lu",
       (unsigned long)info.NamedPipeState);

    /* Listen on the already-connected instance answers PIPE_CONNECTED. */
    poison_iosb(&iosb);
    status = pipe_fsctl(server, FSCTL_PIPE_LISTEN, &iosb);
    ok(status == STATUS_PIPE_CONNECTED, "listen when connected -> %08lx", (unsigned long)status);

    /* Every instance is busy: a second client cannot connect. */
    status = open_pipe_client(&busy, W("\\??\\pipe\\prstest_connect"), &iosb);
    ok(status == STATUS_PIPE_NOT_AVAILABLE, "connect when busy -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(busy);

    NtClose(client);
    NtClose(server);
}

static void test_disconnect(void)
{
    IO_STATUS_BLOCK iosb;
    FILE_PIPE_LOCAL_INFORMATION info;
    HANDLE server = NULL, client = NULL, again = NULL;
    char buffer[8];
    NTSTATUS status;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_disco"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_disco"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    /* Buffered-but-unread bytes are DISCARDED by a disconnect. */
    status = pipe_write(client, "hi", 2, &iosb);
    ok(status == STATUS_SUCCESS, "client write -> %08lx", (unsigned long)status);

    status = pipe_fsctl(server, FSCTL_PIPE_DISCONNECT, &iosb);
    ok(status == STATUS_SUCCESS, "disconnect -> %08lx", (unsigned long)status);

    status = query_pipe_local(server, &info);
    ok(status == STATUS_SUCCESS, "query server -> %08lx", (unsigned long)status);
    ok(info.NamedPipeState == FILE_PIPE_DISCONNECTED_STATE, "server state %lu",
       (unsigned long)info.NamedPipeState);

    /* The orphaned client end answers PIPE_DISCONNECTED to everything. */
    status = pipe_read(client, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_PIPE_DISCONNECTED, "client read -> %08lx", (unsigned long)status);
    status = pipe_write(client, "x", 1, &iosb);
    ok(status == STATUS_PIPE_DISCONNECTED, "client write -> %08lx", (unsigned long)status);
    /* Reads/writes on the disconnected SERVER end fail the same way. */
    status = pipe_read(server, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_PIPE_DISCONNECTED, "server read -> %08lx", (unsigned long)status);
    NtClose(client);

    /* Listen again: the instance returns to listening and accepts a new
     * client (the rpcrt4 accept loop). A blocking listen would park this
     * single-threaded test forever, so flip the server end to nonblocking
     * first — the immediate answer is then STATUS_PIPE_LISTENING. */
    {
        SEM_FILE_PIPE_INFORMATION mode;
        mode.ReadMode = FILE_PIPE_BYTE_STREAM_MODE;
        mode.CompletionMode = FILE_PIPE_COMPLETE_OPERATION;
        status = NtSetInformationFile(server, &iosb, &mode, sizeof(mode), FilePipeInformation);
        ok(status == STATUS_SUCCESS, "nonblocking server -> %08lx", (unsigned long)status);
    }
    status = pipe_fsctl(server, FSCTL_PIPE_LISTEN, &iosb);
    ok(status == STATUS_PIPE_LISTENING, "re-listen -> %08lx", (unsigned long)status);
    status = query_pipe_local(server, &info);
    ok(status == STATUS_SUCCESS, "query server -> %08lx", (unsigned long)status);
    ok(info.NamedPipeState == FILE_PIPE_LISTENING_STATE, "server state %lu",
       (unsigned long)info.NamedPipeState);
    status = open_pipe_client(&again, W("\\??\\pipe\\prstest_disco"), &iosb);
    ok(status == STATUS_SUCCESS, "reconnect -> %08lx", (unsigned long)status);

    NtClose(again);
    NtClose(server);
}

static void test_broken(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    char buffer[8];
    NTSTATUS status;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_broken"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_broken"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    /* Peer close: buffered data survives (drained reads succeed), then the
     * pipe reports broken. */
    status = pipe_write(client, "bye", 3, &iosb);
    ok(status == STATUS_SUCCESS, "client write -> %08lx", (unsigned long)status);
    NtClose(client);

    poison_iosb(&iosb);
    status = pipe_read(server, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_SUCCESS, "drain read -> %08lx", (unsigned long)status);
    ok(iosb.Information == 3, "drain read length %lu", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "bye", 3) == 0, "drain read bytes");

    status = pipe_read(server, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_PIPE_BROKEN, "read after peer close -> %08lx", (unsigned long)status);
    status = pipe_write(server, "x", 1, &iosb);
    ok(status == STATUS_PIPE_CLOSING, "write after peer close -> %08lx", (unsigned long)status);

    NtClose(server);
}

START_TEST(create_pipe)
{
    test_create_and_info();
    test_instances();
    test_connect();
    test_disconnect();
    test_broken();
}
