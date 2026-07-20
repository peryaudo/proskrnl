/*
 * sem_pipe/pipe_blocking.c — blocking listen/read/write (M9). ORACLE-ONLY:
 * threads come from kernel32, so this test never enters the proskrnl
 * manifest (flat binaries are single-threaded); its proskrnl twin is the
 * m9_smoke.exe boot module, which threads through the real ntdll.
 */
#include "util.h"

#ifdef NTAPI_PROSKRNL
START_TEST(pipe_blocking)
{
    skip("threaded blocking test is oracle-only (see m9_smoke.exe)");
}
#else

static DWORD WINAPI connect_thread(void *param)
{
    IO_STATUS_BLOCK iosb;
    HANDLE client = NULL;
    NTSTATUS status;

    Sleep(50);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_blisten"), &iosb);
    ok(status == STATUS_SUCCESS, "thread connect -> %08lx", (unsigned long)status);
    *(HANDLE *)param = client;
    return 0;
}

static void test_blocking_listen(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL, thread;
    NTSTATUS status;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_blisten"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);

    thread = CreateThread(NULL, 0, connect_thread, &client, 0, NULL);
    ok(thread != NULL, "CreateThread");

    /* Blocks until the thread's client shows up. */
    status = pipe_fsctl(server, FSCTL_PIPE_LISTEN, &iosb);
    ok(status == STATUS_SUCCESS, "blocking listen -> %08lx", (unsigned long)status);

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    ok(client != NULL, "client connected");
    if (client)
        NtClose(client);
    NtClose(server);
}

static DWORD WINAPI write_thread(void *param)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    Sleep(50);
    status = pipe_write((HANDLE)param, "wake", 4, &iosb);
    ok(status == STATUS_SUCCESS, "thread write -> %08lx", (unsigned long)status);
    return 0;
}

static void test_blocking_read(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL, thread;
    char buffer[8];
    NTSTATUS status;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_bread"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_bread"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    thread = CreateThread(NULL, 0, write_thread, client, 0, NULL);
    ok(thread != NULL, "CreateThread");

    /* Blocks until the thread's write lands. */
    poison_iosb(&iosb);
    status = pipe_read(server, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_SUCCESS, "blocking read -> %08lx", (unsigned long)status);
    ok(iosb.Information == 4, "blocking read length %lu", (unsigned long)iosb.Information);
    ok(memcmp(buffer, "wake", 4) == 0, "blocking read bytes");

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    NtClose(client);
    NtClose(server);
}

static DWORD WINAPI drain_thread(void *param)
{
    IO_STATUS_BLOCK iosb;
    char buffer[2048];
    NTSTATUS status;

    Sleep(50);
    status = pipe_read((HANDLE)param, buffer, sizeof(buffer), &iosb);
    ok(status == STATUS_SUCCESS, "thread drain -> %08lx", (unsigned long)status);
    return 0;
}

static void test_blocking_write(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL, thread;
    static char big[6000]; /* larger than the 4096 quota: the write must wait
                            * for the reader to drain */
    NTSTATUS status;

    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_bwrite"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_bwrite"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    memset(big, 'q', sizeof(big));
    thread = CreateThread(NULL, 0, drain_thread, client, 0, NULL);
    ok(thread != NULL, "CreateThread");

    poison_iosb(&iosb);
    status = pipe_write(server, big, sizeof(big), &iosb);
    ok(status == STATUS_SUCCESS, "quota-crossing write -> %08lx", (unsigned long)status);
    ok(iosb.Information == sizeof(big), "quota-crossing length %lu",
       (unsigned long)iosb.Information);

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    /* Drain what the thread left so nothing dangles. */
    status = pipe_read(client, big, sizeof(big), &iosb);
    ok(status == STATUS_SUCCESS, "final drain -> %08lx", (unsigned long)status);

    NtClose(client);
    NtClose(server);
}

START_TEST(pipe_blocking)
{
    test_blocking_listen();
    test_blocking_read();
    test_blocking_write();
}
#endif /* NTAPI_PROSKRNL */
