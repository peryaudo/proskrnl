/* user/m9/m9_smoke.c — the M9 acceptance client (docs/02).
 *
 * A real MS-ABI PE started by the unmodified Wine ntdll (kernel32 and
 * kernelbase attach at loader time). It proves, from ring 3 and through the
 * Win32 surface:
 *
 *  1. the threaded blocking-pipe protocol — the proskrnl twin of the
 *     oracle-only sem_pipe/pipe_blocking.c: a blocking ConnectNamedPipe
 *     released by a second thread's connect, blocking reads released by
 *     writes, message framing both directions (the rpcrt4 shape);
 *  2. the console: GetConsoleMode on the kernel-seeded std handle and a
 *     WriteConsoleA that travels kernelbase -> NtDeviceIoControlFile ->
 *     ConDrv -> conhost -> the serial wire.
 *
 * User clients follow the test-code conventions (Wine style, docs/15
 * exemption). Exit code 0 = PASS; a distinct nonzero code per failed step.
 */
#include <windows.h>
#include <winternl.h>

static const WCHAR pipe_name[] = L"\\\\.\\pipe\\m9smoke";

/* Serial progress markers, straight through the kernel (hello.c's say()):
 * they place a crash between two steps without touching the console path
 * under test. */
NTSYSAPI NTSTATUS NTAPI NtDisplayString(UNICODE_STRING *string);

static void say(const char *ascii)
{
    WCHAR wide[80];
    USHORT n = 0;
    UNICODE_STRING string;
    while (ascii[n] != '\0' && n < 79)
    {
        wide[n] = (WCHAR)(unsigned char)ascii[n];
        n++;
    }
    string.Length = (USHORT)(n * sizeof(WCHAR));
    string.MaximumLength = string.Length;
    string.Buffer = wide;
    NtDisplayString(&string);
}

/* No CRT in this PE (built -nostdlib, like hello.exe). */
static int mem_equal(const void *a, const void *b, unsigned int n)
{
    const unsigned char *x = a, *y = b;
    while (n--)
        if (*x++ != *y++)
            return 0;
    return 1;
}

static DWORD WINAPI client_thread(void *param)
{
    HANDLE pipe;
    DWORD mode, count;
    char buffer[16];

    (void)param;
    Sleep(50); /* let the server park in ConnectNamedPipe first */

    pipe = CreateFileW(pipe_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (pipe == INVALID_HANDLE_VALUE)
        return 1;

    mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(pipe, &mode, NULL, NULL))
        return 2;

    if (!WriteFile(pipe, "ping", 4, &count, NULL) || count != 4)
        return 3;

    Sleep(50); /* let the server park in its blocking ReadFile reply wait */
    if (!ReadFile(pipe, buffer, sizeof(buffer), &count, NULL) || count != 4)
        return 4;
    if (!mem_equal(buffer, "pong", 4))
        return 5;

    CloseHandle(pipe);
    return 0;
}

static int test_pipes(void)
{
    HANDLE server, thread;
    DWORD count, thread_exit = ~0u;
    char buffer[16];

    say("m9: create pipe\n");
    server = CreateNamedPipeW(pipe_name, PIPE_ACCESS_DUPLEX,
                              PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 4096, 4096,
                              0, NULL);
    if (server == INVALID_HANDLE_VALUE)
        return 10;

    say("m9: create thread\n");
    thread = CreateThread(NULL, 0, client_thread, NULL, 0, NULL);
    if (!thread)
        return 11;

    /* Blocks until the thread's CreateFileW lands. */
    say("m9: listen\n");
    if (!ConnectNamedPipe(server, NULL) && GetLastError() != ERROR_PIPE_CONNECTED)
        return 12;

    /* Blocks until the thread's "ping" lands; one message per read. */
    if (!ReadFile(server, buffer, sizeof(buffer), &count, NULL) || count != 4)
        return 13;
    if (!mem_equal(buffer, "ping", 4))
        return 14;

    if (!WriteFile(server, "pong", 4, &count, NULL) || count != 4)
        return 15;

    if (WaitForSingleObject(thread, 10000) != WAIT_OBJECT_0)
        return 16;
    if (!GetExitCodeThread(thread, &thread_exit))
        return 17;
    if (thread_exit != 0)
        return 20 + (int)thread_exit;

    CloseHandle(thread);
    if (!DisconnectNamedPipe(server))
        return 18;
    CloseHandle(server);
    return 0;
}

static int test_console(void)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0, written = 0;
    static const char line[] = "m9: console write ok\r\n";

    if (!out)
        return 30;
    /* GetConsoleMode round-trips IOCTL_CONDRV_GET_MODE through conhost. */
    if (!GetConsoleMode(out, &mode))
        return 31;
    if (!(mode & ENABLE_PROCESSED_OUTPUT))
        return 32;
    if (!WriteConsoleA(out, line, sizeof(line) - 1, &written, NULL))
        return 33;
    if (written != sizeof(line) - 1)
        return 34;
    return 0;
}

void m9_start(void *peb)
{
    int failures;

    (void)peb;
    say("m9: start\n");
    failures = test_pipes();
    say("m9: pipes done\n");
    if (!failures)
        failures = test_console();
    ExitProcess((UINT)failures);
}
