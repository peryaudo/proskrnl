/*
 * sem_pipe/pipe_wait.c — FSCTL_PIPE_WAIT on the named-pipe device root
 * (CUI-3): the WaitNamedPipe path both rpcrt4's ncacn_np client open and
 * sechost's service_open_pipe take. The verb is served only on the device
 * ROOT open (kernelbase opens "\??\PIPE\" synchronously —
 * dlls/kernelbase/sync.c WaitNamedPipeW); on a pipe instance handle it is
 * not supported. Semantics from wine/server/named_pipe.c
 * named_pipe_dir_ioctl: undersized buffer -> INVALID_PARAMETER, unknown
 * name -> OBJECT_NAME_NOT_FOUND (no waiting for creation), a listening
 * instance -> immediate SUCCESS, otherwise park until a listener appears or
 * the timeout (the request's, or the pipe's create-time default) expires ->
 * IO_TIMEOUT.
 */
#include "util.h"

static NTSTATUS open_pipe_root(HANDLE *handle)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;

    init_ustr(&name, W("\\??\\PIPE\\"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    *handle = NULL;
    return NtOpenFile(handle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attr, &iosb,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
}

/* Issue FSCTL_PIPE_WAIT for `name` (no "pipe\" prefix, as WaitNamedPipeW
 * strips it). timeout_ms < 0 sends TimeoutSpecified = FALSE (use the pipe's
 * create-time default). */
static NTSTATUS pipe_wait_fsctl(HANDLE root, const void *name, int timeout_ms,
                                IO_STATUS_BLOCK *iosb)
{
    unsigned char raw[sizeof(SEM_PIPE_WAIT_FOR_BUFFER) + 64 * sizeof(WCHAR)];
    SEM_PIPE_WAIT_FOR_BUFFER *wait = (SEM_PIPE_WAIT_FOR_BUFFER *)raw;
    const unsigned short *p = name;
    ULONG len = 0;

    while (p[len])
        len++;
    wait->Timeout.QuadPart = timeout_ms < 0 ? 0 : -(LONGLONG)timeout_ms * 10000;
    wait->TimeoutSpecified = timeout_ms >= 0;
    wait->NameLength = len * sizeof(WCHAR);
    memcpy(wait->Name, p, len * sizeof(WCHAR));
    return NtFsControlFile(root, NULL, NULL, NULL, iosb, FSCTL_PIPE_WAIT, wait,
                           (ULONG)offsetof(SEM_PIPE_WAIT_FOR_BUFFER, Name[len]), NULL, 0);
}

static DWORD WINAPI create_listener_after_delay(void *param)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL;
    NTSTATUS status;

    Sleep(100);
    status = create_pipe_instance(&server, param, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, 2, &iosb);
    ok(status == STATUS_SUCCESS, "thread listener create -> %08lx", (unsigned long)status);
    return (DWORD)(ULONG_PTR)server;
}

START_TEST(pipe_wait)
{
    IO_STATUS_BLOCK iosb;
    HANDLE root = NULL, server = NULL, client = NULL, server2, thread;
    NTSTATUS status;
    DWORD wait, extra;

    status = open_pipe_root(&root);
    ok(status == STATUS_SUCCESS, "device root open -> %08lx", (unsigned long)status);
    if (root == NULL)
    {
        skip("no device root; FSCTL_PIPE_WAIT unbuilt");
        return;
    }

    /* An unknown pipe name answers immediately — no waiting for creation. */
    status = pipe_wait_fsctl(root, W("prstest_pwnone"), 50, &iosb);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "wait for unknown name -> %08lx",
       (unsigned long)status);

    /* A fresh instance is a listener: immediate success. */
    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_pwait"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 2, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = pipe_wait_fsctl(root, W("prstest_pwait"), 5000, &iosb);
    ok(status == STATUS_SUCCESS, "wait with listener -> %08lx", (unsigned long)status);

    /* Occupy the only instance: the wait must now run its timeout out. */
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_pwait"), &iosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);
    status = pipe_wait_fsctl(root, W("prstest_pwait"), 50, &iosb);
    ok(status == STATUS_IO_TIMEOUT, "wait on busy pipe -> %08lx", (unsigned long)status);

    /* TimeoutSpecified = FALSE falls back to the pipe's create-time default
     * (100 ms in create_pipe_instance) — NtCreateNamedPipeFile's timeout
     * parameter is not decoration. */
    status = pipe_wait_fsctl(root, W("prstest_pwait"), -1, &iosb);
    ok(status == STATUS_IO_TIMEOUT, "wait with default timeout -> %08lx", (unsigned long)status);

    /* A listener appearing mid-wait completes it. */
    thread =
        CreateThread(NULL, 0, create_listener_after_delay, W("\\??\\pipe\\prstest_pwait"), 0, NULL);
    ok(thread != NULL, "CreateThread");
    status = pipe_wait_fsctl(root, W("prstest_pwait"), 5000, &iosb);
    ok(status == STATUS_SUCCESS, "wait for appearing listener -> %08lx", (unsigned long)status);
    wait = WaitForSingleObject(thread, 10000);
    ok(wait == WAIT_OBJECT_0, "listener thread join");
    ok(GetExitCodeThread(thread, &extra) && extra != 0, "listener thread had a handle");
    CloseHandle(thread);
    server2 = (HANDLE)(ULONG_PTR)extra;

    /* An undersized input buffer is rejected before the name is looked at. */
    {
        unsigned char tiny[8] = {0};
        status = NtFsControlFile(root, NULL, NULL, NULL, &iosb, FSCTL_PIPE_WAIT, tiny, sizeof(tiny),
                                 NULL, 0);
        ok(status == STATUS_INVALID_PARAMETER, "undersized wait buffer -> %08lx",
           (unsigned long)status);
    }

    /* On a pipe INSTANCE handle the verb is not supported (wineserver:
     * pipe_end_ioctl falls through to default_fd_ioctl). */
    status = pipe_wait_fsctl(server, W("prstest_pwait"), 50, &iosb);
    ok(status == STATUS_NOT_SUPPORTED, "wait on instance handle -> %08lx", (unsigned long)status);

    if (server2)
        NtClose(server2);
    NtClose(client);
    NtClose(server);
    NtClose(root);
}
