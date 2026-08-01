/*
 * sem_file/io_teardown.c — the CUI-8 §7 teardown pin (docs/19 §7: "process
 * or thread teardown with a request in flight").
 *
 * A thread killed while streaming file I/O must not take the file, the
 * volume, or the process with it: the in-flight operation is the kernel's
 * to finish or abandon internally (the §5d ownership rule — the request
 * never outlives its issuer's frame unfinished), and everything observable
 * afterwards — the file's bytes, the volume's ability to serve new opens,
 * other threads' I/O — behaves as if the dead thread had simply stopped
 * issuing. Termination timing is inherently racy, so the assertions are on
 * the AFTERMATH, which is deterministic on both backends.
 */
#include "util.h"

#define TEARDOWN_FILE_BYTES (128 * 1024)

static HANDLE teardown_dir;
static volatile LONG victim_rounds;

/* Stream reads forever (cold reopen every round); the main thread terminates
 * this mid-flight. No cleanup on purpose: the leaked handle is the point —
 * handle sweep at process rundown must cope. */
static DWORD WINAPI teardown_victim(void *param)
{
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    static char chunk[4096];
    (void)param;

    for (;;)
    {
        HANDLE h;
        NTSTATUS status = open_file(&h, teardown_dir, W("victim.bin"), FILE_GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
        if (!NT_SUCCESS(status))
            return 0;
        for (offset.QuadPart = 0; offset.QuadPart < TEARDOWN_FILE_BYTES;
             offset.QuadPart += sizeof(chunk))
        {
            status = NtReadFile(h, NULL, NULL, NULL, &iosb, chunk, sizeof(chunk), &offset, NULL);
            if (!NT_SUCCESS(status))
            {
                NtClose(h);
                return 0;
            }
        }
        NtClose(h);
        victim_rounds++;
    }
    return 0;
}

START_TEST(io_teardown)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, h, thread;
    LARGE_INTEGER offset;
    static char block[4096];
    char buffer[64];

    dir = open_test_dir(W("\\??\\C:\\prstest\\tdwn"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("victim.bin"));
    scrub_file(dir, W("after.bin"));

    status = open_file(&h, dir, W("victim.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create victim.bin -> %08lx", (unsigned long)status);
    memset(block, 0x77, sizeof(block));
    for (offset.QuadPart = 0; offset.QuadPart < TEARDOWN_FILE_BYTES;
         offset.QuadPart += sizeof(block))
    {
        status = NtWriteFile(h, NULL, NULL, NULL, &iosb, block, sizeof(block), &offset, NULL);
        if (!NT_SUCCESS(status))
            break;
    }
    ok(status == STATUS_SUCCESS, "fill 128K -> %08lx", (unsigned long)status);
    NtClose(h);

    /* --- kill the reader mid-stream. ---------------------------------------- */
    teardown_dir = dir;
    victim_rounds = 0;
    thread = CreateThread(NULL, 0, teardown_victim, NULL, 0, NULL);
    ok(thread != NULL, "CreateThread victim");
    Sleep(50); /* let it get properly into the streaming loop */

    ok(TerminateThread(thread, 0), "TerminateThread");
    ok(WaitForSingleObject(thread, 15000) == WAIT_OBJECT_0,
       "terminated thread reaches the signalled state");
    CloseHandle(thread);

    /* --- the aftermath is ordinary. ----------------------------------------
     * The victim's leaked handle may still hold its share grant, so the
     * reopen asks for shared read; the bytes and the volume must be whole. */
    status = open_file(&h, dir, W("victim.bin"), FILE_GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "reopen victim.bin -> %08lx", (unsigned long)status);
    offset.QuadPart = TEARDOWN_FILE_BYTES - 32;
    poison_iosb(&iosb);
    memset(buffer, 0, 32);
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 32, &offset, NULL);
    ok(status == STATUS_SUCCESS && iosb.Information == 32, "tail read -> %08lx/%lu",
       (unsigned long)status, (unsigned long)iosb.Information);
    int intact = 1;
    for (int i = 0; i < 32; i++)
        if (buffer[i] != 0x77)
            intact = 0;
    ok(intact, "victim.bin bytes intact after the kill");
    NtClose(h);

    /* Fresh I/O on the volume works: create, write, read back. */
    status = open_file(&h, dir, W("after.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0,
                       FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create after.bin -> %08lx", (unsigned long)status);
    offset.QuadPart = 0;
    status = NtWriteFile(h, NULL, NULL, NULL, &iosb, "postmortem", 10, &offset, NULL);
    ok(status == STATUS_SUCCESS, "write after kill -> %08lx", (unsigned long)status);
    poison_iosb(&iosb);
    memset(buffer, 0, 16);
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, buffer, 10, &offset, NULL);
    ok(status == STATUS_SUCCESS && memcmp(buffer, "postmortem", 10) == 0,
       "read after kill -> %08lx (%.10s)", (unsigned long)status, buffer);
    NtClose(h);

    scrub_file(dir, W("after.bin"));
    scrub_file(dir, W("victim.bin"));
    NtClose(dir);
}
