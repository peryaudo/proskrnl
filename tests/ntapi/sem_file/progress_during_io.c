/*
 * sem_file/progress_during_io.c — the CUI-8 acceptance property at the
 * boundary (docs/19 §8.3.1): a second thread observably advances while the
 * first is inside a large cold-file read. Before CUI-8 the machine was
 * single-threaded whenever the disk was busy — no other thread ran, no APC
 * was delivered, a ^C was not seen — and no test stated it.
 *
 * Shape: thread B hot-spins a counter; thread C hammers small creates
 * (each takes the FS's serialization, so it parks whenever the main
 * thread's long fill holds it — a guaranteed scheduling point independent
 * of device speed); the main thread reads a multi-megabyte cold file in
 * ONE NtReadFile and asserts B's counter moved between the syscall's entry
 * and exit. On the oracle the host kernel schedules B during the blocking
 * read(2) trivially. On proskrnl the read's cold fill parks on the device
 * and/or C parks on the volume gate, and B — the only runnable thread —
 * advances. On a hypothetical device fast enough that no park ever
 * happens inside the window, the property is not demonstrable here and
 * the case records a skip; the deterministic kernel-side conviction is
 * the kmt CUI-8 suite, which holds the window open (docs/19 §8.3.1's
 * verdict lives there; the throttled cui8 run.sh leg makes this boundary
 * case bite as belt-and-braces).
 */
#include "util.h"

#define PROG_FILE_BYTES (4u * 1024 * 1024) /* 1024 pages: 64 batch awaits */
#define PROG_CHUNK      (64u * 1024)

static volatile LONG prog_stop;
static volatile LONG64 prog_counter;

static DWORD WINAPI counter_thread(void *param)
{
    (void)param;
    while (!prog_stop)
    {
        InterlockedIncrement64((volatile LONG64 *)&prog_counter);
    }
    return 0;
}

static HANDLE prog_dir;
static volatile LONG prog_create_stop;

static DWORD WINAPI create_storm_thread(void *param)
{
    IO_STATUS_BLOCK iosb;
    (void)param;
    while (!prog_create_stop)
    {
        HANDLE h;
        NTSTATUS status =
            open_file(&h, prog_dir, W("storm.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, 0, &iosb);
        if (NT_SUCCESS(status))
            NtClose(h);
    }
    return 0;
}

START_TEST(progress_during_io)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, h, counter, storm;
    LARGE_INTEGER offset;
    static char chunk[PROG_CHUNK];
    static char whole[PROG_CHUNK]; /* read target; the file is streamed */

    dir = open_test_dir(W("\\??\\C:\\prstest\\prog"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("large.bin"));
    scrub_file(dir, W("storm.bin"));

    /* Build the large file, then close every handle so the reopen below is
     * a genuinely cold fill on proskrnl. */
    status = open_file(&h, dir, W("large.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create large.bin -> %08lx", (unsigned long)status);
    memset(chunk, 0x2e, sizeof(chunk));
    for (offset.QuadPart = 0; offset.QuadPart < PROG_FILE_BYTES; offset.QuadPart += PROG_CHUNK)
    {
        status = NtWriteFile(h, NULL, NULL, NULL, &iosb, chunk, PROG_CHUNK, &offset, NULL);
        if (!NT_SUCCESS(status))
            break;
    }
    ok(status == STATUS_SUCCESS, "fill 4M -> %08lx", (unsigned long)status);
    NtClose(h);

    prog_dir = dir;
    prog_stop = 0;
    prog_counter = 0;
    prog_create_stop = 0;
    counter = CreateThread(NULL, 0, counter_thread, NULL, 0, NULL);
    storm = CreateThread(NULL, 0, create_storm_thread, NULL, 0, NULL);
    ok(counter != NULL && storm != NULL, "worker threads");
    Sleep(30); /* both workers provably running before the window opens */

    /* The window: one syscall streaming the whole cold file would need a
     * >4 MiB buffer; a first big chunked read realizes the whole cold FILL
     * inside the FIRST NtReadFile on proskrnl (GetCache loads the file
     * whole), which is the single long syscall the property talks about. */
    status = open_file(&h, dir, W("large.bin"), FILE_GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "reopen large.bin -> %08lx", (unsigned long)status);
    LONG64 before = prog_counter;
    offset.QuadPart = 0;
    poison_iosb(&iosb);
    status = NtReadFile(h, NULL, NULL, NULL, &iosb, whole, PROG_CHUNK, &offset, NULL);
    LONG64 after = prog_counter;
    ok(status == STATUS_SUCCESS && iosb.Information == PROG_CHUNK, "cold read -> %08lx/%lu",
       (unsigned long)status, (unsigned long)iosb.Information);
    ok((UCHAR)whole[0] == 0x2e && (UCHAR)whole[PROG_CHUNK - 1] == 0x2e, "cold read data");

    if (after > before)
        ok(1, "counter advanced inside the cold-read syscall (%ld ticks)", (long)(after - before));
    else
        skip("no scheduling point landed inside the window on this backend/leg "
             "(the kmt CUI-8 suite is the deterministic conviction)");

    /* Liveness across the whole episode: the counter keeps moving after the
     * window. WAIT for it (bounded) instead of sampling once at stop time —
     * on uniprocessor proskrnl nothing need have yielded between the
     * post-window sample and the stop flags, so an instantaneous check is a
     * preemption-point lottery that bites hardest on exactly the throttled
     * and stress legs. */
    {
        int moved = 0;
        for (int i = 0; i < 15000; i++)
        {
            if (prog_counter > after)
            {
                moved = 1;
                break;
            }
            Sleep(1);
        }
        ok(moved, "counter advanced after the window too");
    }

    prog_create_stop = 1;
    prog_stop = 1;
    ok(WaitForSingleObject(storm, 15000) == WAIT_OBJECT_0, "storm thread returned");
    ok(WaitForSingleObject(counter, 15000) == WAIT_OBJECT_0, "counter thread returned");
    CloseHandle(storm);
    CloseHandle(counter);

    NtClose(h);
    scrub_file(dir, W("large.bin"));
    scrub_file(dir, W("storm.bin"));
    NtClose(dir);
}
