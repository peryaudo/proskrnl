/*
 * sem_ps/suspend_resume.c — suspended creation + NtResumeThread /
 * NtSuspendThread (M10).
 *
 * kernelbase's CreateProcessInternalW ALWAYS creates the child's initial
 * thread THREAD_CREATE_FLAGS_CREATE_SUSPENDED and releases it with
 * NtResumeThread after the handles are wired (third_party/wine
 * dlls/kernelbase/process.c create_nt_process) — CreateProcess cannot work
 * on a kernel whose resume is a no-op. Pinned here on a thread instead of a
 * process (same machinery, self-contained): the suspend count, the
 * previous-count write-back, and the not-running-until-zero contract.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);
NTSYSAPI NTSTATUS NTAPI NtSuspendThread(HANDLE, PULONG);

static volatile LONG suspended_ran;
static volatile LONG spinner_stop;

static DWORD WINAPI suspended_worker(void *param)
{
    (void)param;
    InterlockedExchange(&suspended_ran, 1);
    return 0;
}

static DWORD WINAPI spinner_worker(void *param)
{
    (void)param;
    while (!spinner_stop)
        Sleep(10);
    return 0;
}

START_TEST(suspend_resume)
{
    NTSTATUS status;
    ULONG prev;

    /* --- create suspended: the thread must not run --------------------------- */
    HANDLE thread = CreateThread(NULL, 0, suspended_worker, NULL, CREATE_SUSPENDED, NULL);
    ok(thread != NULL, "CreateThread suspended");
    Sleep(50);
    ok(!suspended_ran, "suspended thread ran");

    /* Suspend again while never-run: count 1 -> 2. */
    prev = 0xdead;
    status = NtSuspendThread(thread, &prev);
    ok(status == STATUS_SUCCESS, "suspend suspended -> %08lx", (unsigned long)status);
    ok(prev == 1, "suspend previous count %lu", (unsigned long)prev);

    /* First resume: 2 -> 1, still not running. */
    prev = 0xdead;
    status = NtResumeThread(thread, &prev);
    ok(status == STATUS_SUCCESS, "resume(1) -> %08lx", (unsigned long)status);
    ok(prev == 2, "resume(1) previous count %lu", (unsigned long)prev);
    Sleep(30);
    ok(!suspended_ran, "thread ran at count 1");

    /* Second resume: 1 -> 0, the thread runs. */
    prev = 0xdead;
    status = NtResumeThread(thread, &prev);
    ok(status == STATUS_SUCCESS, "resume(2) -> %08lx", (unsigned long)status);
    ok(prev == 1, "resume(2) previous count %lu", (unsigned long)prev);
    WaitForSingleObject(thread, INFINITE);
    ok(suspended_ran, "thread never ran after final resume");

    /* Resume of a not-suspended thread: success, previous count 0. */
    prev = 0xdead;
    status = NtResumeThread(thread, &prev);
    ok(status == STATUS_SUCCESS, "resume not-suspended -> %08lx", (unsigned long)status);
    ok(prev == 0, "resume not-suspended previous count %lu", (unsigned long)prev);
    CloseHandle(thread);

    /* --- suspending a RUNNING thread: the suspend takes effect at the
     * thread's next return to user mode (CUI-4 — the per-thread suspend gate
     * checked at every ring-3 edge, since there is still no kernel
     * preemption). The count semantics are observable regardless of when the
     * target actually parks. --------------------------------------------- */
    HANDLE spinner = CreateThread(NULL, 0, spinner_worker, NULL, 0, NULL);
    ok(spinner != NULL, "CreateThread spinner");
    Sleep(30);
    prev = 0xdead;
    status = NtSuspendThread(spinner, &prev);
    ok(status == STATUS_SUCCESS, "suspend running -> %08lx", (unsigned long)status);
    ok(prev == 0, "suspend running previous count %lu", (unsigned long)prev);
    prev = 0xdead;
    status = NtResumeThread(spinner, &prev);
    ok(status == STATUS_SUCCESS && prev == 1, "resume running -> %08lx prev %lu",
       (unsigned long)status, (unsigned long)prev);
    InterlockedExchange(&spinner_stop, 1);
    WaitForSingleObject(spinner, INFINITE);
    CloseHandle(spinner);
}
