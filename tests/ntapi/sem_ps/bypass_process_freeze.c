/*
 * sem_ps/bypass_process_freeze.c — THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE.
 *
 * A process freeze is per-THREAD, and one create-time bit exempts a thread
 * from it. The oracle stores the bit at birth and then reads it on every
 * arm of both fanouts:
 *
 *     thread->bypass_proc_suspend = !!(req->flags & THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE);
 *         (third_party/wine server/thread.c, create_thread)
 *
 *     DECL_HANDLER(suspend_process) / DECL_HANDLER(resume_process):
 *         LIST_FOR_EACH_SAFE( ... &process->thread_list )
 *             if (!thread->bypass_proc_suspend) suspend_thread( thread );
 *         (third_party/wine server/process.c)
 *
 * so the exemption is symmetric: such a thread is neither stopped by
 * NtSuspendProcess nor counted down by NtResumeProcess. That symmetry is the
 * whole point of the flag — ntdll's own server-request thread carries it
 * (dlls/ntdll/unix/thread.c NtCreateThreadEx's `flags =
 * THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE` for system threads), so a
 * frozen process can still be talked to.
 *
 * A kernel that accepts the flag and freezes the thread anyway does not fail
 * an assertion — it DEADLOCKS, because the exempt thread is exactly the one
 * expected to un-freeze the process. That is how ntdll:thread wedged for a
 * full 300 s timeout with nothing named on serial
 * (test_thread_bypass_process_freeze, third_party/wine
 * dlls/ntdll/tests/thread.c: the created thread calls NtSuspendProcess on its
 * OWN process and is then the only thread able to call NtResumeProcess).
 *
 * So the pin freezes a CHILD process rather than this one: a hang here would
 * cost the leg its timeout and name nothing, while a child that keeps or
 * stops making measurable progress convicts by an assertion. Same shape and
 * same measurement technique as sem_ps/suspend_process.c, which pins the
 * unexempted half.
 *
 * Oracle-first (G5).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtSuspendProcess(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtResumeProcess(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

typedef NTSTATUS(NTAPI *ps_create_thread_ex)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
                                             PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);

/* wine/include/winternl.h; mingw may omit it. The oracle run VALIDATES the
 * value: a wrong bit leaves bypass_proc_suspend clear, the exempt thread
 * freezes with the rest, and the assertion below fails there first. */
#ifndef THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x00000040
#endif

/* Local wide helper: -nostdlib, no CRT wcs*. */
static int wstr_contains(const WCHAR *haystack, const WCHAR *needle)
{
    size_t nlen = 0;
    while (needle[nlen])
        nlen++;
    for (; *haystack; haystack++)
    {
        size_t i = 0;
        while (i < nlen && haystack[i] == needle[i])
            i++;
        if (i == nlen)
            return 1;
    }
    return 0;
}

/* One byte appended per 20 ms per thread, to its own file: the file's LENGTH
 * is the thread's progress, readable from the parent without any shared
 * memory or synchronization with a process that may be frozen mid-write.
 *
 * NOTHING here is a wall-clock judgement, and that is deliberate. The first
 * version of this pin slept 400 ms for the child to get going and 500 ms for
 * the freeze window, which held on a KVM dev box and FAILED on CI, where the
 * child had written zero bytes at 400 ms. Every step below instead WAITS FOR
 * THE OBSERVABLE — "until this file has grown by n" — with a generous cap
 * that is only ever reached when the behaviour is actually wrong. A timing
 * threshold in a differential test measures the runner, not the kernel.
 *
 * The child's threads run until the parent drops a stop file, so a slow
 * runner cannot let them finish before the parent has looked; BPF_MAX_ITERS
 * is only the runaway bound for a parent that died.
 *
 * BPF_WAIT_MS is sized against both failure modes, not just the flake. The CI
 * run that convicted the sleeps had its child writing by ~1.3 s (the two
 * post-resume assertions passed on the same run that failed the three
 * before them), so 30 s is a ~20x margin on the only latency ever measured.
 * It is not larger because a cap is also what a WRONG kernel costs: five
 * waits precede the stop file and a sixth awaits the child, and each polls
 * as well as sleeps, so a fully-capped failing path is upwards of 200 s
 * against the 900 s the ntapi leg gets for ALL of its cases together
 * (tests/run/run.sh TIMEOUT). A pin that eats its leg's timeout names
 * nothing — the same failure this file exists to avoid. BPF_MAX_ITERS
 * covers the 150 s of pre-stop waiting with room to spare, at one iteration
 * per 20 ms; the cost of that bound is that a child orphaned by a parent
 * that died ticks for ~200 s rather than the old fixed 5 s. */
#define BPF_MAX_ITERS   10000
#define BPF_STEP_MS     20
#define BPF_WAIT_MS     30000
#define BPF_PLAIN_PATH  L"C:\\bpfplain.dat"
#define BPF_BYPASS_PATH L"C:\\bpfbyps.dat"
#define BPF_STOP_PATH   L"C:\\bpfstop.dat"

static ULONGLONG file_size(const WCHAR *path)
{
    WIN32_FILE_ATTRIBUTE_DATA data;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &data))
        return 0;
    return ((ULONGLONG)data.nFileSizeHigh << 32) | data.nFileSizeLow;
}

static int file_exists(const WCHAR *path)
{
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

/* Poll until `path` is at least `target` bytes, or the cap expires; return
 * what it reached either way, so the caller's ok() reports the real number. */
static ULONGLONG wait_for_size(const WCHAR *path, ULONGLONG target)
{
    for (int waited = 0; waited < BPF_WAIT_MS; waited += BPF_STEP_MS)
    {
        ULONGLONG size = file_size(path);
        if (size >= target)
            return size;
        Sleep(BPF_STEP_MS);
    }
    return file_size(path);
}

static void tick_loop(const WCHAR *path)
{
    for (int i = 0; i < BPF_MAX_ITERS && !file_exists(BPF_STOP_PATH); i++)
    {
        HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_ALWAYS, 0, NULL);
        if (h != INVALID_HANDLE_VALUE)
        {
            DWORD wrote = 0;
            const char byte = 'x';
            WriteFile(h, &byte, 1, &wrote, NULL);
            CloseHandle(h);
        }
        Sleep(BPF_STEP_MS);
    }
}

static DWORD WINAPI bypass_thread_proc(LPVOID unused)
{
    (void)unused;
    tick_loop(BPF_BYPASS_PATH);
    return 0;
}

static void child_main(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    ps_create_thread_ex createThreadEx =
        ntdll ? (ps_create_thread_ex)(void *)GetProcAddress(ntdll, "NtCreateThreadEx") : NULL;
    HANDLE thread = NULL;

    if (createThreadEx == NULL ||
        createThreadEx(&thread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(),
                       (PVOID)bypass_thread_proc, NULL, THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE,
                       0, 0, 0, NULL) != STATUS_SUCCESS)
    {
        /* The parent's assertions read the two files; a child that never
         * started the exempt thread leaves the bypass file empty, which the
         * parent reports as the failure it is. */
        ExitProcess(1);
    }

    tick_loop(BPF_PLAIN_PATH);
    WaitForSingleObject(thread, BPF_WAIT_MS);
    NtClose(thread);
    ExitProcess(0);
}

START_TEST(bypass_process_freeze)
{
    if (wstr_contains(GetCommandLineW(), L"--bpf-child"))
        child_main(); /* never returns */

    DeleteFileW(BPF_PLAIN_PATH);
    DeleteFileW(BPF_BYPASS_PATH);
    DeleteFileW(BPF_STOP_PATH); /* a leftover would stop the child instantly */

    WCHAR self[512];
    ok(GetModuleFileNameW(NULL, self, 512) != 0, "GetModuleFileNameW");
    WCHAR cmdline[600];
    int n = 0;
    cmdline[n++] = L'"';
    for (int i = 0; self[i] && n < 560; i++)
        cmdline[n++] = self[i];
    cmdline[n++] = L'"';
    const WCHAR *tail = L" --bpf-child";
    for (int i = 0; tail[i]; i++)
        cmdline[n++] = tail[i];
    cmdline[n] = 0;

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    ok(CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi),
       "CreateProcessW child");
    if (!pi.hProcess)
        return;

    /* Wait until BOTH threads are demonstrably running, then freeze. */
    ULONGLONG plainStart = wait_for_size(BPF_PLAIN_PATH, 1);
    ok(plainStart > 0, "ordinary thread never started (%llu bytes)",
       (unsigned long long)plainStart);
    ULONGLONG bypassStart = wait_for_size(BPF_BYPASS_PATH, 1);
    ok(bypassStart > 0, "exempt thread never started (%llu bytes)",
       (unsigned long long)bypassStart);

    NTSTATUS status = NtSuspendProcess(pi.hProcess);
    ok(status == STATUS_SUCCESS, "suspend -> %08lx", (unsigned long)status);

    /* Both baselines are read AFTER the freeze has been issued, never before:
     * the wait above is unbounded in wall-clock terms, so a baseline taken on
     * its way past would let the ordinary thread run an arbitrary amount
     * between the sample and the suspend and read as a freeze failure. */
    ULONGLONG plainBefore = file_size(BPF_PLAIN_PATH);
    ULONGLONG bypassBefore = file_size(BPF_BYPASS_PATH);

    /* The discriminating measurement, and the reason it is a WAIT and not a
     * sleep: hold the process frozen until the exempt thread has added ten
     * more bytes — proof it is running — and only then read the ordinary
     * thread's file. However long that takes, the ordinary thread was frozen
     * for nearly all of it, so it can only add what it had in flight as the
     * freeze arrived. A kernel that freezes the exempt thread too never
     * reaches ten and fails here on the number it actually reached, rather
     * than hanging.
     *
     * The tolerance is 5 and not 0, and the oracle is why: the server replies
     * to suspend_process without waiting for the target to have stopped —
     * third_party/wine server/thread.c suspend_thread -> stop_thread only
     * `send_thread_signal( thread, SIGUSR1 )` — so the ordinary thread halts
     * a scheduling delay AFTER plainBefore was sampled, and on the fanned-out
     * oracle leg (ORACLE_JOBS = nproc workers, this case forking a child with
     * two more ticking threads) that delay is oversubscribed. At one byte per
     * 20 ms a 5-byte window is 100 ms of slack; an unfrozen thread would add
     * tens to hundreds across a window that runs until the exempt thread has
     * managed ten, so nothing is given away. Same number as the sibling pin,
     * sem_ps/suspend_process.c. */
    ULONGLONG bypassFrozen = wait_for_size(BPF_BYPASS_PATH, bypassBefore + 10);
    ULONGLONG plainFrozen = file_size(BPF_PLAIN_PATH);
    ok(bypassFrozen - bypassBefore >= 10,
       "exempt thread advanced only %llu bytes while the process was suspended",
       (unsigned long long)(bypassFrozen - bypassBefore));
    ok(plainFrozen - plainBefore <= 5, "frozen ordinary thread advanced %llu bytes",
       (unsigned long long)(plainFrozen - plainBefore));

    /* Resume. The exempt thread was never counted down, so it must not be
     * over-resumed into anything odd, and the ordinary one must restart. */
    status = NtResumeProcess(pi.hProcess);
    ok(status == STATUS_SUCCESS, "resume -> %08lx", (unsigned long)status);

    ULONGLONG plainAfter = wait_for_size(BPF_PLAIN_PATH, plainFrozen + 1);
    ULONGLONG bypassAfter = wait_for_size(BPF_BYPASS_PATH, bypassFrozen + 1);
    ok(plainAfter > plainFrozen, "ordinary thread made no progress after resume (%llu -> %llu)",
       (unsigned long long)plainFrozen, (unsigned long long)plainAfter);
    ok(bypassAfter > bypassFrozen, "exempt thread stopped after resume (%llu -> %llu)",
       (unsigned long long)bypassFrozen, (unsigned long long)bypassAfter);

    /* The stop file ends both loops, so the child leaves on its OWN — asked,
     * never killed, so the pin depends on no foreign terminate. It is created
     * only here, after every measurement: a child that ended earlier would
     * have ended the experiment with it. FILE_SHARE_READ because the child
     * polls the file with GetFileAttributesW while this handle is open, and a
     * share denial would make the poll miss (harmlessly — it retries in 20 ms
     * — but there is no reason to leave the window there). */
    HANDLE stop =
        CreateFileW(BPF_STOP_PATH, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    ok(stop != INVALID_HANDLE_VALUE, "create stop file -> %lu", (unsigned long)GetLastError());
    if (stop != INVALID_HANDLE_VALUE)
        CloseHandle(stop);
    ok(WaitForSingleObject(pi.hProcess, BPF_WAIT_MS) == WAIT_OBJECT_0,
       "child did not exit after being asked to stop");

    NtClose(pi.hProcess);
    NtClose(pi.hThread);
    DeleteFileW(BPF_PLAIN_PATH);
    DeleteFileW(BPF_BYPASS_PATH);
    DeleteFileW(BPF_STOP_PATH);
}
