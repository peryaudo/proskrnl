/*
 * sem_ps/job.c — the job-object subset services.exe drives at startup
 * (CUI-3): create a job, set breakaway limits, associate a completion port,
 * assign a process, and read the lifecycle off the port
 * (JOB_OBJECT_MSG_NEW_PROCESS -> EXIT_PROCESS -> ACTIVE_PROCESS_ZERO — the
 * packets process_monitor_thread_proc in programs/services/services.c
 * consumes). Packet shape (wine/server/process.c add_job_completion):
 * key = CompletionKey, value = pid, iosb = {STATUS_SUCCESS, message}.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG,
                                          ULONG);

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

/* Spawn ourselves suspended with the --job-child marker (the child just
 * exits). Mirrors how services.exe holds a service process suspended until
 * it is inside the job. */
static BOOL spawn_suspended_child(PROCESS_INFORMATION *pi)
{
    WCHAR self[512], cmdline[600];
    STARTUPINFOW si;
    int n = 0;

    if (!GetModuleFileNameW(NULL, self, 512))
        return FALSE;
    cmdline[n++] = '"';
    for (int i = 0; self[i]; i++)
        cmdline[n++] = self[i];
    cmdline[n] = 0;
    const WCHAR *tail = L"\" --job-child";
    for (int i = 0; tail[i]; i++)
        cmdline[n + i] = tail[i], cmdline[n + i + 1] = 0;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(pi, 0, sizeof(*pi));
    return CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, pi);
}

/* One packet off the port, bounded. */
static NTSTATUS drain_packet(HANDLE port, ULONG_PTR *key, ULONG_PTR *value, IO_STATUS_BLOCK *iosb,
                             int timeout_ms)
{
    LARGE_INTEGER timeout;
    timeout.QuadPart = -(LONGLONG)timeout_ms * 10000;
    *key = 0;
    *value = 0;
    poison_iosb(iosb);
    return NtRemoveIoCompletion(port, key, value, iosb, &timeout);
}

static void test_limits(HANDLE job)
{
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION ext;
    JOBOBJECT_BASIC_LIMIT_INFORMATION basic;
    NTSTATUS status;

    /* Wrong size and invalid flags are rejected before anything sticks;
     * class ids at/above the ceiling too (wine/dlls/ntdll/unix/sync.c
     * NtSetInformationJobObject). */
    memset(&ext, 0, sizeof(ext));
    status =
        NtSetInformationJobObject(job, JobObjectExtendedLimitInformation, &ext, sizeof(ext) - 1);
    ok(status == STATUS_INVALID_PARAMETER, "ext wrong size -> %08lx", (unsigned long)status);
    ext.BasicLimitInformation.LimitFlags = ~(DWORD)JOB_OBJECT_EXTENDED_LIMIT_VALID_FLAGS;
    status = NtSetInformationJobObject(job, JobObjectExtendedLimitInformation, &ext, sizeof(ext));
    ok(status == STATUS_INVALID_PARAMETER, "ext invalid flags -> %08lx", (unsigned long)status);
    /* Above the class ceiling (Wine's MaxJobObjectInfoClass is 53; mingw's
     * enum is shorter, so spell the probe as a raw id). */
    status = NtSetInformationJobObject(job, (JOBOBJECTINFOCLASS)1000, &ext, sizeof(ext));
    ok(status == STATUS_INVALID_PARAMETER, "class ceiling -> %08lx", (unsigned long)status);

    /* CUI-5 fuzzer-found: a handle without JOB_OBJECT_SET_ATTRIBUTES cannot
     * set limits (wine server/process.c set_job_limits resolves the handle
     * with exactly that right). */
    {
        HANDLE weak = NULL;
        NTSTATUS dupStatus = NtDuplicateObject(GetCurrentProcess(), job, GetCurrentProcess(), &weak,
                                               JOB_OBJECT_QUERY, 0, 0);
        ok(dupStatus == STATUS_SUCCESS, "dup query-only -> %08lx", (unsigned long)dupStatus);
        if (NT_SUCCESS(dupStatus))
        {
            memset(&ext, 0, sizeof(ext));
            status = NtSetInformationJobObject(weak, JobObjectExtendedLimitInformation, &ext,
                                               sizeof(ext));
            ok(status == STATUS_ACCESS_DENIED, "set without SET_ATTRIBUTES -> %08lx",
               (unsigned long)status);
            NtClose(weak);
        }
    }

    /* The exact call services.exe makes at startup (services.c main). */
    memset(&ext, 0, sizeof(ext));
    ext.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
    status = NtSetInformationJobObject(job, JobObjectExtendedLimitInformation, &ext, sizeof(ext));
    ok(status == STATUS_SUCCESS, "ext breakaway limits -> %08lx", (unsigned long)status);

    /* The BASIC class takes only the basic mask (0xff): the breakaway bits
     * are extended-only and bounce. */
    memset(&basic, 0, sizeof(basic));
    basic.LimitFlags = JOB_OBJECT_LIMIT_BREAKAWAY_OK;
    status = NtSetInformationJobObject(job, JobObjectBasicLimitInformation, &basic, sizeof(basic));
    ok(status == STATUS_INVALID_PARAMETER, "basic breakaway bounces -> %08lx",
       (unsigned long)status);
    basic.LimitFlags = JOB_OBJECT_LIMIT_WORKINGSET;
    status = NtSetInformationJobObject(job, JobObjectBasicLimitInformation, &basic, sizeof(basic));
    ok(status == STATUS_SUCCESS, "basic limits -> %08lx", (unsigned long)status);
}

static void test_lifecycle_packets(HANDLE job)
{
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT assoc;
    PROCESS_INFORMATION pi;
    IO_STATUS_BLOCK iosb;
    ULONG_PTR key, value;
    HANDLE port = NULL;
    NTSTATUS status;

    status = NtCreateIoCompletion(&port, IO_COMPLETION_ALL_ACCESS, NULL, 1);
    ok(status == STATUS_SUCCESS, "NtCreateIoCompletion -> %08lx", (unsigned long)status);

    assoc.CompletionKey = (void *)(ULONG_PTR)0x5CA1AB1E;
    assoc.CompletionPort = port;
    status = NtSetInformationJobObject(job, JobObjectAssociateCompletionPortInformation, &assoc,
                                       sizeof(assoc) - 1);
    ok(status == STATUS_INVALID_PARAMETER, "assoc wrong size -> %08lx", (unsigned long)status);
    status = NtSetInformationJobObject(job, JobObjectAssociateCompletionPortInformation, &assoc,
                                       sizeof(assoc));
    ok(status == STATUS_SUCCESS, "assoc port -> %08lx", (unsigned long)status);

    ok(spawn_suspended_child(&pi), "spawn suspended child -> %lu", (unsigned long)GetLastError());

    status = NtAssignProcessToJobObject(job, pi.hProcess);
    ok(status == STATUS_SUCCESS, "assign -> %08lx", (unsigned long)status);

    /* NEW_PROCESS lands at assignment (the port is already associated). */
    status = drain_packet(port, &key, &value, &iosb, 5000);
    ok(status == STATUS_SUCCESS, "drain new-process -> %08lx", (unsigned long)status);
    ok(key == 0x5CA1AB1E, "new-process key %lx", (unsigned long)key);
    ok(value == pi.dwProcessId, "new-process pid %lu (want %lu)", (unsigned long)value,
       (unsigned long)pi.dwProcessId);
    ok(iosb.Status == STATUS_SUCCESS, "new-process iosb %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == JOB_OBJECT_MSG_NEW_PROCESS, "new-process msg %lu",
       (unsigned long)iosb.Information);

    ok(ResumeThread(pi.hThread) != (DWORD)-1, "resume child");
    ok(WaitForSingleObject(pi.hProcess, 30000) == WAIT_OBJECT_0, "child wait");

    /* EXIT_PROCESS carries the pid; the job then drains to zero. */
    status = drain_packet(port, &key, &value, &iosb, 5000);
    ok(status == STATUS_SUCCESS, "drain exit-process -> %08lx", (unsigned long)status);
    ok(key == 0x5CA1AB1E, "exit-process key %lx", (unsigned long)key);
    ok(value == pi.dwProcessId, "exit-process pid %lu", (unsigned long)value);
    ok(iosb.Information == JOB_OBJECT_MSG_EXIT_PROCESS, "exit-process msg %lu",
       (unsigned long)iosb.Information);

    status = drain_packet(port, &key, &value, &iosb, 5000);
    ok(status == STATUS_SUCCESS, "drain zero -> %08lx", (unsigned long)status);
    ok(iosb.Information == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO, "zero msg %lu",
       (unsigned long)iosb.Information);
    ok(value == 0, "zero pid %lu", (unsigned long)value);

    /* Nothing else: the port runs dry. */
    status = drain_packet(port, &key, &value, &iosb, 100);
    ok(status == STATUS_TIMEOUT, "port dry -> %08lx", (unsigned long)status);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    NtClose(port);
}

/* Associating a port AFTER a process is already in the job posts
 * NEW_PROCESS for the existing member (wine/server/process.c
 * add_job_completion_existing_processes) — services.exe does not rely on
 * it, but the ordering must not matter for correctness. */
static void test_existing_process_packet(void)
{
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT assoc;
    PROCESS_INFORMATION pi;
    IO_STATUS_BLOCK iosb;
    ULONG_PTR key, value;
    HANDLE job = NULL, port = NULL;
    NTSTATUS status;

    status = NtCreateJobObject(&job, JOB_OBJECT_ALL_ACCESS, NULL);
    ok(status == STATUS_SUCCESS, "second job create -> %08lx", (unsigned long)status);
    status = NtCreateIoCompletion(&port, IO_COMPLETION_ALL_ACCESS, NULL, 1);
    ok(status == STATUS_SUCCESS, "second port create -> %08lx", (unsigned long)status);

    ok(spawn_suspended_child(&pi), "spawn suspended child -> %lu", (unsigned long)GetLastError());
    status = NtAssignProcessToJobObject(job, pi.hProcess);
    ok(status == STATUS_SUCCESS, "assign before port -> %08lx", (unsigned long)status);

    assoc.CompletionKey = (void *)(ULONG_PTR)0x0DDBA11;
    assoc.CompletionPort = port;
    status = NtSetInformationJobObject(job, JobObjectAssociateCompletionPortInformation, &assoc,
                                       sizeof(assoc));
    ok(status == STATUS_SUCCESS, "late assoc -> %08lx", (unsigned long)status);

    status = drain_packet(port, &key, &value, &iosb, 5000);
    ok(status == STATUS_SUCCESS, "drain existing member -> %08lx", (unsigned long)status);
    ok(key == 0x0DDBA11, "existing member key %lx", (unsigned long)key);
    ok(value == pi.dwProcessId, "existing member pid %lu", (unsigned long)value);
    ok(iosb.Information == JOB_OBJECT_MSG_NEW_PROCESS, "existing member msg %lu",
       (unsigned long)iosb.Information);

    ok(ResumeThread(pi.hThread) != (DWORD)-1, "resume child");
    ok(WaitForSingleObject(pi.hProcess, 30000) == WAIT_OBJECT_0, "child wait");
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    NtClose(port);
    NtClose(job);
}

START_TEST(job)
{
    HANDLE job = NULL;
    NTSTATUS status;

    if (wstr_contains(GetCommandLineW(), L"--job-child"))
        ExitProcess(0x77); /* never returns */

    status = NtCreateJobObject(&job, JOB_OBJECT_ALL_ACCESS, NULL);
    ok(status == STATUS_SUCCESS, "NtCreateJobObject -> %08lx", (unsigned long)status);
    if (job == NULL)
    {
        skip("no job objects; the CUI-3 surface is unbuilt");
        return;
    }

    test_limits(job);
    test_lifecycle_packets(job);
    test_existing_process_packet();
    NtClose(job);
}
