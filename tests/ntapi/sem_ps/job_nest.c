/*
 * sem_ps/job_nest.c — job nesting, create-time membership with breakaway,
 * and real accounting (CUI-6).
 *
 * Finishes the job surface (docs/02). Oracle behaviour pinned from the
 * pinned tree (server/process.c add_job_process / process_in_job /
 * get_job_pids / release_job_process / terminate_job; the create-time
 * chain walk at DECL_HANDLER(new_process)): assigning a process already in
 * job A to a fresh job B makes B a child of A — both jobs' pid lists and
 * counts then include the process, and NtIsProcessInJob is recursive;
 * assigning to a used, unrelated job refuses STATUS_ACCESS_DENIED;
 * NtTerminateJobObject kills nested members; a child process of a job
 * member joins the job, unless the job carries
 * JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, and CREATE_BREAKAWAY_FROM_JOB
 * without JOB_OBJECT_LIMIT_BREAKAWAY_OK fails creation. The per-job CPU
 * time accounting is beyond_oracle (the oracle zero-fills it under a
 * FIXME; JOBOBJECT_BASIC_ACCOUNTING_INFORMATION.TotalUserTime is the
 * documented sum of member user times — learn.microsoft.com).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

#ifndef CREATE_BREAKAWAY_FROM_JOB
#define CREATE_BREAKAWAY_FROM_JOB 0x01000000
#endif

static int wstr_has(const WCHAR *haystack, const WCHAR *needle)
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

/* Spawn ourselves with a marker; the child sleeps briefly then exits so the
 * parent can inspect job membership while it is alive. flags/loop control the
 * CreateProcess flags and whether the child burns CPU before exiting. */
static BOOL spawn_child(const WCHAR *marker, DWORD flags, PROCESS_INFORMATION *pi)
{
    WCHAR self[512], cmdline[640];
    STARTUPINFOW si;
    int n = 0;
    if (!GetModuleFileNameW(NULL, self, 512))
        return FALSE;
    cmdline[n++] = '"';
    for (int i = 0; self[i]; i++)
        cmdline[n++] = self[i];
    cmdline[n++] = '"';
    cmdline[n++] = ' ';
    for (int i = 0; marker[i]; i++)
        cmdline[n++] = marker[i];
    cmdline[n] = 0;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(pi, 0, sizeof(*pi));
    return CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, flags, NULL, NULL, &si, pi);
}

static BOOL job_has_pid(HANDLE job, ULONG pid)
{
    char raw[sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + 64 * sizeof(ULONG_PTR)];
    JOBOBJECT_BASIC_PROCESS_ID_LIST *list = (JOBOBJECT_BASIC_PROCESS_ID_LIST *)raw;
    memset(raw, 0, sizeof(raw));
    NTSTATUS status =
        NtQueryInformationJobObject(job, JobObjectBasicProcessIdList, raw, sizeof(raw), NULL);
    if (status != STATUS_SUCCESS)
        return FALSE;
    for (ULONG i = 0; i < list->NumberOfProcessIdsInList; i++)
        if ((ULONG)list->ProcessIdList[i] == pid)
            return TRUE;
    return FALSE;
}

static ULONG job_active(HANDLE job)
{
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acct;
    memset(&acct, 0, sizeof(acct));
    if (NtQueryInformationJobObject(job, JobObjectBasicAccountingInformation, &acct, sizeof(acct),
                                    NULL) != STATUS_SUCCESS)
        return 0xffffffff;
    return acct.ActiveProcesses;
}

static void job_child_main(void)
{
    /* Burn a little CPU so the job's user-time accounting is nonzero, then
     * exit. Kept short so the parent's waits are bounded. */
    volatile ULONG sink = 0;
    LARGE_INTEGER start, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    for (;;)
    {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        if ((now.QuadPart - start.QuadPart) * 1000 / freq.QuadPart > 60)
            break;
        for (int i = 0; i < 5000; i++)
            sink += (ULONG)i;
    }
    ExitProcess(0x55);
}

START_TEST(job_nest)
{
    NTSTATUS status;

    if (wstr_has(GetCommandLineW(), L"--nest-child"))
    {
        job_child_main();
        return;
    }

    HANDLE jobA = NULL, jobB = NULL, jobC = NULL;
    status = NtCreateJobObject(&jobA, JOB_OBJECT_ALL_ACCESS, NULL);
    ok(status == STATUS_SUCCESS, "create job A -> %08lx", (unsigned long)status);
    if (jobA == NULL)
    {
        skip("no job objects");
        return;
    }
    NtCreateJobObject(&jobB, JOB_OBJECT_ALL_ACCESS, NULL);
    NtCreateJobObject(&jobC, JOB_OBJECT_ALL_ACCESS, NULL);

    /* --- nesting: A holds a process, assign it to fresh B ------------------ */
    PROCESS_INFORMATION pi;
    ok(spawn_child(L"--nest-child", CREATE_SUSPENDED, &pi), "spawn nest child -> %lu",
       (unsigned long)GetLastError());
    ULONG childPid = GetProcessId(pi.hProcess);

    status = NtAssignProcessToJobObject(jobA, pi.hProcess);
    ok(status == STATUS_SUCCESS, "assign to A -> %08lx", (unsigned long)status);
    ok(job_has_pid(jobA, childPid), "A lists the child");
    ok(job_active(jobA) == 1, "A active %lu", (unsigned long)job_active(jobA));

    /* Fresh B, no processes yet: assigning the A-member makes B a child of A. */
    status = NtAssignProcessToJobObject(jobB, pi.hProcess);
    ok(status == STATUS_SUCCESS, "nest into B -> %08lx", (unsigned long)status);
    ok(job_has_pid(jobB, childPid), "B lists the child");
    /* A still contains it — the pid list and count recurse into the child job. */
    ok(job_has_pid(jobA, childPid), "A still lists the nested child");
    ok(job_active(jobA) == 1, "A still counts the nested child (%lu)",
       (unsigned long)job_active(jobA));
    ok(job_active(jobB) == 1, "B counts the child (%lu)", (unsigned long)job_active(jobB));

    /* NtIsProcessInJob is recursive: the child is "in" A through B. */
    status = NtIsProcessInJob(pi.hProcess, jobA);
    ok(status == STATUS_PROCESS_IN_JOB, "IsProcessInJob(A) recursive -> %08lx",
       (unsigned long)status);
    status = NtIsProcessInJob(pi.hProcess, jobB);
    ok(status == STATUS_PROCESS_IN_JOB, "IsProcessInJob(B) -> %08lx", (unsigned long)status);

    /* --- assigning to a used, unrelated job refuses ------------------------ */
    PROCESS_INFORMATION pc;
    ok(spawn_child(L"--nest-child", CREATE_SUSPENDED, &pc), "spawn C-member");
    status = NtAssignProcessToJobObject(jobC, pc.hProcess);
    ok(status == STATUS_SUCCESS, "seed C -> %08lx", (unsigned long)status);
    /* C now has a process; nesting the A/B child under C would need C to
     * become a child, but C is already used and unrelated -> ACCESS_DENIED. */
    status = NtAssignProcessToJobObject(jobC, pi.hProcess);
    ok(status == STATUS_ACCESS_DENIED, "nest into a used unrelated job -> %08lx",
       (unsigned long)status);
    ResumeThread(pc.hThread);
    WaitForSingleObject(pc.hProcess, 30000);
    CloseHandle(pc.hThread);
    CloseHandle(pc.hProcess);

    /* --- job time accounting (beyond_oracle) ------------------------------- */
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, 30000);
    beyond_oracle
    {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acct;
        memset(&acct, 0, sizeof(acct));
        status = NtQueryInformationJobObject(jobA, JobObjectBasicAccountingInformation, &acct,
                                             sizeof(acct), NULL);
        ok(status == STATUS_SUCCESS, "A accounting -> %08lx", (unsigned long)status);
        ok(acct.TotalProcesses == 1, "A total processes %lu", (unsigned long)acct.TotalProcesses);
        /* The exited member burned CPU; its user time rolled up to A. */
        ok(acct.TotalUserTime.QuadPart > 0, "A total user time %lld",
           (long long)acct.TotalUserTime.QuadPart);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    /* --- create-time membership + breakaway -------------------------------- */
    /* Put OURSELVES in a job, then a plain child joins it automatically. */
    HANDLE selfJob = NULL;
    NtCreateJobObject(&selfJob, JOB_OBJECT_ALL_ACCESS, NULL);
    status = NtAssignProcessToJobObject(selfJob, NtCurrentProcess());
    ok(status == STATUS_SUCCESS, "self into a job -> %08lx", (unsigned long)status);

    PROCESS_INFORMATION pj;
    ok(spawn_child(L"--nest-child", CREATE_SUSPENDED, &pj), "spawn auto-join child");
    ok(job_has_pid(selfJob, GetProcessId(pj.hProcess)), "child auto-joined our job");
    ResumeThread(pj.hThread);
    WaitForSingleObject(pj.hProcess, 30000);
    CloseHandle(pj.hThread);
    CloseHandle(pj.hProcess);

    /* CREATE_BREAKAWAY_FROM_JOB without JOB_OBJECT_LIMIT_BREAKAWAY_OK fails. */
    ok(!spawn_child(L"--nest-child", CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, &pj),
       "breakaway without permission fails");
    ok(GetLastError() == ERROR_ACCESS_DENIED, "breakaway error %lu", (unsigned long)GetLastError());

    /* With SILENT_BREAKAWAY_OK, a plain child does NOT join. */
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION ext;
    memset(&ext, 0, sizeof(ext));
    ext.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
    status =
        NtSetInformationJobObject(selfJob, JobObjectExtendedLimitInformation, &ext, sizeof(ext));
    ok(status == STATUS_SUCCESS, "set silent breakaway -> %08lx", (unsigned long)status);
    ok(spawn_child(L"--nest-child", CREATE_SUSPENDED, &pj), "spawn silent-breakaway child");
    ok(!job_has_pid(selfJob, GetProcessId(pj.hProcess)), "silent-breakaway child stays out");
    ResumeThread(pj.hThread);
    WaitForSingleObject(pj.hProcess, 30000);
    CloseHandle(pj.hThread);
    CloseHandle(pj.hProcess);

    NtClose(selfJob);
    NtClose(jobC);
    NtClose(jobB);
    NtClose(jobA);
}
