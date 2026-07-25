/*
 * sem_ps/job_query.c — the job surface a build tool drives (CUI-4).
 *
 * CUI-3 built create/assign/limits/completion-port for services.exe; a real
 * job-using build tool also reads the job back and relies on its children
 * dying with it. Pinned here: NtQueryInformationJobObject's accounting and
 * process-id list, NtIsProcessInJob's two success codes
 * (STATUS_PROCESS_IN_JOB / _NOT_IN_JOB — wineserver process_in_job, with a
 * null job handle asking "in ANY job"), and NtTerminateJobObject. Green on
 * the pinned Wine oracle first (Art. 5).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryInformationJobObject(HANDLE, JOBOBJECTINFOCLASS, PVOID, ULONG,
                                                    PULONG);
NTSYSAPI NTSTATUS NTAPI NtTerminateJobObject(HANDLE, NTSTATUS);
NTSYSAPI NTSTATUS NTAPI NtIsProcessInJob(HANDLE, HANDLE);

/* The two query shapes the test reads (wine/include/winnt.h layouts). */
typedef struct
{
    LARGE_INTEGER TotalUserTime;
    LARGE_INTEGER TotalKernelTime;
    LARGE_INTEGER ThisPeriodTotalUserTime;
    LARGE_INTEGER ThisPeriodTotalKernelTime;
    DWORD TotalPageFaultCount;
    DWORD TotalProcesses;
    DWORD ActiveProcesses;
    DWORD TotalTerminatedProcesses;
} ps_job_basic_accounting;

typedef struct
{
    DWORD NumberOfAssignedProcesses;
    DWORD NumberOfProcessIdsInList;
    ULONG_PTR ProcessIdList[8];
} ps_job_pid_list;

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

static BOOL spawn_child(const WCHAR *marker, PROCESS_INFORMATION *pi)
{
    WCHAR self[512];
    GetModuleFileNameW(NULL, self, 512);
    WCHAR cmdline[600];
    int n = 0;
    cmdline[n++] = L'"';
    for (int i = 0; self[i] && n < 540; i++)
        cmdline[n++] = self[i];
    cmdline[n++] = L'"';
    cmdline[n++] = L' ';
    for (int i = 0; marker[i]; i++)
        cmdline[n++] = marker[i];
    cmdline[n] = 0;

    STARTUPINFOW si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(pi, 0, sizeof(*pi));
    return CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, pi);
}

START_TEST(job_query)
{
    if (wstr_contains(GetCommandLineW(), L"--job-member"))
    {
        Sleep(30000); /* the job terminates us long before this */
        ExitProcess(0);
    }

    NTSTATUS status;
    HANDLE job = NULL;
    status = NtCreateJobObject(&job, JOB_OBJECT_ALL_ACCESS, NULL);
    ok(status == STATUS_SUCCESS, "NtCreateJobObject -> %08lx", (unsigned long)status);
    if (!job)
        return;

    /* --- an empty job's accounting -------------------------------------- */
    ps_job_basic_accounting acct;
    memset(&acct, 0xcc, sizeof(acct));
    ULONG retLen = 0;
    status = NtQueryInformationJobObject(job, JobObjectBasicAccountingInformation, &acct,
                                         sizeof(acct), &retLen);
    ok(status == STATUS_SUCCESS, "empty accounting -> %08lx", (unsigned long)status);
    ok(retLen == sizeof(acct), "accounting returned %lu bytes", (unsigned long)retLen);
    ok(acct.ActiveProcesses == 0, "empty job has %lu active", (unsigned long)acct.ActiveProcesses);
    ok(acct.TotalProcesses == 0, "empty job has %lu total", (unsigned long)acct.TotalProcesses);

    /* --- self is in no job yet ------------------------------------------ */
    status = NtIsProcessInJob(NtCurrentProcess(), NULL);
    ok(status == STATUS_PROCESS_NOT_IN_JOB, "self in any job -> %08lx", (unsigned long)status);
    status = NtIsProcessInJob(NtCurrentProcess(), job);
    ok(status == STATUS_PROCESS_NOT_IN_JOB, "self in this job -> %08lx", (unsigned long)status);

    /* --- assign two children -------------------------------------------- */
    PROCESS_INFORMATION kids[2];
    int assigned = 0;
    for (int i = 0; i < 2; i++)
    {
        if (!spawn_child(L"--job-member", &kids[i]))
        {
            kids[i].hProcess = NULL;
            continue;
        }
        status = NtAssignProcessToJobObject(job, kids[i].hProcess);
        ok(status == STATUS_SUCCESS, "assign child %d -> %08lx", i, (unsigned long)status);
        if (status == STATUS_SUCCESS)
            assigned++;
        ResumeThread(kids[i].hThread);
    }
    ok(assigned == 2, "assigned %d children", assigned);
    Sleep(200); /* let them start */

    /* --- the members show up in the accounting and the pid list --------- */
    memset(&acct, 0, sizeof(acct));
    status = NtQueryInformationJobObject(job, JobObjectBasicAccountingInformation, &acct,
                                         sizeof(acct), &retLen);
    ok(status == STATUS_SUCCESS, "populated accounting -> %08lx", (unsigned long)status);
    ok(acct.ActiveProcesses == 2, "job reports %lu active, wanted 2",
       (unsigned long)acct.ActiveProcesses);
    ok(acct.TotalProcesses >= 2, "job reports %lu total", (unsigned long)acct.TotalProcesses);

    ps_job_pid_list pids;
    memset(&pids, 0, sizeof(pids));
    status =
        NtQueryInformationJobObject(job, JobObjectBasicProcessIdList, &pids, sizeof(pids), &retLen);
    ok(status == STATUS_SUCCESS, "pid list -> %08lx", (unsigned long)status);
    ok(pids.NumberOfAssignedProcesses == 2, "pid list claims %lu assigned",
       (unsigned long)pids.NumberOfAssignedProcesses);
    ok(pids.NumberOfProcessIdsInList == 2, "pid list returned %lu ids",
       (unsigned long)pids.NumberOfProcessIdsInList);
    for (DWORD i = 0; i < pids.NumberOfProcessIdsInList && i < 2; i++)
    {
        int matches = 0;
        for (int k = 0; k < 2; k++)
            if (kids[k].hProcess && pids.ProcessIdList[i] == (ULONG_PTR)kids[k].dwProcessId)
                matches = 1;
        ok(matches, "pid list entry %lu (%llu) is not one of our children", (unsigned long)i,
           (unsigned long long)pids.ProcessIdList[i]);
    }

    /* --- membership queries now answer IN_JOB --------------------------- */
    if (kids[0].hProcess)
    {
        status = NtIsProcessInJob(kids[0].hProcess, job);
        ok(status == STATUS_PROCESS_IN_JOB, "member in this job -> %08lx", (unsigned long)status);
        status = NtIsProcessInJob(kids[0].hProcess, NULL);
        ok(status == STATUS_PROCESS_IN_JOB, "member in any job -> %08lx", (unsigned long)status);
    }
    status = NtIsProcessInJob(NtCurrentProcess(), job);
    ok(status == STATUS_PROCESS_NOT_IN_JOB, "non-member -> %08lx", (unsigned long)status);

    /* --- terminate the job: every member dies --------------------------- */
    status = NtTerminateJobObject(job, 0x99);
    ok(status == STATUS_SUCCESS, "NtTerminateJobObject -> %08lx", (unsigned long)status);
    for (int i = 0; i < 2; i++)
    {
        if (!kids[i].hProcess)
            continue;
        ok(WaitForSingleObject(kids[i].hProcess, 10000) == WAIT_OBJECT_0, "member %d survived", i);
        NtClose(kids[i].hProcess);
        NtClose(kids[i].hThread);
    }

    /* The drained job reports no active members. */
    memset(&acct, 0, sizeof(acct));
    status = NtQueryInformationJobObject(job, JobObjectBasicAccountingInformation, &acct,
                                         sizeof(acct), &retLen);
    ok(status == STATUS_SUCCESS, "drained accounting -> %08lx", (unsigned long)status);
    ok(acct.ActiveProcesses == 0, "drained job reports %lu active",
       (unsigned long)acct.ActiveProcesses);

    NtClose(job);
}
