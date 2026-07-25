/* tests/cui/jobtool.c — the CUI-4 acceptance's job-object-using build tool.
 *
 * The shape real build tools (MSBuild, ninja, cmd's own job usage) rely on:
 * create a job with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, spawn children into
 * it, read the job back to see them, then close the job handle and let the
 * kernel clean the children up. A third-party CUI app (mingw + its own CRT),
 * driven from the interactive cmd session.
 *
 * Prints "jobtool-active-<n>" (the live member count from the job's own
 * accounting) and finally "jobtool-done-<n>" — digits the typed command line
 * cannot supply.
 */
#include <windows.h>
#include <stdio.h>

#define CHILDREN 2

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--child") == 0)
    {
        Sleep(30000); /* the job kills us long before this */
        return 0;
    }

    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (!job)
    {
        printf("jobtool-nojob\n");
        return 1;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    memset(&limits, 0, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
    {
        printf("jobtool-nolimit\n");
        return 1;
    }

    char self[MAX_PATH];
    GetModuleFileNameA(NULL, self, MAX_PATH);

    HANDLE kids[CHILDREN];
    int spawned = 0;
    for (int i = 0; i < CHILDREN; i++)
    {
        char cmdline[MAX_PATH + 32];
        snprintf(cmdline, sizeof(cmdline), "\"%s\" --child", self);
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        memset(&pi, 0, sizeof(pi));
        if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si,
                            &pi))
            continue;
        if (AssignProcessToJobObject(job, pi.hProcess))
        {
            kids[spawned++] = pi.hProcess;
            ResumeThread(pi.hThread);
        }
        else
        {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
        }
        CloseHandle(pi.hThread);
    }
    Sleep(300);

    /* Read the job back: the accounting must see exactly our members. */
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acct;
    DWORD retLen = 0;
    memset(&acct, 0, sizeof(acct));
    if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &acct, sizeof(acct),
                                   &retLen))
    {
        printf("jobtool-noquery\n");
        return 1;
    }
    printf("jobtool-active-%lu\n", (unsigned long)acct.ActiveProcesses);
    fflush(stdout);

    /* Closing the last handle is the cleanup contract: KILL_ON_JOB_CLOSE
     * must terminate every member. */
    CloseHandle(job);

    int died = 0;
    for (int i = 0; i < spawned; i++)
    {
        if (WaitForSingleObject(kids[i], 10000) == WAIT_OBJECT_0)
            died++;
        CloseHandle(kids[i]);
    }
    printf("jobtool-done-%d\n", died);
    fflush(stdout);
    return died == spawned ? 0 : 1;
}
