/* kernel/ps/job.c — job objects, the SCM subset (CUI-3).
 *
 * The consumer that forces this surface is services.exe: its main() dies at
 * startup if SetInformationJobObject fails (programs/services/services.c),
 * it puts every service process in one job with breakaway limits, and its
 * process monitor drains JOB_OBJECT_MSG_* packets from the associated
 * completion port to notice service death. Semantics from the pinned
 * oracle (wineserver server/process.c: add_job_process,
 * release_job_process, set_job_completion_port; ntdll unix/sync.c argument
 * gates), pinned by tests/ntapi/sem_ps/job.c.
 *
 * Deliberately unbuilt (loud, docs/03 "CUI-3 SCM notes"): limit
 * ENFORCEMENT (flags are validated and stored — services.exe only sets
 * breakaway bits, which gate behaviour proskrnl does not have), job
 * nesting (assigning a process already in another job), and the
 * query/terminate/open/IsProcessInJob surface (no baked caller).
 */
#include "kernel/ps/ps.h"
#include "kernel/io/io.h"
#include "kernel/mm/pool.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

#include "abi/ntpsapi.h"

typedef struct EJOB
{
    ULONG limitFlags;    /* validated + stored, not enforced (docs/03) */
    PIO_COMPLETION port; /* referenced port body, 0 until associated */
    ULONG_PTR completionKey;
    LIST_ENTRY processList; /* EPROCESS.jobLinks (members may be dead but
                             * undeleted; jobExitNotified marks those) */
    LONG activeCount;       /* members that have not exited yet */
} EJOB, *PEJOB;

static void PspDeleteJob(PVOID body)
{
    PEJOB job = body;
    /* Members hold a job reference each (dropped in PspDeleteProcess), so a
     * job with members cannot reach its delete procedure. */
    ASSERT(IsListEmpty(&job->processList));
    if (job->port != 0)
    {
        ObDereferenceObject(job->port);
    }
}

OBJECT_TYPE PspJobType = {
    .name = "Job",
    .validAccess = JOB_OBJECT_ALL_ACCESS,
    .waitable = FALSE,
    .deleteProcedure = PspDeleteJob,
};

NTSTATUS NtCreateJobObject(PHANDLE handleOut, ACCESS_MASK desiredAccess,
                           const OBJECT_ATTRIBUTES *attributes)
{
    if (handleOut == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    PVOID body;
    NTSTATUS status = ObpCreateObjectWithHandle(&PspJobType, sizeof(EJOB), attributes,
                                                desiredAccess, &body, handleOut);
    if (status == STATUS_SUCCESS)
    {
        PEJOB job = body;
        memset(job, 0, sizeof(*job));
        InitializeListHead(&job->processList);
    }
    return status;
}

NTSTATUS NtSetInformationJobObject(HANDLE handle, JOBOBJECTINFOCLASS infoClass, PVOID buffer,
                                   ULONG length)
{
    /* The class ceiling comes first, before the handle is even looked at
     * (wine/dlls/ntdll/unix/sync.c; pinned sem_ps/job.c). */
    if ((ULONG)infoClass >= (ULONG)MaxJobObjectInfoClass)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PVOID body;
    NTSTATUS status =
        ObReferenceObjectByHandle(handle, 0, &PspJobType, ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PEJOB job = body;

    switch (infoClass)
    {
    case JobObjectBasicLimitInformation:
    case JobObjectExtendedLimitInformation:
    {
        /* Exact size and the class's own valid mask — the BASIC class takes
         * only the 0xff subset (pinned: breakaway bits bounce there). */
        BOOLEAN extended = infoClass == JobObjectExtendedLimitInformation;
        ULONG expected = extended ? sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)
                                  : sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION);
        ULONG validMask =
            extended ? JOB_OBJECT_EXTENDED_LIMIT_VALID_FLAGS : JOB_OBJECT_BASIC_LIMIT_VALID_FLAGS;
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
        if (length != expected)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = KiCopyFromUser(&info, buffer, length);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        if ((info.BasicLimitInformation.LimitFlags & ~validMask) != 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        job->limitFlags = info.BasicLimitInformation.LimitFlags;
        status = STATUS_SUCCESS;
        break;
    }
    case JobObjectAssociateCompletionPortInformation:
    {
        JOBOBJECT_ASSOCIATE_COMPLETION_PORT info;
        if (length != sizeof(info))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = KiCopyFromUser(&info, buffer, length);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        if (job->port != 0)
        {
            /* Re-association is refused (wineserver
             * set_job_completion_port: only an unset port accepts). */
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        PVOID portBody;
        status = ObReferenceObjectByHandle(info.CompletionPort, IO_COMPLETION_MODIFY_STATE,
                                           &IoCompletionType, ExGetPreviousMode(), &portBody, 0);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        job->port = portBody; /* keeps the reference */
        job->completionKey = (ULONG_PTR)info.CompletionKey;
        /* Members that joined before the port did get their NEW_PROCESS now
         * (wineserver add_job_completion_existing_processes; pinned). */
        for (PLIST_ENTRY entry = job->processList.Flink; entry != &job->processList;
             entry = entry->Flink)
        {
            PEPROCESS member = CONTAINING_RECORD(entry, EPROCESS, jobLinks);
            if (!member->jobExitNotified)
            {
                IopPostCompletionPacket(job->port, job->completionKey,
                                        (ULONG_PTR)member->uniqueProcessId, STATUS_SUCCESS,
                                        JOB_OBJECT_MSG_NEW_PROCESS);
            }
        }
        break;
    }
    default:
        /* Valid-but-unbuilt classes refuse loudly (Art. 12). */
        DbgPrint("job: unimplemented set class %u\n", (unsigned)infoClass);
        status = STATUS_NOT_IMPLEMENTED;
        break;
    }

    ObDereferenceObject(job);
    return status;
}

NTSTATUS NtAssignProcessToJobObject(HANDLE jobHandle, HANDLE processHandle)
{
    PVOID body;
    NTSTATUS status =
        ObReferenceObjectByHandle(jobHandle, 0, &PspJobType, ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PEJOB job = body;

    PEPROCESS process;
    BOOLEAN referenced = FALSE;
    if (processHandle == NtCurrentProcess())
    {
        process = KeGetCurrentThread()->process;
    }
    else
    {
        status = ObReferenceObjectByHandle(processHandle, 0, &PspProcessType, ExGetPreviousMode(),
                                           &body, 0);
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(job);
            return status;
        }
        process = body;
        referenced = TRUE;
    }

    if (process->job == job)
    {
        status = STATUS_SUCCESS; /* already a member (wineserver no-op) */
    }
    else if (process->job != 0)
    {
        /* Job NESTING is unbuilt: refuse loudly rather than emulate the
         * parent-chain rules (Art. 12; no baked caller re-assigns). */
        DbgPrint("job: process already in a job (nesting unbuilt)\n");
        status = STATUS_NOT_IMPLEMENTED;
    }
    else
    {
        ObfReferenceObject(job); /* the member's reference (G11: dropped in
                                  * PspDeleteProcess) */
        process->job = job;
        process->jobExitNotified = FALSE;
        InsertTailList(&job->processList, &process->jobLinks);
        job->activeCount++;
        if (job->port != 0)
        {
            IopPostCompletionPacket(job->port, job->completionKey,
                                    (ULONG_PTR)process->uniqueProcessId, STATUS_SUCCESS,
                                    JOB_OBJECT_MSG_NEW_PROCESS);
        }
        status = STATUS_SUCCESS;
    }

    if (referenced)
    {
        ObDereferenceObject(process);
    }
    ObDereferenceObject(job);
    return status;
}

/* Called once from each process-exit path (PspExitCurrentProcess and the
 * last-thread leg of PspExitCurrentThread): the wineserver
 * release_job_process shape — EXIT_PROCESS for the member, then
 * ACTIVE_PROCESS_ZERO when the job drains. Unlink/deref happen later in
 * PspDeleteProcess; the flag keeps the accounting single-shot. */
void PspNotifyProcessExit(PEPROCESS process)
{
    /* Both CUI-3 exit-time notifications ride the one hook: the
     * make-process-system count (kernel/ps/query.c) ... */
    PspShutdownNoteProcessExit(process);
    /* ... and the job packets. */
    PEJOB job = process->job;
    if (job == 0 || process->jobExitNotified)
    {
        return;
    }
    process->jobExitNotified = TRUE;
    if (job->port != 0)
    {
        IopPostCompletionPacket(job->port, job->completionKey, (ULONG_PTR)process->uniqueProcessId,
                                STATUS_SUCCESS, JOB_OBJECT_MSG_EXIT_PROCESS);
    }
    ASSERT(job->activeCount > 0);
    if (--job->activeCount == 0 && job->port != 0)
    {
        IopPostCompletionPacket(job->port, job->completionKey, 0, STATUS_SUCCESS,
                                JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO);
    }
}

/* Called from PspDeleteProcess: drop the membership (the job cannot die
 * before this — the member held a reference). */
void PspUnlinkProcessFromJob(PEPROCESS process)
{
    PEJOB job = process->job;
    if (job == 0)
    {
        return;
    }
    if (!process->jobExitNotified)
    {
        /* Deleted without ever exiting (a failed create after assignment —
         * unreachable for baked callers): keep the count honest, silently. */
        ASSERT(job->activeCount > 0);
        job->activeCount--;
    }
    RemoveEntryList(&process->jobLinks);
    process->job = 0;
    ObDereferenceObject(job);
}
