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
 * CUI-4 completes the surface a job-driving BUILD TOOL needs: the
 * accounting/pid-list queries, NtTerminateJobObject, NtOpenJobObject,
 * NtIsProcessInJob, and JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (the one limit
 * flag that IS enforced, via the type's close procedure). Termination rides
 * the shared foreign-terminate primitive, so members reap themselves at
 * their ring-3 edges (kernel/ps/process.c).
 *
 * Deliberately unbuilt (loud, docs/03): the remaining limit ENFORCEMENT
 * (flags validated and stored — services.exe only sets breakaway bits, which
 * gate behaviour proskrnl does not have), job nesting (assigning a process
 * already in another job), and the per-job CPU/IO accounting (the time and
 * IO counters read back zero rather than a fabricated number).
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
    ULONG limitFlags;    /* validated + stored; KILL_ON_JOB_CLOSE enforced */
    PIO_COMPLETION port; /* referenced port body, 0 until associated */
    ULONG_PTR completionKey;
    LIST_ENTRY processList; /* EPROCESS.jobLinks (members may be dead but
                             * undeleted; jobExitNotified marks those) */
    LONG activeCount;       /* members that have not exited yet */
    LONG totalCount;        /* CUI-4: members ever assigned (accounting) */
} EJOB, *PEJOB;

/* CUI-4: terminate every live member (shared by NtTerminateJobObject and the
 * kill-on-close path). Each target reaps itself at its ring-3 edge — nothing
 * is torn down here (Art. 3). */
static void PspTerminateJobMembers(PEJOB job, NTSTATUS exitStatus)
{
    for (PLIST_ENTRY entry = job->processList.Flink; entry != &job->processList;
         entry = entry->Flink)
    {
        PEPROCESS member = CONTAINING_RECORD(entry, EPROCESS, jobLinks);
        if (!member->jobExitNotified)
        {
            PspTerminateProcessThreads(member, exitStatus);
        }
    }
}

/* Fires on the LAST HANDLE close (kernel/ob/handle.c), in thread context and
 * before the object's own delete: the JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
 * contract a build tool relies on to clean up its children. */
static void PspCloseJob(PVOID body)
{
    PEJOB job = body;
    if ((job->limitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0)
    {
        PspTerminateJobMembers(job, STATUS_SUCCESS);
    }
}

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
    .closeProcedure = PspCloseJob,
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
    /* JOB_OBJECT_SET_ATTRIBUTES is required (wine server/process.c
     * set_job_limits; fuzzer-found when access 0 let a query-only handle
     * set limits — pinned by sem_ps/job.c). */
    NTSTATUS status = ObReferenceObjectByHandle(handle, JOB_OBJECT_SET_ATTRIBUTES, &PspJobType,
                                                ExGetPreviousMode(), &body, 0);
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
        job->totalCount++;
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

/* --- the CUI-4 query/terminate/open/membership surface --------------------- */

NTSTATUS NtQueryInformationJobObject(HANDLE handle, JOBOBJECTINFOCLASS infoClass, PVOID buffer,
                                     ULONG length, PULONG returnLength)
{
    /* Class ceiling first, as the set path does (wine/dlls/ntdll/unix/sync.c). */
    if ((ULONG)infoClass >= (ULONG)MaxJobObjectInfoClass)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(handle, JOB_OBJECT_QUERY, &PspJobType,
                                                ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PEJOB job = body;

    switch (infoClass)
    {
    case JobObjectBasicAccountingInformation:
    case JobObjectBasicAndIoAccountingInformation:
    {
        /* The accounting a build tool polls. Times/page faults/IO stay zero:
         * proskrnl keeps no per-job CPU or IO accounting and inventing one
         * would be a fabricated answer (Art. 12) — the counts that ARE real
         * (assigned, still-active, terminated) are what the consumers read.
         * Pinned by sem_ps/job_query. */
        BOOLEAN withIo = infoClass == JobObjectBasicAndIoAccountingInformation;
        ULONG needed = withIo ? (ULONG)sizeof(JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION)
                              : (ULONG)sizeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION);
        if (returnLength != 0)
        {
            *returnLength = needed;
        }
        if (length < needed)
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        status = KiProbeForWrite(buffer, needed, sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            break;
        }
        JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION info;
        memset(&info, 0, sizeof(info));
        info.BasicInfo.TotalProcesses = (DWORD)job->totalCount;
        info.BasicInfo.ActiveProcesses = (DWORD)job->activeCount;
        info.BasicInfo.TotalTerminatedProcesses = (DWORD)(job->totalCount - job->activeCount);
        memcpy(buffer, &info, needed);
        status = STATUS_SUCCESS;
        break;
    }
    case JobObjectBasicProcessIdList:
    {
        /* Header + as many ids as fit; NumberOfAssignedProcesses always
         * reports the true member count, NumberOfProcessIdsInList what was
         * written, and a short buffer is STATUS_BUFFER_OVERFLOW (a success
         * code — wineserver's shape, so a caller can size its retry). */
        ULONG headerSize = (ULONG)offsetof(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList);
        if (length < headerSize + sizeof(ULONG_PTR))
        {
            if (returnLength != 0)
            {
                *returnLength = headerSize + (ULONG)sizeof(ULONG_PTR);
            }
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        ULONG capacity = (length - headerSize) / (ULONG)sizeof(ULONG_PTR);
        status = KiProbeForWrite(buffer, length, sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            break;
        }
        JOBOBJECT_BASIC_PROCESS_ID_LIST *out = buffer;
        ULONG assigned = 0;
        ULONG written = 0;
        for (PLIST_ENTRY entry = job->processList.Flink; entry != &job->processList;
             entry = entry->Flink)
        {
            PEPROCESS member = CONTAINING_RECORD(entry, EPROCESS, jobLinks);
            if (member->jobExitNotified)
            {
                continue; /* already exited: not a live member */
            }
            assigned++;
            if (written < capacity)
            {
                out->ProcessIdList[written++] = (ULONG_PTR)member->uniqueProcessId;
            }
        }
        out->NumberOfAssignedProcesses = assigned;
        out->NumberOfProcessIdsInList = written;
        if (returnLength != 0)
        {
            *returnLength = headerSize + written * (ULONG)sizeof(ULONG_PTR);
        }
        status = written < assigned ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
        break;
    }
    case JobObjectBasicLimitInformation:
    case JobObjectExtendedLimitInformation:
    {
        /* The read-back of what NtSetInformationJobObject stored. */
        BOOLEAN extended = infoClass == JobObjectExtendedLimitInformation;
        ULONG needed = extended ? (ULONG)sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)
                                : (ULONG)sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION);
        if (returnLength != 0)
        {
            *returnLength = needed;
        }
        if (length < needed)
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        status = KiProbeForWrite(buffer, needed, sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            break;
        }
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
        memset(&info, 0, sizeof(info));
        info.BasicLimitInformation.LimitFlags = job->limitFlags;
        memcpy(buffer, &info, needed);
        status = STATUS_SUCCESS;
        break;
    }
    default:
        /* Valid-but-unbuilt classes refuse loudly (Art. 12). */
        DbgPrint("job: unimplemented query class %u\n", (unsigned)infoClass);
        status = STATUS_NOT_IMPLEMENTED;
        break;
    }

    ObDereferenceObject(job);
    return status;
}

NTSTATUS NtTerminateJobObject(HANDLE handle, NTSTATUS exitStatus)
{
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(handle, JOB_OBJECT_TERMINATE, &PspJobType,
                                                ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PspTerminateJobMembers(body, exitStatus);
    ObDereferenceObject(body);
    return STATUS_SUCCESS;
}

NTSTATUS NtOpenJobObject(PHANDLE handleOut, ACCESS_MASK desiredAccess,
                         const OBJECT_ATTRIBUTES *attributes)
{
    if (handleOut == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    /* The shared name-resolution/open engine (G11) — no parallel path. */
    return ObpOpenObjectByName(&PspJobType, attributes, desiredAccess, handleOut);
}

NTSTATUS NtIsProcessInJob(HANDLE processHandle, HANDLE jobHandle)
{
    /* Both answers are SUCCESS-class codes (wineserver process_in_job): a
     * null job handle asks "in ANY job". Pinned by sem_ps/job_query. */
    PEPROCESS process;
    BOOLEAN referenced = FALSE;
    if (processHandle == NtCurrentProcess())
    {
        process = KeGetCurrentThread()->process;
    }
    else
    {
        PVOID body;
        NTSTATUS status = ObReferenceObjectByHandle(processHandle, PROCESS_QUERY_INFORMATION,
                                                    &PspProcessType, ExGetPreviousMode(), &body, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        process = body;
        referenced = TRUE;
    }

    NTSTATUS status;
    if (jobHandle == 0)
    {
        status = process->job != 0 ? STATUS_PROCESS_IN_JOB : STATUS_PROCESS_NOT_IN_JOB;
    }
    else
    {
        PVOID jobBody;
        status = ObReferenceObjectByHandle(jobHandle, JOB_OBJECT_QUERY, &PspJobType,
                                           ExGetPreviousMode(), &jobBody, 0);
        if (NT_SUCCESS(status))
        {
            status =
                (PVOID)process->job == jobBody ? STATUS_PROCESS_IN_JOB : STATUS_PROCESS_NOT_IN_JOB;
            ObDereferenceObject(jobBody);
        }
    }

    if (referenced)
    {
        ObDereferenceObject(process);
    }
    return status;
}
