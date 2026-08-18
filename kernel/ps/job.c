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
 * CUI-6 finishes the surface: job NESTING (assign a process already in one
 * job to a fresh job, making it a child — wineserver's parent/child_job
 * chain), create-time membership with silent/explicit BREAKAWAY, and real
 * per-job CPU-time accounting (the subtree's exited totals plus live
 * members' tick counters). The remaining limit ENFORCEMENT (working-set,
 * time and memory caps) stays validated-and-stored, not enforced: the
 * oracle reads limit_flags nowhere but the breakaway/kill-on-close bits, so
 * inventing enforcement would exceed the boundary (Art. 1, docs/03). IO
 * counters stay zero — no per-process IO accounting exists (Art. 12).
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
    LONG activeCount;       /* members that have not exited yet, chain-propagated */
    LONG totalCount;        /* CUI-4: members ever assigned (accounting) */
    /* CUI-6: nesting (wineserver's parent/child_job_list shape). A child
     * job holds a reference to its parent (so the parent outlives it); the
     * parent's childJobList links children without a reference. */
    struct EJOB *parent;       /* referenced; 0 for a root job */
    LIST_ENTRY childJobList;   /* child EJOB.parentJobEntry */
    LIST_ENTRY parentJobEntry; /* on parent->childJobList */
    /* CUI-6: real per-job CPU accounting — the exited members' totals,
     * rolled up the parent chain at member exit; a query adds the live
     * subtree members' current counters. */
    uint64_t exitedKernelTime100ns;
    uint64_t exitedUserTime100ns;
} EJOB, *PEJOB;

/* CUI-4: terminate every live member (shared by NtTerminateJobObject and the
 * kill-on-close path). CUI-6: recurse into child jobs first, as wineserver
 * terminate_job does. Each target reaps itself at its ring-3 edge — nothing
 * is torn down here (Art. 3). */
static void PspTerminateJobMembers(PEJOB job, NTSTATUS exitStatus)
{
    for (PLIST_ENTRY child = job->childJobList.Flink; child != &job->childJobList;
         child = child->Flink)
    {
        PspTerminateJobMembers(CONTAINING_RECORD(child, EJOB, parentJobEntry), exitStatus);
    }
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

/* CUI-6: is `process` in `job`'s subtree? Recursive over child jobs, exactly
 * the wineserver process_in_job shape. Lock-free under Art. 3. */
static BOOLEAN PspProcessInJobTree(PEJOB job, PEPROCESS process)
{
    for (PLIST_ENTRY child = job->childJobList.Flink; child != &job->childJobList;
         child = child->Flink)
    {
        if (PspProcessInJobTree(CONTAINING_RECORD(child, EJOB, parentJobEntry), process))
        {
            return TRUE;
        }
    }
    return process->job == job;
}

/* CUI-6: THE add-process-to-job engine (wineserver add_job_process),
 * shared by NtAssignProcessToJobObject and the create-time auto-join (G11).
 * Handles nesting: a process already in job P assigned to a fresh, unused
 * job J makes J a child of P; assigning it under an unrelated, used job is
 * STATUS_ACCESS_DENIED. Counts propagate up to (but not through) the common
 * parent, matching the server. */
static NTSTATUS PspAddProcessToJob(PEJOB job, PEPROCESS process)
{
    if (process->job == job)
    {
        return STATUS_SUCCESS; /* already a member (server no-op) */
    }
    PEJOB commonParent = process->job;
    if (commonParent != 0)
    {
        if (job->parent != 0)
        {
            /* job already nests somewhere: only legal if the process's job
             * is an ancestor of `job` (re-parenting within one chain). */
            PEJOB ancestor = job->parent;
            while (ancestor != 0 && ancestor != commonParent)
            {
                ancestor = ancestor->parent;
            }
            if (ancestor != commonParent)
            {
                return STATUS_ACCESS_DENIED;
            }
            ObDereferenceObject(commonParent); /* the process's stale job ref */
        }
        else
        {
            if (job->totalCount != 0)
            {
                return STATUS_ACCESS_DENIED; /* can't make a used job a child */
            }
            /* Transfer the process's job reference to job->parent. */
            job->parent = commonParent;
            InsertTailList(&commonParent->childJobList, &job->parentJobEntry);
        }
        RemoveEntryList(&process->jobLinks); /* leave the old process_list */
    }

    ObfReferenceObject(job); /* the member's reference (G11: PspDeleteProcess) */
    process->job = job;
    process->jobExitNotified = FALSE;
    InsertTailList(&job->processList, &process->jobLinks);

    for (PEJOB j = job; j != commonParent; j = j->parent)
    {
        j->activeCount++;
        j->totalCount++;
        if (j->port != 0)
        {
            IopPostCompletionPacket(j->port, j->completionKey, (ULONG_PTR)process->uniqueProcessId,
                                    STATUS_SUCCESS, JOB_OBJECT_MSG_NEW_PROCESS);
        }
    }
    return STATUS_SUCCESS;
}

/* Fires on the LAST HANDLE close (kernel/ob/handle.c), in thread context and
 * before the object's own delete: the JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
 * contract a build tool relies on to clean up its children. */
static void PspCloseJob(PEPROCESS process, PVOID body, ULONG processHandleCount,
                        ULONG systemHandleCount)
{
    PEJOB job = body;
    /* KILL_ON_JOB_CLOSE is about the last handle in the SYSTEM (ob.h). */
    (void)process;
    (void)processHandleCount;
    if (systemHandleCount != 1)
    {
        return;
    }
    if ((job->limitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0)
    {
        PspTerminateJobMembers(job, STATUS_SUCCESS);
    }
}

static void PspDeleteJob(PVOID body)
{
    PEJOB job = body;
    /* Members hold a job reference each (dropped in PspDeleteProcess), and a
     * child job holds a reference to its parent, so neither a job with
     * members nor a parent with live children can reach its delete
     * procedure. */
    ASSERT(IsListEmpty(&job->processList));
    ASSERT(IsListEmpty(&job->childJobList));
    if (job->parent != 0)
    {
        RemoveEntryList(&job->parentJobEntry); /* leave the parent's child list */
        ObDereferenceObject(job->parent);      /* drop the parent reference */
    }
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
    NTSTATUS clearStatus = ObpClearOutHandle(handleOut);
    if (!NT_SUCCESS(clearStatus))
    {
        return clearStatus;
    }
    PVOID body;
    NTSTATUS status = ObpCreateObjectWithHandle(&PspJobType, sizeof(EJOB), attributes,
                                                desiredAccess, &body, handleOut);
    if (status == STATUS_SUCCESS)
    {
        PEJOB job = body;
        memset(job, 0, sizeof(*job));
        InitializeListHead(&job->processList);
        InitializeListHead(&job->childJobList);
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
    /* The access both handles must carry, transcribed from the oracle
     * (third_party/wine server/process.c DECL_HANDLER(assign_job):
     * `get_job_obj( current->process, req->job, JOB_OBJECT_ASSIGN_PROCESS )`
     * and `get_process_from_handle( req->process,
     * PROCESS_SET_QUOTA | PROCESS_TERMINATE )`).
     *
     * Both were 0. Zero access on the process handle is the serious half: a
     * job with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE kills its members, so
     * assigning a process into one is termination, and it was available
     * without PROCESS_TERMINATE (docs/review-2026-07 §11). The comment at
     * the top of this file already records that a fuzzer found this exact
     * class on NtSetInformationJobObject; the assign path was not fixed
     * then. */
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(jobHandle, JOB_OBJECT_ASSIGN_PROCESS, &PspJobType,
                                                ExGetPreviousMode(), &body, 0);
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
        status = ObReferenceObjectByHandle(processHandle, PROCESS_SET_QUOTA | PROCESS_TERMINATE,
                                           &PspProcessType, ExGetPreviousMode(), &body, 0);
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(job);
            return status;
        }
        process = body;
        referenced = TRUE;
    }

    /* CUI-6: nesting is built now — the shared engine (G11). */
    status = PspAddProcessToJob(job, process);

    if (referenced)
    {
        ObDereferenceObject(process);
    }
    ObDereferenceObject(job);
    return status;
}

/* CUI-6: does the creator's IMMEDIATE job forbid a requested breakaway?
 * (wineserver DECL_HANDLER(new_process) early check.) */
NTSTATUS PspCheckCreatorBreakaway(BOOLEAN breakawayRequested)
{
    PEJOB job = KeGetCurrentThread()->process->job;
    if (job != 0 && breakawayRequested &&
        (job->limitFlags &
         (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)) == 0)
    {
        return STATUS_ACCESS_DENIED;
    }
    return STATUS_SUCCESS;
}

/* CUI-6: enrol a freshly-created child in the creator's job chain
 * (wineserver DECL_HANDLER(new_process) chain walk): the child joins the
 * first job up the chain that neither is silent-breakaway nor was explicitly
 * broken away from. Must run before the child is readied. */
void PspJoinCreatorJob(PEPROCESS child, BOOLEAN breakawayRequested)
{
    for (PEJOB job = KeGetCurrentThread()->process->job; job != 0; job = job->parent)
    {
        BOOLEAN silent = (job->limitFlags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) != 0;
        BOOLEAN explicitBreakaway =
            breakawayRequested && (job->limitFlags & JOB_OBJECT_LIMIT_BREAKAWAY_OK) != 0;
        if (!silent && !explicitBreakaway)
        {
            NTSTATUS status = PspAddProcessToJob(job, child);
            ASSERT(NT_SUCCESS(status)); /* a fresh child is in no job: always succeeds */
            (void)status;
            return;
        }
    }
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
    /* CUI-6: roll the dying member's CPU time into its immediate job's
     * exited totals (a query sums up the subtree). By the time this runs on
     * the last-thread exit path, every thread has retired into the process's
     * exited totals (kernel/ps/thread.c PspRetireCurrentThread), so those
     * carry the whole process. Then walk the parent chain posting packets and
     * draining counts, exactly as wineserver release_job_process does. */
    job->exitedKernelTime100ns += process->exitedKernelTime100ns;
    job->exitedUserTime100ns += process->exitedUserTime100ns;
    for (PEJOB j = job; j != 0; j = j->parent)
    {
        if (j->port != 0)
        {
            IopPostCompletionPacket(j->port, j->completionKey, (ULONG_PTR)process->uniqueProcessId,
                                    STATUS_SUCCESS, JOB_OBJECT_MSG_EXIT_PROCESS);
        }
        ASSERT(j->activeCount > 0);
        if (--j->activeCount == 0 && j->port != 0)
        {
            IopPostCompletionPacket(j->port, j->completionKey, 0, STATUS_SUCCESS,
                                    JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO);
        }
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

/* CUI-6: collect the subtree's live-member pids (wineserver get_job_pids —
 * child jobs first, then this job's own list). Writes up to `capacity`; keeps
 * counting past it so the caller learns the true assigned count. */
static void PspCollectJobPids(PEJOB job, ULONG_PTR *out, ULONG capacity, ULONG *written,
                              ULONG *assigned)
{
    for (PLIST_ENTRY child = job->childJobList.Flink; child != &job->childJobList;
         child = child->Flink)
    {
        PspCollectJobPids(CONTAINING_RECORD(child, EJOB, parentJobEntry), out, capacity, written,
                          assigned);
    }
    for (PLIST_ENTRY entry = job->processList.Flink; entry != &job->processList;
         entry = entry->Flink)
    {
        PEPROCESS member = CONTAINING_RECORD(entry, EPROCESS, jobLinks);
        if (member->jobExitNotified)
        {
            continue;
        }
        (*assigned)++;
        if (*written < capacity)
        {
            out[(*written)++] = (ULONG_PTR)member->uniqueProcessId;
        }
    }
}

/* CUI-6: the subtree's total CPU time — each job's exited-member totals plus
 * its live members' current tick counters, recursively. */
static void PspCollectJobTime(PEJOB job, uint64_t *kernel100ns, uint64_t *user100ns)
{
    *kernel100ns += job->exitedKernelTime100ns;
    *user100ns += job->exitedUserTime100ns;
    for (PLIST_ENTRY entry = job->processList.Flink; entry != &job->processList;
         entry = entry->Flink)
    {
        PEPROCESS member = CONTAINING_RECORD(entry, EPROCESS, jobLinks);
        if (member->jobExitNotified)
        {
            continue;
        }
        *kernel100ns += member->exitedKernelTime100ns;
        *user100ns += member->exitedUserTime100ns;
        for (PLIST_ENTRY t = member->threadListHead.Flink; t != &member->threadListHead;
             t = t->Flink)
        {
            PKTHREAD tcb = CONTAINING_RECORD(t, ETHREAD, threadListEntry)->tcb;
            *kernel100ns += tcb->kernelTime100ns;
            *user100ns += tcb->userTime100ns;
        }
    }
    for (PLIST_ENTRY child = job->childJobList.Flink; child != &job->childJobList;
         child = child->Flink)
    {
        PspCollectJobTime(CONTAINING_RECORD(child, EJOB, parentJobEntry), kernel100ns, user100ns);
    }
}

/* --- the CUI-4 query/terminate/open/membership surface --------------------- */

NTSTATUS NtQueryInformationJobObject(HANDLE handle, JOBOBJECTINFOCLASS infoClass, PVOID buffer,
                                     ULONG length, PULONG returnLength)
{
    NTSTATUS probeStatus = PspProbeReturnLength(returnLength);
    if (!NT_SUCCESS(probeStatus))
    {
        return probeStatus;
    }
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
        /* CUI-6: real per-job CPU time — the subtree's exited totals plus
         * live members' current counters (sem_ps/job_nest, beyond_oracle;
         * the oracle zero-fills). IO counters stay zero: no per-process IO
         * accounting exists (Art. 12 — a fabricated number would be worse). */
        uint64_t kernel100ns = 0, user100ns = 0;
        PspCollectJobTime(job, &kernel100ns, &user100ns);
        info.BasicInfo.TotalKernelTime.QuadPart = (LONGLONG)kernel100ns;
        info.BasicInfo.TotalUserTime.QuadPart = (LONGLONG)user100ns;
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
        /* CUI-6: recurse the subtree — a nested child's members are in the
         * parent's list too (wineserver get_job_pids). */
        PspCollectJobPids(job, out->ProcessIdList, capacity, &written, &assigned);
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
    NTSTATUS clearStatus = ObpClearOutHandle(handleOut);
    if (!NT_SUCCESS(clearStatus))
    {
        return clearStatus;
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
            status = PspProcessInJobTree(jobBody, process) ? STATUS_PROCESS_IN_JOB
                                                           : STATUS_PROCESS_NOT_IN_JOB;
            ObDereferenceObject(jobBody);
        }
    }

    if (referenced)
    {
        ObDereferenceObject(process);
    }
    return status;
}
