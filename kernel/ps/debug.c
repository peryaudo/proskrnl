/* kernel/ps/debug.c — debugger ATTACH, and nothing else.
 *
 * ADR 0011 put the debug port out of scope and its WOW64-milestone amendment
 * re-opened exactly one corner: the three calls DebugActiveProcess and
 * DebugActiveProcessStop make (dlls/kernelbase/debug.c ->
 * DbgUiConnectToDbg / DbgUiDebugActiveProcess / DbgUiStopDebugging in
 * dlls/ntdll/process.c). ntdll:wow64 attaches to its 32-bit child and reads
 * BeingDebugged out of BOTH PEBs, which is a boundary behavior (Art. 1) and
 * the reason this file exists.
 *
 * The whole observable effect of attaching is that flag. There is NO event
 * queue: NtWaitForDebugEvent, NtDebugContinue, NtSetInformationDebugObject
 * and DEBUG_PROCESS-at-create keep their loud KI_SYSCALL_MISSING refusals
 * (Art. 12), because an event queue is a scheduling contract — every
 * debuggee thread blocking until a debugger answers — and would put a second
 * stop/continue authority beside the dispatcher (Art. 11) for a consumer
 * that does not exist. A process that attaches here learns only that the
 * flag is set.
 *
 * Pinned by tests/ntapi/sem_ps/debug_attach.c, which is where the statuses
 * below come from — including the two that contradict the documentation.
 */
#include "kernel/ps/ps.h"

#include "abi/ntpebteb.h"
#include "abi/ntpsapi.h"
#include "abi/ntwow64.h"
#include "kernel/init/panic.h"
#include "kernel/lib/list.h"
#include "kernel/mm/virtual.h"
#include "kernel/ob/ob.h"
#include "kernel/syscall/uaccess.h"

#include "kernel/lib/string.h"

/* The object body. A list rather than a single process because the flag the
 * handle carries is DEBUG_KILL_ON_CLOSE: one debug object may hold several
 * targets, and closing it must reach all of them. */
typedef struct EDEBUGOBJECT
{
    ULONG flags;            /* DEBUG_KILL_ON_CLOSE, as created */
    LIST_ENTRY processList; /* EPROCESS.debugLinks while attached */
} EDEBUGOBJECT, *PEDEBUGOBJECT;

/* BeingDebugged is one byte in the PEB, and a WOW64 process has two PEBs
 * that must agree — ntdll:wow64 reads both. One writer for both (Art. 11):
 * the field sits at the same offset in PEB and PEB32, which the generated
 * layouts assert, so the 32-bit copy is the same store at another address. */
_Static_assert(offsetof(PEB, BeingDebugged) == offsetof(PEB32, BeingDebugged),
               "BeingDebugged must sit at one offset for both PEBs");

static void PspSetBeingDebugged(PEPROCESS process, BOOLEAN debugged)
{
    UCHAR value = debugged ? 1 : 0;
    if (process->pebBase != 0)
    {
        MiCopyToUserRange(&process->addressSpace, process->pebBase + offsetof(PEB, BeingDebugged),
                          &value, sizeof(value));
    }
    if (process->peb32Base != 0)
    {
        MiCopyToUserRange(&process->addressSpace, process->peb32Base + offsetof(PEB, BeingDebugged),
                          &value, sizeof(value));
    }
}

/* Fires on the LAST HANDLE close, in thread context and before the object's
 * own delete — the same seam the job type's KILL_ON_JOB_CLOSE uses
 * (kernel/ps/job.c PspCloseJob), so kill-on-close has one implementation
 * shape in the tree rather than two. */
static void PspCloseDebugObject(PVOID body)
{
    PEDEBUGOBJECT debug = body;
    /* The DETACH is unconditional; only the KILL is conditional. Getting
     * that split wrong leaves a live process permanently marked
     * BeingDebugged with no handle left that could ever clear it —
     * detach_debugged_processes runs on every debug_obj_destroy and takes
     * the exit code as its argument, not as its condition
     * (server/debugger.c:345, server/process.c:1110).
     *
     * STATUS_DEBUGGER_INACTIVE is the oracle's own code for the kill
     * (debugger.c:346) and is a value the target's parent reads back out of
     * GetExitCodeProcess, so it is not a status to invent. Both halves are
     * pinned by sem_ps/debug_attach.c, which closes the handle with a target
     * still attached — the path every real debugger takes on exit, since
     * DbgUiConnectToDbg always asks for DEBUG_KILL_ON_CLOSE.
     *
     * Two passes, because PspTerminateProcessThreads only FLAGS the target's
     * threads and wakes them (it does not unlink the process), while the
     * detach below does unlink — walking and unlinking at once would drop
     * the list out from under the walk. */
    if ((debug->flags & DEBUG_KILL_ON_CLOSE) != 0)
    {
        for (PLIST_ENTRY entry = debug->processList.Flink; entry != &debug->processList;
             entry = entry->Flink)
        {
            PspTerminateProcessThreads(CONTAINING_RECORD(entry, EPROCESS, debugLinks),
                                       STATUS_DEBUGGER_INACTIVE);
        }
    }
    while (!IsListEmpty(&debug->processList))
    {
        PspDetachDebugObject(CONTAINING_RECORD(debug->processList.Flink, EPROCESS, debugLinks));
    }
}

static void PspDeleteDebugObject(PVOID body)
{
    PEDEBUGOBJECT debug = body;
    /* Every attached process holds a reference to this object (taken at
     * attach, dropped at detach or at process delete), so an object with
     * targets cannot reach its delete procedure. */
    ASSERT(IsListEmpty(&debug->processList));
}

OBJECT_TYPE PspDebugObjectType = {
    .name = "DebugObject",
    .validAccess = DEBUG_ALL_ACCESS,
    .waitable = FALSE,
    .closeProcedure = PspCloseDebugObject,
    .deleteProcedure = PspDeleteDebugObject,
};

/* Drop an attachment. The one place a process leaves a debug object, called
 * both from NtRemoveProcessDebug and from process teardown (Art. 11: one
 * unlink site, so the refcount cannot drift between the two). */
void PspDetachDebugObject(PEPROCESS process)
{
    if (process->debugObject == 0)
    {
        return;
    }
    PEDEBUGOBJECT debug = process->debugObject;
    process->debugObject = 0;
    RemoveEntryList(&process->debugLinks);
    PspSetBeingDebugged(process, FALSE);
    ObDereferenceObject(debug);
}

NTSTATUS NtCreateDebugObject(PHANDLE handleOut, ACCESS_MASK desiredAccess,
                             OBJECT_ATTRIBUTES *attributes, ULONG flags)
{
    NTSTATUS clearStatus = ObpClearOutHandle(handleOut);
    if (!NT_SUCCESS(clearStatus))
    {
        return clearStatus;
    }
    /* DEBUG_KILL_ON_CLOSE is the only defined flag; anything else is a
     * caller error rather than something to ignore (server/debugger.c
     * DECL_HANDLER(create_debug_obj) accepts only that bit). */
    if ((flags & ~(ULONG)DEBUG_KILL_ON_CLOSE) != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    PVOID body;
    NTSTATUS status = ObpCreateObjectWithHandle(&PspDebugObjectType, sizeof(EDEBUGOBJECT),
                                                attributes, desiredAccess, &body, handleOut);
    if (status == STATUS_SUCCESS)
    {
        PEDEBUGOBJECT debug = body;
        debug->flags = flags;
        InitializeListHead(&debug->processList);
    }
    return status;
}

/* The access both handles must carry, from the oracle's own handler
 * (server/debugger.c DECL_HANDLER(debug_process)): the target by
 * VM_READ|VM_WRITE|SUSPEND_RESUME, the debug object by PROCESS_ASSIGN. */
static NTSTATUS PspReferenceForDebug(HANDLE processHandle, HANDLE debugHandle,
                                     PEPROCESS *processOut, PEDEBUGOBJECT *debugOut)
{
    PVOID processBody;
    NTSTATUS status = ObReferenceObjectByHandle(
        processHandle, PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME, &PspProcessType,
        ExGetPreviousMode(), &processBody, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PVOID debugBody;
    status = ObReferenceObjectByHandle(debugHandle, DEBUG_PROCESS_ASSIGN, &PspDebugObjectType,
                                       ExGetPreviousMode(), &debugBody, 0);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(processBody);
        return status;
    }
    *processOut = processBody;
    *debugOut = debugBody;
    return STATUS_SUCCESS;
}

NTSTATUS NtDebugActiveProcess(HANDLE processHandle, HANDLE debugHandle)
{
    PEPROCESS process;
    PEDEBUGOBJECT debug;
    NTSTATUS status = PspReferenceForDebug(processHandle, debugHandle, &process, &debug);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (process->debugObject != 0)
    {
        /* Already debugged. ACCESS_DENIED is measured, not the documented
         * STATUS_PORT_ALREADY_SET (sem_ps/debug_attach.c says why the
         * oracle wins here). */
        status = STATUS_ACCESS_DENIED;
    }
    else
    {
        /* The attachment owns a reference to the debug object; the process
         * owns nothing of the debugger's. Dropped by PspDetachDebugObject,
         * which process teardown also calls, so a target that exits while
         * attached releases it. */
        ObfReferenceObject(debug);
        process->debugObject = debug;
        InsertTailList(&debug->processList, &process->debugLinks);
        PspSetBeingDebugged(process, TRUE);
        status = STATUS_SUCCESS;
    }
    ObDereferenceObject(debug);
    ObDereferenceObject(process);
    return status;
}

NTSTATUS NtRemoveProcessDebug(HANDLE processHandle, HANDLE debugHandle)
{
    PEPROCESS process;
    PEDEBUGOBJECT debug;
    NTSTATUS status = PspReferenceForDebug(processHandle, debugHandle, &process, &debug);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (process->debugObject != debug)
    {
        /* Not attached, or attached to a DIFFERENT debug object — one
         * status for both, as measured. */
        status = STATUS_ACCESS_DENIED;
    }
    else
    {
        PspDetachDebugObject(process);
        status = STATUS_SUCCESS;
    }
    ObDereferenceObject(debug);
    ObDereferenceObject(process);
    return status;
}
