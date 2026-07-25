/* kernel/ps/thread.c — user threads as Ob objects + the M7 thread surface.
 *
 * A thread handle must be waitable (join) and openable, so a thread is an Ob
 * object (ETHREAD) whose body begins with a DISPATCHER_HEADER, signalled when
 * the thread exits. The Ke thread (KTHREAD) it wraps carries the scheduling +
 * ring-crossing state (docs/05: ETHREAD internal layout is entirely ours). A
 * process holds a reference to none of its threads, but each thread holds one
 * on its process, so the process object outlives its threads.
 *
 * NtCreateThreadEx builds an additional thread sharing the process address
 * space, with its own guard-page stack and TEB, entering ring 3 through the
 * image's RtlUserThreadStart-shaped protocol. Termination and the small query
 * surface ntdll's startup reads (ThreadBasicInformation, ThreadAmILastThread)
 * round out the milestone's "thread creation".
 */
#include "kernel/ps/ps.h"
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h"
#include "kernel/mm/pool.h"
#include "kernel/mm/virtual.h"
#include "kernel/mm/phys.h"
#include "kernel/syscall/syscall.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "kernel/init/trace.h"
#include "arch/x86_64/mmu.h"

#include "abi/ntpsapi.h"
#include "abi/ntpebteb.h"

static uint64_t PspNextUniqueProcessId = 0x100; /* even ids, NT-flavoured */

uint64_t PspAllocateProcessId(void)
{
    PspNextUniqueProcessId += 4;
    return PspNextUniqueProcessId;
}

/* Was this id EVER allocated? The oracle's session-wide alert table keeps a
 * slot for every id it ever handed out, so alerting a since-exited thread
 * is an accepted no-op while a never-allocated id is STATUS_INVALID_CID
 * (ntdll:sync test_tid_alert alerts a joined thread's id). */
static BOOLEAN PspIdWasAllocated(uint64_t id)
{
    return id > 0x100 && id <= PspNextUniqueProcessId && (id & 3) == 0;
}

/* --- the ETHREAD object type --------------------------------------------- */

static void PspDeleteThread(PVOID body)
{
    PETHREAD thread = body;
    if (thread->tcb != 0)
    {
        KiDeleteThread(thread->tcb);
    }
    if (thread->process != 0)
    {
        ObDereferenceObject(thread->process);
    }
}

OBJECT_TYPE PspThreadType = {
    .name = "Thread",
    .validAccess = THREAD_ALL_ACCESS,
    .waitable = TRUE,
    .deleteProcedure = PspDeleteThread,
};

/* First code of a user thread on its kernel stack: descend to ring 3 at the
 * thread's initial register state. For the process main thread that is the
 * image entry via the loader protocol; for an NtCreateThreadEx thread it is
 * (startRoutine, argument) placed in rcx/rdx. Shared by process.c. */
void PspUserThreadStartup(void *context)
{
    PKTHREAD tcb = KeGetCurrentThread();
    (void)context;
    PspEnterUserThread(tcb); /* kernel/ps/usermode.c: the NT CONTEXT protocol
                              * when ntdll is mapped, bare registers otherwise */
}

/* Build the ETHREAD wrapper for a KTHREAD and link it into the process. The
 * caller has already prepared the KTHREAD's user-start state; this readies it
 * only via KiCreateThreadEx elsewhere. Returns a creator reference. */
NTSTATUS PspCreateThreadObject(PEPROCESS process, PKTHREAD tcb, uint64_t tebBase,
                               uint64_t stackAllocationBase, uint64_t stackBase,
                               uint64_t uniqueThreadId, PETHREAD *threadOut)
{
    PVOID body;
    NTSTATUS status = ObpAllocateObject(&PspThreadType, sizeof(ETHREAD), &body);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PETHREAD thread = body;
    KiInitializeDispatcherHeader(&thread->header, KI_OBJECT_THREAD, 0);
    thread->tcb = tcb;
    thread->process = process;
    thread->tebBase = tebBase;
    thread->stackAllocationBase = stackAllocationBase;
    thread->stackBase = stackBase;
    KeInitializeEvent(&thread->tidAlertEvent, SynchronizationEvent, FALSE);

    ObfReferenceObject(process); /* the thread pins its process */
    ObfReferenceObject(thread);  /* the RUNNING PIN: a live thread pins its own
                                  * ETHREAD (closing the last handle to a
                                  * running thread must not delete it); parked
                                  * on the reaper list at exit. */
    uint64_t flags = KiAcquireDispatcherLock();
    thread->uniqueThreadId = uniqueThreadId;
    InsertTailList(&process->threadListHead, &thread->threadListEntry);
    process->activeThreadCount++;
    KiReleaseDispatcherLock(flags);

    tcb->threadObject = thread;
    *threadOut = thread;
    return STATUS_SUCCESS;
}

/* --- deferred ETHREAD release (M10) ---------------------------------------
 * A LIVE thread pins its own ETHREAD (the "running pin",
 * PspCreateThreadObject): NT semantics — closing the last handle to a
 * running thread must not delete it (ntdll's threadpool closes its worker
 * handles immediately). The pin cannot be dropped by the exiting thread
 * itself (the deref would free the kernel stack it is running on), so exits
 * park the ETHREAD on this list and any LATER exit — by then the parked
 * threads are KI_THREAD_STATE_TERMINATED — drops the references. Bounded
 * residue: the most recent exit stays parked until the next one. */
static LIST_ENTRY PspReaperListHead = {&PspReaperListHead, &PspReaperListHead};

void PspReapExitedThreads(void)
{
    for (;;)
    {
        uint64_t flags = KiAcquireDispatcherLock();
        PETHREAD parked = 0;
        if (!IsListEmpty(&PspReaperListHead))
        {
            PLIST_ENTRY head = RemoveHeadList(&PspReaperListHead);
            parked = CONTAINING_RECORD(head, ETHREAD, threadListEntry);
        }
        KiReleaseDispatcherLock(flags);
        if (parked == 0)
        {
            return;
        }
        ObDereferenceObject(parked); /* deletion (if last) is now safe: TERMINATED */
    }
}

/* Consistency sweep (kernel/init/verify.c; lock held): the reaper holds only
 * finished threads — a live thread here would be freed under its own stack
 * on the next drain (the edf9f0b failure shape). */
void PspVerifyReaperList(void)
{
    for (PLIST_ENTRY entry = PspReaperListHead.Flink; entry != &PspReaperListHead;
         entry = entry->Flink)
    {
        ASSERT(entry->Flink->Blink == entry && entry->Blink->Flink == entry);
        PETHREAD parked = CONTAINING_RECORD(entry, ETHREAD, threadListEntry);
        ASSERT(ObpGetHeader(parked)->type == &PspThreadType);
        ASSERT(ObpGetHeader(parked)->pointerCount >= 1); /* the parked pin */
        ASSERT(parked->tcb != 0);
        ASSERT(parked->tcb->state == KI_THREAD_STATE_TERMINATED);
        ASSERT(parked->header.signalState == 1);
    }
}

/* The thread-side bookkeeping every exit path runs: leave the process's
 * thread list and satisfy joins. May still block after this. */
void PspRetireCurrentThread(NTSTATUS exitStatus)
{
    PKTHREAD tcb = KeGetCurrentThread();
    PETHREAD thread = tcb->threadObject;
    tcb->exitStatus = exitStatus;
    if (thread == 0)
    {
        return; /* kernel threads and flat-binary main threads */
    }
    KiTraceEvent(KiTraceThreadExit, (uint64_t)(uintptr_t)tcb, (uint64_t)(uint32_t)exitStatus, 0);
    uint64_t flags = KiAcquireDispatcherLock();
    RemoveEntryList(&thread->threadListEntry);
    thread->header.signalState = 1; /* joins on the thread handle satisfy */
    KiWaitTest(&thread->header);
    KiReleaseDispatcherLock(flags);
}

/* Park the running pin and stop. The park MUST be the exiting thread's very
 * last act before KiTerminateThread (after every possibly-blocking step): a
 * drain by another thread would otherwise free this stack mid-run — safe
 * only because nothing runs between the park and the switch (no preemption,
 * Art. 3). threadListEntry is reused for the reaper list (the retire above
 * already unlinked it). */
__attribute__((noreturn)) void PspParkCurrentThreadAndTerminate(void)
{
    PETHREAD thread = KeGetCurrentThread()->threadObject;
    if (thread != 0)
    {
        uint64_t flags = KiAcquireDispatcherLock();
        InsertTailList(&PspReaperListHead, &thread->threadListEntry);
        KiReleaseDispatcherLock(flags);
    }
    KiTerminateThread();
}

__attribute__((noreturn)) void PspExitCurrentThread(NTSTATUS exitStatus)
{
    PKTHREAD tcb = KeGetCurrentThread();
    PEPROCESS process = tcb->process;

    PspReapExitedThreads(); /* earlier exits are TERMINATED by now */

    /* The last thread's exit is the process's exit: close handles (in thread
     * context, before the address space is torn down) and signal the process
     * object. A non-last thread just signals its own thread object so joins
     * complete; its KTHREAD/stack are reclaimed when the ETHREAD is deleted. */
    uint64_t flags = KiAcquireDispatcherLock();
    LONG remaining = --process->activeThreadCount;
    KiReleaseDispatcherLock(flags);

    PspRetireCurrentThread(exitStatus);

    if (remaining == 0)
    {
        ObpCloseAllHandles(&process->handleTable);
        process->exitStatus = exitStatus;
        PspNotifyProcessExit(process); /* CUI-3: the job's EXIT_PROCESS packets */
        KiTraceEvent(KiTraceProcessExit, (uint64_t)(uintptr_t)process,
                     (uint64_t)(uint32_t)exitStatus, 0);
        uint64_t f3 = KiAcquireDispatcherLock();
        process->header.signalState = 1; /* never reset: joins always satisfy */
        KiWaitTest(&process->header);
        KiReleaseDispatcherLock(f3);
    }

    PspParkCurrentThreadAndTerminate();
}

/* --- NtCreateThreadEx ----------------------------------------------------- */

/* A fresh user stack (guard-page grown) for an additional thread. Mirrors the
 * main-thread stack shape in process.c but standalone. */
static NTSTATUS PspAllocateThreadStack(PEPROCESS process, uint64_t reserve, uint64_t commit,
                                       uint64_t *allocBaseOut, uint64_t *stackTopOut,
                                       uint64_t *stackLimitOut)
{
    PMI_ADDRESS_SPACE space = &process->addressSpace;
    reserve = (reserve + MI_ALLOCATION_GRANULARITY - 1) & ~(MI_ALLOCATION_GRANULARITY - 1);
    if (reserve < 4ULL * PAGE_SIZE)
    {
        reserve = 0x10000;
    }
    commit = (commit + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1ULL);
    if (commit < PAGE_SIZE)
    {
        commit = PAGE_SIZE;
    }
    if (commit > reserve - 2ULL * PAGE_SIZE)
    {
        commit = reserve - 2ULL * PAGE_SIZE;
    }

    PVOID base = 0;
    SIZE_T size = reserve;
    NTSTATUS status = MiAllocateVirtualMemory(space, &base, &size, MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t bottom = (uint64_t)(uintptr_t)base;
    uint64_t top = bottom + reserve;

    PVOID commitBase = (PVOID)(uintptr_t)(top - commit);
    size = commit;
    status = MiAllocateVirtualMemory(space, &commitBase, &size, MEM_COMMIT, PAGE_READWRITE);
    if (NT_SUCCESS(status))
    {
        PVOID guardBase = (PVOID)(uintptr_t)(top - commit - PAGE_SIZE);
        size = PAGE_SIZE;
        status = MiAllocateVirtualMemory(space, &guardBase, &size, MEM_COMMIT,
                                         PAGE_READWRITE | PAGE_GUARD);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *allocBaseOut = bottom;
    *stackTopOut = top;
    *stackLimitOut = top - commit;
    return STATUS_SUCCESS;
}

/* Build a user thread in `process` (its own stack + TEB + ETHREAD), entering
 * ring 3 at startRoutine(argument) through the image's loader protocol, and
 * hand back a creator reference WITHOUT touching the caller's handle table.
 * PspCreateUserThread adds the caller-visible handle; PspInjectUserThread
 * (CUI-4's console-control delivery) needs a thread with no handle at all,
 * since the kernel is the creator. The thread is left un-readied so the
 * caller can finalize it. */
static NTSTATUS PspBuildUserThread(PEPROCESS process, uint64_t startRoutine, uint64_t argument,
                                   PETHREAD *threadOut, uint64_t *threadIdOut, uint64_t *tebBaseOut)
{
    uint64_t allocBase = 0, stackTop = 0, stackLimit = 0;
    NTSTATUS status =
        PspAllocateThreadStack(process, 0x100000, 0x10000, &allocBase, &stackTop, &stackLimit);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    uint64_t tebBase = 0;
    /* Ids come from the shared Ps id source: NT's client ids are GLOBALLY
     * unique (one CID table for pids and tids), and the global alert-by-tid
     * lookup depends on it (ntdll:sync test_tid_alert). */
    uint64_t threadId = PspAllocateProcessId();
    status =
        PspBuildTeb(process, stackTop, stackLimit, process->uniqueProcessId, threadId, &tebBase);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* Create the Ke thread but do not ready it until its user-start state and
     * ETHREAD are set (the context switch programs GS from the TEB). */
    PKTHREAD tcb =
        KiCreateThreadSuspended(8, PspUserThreadStartup, 0, process, (void *)(uintptr_t)tebBase);
    if (tcb == 0)
    {
        return STATUS_NO_MEMORY;
    }
    /* Enter ring 3 at the image's RtlUserThreadStart-shaped entry: rcx =
     * startRoutine, rdx = argument (the loader protocol NtCreateThreadEx uses,
     * matching Wine's dlls/ntdll RtlUserThreadStart). */
    tcb->userStartRip =
        process->ldrInitializeThunk != 0 ? process->ldrInitializeThunk : startRoutine;
    tcb->userStartRsp = (stackTop & ~(uint64_t)0xf) - 0x28;
    tcb->userStartArg1 = startRoutine;
    tcb->userStartArg2 = argument;

    PETHREAD thread;
    status = PspCreateThreadObject(process, tcb, tebBase, allocBase, stackTop, threadId, &thread);
    if (!NT_SUCCESS(status))
    {
        KiDeleteThread(tcb);
        return status;
    }
    *threadOut = thread;
    if (threadIdOut != 0)
    {
        *threadIdOut = threadId;
    }
    if (tebBaseOut != 0)
    {
        *tebBaseOut = tebBase;
    }
    return STATUS_SUCCESS;
}

/* CUI-4: start a thread in `process` with NO handle in anyone's table — the
 * kernel-initiated injection the console-control fanout uses to run ntdll's
 * __wine_ctrl_routine (mirroring what ntdll's unix int_handler does with
 * NtCreateThreadEx + an immediate NtClose). */
NTSTATUS PspInjectUserThread(PEPROCESS process, uint64_t startRoutine, uint64_t argument)
{
    PETHREAD thread;
    NTSTATUS status = PspBuildUserThread(process, startRoutine, argument, &thread, 0, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PKTHREAD tcb = thread->tcb;
    /* The thread holds its own running pin (PspCreateThreadObject); drop the
     * creator reference — no handle stands in for it (G11: the running pin is
     * what keeps the ETHREAD alive until it exits). */
    ObDereferenceObject(thread);
    KiReadyCreatedThread(tcb);
    return STATUS_SUCCESS;
}

NTSTATUS PspCreateUserThread(PEPROCESS process, uint64_t startRoutine, uint64_t argument,
                             BOOLEAN createSuspended, PHANDLE threadHandleOut,
                             uint64_t *threadIdOut, uint64_t *tebBaseOut)
{
    uint64_t allocBase = 0, stackTop = 0, stackLimit = 0;
    NTSTATUS status =
        PspAllocateThreadStack(process, 0x100000, 0x10000, &allocBase, &stackTop, &stackLimit);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    uint64_t tebBase = 0;
    /* Ids come from the shared Ps id source: NT's client ids are GLOBALLY
     * unique (one CID table for pids and tids), and the global alert-by-tid
     * lookup depends on it (ntdll:sync test_tid_alert). */
    uint64_t threadId = PspAllocateProcessId();
    status =
        PspBuildTeb(process, stackTop, stackLimit, process->uniqueProcessId, threadId, &tebBase);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* Create the Ke thread but do not ready it until its user-start state and
     * ETHREAD are set (the context switch programs GS from the TEB). */
    PKTHREAD tcb =
        KiCreateThreadSuspended(8, PspUserThreadStartup, 0, process, (void *)(uintptr_t)tebBase);
    if (tcb == 0)
    {
        return STATUS_NO_MEMORY;
    }
    /* Enter ring 3 at the image's RtlUserThreadStart-shaped entry: rcx =
     * startRoutine, rdx = argument (the loader protocol NtCreateThreadEx uses,
     * matching Wine's dlls/ntdll RtlUserThreadStart). */
    tcb->userStartRip =
        process->ldrInitializeThunk != 0 ? process->ldrInitializeThunk : startRoutine;
    tcb->userStartRsp = (stackTop & ~(uint64_t)0xf) - 0x28;
    tcb->userStartArg1 = startRoutine;
    tcb->userStartArg2 = argument;

    PETHREAD thread;
    status = PspCreateThreadObject(process, tcb, tebBase, allocBase, stackTop, threadId, &thread);
    if (!NT_SUCCESS(status))
    {
        KiDeleteThread(tcb);
        return status;
    }

    /* Write the handle straight into the caller's (user) PHANDLE — ObpCreateHandle
     * is the choke point that probes it under the current previous mode. A
     * kernel-local out-pointer would be rejected as a bad user pointer. */
    status = ObpCreateHandle(thread, THREAD_ALL_ACCESS, 0, threadHandleOut);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(thread); /* deletes the never-started thread */
        return status;
    }

    ObDereferenceObject(thread); /* the handle holds its own reference */
    if (createSuspended)
    {
        /* THREAD_CREATE_FLAGS_CREATE_SUSPENDED (the CreateProcess/
         * CreateThread(CREATE_SUSPENDED) path): the thread stays
         * KI_THREAD_STATE_INITIALIZED with one suspend and its gate closed;
         * PspResumeTcb readies it when the count hits zero. */
        tcb->suspendCount = 1;
        KeClearEvent(&tcb->suspendGate);
    }
    else
    {
        KiReadyCreatedThread(tcb); /* now everything it reads is final */
    }
    if (threadIdOut != 0)
    {
        *threadIdOut = threadId;
    }
    if (tebBaseOut != 0)
    {
        *tebBaseOut = tebBase;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtCreateThreadEx(HANDLE *threadHandle, ACCESS_MASK desiredAccess,
                          OBJECT_ATTRIBUTES *objectAttributes, HANDLE processHandle,
                          PRTL_THREAD_START_ROUTINE startRoutine, void *argument, ULONG createFlags,
                          ULONG_PTR zeroBits, SIZE_T stackSize, SIZE_T maximumStackSize,
                          PS_ATTRIBUTE_LIST *attributeList)
{
    (void)desiredAccess;
    (void)objectAttributes;
    (void)zeroBits;
    (void)stackSize;
    (void)maximumStackSize;

    PKTHREAD caller = KeGetCurrentThread();
    PEPROCESS process;
    BOOLEAN referenced = FALSE;
    if (processHandle == NtCurrentProcess())
    {
        process = caller->process;
    }
    else
    {
        PVOID body;
        NTSTATUS status = ObReferenceObjectByHandle(processHandle, PROCESS_CREATE_THREAD,
                                                    &PspProcessType, ExGetPreviousMode(), &body, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        process = body;
        referenced = TRUE;
    }

    BOOLEAN suspended = (createFlags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED) != 0;
    uint64_t threadId = 0, tebBase = 0;
    NTSTATUS status = PspCreateUserThread(process, (uint64_t)(uintptr_t)startRoutine,
                                          (uint64_t)(uintptr_t)argument, suspended, threadHandle,
                                          &threadId, &tebBase);

    /* Output attributes, exactly Wine's update_attr_list (dlls/ntdll/unix/
     * thread.c): CLIENT_ID and TEB_ADDRESS write back min(Size, actual) and
     * the optional ReturnLength; kernelbase's CreateThread reads its
     * lpThreadId from the CLIENT_ID one. Unknown attributes are tolerated. */
    if (NT_SUCCESS(status) && attributeList != 0)
    {
        NTSTATUS probe = KiProbeForRead(attributeList, sizeof(SIZE_T), sizeof(SIZE_T));
        SIZE_T totalLength = NT_SUCCESS(probe) ? attributeList->TotalLength : 0;
        SIZE_T listHeader = offsetof(PS_ATTRIBUTE_LIST, Attributes);
        if (NT_SUCCESS(probe) && totalLength >= listHeader && totalLength <= 0x1000 &&
            (totalLength - listHeader) % sizeof(PS_ATTRIBUTE) == 0 &&
            NT_SUCCESS(KiProbeForRead(attributeList, totalLength, sizeof(SIZE_T))))
        {
            SIZE_T count = (totalLength - listHeader) / sizeof(PS_ATTRIBUTE);
            for (SIZE_T i = 0; i < count; i++)
            {
                const PS_ATTRIBUTE *attribute = &attributeList->Attributes[i];
                const void *value = 0;
                CLIENT_ID clientId;
                PVOID tebPointer;
                SIZE_T valueSize = 0;
                if (attribute->Attribute == PS_ATTRIBUTE_CLIENT_ID)
                {
                    clientId.UniqueProcess = (HANDLE)(uintptr_t)process->uniqueProcessId;
                    clientId.UniqueThread = (HANDLE)(uintptr_t)threadId;
                    value = &clientId;
                    valueSize = sizeof(clientId);
                }
                else if (attribute->Attribute == PS_ATTRIBUTE_TEB_ADDRESS)
                {
                    tebPointer = (PVOID)(uintptr_t)tebBase;
                    value = &tebPointer;
                    valueSize = sizeof(tebPointer);
                }
                if (value == 0)
                {
                    continue;
                }
                SIZE_T size = attribute->Size < valueSize ? attribute->Size : valueSize;
                if (attribute->ValuePtr != 0 &&
                    NT_SUCCESS(KiProbeForWrite(attribute->ValuePtr, size, 1)))
                {
                    memcpy(attribute->ValuePtr, value, size);
                }
                if (attribute->ReturnLength != 0 &&
                    NT_SUCCESS(
                        KiProbeForWrite(attribute->ReturnLength, sizeof(SIZE_T), sizeof(SIZE_T))))
                {
                    *attribute->ReturnLength = size;
                }
            }
        }
    }
    if (referenced)
    {
        ObDereferenceObject(process);
    }
    return status;
}

/* --- termination / alerts / APCs ----------------------------------------- */

NTSTATUS NtTerminateThread(HANDLE threadHandle, LONG exitStatus)
{
    PKTHREAD caller = KeGetCurrentThread();

    /* Self (or the pseudo-handle) is the only case reachable without stopping
     * a running foreign thread, which no-preemption (Art. 3) cannot do. */
    if (threadHandle == 0 || threadHandle == NtCurrentThread())
    {
        PspExitCurrentThread(exitStatus);
    }

    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(threadHandle, THREAD_TERMINATE, &PspThreadType,
                                                ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PETHREAD thread = body;
    if (thread->tcb == caller)
    {
        ObDereferenceObject(thread);
        PspExitCurrentThread(exitStatus);
    }
    /* Foreign thread (CUI-4): flag it and wake it; it reaps itself at its next
     * return to user mode (Art. 3 — never torn down from here). */
    uint64_t flags = KiAcquireDispatcherLock();
    PspFlagThreadTermination(thread->tcb, (NTSTATUS)exitStatus);
    KiReleaseDispatcherLock(flags);
    ObDereferenceObject(thread);
    return STATUS_SUCCESS;
}

NTSTATUS NtQueueApcThread(HANDLE threadHandle, PNTAPCFUNC apcRoutine, ULONG_PTR apcArgument1,
                          ULONG_PTR apcArgument2, ULONG_PTR apcArgument3)
{
    PKTHREAD target;
    PETHREAD threadObject = 0;
    if (threadHandle == NtCurrentThread())
    {
        target = KeGetCurrentThread();
    }
    else
    {
        PVOID body;
        NTSTATUS status = ObReferenceObjectByHandle(threadHandle, THREAD_SET_INFORMATION,
                                                    &PspThreadType, ExGetPreviousMode(), &body, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        threadObject = body;
        target = threadObject->tcb;
    }

    PKAPC apc = MiAllocatePool(sizeof(KAPC));
    if (apc == 0)
    {
        if (threadObject != 0)
        {
            ObDereferenceObject(threadObject);
        }
        return STATUS_NO_MEMORY;
    }
    apc->normalRoutine = (uint64_t)(uintptr_t)apcRoutine;
    apc->normalContext = apcArgument1;
    apc->systemArgument1 = apcArgument2;
    apc->systemArgument2 = apcArgument3;
    KiInsertQueueUserApc(target, apc);

    if (threadObject != 0)
    {
        ObDereferenceObject(threadObject);
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtTestAlert(void)
{
    uint64_t flags = KiAcquireDispatcherLock();
    KiTestAlertCurrentThread();
    KiReleaseDispatcherLock(flags);
    /* A queued APC is delivered by the syscall-return path (table.c) which
     * checks KiUserApcPending after this service. */
    return STATUS_SUCCESS;
}

NTSTATUS NtAlertThread(HANDLE threadHandle)
{
    PKTHREAD target;
    PETHREAD threadObject = 0;
    if (threadHandle == NtCurrentThread())
    {
        target = KeGetCurrentThread();
    }
    else
    {
        PVOID body;
        NTSTATUS status = ObReferenceObjectByHandle(threadHandle, THREAD_SET_INFORMATION,
                                                    &PspThreadType, ExGetPreviousMode(), &body, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        threadObject = body;
        target = threadObject->tcb;
    }
    uint64_t flags = KiAcquireDispatcherLock();
    target->alerted = TRUE;
    if (target->state == KI_THREAD_STATE_WAITING && target->waitAlertable)
    {
        target->waitAlertable = FALSE;
        KiAlertWaitingThread(target);
    }
    KiReleaseDispatcherLock(flags);
    if (threadObject != 0)
    {
        ObDereferenceObject(threadObject);
    }
    return STATUS_SUCCESS;
}

/* Thread-id keyed alerts (modern ntdll critical-section / SRW / WaitOnAddress
 * paths, dlls/ntdll/sync.c). The contract is a latched per-thread alert bit
 * (Wine dlls/ntdll/unix/sync.c: futex 0/1 + InterlockedExchange) — the
 * ETHREAD's synchronization event carries it exactly (sem_wait/alert_by_tid).
 * Ids are GLOBAL (the active-process list): an unknown id is
 * STATUS_INVALID_CID and a foreign process's live id is accepted, both as
 * the oracle's session-wide alert table behaves (ntdll:sync
 * test_tid_alert; the M10 process-local shortcut is retired). */
static PETHREAD PspFindThreadByThreadId(uint64_t threadId)
{
    ASSERT(KiIsDispatcherLockHeld());
    for (PLIST_ENTRY p = PspActiveProcessListHead.Flink; p != &PspActiveProcessListHead;
         p = p->Flink)
    {
        PEPROCESS process = CONTAINING_RECORD(p, EPROCESS, activeProcessLinks);
        for (PLIST_ENTRY entry = process->threadListHead.Flink; entry != &process->threadListHead;
             entry = entry->Flink)
        {
            PETHREAD candidate = CONTAINING_RECORD(entry, ETHREAD, threadListEntry);
            if (candidate->uniqueThreadId == threadId)
            {
                return candidate;
            }
        }
    }
    return 0;
}

NTSTATUS NtAlertThreadByThreadId(HANDLE threadId)
{
    uint64_t flags = KiAcquireDispatcherLock();
    PETHREAD target = PspFindThreadByThreadId((uint64_t)(uintptr_t)threadId);
    KiReleaseDispatcherLock(flags);
    if (target == 0)
    {
        /* An id that once existed aliases the oracle's still-allocated
         * table slot: the alert lands nowhere, successfully. */
        return PspIdWasAllocated((uint64_t)(uintptr_t)threadId) ? STATUS_SUCCESS
                                                                : STATUS_INVALID_CID;
    }
    /* Safe outside the lock: no kernel preemption (Art. 3), so the target
     * cannot be reclaimed between the lookup and the set. */
    KeSetEvent(&target->tidAlertEvent, 0, FALSE);
    return STATUS_SUCCESS;
}

/* Validate every id FIRST, then alert each — a bad id alerts nothing (Wine
 * dlls/ntdll/unix/sync.c NtAlertMultipleThreadByThreadId; the two trailing
 * arguments are unused there too). */
NTSTATUS NtAlertMultipleThreadByThreadId(HANDLE *threadIds, ULONG count, void *unknown1,
                                         void *unknown2)
{
    (void)unknown1;
    (void)unknown2;
    if (count == 0)
    {
        return STATUS_SUCCESS;
    }
    NTSTATUS status = KiProbeForRead(threadIds, count * sizeof(HANDLE), sizeof(HANDLE));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t flags = KiAcquireDispatcherLock();
    for (ULONG i = 0; i < count; i++)
    {
        if (PspFindThreadByThreadId((uint64_t)(uintptr_t)threadIds[i]) == 0 &&
            !PspIdWasAllocated((uint64_t)(uintptr_t)threadIds[i]))
        {
            KiReleaseDispatcherLock(flags);
            return STATUS_INVALID_CID;
        }
    }
    for (ULONG i = 0; i < count; i++)
    {
        PETHREAD target = PspFindThreadByThreadId((uint64_t)(uintptr_t)threadIds[i]);
        if (target != 0)
        {
            KeSetEvent(&target->tidAlertEvent, 0, FALSE);
        }
    }
    KiReleaseDispatcherLock(flags);
    return STATUS_SUCCESS;
}

NTSTATUS NtWaitForAlertByThreadId(const void *address, const LARGE_INTEGER *timeout)
{
    (void)address; /* opaque to the wait; pairs are keyed by thread id only */
    PETHREAD self = KeGetCurrentThread()->threadObject;
    if (self == 0)
    {
        return STATUS_TIMEOUT; /* kernel threads have no alert latch */
    }
    NTSTATUS status = KeWaitForSingleObject(&self->tidAlertEvent, UserRequest, KernelMode, FALSE,
                                            (PLARGE_INTEGER)timeout);
    /* A satisfied wait is reported as STATUS_ALERTED (the whole point of the
     * service); timeouts pass through. */
    return status == STATUS_SUCCESS ? STATUS_ALERTED : status;
}

/* CUI-4: the shared suspend/resume primitives (one truth for the thread- and
 * process-level Nt*; lock held). PspSuspendTcb closes the gate on the first
 * hold; a thread that has already run parks on it at its next ring-3 edge. */
void PspSuspendTcb(PKTHREAD tcb)
{
    ASSERT(KiIsDispatcherLockHeld());
    if (tcb->suspendCount++ == 0)
    {
        tcb->suspendGate.header.signalState = 0; /* close: park at the next edge */
    }
}

/* Drop one hold; at zero the gate opens (waking a parked thread) and a
 * never-run thread is readied — the unified create-suspended release point. */
void PspResumeTcb(PKTHREAD tcb)
{
    ASSERT(KiIsDispatcherLockHeld());
    if (tcb->suspendCount > 0 && --tcb->suspendCount == 0)
    {
        tcb->suspendGate.header.signalState = 1;
        KiWaitTest(&tcb->suspendGate.header); /* wake a thread parked on the gate */
        if (tcb->state == KI_THREAD_STATE_INITIALIZED)
        {
            KiReadyThread(tcb); /* create-suspended release */
        }
    }
}

NTSTATUS NtResumeThread(HANDLE threadHandle, PULONG previousCount)
{
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(threadHandle, THREAD_SUSPEND_RESUME, &PspThreadType,
                                                ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PETHREAD thread = body;
    PKTHREAD tcb = thread->tcb;

    uint64_t flags = KiAcquireDispatcherLock();
    ULONG previous = (ULONG)tcb->suspendCount;
    PspResumeTcb(tcb);
    KiReleaseDispatcherLock(flags);
    ObDereferenceObject(thread);

    if (previousCount != 0 &&
        NT_SUCCESS(KiProbeForWrite(previousCount, sizeof(ULONG), sizeof(ULONG))))
    {
        *previousCount = previous;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtSuspendThread(HANDLE threadHandle, PULONG previousCount)
{
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(threadHandle, THREAD_SUSPEND_RESUME, &PspThreadType,
                                                ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PETHREAD thread = body;
    PKTHREAD tcb = thread->tcb;

    uint64_t flags = KiAcquireDispatcherLock();
    ULONG previous = (ULONG)tcb->suspendCount;
    PspSuspendTcb(tcb);
    KiReleaseDispatcherLock(flags);
    ObDereferenceObject(thread);

    if (previousCount != 0 &&
        NT_SUCCESS(KiProbeForWrite(previousCount, sizeof(ULONG), sizeof(ULONG))))
    {
        *previousCount = previous;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtOpenThread(HANDLE *threadHandle, ACCESS_MASK desiredAccess,
                      const OBJECT_ATTRIBUTES *objectAttributes, const CLIENT_ID *clientId)
{
    (void)threadHandle;
    (void)desiredAccess;
    (void)objectAttributes;
    (void)clientId;
    return STATUS_NOT_IMPLEMENTED; /* open-by-CLIENT_ID: not on the M7 path */
}

NTSTATUS NtGetNextThread(HANDLE processHandle, HANDLE threadHandle, ACCESS_MASK desiredAccess,
                         ULONG attributes, ULONG flags, HANDLE *handleOut)
{
    /* The loader's TLS walk (dlls/ntdll/loader.c alloc_tls_slot enumerates
     * every thread when a TLS-bearing DLL loads at runtime). Contract from
     * wineserver's get_next_thread (server/thread.c): flags 0 walks
     * creation order forward, 1 backward, anything else refuses; last = 0
     * starts at the end; each success is a NEW handle; the walk finishes
     * with STATUS_NO_MORE_ENTRIES. wineserver walks its global list, which
     * restricted to one process is the same creation order as
     * EPROCESS.threadListHead. The list is re-scanned rather than chained
     * from last's links: an exited thread has left the list (its entry is
     * reused for the reaper), so a stale `last` ends the walk gracefully
     * instead of wandering. Pinned by sem_ps/get_next_thread. */
    if (flags > 1)
    {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = KiProbeForWrite(handleOut, sizeof(*handleOut), sizeof(*handleOut));
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PEPROCESS process;
    BOOLEAN processReferenced = FALSE;
    if (processHandle == NtCurrentProcess())
    {
        process = KeGetCurrentThread()->process;
    }
    else
    {
        PVOID body;
        status = ObReferenceObjectByHandle(processHandle, PROCESS_QUERY_INFORMATION,
                                           &PspProcessType, ExGetPreviousMode(), &body, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        process = body;
        processReferenced = TRUE;
    }

    PETHREAD lastThread = 0;
    if (threadHandle != 0)
    {
        PVOID body;
        status = ObReferenceObjectByHandle(threadHandle, 0, &PspThreadType, ExGetPreviousMode(),
                                           &body, 0);
        if (!NT_SUCCESS(status))
        {
            if (processReferenced)
            {
                ObDereferenceObject(process);
            }
            return status;
        }
        lastThread = body;
    }

    PETHREAD found = 0;
    uint64_t lockFlags = KiAcquireDispatcherLock();
    BOOLEAN seen = (lastThread == 0);
    PLIST_ENTRY head = &process->threadListHead;
    for (PLIST_ENTRY entry = flags ? head->Blink : head->Flink; entry != head;
         entry = flags ? entry->Blink : entry->Flink)
    {
        PETHREAD candidate = CONTAINING_RECORD(entry, ETHREAD, threadListEntry);
        if (seen)
        {
            found = candidate;
            ObfReferenceObject(found); /* pins it across the lock drop */
            break;
        }
        if (candidate == lastThread)
        {
            seen = TRUE;
        }
    }
    KiReleaseDispatcherLock(lockFlags);

    if (lastThread != 0)
    {
        ObDereferenceObject(lastThread);
    }
    if (found == 0)
    {
        status = STATUS_NO_MORE_ENTRIES;
    }
    else
    {
        status = ObpCreateHandle(found, ObpMapDesiredAccess(&PspThreadType, desiredAccess),
                                 attributes, handleOut);
        ObDereferenceObject(found); /* the handle holds its own reference */
    }
    if (processReferenced)
    {
        ObDereferenceObject(process);
    }
    return status;
}

/* --- queries -------------------------------------------------------------- */

NTSTATUS NtQueryInformationThread(HANDLE threadHandle, THREADINFOCLASS infoClass, PVOID buffer,
                                  ULONG length, PULONG returnLength)
{
    PKTHREAD caller = KeGetCurrentThread();
    PETHREAD self = caller->threadObject;

    switch (infoClass)
    {
    case ThreadBasicInformation:
    {
        if (length < sizeof(THREAD_BASIC_INFORMATION))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status =
            KiProbeForWrite(buffer, sizeof(THREAD_BASIC_INFORMATION), sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        /* Resolve the target: the pseudo-handle (or an unwired M7-era 0)
         * means the caller; a real handle names any thread — M9's
         * GetExitCodeThread reads a JOINED thread's status through here. */
        PETHREAD target = self;
        PKTHREAD targetTcb = caller;
        BOOLEAN referenced = FALSE;
        if (threadHandle != 0 && threadHandle != NtCurrentThread())
        {
            PVOID body;
            status = ObReferenceObjectByHandle(threadHandle, THREAD_QUERY_INFORMATION,
                                               &PspThreadType, ExGetPreviousMode(), &body, 0);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            target = body;
            targetTcb = target->tcb;
            referenced = TRUE;
        }

        THREAD_BASIC_INFORMATION info;
        memset(&info, 0, sizeof(info));
        /* Signaled thread object = exited (the join contract); a live
         * thread reports STATUS_PENDING — what STILL_ACTIVE decodes to. */
        BOOLEAN exited = target != 0 && target->header.signalState != 0;
        info.ExitStatus = exited ? targetTcb->exitStatus : STATUS_PENDING;
        info.TebBaseAddress = target != 0 ? (PVOID)(uintptr_t)target->tebBase : caller->teb;
        info.ClientId.UniqueProcess =
            (HANDLE)(uintptr_t)(target != 0 ? target->process->uniqueProcessId
                                            : caller->process->uniqueProcessId);
        info.ClientId.UniqueThread = (HANDLE)(uintptr_t)(target != 0 ? target->uniqueThreadId : 0);
        info.Priority = targetTcb != 0 ? targetTcb->priority : caller->priority;
        info.BasePriority = info.Priority;
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
        if (referenced)
        {
            ObDereferenceObject(target);
        }
        return STATUS_SUCCESS;
    }
    case ThreadAmILastThread:
    {
        if (length < sizeof(ULONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(ULONG), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        ULONG isLast = caller->process->activeThreadCount <= 1 ? 1 : 0;
        memcpy(buffer, &isLast, sizeof(isLast));
        if (returnLength != 0)
        {
            *returnLength = sizeof(isLast);
        }
        return STATUS_SUCCESS;
    }
    default:
        (void)threadHandle;
        return STATUS_NOT_IMPLEMENTED;
    }
}

NTSTATUS NtSetInformationThread(HANDLE threadHandle, THREADINFOCLASS infoClass, LPCVOID buffer,
                                ULONG length)
{
    (void)threadHandle;
    (void)buffer;
    (void)length;
    /* The classes ntdll sets at startup (name, ideal processor, hide-from-
     * debugger, TEB pointers) have no observable effect on a single-CPU
     * proskrnl; accept them so the loader proceeds. */
    switch (infoClass)
    {
    case ThreadZeroTlsCell:
    case ThreadHideFromDebugger:
        return STATUS_SUCCESS;
    default:
        return STATUS_SUCCESS;
    }
}
