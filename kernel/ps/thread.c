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
    KiEnterUserMode(tcb->userStartRip, tcb->userStartRsp, tcb->userStartArg1, tcb->userStartArg2);
}

/* Build the ETHREAD wrapper for a KTHREAD and link it into the process. The
 * caller has already prepared the KTHREAD's user-start state; this readies it
 * only via KiCreateThreadEx elsewhere. Returns a creator reference. */
NTSTATUS PspCreateThreadObject(PEPROCESS process, PKTHREAD tcb, uint64_t tebBase,
                               uint64_t stackAllocationBase, uint64_t stackBase,
                               PETHREAD *threadOut)
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

    ObfReferenceObject(process); /* the thread pins its process */
    uint64_t flags = KiAcquireDispatcherLock();
    thread->uniqueThreadId = ++process->nextThreadId;
    InsertTailList(&process->threadListHead, &thread->threadListEntry);
    process->activeThreadCount++;
    KiReleaseDispatcherLock(flags);

    tcb->threadObject = thread;
    *threadOut = thread;
    return STATUS_SUCCESS;
}

__attribute__((noreturn)) void PspExitCurrentThread(NTSTATUS exitStatus)
{
    PKTHREAD tcb = KeGetCurrentThread();
    PEPROCESS process = tcb->process;
    PETHREAD thread = tcb->threadObject;

    /* The last thread's exit is the process's exit: close handles (in thread
     * context, before the address space is torn down) and signal the process
     * object. A non-last thread just signals its own thread object so joins
     * complete; its KTHREAD/stack are reclaimed when the ETHREAD is deleted. */
    uint64_t flags = KiAcquireDispatcherLock();
    LONG remaining = --process->activeThreadCount;
    if (thread != 0)
    {
        RemoveEntryList(&thread->threadListEntry);
    }
    KiReleaseDispatcherLock(flags);

    tcb->exitStatus = exitStatus;
    if (thread != 0)
    {
        KiTraceEvent(KiTraceThreadExit, (uint64_t)(uintptr_t)tcb, (uint64_t)(uint32_t)exitStatus,
                     0);
        uint64_t f2 = KiAcquireDispatcherLock();
        thread->header.signalState = 1; /* joins on the thread handle satisfy */
        KiWaitTest(&thread->header);
        KiReleaseDispatcherLock(f2);
    }

    if (remaining == 0)
    {
        ObpCloseAllHandles(&process->handleTable);
        process->exitStatus = exitStatus;
        KiTraceEvent(KiTraceProcessExit, (uint64_t)(uintptr_t)process,
                     (uint64_t)(uint32_t)exitStatus, 0);
        uint64_t f3 = KiAcquireDispatcherLock();
        process->header.signalState = 1; /* never reset: joins always satisfy */
        KiWaitTest(&process->header);
        KiReleaseDispatcherLock(f3);
    }

    KiTerminateThread();
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

NTSTATUS PspCreateUserThread(PEPROCESS process, uint64_t startRoutine, uint64_t argument,
                             BOOLEAN createSuspended, PHANDLE threadHandleOut)
{
    (void)createSuspended; /* M7: suspend-on-create not needed by the test/ntdll path */

    uint64_t allocBase = 0, stackTop = 0, stackLimit = 0;
    NTSTATUS status =
        PspAllocateThreadStack(process, 0x100000, 0x10000, &allocBase, &stackTop, &stackLimit);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    uint64_t tebBase = 0;
    status = PspBuildTeb(process, stackTop, stackLimit, process->uniqueProcessId,
                         ++process->nextThreadId, &tebBase);
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
    tcb->userStartRsp = (stackTop - 0x28) & ~(uint64_t)0xf;
    tcb->userStartArg1 = startRoutine;
    tcb->userStartArg2 = argument;

    PETHREAD thread;
    status = PspCreateThreadObject(process, tcb, tebBase, allocBase, stackTop, &thread);
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
    KiReadyCreatedThread(tcb);   /* now everything it reads is final */
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
    (void)attributeList;

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
    NTSTATUS status = PspCreateUserThread(process, (uint64_t)(uintptr_t)startRoutine,
                                          (uint64_t)(uintptr_t)argument, suspended, threadHandle);
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
    ObDereferenceObject(thread);
    return STATUS_NOT_IMPLEMENTED; /* foreign running thread: needs suspend (unbuilt) */
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

/* Thread-id keyed alerts (modern ntdll critical-section / SRW fast paths). A
 * minimal build over the same alert bit; the id is the ETHREAD's. */
NTSTATUS NtAlertThreadByThreadId(HANDLE threadId)
{
    (void)threadId;
    /* proskrnl's ntdll targets the raw-syscall path; the address-wait fast
     * path is only reached under contention, which the single-threaded M7
     * bring-up never hits. Accept and no-op (nothing is waiting on it). */
    return STATUS_SUCCESS;
}

NTSTATUS NtWaitForAlertByThreadId(const void *address, const LARGE_INTEGER *timeout)
{
    (void)address;
    /* Symmetric with the above: with nothing to wait on, a bounded wait times
     * out (callers loop). Honour a zero timeout immediately. */
    if (timeout != 0 && timeout->QuadPart == 0)
    {
        return STATUS_TIMEOUT;
    }
    return STATUS_TIMEOUT;
}

NTSTATUS NtResumeThread(HANDLE threadHandle, PULONG previousCount)
{
    (void)threadHandle;
    if (previousCount != 0 &&
        NT_SUCCESS(KiProbeForWrite(previousCount, sizeof(ULONG), sizeof(ULONG))))
    {
        *previousCount = 1;
    }
    return STATUS_SUCCESS; /* create-suspended is unused; nothing to resume */
}

NTSTATUS NtSuspendThread(HANDLE threadHandle, PULONG previousCount)
{
    (void)threadHandle;
    if (previousCount != 0 &&
        NT_SUCCESS(KiProbeForWrite(previousCount, sizeof(ULONG), sizeof(ULONG))))
    {
        *previousCount = 0;
    }
    return STATUS_NOT_IMPLEMENTED;
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
        THREAD_BASIC_INFORMATION info;
        memset(&info, 0, sizeof(info));
        info.ExitStatus = STATUS_PENDING;
        info.TebBaseAddress = self != 0 ? (PVOID)(uintptr_t)self->tebBase : caller->teb;
        info.ClientId.UniqueProcess = (HANDLE)(uintptr_t)caller->process->uniqueProcessId;
        info.ClientId.UniqueThread = (HANDLE)(uintptr_t)(self != 0 ? self->uniqueThreadId : 0);
        info.Priority = caller->priority;
        info.BasePriority = caller->priority;
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
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
