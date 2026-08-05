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
#include "kernel/se/se.h" /* CUI-6: SeTokenType / TOKEN_IMPERSONATE for impersonation attach */
#include "kernel/mm/pool.h"
#include "kernel/mm/virtual.h"
#include "kernel/mm/phys.h"
#include "kernel/syscall/syscall.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "kernel/init/trace.h"
#include "kernel/lib/dbgprint.h"
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
    if (thread->impersonationToken != 0)
    {
        ObDereferenceObject(thread->impersonationToken); /* CUI-6: the one token ref */
    }
    if (thread->tcb != 0)
    {
        KiDeleteThread(thread->tcb);
    }
    if (thread->process != 0)
    {
        ObDereferenceObject(thread->process);
    }
}

/* CUI-6: the current thread's impersonation token (ps.h; G11). Null-safe
 * for the early-boot window before the scheduler has a current thread. */
PVOID PsCurrentThreadImpersonationToken(void)
{
    PKTHREAD tcb = KeGetCurrentThread();
    if (tcb == 0 || tcb->threadObject == 0)
    {
        return 0;
    }
    return ((PETHREAD)tcb->threadObject)->impersonationToken;
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
    /* CUI-6: birth stamp (sem_ps/times); exit stamped at retire. */
    KeQuerySystemTime(&thread->createTime);
    thread->exitTime.QuadPart = 0;
    thread->impersonationToken = 0; /* not impersonating until SetThreadToken */
    /* CUI-6: the Win32 start address — userStartArg1 IS the creation start
     * routine for user threads (the RtlUserThreadStart argument protocol);
     * 0 for main threads built before their entry is known, answered from
     * the process entry at query time. */
    thread->win32StartAddress = tcb->userStartArg1;

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

/* Undo PspCreateThreadObject for a thread that was built but never started.
 *
 * The caller's single ObDereferenceObject was not enough, and the comment
 * that claimed it "deletes the never-started thread" was wrong: the object's
 * pointerCount is 2 at that point (the allocation's, plus the RUNNING PIN
 * this function takes), so the ETHREAD survived -- still on
 * threadListHead, still counted in activeThreadCount. `remaining` then never
 * reached 0, so the process could NEVER exit: handles never closed,
 * exitStatus never published, every wait on that process hanging forever
 * (docs/review-2026-07 §7).
 *
 * This drops exactly what PspCreateThreadObject added, in reverse, leaving
 * the caller's own creator reference to release the object. The KTHREAD goes
 * with it through PspDeleteThread, so the caller must NOT also free it. */
static void PspUnwindUnstartedThread(PETHREAD thread)
{
    uint64_t flags = KiAcquireDispatcherLock();
    ASSERT(thread->process->activeThreadCount > 0);
    RemoveEntryList(&thread->threadListEntry);
    thread->process->activeThreadCount--;
    KiReleaseDispatcherLock(flags);
    ObDereferenceObject(thread); /* the running pin */
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
    /* CUI-6: the exit stamp, and the dying thread's tick counters roll into
     * the process's exited totals — from here on ProcessTimes = exited
     * totals + live threads, with this thread counted exactly once. */
    KeQuerySystemTime(&thread->exitTime);
    uint64_t flags = KiAcquireDispatcherLock();
    thread->process->exitedKernelTime100ns += tcb->kernelTime100ns;
    thread->process->exitedUserTime100ns += tcb->userTime100ns;
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
    /* The last exit before the thread stops running: everything it took
     * during its own rundown (the delete-on-close writeback's volume gate, a
     * transient handle) has been given back by now, and anything still held
     * is held forever — nobody else can release it (issue #96 B). */
    KiAssertNoObligations("thread exit");
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
        KeQuerySystemTime(&process->exitTime); /* CUI-6 (sem_ps/times) */
        PspNotifyProcessExit(process);         /* CUI-3: the job's EXIT_PROCESS packets */
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
                             BOOLEAN createSuspended, const PSP_THREAD_OPTIONS *options,
                             PHANDLE threadHandleOut, uint64_t *threadIdOut, uint64_t *tebBaseOut)
{
    /* Stack geometry, following the oracle's own rules
     * (third_party/wine dlls/ntdll/unix/virtual.c virtual_alloc_thread_stack):
     * a 0 size means the image's default, the RESERVE is the larger of the
     * two, and the whole thing is floored at 1 MiB and rounded to the
     * allocation granularity. The floor is not decoration -- without it a
     * caller asking for a small stack gets one, and ntdll's own thread
     * startup overflows it. */
    /* The RESERVE is the caller's, floored and rounded as the oracle floors
     * and rounds it (third_party/wine dlls/ntdll/unix/virtual.c
     * virtual_alloc_thread_stack: `size = max( reserve_size, commit_size );
     * if (size < 1024 * 1024) size = 1024 * 1024;` then round to the
     * granularity). It was hardcoded at 1 MiB (docs/review-2026-07 §11).
     *
     * The COMMIT is the caller's as a FLOOR only, never below the 64 KiB
     * default. That is deliberate and it is not laziness: this kernel grows
     * a thread stack one page at a time off a single guard page, so a
     * function whose frame is larger than the gap steps clean over the guard
     * and takes a plain access violation. Wine does not have the problem
     * because it commits the WHOLE reservation up front and uses the guard
     * page only as an overflow tripwire. Honouring a 4 KiB commit literally
     * -- which is what ntdll's own threadpool asks for -- crashes those
     * threads in ntdll startup, convicted by sem_port/ports. The commit is
     * not part of any pinned contract; the reserve is (the TEB's
     * DeallocationStack). */
    uint64_t reserve = options->stackReserve != 0 ? options->stackReserve : 0x100000;
    uint64_t commit = options->stackCommit > 0x10000 ? options->stackCommit : 0x10000;
    if (reserve < commit)
    {
        reserve = commit;
    }
    if (reserve < 0x100000)
    {
        reserve = 0x100000;
    }
    reserve = (reserve + MI_ALLOCATION_GRANULARITY - 1) & ~(MI_ALLOCATION_GRANULARITY - 1);
    uint64_t allocBase = 0, stackTop = 0, stackLimit = 0;
    NTSTATUS status =
        PspAllocateThreadStack(process, reserve, commit, &allocBase, &stackTop, &stackLimit);
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
    /* The caller's DesiredAccess and OBJECT_ATTRIBUTES, not THREAD_ALL_ACCESS
     * and 0. NtCreateThreadEx used to grant every right regardless of what
     * was asked for and to drop OBJ_INHERIT on the floor
     * (docs/review-2026-07 §11). */
    status = ObpCreateHandle(thread, ObpMapDesiredAccess(&PspThreadType, options->desiredAccess),
                             options->handleAttributes, threadHandleOut);
    if (!NT_SUCCESS(status))
    {
        PspUnwindUnstartedThread(thread); /* the running pin + the process link */
        ObDereferenceObject(thread);      /* the creator reference: now it dies */
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
    (void)zeroBits;

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

    /* stackSize is the COMMIT and maximumStackSize the RESERVE, as
     * kernelbase's CreateThread fills them (Wine dlls/ntdll/unix/thread.c
     * NtCreateThreadEx: stack_commit / stack_reserve). Both were hardcoded. */
    PSP_THREAD_OPTIONS options;
    memset(&options, 0, sizeof(options));
    options.desiredAccess = desiredAccess;
    options.stackCommit = stackSize;
    options.stackReserve = maximumStackSize;
    if (objectAttributes != 0)
    {
        NTSTATUS probeStatus = ObProbeObjectAttributes(objectAttributes);
        if (!NT_SUCCESS(probeStatus))
        {
            if (referenced)
            {
                ObDereferenceObject(process);
            }
            return probeStatus;
        }
        options.handleAttributes = objectAttributes->Attributes;
    }

    BOOLEAN suspended = (createFlags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED) != 0;
    uint64_t threadId = 0, tebBase = 0;
    NTSTATUS status = PspCreateUserThread(process, (uint64_t)(uintptr_t)startRoutine,
                                          (uint64_t)(uintptr_t)argument, suspended, &options,
                                          threadHandle, &threadId, &tebBase);

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

/* THE user-APC queue engine, shared by NtQueueApcThread and
 * NtQueueApcThreadEx2 (the pinned tree funnels the classic entry into Ex2:
 * dlls/ntdll/unix/thread.c). The target handle needs THREAD_SET_CONTEXT —
 * the server's APC_USER gate (server/thread.c queue_apc), which
 * sem_ps/apc_ex pins. */
static NTSTATUS PspQueueUserApc(HANDLE threadHandle, PNTAPCFUNC apcRoutine, ULONG_PTR apcArgument1,
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
        NTSTATUS status = ObReferenceObjectByHandle(threadHandle, THREAD_SET_CONTEXT,
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

NTSTATUS NtQueueApcThread(HANDLE threadHandle, PNTAPCFUNC apcRoutine, ULONG_PTR apcArgument1,
                          ULONG_PTR apcArgument2, ULONG_PTR apcArgument3)
{
    return PspQueueUserApc(threadHandle, apcRoutine, apcArgument1, apcArgument2, apcArgument3);
}

/* CUI-6: QueueUserAPC2's back end. The flag bits change nothing at this
 * boundary — the pinned server carries SERVER_USER_APC_SPECIAL only to
 * refuse wow64 targets and delivery is identical (sem_ps/apc_ex pins it;
 * Art. 6: the oracle is the spec). Reserve objects do not exist
 * (NtAllocateReserveObject is permanently out of scope, docs/16), so a
 * non-NULL reserve handle refuses loudly (Art. 12) — no baked caller
 * passes one (kernelbase always sends NULL). */
NTSTATUS NtQueueApcThreadEx2(HANDLE threadHandle, HANDLE reserveHandle, ULONG flags,
                             PNTAPCFUNC apcRoutine, ULONG_PTR apcArgument1, ULONG_PTR apcArgument2,
                             ULONG_PTR apcArgument3)
{
    (void)flags; /* accepted; unmapped bits are dropped exactly as the
                  * oracle's unix layer drops them */
    if (reserveHandle != 0)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    return PspQueueUserApc(threadHandle, apcRoutine, apcArgument1, apcArgument2, apcArgument3);
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

/* THE alert-delivery core (lock held), shared by NtAlertThread and
 * NtAlertResumeThread (G10). */
static void PspAlertTcbLocked(PKTHREAD target)
{
    ASSERT(KiIsDispatcherLockHeld());
    if (target->state == KI_THREAD_STATE_WAITING && target->waitAlertable)
    {
        /* The alert is CONSUMED by the wake it causes: the woken wait
         * returns STATUS_ALERTED, which IS the delivery. Latching the bit as
         * well let one NtAlertThread satisfy two alertable waits -- the
         * parked one it woke, and the next one, which found the bit still
         * set (docs/review-2026-07 §9). A SleepEx loop spins on that. */
        target->waitAlertable = FALSE;
        KiAlertWaitingThread(target);
    }
    else
    {
        /* Nothing to wake: latch it for the target's next alertable wait. */
        target->alerted = TRUE;
    }
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
    PspAlertTcbLocked(target);
    KiReleaseDispatcherLock(flags);
    if (threadObject != 0)
    {
        ObDereferenceObject(threadObject);
    }
    return STATUS_SUCCESS;
}

/* CUI-6: the alert+resume pair. The resume half is the oracle's
 * (NtResumeThread with the previous-count write-back); the alert half is
 * the documented NT contract the pinned unix side drops under its own
 * FIXME, pinned beyond_oracle by sem_ps/apc_ex. One lock hold covers both
 * so the previous count and the alert are one atomic observation. */
NTSTATUS NtAlertResumeThread(HANDLE threadHandle, PULONG previousCount)
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
    PspAlertTcbLocked(tcb);
    KiReleaseDispatcherLock(flags);
    ObDereferenceObject(thread);

    if (previousCount != 0 &&
        NT_SUCCESS(KiProbeForWrite(previousCount, sizeof(ULONG), sizeof(ULONG))))
    {
        *previousCount = previous;
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
    target->tidAlertsIn++;
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
            target->tidAlertsIn++;
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
    if (status == STATUS_SUCCESS)
    {
        self->tidAlertsOut++;
    }
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
    /* && sequences the guard before the decrement, so the drop happens
     * exactly on a held count. */
    /* NOLINTNEXTLINE(bugprone-inc-dec-in-conditions) */
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
    /* CUI-6: open by CLIENT_ID (sem_ps/open_thread). Only UniqueThread is
     * consulted, matching the oracle (server/thread.c open_thread sends just
     * req->tid; get_thread_from_id fails with STATUS_INVALID_CID). Reuses
     * the one by-id thread lookup (PspFindThreadByThreadId, G11) — never a
     * second walk. */
    CLIENT_ID capturedId;
    NTSTATUS status = KiCopyFromUser(&capturedId, clientId, sizeof(capturedId));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    ULONG attributes = 0;
    if (objectAttributes != 0)
    {
        OBJECT_ATTRIBUTES capturedAttr;
        status = KiCopyFromUser(&capturedAttr, objectAttributes, sizeof(capturedAttr));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        attributes = capturedAttr.Attributes;
    }

    uint64_t threadId = (uint64_t)(uintptr_t)capturedId.UniqueThread;
    uint64_t flags = KiAcquireDispatcherLock();
    PETHREAD target = PspFindThreadByThreadId(threadId);
    if (target != 0)
    {
        ObfReferenceObject(target); /* pin across the lock drop */
    }
    KiReleaseDispatcherLock(flags);
    if (target == 0)
    {
        return STATUS_INVALID_CID;
    }
    status = ObpCreateHandle(target, ObpMapDesiredAccess(&PspThreadType, desiredAccess), attributes,
                             threadHandle);
    ObDereferenceObject(target); /* the handle holds its own reference */
    return status;
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
    NTSTATUS probeStatus = PspProbeReturnLength(returnLength);
    if (!NT_SUCCESS(probeStatus))
    {
        return probeStatus;
    }
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
    case ThreadTimes:
    {
        /* CUI-6 (sem_ps/times): wall stamps from the ETHREAD, CPU time from
         * the KTHREAD's tick counters. The oracle has NO length gate here —
         * it copies min(length, sizeof) and reports that as the return
         * length (dlls/ntdll/unix/thread.c ThreadTimes). */
        PETHREAD target = self;
        PKTHREAD targetTcb = caller;
        BOOLEAN referenced = FALSE;
        NTSTATUS status;
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
        KERNEL_USER_TIMES times;
        memset(&times, 0, sizeof(times));
        uint64_t flags = KiAcquireDispatcherLock();
        if (target != 0)
        {
            times.CreateTime = target->createTime;
            times.ExitTime = target->exitTime;
        }
        times.KernelTime.QuadPart = (LONGLONG)targetTcb->kernelTime100ns;
        times.UserTime.QuadPart = (LONGLONG)targetTcb->userTime100ns;
        KiReleaseDispatcherLock(flags);
        if (referenced)
        {
            ObDereferenceObject(target);
        }
        ULONG copy = length < sizeof(times) ? length : (ULONG)sizeof(times);
        if (copy != 0)
        {
            status = KiProbeForWrite(buffer, copy, 1);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            memcpy(buffer, &times, copy);
        }
        if (returnLength != 0)
        {
            *returnLength = copy;
        }
        return STATUS_SUCCESS;
    }
    case ThreadQuerySetWin32StartAddress:
    {
        /* CUI-6 (sem_ps/proc_classes): the oracle copies min(length,
         * sizeof) with no length gate (dlls/ntdll/unix/thread.c
         * get_thread_info ENTRYPOINT read-back). A main thread stamped
         * before its entry was known answers the process entry. */
        PETHREAD target = self;
        PKTHREAD targetTcb = caller;
        BOOLEAN referenced = FALSE;
        NTSTATUS status;
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
        uint64_t entry = target != 0 ? target->win32StartAddress : 0;
        if (entry == 0)
        {
            entry = targetTcb->process->entryRip;
        }
        if (referenced)
        {
            ObDereferenceObject(target);
        }
        ULONG copy = length < sizeof(entry) ? length : (ULONG)sizeof(entry);
        if (copy != 0)
        {
            status = KiProbeForWrite(buffer, copy, 1);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            memcpy(buffer, &entry, copy);
        }
        if (returnLength != 0)
        {
            *returnLength = copy;
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
        /* The refusal split (Art. 12, docs/21 W1): a class NUMBER outside
         * the enum abi/ generates is INVALID and answers
         * STATUS_INVALID_INFO_CLASS — an implemented answer. A class inside
         * it that is merely unbuilt keeps STATUS_NOT_IMPLEMENTED, named on
         * serial and fatal under the armed boot, because collapsing the two
         * would let every unbuilt class answer plausibly. The bound is the
         * header's own MaxThreadInfoClass sentinel, never typed (Art. 4).
         *
         * ThreadWineNativeThreadName (1000) sits ABOVE that sentinel and is
         * still a real class — the fork's own extension, which its ntdll
         * calls (third_party/wine dlls/ntdll/thread.c). It is unbuilt, not
         * invalid, so it must keep the loud refusal; treating "above the
         * sentinel" as "does not exist" would silently accept it. */
        if (infoClass != ThreadWineNativeThreadName &&
            ((LONG)infoClass < 0 || (ULONG)infoClass >= (ULONG)MaxThreadInfoClass))
        {
            return STATUS_INVALID_INFO_CLASS;
        }
        DbgPrint("NtQueryInformationThread: unbuilt info class %d\n", (int)infoClass);
        return STATUS_NOT_IMPLEMENTED;
    }
}

NTSTATUS NtSetInformationThread(HANDLE threadHandle, THREADINFOCLASS infoClass, LPCVOID buffer,
                                ULONG length)
{
    /* CUI-6 (sem_se/se_impersonate): thread impersonation attach. The buffer
     * is a HANDLE naming a token to impersonate, or 0 to revert
     * (RevertToSelf); the token handle is resolved with TOKEN_IMPERSONATE
     * (server/thread.c security_set_thread_token), and a failed resolve
     * leaves the old token in place. */
    if (infoClass == ThreadImpersonationToken)
    {
        if (length != sizeof(HANDLE))
        {
            return STATUS_INVALID_PARAMETER;
        }
        HANDLE tokenHandle;
        NTSTATUS status = KiCopyFromUser(&tokenHandle, buffer, sizeof(tokenHandle));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        /* Impersonation targets the CURRENT thread (RtlImpersonateSelf /
         * SetThreadToken(NULL, ...) — no baked caller sets another thread's
         * token, and the server path resolves req->handle with 0 access). */
        PETHREAD self = KeGetCurrentThread()->threadObject;
        if (self == 0)
        {
            return STATUS_INVALID_HANDLE; /* a kernel thread has no ETHREAD */
        }
        PVOID newToken = 0;
        if (tokenHandle != 0)
        {
            status = ObReferenceObjectByHandle(tokenHandle, TOKEN_IMPERSONATE, &SeTokenType,
                                               ExGetPreviousMode(), &newToken, 0);
            if (!NT_SUCCESS(status))
            {
                return status; /* the old token stays in place */
            }
        }
        /* Replace: drop the old reference only after the new one is secured. */
        if (self->impersonationToken != 0)
        {
            ObDereferenceObject(self->impersonationToken);
        }
        self->impersonationToken = newToken; /* keeps the reference (or 0) */
        return STATUS_SUCCESS;
    }
    /* CUI-6 (sem_ps/proc_classes): the one stored set — the Win32 start
     * address, sizeof(PVOID) exactly (dlls/ntdll/unix/thread.c
     * SET_THREAD_INFO_ENTRYPOINT). */
    if (infoClass == ThreadQuerySetWin32StartAddress)
    {
        if (length != sizeof(PVOID))
        {
            return STATUS_INVALID_PARAMETER;
        }
        uint64_t entry;
        NTSTATUS status = KiCopyFromUser(&entry, buffer, sizeof(entry));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        PETHREAD target = KeGetCurrentThread()->threadObject;
        BOOLEAN referenced = FALSE;
        if (threadHandle != 0 && threadHandle != NtCurrentThread())
        {
            PVOID body;
            status = ObReferenceObjectByHandle(threadHandle, THREAD_SET_INFORMATION, &PspThreadType,
                                               ExGetPreviousMode(), &body, 0);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            target = body;
            referenced = TRUE;
        }
        if (target != 0)
        {
            target->win32StartAddress = entry;
        }
        if (referenced)
        {
            ObDereferenceObject(target);
        }
        return STATUS_SUCCESS;
    }
    (void)threadHandle;
    (void)buffer;
    (void)length;
    /* The default arm used to be STATUS_SUCCESS for EVERY class, and it did
     * not even name the class on serial. ThreadImpersonationToken went
     * through it: a caller that impersonates, gets success, and then makes a
     * security decision on that answer is exactly the deferred bug Art. 12
     * describes. An unbuilt class refuses loudly instead, and the
     * dispatcher's PARTIAL line names it.
     *
     * The accepted list is the classes ntdll sets at startup whose effect is
     * genuinely nil on a single-CPU proskrnl -- accepting them is an
     * IMPLEMENTATION of a no-op, not a fabrication, and each is listed
     * explicitly so that adding one is a decision. */
    switch (infoClass)
    {
    case ThreadZeroTlsCell:
    case ThreadHideFromDebugger:
    /* Priority and affinity: one CPU, one priority band that matters
     * (docs/03 "Deliberate simplifications"). */
    case ThreadPriority:
    case ThreadBasePriority:
    case ThreadAffinityMask:
    case ThreadIdealProcessor:
    case ThreadIdealProcessorEx:
    case ThreadPriorityBoost:
    /* The thread name is stored by ntdll in the TEB; nothing in the kernel
     * observes it. */
    case ThreadNameInformation:
        return STATUS_SUCCESS;
    default:
        /* The refusal split (Art. 12, docs/21 W1): a class NUMBER outside
         * the enum abi/ generates is INVALID and answers
         * STATUS_INVALID_INFO_CLASS — an implemented answer. A class inside
         * it that is merely unbuilt keeps STATUS_NOT_IMPLEMENTED, named on
         * serial and fatal under the armed boot, because collapsing the two
         * would let every unbuilt class answer plausibly. The bound is the
         * header's own MaxThreadInfoClass sentinel, never typed (Art. 4).
         *
         * ThreadWineNativeThreadName (1000) sits ABOVE that sentinel and is
         * still a real class — the fork's own extension, which its ntdll
         * calls (third_party/wine dlls/ntdll/thread.c). It is unbuilt, not
         * invalid, so it must keep the loud refusal; treating "above the
         * sentinel" as "does not exist" would silently accept it. */
        if (infoClass != ThreadWineNativeThreadName &&
            ((LONG)infoClass < 0 || (ULONG)infoClass >= (ULONG)MaxThreadInfoClass))
        {
            return STATUS_INVALID_INFO_CLASS;
        }
        DbgPrint("NtSetInformationThread: unbuilt info class %d\n", (int)infoClass);
        return STATUS_NOT_IMPLEMENTED;
    }
}
