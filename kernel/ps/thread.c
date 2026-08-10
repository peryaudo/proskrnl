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
#include "abi/ntwow64.h"
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
    if (thread->threadName.Buffer != 0)
    {
        MiFreePool(thread->threadName.Buffer);
        thread->threadName.Buffer = 0;
    }
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

/* NT's thread access implications, verbatim from the oracle's own
 * thread_map_access (third_party/wine server/thread.c): the full query and
 * set rights each imply their LIMITED counterpart. Without this a handle
 * opened THREAD_QUERY_INFORMATION is refused by every class that asks for
 * the limited right — and kernel32:thread opens exactly the other way
 * round, with OpenThread(THREAD_QUERY_LIMITED_INFORMATION), which is how
 * the gap surfaced. */
static ACCESS_MASK PspMapThreadAccess(ACCESS_MASK granted)
{
    if (granted & THREAD_QUERY_INFORMATION)
    {
        granted |= THREAD_QUERY_LIMITED_INFORMATION;
    }
    if (granted & THREAD_SET_INFORMATION)
    {
        granted |= THREAD_SET_LIMITED_INFORMATION;
    }
    return granted;
}

OBJECT_TYPE PspThreadType = {
    .name = "Thread",
    .validAccess = THREAD_ALL_ACCESS,
    .waitable = TRUE,
    .deleteProcedure = PspDeleteThread,
    .mapAccess = PspMapThreadAccess,
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
    /* A new thread INHERITS its process's boost-disable, exactly as the
     * oracle's server does it (third_party/wine server/thread.c
     * create_thread: `thread->disable_boost = process->disable_boost;`).
     * After that the two are independent — see PspSetProcessPriorityBoost
     * in kernel/ps/query.c for why this is a copy and not a lookup. */
    thread->priorityBoostDisabled = process->priorityBoostDisabled;

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
 * main-thread stack shape in process.c but standalone.
 *
 * `limitHigh` is NtCreateThreadEx's ZeroBits ceiling, inclusive of the
 * reservation's last byte (0 = unconstrained). It bounds the RESERVATION and
 * nothing else, which is the oracle's arrangement: `init_thread_stack` passes
 * `get_zero_bits_limit( zero_bits )` to `virtual_alloc_thread_stack`'s
 * `map_view` and the TEB allocation beside it is unconstrained
 * (third_party/wine dlls/ntdll/unix/thread.c, unix/virtual.c). */
static NTSTATUS PspAllocateThreadStack(PEPROCESS process, uint64_t reserve, uint64_t commit,
                                       uint64_t limitHigh, uint64_t *allocBaseOut,
                                       uint64_t *stackTopOut, uint64_t *stackLimitOut)
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
    /* The constrained form even when limitHigh is 0: it IS the classic form's
     * engine, and the zero means unconstrained (mm/virtual.h). */
    NTSTATUS status = MiAllocateVirtualMemoryEx(space, &base, &size, MEM_RESERVE, PAGE_READWRITE, 0,
                                                limitHigh, 0, 0);
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
    /* No caller named a size — this thread is the kernel's — so the geometry
     * is the image's, through the one rule (PspResolveStackGeometry). That is
     * what the layer this injection replaces does: ntdll's own int_handler
     * reaches NtCreateThreadEx with a zero reserve and a zero commit. */
    uint64_t reserve = 0, commit = 0;
    PspResolveStackGeometry(process->imageInformation.MaximumStackSize,
                            process->imageInformation.CommittedStackSize, 0, 0, &reserve, &commit);
    uint64_t allocBase = 0, stackTop = 0, stackLimit = 0;
    NTSTATUS status =
        PspAllocateThreadStack(process, reserve, commit, 0, &allocBase, &stackTop, &stackLimit);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    uint64_t tebBase = 0;
    /* Ids come from the shared Ps id source: NT's client ids are GLOBALLY
     * unique (one CID table for pids and tids), and the global alert-by-tid
     * lookup depends on it (ntdll:sync test_tid_alert). */
    uint64_t threadId = PspAllocateProcessId();
    status = PspBuildTeb(process, allocBase, stackTop, stackLimit, process->uniqueProcessId,
                         threadId, &tebBase);
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
    /* Stack geometry through the one rule (PspResolveStackGeometry, whose
     * contract in ps.h quotes the oracle's body): a 0 size is the IMAGE's
     * declared size — not a number this kernel picked — the reserve is the
     * larger of the two, and the whole thing is floored at 1 MiB.
     *
     * The image's sizes are the TARGET process's, which is also what the
     * oracle uses: a create for another process is forwarded as an APC and
     * runs inside that process, where `main_image_info` is its image
     * (dlls/ntdll/unix/thread.c NtCreateThreadEx's remote arm).
     *
     * Pinned by tests/ntapi/sem_ps/thread_stack_default.c. The reserve was
     * hardwired at 1 MiB, which cost ntdll:virtual:1050/:1068 and, more than
     * that, silently discarded the one number an image gets to state about
     * its threads. */
    uint64_t reserve = 0, commit = 0;
    PspResolveStackGeometry(process->imageInformation.MaximumStackSize,
                            process->imageInformation.CommittedStackSize, options->stackReserve,
                            options->stackCommit, &reserve, &commit);
    reserve = (reserve + MI_ALLOCATION_GRANULARITY - 1) & ~(MI_ALLOCATION_GRANULARITY - 1);
    uint64_t allocBase = 0, stackTop = 0, stackLimit = 0;
    NTSTATUS status = PspAllocateThreadStack(process, reserve, commit, options->stackLimitHigh,
                                             &allocBase, &stackTop, &stackLimit);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    uint64_t tebBase = 0;
    /* Ids come from the shared Ps id source: NT's client ids are GLOBALLY
     * unique (one CID table for pids and tids), and the global alert-by-tid
     * lookup depends on it (ntdll:sync test_tid_alert). */
    uint64_t threadId = PspAllocateProcessId();
    status = PspBuildTeb(process, allocBase, stackTop, stackLimit, process->uniqueProcessId,
                         threadId, &tebBase);
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
    /* Set before the thread is readied, so nothing can observe it clear on a
     * thread that was created hidden. */
    thread->hideFromDebugger = options->hideFromDebugger;
    thread->bypassProcessFreeze = options->bypassProcessFreeze;

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
    /* ZeroBits is the new stack's placement CEILING, and its invalid band is
     * NOT NtAllocateVirtualMemory's — this entry point has ONE band where the
     * allocation path has two. The oracle's whole x86-64 validation is a
     * single line (third_party/wine dlls/ntdll/unix/thread.c
     * NtCreateThreadEx); the `zero_bits >= 32` refusal beside it is inside
     * `#ifndef _WIN64`, and the allocation path's second band
     * (`> 32 && < granularity_mask`, unix/virtual.c) has no counterpart here.
     * So 33 is STATUS_INVALID_PARAMETER_3 through
     * NtSetInformationProcess(ProcessThreadStackAllocation) — which really is
     * implemented by calling NtAllocateVirtualMemory, hence
     * MiZeroBitsPlacementLimit in ps/query.c — and here it is a legal MASK
     * naming a 63-byte ceiling that no stack fits under, i.e.
     * STATUS_NO_MEMORY. Reusing MiZeroBitsPlacementLimit would answer the
     * wrong status for every value in that band; MiZeroBitsLimit, the
     * count-or-mask resolution both ladders share, is the part that IS one
     * authority (Art. 11). Pinned by tests/ntapi/sem_ps/thread_zero_bits.c.
     *
     * The check sits ABOVE the process-handle resolution because the oracle's
     * does: its two lines precede `if (process != NtCurrentProcess())`, so a
     * bad ZeroBits is reported for a handle that names nothing. */
    if (zeroBits > 21 && zeroBits < 32)
    {
        return STATUS_INVALID_PARAMETER_3;
    }

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
    options.stackLimitHigh = MiZeroBitsLimit(zeroBits);
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
    /* HIDE_FROM_DEBUGGER is legal HERE and illegal on the process-creating
     * entry point — see NtCreateUserProcess, which refuses it. The
     * asymmetry is the oracle's (dlls/ntdll/unix/thread.c lists it in
     * NtCreateThreadEx's supported_flags; dlls/ntdll/unix/process.c returns
     * STATUS_INVALID_PARAMETER for it) and ntdll:thread asserts both halves
     * ten lines apart (thread.c:122 and :153). */
    options.hideFromDebugger = (createFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER) != 0;
    /* BYPASS_PROCESS_FREEZE is a create-time property of the THREAD, read by
     * the process-level suspend/resume fanout (PspSuspendResumeProcess).
     * Wine lists it in NtCreateThreadEx's supported_flags
     * (dlls/ntdll/unix/thread.c) and its own PsCreateSystemThread passes
     * nothing else — a frozen process must still be able to answer. */
    options.bypassProcessFreeze = (createFlags & THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE) != 0;
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

    /* A NULL routine is the server's APC_NONE, not an error: the pinned
     * tree omits the call data entirely when `func` is NULL
     * (dlls/ntdll/unix/thread.c NtQueueApcThreadEx2), and the server then
     * takes the request, finds no queue for that type, and returns success
     * having stored nothing (server/thread.c queue_apc + get_apc_queue).
     * Passing 0 through to Ke keeps the ONE acceptance rule — the
     * terminated-target test — in the one place that owns it, instead of
     * spelling it a second time here. */
    PKAPC apc = 0;
    if (apcRoutine != 0)
    {
        apc = MiAllocatePool(sizeof(KAPC));
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
    }

    /* A terminated target refuses. The server says so — queue_apc returns 0
     * and DECL_HANDLER(queue_apc) turns that into STATUS_UNSUCCESSFUL — and
     * kernel32:sync reads it back through both entry points
     * (sync.c:3040/:3042 on the status, :3048/:3049 on the
     * ERROR_GEN_FAILURE kernelbase maps it to). */
    BOOLEAN queued = KiInsertQueueUserApc(target, apc);

    if (threadObject != 0)
    {
        ObDereferenceObject(threadObject);
    }
    return queued ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
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
    /* A TERMINATED thread cannot be suspended, and the status is
     * STATUS_ACCESS_DENIED rather than anything about the thread's state —
     * the oracle's server says so in one line (third_party/wine
     * server/thread.c suspend_thread handler: `if (thread->state ==
     * TERMINATED) set_error( STATUS_ACCESS_DENIED );`). kernel32:thread
     * depends on it: after joining a thread it asserts SuspendThread
     * returns -1, and proskrnl was handing back a live count for a thread
     * that had already exited. Checked under the dispatcher lock with the
     * count read, because "has exited" and "what the count is" must be one
     * observation — the signal state IS the exit fact here, as
     * ThreadBasicInformation already reads it. */
    if (thread->header.signalState != 0)
    {
        KiReleaseDispatcherLock(flags);
        ObDereferenceObject(thread);
        return STATUS_ACCESS_DENIED;
    }
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

/* The access check a class owes even when it needs no thread STATE. The
 * pseudo-handle is the caller's own thread and always passes, as every
 * resolution in this file treats it. */
static NTSTATUS PspCheckThreadAccess(HANDLE threadHandle, ACCESS_MASK access)
{
    if (threadHandle == 0 || threadHandle == NtCurrentThread())
    {
        return STATUS_SUCCESS;
    }
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(threadHandle, access, &PspThreadType,
                                                ExGetPreviousMode(), &body, 0);
    if (NT_SUCCESS(status))
    {
        ObDereferenceObject(body);
    }
    return status;
}

/* NtSetInformationThread(ThreadZeroTlsCell): clear one TLS slot in EVERY
 * thread of `process`. A caller frees a TLS index once (TlsFree) and none of
 * its threads may keep a stale value behind it — the per-thread sweep is the
 * whole content of the class, and the reason it cannot be an accept-and-drop
 * stub.
 *
 * The two bounds come from the layouts themselves rather than from typed
 * numbers: the direct slots are the TEB's own TlsSlots[] and the expansion
 * range is as wide as the PEB's TlsExpansionBitmap has bits, which is how
 * the oracle expresses the same check (dlls/ntdll/unix/virtual.c
 * virtual_clear_tls_index: `index < TLS_MINIMUM_AVAILABLE` then
 * `index >= 8 * sizeof(peb->TlsExpansionBitmapBits)`).
 *
 * The TEBs are reached through the address space rather than dereferenced,
 * for the same reason PspBuildTeb writes them that way: a sibling thread's
 * TEB is a user VA, and a caller that has unmapped one must not fault the
 * kernel. The checked copies simply skip such a thread. */
static NTSTATUS PspZeroTlsCell(PEPROCESS process, ULONG index)
{
    const ULONG directSlots = (ULONG)(sizeof(((TEB *)0)->TlsSlots) / sizeof(PVOID));
    const ULONG expansionSlots = (ULONG)(8 * sizeof(((PEB *)0)->TlsExpansionBitmapBits));
    ULONG expansionIndex = 0;
    BOOLEAN expansion = FALSE;

    if (index >= directSlots)
    {
        expansionIndex = index - directSlots;
        if (expansionIndex >= expansionSlots)
        {
            return STATUS_INVALID_PARAMETER;
        }
        expansion = TRUE;
    }

    PVOID zero = 0;
    PMI_ADDRESS_SPACE space = &process->addressSpace;
    for (PLIST_ENTRY entry = process->threadListHead.Flink; entry != &process->threadListHead;
         entry = entry->Flink)
    {
        PETHREAD thread = CONTAINING_RECORD(entry, ETHREAD, threadListEntry);
        if (thread->tebBase == 0)
        {
            continue;
        }
        if (!expansion)
        {
            MiCopyToUserRangeChecked(
                space, thread->tebBase + offsetof(TEB, TlsSlots) + (uint64_t)index * sizeof(PVOID),
                &zero, sizeof(zero));
            continue;
        }
        /* The expansion table is a separate user allocation the TEB points
         * at, and a thread that has never grown past the direct slots does
         * not have one. */
        PVOID *table = 0;
        if (MiCopyFromUserRange(space, &table, thread->tebBase + offsetof(TEB, TlsExpansionSlots),
                                sizeof(table)) != sizeof(table) ||
            table == 0)
        {
            continue;
        }
        MiCopyToUserRangeChecked(
            space, (uint64_t)(uintptr_t)table + (uint64_t)expansionIndex * sizeof(PVOID), &zero,
            sizeof(zero));
    }
    return STATUS_SUCCESS;
}

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
            status = ObReferenceObjectByHandle(threadHandle, THREAD_QUERY_LIMITED_INFORMATION,
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
        /* BasePriority is SetThreadPriority's value read back — kernelbase's
         * GetThreadPriority returns exactly this field. It is NOT the
         * scheduler's priority, and conflating the two made every
         * Set/Get round-trip fail (kernel32:thread thread.c:697, :717,
         * :719). */
        info.BasePriority = target != 0 ? target->basePriority : 0;
        /* kernel32's SetThreadAffinityMask RETURNS this field as the
         * previous mask (dlls/kernel32/thread.c), so leaving it zero made
         * every call read as a failure — thread.c:909 "SetThreadAffinityMask
         * failed" with nothing else wrong. One CPU, one bit, from the
         * KE_NUMBER_PROCESSORS authority. */
        info.AffinityMask = ((ULONG_PTR)1 << KE_NUMBER_PROCESSORS) - 1;
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
            status = ObReferenceObjectByHandle(threadHandle, THREAD_QUERY_LIMITED_INFORMATION,
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
    case ThreadWow64Context:
    {
        /* The guest CONTEXT of a WOW64 thread, read out of the CPU area on
         * its 64-bit stack (kernel/ps/wow64.c builds it there;
         * RtlWow64GetCpuAreaInfo is ntdll's view of the same bytes).
         *
         * This is the first thing wow64cpu asks for — BTCpuProcessInit
         * calls RtlWow64GetThreadContext to learn the guest's CS and SS
         * (dlls/wow64cpu/cpu.c), so a WOW64 process cannot start without
         * it. A non-WOW64 target has no CPU area and must FAIL: ntdll's
         * RtlWow64GetThreadSelectorEntry keys its hardcoded-selector
         * fallback on exactly that failure (dlls/ntdll/process.c). Pinned
         * by sem_ps/wow64_thread_context. */
        if (length != sizeof(I386_CONTEXT))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(I386_CONTEXT), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        PETHREAD target = self;
        BOOLEAN referenced = FALSE;
        if (threadHandle != 0 && threadHandle != NtCurrentThread())
        {
            PVOID body;
            status = ObReferenceObjectByHandle(threadHandle, THREAD_GET_CONTEXT, &PspThreadType,
                                               ExGetPreviousMode(), &body, 0);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            target = body;
            referenced = TRUE;
        }
        uint64_t cpuArea = 0;
        status = PspWow64ThreadCpuArea(target, &cpuArea);
        if (NT_SUCCESS(status))
        {
            /* The caller's ContextFlags select what it wants; the CPU area
             * carries a full context, so honouring them is a copy of the
             * whole struct with the flags word the caller asked for left
             * in place (the same shape KiTrapFrameToContext takes). */
            I386_CONTEXT context;
            ULONG wanted;
            status = KiCopyFromUser(&wanted, buffer, sizeof(wanted));
            if (NT_SUCCESS(status))
            {
                status = MiCopyFromUserRange(&target->process->addressSpace, &context,
                                             cpuArea + sizeof(WOW64_CPURESERVED),
                                             sizeof(context)) == sizeof(context)
                             ? STATUS_SUCCESS
                             : STATUS_ACCESS_VIOLATION;
            }
            if (NT_SUCCESS(status))
            {
                context.ContextFlags = wanted;
                memcpy(buffer, &context, sizeof(context));
                /* No return length, deliberately: the oracle leaves it
                 * untouched for this class and sem_ps/wow64_thread_context
                 * pins that, so writing one is a divergence, not a
                 * courtesy. */
            }
        }
        if (referenced)
        {
            ObDereferenceObject(target);
        }
        return status;
    }
    case ThreadDescriptorTableEntry:
    {
        /* The sweep asks with a ZEROED descriptor, and the oracle rejects
         * that before ever reaching an LDT (dlls/ntdll/unix/signal_x86_64.c
         * get_thread_ldt_entry): a selector above 16 bits is
         * STATUS_UNSUCCESSFUL, and so is one naming the GDT —
         * `is_gdt_sel(sel)` is `!(sel & 4)`, the table-indicator bit
         * (unix_private.h; Intel SDM Vol. 3 §3.4.2 segment selector). A
         * zero selector names the GDT, so the reachable answer is
         * STATUS_UNSUCCESSFUL. Pinned by
         * tests/ntapi/sem_ps/thread_info_sweep.c.
         *
         * An LDT selector answers the same way, which sem_ps/ldt.c measured
         * rather than assumed: a 64-bit thread has no LDT for the lookup to
         * reach, so the oracle never gets as far as STATUS_NO_LDT and
         * refuses the whole 0x00..0xff range identically. ntdll:wow64's
         * test_selectors sweeps exactly that range through
         * RtlWow64GetThreadSelectorEntry, which asks here first and
         * synthesizes a descriptor PE-side on refusal — so the refusal IS
         * the contract, and the pre-WOW64 STATUS_NOT_IMPLEMENTED on the LDT
         * half was fatal the moment the sweep walked past selector 3. */
        if (length != sizeof(THREAD_DESCRIPTOR_INFORMATION))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status =
            KiProbeForRead(buffer, sizeof(THREAD_DESCRIPTOR_INFORMATION), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        NTSTATUS access = PspCheckThreadAccess(threadHandle, THREAD_QUERY_INFORMATION);
        if (!NT_SUCCESS(access))
        {
            return access;
        }
        /* An LDT selector may name a real entry, once the process has set
         * one (kernel/ps/ldt.c; a 64-bit thread of a process that never
         * called NtSetLdtEntries has no LDT, which is the uniform refusal
         * sem_ps/ldt.c pins). Read back byte-exact — the caller memcmps
         * what it wrote.
         *
         * The LDT belongs to the process of the thread the HANDLE names,
         * not to the caller's: this class takes a thread handle, and the
         * oracle resolves it the same way (get_thread_ldt_entry hands
         * ldt_get_entry the TARGET's ClientId, dlls/ntdll/unix/
         * signal_x86_64.c). Reading the caller's table instead would answer
         * a cross-thread query with the wrong process's descriptors. */
        PETHREAD target = self;
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
            referenced = TRUE;
        }
        THREAD_DESCRIPTOR_INFORMATION descriptor;
        memcpy(&descriptor, buffer, sizeof(descriptor));
        BOOLEAN found = (descriptor.Selector >> 16) == 0 && (descriptor.Selector & 4) != 0 &&
                        target != 0 &&
                        PspQueryLdtEntry(target->process, descriptor.Selector, &descriptor.Entry);
        if (referenced)
        {
            ObDereferenceObject(target);
        }
        if (found)
        {
            status = KiProbeForWrite(buffer, sizeof(descriptor), sizeof(ULONG));
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            memcpy(buffer, &descriptor, sizeof(descriptor));
            if (returnLength != 0)
            {
                *returnLength = sizeof(descriptor.Entry);
            }
            return STATUS_SUCCESS;
        }
        return STATUS_UNSUCCESSFUL;
    }
    case ThreadNameInformation:
    {
        /* The oracle's shape (dlls/ntdll/unix/thread.c): the struct is
         * followed IN THE CALLER'S BUFFER by the characters, and
         * ThreadName.Buffer points just past the struct. *ret_len is the
         * whole thing — struct plus name bytes — on success AND on the
         * short-buffer path, so a caller can size its second call. A NULL
         * info is STATUS_BUFFER_TOO_SMALL here, not an access violation.
         * Pinned by tests/ntapi/sem_ps/thread_info_sweep.c. */
        PETHREAD target = self;
        BOOLEAN referenced = FALSE;
        if (threadHandle != 0 && threadHandle != NtCurrentThread())
        {
            PVOID body;
            NTSTATUS refStatus =
                ObReferenceObjectByHandle(threadHandle, THREAD_QUERY_LIMITED_INFORMATION,
                                          &PspThreadType, ExGetPreviousMode(), &body, 0);
            if (!NT_SUCCESS(refStatus))
            {
                return refStatus;
            }
            target = body;
            referenced = TRUE;
        }
        USHORT nameBytes = target != 0 ? target->threadName.Length : 0;
        ULONG needed = (ULONG)sizeof(THREAD_NAME_INFORMATION) + nameBytes;
        NTSTATUS status = STATUS_SUCCESS;
        if (buffer == 0 || length < needed)
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        else
        {
            status = KiProbeForWrite(buffer, needed, sizeof(void *));
            if (NT_SUCCESS(status))
            {
                THREAD_NAME_INFORMATION info;
                WCHAR *namePtr = (WCHAR *)((UCHAR *)buffer + sizeof(THREAD_NAME_INFORMATION));
                info.ThreadName.Length = nameBytes;
                info.ThreadName.MaximumLength = nameBytes;
                info.ThreadName.Buffer = namePtr;
                memcpy(buffer, &info, sizeof(info));
                if (nameBytes != 0)
                {
                    memcpy(namePtr, target->threadName.Buffer, nameBytes);
                }
            }
        }
        if (referenced)
        {
            ObDereferenceObject(target);
        }
        if (returnLength != 0 && (status == STATUS_SUCCESS || status == STATUS_BUFFER_TOO_SMALL))
        {
            *returnLength = needed;
        }
        return status;
    }
    case ThreadGroupInformation:
    {
        /* The processor-GROUP form of the affinity mask. Group 0 always,
         * because a group holds at most 64 processors and this machine has
         * one (Art. 3) — the oracle hardcodes group 0 for the same reason
         * ("Wine only supports max 64 processors",
         * dlls/ntdll/unix/thread.c). Same KE_NUMBER_PROCESSORS authority as
         * ThreadAffinityMask below, truncating on a short buffer as that
         * class does, and the same access rule: the limited right does not
         * reach here. */
        NTSTATUS access = PspCheckThreadAccess(threadHandle, THREAD_QUERY_INFORMATION);
        if (!NT_SUCCESS(access))
        {
            return access;
        }
        GROUP_AFFINITY affinity;
        memset(&affinity, 0, sizeof(affinity));
        affinity.Group = 0;
        affinity.Mask = ((KAFFINITY)1 << KE_NUMBER_PROCESSORS) - 1;
        ULONG copy = length < sizeof(affinity) ? length : (ULONG)sizeof(affinity);
        NTSTATUS status = KiProbeForWrite(buffer, copy, 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        memcpy(buffer, &affinity, copy);
        if (returnLength != 0)
        {
            *returnLength = copy;
        }
        return STATUS_SUCCESS;
    }
    case ThreadAffinityMask:
    {
        /* One CPU, so one bit — and Art. 3's uniprocessor mandate is what
         * makes that the TRUTH here rather than a placeholder for a richer
         * answer. KE_NUMBER_PROCESSORS is the one authority for the count
         * (Art. 11); when the mandate is lifted (docs/18 §13) this follows
         * it without being rewritten.
         *
         * Truncates rather than refusing a short buffer, as the oracle does
         * (`min(length, sizeof(affinity))`, no length gate —
         * dlls/ntdll/unix/thread.c). Pinned by
         * tests/ntapi/sem_ps/thread_info_sweep.c. */
        /* The value needs no thread, but the ACCESS CHECK is still owed:
         * kernel32:thread queries through a
         * THREAD_QUERY_LIMITED_INFORMATION handle and expects this class
         * to be REFUSED, so a class that answers without validating the
         * handle answers a caller that was never entitled to ask. */
        NTSTATUS access = PspCheckThreadAccess(threadHandle, THREAD_QUERY_INFORMATION);
        if (!NT_SUCCESS(access))
        {
            return access;
        }
        ULONG_PTR affinity = ((ULONG_PTR)1 << KE_NUMBER_PROCESSORS) - 1;
        ULONG copy = length < sizeof(affinity) ? length : (ULONG)sizeof(affinity);
        NTSTATUS status = KiProbeForWrite(buffer, copy, 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        memcpy(buffer, &affinity, copy);
        if (returnLength != 0)
        {
            *returnLength = copy;
        }
        return STATUS_SUCCESS;
    }
    case ThreadHideFromDebugger:
    {
        /* PspProbeReturnLength above already ran, which is exactly the
         * ordering the oracle documents for this class: "TP Shell Service
         * depends on ThreadHideFromDebugger returning
         * STATUS_ACCESS_VIOLATION if *ret_len is not writable, before any
         * other checks" (dlls/ntdll/unix/thread.c). An unwritable ret_len
         * therefore beats a wrong length here, and the pin asserts that. */
        if (length != sizeof(BOOLEAN))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(BOOLEAN), 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        /* The pseudo-handle (or an unwired 0) means the caller, exactly as
         * ThreadBasicInformation above resolves it — one idiom, one place. */
        PETHREAD target = self;
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
            referenced = TRUE;
        }
        BOOLEAN hidden = target != 0 ? target->hideFromDebugger : FALSE;
        if (referenced)
        {
            ObDereferenceObject(target);
        }
        memcpy(buffer, &hidden, sizeof(hidden));
        if (returnLength != 0)
        {
            *returnLength = sizeof(BOOLEAN);
        }
        return STATUS_SUCCESS;
    }
    case ThreadPriorityBoost:
    {
        /* The disable flag, stored and returned. proskrnl does no priority
         * boosting at all (docs/03 "Deliberate simplifications"), so
         * nothing acts on the value — but a query that ignored the set
         * would make the pair disagree with itself, which is the
         * silent-plausible answer G12 forbids. The oracle's shape: a
         * ULONG, exact length or STATUS_INFO_LENGTH_MISMATCH
         * (dlls/ntdll/unix/thread.c). */
        if (length != sizeof(ULONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(ULONG), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        PETHREAD target = self;
        BOOLEAN referenced = FALSE;
        if (threadHandle != 0 && threadHandle != NtCurrentThread())
        {
            PVOID body;
            status = ObReferenceObjectByHandle(threadHandle, THREAD_QUERY_LIMITED_INFORMATION,
                                               &PspThreadType, ExGetPreviousMode(), &body, 0);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            target = body;
            referenced = TRUE;
        }
        /* The THREAD's own flag, and only that. The process flag reaches a
         * thread by being COPIED into it when the process class is set and
         * when a thread is created (kernel/ps/query.c, PspCreateThread) —
         * so a later thread-level set overrides it and the process keeps
         * its own value. Reading the two together with an OR instead would
         * make the override impossible; that is exactly what
         * kernel32:thread thread.c:806-809 checks. */
        ULONG disableBoost = (target != 0 && target->priorityBoostDisabled) ? 1 : 0;
        if (referenced)
        {
            ObDereferenceObject(target);
        }
        memcpy(buffer, &disableBoost, sizeof(disableBoost));
        if (returnLength != 0)
        {
            *returnLength = sizeof(ULONG);
        }
        return STATUS_SUCCESS;
    }
    case ThreadIsIoPending:
    {
        /* FALSE, always — and that fixed answer is legitimate here for the
         * one reason Art. 12 allows: it is the PINNED ORACLE'S answer, not
         * a plausible value invented to get past a caller. The oracle is
         * itself a declared stub (dlls/ntdll/unix/thread.c: `FIXME(
         * "ThreadIsIoPending info class not supported yet" ); ... *(BOOL*)
         * data = FALSE;`), so matching it is reproducing the boundary
         * rather than fabricating one, and it is pinned like any other
         * implementation (tests/ntapi/sem_ps/thread_info_sweep.c).
         *
         * Note the shape: a NULL buffer is STATUS_ACCESS_DENIED here, not
         * the ACCESS_VIOLATION most classes give. That is the oracle's,
         * too, and it is exactly the sort of detail an implementation
         * written from the documentation would get wrong. */
        if (length != sizeof(BOOL))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        if (buffer == 0)
        {
            return STATUS_ACCESS_DENIED;
        }
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(BOOL), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        BOOL pending = FALSE;
        memcpy(buffer, &pending, sizeof(pending));
        if (returnLength != 0)
        {
            *returnLength = sizeof(BOOL);
        }
        return STATUS_SUCCESS;
    }
    case ThreadIdealProcessor:
    case ThreadEnableAlignmentFaultFixup:
        /* The ORACLE calls these invalid itself, in an explicit
         * `return STATUS_INVALID_INFO_CLASS;` arm kept separate from its
         * FIXME/NOT_IMPLEMENTED group (dlls/ntdll/unix/thread.c) — so the
         * split this kernel draws is the boundary's own, not ours, and
         * these are pinned normally rather than beyond_oracle. */
        return STATUS_INVALID_INFO_CLASS;
    case ThreadPriority:
    case ThreadBasePriority:
    case ThreadImpersonationToken:
    case ThreadEventPair_Reusable:
    case ThreadZeroTlsCell:
    case ThreadPerformanceCount:
    case ThreadSetTlsArrayAddress:
        /* Set-only and obsolete classes: queried, never queryable. The
         * oracle groups them into its `FIXME(...) return
         * STATUS_NOT_IMPLEMENTED` arm, and an oracle answering that is
         * unbuilt rather than authoritative (G12) — so this is a
         * beyond_oracle answer, pinned by
         * tests/ntapi/sem_ps/thread_info_sweep.c. INVALID_INFO_CLASS is
         * what a non-queryable class is, and kernel32:thread's sweep
         * accepts it by name. */
        return STATUS_INVALID_INFO_CLASS;
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
    case ThreadWow64Context:
    {
        /* The write half of the CPU area (RtlWow64SetThreadContext). Every
         * WOW64 thread starts through it: wow64.dll's thread_init seeds the
         * guest entry this way, and BTCpuSetContext is how the guest's
         * exception and APC returns land. Merged per ContextFlags GROUP,
         * not wholesale — a caller setting only CONTEXT_I386_CONTROL must
         * not zero the integer registers (set_thread_wow64_context,
         * dlls/ntdll/unix/signal_x86_64.c). */
        if (length != sizeof(I386_CONTEXT))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForRead(buffer, sizeof(I386_CONTEXT), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        I386_CONTEXT wanted;
        status = KiCopyFromUser(&wanted, buffer, sizeof(wanted));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        PETHREAD self = KeGetCurrentThread()->threadObject;
        PETHREAD target = self;
        BOOLEAN referenced = FALSE;
        if (threadHandle != 0 && threadHandle != NtCurrentThread())
        {
            PVOID body;
            status = ObReferenceObjectByHandle(threadHandle, THREAD_SET_CONTEXT, &PspThreadType,
                                               ExGetPreviousMode(), &body, 0);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            target = body;
            referenced = TRUE;
        }
        uint64_t cpuArea = 0;
        status = PspWow64ThreadCpuArea(target, &cpuArea);
        if (NT_SUCCESS(status))
        {
            uint64_t contextVa = cpuArea + sizeof(WOW64_CPURESERVED);
            I386_CONTEXT context;
            status = MiCopyFromUserRange(&target->process->addressSpace, &context, contextVa,
                                         sizeof(context)) == sizeof(context)
                         ? STATUS_SUCCESS
                         : STATUS_ACCESS_VIOLATION;
            if (NT_SUCCESS(status))
            {
                ULONG flags = wanted.ContextFlags;
                if ((flags & CONTEXT_I386_CONTROL) == CONTEXT_I386_CONTROL)
                {
                    context.Ebp = wanted.Ebp;
                    context.Eip = wanted.Eip;
                    context.SegCs = wanted.SegCs;
                    context.EFlags = wanted.EFlags;
                    context.Esp = wanted.Esp;
                    context.SegSs = wanted.SegSs;
                }
                if ((flags & CONTEXT_I386_INTEGER) == CONTEXT_I386_INTEGER)
                {
                    context.Eax = wanted.Eax;
                    context.Ebx = wanted.Ebx;
                    context.Ecx = wanted.Ecx;
                    context.Edx = wanted.Edx;
                    context.Esi = wanted.Esi;
                    context.Edi = wanted.Edi;
                }
                if ((flags & CONTEXT_I386_SEGMENTS) == CONTEXT_I386_SEGMENTS)
                {
                    context.SegDs = wanted.SegDs;
                    context.SegEs = wanted.SegEs;
                    context.SegFs = wanted.SegFs;
                    context.SegGs = wanted.SegGs;
                }
                if ((flags & CONTEXT_I386_FLOATING_POINT) == CONTEXT_I386_FLOATING_POINT)
                {
                    context.FloatSave = wanted.FloatSave;
                }
                if ((flags & CONTEXT_I386_DEBUG_REGISTERS) == CONTEXT_I386_DEBUG_REGISTERS)
                {
                    context.Dr0 = wanted.Dr0;
                    context.Dr1 = wanted.Dr1;
                    context.Dr2 = wanted.Dr2;
                    context.Dr3 = wanted.Dr3;
                    context.Dr6 = wanted.Dr6;
                    context.Dr7 = wanted.Dr7;
                }
                if ((flags & CONTEXT_I386_EXTENDED_REGISTERS) == CONTEXT_I386_EXTENDED_REGISTERS)
                {
                    memcpy(context.ExtendedRegisters, wanted.ExtendedRegisters,
                           sizeof(context.ExtendedRegisters));
                }
                /* The context is now the guest's whole state, so the
                 * "re-derive it from scratch" request the CPU area may be
                 * carrying is satisfied and must be cleared — otherwise
                 * wow64cpu resets the very state just written
                 * (WOW64_CPURESERVED_FLAG_RESET_STATE, dlls/wow64cpu). */
                context.ContextFlags = CONTEXT_I386_ALL;
                MiCopyToUserRange(&target->process->addressSpace, contextVa, &context,
                                  sizeof(context));
                WOW64_CPURESERVED reserved;
                if (MiCopyFromUserRange(&target->process->addressSpace, &reserved, cpuArea,
                                        sizeof(reserved)) == sizeof(reserved))
                {
                    reserved.Flags &= ~(USHORT)WOW64_CPURESERVED_FLAG_RESET_STATE;
                    MiCopyToUserRange(&target->process->addressSpace, cpuArea, &reserved,
                                      sizeof(reserved));
                }
            }
        }
        if (referenced)
        {
            ObDereferenceObject(target);
        }
        return status;
    }
    case ThreadZeroTlsCell:
    {
        /* This class used to share ThreadAffinityMask's body one line
         * below, and nothing in that body is about TLS: it applied an
         * 8-byte length rule and a processor-mask narrowing to a TLS INDEX.
         * The grouping was accidental and the result was a plausible status
         * computed from the wrong contract (Art. 12). It is not a dead
         * path — TlsFree issues this class on every call, with a DWORD
         * (third_party/wine dlls/kernelbase/thread.c), so the 8-byte rule
         * refused every real caller.
         *
         * The contract is the oracle's (dlls/ntdll/unix/thread.c, the first
         * case of NtSetInformationThread, and virtual_clear_tls_index in
         * dlls/ntdll/unix/virtual.c): the CURRENT thread only, a wrong
         * length is STATUS_INVALID_PARAMETER, and the slot is zeroed in
         * EVERY thread of the process — a caller frees a TLS index once and
         * expects no thread to keep a stale value behind it. Pinned by
         * tests/ntapi/sem_ps/zero_tls_cell.c. */
        if (threadHandle != 0 && threadHandle != NtCurrentThread())
        {
            /* Unbuilt on the oracle too, so there is nothing to copy and
             * no pin that could hold it: it refuses loudly (G12). */
            DbgPrint("NtSetInformationThread: ThreadZeroTlsCell on another thread\n");
            return STATUS_NOT_IMPLEMENTED;
        }
        if (length != sizeof(ULONG))
        {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = KiProbeForRead(buffer, sizeof(ULONG), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        ULONG index;
        memcpy(&index, buffer, sizeof(index));
        return PspZeroTlsCell(KeGetCurrentThread()->process, index);
    }
    case ThreadAffinityMask:
    {
        /* NARROWED to the system mask, not validated against it — that
         * distinction is the whole class. `SetThreadAffinityMask(t, -1)`
         * means "every processor", and the oracle implements it by ANDing
         * the request with the system mask and refusing only if nothing
         * survives (dlls/ntdll/unix/thread.c:
         * `req_aff = *(const ULONG_PTR *)data & affinity_mask;`
         * `if (!req_aff) return STATUS_INVALID_PARAMETER;`). A kernel that
         * rejected out-of-range bits instead would refuse the single most
         * common call, and one that accepted them unnarrowed would hand
         * back -1 as the previous mask — kernel32:thread sees that as
         * "Unexpected return value 4294967295" (thread.c:937).
         *
         * On one CPU the surviving mask is always 1, so nothing is stored;
         * the NARROWING and the refusal are the observable behaviour.
         * Length is STATUS_INVALID_PARAMETER here, not
         * INFO_LENGTH_MISMATCH — the oracle's choice, and different from
         * the query side's. */
        if (length != sizeof(ULONG_PTR))
        {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = KiProbeForRead(buffer, sizeof(ULONG_PTR), sizeof(ULONG_PTR));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        ULONG_PTR requested;
        memcpy(&requested, buffer, sizeof(requested));
        ULONG_PTR systemMask = ((ULONG_PTR)1 << KE_NUMBER_PROCESSORS) - 1;
        if ((requested & systemMask) == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        return PspCheckThreadAccess(threadHandle, THREAD_SET_INFORMATION);
    }
    case ThreadBasePriority:
    {
        /* STORED, not dropped — the seventh accept-and-drop stub this work
         * item has found. proskrnl runs one priority band that matters
         * (docs/03 "Deliberate simplifications"), so the value steers
         * nothing; but GetThreadPriority reads it straight back out of
         * ThreadBasicInformation.BasePriority, so dropping it made the
         * Set/Get pair disagree with itself.
         *
         * A wrong length is STATUS_INVALID_PARAMETER, not the
         * INFO_LENGTH_MISMATCH the QUERY side of this same class gives —
         * `if (length != sizeof(DWORD)) return STATUS_INVALID_PARAMETER;`
         * is the oracle's own line for this arm (dlls/ntdll/unix/thread.c).
         * It read INFO_LENGTH_MISMATCH here until the pin covered the case.
         */
        if (length != sizeof(LONG))
        {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = KiProbeForRead(buffer, sizeof(LONG), sizeof(LONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        LONG priority;
        memcpy(&priority, buffer, sizeof(priority));
        /* The oracle's range check, verbatim (server/thread.c
         * set_thread_base_priority): IDLE and TIME_CRITICAL are always
         * legal however far outside the band they sit, and everything else
         * must land in MIN..MAX. Without it SetThreadPriority SUCCEEDED on
         * a bad argument and never set an error at all — kernel32:thread
         * caught that by reading back its own 0xDEADBEEF poison from
         * GetLastError (thread.c:738-739).
         *
         * The realtime widening the oracle also has is deliberately not
         * reproduced: it keys off a process priority CLASS proskrnl does
         * not have, so there is no state here that could ever select it,
         * and inventing one would be a boundary entity NT-shaped for no
         * caller (Art. 2). */
        if (priority != THREAD_BASE_PRIORITY_IDLE && priority != THREAD_BASE_PRIORITY_LOWRT &&
            (priority < THREAD_BASE_PRIORITY_MIN || priority > THREAD_BASE_PRIORITY_MAX))
        {
            return STATUS_INVALID_PARAMETER;
        }
        PETHREAD target = KeGetCurrentThread()->threadObject;
        PVOID body = 0;
        if (threadHandle != 0 && threadHandle != NtCurrentThread())
        {
            status = ObReferenceObjectByHandle(threadHandle, THREAD_SET_INFORMATION, &PspThreadType,
                                               ExGetPreviousMode(), &body, 0);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            target = body;
        }
        if (target != 0)
        {
            target->basePriority = priority;
        }
        if (body != 0)
        {
            ObDereferenceObject(body);
        }
        return STATUS_SUCCESS;
    }
    /* Priority and ideal processor: one CPU, one priority band that
     * matters (docs/03 "Deliberate simplifications"). Accepted and not
     * stored, and unlike the classes above nothing reads them back — the
     * SET is the whole of their observable surface, so there is no pair to
     * disagree with itself. Kept as its OWN group: folding the refusing
     * class below into this list silently turned these three into
     * refusals, and kernel32:thread caught it as SetThreadIdealProcessor
     * returning ~0u (thread.c:937). */
    case ThreadIdealProcessor:
    {
        /* Accepted but RANGE-CHECKED, which is the whole of its observable
         * surface: nothing reads the value back, so the refusal is the only
         * thing a caller can detect — and kernel32:thread detects exactly
         * that (thread.c:955, SetThreadIdealProcessor(MAXIMUM_PROCESSORS+1)
         * must return ~0u with ERROR_INVALID_PARAMETER). The oracle is a
         * declared stub for the VALUE and still performs the check
         * (dlls/ntdll/unix/thread.c: `if (*number > MAXIMUM_PROCESSORS)
         * return STATUS_INVALID_PARAMETER;` then `FIXME(...)` then
         * success), so the bound is its bound, generated into abi/. */
        if (length != sizeof(ULONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForRead(buffer, sizeof(ULONG), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        ULONG number;
        memcpy(&number, buffer, sizeof(number));
        if (number > MAXIMUM_PROCESSORS)
        {
            return STATUS_INVALID_PARAMETER;
        }
        return STATUS_SUCCESS;
    }
    case ThreadPriority:
    {
        /* An ABSOLUTE priority LEVEL, not one of the THREAD_PRIORITY_*
         * deltas SetThreadPriority takes — the neighbouring
         * ThreadBasePriority class is the relative one. This arm used to be
         * a bare `return STATUS_SUCCESS` sharing a case label with
         * ThreadIdealProcessorEx: no length rule, no probe, no access
         * check, and success for a level NT refuses. It was never convicted
         * because its pin sat inside a beyond_oracle block that skipped it
         * on the one runner that implements it.
         *
         * The level goes nowhere — proskrnl runs one priority band that
         * matters (docs/03 "Deliberate simplifications") and the QUERY side
         * of this class is unbuilt on the oracle too, so there is no pair
         * to disagree with itself. The VALIDATION is therefore the whole
         * observable behaviour, and it has three distinct answers:
         *
         *   outside 1..HIGH_PRIORITY   STATUS_INVALID_PARAMETER
         *   >= LOW_REALTIME_PRIORITY   STATUS_PRIVILEGE_NOT_HELD
         *   otherwise                  STATUS_SUCCESS
         *
         * (wine server/thread.c set_thread_priority does exactly these two
         * comparisons in this order; the realtime one is a privilege
         * refusal because the process is not in the realtime class, and
         * proskrnl has no realtime class at all.) A wrong length is
         * STATUS_INVALID_PARAMETER here and STATUS_INFO_LENGTH_MISMATCH one
         * case label above — the asymmetry a shared body destroys. */
        if (length != sizeof(ULONG))
        {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = KiProbeForRead(buffer, sizeof(ULONG), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        ULONG level;
        memcpy(&level, buffer, sizeof(level));
        if (level < LOW_PRIORITY + 1 || level > HIGH_PRIORITY)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (level >= LOW_REALTIME_PRIORITY)
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }
        return PspCheckThreadAccess(threadHandle, THREAD_SET_INFORMATION);
    }
    case ThreadWineNativeThreadName:
        /* The fork's private class, and it names a thing this boundary does
         * not have. On the oracle it sets the underlying UNIX thread's name
         * (a second identity beside the NT one); on proskrnl the NT thread
         * IS the native thread, and its name was stored by the
         * ThreadNameInformation case below one line earlier in the very
         * same caller — RtlSetThreadName (third_party/wine
         * dlls/ntdll/thread.c) issues both back to back and discards this
         * one's status.
         *
         * So there is no second name to set, and STATUS_INVALID_INFO_CLASS
         * says exactly that. The alternative that must NOT be taken is a
         * bare STATUS_SUCCESS: nothing would observe the difference, which
         * is precisely what makes it the silent-plausible stub G12 forbids
         * — five classes in this file have already had to be rescued from
         * that shape. beyond_oracle, pinned by
         * tests/ntapi/sem_ps/thread_info_sweep.c: the oracle implements the
         * class for a host proskrnl does not have, so it cannot answer for
         * us here. */
        return STATUS_INVALID_INFO_CLASS;
    case ThreadNameInformation:
    {
        /* STORED, not dropped. This returned a bare success on the grounds
         * that ntdll keeps the name in the TEB — true only while the QUERY
         * side was unreachable; a set the query cannot see is the
         * silent-plausible stub G12 forbids.
         *
         * The oracle's refusals, each distinct
         * (dlls/ntdll/unix/thread.c): a wrong length is
         * STATUS_INFO_LENGTH_MISMATCH, a NULL info is
         * STATUS_ACCESS_VIOLATION, and so is a non-zero Length with a NULL
         * Buffer. */
        if (length != sizeof(THREAD_NAME_INFORMATION))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        if (buffer == 0)
        {
            return STATUS_ACCESS_VIOLATION;
        }
        NTSTATUS status = KiProbeForRead(buffer, sizeof(THREAD_NAME_INFORMATION), sizeof(void *));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        THREAD_NAME_INFORMATION info;
        memcpy(&info, buffer, sizeof(info));
        if (info.ThreadName.Length != 0 && info.ThreadName.Buffer == 0)
        {
            return STATUS_ACCESS_VIOLATION;
        }
        PWSTR copy = 0;
        if (info.ThreadName.Length != 0)
        {
            status = KiProbeForRead(info.ThreadName.Buffer, info.ThreadName.Length, sizeof(WCHAR));
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            copy = MiAllocatePool(info.ThreadName.Length);
            if (copy == 0)
            {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            memcpy(copy, info.ThreadName.Buffer, info.ThreadName.Length);
        }
        PETHREAD target = KeGetCurrentThread()->threadObject;
        PVOID body = 0;
        if (threadHandle != 0 && threadHandle != NtCurrentThread())
        {
            status = ObReferenceObjectByHandle(threadHandle, THREAD_SET_LIMITED_INFORMATION,
                                               &PspThreadType, ExGetPreviousMode(), &body, 0);
            if (!NT_SUCCESS(status))
            {
                if (copy != 0)
                {
                    MiFreePool(copy);
                }
                return status;
            }
            target = body;
        }
        if (target != 0)
        {
            /* Replace: the previous name's pool block is this thread's to
             * free, and PspDeleteThread frees whatever is left. */
            if (target->threadName.Buffer != 0)
            {
                MiFreePool(target->threadName.Buffer);
            }
            target->threadName.Buffer = copy;
            target->threadName.Length = info.ThreadName.Length;
            target->threadName.MaximumLength = info.ThreadName.Length;
            copy = 0;
        }
        if (body != 0)
        {
            ObDereferenceObject(body);
        }
        if (copy != 0)
        {
            MiFreePool(copy);
        }
        return STATUS_SUCCESS;
    }
    case ThreadPriorityBoost:
    {
        /* Stored, not dropped — the query above must be able to see it. */
        if (length != sizeof(ULONG))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForRead(buffer, sizeof(ULONG), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        ULONG disableBoost;
        memcpy(&disableBoost, buffer, sizeof(disableBoost));
        PETHREAD target = KeGetCurrentThread()->threadObject;
        if (threadHandle != 0 && threadHandle != NtCurrentThread())
        {
            PVOID body;
            status = ObReferenceObjectByHandle(threadHandle, THREAD_SET_INFORMATION, &PspThreadType,
                                               ExGetPreviousMode(), &body, 0);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            ((PETHREAD)body)->priorityBoostDisabled = disableBoost != 0;
            ObDereferenceObject(body);
            return STATUS_SUCCESS;
        }
        if (target != 0)
        {
            target->priorityBoostDisabled = disableBoost != 0;
        }
        return STATUS_SUCCESS;
    }
    case ThreadGroupInformation:
    {
        /* A validating setter, and every one of its refusals is the
         * oracle's (dlls/ntdll/unix/thread.c): a wrong length is
         * STATUS_INVALID_PARAMETER rather than INFO_LENGTH_MISMATCH, a
         * NULL buffer is STATUS_ACCESS_VIOLATION, any RESERVED field set
         * is INVALID_PARAMETER ("On Windows the request fails if the
         * reserved fields are set", per its own comment), a non-zero
         * Group is INVALID_PARAMETER, and so is a mask carrying bits
         * outside the system mask or no bits at all.
         *
         * The mask that survives all of that is the only one this machine
         * has, so nothing is stored — but the VALIDATION is the observable
         * behaviour here, and skipping it to "accept and move on" is the
         * silent-plausible stub G12 forbids. */
        if (length != sizeof(GROUP_AFFINITY))
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (buffer == 0)
        {
            return STATUS_ACCESS_VIOLATION;
        }
        NTSTATUS status = KiProbeForRead(buffer, sizeof(GROUP_AFFINITY), sizeof(ULONG_PTR));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        GROUP_AFFINITY requested;
        memcpy(&requested, buffer, sizeof(requested));
        if (requested.Reserved[0] != 0 || requested.Reserved[1] != 0 || requested.Reserved[2] != 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (requested.Group != 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        KAFFINITY systemMask = ((KAFFINITY)1 << KE_NUMBER_PROCESSORS) - 1;
        if (requested.Mask == 0 || (requested.Mask & ~systemMask) != 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        return PspCheckThreadAccess(threadHandle, THREAD_SET_INFORMATION);
    }
    case ThreadHideFromDebugger:
    {
        /* Zero length, no buffer (dlls/ntdll/unix/thread.c: `if (length)
         * return STATUS_INFO_LENGTH_MISMATCH;`). Set-only: NT has no
         * un-hide, so there is no value to carry. It used to sit in the
         * accept-and-drop group above, which is the silent-plausible stub
         * G12 forbids — the caller set a flag and the query could never see
         * it. Now it is stored. */
        if (length != 0)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        PETHREAD target = KeGetCurrentThread()->threadObject;
        if (threadHandle != 0 && threadHandle != NtCurrentThread())
        {
            PVOID body;
            NTSTATUS status =
                ObReferenceObjectByHandle(threadHandle, THREAD_SET_INFORMATION, &PspThreadType,
                                          ExGetPreviousMode(), &body, 0);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            ((PETHREAD)body)->hideFromDebugger = TRUE;
            ObDereferenceObject(body);
            return STATUS_SUCCESS;
        }
        if (target != 0)
        {
            target->hideFromDebugger = TRUE;
        }
        return STATUS_SUCCESS;
    }
    case ThreadManageWritesToExecutableMemory:
        /* The ARM64EC write-to-executable-memory contract, and on x86_64 the
         * whole of it is one refusal: the pinned oracle's arm is
         * `#ifdef __aarch64__ ... #else return STATUS_NOT_SUPPORTED; #endif`
         * (third_party/wine dlls/ntdll/unix/thread.c, case
         * ThreadManageWritesToExecutableMemory). So the length, the Version
         * and the mutually-exclusive flag are never looked at here — the
         * answer is about the MACHINE, not about the arguments — and nothing
         * captures the caller's buffer. Pinned by
         * tests/ntapi/sem_ps/manage_exec_writes.c, which measures exactly
         * that ordering. */
        return STATUS_NOT_SUPPORTED;
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
