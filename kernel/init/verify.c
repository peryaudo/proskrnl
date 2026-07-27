/* kernel/init/verify.c — the kernel-state consistency sweep ("fsck for the
 * executive", docs/08 verification tooling like ASSERT/KASAN/the trace ring).
 *
 * Art. 3 makes a global sweep nearly free: on a uniprocessor, no-preemption
 * kernel every thread that is not running sits at a blocking point, where all
 * executive state is contract-consistent (the same argument that lets Ob run
 * lockless — ob.h). So one walk under the dispatcher lock sees an atomic,
 * globally consistent snapshot: all processes → threads → handle tables →
 * objects → wait lists → ready queues → timers → namespace, with every
 * cross-department reference asserted.
 *
 * The value is in STANDING inconsistencies — a value owned in two places that
 * disagree, a live object without its lifetime pin, a parallel path that
 * skipped shared bookkeeping. Each department stays locally consistent, so no
 * path-local ASSERT fires; the bug surfaces milestones later in whatever
 * consumer first trips over it. Three shipped examples this sweep would have
 * caught the day they were introduced:
 *   - 4fc732c: the TEB's ClientId and the ETHREAD's uniqueThreadId were
 *     assigned from two allocator calls (split-brain id), and kernel-launched
 *     processes had no main-thread ETHREAD at all;
 *   - edf9f0b: a LIVE thread's ETHREAD carried no running pin, so closing its
 *     last handle freed the stack it was running on;
 *   - the pointerCount/handleCount recount below convicts any path that
 *     creates or destroys a handle without the shared Ob bookkeeping.
 *
 * The sweep only reads; a violated invariant is fatal via ASSERT ([ASSERT]
 * file:line + stack trace, Art. 9). It names a suspect — only a differential
 * test convicts (Art. 6). Runs at test boundaries (kernel/init/main.c) and
 * periodically from the idle loop. */
#include "kernel/init/verify.h"
#include "kernel/init/panic.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h"
#include "kernel/ps/ps.h"
#include "kernel/mm/phys.h"
#include "arch/x86_64/mmu.h"

#include "abi/ntpebteb.h"

uint64_t KiSweepCount;

/* --- one thread ------------------------------------------------------------ */

/* The TEB is the user-visible mirror of the kernel's thread identity: one id,
 * stamped once, owned by the ETHREAD (the 4fc732c contract). Read it through
 * the process page tables (no eviction — Art. 3 — so a committed TEB is
 * resident); a page user code decommitted is skipped, not asserted. */
static void KiVerifyThreadTeb(PEPROCESS process, PETHREAD thread)
{
    if (thread->tebBase == 0 || process == PsInitialSystemProcess)
    {
        return;
    }
    ASSERT((thread->tebBase & (PAGE_SIZE - 1)) == 0); /* Mm allocations are page-granular */
    int present = 0;
    uint64_t frame =
        MiTranslateUserPage(process->addressSpace.pml4Physical, thread->tebBase, 0, &present);
    if (frame == 0 || present == 0)
    {
        return;
    }
    const TEB *teb = MiPhysicalToVirtual(frame);
    ASSERT((uint64_t)(uintptr_t)teb->Tib.Self == thread->tebBase);
    ASSERT((uint64_t)(uintptr_t)teb->ClientId.UniqueThread == thread->uniqueThreadId);
    ASSERT((uint64_t)(uintptr_t)teb->ClientId.UniqueProcess == process->uniqueProcessId);
}

/* An ETHREAD on a process's thread list is LIVE: the KTHREAD has not
 * terminated, the ETHREAD is unsignalled (retire unlinks and signals under
 * one lock hold), and — the edf9f0b invariant — it carries the running pin,
 * so its references strictly exceed its handles. Both directions of the
 * ETHREAD<->KTHREAD identity are asserted (the 4fc732c split-brain class). */
static void KiVerifyThreadObject(PEPROCESS process, PETHREAD thread)
{
    POBJECT_HEADER header = ObpGetHeader(thread);
    ASSERT(header->type == &PspThreadType);
    ASSERT(thread->header.type == KI_OBJECT_THREAD);
    ASSERT(thread->header.signalState == 0);
    ASSERT(thread->process == process);
    /* Id shape per our own allocator (kernel/ps/thread.c PspAllocateProcessId
     * steps by 4) — an id that breaks it never came from the allocator. */
    ASSERT(thread->uniqueThreadId != 0 && (thread->uniqueThreadId & 3) == 0);
    ASSERT(header->pointerCount >= header->handleCount + 1); /* the running pin */

    PKTHREAD tcb = thread->tcb;
    ASSERT(tcb != 0);
    ASSERT(tcb->threadObject == thread);
    ASSERT(tcb->process == process);
    ASSERT(tcb->teb == (void *)(uintptr_t)thread->tebBase); /* one value, two owners */
    ASSERT(tcb->state != KI_THREAD_STATE_TERMINATED);

    KiVerifyThreadWaitState(tcb);
    ASSERT(thread->tidAlertEvent.header.type == KI_OBJECT_SYNCHRONIZATION_EVENT);
    KiVerifyWaitList(&thread->tidAlertEvent.header);
    KiVerifyWaitList(&thread->header);
    KiVerifyWaitList(&tcb->header);
    KiVerifyThreadTeb(process, thread);
}

/* --- one process ----------------------------------------------------------- */

/* The user-space deadlock detector (GUI-5). Art. 3 gives the sweep an
 * atomic snapshot, so this is one cheap read per thread: when EVERY thread
 * of a user process is parked in an UNTIMED wait on its own tid-alert
 * latch, the process can only be woken by NtAlertThreadByThreadId — and
 * ntdll's futex protocol (RtlWaitOnAddress, behind every SRW lock,
 * condition variable and critical-section slow path) only ever alerts
 * same-process tids. No thread of the process can run again to send that
 * alert, so the process is deadlocked in user-space locks the kernel
 * cannot name — msg.c's winefb ABBA sat exactly here for a 40-minute
 * harness timeout before the dump told the story. Two consecutive sweeps
 * with the same alert counters confirm the picture is standing (not a
 * mid-flight handoff); then the wedge dump fires once. A diagnostic, not
 * an ASSERT: a cross-process alert is theoretically expressible, so the
 * report is loud but the boot is allowed to continue to its timeout. */
static void KiDetectUserWedge(PEPROCESS process, LONG listedThreads)
{
    if (process->isSystemProcess || listedThreads == 0 ||
        process->activeThreadCount != listedThreads || process->wedgeReported)
    {
        return;
    }

    uint64_t sig = 0;
    for (PLIST_ENTRY entry = process->threadListHead.Flink; entry != &process->threadListHead;
         entry = entry->Flink)
    {
        PETHREAD thread = CONTAINING_RECORD(entry, ETHREAD, threadListEntry);
        PKTHREAD tcb = thread->tcb;
        PKWAIT_BLOCK block = tcb->waitBlockList;
        if (tcb->state != KI_THREAD_STATE_WAITING || tcb->timerArmed || block == 0 ||
            block->nextWaitBlock != 0 || block->object != &thread->tidAlertEvent)
        {
            process->wedgeSweeps = 0;
            return;
        }
        sig = sig * 1000003 + thread->uniqueThreadId * 31 + thread->tidAlertsIn;
    }

    if (process->wedgeSig != sig)
    {
        process->wedgeSig = sig;
        process->wedgeSweeps = 1;
        return;
    }
    if (++process->wedgeSweeps < 3)
    {
        return;
    }

    process->wedgeReported = TRUE;
    DbgPrint("[KTEST] wedge-detect pid=%lu image=%s: every thread parked on its own "
             "tid-alert latch, untimed, across %d sweeps — user-space deadlock\n",
             (unsigned long)process->uniqueProcessId, process->imageName ? process->imageName : "?",
             process->wedgeSweeps);
    PsDumpWedgedProcessLocked(process);
}

static void KiVerifyProcess(PEPROCESS process)
{
    POBJECT_HEADER header = ObpGetHeader(process);
    ASSERT(header->type == &PspProcessType);
    ASSERT(process->header.type == KI_OBJECT_PROCESS);
    ASSERT(process->header.signalState == 0 || process->header.signalState == 1);
    KiVerifyWaitList(&process->header);
    ObpVerifyHandleTable(&process->handleTable);

    LONG listedThreads = 0;
    for (PLIST_ENTRY entry = process->threadListHead.Flink; entry != &process->threadListHead;
         entry = entry->Flink)
    {
        KiVerifyThreadObject(process, CONTAINING_RECORD(entry, ETHREAD, threadListEntry));
        listedThreads++;
    }

    /* Count/list agreement. A wrapperless main thread (PspCreateUserProcess:
     * flat binaries and native PE clients carry no ETHREAD) is counted but
     * never listed, and its exit decrements the count one blocking point
     * (ObpCloseAllHandles) before KiTerminateThread re-states it — so while
     * such a main thread exists the count may sit one above the list. */
    if (process->mainThread != 0 && process->mainThread->state != KI_THREAD_STATE_TERMINATED)
    {
        ASSERT(process->activeThreadCount == listedThreads ||
               process->activeThreadCount == listedThreads + 1);
    }
    else
    {
        ASSERT(process->activeThreadCount == listedThreads);
    }

    /* Every listed thread pins its process (plus handles; parked ETHREADs and
     * creator references only push the count higher). */
    ASSERT(header->pointerCount >= header->handleCount + listedThreads);

    KiDetectUserWedge(process, listedThreads);
}

/* --- global client-id uniqueness ------------------------------------------- */

/* One CID space (PspAllocateProcessId serves pids AND tids): every id is
 * globally unique. Two ETHREADs sharing an id — or a thread reusing a
 * process's id — is exactly the split-brain state 4fc732c fixed. */
static void KiVerifyUniqueClientIds(void)
{
    for (PLIST_ENTRY pe = PspActiveProcessListHead.Flink; pe != &PspActiveProcessListHead;
         pe = pe->Flink)
    {
        PEPROCESS process = CONTAINING_RECORD(pe, EPROCESS, activeProcessLinks);
        for (PLIST_ENTRY qe = pe->Flink; qe != &PspActiveProcessListHead; qe = qe->Flink)
        {
            PEPROCESS other = CONTAINING_RECORD(qe, EPROCESS, activeProcessLinks);
            ASSERT(process->uniqueProcessId == 0 ||
                   process->uniqueProcessId != other->uniqueProcessId);
        }
        for (PLIST_ENTRY te = process->threadListHead.Flink; te != &process->threadListHead;
             te = te->Flink)
        {
            PETHREAD thread = CONTAINING_RECORD(te, ETHREAD, threadListEntry);
            /* Against every process id... */
            for (PLIST_ENTRY qe = PspActiveProcessListHead.Flink; qe != &PspActiveProcessListHead;
                 qe = qe->Flink)
            {
                PEPROCESS other = CONTAINING_RECORD(qe, EPROCESS, activeProcessLinks);
                ASSERT(thread->uniqueThreadId != other->uniqueProcessId);
            }
            /* ...and every thread id after this one, in list order. */
            for (PLIST_ENTRY ue = te->Flink; ue != &process->threadListHead; ue = ue->Flink)
            {
                PETHREAD later = CONTAINING_RECORD(ue, ETHREAD, threadListEntry);
                ASSERT(thread->uniqueThreadId != later->uniqueThreadId);
            }
            for (PLIST_ENTRY qe = pe->Flink; qe != &PspActiveProcessListHead; qe = qe->Flink)
            {
                PEPROCESS other = CONTAINING_RECORD(qe, EPROCESS, activeProcessLinks);
                for (PLIST_ENTRY ue = other->threadListHead.Flink; ue != &other->threadListHead;
                     ue = ue->Flink)
                {
                    PETHREAD later = CONTAINING_RECORD(ue, ETHREAD, threadListEntry);
                    ASSERT(thread->uniqueThreadId != later->uniqueThreadId);
                }
            }
        }
    }
}

/* --- global handle/reference bookkeeping ----------------------------------- */

/* Every handle table lives in an EPROCESS, and every EPROCESS is on the
 * active list from init to delete (process.c) — so the tables reachable here
 * are ALL of them, and an object's handleCount must equal the entries
 * pointing at it, table-wide. This is the check a parallel path that skips
 * the shared Ob engine cannot pass. */
static PVOID KiHandleObjectAt(PEPROCESS process, ULONG index)
{
    return ObpHandleTableObjectAt(&process->handleTable, index);
}

/* Was `body` already visited at an earlier (process, slot) position? Keeps
 * the recount once-per-object without any allocation (the sweep must not
 * touch the pool it is auditing). */
static BOOLEAN KiHandleSeenBefore(PEPROCESS limitProcess, ULONG limitIndex, PVOID body)
{
    for (PLIST_ENTRY entry = PspActiveProcessListHead.Flink;; entry = entry->Flink)
    {
        ASSERT(entry != &PspActiveProcessListHead); /* limitProcess must be on the list */
        PEPROCESS process = CONTAINING_RECORD(entry, EPROCESS, activeProcessLinks);
        ULONG stop = process == limitProcess ? limitIndex : process->handleTable.capacity;
        for (ULONG index = 0; index < stop; index++)
        {
            if (KiHandleObjectAt(process, index) == body)
            {
                return TRUE;
            }
        }
        if (process == limitProcess)
        {
            return FALSE;
        }
    }
}

static void KiVerifyGlobalHandleCounts(void)
{
    for (PLIST_ENTRY pe = PspActiveProcessListHead.Flink; pe != &PspActiveProcessListHead;
         pe = pe->Flink)
    {
        PEPROCESS process = CONTAINING_RECORD(pe, EPROCESS, activeProcessLinks);
        for (ULONG index = 0; index < process->handleTable.capacity; index++)
        {
            PVOID body = KiHandleObjectAt(process, index);
            if (body == 0 || KiHandleSeenBefore(process, index, body))
            {
                continue;
            }
            LONG total = 0;
            for (PLIST_ENTRY qe = PspActiveProcessListHead.Flink; qe != &PspActiveProcessListHead;
                 qe = qe->Flink)
            {
                PEPROCESS other = CONTAINING_RECORD(qe, EPROCESS, activeProcessLinks);
                for (ULONG j = 0; j < other->handleTable.capacity; j++)
                {
                    if (KiHandleObjectAt(other, j) == body)
                    {
                        total++;
                    }
                }
            }
            POBJECT_HEADER header = ObpGetHeader(body);
            ASSERT(header->handleCount == total);
            /* Handles + the name each hold a reference; transient refs only
             * push pointerCount higher. */
            ASSERT(header->pointerCount >=
                   header->handleCount + (header->parentDirectory != 0 ? 1 : 0));
        }
    }
}

/* --- the sweep -------------------------------------------------------------- */

void KiVerifyKernelState(void)
{
    uint64_t flags = KiAcquireDispatcherLock();

    KiVerifyScheduler();
    KiVerifyTimerList();
    for (PLIST_ENTRY entry = PspActiveProcessListHead.Flink; entry != &PspActiveProcessListHead;
         entry = entry->Flink)
    {
        KiVerifyProcess(CONTAINING_RECORD(entry, EPROCESS, activeProcessLinks));
    }
    KiVerifyUniqueClientIds();
    KiVerifyGlobalHandleCounts();
    PspVerifyReaperList();
    ObpVerifyNamespace();

    KiSweepCount++;
    KiReleaseDispatcherLock(flags);
}

void KiVerifyKernelStateIdle(void)
{
    /* Once a second of idle: cheap enough that a wedged-but-idle kernel keeps
     * auditing itself, throttled so the interrupts-off walk cannot distort
     * timer-driven tests (the sweep holds the dispatcher lock throughout). */
    static uint64_t KiLastIdleSweepTick;
    if (KeTickCount - KiLastIdleSweepTick < 1000)
    {
        return;
    }
    KiLastIdleSweepTick = KeTickCount;
    KiVerifyKernelState();
}
