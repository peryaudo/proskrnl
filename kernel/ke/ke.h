/* kernel/ke/ke.h — the Ke department: dispatcher objects, wait, threads (M2).
 *
 * The dispatcher shape is forced by NtWaitForMultipleObjects (docs/05): every
 * waitable object begins with a DISPATCHER_HEADER carrying a signal state and
 * a list of KWAIT_BLOCKs linking it to waiting threads. Struct shapes and all
 * Ke* signatures are taken from Wine's headers/exports (grep
 * third_party/wine/include/ddk/wdm.h and dlls/ntoskrnl.exe/sync.c — docs/15);
 * members follow this project's camelCase (docs/15), since none of these
 * layouts is user-observable (docs/03: internal layout entirely ours).
 *
 * Concurrency model (Constitution Art. 3): uniprocessor, ONE dispatcher lock
 * (= interrupt disable), no kernel preemption. Context switches happen only at
 * explicit waits/yields; the timer interrupt only readies threads. Alertable
 * waits are accepted but never alerted: APC queues arrive with M3/M4.
 */
#ifndef PROSKRNL_KERNEL_KE_KE_H
#define PROSKRNL_KERNEL_KE_KE_H

#include <stdint.h>

#include "abi/ntdef.h"
#include "abi/ntstatus.h"
#include "kernel/lib/list.h"
#include "arch/x86_64/trap.h"

/* --- Dispatcher object types (DISPATCHER_HEADER.type) ------------------- */
/* Values as Wine's ntoskrnl uses internally (dlls/ntoskrnl.exe/sync.c);
 * unobservable, but keeping them aligned costs nothing. */
#define KI_OBJECT_NOTIFICATION_EVENT    0
#define KI_OBJECT_SYNCHRONIZATION_EVENT 1
#define KI_OBJECT_MUTANT                2
#define KI_OBJECT_PROCESS               3 /* Wine assigns no value; 3 is a free internal tag */
#define KI_OBJECT_SEMAPHORE             5
#define KI_OBJECT_THREAD                6
#define KI_OBJECT_NOTIFICATION_TIMER    8
#define KI_OBJECT_SYNCHRONIZATION_TIMER 9

typedef struct
{
    UCHAR type;
    UCHAR absolute;
    UCHAR size;
    UCHAR inserted;
    LONG signalState;
    LIST_ENTRY waitListHead;
} DISPATCHER_HEADER, *PDISPATCHER_HEADER;

typedef struct
{
    DISPATCHER_HEADER header;
} KEVENT, *PKEVENT, *PRKEVENT;

typedef struct
{
    DISPATCHER_HEADER header;
    LONG limit;
} KSEMAPHORE, *PKSEMAPHORE, *PRKSEMAPHORE;

typedef struct KTHREAD KTHREAD, *PKTHREAD;

typedef struct
{
    DISPATCHER_HEADER header;
    LIST_ENTRY mutantListEntry; /* on the owner's mutantListHead */
    PKTHREAD ownerThread;
    BOOLEAN abandoned;
    UCHAR apcDisable;
} KMUTANT, *PKMUTANT, *PRKMUTANT, KMUTEX, *PKMUTEX, *PRKMUTEX;

/* DPCs are dropped by design (docs/03): the type stays opaque so KTIMER and
 * KeSetTimer* keep their NT shape, and a non-NULL KDPC pointer panics. */
typedef struct KDPC KDPC, *PKDPC;

typedef struct
{
    DISPATCHER_HEADER header;
    ULARGE_INTEGER dueTime; /* absolute interrupt time, 100 ns units */
    LIST_ENTRY timerListEntry;
    PKDPC dpc;
    LONG period; /* milliseconds; 0 = one-shot */
} KTIMER, *PKTIMER;

typedef struct KWAIT_BLOCK
{
    LIST_ENTRY waitListEntry; /* on the object's waitListHead */
    PKTHREAD thread;
    PVOID object; /* the DISPATCHER_HEADER waited on */
    struct KWAIT_BLOCK *nextWaitBlock;
    USHORT waitKey;  /* index in the wait array; STATUS_TIMEOUT for the timer */
    USHORT waitType; /* WAIT_TYPE; the timeout block is always WaitAny */
} KWAIT_BLOCK, *PKWAIT_BLOCK;

/* NOLINTBEGIN(readability-identifier-naming) — NT enumerators keep NT casing
 * (transcribed verbatim from third_party/wine/include/ddk/wdm.h). */
typedef enum
{
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    Spare2,
    Spare3,
    Spare4,
    Spare5,
    Spare6,
    WrKernel,
    MaximumWaitReason,
} KWAIT_REASON;
/* NOLINTEND(readability-identifier-naming) */

/* --- APCs (M7) ----------------------------------------------------------- */

/* A queued asynchronous procedure call. proskrnl needs only the USER-mode
 * APC (docs/05 "APC delivery timing" is the forced part): delivered to a
 * thread at an alertable wait / NtTestAlert, it runs KiUserApcDispatcher in
 * ring 3 with (normalRoutine, arg1, arg2, arg3). Kernel-mode APCs and the
 * special-kernel-APC machinery are NT internals nothing observes, so they
 * are not built. */
typedef struct KAPC
{
    LIST_ENTRY apcListEntry;  /* on the target thread's userApcListHead */
    uint64_t normalRoutine;   /* user PNTAPCFUNC */
    uint64_t normalContext;   /* arg1 */
    uint64_t systemArgument1; /* arg2 */
    uint64_t systemArgument2; /* arg3 */
} KAPC, *PKAPC;

/* --- Threads ------------------------------------------------------------- */

#define KI_THREAD_WAIT_OBJECTS 3 /* embedded wait blocks (NT: THREAD_WAIT_OBJECTS) */

#define KI_THREAD_STATE_INITIALIZED 0 /* created suspended, never readied */
#define KI_THREAD_STATE_READY       1
#define KI_THREAD_STATE_RUNNING     2
#define KI_THREAD_STATE_WAITING     3
#define KI_THREAD_STATE_TERMINATED  4

/* KPRIORITY 0..31, NT's range (Microsoft "Scheduling Priorities",
 * https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities). */
#define KI_PRIORITY_LEVELS 32

/* --- release obligations (issue #96 B) -----------------------------------
 *
 * docs/20 §10.2's worst row was a gate leaked by a ring-0 fault: the create
 * path carried a user pointer under the volume gate, the fault-recovery
 * unwind ran no cleanup (kernel/syscall/uaccess.h says so in prose), and the
 * volume wedged permanently and silently. A leaked gate is not a subtle
 * property — it is a counter that must be zero at the kernel's exits.
 *
 * So every thread carries a small stack of what it owes. It is asserted at
 * the normal syscall return AND — the part that matters — on the unwind path
 * in KiCallServiceGuarded, which turns that permanent silent wedge into a
 * panic naming the gate, at the first fault any test injects across it.
 *
 * Depth 8 is not a resource limit: obligations nest at most two deep today
 * (a sync-I/O span inside a file-object lock), and overflowing is itself a
 * bug worth panicking on. */
#define KI_MAX_OBLIGATIONS 8

typedef struct
{
    const char *name; /* "volume gate", "sync-io span", "transient handle" */
    void *object;     /* the gate/handle it was taken on, for the panic line */
} KI_OBLIGATION;

/* Internal layout is entirely ours (docs/03); only two shapes are pinned:
 * the DISPATCHER_HEADER must come first (threads are waitable, signalled at
 * termination like a notification object) and kernelStack's offset is welded
 * into arch/x86_64/ctxswitch.S. */
struct EPROCESS; /* kernel/ps/ps.h */

struct KTHREAD
{
    DISPATCHER_HEADER header;
    uint64_t kernelStack; /* saved RSP while off-CPU; ctxswitch.S offset 24 */
    /* M7: the thread's x87/SSE state, FXSAVE image layout (Intel SDM Vol. 1
     * "FXSAVE Area"). Saved/restored by KiSwapContext (ctxswitch.S offset 32)
     * because NT preserves the MS-ABI nonvolatile XMM6-15 across syscalls and
     * waits — kernel code never touches SSE (-mno-sse), but the NEXT user
     * thread does. 16-byte-aligned as fxsave64 requires (the pool returns
     * 16-aligned blocks and offset 32 keeps it). KiInitializeThreadFxArea
     * seeds the NT initial state. */
    __attribute__((aligned(16))) unsigned char fxArea[512];
    void *stackBase;
    int state;
    KPRIORITY priority;
    LIST_ENTRY readyListEntry;

    /* Suspend count (CUI-4: generalized to any state). A create-suspended
     * thread is born with 1; NtSuspend/ResumeThread and NtSuspend/Resume
     * Process stack/unstack it (PspSuspend/ResumeTcb). While nonzero the
     * suspendGate below is cleared; a thread that has already run parks on it
     * at its next return to user mode (KiProcessPendingUserSignals) — the
     * suspend point Art. 3's no-preemption model otherwise lacks. At zero the
     * gate opens; a never-run thread is readied then. */
    LONG suspendCount;
    KEVENT suspendGate; /* NotificationEvent: signalled == may run */

    /* CUI-4: a foreign NtTerminateProcess/Thread request. The initiator sets
     * these + wakes the target; the target reaps ITSELF at its next ring-3
     * edge through the ordinary PspExitCurrentThread path (never torn down
     * from another context — Art. 3). */
    BOOLEAN terminating;
    NTSTATUS terminateStatus;
    /* CUI-8 (docs/20 R1 fallout): TRUE only while this thread is parked in
     * KiAcquireEventGate's rundown leg — a terminating thread's rundown I/O
     * still needs the volume gate, and a real queued wait is the only
     * acquire the scheduler can guarantee liveness for (a try/yield loop
     * starves against a lower-priority holder). Exempts the wait from the
     * CUI-4 termination refusal and from KiAbortThreadWait; sound because a
     * gate hold is bounded (the holder's device waits complete by device
     * action), so the park cannot trap the dying thread indefinitely. */
    BOOLEAN rundownWait;

    /* M4: the owning process (never 0 once Ps is up — kernel threads belong
     * to PsInitialSystemProcess), the ring-crossing state the context switch
     * programs (stack top for TSS.RSP0/syscall entry, TEB for the user GS
     * base), and the mode the current kernel entry came from. */
    struct EPROCESS *process;
    uint64_t stackTop; /* kernel stack top; 0 only for the boot/idle thread */
    void *teb;         /* user-space TEB, 0 for kernel-only threads */
    KPROCESSOR_MODE previousMode;

    /* The armed ring-0 fault recovery frame (KI_FAULT_RECOVERY *, opaque
     * here — kernel/syscall/uaccess.h owns the shape). The system service
     * dispatcher arms one around every ring-3-originated service; a ring-0
     * fault on a user address unwinds to it with STATUS_ACCESS_VIOLATION
     * rather than halting the machine. 0 whenever no service is running. */
    void *faultRecovery;

    /* Who armed the frame, and whether an unwind through it is a deliberate
     * provocation rather than a defect report (issue #32 A3). The recovery
     * frame is a BACKSTOP for a missing or stale probe, so every unwind is a
     * bug until a test says otherwise — the name is what the [UACCESS] line
     * blames, and `expected` is the only thing that keeps a leg green. Set
     * and cleared by KiArmFaultRecovery/KiDisarmFaultRecovery, which are the
     * one authority for arming (uaccess.h). */
    const char *faultRecoveryName;
    BOOLEAN faultRecoveryExpected;

    /* wait machinery */
    NTSTATUS waitStatus;
    PKWAIT_BLOCK waitBlockList; /* chain via nextWaitBlock; 0 = pure delay */
    KWAIT_BLOCK waitBlocks[KI_THREAD_WAIT_OBJECTS];
    KWAIT_BLOCK timerWaitBlock;
    BOOLEAN timerArmed;
    KTIMER timer; /* the thread's timeout timer */

    LIST_ENTRY mutantListHead; /* mutants owned; abandoned at termination */

    /* M7: the current syscall/trap frame (entry.S publishes it), so the
     * user-mode return protocol — NtContinue, NtRaiseException,
     * NtGet/SetContextThread, APC/exception delivery — can rewrite the
     * outgoing ring-3 register context. 0 while not in a ring-3-originated
     * kernel entry. */
    PKTRAP_FRAME trapFrame;
    BOOLEAN userContextReplaced; /* a service rewrote trapFrame->rax itself */

    /* M7: user-APC delivery (docs/05 "APC mechanism / delivery timing").
     * Queued APCs run KiUserApcDispatcher in ring 3 at the next alertable
     * wait / NtTestAlert; `alerted` is a pending NtAlertThread. */
    LIST_ENTRY userApcListHead;
    BOOLEAN userApcPending;    /* queue non-empty */
    BOOLEAN apcDeliverPending; /* deliver one on the next ring-3 return */
    BOOLEAN alerted;           /* NtAlertThread */
    BOOLEAN waitAlertable;     /* the current wait is alertable */

    /* CUI-5 NtCancelSynchronousIoFile: the in-flight synchronous I/O this
     * thread is inside (kernel/io marks it around blocking device ops via
     * IopEnterSyncIo/IopLeaveSyncIo); the cancel event breaks the
     * cancellable parks (IoWaitCancellable — npfs's blocking waits). */
    void *syncIoUserIosb;    /* the op's user IOSB VA, the cancel filter key */
    BOOLEAN syncIoActive;    /* inside a cancellable synchronous op */
    BOOLEAN syncIoCancelled; /* a canceller marked this op */
    /* Did the current span ENTER the Io layer's cancellable wait? Set by
     * IoWaitCancellable on the way in — before the wait, so a wait that
     * returns at once still counts — and cleared by IopEnterSyncIo. It stands
     * for the oracle's "was this async QUEUED", which decides what a FAILING
     * blocking request owes the caller's event and the file object
     * (kernel/io/async.c IopEndBlockingRequest; pinned
     * sem_pipe/blocking_signal.c). The two coincide because npfs reaches the
     * wait only when its condition is unmet, exactly where the server would
     * have queued — that is an npfs property, not a promise of this field.
     * Recorded by the ENGINE at the one place a cancellable park happens, for
     * the same reason IO_CONTROL_CONTEXT.pended is set by the engine: a
     * device that has to remember to say so eventually forgets. */
    BOOLEAN syncIoParked;
    KEVENT syncIoCancelEvent;

    /* M7: a user thread's initial ring-3 register state (NtCreateThreadEx /
     * NtCreateUserProcess set these before readying it; PspUserThreadStartup
     * descends to ring 3 with them). */
    uint64_t userStartRip;
    uint64_t userStartRsp;
    uint64_t userStartArg1;
    uint64_t userStartArg2;
    void *threadObject; /* the Ob ETHREAD body (kernel/ps), 0 for kernel threads */

    /* Debug bookkeeping (Art. 9, the panic dump): the last system service
     * this thread entered — the global KiLastSystemCall names only the
     * CURRENT thread's, and a hang is a picture of the OTHER threads. ~0 =
     * never entered one. */
    uint64_t lastSyscall;

    NTSTATUS exitStatus; /* published at thread termination */

    void (*startRoutine)(void *startContext);
    void *startContext;

    /* Release obligations (issue #96 B): things this thread has taken and
     * MUST give back before it leaves the kernel — gates held, sync-I/O
     * spans, transient handles. A stack, so the panic line can name WHICH
     * one leaked and what it was taken on. See KiPushObligation. */
    KI_OBLIGATION obligations[KI_MAX_OBLIGATIONS];
    ULONG obligationCount;

    /* Park generation (issue #96 C): advanced by KiSwapToNext — the kernel's
     * single context-switch site — each time this thread actually yields the
     * CPU. A probe token stamped with an older generation is stale by
     * construction: a sibling had the chance to unmap the range in between.
     * See KI_PROBE_TOKEN in kernel/syscall/uaccess.h. */
    uint64_t parkGeneration;

    /* CUI-6: per-thread CPU time, whole-tick sampling at the clock interrupt
     * (KiUpdateClock charges KI_100NS_PER_TICK to the interrupted thread,
     * kernel or user by the interrupted CS — exactly NT's clock-interrupt
     * accounting). Read under the dispatcher lock; written with interrupts
     * off, which on the uniprocessor IS the lock. */
    uint64_t kernelTime100ns;
    uint64_t userTime100ns;
};

/* --- sched.c ------------------------------------------------------------- */

extern PKTHREAD KiCurrentThread;

void KiInitializeScheduler(void);

/* THE dispatcher lock (Art. 3): interrupt disable, one owner, no nesting
 * games — acquire returns the previous RFLAGS, release restores them. */
uint64_t KiAcquireDispatcherLock(void);
void KiReleaseDispatcherLock(uint64_t flags);

/* The lock IS interrupt disable (uniprocessor, Art. 3), so lock-held-only
 * internals can ASSERT on RFLAGS.IF directly. */
static inline BOOLEAN KiIsDispatcherLockHeld(void)
{
    uint64_t flags;
    __asm__ volatile("pushfq; popq %0" : "=r"(flags));
    return (flags & 0x200) == 0; /* IF clear */
}

/* Dispatcher-lock-held internals. */
void KiReadyThread(PKTHREAD thread);
void KiSwapToNext(void); /* current must already be re-stated; lock held */

/* Consistency-sweep helpers (kernel/init/verify.c orchestrates; lock held).
 * Each asserts the invariants of the state its file owns. */
void KiVerifyScheduler(void);                     /* ready queues + summary bitmap */
BOOLEAN KiIsThreadOnReadyQueue(PKTHREAD thread);  /* membership, for cross-checks */
void KiVerifyTimerList(void);                     /* ordering + inserted flags */
void KiVerifyWaitList(PDISPATCHER_HEADER object); /* each waiter armed this wait */
void KiVerifyThreadWaitState(PKTHREAD thread);    /* state <-> queues/waits agree */

/* --- deterministic schedule strings (issue #96 D) -------------------------
 *
 * Test instrumentation, in the same class as VioBlkSetAwaitSpinBound and for
 * the same reason: the interesting states are reachable but rare, so a test
 * has to be able to steer the machine into them rather than hope.
 *
 * Because this kernel is cooperative (Art. 3: switches happen only at
 * enumerable yield points), the set of interleavings for K threads is a
 * finite, controllable search space — not the hardware lottery it is on
 * preemptive SMP. When a schedule is armed, each scheduling decision that has
 * more than one candidate consumes one byte of the schedule and picks that
 * candidate instead of the highest-priority one; past the end of the string
 * the default policy resumes, so every run terminates. The trace records the
 * branching factor and the index taken at each choice, which is what lets a
 * harness enumerate schedules depth-first with a preemption bound (the CHESS
 * insight: nearly all real concurrency bugs surface within 2-3 deviations).
 *
 * Index 0 is always the thread the default policy would have picked, so
 * "deviations" == "nonzero indexes" == the preemption count.
 *
 * OFF BY DEFAULT, and its absence is a single predicate on the hot path: the
 * default runs' single deterministic interleaving — the property docs/19 §8.1
 * commits to and the differential fuzzer's minimization depends on — is
 * untouched. A failing schedule is a byte string, so it replays exactly. */
#define KI_SCHEDULE_MAX_CHOICES 96

typedef struct
{
    ULONG choiceCount;                      /* choice points reached */
    ULONG preemptions;                      /* choices that took a non-default thread */
    ULONG consumed;                         /* choices steered by the string */
    UCHAR options[KI_SCHEDULE_MAX_CHOICES]; /* candidates at each choice */
    UCHAR chosen[KI_SCHEDULE_MAX_CHOICES];  /* index taken */
    BOOLEAN overflowed;                     /* ran past MAX_CHOICES; trace truncated */
} KI_SCHEDULE_TRACE, *PKI_SCHEDULE_TRACE;

/* Arm/disarm a schedule around one exploration run. `bytes` is borrowed and
 * must outlive the run. Not nestable. */
void KiArmSchedule(const UCHAR *bytes, ULONG length);
void KiDisarmSchedule(PKI_SCHEDULE_TRACE traceOut);

void KiYield(void);
/* CUI-4: round-robin at the timer interrupt's return to ring 3 (the one
 * preemption point; kernel/init/panic.c). */
void KiPreemptAtUserReturn(void);
__attribute__((noreturn)) void KiIdleLoop(void);

PKTHREAD KeGetCurrentThread(void);

/* --- thread.c ------------------------------------------------------------ */

PKTHREAD KiCreateThread(KPRIORITY priority, void (*startRoutine)(void *), void *startContext);
/* M4: a thread bound to a specific process (0 = the system process) and,
 * for user threads, its TEB — both must be final before the thread is
 * readied, because the context switch programs CR3/GS from them. */
PKTHREAD KiCreateThreadEx(KPRIORITY priority, void (*startRoutine)(void *), void *startContext,
                          struct EPROCESS *process, void *teb);
/* M7: build a thread WITHOUT readying it, so Ps can set its user-start state
 * and thread object first (a user thread's ring-3 entry state and its ETHREAD
 * must be final before the scheduler can pick it). Pair with
 * KiReadyCreatedThread. Returns 0 on out-of-pool. */
PKTHREAD KiCreateThreadSuspended(KPRIORITY priority, void (*startRoutine)(void *),
                                 void *startContext, struct EPROCESS *process, void *teb);
void KiReadyCreatedThread(PKTHREAD thread);
__attribute__((noreturn)) void KiTerminateThread(void);
void KiDeleteThread(PKTHREAD thread); /* thread must be terminated */

/* --- wait.c -------------------------------------------------------------- */

void KiInitializeDispatcherHeader(PDISPATCHER_HEADER header, UCHAR type, LONG signalState);

/* Object became signalled (lock held): satisfy whatever waits it can. */
void KiWaitTest(PDISPATCHER_HEADER object);

/* Tear a waiting thread off its waits and ready it with `status` (lock held).
 * Shared by the wake paths (APC/alert completion). */
void KiUnwaitThreadWithStatus(PKTHREAD thread, NTSTATUS status);
/* Complete an alertable wait with STATUS_ALERTED (lock held). */
void KiAlertWaitingThread(PKTHREAD thread);

/* CUI-4: abort a foreign-terminated user thread's wait with
 * STATUS_THREAD_IS_TERMINATING so it reaches its reaping edge (lock held). */
void KiAbortThreadWait(PKTHREAD thread);

/* Abandon-aware mutant release shared by KeReleaseMutex and termination. */
LONG KiReleaseMutant(PKMUTANT mutant, BOOLEAN abandoned);

NTSTATUS KeWaitForSingleObject(void *object, KWAIT_REASON waitReason, KPROCESSOR_MODE waitMode,
                               BOOLEAN alertable, PLARGE_INTEGER timeout);
NTSTATUS KeWaitForMultipleObjects(ULONG count, void *objects[], WAIT_TYPE waitType,
                                  KWAIT_REASON waitReason, KPROCESSOR_MODE waitMode,
                                  BOOLEAN alertable, PLARGE_INTEGER timeout,
                                  PKWAIT_BLOCK waitBlockArray);
NTSTATUS KeDelayExecutionThread(KPROCESSOR_MODE waitMode, BOOLEAN alertable,
                                PLARGE_INTEGER interval);

/* --- event.c / sema.c / mutex.c (signatures per Wine's ntoskrnl) --------- */

void KeInitializeEvent(PRKEVENT event, EVENT_TYPE type, BOOLEAN state);
LONG KeSetEvent(PRKEVENT event, KPRIORITY increment, BOOLEAN wait);
LONG KiPulseEvent(PRKEVENT event); /* release current waiters, end unsignalled */
/* The processor count, and the ONE place it is stated (Art. 11). Art. 3
 * mandates uniprocessor, so this is 1 — a fact about the machine, not a
 * placeholder: an affinity mask of one bit, a PEB NumberOfProcessors of 1
 * and a one-entry SystemProcessorPerformanceInformation array are all
 * TRUE here, not approximations. When the mandate is lifted (docs/18 §13
 * names the four gates), every consumer follows this symbol instead of
 * being hunted down individually. */
/* Spelled in macro case rather than NT's own `KeNumberProcessors` (a CCHAR
 * variable in the real kernel) because this IS a macro here and `make format`
 * rewrites it otherwise — it did, silently, breaking the build, which is
 * the only reason the name diverges. */
#define KE_NUMBER_PROCESSORS 1

LONG KeResetEvent(PRKEVENT event);
void KeClearEvent(PRKEVENT event);
LONG KeReadStateEvent(PRKEVENT event);

/* Acquire a synchronization event used as a binary-semaphore gate (CUI-8:
 * the fat32 volume gate, docs/20 R1; the file-object I/O lock): an ordinary
 * queued wait, falling back to the rundownWait-exempt park when the wait
 * refuses for a terminating thread — every acquirer is a queued waiter, so
 * the release's hand-off discipline (KiWaitTest, FIFO) guarantees liveness
 * whatever the priorities. Internal Ki name: NT has no such export
 * (docs/15). */
void KiAcquireEventGate(PRKEVENT event);
/* The pairing release — see event.c. Every gate release goes through this,
 * never a bare KeSetEvent, so the obligation ledger stays exact. */
void KiReleaseEventGate(PRKEVENT event);

/* Obligation names. String literals compared by pointer for the panic line
 * only; keeping them here means every taker spells the kind the same way. */
#define KI_OBLIGATION_GATE      "gate"
#define KI_OBLIGATION_SYNC_IO   "sync-io span"
#define KI_OBLIGATION_TRANSIENT "transient handle"

/* --- non-blocking regions (issue #96 A, the runtime half) ----------------
 *
 * "Which contexts may block?" was prose (docs/20 R2 says the drain must not,
 * §1 F2 says the tick is a third execution context) and prose does not fire.
 * This is the Linux might_sleep() pattern, which fits here because asserts
 * are always compiled in: a region declares itself non-blocking, and every
 * park asserts it is not inside one. The static mirror is
 * tools/blocking_frontier.py --check, whose MUST_NOT_BLOCK list names the
 * same regions — one catches drift at review time, this catches it under any
 * test that reaches the path.
 *
 * A COUNT, and a global rather than a KTHREAD field, because the regions
 * belong to the CPU and nest: the timer tick raises one on whatever thread it
 * interrupted, and the drain it calls raises another. On the uniprocessor
 * (Art. 3) "the CPU" and "the current thread" are the same place, and a
 * global also works before the first thread exists.
 *
 * KiInCompletionDrain stays a separate flag: it forbids ALLOCATION, which is
 * a different prohibition on a subset of the same region. */
extern ULONG KiNoBlockDepth;
extern const char *KiNoBlockReason; /* innermost region, for the panic line */

void KiEnterNoBlockRegion(const char *reason);
void KiLeaveNoBlockRegion(void);

/* Every blocking primitive calls this. Fatal, naming the region that must not
 * have reached a park (Art. 12: an unbuilt guarantee refuses loudly). */
void KiAssertMayBlock(const char *primitive);
#define KI_MAY_BLOCK() KiAssertMayBlock(__func__)

/* --- release obligations (issue #96 B; the ledger's shape is above) ------ */

/* Take/give back an obligation. `name` is a string literal (compared by
 * pointer only for the panic line, never for logic); `object` identifies
 * which gate/handle, so two holds of the same kind are distinguishable. The
 * pop asserts it matches the top of the stack — an out-of-order release is a
 * pairing bug and is caught here rather than becoming a leak later. */
void KiPushObligation(const char *name, void *object);
void KiPopObligation(const char *name, void *object);

/* Fatal unless the ledger is empty; `where` names the exit (syscall return,
 * fault-recovery unwind, thread exit). Dumps every outstanding entry first. */
void KiAssertNoObligations(const char *where);

/* TRUE while the device-completion drain runs (CUI-8, docs/20 R2). The
 * drain can fire from the timer tick, which may have interrupted a thread
 * MID-ALLOCATION — the unlocked pool/frame free lists tolerate that only
 * because the drain never touches them: it completes requests with result
 * stores and KeSetEvent, nothing else. The allocators assert the
 * prohibition (kernel/mm/pool.c, kernel/mm/phys.c). Defined in sched.c. */
extern BOOLEAN KiInCompletionDrain;

/* The device-completion drain upcall (CUI-8, docs/19 §5b/§11), implemented
 * in kernel/io/file.c beside the transport it drains. Called with the
 * dispatcher lock held: the blk completion ISR holds it by arriving
 * (kernel/ke/irq.c — the lock IS interrupt-disable, docs/18 §6d), the tick
 * holds it implicitly (KiUpdateClock — the guest-clocked latency bound,
 * docs/19 §11c), and thread-context waiters acquire it. Returns the number
 * of requests still in flight after the harvest. */
ULONG IoDrainDeviceCompletions(void);

/* Times the blk completion vector dispatched (kernel/ke/irq.c) — the
 * docs/19 §11e delivery verdict's raw number, exposed as a bare extern the
 * way Ke measurements are (KiTscPerMillisecond precedent). */
extern uint64_t KiBlkInterruptCount;

/* Times the idle loop reached hlt (kernel/ke/sched.c) — the docs/19 §11e
 * idle-sleep verdict's raw number. */
extern uint64_t KiIdleHltCount;

void KeInitializeSemaphore(PRKSEMAPHORE semaphore, LONG count, LONG limit);
LONG KeReleaseSemaphore(PRKSEMAPHORE semaphore, KPRIORITY increment, LONG count, BOOLEAN wait);

void KeInitializeMutex(PRKMUTEX mutex, ULONG level);
LONG KeReleaseMutex(PRKMUTEX mutex, BOOLEAN wait);

/* --- timer.c ------------------------------------------------------------- */

/* Monotonic 1 ms tick count and 100 ns interrupt time since boot. */
extern volatile uint64_t KeTickCount;
#define KI_100NS_PER_TICK 10000ULL /* 1 ms tick */

/* The performance counter's frequency: one count per 100 ns, so a count IS a
 * FILETIME unit and the counter is just interrupt time under another name.
 * This is the value Windows reports "when running under a hypervisor that
 * implements the hypervisor version 1.0 interface (or always in some newer
 * versions of Windows)" (learn.microsoft.com, "Acquiring high-resolution time
 * stamps"), and the one the oracle hardcodes (third_party/wine
 * dlls/ntdll/time.c TICKSPERSEC). Named once because two places answer it —
 * NtQueryPerformanceCounter and KUSER_SHARED_DATA's QpcFrequency — and NT's
 * own conformance test requires them to agree (Art. 11). */
#define KI_PERFORMANCE_FREQUENCY 10000000LL

ULONGLONG KeQueryInterruptTime(void);
void KeQuerySystemTime(LARGE_INTEGER *time);

/* CUI-7 (NtSetSystemTime): move the wall-clock base (armed absolute timers
 * stand — docs/03 "CUI-7" notes) and republish KUSER_SHARED_DATA. */
void KeSetSystemTime(LONGLONG newTime);

/* Wall-clock base (100 ns since 1601 at boot): seeded once from the CMOS RTC
 * during KiSystemStartup (CUI-1); the initializer is the fixed-date fallback
 * (docs/03). SystemTime = base + interrupt time. */
extern uint64_t KiSystemTimeBase;

/* The KUSER_SHARED_DATA page (kernel alias), registered by Ps at boot
 * (PspInitializeSharedUserData); once set, the clock tick mirrors the time
 * fields into it (M10). Typed void* here so ke.h does not pull in the whole
 * generated abi/ntkeapi.h; timer.c casts. */
extern void *KiUserSharedData;
void KiSeedUserSharedDataTime(void);

void KeInitializeTimer(PKTIMER timer);
void KeInitializeTimerEx(PKTIMER timer, TIMER_TYPE type);
BOOLEAN KeSetTimer(PKTIMER timer, LARGE_INTEGER dueTime, PKDPC dpc);
BOOLEAN KeSetTimerEx(PKTIMER timer, LARGE_INTEGER dueTime, LONG period, PKDPC dpc);
BOOLEAN KeCancelTimer(PKTIMER timer);

void KiInitializeTimerList(void);
/* Re-base the sub-tick interpolation on now. KiInitializeClock calls this with
 * interrupts still off, so the clock's first tick measures from the moment the
 * clock started rather than from KiInitializeTimerList. */
void KiResetTickBase(void);
/* Ticks the clock recovered beyond one per interrupt since boot — time this
 * platform failed to deliver on schedule (kernel/ke/timer.c KiTicksElapsed). */
extern volatile uint64_t KiCatchUpTicks;
/* Queue a timer at an absolute interrupt-time deadline / dequeue it. */
void KiInsertTimer(PKTIMER timer, uint64_t dueInterruptTime);
void KiRemoveTimer(PKTIMER timer);
/* Convert a wait/delay LARGE_INTEGER (negative = relative 100 ns) into an
 * absolute interrupt-time deadline. */
uint64_t KiComputeDueTime(PLARGE_INTEGER timeout);
/* How long until a queued timer comes due, in 100 ns — negative once past due,
 * zero if it is not armed. Lives here rather than in the caller because the
 * answer is "due minus the queue's own clock", and that clock is this
 * department's (KiInterruptTime is static to timer.c on purpose). Dispatcher
 * lock held. */
LONGLONG KiQueryTimerRemainingTime(PKTIMER timer);
/* The clock tick: advance time, expire due timers. Interrupt context. */
void KiUpdateClock(BOOLEAN interruptedUser);

/* CUI-6: machine-wide CPU time totals, charged in KiUpdateClock alongside
 * the per-thread counters. Their sum plus idle equals KiInterruptTime by
 * construction (every tick charged exactly once — asserted at the charge
 * site). Readers hold the dispatcher lock. */
extern volatile uint64_t KiIdleTime100ns;
extern volatile uint64_t KiTotalKernelTime100ns;
extern volatile uint64_t KiTotalUserTime100ns;

/* CUI-6: is this KTHREAD the boot/idle thread? (sched.c owns the idle
 * thread's identity; the clock tick charges it to idle time.) */
BOOLEAN KiThreadIsIdle(PKTHREAD thread);

/* --- apc.c (M7) ---------------------------------------------------------- */

/* Queue a user APC to `thread` (takes the dispatcher lock). The APC block is
 * pool-owned; delivery/teardown frees it. Wakes an alertable wait.
 *
 * FALSE means the target is TERMINATED and could not accept it — the block
 * is freed here, and the caller owes its own boundary that refusal
 * (NtQueueApcThread answers STATUS_UNSUCCESSFUL). `apc == 0` requests the
 * server's APC_NONE: the same acceptance test, nothing queued, nothing
 * woken. Both rules are the pinned server's queue_apc, cited in apc.c. */
BOOLEAN KiInsertQueueUserApc(PKTHREAD thread, PKAPC apc);

/* Free every user APC still queued to an exiting thread (dispatcher lock
 * held). The queue owns those pool blocks and nothing else can release
 * them once the thread is gone. */
void KiDrainUserApcQueue(PKTHREAD thread);

/* Does the current thread have a user APC (or a pending alert) to deliver on
 * the way back to ring 3? Called by the trap/syscall return path. */
BOOLEAN KiUserApcPending(PKTHREAD thread);

/* Deliver one pending user APC by rewriting the outgoing trap frame to enter
 * KiUserApcDispatcher in ring 3 (kernel/ps/usermode.c). Lock NOT held. */
void KiDeliverUserApc(PKTHREAD thread, PKTRAP_FRAME trapFrame);

/* Consume a pending alert for an alertable wait: returns TRUE (and clears it)
 * if the thread was alerted or has a user APC queued. Lock held. */
BOOLEAN KiTestAlertCurrentThread(void);

/* --- irq.c --------------------------------------------------------------- */

void KiDispatchInterrupt(uint64_t vector, BOOLEAN interruptedUser);

#endif /* PROSKRNL_KERNEL_KE_KE_H */
