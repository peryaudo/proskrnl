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

    /* M10: suspend count. Nonzero only while the thread has never run
     * (KI_THREAD_STATE_INITIALIZED — create-suspended and stacked suspends
     * on it); NtResumeThread readies the thread when it reaches zero.
     * Suspending a RUNNING thread is unbuilt (docs/03: no preemption). */
    LONG suspendCount;

    /* M4: the owning process (never 0 once Ps is up — kernel threads belong
     * to PsInitialSystemProcess), the ring-crossing state the context switch
     * programs (stack top for TSS.RSP0/syscall entry, TEB for the user GS
     * base), and the mode the current kernel entry came from. */
    struct EPROCESS *process;
    uint64_t stackTop; /* kernel stack top; 0 only for the boot/idle thread */
    void *teb;         /* user-space TEB, 0 for kernel-only threads */
    KPROCESSOR_MODE previousMode;

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

    /* M7: a user thread's initial ring-3 register state (NtCreateThreadEx /
     * NtCreateUserProcess set these before readying it; PspUserThreadStartup
     * descends to ring 3 with them). */
    uint64_t userStartRip;
    uint64_t userStartRsp;
    uint64_t userStartArg1;
    uint64_t userStartArg2;
    void *threadObject; /* the Ob ETHREAD body (kernel/ps), 0 for kernel threads */

    NTSTATUS exitStatus; /* published at thread termination */

    void (*startRoutine)(void *startContext);
    void *startContext;
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

void KiYield(void);
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
LONG KeResetEvent(PRKEVENT event);
void KeClearEvent(PRKEVENT event);
LONG KeReadStateEvent(PRKEVENT event);

void KeInitializeSemaphore(PRKSEMAPHORE semaphore, LONG count, LONG limit);
LONG KeReleaseSemaphore(PRKSEMAPHORE semaphore, KPRIORITY increment, LONG count, BOOLEAN wait);

void KeInitializeMutex(PRKMUTEX mutex, ULONG level);
LONG KeReleaseMutex(PRKMUTEX mutex, BOOLEAN wait);

/* --- timer.c ------------------------------------------------------------- */

/* Monotonic 1 ms tick count and 100 ns interrupt time since boot. */
extern volatile uint64_t KeTickCount;
#define KI_100NS_PER_TICK 10000ULL /* 1 ms tick */

ULONGLONG KeQueryInterruptTime(void);
void KeQuerySystemTime(LARGE_INTEGER *time);

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
/* Queue a timer at an absolute interrupt-time deadline / dequeue it. */
void KiInsertTimer(PKTIMER timer, uint64_t dueInterruptTime);
void KiRemoveTimer(PKTIMER timer);
/* Convert a wait/delay LARGE_INTEGER (negative = relative 100 ns) into an
 * absolute interrupt-time deadline. */
uint64_t KiComputeDueTime(PLARGE_INTEGER timeout);
/* The clock tick: advance time, expire due timers. Interrupt context. */
void KiUpdateClock(void);

/* --- apc.c (M7) ---------------------------------------------------------- */

/* Queue a user APC to `thread` (takes the dispatcher lock). The APC block is
 * pool-owned; delivery/teardown frees it. Wakes an alertable wait. */
void KiInsertQueueUserApc(PKTHREAD thread, PKAPC apc);

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

void KiDispatchInterrupt(uint64_t vector);

#endif /* PROSKRNL_KERNEL_KE_KE_H */
