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

/* --- Dispatcher object types (DISPATCHER_HEADER.type) ------------------- */
/* Values as Wine's ntoskrnl uses internally (dlls/ntoskrnl.exe/sync.c);
 * unobservable, but keeping them aligned costs nothing. */
#define KI_OBJECT_NOTIFICATION_EVENT    0
#define KI_OBJECT_SYNCHRONIZATION_EVENT 1
#define KI_OBJECT_MUTANT                2
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

/* --- Threads ------------------------------------------------------------- */

#define KI_THREAD_WAIT_OBJECTS 3 /* embedded wait blocks (NT: THREAD_WAIT_OBJECTS) */

#define KI_THREAD_STATE_READY      1
#define KI_THREAD_STATE_RUNNING    2
#define KI_THREAD_STATE_WAITING    3
#define KI_THREAD_STATE_TERMINATED 4

#define KI_PRIORITY_LEVELS 32 /* KPRIORITY 0..31, NT's range */

/* Internal layout is entirely ours (docs/03); only two shapes are pinned:
 * the DISPATCHER_HEADER must come first (threads are waitable, signalled at
 * termination like a notification object) and kernelStack's offset is welded
 * into arch/x86_64/ctxswitch.S. */
struct KTHREAD
{
    DISPATCHER_HEADER header;
    uint64_t kernelStack; /* saved RSP while off-CPU; ctxswitch.S offset 24 */
    void *stackBase;
    int state;
    KPRIORITY priority;
    LIST_ENTRY readyListEntry;

    /* wait machinery */
    NTSTATUS waitStatus;
    PKWAIT_BLOCK waitBlockList; /* chain via nextWaitBlock; 0 = pure delay */
    KWAIT_BLOCK waitBlocks[KI_THREAD_WAIT_OBJECTS];
    KWAIT_BLOCK timerWaitBlock;
    BOOLEAN timerArmed;
    KTIMER timer; /* the thread's timeout timer */

    LIST_ENTRY mutantListHead; /* mutants owned; abandoned at termination */

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

void KiYield(void);
__attribute__((noreturn)) void KiIdleLoop(void);

PKTHREAD KeGetCurrentThread(void);

/* --- thread.c ------------------------------------------------------------ */

PKTHREAD KiCreateThread(KPRIORITY priority, void (*startRoutine)(void *), void *startContext);
__attribute__((noreturn)) void KiTerminateThread(void);
void KiDeleteThread(PKTHREAD thread); /* thread must be terminated */

/* --- wait.c -------------------------------------------------------------- */

void KiInitializeDispatcherHeader(PDISPATCHER_HEADER header, UCHAR type, LONG signalState);

/* Object became signalled (lock held): satisfy whatever waits it can. */
void KiWaitTest(PDISPATCHER_HEADER object);

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

/* --- irq.c --------------------------------------------------------------- */

void KiDispatchInterrupt(uint64_t vector);

#endif /* PROSKRNL_KERNEL_KE_KE_H */
