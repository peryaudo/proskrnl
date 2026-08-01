/* kernel/ps/ps.h — the Ps department: processes and user threads (M4).
 *
 * EPROCESS internal layout is entirely ours (docs/05: "nobody reads it — no
 * drivers"); only the outside is strict, and at M4 the outside is small: a
 * process is an Ob object, waitable like NT's (signalled at termination,
 * never reset), owns a handle table and a user address space, and dies
 * through NtTerminateProcess or a contained user-mode fault. The byte-exact
 * TEB/PEB and NtCreateUserProcess arrive with M7; M4 processes run a flat
 * binary handed to the kernel as a Limine module (docs/02: "test client is
 * a flat binary, not yet a PE").
 */
#ifndef PROSKRNL_KERNEL_PS_PS_H
#define PROSKRNL_KERNEL_PS_PS_H

#include "abi/ntdef.h"
#include "abi/ntpsapi.h"
#include "abi/ntmmapi.h"            /* SECTION_IMAGE_INFORMATION (M10 IMAGE_INFO write-back) */
#include "abi/ntpebteb.h"           /* RTL_USER_PROCESS_PARAMETERS (M10 params capture) */
#include "kernel/syscall/uaccess.h" /* KI_USER_SPACE_LIMIT (the dump scans) */
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h"
#include "kernel/mm/virtual.h"
#include "kernel/init/initrd.h"

typedef struct EPROCESS
{
    DISPATCHER_HEADER header; /* signalled at termination, never reset */
    MI_ADDRESS_SPACE addressSpace;
    OBP_HANDLE_TABLE handleTable;
    NTSTATUS exitStatus;
    PKTHREAD mainThread; /* M4: the first thread; M7 adds more via threadList */
    uint64_t entryRip;   /* user entry state, set before the */
    uint64_t entryRsp;   /* thread is readied */
    void *teb;           /* the main thread's TEB (per-thread TEBs at M7) */
    /* The main thread's stack region [reserve base, top): mm/fault.c grows
     * it a guard page at a time (M5, docs/02 "guard-page stack growth"). */
    uint64_t stackAllocationBase;
    uint64_t stackBase;      /* the top; NT names the high end StackBase */
    const char *imageName;   /* for dumps; storage owned by the caller... */
    BOOLEAN imageNamePooled; /* ...unless pooled (NtCreateUserProcess copies
                              * the caller's path; freed at process delete) */

    /* M7: the user-visible process structures (docs/00 "byte-for-byte"). */
    uint64_t pebBase;   /* user VA of the PEB (0 for the system process) */
    uint64_t imageBase; /* user VA the main image mapped at */
    /* The main image's facts from the PE parse, retained at creation
     * (PspFillImageInformation): ProcessImageInformation and the
     * PS_ATTRIBUTE_IMAGE_INFO write-back serve this one copy (G11).
     * All-zero when the image had no PE parse (M4 flat clients). */
    SECTION_IMAGE_INFORMATION imageInformation;
    /* CUI-6: the ProcessTimes surface. Wall-clock stamps from
     * KeQuerySystemTime; the exited totals accumulate each dying thread's
     * tick counters at retire time (under the dispatcher lock), so a
     * process query is exited totals + the live threads' counters. */
    LARGE_INTEGER createTime;
    LARGE_INTEGER exitTime;
    uint64_t exitedKernelTime100ns;
    uint64_t exitedUserTime100ns;
    /* CUI-6: Get/SetPriorityClass's stored value (store/report only — one
     * CPU, one priority band that matters; wineserver likewise only maps it
     * to nice, invisible at this boundary) and the NT-form image path
     * ProcessImageFileName serves (pooled WCHAR buffer, empty for
     * flat/boot processes that never had an NT path). */
    UCHAR priorityClass;
    UNICODE_STRING imageNtPath;
    uint64_t uniqueProcessId;         /* CLIENT_ID.UniqueProcess (a plain counter) */
    uint64_t parentProcessId;         /* CUI-4: the creator's id, reported by
                                       * SystemProcessInformation.ParentProcessId
                                       * (0 for the system process / kernel launches) */
    uint64_t processGroupId;          /* CUI-4: the console-signal group
                                       * (wineserver's process->group_id):
                                       * inherited from the creator, or the
                                       * process's own id when it starts a new
                                       * group. GenerateConsoleCtrlEvent filters
                                       * the ctrl-event fanout on it. */
    ULONG cookie;                     /* ProcessCookie: RtlEncodePointer's obfuscator */
    ULONG hardErrorMode;              /* ProcessDefaultHardErrorMode (kernelbase
                                       * Set/GetErrorMode); fresh process = 0 */
    BOOLEAN timerResolutionRequested; /* NtSetTimerResolution's per-process
                                       * has-a-request latch (M10 winetest) */
    EXECUTION_STATE executionState;   /* NtSetThreadExecutionState's per-process
                                       * latch (CUI-6); Wine's is a per-ntdll
                                       * static, i.e. per process */
    LIST_ENTRY activeProcessLinks;    /* PspActiveProcessListHead (the NT
                                       * PsActiveProcessHead shape) — the
                                       * global tid lookup walks it */

    /* M7: the ring-3 return-protocol entry points, resolved from the process's
     * system DLL (ntdll) — or, for a native single-image client, from the
     * image's own export table (kernel/mm/pecoff.c). NT keeps these in
     * ntoskrnl's KeUser* globals; here they are per-process. 0 = unresolved. */
    uint64_t userExceptionDispatcher;
    uint64_t userApcDispatcher;
    uint64_t ldrInitializeThunk;
    /* M7 Wine bring-up: RtlUserThreadStart (also from ntdll's exports). When
     * resolved, threads start on the NT protocol — a full CONTEXT on the user
     * stack handed to LdrInitializeThunk, whose Rip is this and which ntdll
     * reaches by NtContinue after loader_init (kernel/ps/usermode.c). 0 keeps
     * the bare-register entry the native M4-M7 clients use. */
    uint64_t rtlUserThreadStart;
    /* CUI-4: ntdll's __wine_ctrl_routine export — the entry a kernel-injected
     * thread runs to deliver a console control event (it calls kernelbase's
     * CtrlRoutine, which runs the process's handler list). 0 = unresolved,
     * and such a process is simply skipped by the fanout (Art. 12: no
     * fabricated delivery). */
    uint64_t ctrlRoutine;
    uint64_t ntdllBase; /* where the system DLL mapped (0 = none loaded) */

    /* M7: all threads of the process (the main thread plus NtCreateThreadEx
     * threads). The process object signals when the last one exits. */
    LIST_ENTRY threadListHead;
    LONG activeThreadCount;

    /* M9/CUI-4: the console handle duplicated into THIS process's handle
     * table by the create-path console fixup (a child inherits its parent's
     * console through its RTL_USER_PROCESS_PARAMETERS.ConsoleHandle); 0 =
     * not a console process — what the Ctrl+C fanout selects on. */
    HANDLE consoleHandle;

    /* CUI-2: the primary token — a per-process DUPLICATE of the creator's
     * (never shared; wineserver's child rule, server/process.c), minted by
     * SeAssignPrimaryToken from PspInitializeProcessCommon and dropped by
     * SeDeassignPrimaryToken at delete. EPROCESS holds one reference. */
    struct TOKEN *token;

    /* CUI-3: job membership (kernel/ps/job.c). `job` referenced (dropped by
     * PspUnlinkProcessFromJob at delete); `jobExitNotified` keeps the
     * exit-packet accounting single-shot across the two exit paths. */
    struct EJOB *job;
    LIST_ENTRY jobLinks; /* on EJOB.processList while job != 0 */
    BOOLEAN jobExitNotified;

    /* CUI-3: ProcessWineMakeProcessSystem's mark (kernel/ps/query.c) — the
     * process no longer counts toward the live-user-process total whose
     * zero-crossing signals the global shutdown event — and the
     * exactly-once latch for leaving that count (exit, or delete after a
     * failed create that never ran). */
    BOOLEAN isSystemProcess;
    BOOLEAN shutdownAccounted;

    /* GUI-5: the consistency sweep's wedge detector (kernel/init/verify.c).
     * When EVERY thread of a user process sits in an untimed wait on its own
     * tid-alert latch, no in-process waker can ever run again — ntdll's
     * futex protocol (RtlWaitOnAddress) only ever alerts same-process tids —
     * so the process is deadlocked in user-space locks the kernel cannot
     * see. The sweep confirms the picture is STANDING (same alert counters
     * across consecutive sweeps) and then dumps it once, loudly, instead of
     * letting a harness timeout discover it forty minutes later. */
    uint64_t wedgeSig;
    int wedgeSweeps;
    BOOLEAN wedgeReported;
} EPROCESS, *PEPROCESS;

/* One user thread's Ps-level state, hung off KTHREAD via a parallel object.
 * ETHREAD internal layout is entirely ours (docs/05: "nobody reads it"). */
typedef struct ETHREAD
{
    DISPATCHER_HEADER header; /* threads are waitable (join); signalled at exit */
    PKTHREAD tcb;             /* the Ke thread */
    PEPROCESS process;
    LIST_ENTRY threadListEntry; /* on EPROCESS.threadListHead */
    uint64_t uniqueThreadId;    /* CLIENT_ID.UniqueThread */
    uint64_t tebBase;           /* this thread's TEB */
    uint64_t stackAllocationBase;
    uint64_t stackBase;
    /* M10: the latched thread-id alert (NtAlertThreadByThreadId /
     * NtWaitForAlertByThreadId — ntdll's RtlWaitOnAddress/SRW primitive). A
     * synchronization event IS the contract: set-while-not-waiting latches,
     * one wait consumes (Wine dlls/ntdll/unix/sync.c futex semantics). */
    KEVENT tidAlertEvent;
    /* Diagnostic counters for the wedge dump (kernel/ps/process.c): how many
     * alerts ever landed on this thread and how many alert waits were
     * satisfied. alertsIn == alertsOut with a waiter parked on the latch is
     * "the wake was never sent"; alertsIn > alertsOut with signalState 0 is
     * a consumed-elsewhere trail. Cheap enough to keep. */
    uint64_t tidAlertsIn;
    uint64_t tidAlertsOut;
    /* CUI-6: the ThreadTimes wall-clock stamps (CPU counters live on the
     * KTHREAD, where the clock tick charges them), and the
     * ThreadQuerySetWin32StartAddress value — stamped from the creation
     * start routine, rewritable through the set arm as the oracle's
     * SET_THREAD_INFO_ENTRYPOINT is. */
    LARGE_INTEGER createTime;
    LARGE_INTEGER exitTime;
    uint64_t win32StartAddress;
} ETHREAD, *PETHREAD;

extern OBJECT_TYPE PspThreadType;

extern OBJECT_TYPE PspProcessType;

extern OBJECT_TYPE PspJobType; /* CUI-3, kernel/ps/job.c */

/* CUI-3 (kernel/ps/job.c): post the job's exit packets — call once from
 * each process-exit path, BEFORE the process object can be deleted. */
void PspNotifyProcessExit(PEPROCESS process);
/* Drop the job membership at process delete. */
void PspUnlinkProcessFromJob(PEPROCESS process);

/* CUI-3 (kernel/ps/query.c): the ProcessWineMakeProcessSystem accounting —
 * count a user process at birth; un-count at exit (called from
 * PspNotifyProcessExit) so the global shutdown event can signal when the
 * last counted process goes. */
void PspNoteUserProcessBirth(void);
void PspShutdownNoteProcessExit(PEPROCESS process);

/* The process kernel threads belong to. Its address space is the kernel
 * PML4 and its handle table is the one kmt/kernel Nt* callers use. */
extern PEPROCESS PsInitialSystemProcess;

/* Every live process (NT's PsActiveProcessHead shape); walked under the
 * dispatcher lock (the global thread-id lookup, kernel/ps/thread.c). */
extern LIST_ENTRY PspActiveProcessListHead;

/* Create the system process and freeze the kernel PML4's top level (process
 * page tables share it by copy — see arch/x86_64/mmu.h). Needs Ob; call
 * before the scheduler exists so every thread can carry a process. */
void PsInitializeProcessSubsystem(void);

/* Build a user process around a RAM-disk image: a PE (M5 — loaded through a
 * SEC_IMAGE section, entry and stack sizes from its headers) or a flat
 * binary (M4 — copied to the fixed flat-binary base). Either way it gets an
 * NT-shaped guard-page stack and a TEB (NT_TIB filled), and its single
 * thread is readied. The caller owns the returned creator reference. */
NTSTATUS PspCreateUserProcess(PKI_RAMDISK_FILE file, PEPROCESS *processOut, PETHREAD *threadOut);

/* M10: the full-control variant NtCreateUserProcess uses. */
struct PSP_CAPTURED_PARAMS; /* defined below (peb.c section) */
typedef struct PSP_CREATE_OPTIONS
{
    /* Ownership taken — freed on every path. 0 = kernel-default params. */
    struct PSP_CAPTURED_PARAMS *params;
    BOOLEAN userParams; /* params came from ring 3: apply the console/std
                         * fixups (server/process.c mirror) */
    BOOLEAN createSuspended;
    BOOLEAN inheritHandles;
    const HANDLE *handleList; /* kernel copy; 0 = inherit-all */
    ULONG handleCount;
    SECTION_IMAGE_INFORMATION *imageInfoOut; /* optional, kernel pointer */
    const char *commandLine;                 /* kernel launches with params == 0 only:
                                              * CommandLine for the default parameter block
                                              * (0 = the image path, the M7 shape) */
} PSP_CREATE_OPTIONS;

/* The stack scans in the wedge/fault dumps keep only values that could be a
 * return address into some mapped image. The floor is the lowest PE base a
 * loaded module can have here: 0x140000000, the linker's default x64 EXE
 * image base (Microsoft "PE Format" / /BASE documentation; re-verify with
 * `llvm-readobj --file-headers` on any baked .exe — e.g. user32_test.exe
 * and our own modules all report it). Everything above is a module: the
 * pinned Wine DLLs land at 0x170000000+ and our own win32u.dll links at
 * 0x326170000 (re-verify the same way), so the ceiling is simply the top of
 * user space — a stack slot at or above it cannot be user code at all.
 * Wrong-but-plausible values only add a line to a dump a human reads; the
 * range exists to drop obvious non-addresses, not to be authoritative. */
#define PSP_MODULE_FLOOR 0x140000000ULL
#define PSP_MODULE_CEIL  KI_USER_SPACE_LIMIT

/* Art. 9: print every thread of a process (state, wait, user RIP, stack
 * window) — the harness-timeout dump, also fired by the sweep's wedge
 * detector (kernel/init/verify.c). Caller holds the dispatcher lock. */
void PsDumpWedgedProcessLocked(PEPROCESS process);

/* The boot-path image launcher (kernel/init/main.c KiRunSessionManager —
 * its ONE remaining caller; every other user process is spawned by smss
 * through NtCreateUserProcess).
 *
 * Builds a process from an on-disk PE plus the on-disk ntdll.dll
 * (\??\C:\windows\system32), dispatchers resolved from ntdll, initial
 * thread on the NT CONTEXT protocol (the M7 Wine bring-up path), and waits
 * for exit. Needs the boot volume mounted (IoMountBootVolume) and a thread
 * with a handle table. `commandLine` 0 = the DOS image path; timeoutMs 0 =
 * forever. On STATUS_TIMEOUT the process is STILL RUNNING and cannot be
 * reaped (no foreign terminate — docs/03); its creator references are
 * deliberately leaked. */
NTSTATUS PsRunUserImageEx(const WCHAR *exeNtPath, const char *imageDosPath, const char *commandLine,
                          ULONG timeoutMs, NTSTATUS *exitStatusOut);

/* Terminate the calling thread's process: close its handles, publish the
 * exit status, signal the process object, never return. The user-fault
 * containment path (panic.c) and NtTerminateProcess both land here. */
__attribute__((noreturn)) void PspExitCurrentProcess(NTSTATUS exitStatus);

/* M10 thread-exit protocol (kernel/ps/thread.c): drop earlier exits' parked
 * ETHREAD pins, do the current thread's list/join bookkeeping, park its own
 * running pin and stop. Park+terminate must be the thread's last act. */
void PspReapExitedThreads(void);
void PspRetireCurrentThread(NTSTATUS exitStatus);
__attribute__((noreturn)) void PspParkCurrentThreadAndTerminate(void);

/* Consistency sweep (kernel/init/verify.c; dispatcher lock held): every
 * parked ETHREAD is a TERMINATED, signalled thread still holding its pin. */
void PspVerifyReaperList(void);

/* Where a flat binary is mapped; its entry point is its first byte. */
#define PSP_IMAGE_BASE 0x400000ULL

/* Run one boot-module program (PE or flat binary, already registered as a
 * RAM-disk file) to completion from a kernel thread: create the process,
 * wait for it, and return its exit NTSTATUS. */
NTSTATUS PsRunBootModule(PKI_RAMDISK_FILE file, NTSTATUS *exitStatusOut);

/* --- peb.c (M7; params passthrough M10) ----------------------------------- */

/* The eight embedded strings of RTL_USER_PROCESS_PARAMETERS, in the order
 * Wine's own builder lays them out (third_party/wine dlls/ntdll/env.c
 * alloc_process_params). */
enum
{
    PSP_PARAM_CURRENT_DIRECTORY = 0,
    PSP_PARAM_DLL_PATH,
    PSP_PARAM_IMAGE_PATH,
    PSP_PARAM_COMMAND_LINE,
    PSP_PARAM_WINDOW_TITLE,
    PSP_PARAM_DESKTOP,
    PSP_PARAM_SHELL_INFO,
    PSP_PARAM_RUNTIME_INFO,
    PSP_PARAM_COUNT
};

/* A kernel copy of a caller's RTL_USER_PROCESS_PARAMETERS (M10: the child
 * observes the parent's block, not kernel defaults). The header's scalar
 * fields are authoritative (ConsoleHandle/hStd* after the creation-time
 * fixups); its string Buffers and Environment pointer are the PARENT's VAs
 * and are dead — the pooled copies below are the truth, re-pointed into the
 * child block by PspBuildPeb. */
typedef struct PSP_CAPTURED_PARAMS
{
    RTL_USER_PROCESS_PARAMETERS header;
    UNICODE_STRING strings[PSP_PARAM_COUNT]; /* pooled; Buffer 0 = absent */
    WCHAR *environment;                      /* pooled double-NUL block; 0 = none */
    SIZE_T environmentSize;                  /* bytes, including the final NUL */
} PSP_CAPTURED_PARAMS;

/* Capture a user-mode params block (probes; parent context). */
NTSTATUS PspCaptureProcessParameters(const RTL_USER_PROCESS_PARAMETERS *userParams,
                                     PSP_CAPTURED_PARAMS **capturedOut);
/* Kernel-default params for kernel-launched images (ASCII inputs). */
NTSTATUS PspBuildDefaultParams(const char *imagePath, const char *commandLine,
                               PSP_CAPTURED_PARAMS **capturedOut);
void PspFreeCapturedParams(PSP_CAPTURED_PARAMS *captured);

/* Map the single shared KUSER_SHARED_DATA page at its NT-fixed user address
 * (0x7ffe0000) into `process`, read-only. Wine's PE ntdll thunks and RTL read
 * it directly (docs/00). Call once per process during creation. */
NTSTATUS PspMapSharedUserData(PEPROCESS process);

/* Fill the global KUSER_SHARED_DATA contents (called once at Ps init). The
 * timer tick fields are refreshed lazily on read paths that need them. */
void PspInitializeSharedUserData(void);

/* Build the PEB + RTL_USER_PROCESS_PARAMETERS in `process`'s address space
 * (user allocations, VAD-tracked). On success process->pebBase is set and the
 * per-thread TEB's Peb pointer can be wired. `imageBase` is the mapped main
 * image, from a captured params block (M10) whose header scalars —
 * ConsoleHandle/hStd* included — are written through verbatim. Does not
 * take ownership of `captured`. */
NTSTATUS PspBuildPeb(PEPROCESS process, uint64_t imageBase, const PSP_CAPTURED_PARAMS *captured);

/* Allocate + initialize a TEB for a thread: a full user page, NT_TIB filled
 * (stack bounds, Self), Peb wired, ClientId set. Returns the user VA. */
NTSTATUS PspBuildTeb(PEPROCESS process, uint64_t stackTop, uint64_t stackLimit,
                     uint64_t uniqueProcessId, uint64_t uniqueThreadId, uint64_t *tebOut);

/* --- thread.c (M7) ------------------------------------------------------- */

/* The caller-controlled parts of a thread create that are not the entry
 * point: the handle's access and attributes, and the stack geometry. All
 * optional -- 0 means "the image's / the default" for the sizes, and a 0
 * desiredAccess is mapped like any other (an empty mapped mask is refused by
 * the handle layer, as NT refuses it). */
typedef struct PSP_THREAD_OPTIONS
{
    ACCESS_MASK desiredAccess;
    ULONG handleAttributes; /* OBJ_INHERIT etc., from OBJECT_ATTRIBUTES */
    uint64_t stackReserve;  /* 0 = the default 1 MiB */
    uint64_t stackCommit;   /* 0 = the default 64 KiB */
} PSP_THREAD_OPTIONS;

/* Create and ready an additional user thread in `process`: its own guard-page
 * stack + TEB, entering ring 3 at `startRoutine(argument)` through the image's
 * RtlUserThreadStart-shaped entry protocol (rcx=startRoutine, rdx=argument).
 * Returns a handle in the CURRENT process's table. */
NTSTATUS PspCreateUserThread(PEPROCESS process, uint64_t startRoutine, uint64_t argument,
                             BOOLEAN createSuspended, const PSP_THREAD_OPTIONS *options,
                             PHANDLE threadHandleOut, uint64_t *threadIdOut, uint64_t *tebBaseOut);

/* CUI-4: start a thread in `process` with NO handle in any table — the
 * kernel-initiated injection the console-control fanout uses (ntdll's unix
 * int_handler does the same with NtCreateThreadEx + an immediate NtClose). */
NTSTATUS PspInjectUserThread(PEPROCESS process, uint64_t startRoutine, uint64_t argument);

/* CUI-4: deliver a console control event (CTRL_C_EVENT / CTRL_BREAK_EVENT) to
 * every process attached to the console, filtered by `groupId` when nonzero:
 * a new user thread runs ntdll's __wine_ctrl_routine with the event as its
 * argument, exactly as wineserver's propagate_console_signal + ntdll's
 * int_handler do. Called from drivers/condrv.c. */
NTSTATUS PsPropagateConsoleCtrlEvent(ULONG event, uint64_t groupId);

/* The first ring-3 descent of a user thread (shared by process/thread.c):
 * enters user mode at the KTHREAD's user-start register state. */
void PspUserThreadStartup(void *context);

/* First descent into ring 3 (kernel/ps/usermode.c): the NT initial-CONTEXT
 * protocol through LdrInitializeThunk/RtlUserThreadStart when the process has
 * a real ntdll, the bare-register entry otherwise. */
__attribute__((noreturn)) void PspEnterUserThread(PKTHREAD tcb);

/* The Ps-level exit of the current user thread: signal its thread object,
 * unlink it from the process, and — when it was the last thread — publish the
 * process exit status and signal the process. Never returns. */
__attribute__((noreturn)) void PspExitCurrentThread(NTSTATUS exitStatus);

/* CUI-4: the shared suspend/resume primitives (dispatcher lock held). One
 * truth for NtSuspend/ResumeThread and NtSuspend/ResumeProcess (G11). */
void PspSuspendTcb(PKTHREAD tcb);
void PspResumeTcb(PKTHREAD tcb);

/* CUI-4: foreign-termination primitives. PspFlagThreadTermination marks one
 * thread and wakes it (lock held); PspTerminateProcessThreads flags a whole
 * process (lock taken internally). Each target reaps ITSELF at its next
 * ring-3 edge (never torn down from the caller's context, Art. 3). Shared by
 * foreign NtTerminateProcess/Thread, NtTerminateJobObject, kill-on-job-close
 * (G11). */
void PspFlagThreadTermination(PKTHREAD tcb, NTSTATUS exitStatus);
void PspTerminateProcessThreads(PEPROCESS process, NTSTATUS exitStatus);

/* CUI-4: called at every return-to-ring-3 edge (syscall return, interrupt
 * return, first descent). Reaps the current thread if a foreign terminate is
 * pending, else parks it while its suspend gate is closed. Lock NOT held. */
void KiProcessPendingUserSignals(PKTHREAD thread);

/* Build the ETHREAD wrapper for a KTHREAD and link it into the process
 * (kernel/ps/thread.c); increments activeThreadCount. `uniqueThreadId` is
 * the id already stamped into the thread's TEB — one assignment, one truth
 * (NtAlertThreadByThreadId looks threads up by it). Returns a creator
 * reference. */
NTSTATUS PspCreateThreadObject(PEPROCESS process, PKTHREAD tcb, uint64_t tebBase,
                               uint64_t stackAllocationBase, uint64_t stackBase,
                               uint64_t uniqueThreadId, PETHREAD *threadOut);

/* --- usermode.c (M7) ----------------------------------------------------- */

/* Deliver a user-mode exception to the current thread by re-pointing its
 * outgoing trap frame at the process's KiUserExceptionDispatcher, with an
 * EXCEPTION_RECORD + CONTEXT pushed on the user stack (docs/02: the return
 * protocol). Used by the fault path (a contained AV becomes a first-chance
 * exception) and by NtRaiseException. Returns FALSE if no dispatcher is
 * resolved (the process then dies, as before M7). */
struct EXCEPTION_RECORD;
BOOLEAN PspDispatchUserException(PKTRAP_FRAME trapFrame, ULONG exceptionCode,
                                 uint64_t faultAddress);

/* Validate a query service's optional ReturnLength out-parameter, once, at
 * the top of the service — NT's ProbeForWriteUlong placement, and the one
 * the oracle's ordering demands: a bad pointer outranks an unknown info
 * class (pinned in tests/ntapi/sem_ps/process_query.c). A NULL pointer is
 * legal and succeeds.
 *
 * It lives here, and is called once per service rather than at each of the
 * ~25 sites that assign through the pointer, because every one of those
 * sites was previously a raw store: user and kernel VA share a PML4, so an
 * unprobed `*returnLength = ...` wrote wherever the caller pointed, and an
 * unmapped target faulted in ring 0 — which is a KiPanic, not a fault the
 * caller can catch. */
static inline NTSTATUS PspProbeReturnLength(PULONG returnLength)
{
    if (returnLength == 0)
    {
        return STATUS_SUCCESS;
    }
    return KiProbeForWrite(returnLength, sizeof(ULONG), sizeof(ULONG));
}

#endif /* PROSKRNL_KERNEL_PS_PS_H */
