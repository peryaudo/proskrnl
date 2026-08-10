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

    /* WOW64 (docs/02 final milestone). A process whose main image is a PE32
     * runs Wine's new WoW64: the 32->64 transition is entirely user-mode, so
     * the kernel's whole share is this furniture plus the guest's initial
     * context. `wow64` is the one predicate every WOW64 branch keys off.
     * peb32Base/teb-side mirrors are built by kernel/ps/wow64.c. */
    BOOLEAN wow64;
    USHORT machine;         /* the main image's IMAGE_FILE_MACHINE_* */
    uint64_t peb32Base;     /* the PEB32 (pebBase + PAGE_SIZE); 0 when !wow64 */
    uint64_t ntdll32Base;   /* where syswow64\ntdll.dll mapped */
    uint64_t wowSpaceLimit; /* highest guest address + 1 (2GB, or 4GB for a
                             * LARGE_ADDRESS_AWARE image) — the ceiling every
                             * guest allocation is placed under */
    /* The GUEST ntdll's RtlUserThreadStart — where the initial 32-bit
     * context points before wow64.dll's thread_init rewrites it. */
    uint64_t wow64RtlUserThreadStart;

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

    /* WOW64 milestone (kernel/ps/debug.c, ADR 0011's attach-only
     * amendment): the debug object attached to this process, referenced
     * while attached and dropped by PspDetachDebugObject — which process
     * teardown also calls, so a target that exits while attached releases
     * it. There is no event queue behind this; the whole observable effect
     * is PEB.BeingDebugged. */
    struct EDEBUGOBJECT *debugObject;
    LIST_ENTRY debugLinks; /* on EDEBUGOBJECT.processList while attached */

    /* WOW64 milestone (kernel/ps/ldt.c): the process's LDT, allocated on the
     * first NtSetLdtEntries and freed at delete. 0 for every process that
     * never asks, which is nearly all of them. */
    void *ldt;

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
    /* ProcessPriorityBoost's disable flag — the process twin of ETHREAD's,
     * and stored for the same reason: proskrnl boosts nothing, but a query
     * that ignored the set would make the class disagree with itself. */
    BOOLEAN priorityBoostDisabled;
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
    /* CUI-6: the thread impersonation token (SetThreadToken/RevertToSelf).
     * A referenced TOKEN body, 0 when not impersonating; released on
     * replacement and at thread delete (G11: the ONE thread-token
     * reference). SeCurrentToken and the ~4/~5 magic handles prefer it. */
    PVOID impersonationToken;
    /* ThreadHideFromDebugger: a plain per-thread flag, set once and never
     * cleared (NT has no un-hide), read back by the query. proskrnl has no
     * debugger to hide FROM — debug objects are permanently out of scope
     * (ADR 0011) — so the flag is STORED and OBSERVED and nothing else acts
     * on it. That is not a fabricated answer: the value the caller set is
     * the value the caller reads, which is the whole of the observable
     * contract here. Consumers: ntdll:thread, kernel32:thread. */
    BOOLEAN hideFromDebugger;
    /* THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE at create time: this thread
     * is exempt from the PROCESS-level freeze, and symmetrically from the
     * process-level resume — NtSuspendProcess/NtResumeProcess skip it, while
     * the per-THREAD NtSuspendThread/NtResumeThread still reach it. The
     * server stores and reads exactly that (`thread->bypass_proc_suspend =
     * !!(req->flags & THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE)` in
     * third_party/wine server/thread.c create_thread; the two
     * `if (!thread->bypass_proc_suspend)` arms in server/process.c's
     * suspend_process/resume_process handlers). Set once at birth; NT has no
     * entry point that changes it afterwards. */
    BOOLEAN bypassProcessFreeze;
    /* ThreadPriorityBoost's disable flag, same shape and same reasoning:
     * proskrnl does not boost priorities at all (docs/03 "Deliberate
     * simplifications"), so nothing acts on it — but the query must return
     * what the set stored, or the pair disagrees with itself. */
    BOOLEAN priorityBoostDisabled;
    /* ThreadNameInformation: the thread's description, OWNED here — a pool
     * copy of the caller's string, replaced on each set and freed at thread
     * delete (PspDeleteThread). It used to be accepted and dropped on the
     * grounds that ntdll keeps the name in the TEB, which was true only for
     * as long as the QUERY side was unreachable: a set the query cannot see
     * is the silent-plausible stub G12 forbids. Buffer 0 = never named. */
    UNICODE_STRING threadName;
    /* SetThreadPriority's value, verbatim. kernelbase's GetThreadPriority
     * is `NtQueryInformationThread(ThreadBasicInformation).BasePriority`
     * and SetThreadPriority is `NtSetInformationThread(ThreadBasePriority)`
     * (dlls/kernelbase/thread.c), so the pair is a round-trip through this
     * field and nothing else. proskrnl runs one priority band that matters
     * (docs/03 "Deliberate simplifications") — so the value STEERS nothing,
     * but it must still be returned, or the pair disagrees with itself.
     * 0 is THREAD_PRIORITY_NORMAL, which is where every thread starts. */
    LONG basePriority;
} ETHREAD, *PETHREAD;

extern OBJECT_TYPE PspThreadType;

extern OBJECT_TYPE PspProcessType;

/* WOW64 milestone (kernel/ps/ldt.c): the per-process LDT. Loaded into the
 * GDT's LDT slot at context switch, read back by
 * NtQueryInformationThread(ThreadDescriptorTableEntry), released at
 * process delete. */
void PspLoadProcessLdt(PEPROCESS process);
BOOLEAN PspQueryLdtEntry(PEPROCESS process, ULONG selector, void *entryOut);
void PspFreeLdt(PEPROCESS process);

extern OBJECT_TYPE PspDebugObjectType; /* WOW64 milestone, kernel/ps/debug.c */

/* Drop this process's debug attachment, if any: the ONE unlink site, shared
 * by NtRemoveProcessDebug, the debug object's kill-on-close, and process
 * teardown. */
void PspDetachDebugObject(PEPROCESS process);

extern OBJECT_TYPE PspJobType; /* CUI-3, kernel/ps/job.c */

/* CUI-3 (kernel/ps/job.c): post the job's exit packets — call once from
 * each process-exit path, BEFORE the process object can be deleted. */
void PspNotifyProcessExit(PEPROCESS process);
/* Drop the job membership at process delete. */
void PspUnlinkProcessFromJob(PEPROCESS process);

/* CUI-6 (kernel/ps/job.c): the create-time job inheritance. The check runs
 * BEFORE the child is built — a requested breakaway the creator's immediate
 * job forbids fails creation (STATUS_ACCESS_DENIED); the join walks the
 * creator's job chain and enrolls the child in the first capturing job,
 * honouring silent/explicit breakaway. Both read the creator from the
 * current thread's process. */
NTSTATUS PspCheckCreatorBreakaway(BOOLEAN breakawayRequested);
void PspJoinCreatorJob(PEPROCESS child, BOOLEAN breakawayRequested);

/* CUI-6 (kernel/ps/thread.c): the current thread's impersonation token body
 * (a TOKEN *), or 0 when not impersonating. The ONE reader for Ob's magic
 * pseudo-handles and Se's effective-token resolution (G11). */
PVOID PsCurrentThreadImpersonationToken(void);

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
    BOOLEAN breakawayRequested;              /* CUI-6: PROCESS_CREATE_FLAGS_BREAKAWAY — the
                                              * child asked to break away from the creator's
                                              * job (join honours it per the job's limits) */
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
 * (stack bounds, Self), Peb wired, ClientId set. Returns the user VA.
 *
 * The stack is described by THREE addresses, not two: `stackTop` and
 * `stackLimit` bracket the committed slice and both move as it grows, while
 * `stackAllocationBase` is the base of the whole reservation and never moves.
 * The caller must pass all three — a TEB that reports the first two and
 * leaves DeallocationStack zero describes a stack reaching address 0
 * (sem_ps/teb_stack.c). */
NTSTATUS PspBuildTeb(PEPROCESS process, uint64_t stackAllocationBase, uint64_t stackTop,
                     uint64_t stackLimit, uint64_t uniqueProcessId, uint64_t uniqueThreadId,
                     uint64_t *tebOut);

/* ---- WOW64 (kernel/ps/wow64.c) ------------------------------------------
 * Every entry point the 32-bit side needs, in one place so that deleting
 * that file and the `if (process->wow64)` call sites leaves the CUI core
 * intact (Art. 7 / G7). */

/* The guest ntdll's entry points, looked up in the syswow64 image before it
 * is mapped (the PSP_USER_DISPATCHER_RVAS pattern) and turned into VAs by
 * PspWow64FillInitBlock. */
typedef struct PSP_WOW64_NTDLL32_RVAS
{
    uint32_t ldrInitializeThunk;
    uint32_t kiUserExceptionDispatcher;
    uint32_t kiUserApcDispatcher;
    uint32_t kiUserCallbackDispatcher;
    uint32_t rtlUserThreadStart;
    uint32_t ldrSystemDllInitBlock;
    uint32_t rtlpFreezeTimeBias;
    uint32_t rtlpQueryProcessDebugInformationRemote;
} PSP_WOW64_NTDLL32_RVAS;

/* NtGlobalFlag as the create path computes it (peb.c) — the PEB32 must
 * carry the same value the PEB does. imageKeyFoundOut may be 0. */
ULONG PspQueryGlobalFlag(const PSP_CAPTURED_PARAMS *captured, BOOLEAN *imageKeyFoundOut);

/* The compat-mode FS base for `thread` (its TEB32), or 0 for a thread of a
 * 64-bit process. Called on every context switch. */
uint64_t PspWow64Fs32Base(PKTHREAD thread);

/* The lowest address a WOW64 thread's 64-bit stack may take (4GB): the low
 * space belongs to the guest. */
uint64_t PspWow64HostStackFloor(void);

NTSTATUS PspWow64ThreadCpuArea(PETHREAD thread, uint64_t *cpuAreaOut);
const WCHAR *PspWow64Ntdll32Path(void);
uint64_t PspWow64HostStackSize(void);
uint64_t PspWow64SpaceLimit(USHORT imageCharacteristics);
NTSTATUS PspWow64BuildPeb32(PEPROCESS process, uint64_t imageBase,
                            const PSP_CAPTURED_PARAMS *captured, ULONG globalFlag);
NTSTATUS PspWow64BuildTeb32(PEPROCESS process, uint64_t tebVa, uint64_t uniqueProcessId,
                            uint64_t uniqueThreadId, uint64_t guestStackBase,
                            uint64_t guestStackLimit, uint64_t guestStackAllocation);
NTSTATUS PspWow64BuildCpuArea(PEPROCESS process, uint64_t tebVa, uint64_t hostStackTop,
                              uint64_t guestEntry, uint64_t guestStackBase, uint64_t *cpuAreaOut);
NTSTATUS PspWow64FillInitBlock(PEPROCESS process, uint64_t hostBlockVa, uint64_t guestBlockVa,
                               const PSP_WOW64_NTDLL32_RVAS *rvas);
NTSTATUS PspWow64AllocateGuestStack(PEPROCESS process, uint64_t reserve, uint64_t commit,
                                    uint64_t *baseOut, uint64_t *limitOut, uint64_t *allocationOut);

/* NT's thread-stack geometry rule, for EVERY stack this kernel reserves —
 * the main thread's and every additional one's. Stated once because it is one
 * rule (Art. 11): the two entry points differ only in where the caller's
 * numbers come from, not in what happens to them.
 *
 * `imageReserve` / `imageCommit` are the main image's declared sizes
 * (SizeOfStackReserve / SizeOfStackCommit, reaching here as
 * SECTION_IMAGE_INFORMATION's MaximumStackSize / CommittedStackSize);
 * `reserve` / `commit` are what the caller asked for, 0 meaning "the image's".
 * The pinned oracle's own body (third_party/wine dlls/ntdll/unix/virtual.c
 * virtual_alloc_thread_stack):
 *
 *     if (!reserve_size) reserve_size = main_image_info.MaximumStackSize;
 *     if (!commit_size)  commit_size  = main_image_info.CommittedStackSize;
 *     size = max( reserve_size, commit_size );
 *     if (size < 1024 * 1024) size = 1024 * 1024;
 *
 * Granularity rounding is NOT done here: each stack allocator rounds behind
 * its own overflow guard, and an image may declare a reserve near 2^64.
 * Pinned by tests/ntapi/sem_ps/thread_stack_default.c. */
void PspResolveStackGeometry(uint64_t imageReserve, uint64_t imageCommit, uint64_t reserve,
                             uint64_t commit, uint64_t *reserveOut, uint64_t *commitOut);

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
    uint64_t stackReserve;  /* 0 = the image's SizeOfStackReserve */
    uint64_t stackCommit;   /* 0 = the image's SizeOfStackCommit */
    /* NtCreateThreadEx's ZeroBits, resolved to a placement CEILING for the
     * stack reservation — inclusive of its last byte, 0 = unconstrained, the
     * convention MiAllocateVirtualMemoryEx's limitHigh already uses. It is
     * the resolved limit rather than the raw argument because the value is
     * only a ceiling once MiZeroBitsLimit has decided whether it was a count
     * or a mask, and that decision belongs to Mm (Art. 11). */
    uint64_t stackLimitHigh;
    /* THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER at create time. The same flag
     * NtSetInformationThread(ThreadHideFromDebugger) sets later, so it is
     * born set rather than set by a second path — the server does exactly
     * this (`thread->dbg_hidden = !!(req->flags & ...)` in server/thread.c
     * create_thread) and ntdll:thread reads it straight back out through
     * the query class (thread.c:120-:122). */
    BOOLEAN hideFromDebugger;
    /* THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE: this thread is exempt from
     * its process's freeze, in BOTH directions — see ETHREAD's field. */
    BOOLEAN bypassProcessFreeze;
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

/* CUI-7 (nls.c): seed the default-locale slots from the registry once the
 * Cm tree is up (kernel/init/main.c, right after CmInitialize). */
void PspInitializeLanguage(void);

#endif /* PROSKRNL_KERNEL_PS_PS_H */
