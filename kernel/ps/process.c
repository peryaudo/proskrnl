/* kernel/ps/process.c — processes as Ob objects + the process lifecycle
 * (M4 flat/PE boot modules; M7 NtCreateUserProcess + the user structures).
 *
 * A process is waitable (signalled at termination, never reset), owns the
 * per-process handle table and user address space, and carries one or more
 * threads (M7: NtCreateThreadEx adds more). M7 wires the user-visible state:
 * the PEB / RTL_USER_PROCESS_PARAMETERS (kernel/ps/peb.c), a per-thread TEB,
 * the shared KUSER_SHARED_DATA page, and the ring-3 return-protocol entry
 * points resolved from the image's exports (kernel/mm/pecoff.c) — everything
 * an unmodified PE ntdll reads at startup (docs/00, docs/02).
 */
#include "kernel/ps/ps.h"
#include "kernel/se/se.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/pool.h"
#include "kernel/mm/section.h"
#include "kernel/syscall/syscall.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/io/io.h"
#include "drivers/condrv.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "kernel/init/trace.h"
#include "kernel/init/verify.h"
#include "kernel/lib/dbgprint.h"
#include "arch/x86_64/mmu.h"

#include "abi/ntimage.h"
#include "abi/ntpsapi.h"
#include "abi/ntcondrv.h" /* CUI-4: CTRL_C_EVENT / CTRL_BREAK_EVENT */

#include <stddef.h>

PEPROCESS PsInitialSystemProcess;

/* Ps-wide unique-id source (kernel/ps/thread.c). */
uint64_t PspAllocateProcessId(void);

/* Default stack shape for flat binaries (a PE brings its own sizes): the
 * NT x64 defaults — 1 MiB reserved, 64 KiB committed up front. */
#define PSP_STACK_RESERVE (1024ULL * 1024)
#define PSP_STACK_COMMIT  (64ULL * 1024)

/* Deleting a process (last reference gone) tears down what termination left:
 * the parked KTHREAD, the handle-table storage, and the address space. Runs
 * in some OTHER thread's context (the last referencer's). */
static void PspDeleteProcess(PVOID body)
{
    PEPROCESS process = body;
    ASSERT(KeGetCurrentThread() == 0 || KeGetCurrentThread()->process != process);
    uint64_t listFlags = KiAcquireDispatcherLock();
    RemoveEntryList(&process->activeProcessLinks);
    KiReleaseDispatcherLock(listFlags);
    if (process->mainThread != 0)
    {
        KiDeleteThread(process->mainThread);
    }
    if (process->imageNamePooled && process->imageName != 0)
    {
        MiFreePool((void *)process->imageName);
    }
    PspUnlinkProcessFromJob(process);
    PspShutdownNoteProcessExit(process); /* idempotent: covers a process
                                          * deleted without ever exiting */
    SeDeassignPrimaryToken(process);
    ObpDeleteHandleTable(&process->handleTable);
    if (process->addressSpace.pml4Physical != 0)
    {
        MiDeleteAddressSpace(&process->addressSpace);
    }
    /* Ask the idle loop for a prompt consistency sweep: a fully-gone process
     * is exactly the "did it leave debris?" moment the per-test kernel-runner
     * sweeps used to audit (kernel/init/verify.c). */
    KiSweepRequested = TRUE;
}

OBJECT_TYPE PspProcessType = {
    .name = "Process",
    .validAccess = PROCESS_ALL_ACCESS,
    .waitable = TRUE,
    .deleteProcedure = PspDeleteProcess,
};

/* Every process, system included, is on the active list from init to
 * delete (NT's PsActiveProcessHead); the global thread-id lookup
 * (kernel/ps/thread.c) walks it under the dispatcher lock. */
LIST_ENTRY PspActiveProcessListHead = {&PspActiveProcessListHead, &PspActiveProcessListHead};

/* Zero the M7 fields common to every process body. */
static void PspInitializeProcessCommon(PEPROCESS process)
{
    uint64_t flags = KiAcquireDispatcherLock();
    InsertTailList(&PspActiveProcessListHead, &process->activeProcessLinks);
    KiReleaseDispatcherLock(flags);
    process->pebBase = 0;
    process->imageBase = 0;
    process->uniqueProcessId = 0;
    process->parentProcessId = 0;
    process->processGroupId = 0;
    /* The ProcessCookie: ntdll's get_process_cookie feeds this straight
     * into RtlEncodePointer/RtlDecodePointer WITHOUT checking the query's
     * status, so every process must carry a stable nonzero value from
     * birth (sem_ps/process_query pins the query). TSC bits are entropy
     * enough — the cookie hardens nothing here; it only has to be
     * self-consistent. */
    ULONG cookie = (ULONG)__builtin_ia32_rdtsc();
    process->cookie = cookie != 0 ? cookie : 0xd1ce; /* never 0: 0 means "unset" to ntdll */
    process->job = 0;
    process->jobExitNotified = FALSE;
    /* CUI-6: the awake triple every fresh process starts from (Wine
     * dlls/ntdll/unix/system.c NtSetThreadExecutionState's static init). */
    process->executionState = ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED | ES_USER_PRESENT;
    process->isSystemProcess = FALSE;
    if (process != PsInitialSystemProcess)
    {
        PspNoteUserProcessBirth(); /* CUI-3: the make-process-system count */
    }
    process->userExceptionDispatcher = 0;
    process->userApcDispatcher = 0;
    process->ldrInitializeThunk = 0;
    process->rtlUserThreadStart = 0;
    process->ctrlRoutine = 0;
    process->ntdllBase = 0;
    process->activeThreadCount = 0;
    InitializeListHead(&process->threadListHead);
    process->consoleHandle = 0;
    /* CUI-2: every process is born with a primary-token duplicate (the ONE
     * mint site, G11). Failure means pool exhaustion — already fatal under
     * one-pool/no-eviction (Art. 3). */
    if (!NT_SUCCESS(SeAssignPrimaryToken(process)))
    {
        KiPanic("PspInitializeProcessCommon: cannot mint the process token");
    }
}

void PsInitializeProcessSubsystem(void)
{
    /* Process PML4s copy the kernel half from here on (arch/x86_64/mmu.h). */
    MiFreezeKernelPml4();

    PVOID body;
    if (!NT_SUCCESS(ObpAllocateObject(&PspProcessType, sizeof(EPROCESS), &body)))
    {
        KiPanic("PsInitializeProcessSubsystem: out of pool");
    }
    PsInitialSystemProcess = body;
    KiInitializeDispatcherHeader(&PsInitialSystemProcess->header, KI_OBJECT_PROCESS, 0);
    PsInitialSystemProcess->addressSpace.pml4Physical = MiGetKernelPml4();
    InitializeListHead(&PsInitialSystemProcess->addressSpace.vadListHead);
    ObpInitializeHandleTable(&PsInitialSystemProcess->handleTable);
    PsInitialSystemProcess->imageName = "System";
    PspInitializeProcessCommon(PsInitialSystemProcess);

    /* The single shared KUSER_SHARED_DATA page (kernel/ps/peb.c). */
    PspInitializeSharedUserData();
}

/* Allocate + commit one user region through the Mm engine (so it is
 * VAD-tracked like any NtAllocateVirtualMemory result). */
static NTSTATUS PspAllocateUserRegion(PEPROCESS process, uint64_t requestedBase, uint64_t size,
                                      ULONG protect, uint64_t *baseOut)
{
    PVOID base = (PVOID)(uintptr_t)requestedBase;
    SIZE_T regionSize = size;
    NTSTATUS status = MiAllocateVirtualMemory(&process->addressSpace, &base, &regionSize,
                                              MEM_RESERVE | MEM_COMMIT, protect);
    if (NT_SUCCESS(status))
    {
        *baseOut = (uint64_t)(uintptr_t)base;
    }
    return status;
}

/* Build the NT-shaped main-thread stack (docs/02 "guard-page stack growth"):
 * reserve the whole region, commit `commit` bytes at the top, and arm one
 * PAGE_GUARD page below them; mm/fault.c grows the committed slice downward. */
static NTSTATUS PspAllocateUserStack(PEPROCESS process, uint64_t reserve, uint64_t commit,
                                     uint64_t *stackTopOut, uint64_t *stackLimitOut)
{
    /* Both sizes come from the image's optional header, i.e. from a file the
     * caller supplies. Round with a guard and floor the reserve at something
     * the layout below can actually hold: unguarded, a SizeOfStackReserve
     * near 2^64 rounded to 0, and `reserve - 2 * PAGE_SIZE` then underflowed
     * to a huge commit (docs/review-2026-07 §3). The floor is the guard page
     * plus one committed page plus one page of slack -- the smallest stack
     * the guard-page growth logic is meaningful on. */
    if (reserve > KI_USER_SPACE_LIMIT - MI_ALLOCATION_GRANULARITY)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    reserve = (reserve + MI_ALLOCATION_GRANULARITY - 1) & ~(MI_ALLOCATION_GRANULARITY - 1);
    if (reserve < 3ULL * PAGE_SIZE)
    {
        reserve = MI_ALLOCATION_GRANULARITY;
    }
    if (commit > KI_USER_SPACE_LIMIT - PAGE_SIZE)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
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
    NTSTATUS status =
        MiAllocateVirtualMemory(&process->addressSpace, &base, &size, MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t stackBottom = (uint64_t)(uintptr_t)base;
    uint64_t stackTop = stackBottom + reserve;

    PVOID commitBase = (PVOID)(uintptr_t)(stackTop - commit);
    size = commit;
    status = MiAllocateVirtualMemory(&process->addressSpace, &commitBase, &size, MEM_COMMIT,
                                     PAGE_READWRITE);
    if (NT_SUCCESS(status))
    {
        PVOID guardBase = (PVOID)(uintptr_t)(stackTop - commit - PAGE_SIZE);
        size = PAGE_SIZE;
        status = MiAllocateVirtualMemory(&process->addressSpace, &guardBase, &size, MEM_COMMIT,
                                         PAGE_READWRITE | PAGE_GUARD);
    }
    if (!NT_SUCCESS(status))
    {
        return status; /* PspDeleteProcess unwinds the reservation */
    }

    process->stackAllocationBase = stackBottom;
    process->stackBase = stackTop;
    *stackTopOut = stackTop;
    *stackLimitOut = stackTop - commit; /* lowest committed non-guard page */
    return STATUS_SUCCESS;
}

/* Resolve the ring-3 return-protocol entry points from a mapped image's export
 * table (kernel/mm/pecoff.c), reading the raw file bytes. NT keeps these in
 * ntoskrnl's KeUser* globals, initialized from ntdll's exports; here they are
 * per-process, resolved from ntdll — or, for a native single-image client,
 * from the image itself. Missing exports leave the field 0 (a flat binary or
 * an image without the dispatchers: exceptions then kill the process). */
static void PspResolveUserDispatchers(PEPROCESS process, PMI_SECTION section, uint64_t base)
{
    if (section->image == 0 || section->rawData == 0)
    {
        return;
    }
    uint32_t rva;
    rva = MiLookupImageExport(section->rawData, section->rawSize, section->image,
                              "KiUserExceptionDispatcher");
    if (rva != 0)
    {
        process->userExceptionDispatcher = base + rva;
    }
    rva = MiLookupImageExport(section->rawData, section->rawSize, section->image,
                              "KiUserApcDispatcher");
    if (rva != 0)
    {
        process->userApcDispatcher = base + rva;
    }
    rva = MiLookupImageExport(section->rawData, section->rawSize, section->image,
                              "LdrInitializeThunk");
    if (rva != 0)
    {
        process->ldrInitializeThunk = base + rva;
    }
    rva = MiLookupImageExport(section->rawData, section->rawSize, section->image,
                              "RtlUserThreadStart");
    if (rva != 0)
    {
        process->rtlUserThreadStart = base + rva;
    }
    /* CUI-4: the console-control entry. ntdll exports it (dlls/ntdll/
     * ntdll.spec, loader.c __wine_ctrl_routine) precisely so the OS can start
     * a thread there to deliver CTRL_C/CTRL_BREAK; it forwards to
     * kernelbase's CtrlRoutine, which runs the process's handler list. */
    rva = MiLookupImageExport(section->rawData, section->rawSize, section->image,
                              "__wine_ctrl_routine");
    if (rva != 0)
    {
        process->ctrlRoutine = base + rva;
    }
}

/* The main image's SECTION_IMAGE_INFORMATION from the PE parse (abi shape;
 * `entry` is the RELOCATED entry point). One fill for the retained
 * EPROCESS.imageInformation and the PS_ATTRIBUTE_IMAGE_INFO write-back. */
static void PspFillImageInformation(const MI_IMAGE_INFO *image, uint64_t entry,
                                    SECTION_IMAGE_INFORMATION *info)
{
    memset(info, 0, sizeof(*info));
    info->TransferAddress = (PVOID)(uintptr_t)entry;
    info->MaximumStackSize = image->stackReserve;
    info->CommittedStackSize = image->stackCommit;
    info->SubSystemType = image->subsystem;
    info->MinorSubsystemVersion = image->subsystemMinor;
    info->MajorSubsystemVersion = image->subsystemMajor;
    info->MinorOperatingSystemVersion = image->osMinor;
    info->MajorOperatingSystemVersion = image->osMajor;
    info->ImageCharacteristics = image->characteristics;
    info->DllCharacteristics = image->dllCharacteristics;
    info->Machine = image->machine;
    info->ImageContainsCode = image->containsCode;
    info->CheckSum = image->checksum;
    info->ImageFileSize = image->fileSize;
}

/* Map an already-built image section into `process`. Returns the entry point
 * + the PE-declared stack shape. */
static NTSTATUS PspMapImageSection(PEPROCESS process, PMI_SECTION section, uint64_t *entryOut,
                                   uint64_t *baseOut, uint64_t *stackReserveOut,
                                   uint64_t *stackCommitOut)
{
    uint64_t base = 0;
    uint64_t viewSize = 0;
    NTSTATUS status =
        MiMapViewOfSection(section, &process->addressSpace, &base, 0, &viewSize, PAGE_EXECUTE);
    if (!NT_SUCCESS(status)) /* STATUS_IMAGE_NOT_AT_BASE is a success code */
    {
        return status;
    }
    *entryOut = base + section->image->entryRva;
    *baseOut = base;
    if (stackReserveOut != 0)
    {
        *stackReserveOut = section->image->stackReserve;
    }
    if (stackCommitOut != 0)
    {
        *stackCommitOut = section->image->stackCommit;
    }
    return STATUS_SUCCESS;
}

/* Map a PE program through the section machinery (M5). Also resolves the M7
 * user dispatchers from its exports. Returns the entry point + stack shape. */
static NTSTATUS PspMapImage(PEPROCESS process, PKI_RAMDISK_FILE file, uint64_t *entryOut,
                            uint64_t *baseOut, uint64_t *stackReserveOut, uint64_t *stackCommitOut)
{
    PMI_SECTION section;
    NTSTATUS status = MiCreateSection(0, PAGE_EXECUTE, SEC_IMAGE, file, &section);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status =
        PspMapImageSection(process, section, entryOut, baseOut, stackReserveOut, stackCommitOut);
    if (NT_SUCCESS(status))
    {
        PspResolveUserDispatchers(process, section, *baseOut);
    }
    ObDereferenceObject(section); /* the view holds its own pin */
    return status;
}

NTSTATUS PspCreateUserProcess(PKI_RAMDISK_FILE file, PEPROCESS *processOut, PETHREAD *threadOut)
{
    if (file == 0 || file->size == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PVOID body;
    NTSTATUS status = ObpAllocateObject(&PspProcessType, sizeof(EPROCESS), &body);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PEPROCESS process = body;
    KiInitializeDispatcherHeader(&process->header, KI_OBJECT_PROCESS, 0);
    ObpInitializeHandleTable(&process->handleTable);
    process->imageName = file->name;
    PspInitializeProcessCommon(process);
    process->uniqueProcessId = PspAllocateProcessId();
    process->parentProcessId = KeGetCurrentThread()->process->uniqueProcessId;

    status = MiCreateAddressSpace(&process->addressSpace);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(process);
        return status;
    }

    uint64_t entry = 0;
    uint64_t imageBase = 0;
    uint64_t stackReserve = PSP_STACK_RESERVE;
    uint64_t stackCommit = PSP_STACK_COMMIT;
    BOOLEAN isPe = FALSE;
    const unsigned char *magic = file->data;
    if (file->size >= 2 && magic[0] == 'M' && magic[1] == 'Z')
    {
        isPe = TRUE;
        status = PspMapImage(process, file, &entry, &imageBase, &stackReserve, &stackCommit);
        if (NT_SUCCESS(status) && stackReserve == 0)
        {
            stackReserve = PSP_STACK_RESERVE;
        }
        if (NT_SUCCESS(status) && stackReserve < 4ULL * PAGE_SIZE)
        {
            stackReserve = 4ULL * PAGE_SIZE;
        }
    }
    else
    {
        /* An M4 flat binary at its fixed base, RWX; entry is its first byte. */
        status = PspAllocateUserRegion(process, PSP_IMAGE_BASE, file->size, PAGE_EXECUTE_READWRITE,
                                       &imageBase);
        if (NT_SUCCESS(status))
        {
            MiCopyToUserRange(&process->addressSpace, imageBase, file->data, file->size);
            entry = imageBase;
        }
    }

    uint64_t stackTop = 0;
    uint64_t stackLimit = 0;
    if (NT_SUCCESS(status))
    {
        status = PspAllocateUserStack(process, stackReserve, stackCommit, &stackTop, &stackLimit);
    }

    /* M7: the shared KUSER_SHARED_DATA page + the PEB/params, then the main
     * thread's TEB (wired to the PEB). A flat binary (M4) still runs without
     * these; build them only for a PE so the M4 clients are unchanged. */
    uint64_t tebBase = 0;
    if (NT_SUCCESS(status))
    {
        status = PspMapSharedUserData(process);
    }
    if (NT_SUCCESS(status) && isPe)
    {
        PSP_CAPTURED_PARAMS *defaults = 0;
        status = PspBuildDefaultParams(process->imageName, process->imageName, &defaults);
        if (NT_SUCCESS(status))
        {
            status = PspBuildPeb(process, imageBase, defaults);
            PspFreeCapturedParams(defaults);
        }
    }
    /* One GLOBAL id serves the TEB's ClientId and the ETHREAD below — same
     * discipline as PspCreateUserProcessImage: a TEB id that disagrees with what
     * NtQueryInformationThread reports is exactly the class the ABI probe
     * convicts (tests/boot/abi_probe.c). */
    uint64_t mainThreadId = PspAllocateProcessId();
    if (NT_SUCCESS(status) && isPe)
    {
        status = PspBuildTeb(process, stackTop, stackLimit, process->uniqueProcessId, mainThreadId,
                             &tebBase);
    }
    else if (NT_SUCCESS(status))
    {
        /* Flat binary: a bare TEB with just the NT_TIB (M4 shape). */
        status = PspAllocateUserRegion(process, 0, PAGE_SIZE, PAGE_READWRITE, &tebBase);
        if (NT_SUCCESS(status))
        {
            uint64_t tebFrame =
                MiTranslateUserPage(process->addressSpace.pml4Physical, tebBase, 0, 0);
            ASSERT(tebFrame != 0);
            NT_TIB *tib = MiPhysicalToVirtual(tebFrame);
            memset(tib, 0, sizeof(*tib));
            tib->StackBase = (PVOID)(uintptr_t)stackTop;
            tib->StackLimit = (PVOID)(uintptr_t)stackLimit;
            tib->Self = (struct _NT_TIB *)(uintptr_t)tebBase;
        }
    }
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(process); /* PspDeleteProcess unwinds the rest */
        return status;
    }

    process->teb = (void *)(uintptr_t)tebBase;
    process->entryRip = entry;
    process->entryRsp = stackTop;

    /* Build the main thread. For a PE the loader protocol enters ntdll's
     * LdrInitializeThunk (when resolved) with rcx = image entry; for a flat
     * binary / an image without ntdll it enters `entry` directly. */
    PKTHREAD main = KiCreateThreadSuspended(8, PspUserThreadStartup, 0, process, process->teb);
    if (main == 0)
    {
        ObDereferenceObject(process);
        return STATUS_NO_MEMORY;
    }
    if (isPe && process->ldrInitializeThunk != 0)
    {
        main->userStartRip = process->ldrInitializeThunk;
        main->userStartArg1 = entry;            /* rcx: thread start routine */
        main->userStartArg2 = process->pebBase; /* rdx: the PEB */
    }
    else
    {
        main->userStartRip = entry;
        main->userStartArg1 = process->pebBase; /* rcx (native client reads it) */
        main->userStartArg2 = 0;
    }
    main->userStartRsp = (stackTop & ~(uint64_t)0xf) - 0x28;

    /* The main thread's ETHREAD, BEFORE the thread runs, with the id the TEB
     * was stamped with above — thread queries and NtAlertThreadByThreadId
     * must see boot-module threads like any other (the Wine-process path
     * already does this; the ABI probe convicted this path's omission). The
     * ETHREAD owns the KTHREAD; the count starts at 0 and the create call
     * counts it. The caller owns the returned creator reference and must
     * hold it until the thread has exited. */
    process->activeThreadCount = 0;
    PETHREAD mainThreadObject;
    status = PspCreateThreadObject(process, main, tebBase, 0, 0, mainThreadId, &mainThreadObject);
    if (!NT_SUCCESS(status))
    {
        KiDeleteThread(main);
        ObDereferenceObject(process);
        return status;
    }
    process->mainThread = 0; /* the ETHREAD owns the KTHREAD (M10 shape) */

    KiReadyCreatedThread(main);
    *processOut = process;
    *threadOut = mainThreadObject;
    return STATUS_SUCCESS;
}

/* Build a user process the way NtCreateUserProcess will: the executable AND
 * the system DLL (ntdll) mapped from the boot volume, the ring-3 dispatchers
 * resolved from ntdll's exports, and the initial thread started on the NT
 * CONTEXT protocol through LdrInitializeThunk (kernel/ps/usermode.c). This is
 * the M7 Wine bring-up path: an unmodified PE ntdll takes over from
 * LdrInitializeThunk on. `exeNtPath` is the namespace path (\??\C:\...);
 * `imageDosPath` the DOS path ntdll sees in ProcessParameters. */
#define PSP_NTDLL_PATH WSTR("\\??\\C:\\windows\\system32\\ntdll.dll")

static NTSTATUS PspCreateUserProcessImage(const WCHAR *exeNtPath, const char *imageDosPath,
                                          PSP_CREATE_OPTIONS *options, PEPROCESS *processOut,
                                          PETHREAD *threadOut)
{
    PMI_SECTION exeSection;
    NTSTATUS status = IoOpenImageSection(exeNtPath, &exeSection);
    if (!NT_SUCCESS(status))
    {
        PspFreeCapturedParams(options->params);
        return status;
    }
    PMI_SECTION ntdllSection;
    status = IoOpenImageSection(PSP_NTDLL_PATH, &ntdllSection);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(exeSection);
        PspFreeCapturedParams(options->params);
        return status;
    }

    /* The child's parameters: the caller's captured block, or kernel
     * defaults for kernel-launched images. Owned here from this point. */
    PSP_CAPTURED_PARAMS *params = options->params;
    options->params = 0;
    if (params == 0)
    {
        const char *commandLine = options->commandLine ? options->commandLine : imageDosPath;
        status = PspBuildDefaultParams(imageDosPath, commandLine, &params);
        if (!NT_SUCCESS(status))
        {
            goto out_sections;
        }
    }

    PVOID body;
    status = ObpAllocateObject(&PspProcessType, sizeof(EPROCESS), &body);
    if (!NT_SUCCESS(status))
    {
        goto out_params;
    }
    PEPROCESS process = body;
    KiInitializeDispatcherHeader(&process->header, KI_OBJECT_PROCESS, 0);
    ObpInitializeHandleTable(&process->handleTable);
    process->imageName = imageDosPath;
    PspInitializeProcessCommon(process);
    process->uniqueProcessId = PspAllocateProcessId();
    /* CUI-4: SystemProcessInformation.ParentProcessId — the creator, or 0
     * for a boot-time kernel launch (KiInitialize runs on the system
     * process, whose id is 0). */
    PEPROCESS creator = KeGetCurrentThread()->process;
    process->parentProcessId = creator->uniqueProcessId;
    /* The console-signal group (wineserver server/process.c new_process): a
     * child joins its creator's group; a process whose creator has none —
     * every kernel launch — starts its own, keyed on its own id. */
    process->processGroupId =
        creator->processGroupId != 0 ? creator->processGroupId : process->uniqueProcessId;

    status = MiCreateAddressSpace(&process->addressSpace);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(process);
        goto out_params;
    }

    /* --- M10: handle inheritance + the console/std fixups ------------------
     * All in the PARENT's context, before anything else can fail — the spec
     * is wineserver's copy_handle_table + new_process (server/handle.c,
     * server/process.c), pinned by sem_ps/inherit.c. */
    POBP_HANDLE_TABLE parentTable = &KeGetCurrentThread()->process->handleTable;
    if (options->inheritHandles)
    {
        HANDLE stdHandles[3];
        stdHandles[0] = params->header.hStdInput;
        stdHandles[1] = params->header.hStdOutput;
        stdHandles[2] = params->header.hStdError;
        status = ObpInheritHandles(parentTable, &process->handleTable, options->handleList,
                                   options->handleCount, stdHandles);
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(process);
            goto out_params;
        }
    }
    if (options->userParams)
    {
        /* Inherit the process console, but keep pseudo handles (< 0) and 0
         * (no console) as-is; a real handle is re-duplicated to a fresh
         * child value written back into the child's params
         * (server/process.c). */
        HANDLE consoleHandle = params->header.ConsoleHandle;
        if ((LONGLONG)(uintptr_t)consoleHandle > 0)
        {
            HANDLE duplicated = 0;
            if (NT_SUCCESS(ObpDuplicateIntoTable(parentTable, consoleHandle, &process->handleTable,
                                                 FALSE, &duplicated)))
            {
                params->header.ConsoleHandle = duplicated;
                /* CUI-4: record the inherited console on the EPROCESS too —
                 * `consoleHandle != 0` is what marks a process as attached to
                 * the console, and so what the Ctrl+C fanout selects on
                 * (PsPropagateConsoleCtrlEvent). A cmd child reaches its
                 * console THIS way, not through the kernel-launch seeding
                 * below, so leaving it 0 made every interactive child
                 * invisible to console control events. */
                process->consoleHandle = duplicated;
            }
            else
            {
                params->header.ConsoleHandle = 0;
            }
        }
        if (!options->inheritHandles)
        {
            /* Not inheriting: the three std handles are still duplicated
             * into the child, invalid ones tolerated (become 0). */
            HANDLE *stdFields[3] = {&params->header.hStdInput, &params->header.hStdOutput,
                                    &params->header.hStdError};
            for (int i = 0; i < 3; i++)
            {
                HANDLE value = *stdFields[i];
                if ((LONGLONG)(uintptr_t)value <= 0)
                {
                    continue;
                }
                HANDLE duplicated = 0;
                *stdFields[i] = NT_SUCCESS(ObpDuplicateIntoTable(
                                    parentTable, value, &process->handleTable, TRUE, &duplicated))
                                    ? duplicated
                                    : 0;
            }
        }
    }

    /* The executable first (it prefers its header base), then ntdll. */
    uint64_t entry = 0;
    uint64_t imageBase = 0;
    uint64_t stackReserve = PSP_STACK_RESERVE;
    uint64_t stackCommit = PSP_STACK_COMMIT;
    status =
        PspMapImageSection(process, exeSection, &entry, &imageBase, &stackReserve, &stackCommit);
    uint64_t ntdllEntry = 0;
    uint64_t ntdllBase = 0;
    if (NT_SUCCESS(status))
    {
        status = PspMapImageSection(process, ntdllSection, &ntdllEntry, &ntdllBase, 0, 0);
    }
    if (NT_SUCCESS(status))
    {
        /* The return-protocol entry points come from ntdll, exactly as NT
         * resolves its KeUser* globals from the system DLL's exports. */
        PspResolveUserDispatchers(process, ntdllSection, ntdllBase);
        process->ntdllBase = ntdllBase;
        if (process->ldrInitializeThunk == 0 || process->rtlUserThreadStart == 0)
        {
            status = STATUS_ENTRYPOINT_NOT_FOUND;
        }
    }
    if (NT_SUCCESS(status) && stackReserve < 4ULL * PAGE_SIZE)
    {
        stackReserve = PSP_STACK_RESERVE;
    }
    /* Wine's ntdll assumes the initial commit its own loader would have
     * made: signal_start_thread (dlls/ntdll/signal_x86_64.c) zeroes 0xf000
     * bytes below the initial CONTEXT before NtContinue, deeper than a
     * minimal PE-header SizeOfStackCommit. Commit at least the 64 KiB every
     * additional thread gets (kernel/ps/thread.c). */
    if (NT_SUCCESS(status) && stackCommit < PSP_STACK_COMMIT)
    {
        stackCommit = PSP_STACK_COMMIT;
    }

    uint64_t stackTop = 0;
    uint64_t stackLimit = 0;
    if (NT_SUCCESS(status))
    {
        status = PspAllocateUserStack(process, stackReserve, stackCommit, &stackTop, &stackLimit);
    }
    if (NT_SUCCESS(status))
    {
        status = PspMapSharedUserData(process);
    }
    if (NT_SUCCESS(status))
    {
        status = PspBuildPeb(process, imageBase, params);
    }
    uint64_t tebBase = 0;
    /* One GLOBAL id serves the TEB's ClientId and the ETHREAD below — NT's
     * client ids come from the shared CID space (ntdll:sync test_tid_alert
     * depends on cross-process uniqueness). */
    uint64_t mainThreadId = PspAllocateProcessId();
    if (NT_SUCCESS(status))
    {
        status = PspBuildTeb(process, stackTop, stackLimit, process->uniqueProcessId, mainThreadId,
                             &tebBase);
    }
    if (!NT_SUCCESS(status))
    {
        /* Seeded/inherited handles must go before the table storage does
         * (ObpDeleteHandleTable asserts an empty table). */
        ObpCloseAllHandles(&process->handleTable);
        ObDereferenceObject(process); /* PspDeleteProcess unwinds the rest */
        goto out_params;
    }

    process->teb = (void *)(uintptr_t)tebBase;
    process->entryRip = entry;
    process->entryRsp = stackTop;
    process->activeThreadCount = 1;

    PKTHREAD main = KiCreateThreadSuspended(8, PspUserThreadStartup, 0, process, process->teb);
    if (main == 0)
    {
        ObpCloseAllHandles(&process->handleTable);
        ObDereferenceObject(process);
        status = STATUS_NO_MEMORY;
        goto out_params;
    }
    /* The NT protocol (PspEnterUserThread): CONTEXT.Rcx = the image entry,
     * CONTEXT.Rdx = the PEB — what Wine's unix loader seeds for the first
     * thread (init_syscall_frame) and RtlUserThreadStart expects. */
    main->userStartRip = 0;
    main->userStartArg1 = entry;
    main->userStartArg2 = process->pebBase;
    main->userStartRsp = (stackTop & ~(uint64_t)0xf) - 0x28;

    /* The main thread's ETHREAD, BEFORE the thread runs: id 1 (the TEB was
     * stamped with it above), so NtAlertThreadByThreadId and thread queries
     * see every thread — kernel-launched processes included (M10). The
     * ETHREAD owns the KTHREAD; the count starts at 0 and the create call
     * counts it. The caller owns the returned creator reference and must
     * hold it until the thread has exited. */
    process->activeThreadCount = 0;
    PETHREAD mainThreadObject;
    status = PspCreateThreadObject(process, main, tebBase, 0, 0, mainThreadId, &mainThreadObject);
    if (!NT_SUCCESS(status))
    {
        KiDeleteThread(main);
        ObpCloseAllHandles(&process->handleTable);
        ObDereferenceObject(process);
        goto out_params;
    }
    process->mainThread = 0;

    /* The image facts from the PE parse, retained on the process: served by
     * ProcessImageInformation (ntdll's build_main_module reads it at every
     * process start) and by CreateProcess's PS_ATTRIBUTE_IMAGE_INFO
     * write-back below — one copy, one fill (G11). */
    PspFillImageInformation(exeSection->image, entry, &process->imageInformation);
    if (options->imageInfoOut != 0)
    {
        memcpy(options->imageInfoOut, &process->imageInformation,
               sizeof(process->imageInformation));
    }

    if (options->createSuspended)
    {
        /* THREAD_CREATE_FLAGS_CREATE_SUSPENDED: kernelbase resumes the
         * initial thread itself after wiring the handles
         * (dlls/kernelbase/process.c). */
        main->suspendCount = 1;
    }
    else
    {
        KiReadyCreatedThread(main);
    }
    *processOut = process;
    *threadOut = mainThreadObject;
    status = STATUS_SUCCESS;

out_params:
    PspFreeCapturedParams(params);
out_sections:
    ObDereferenceObject(ntdllSection); /* the views hold their own pins */
    ObDereferenceObject(exeSection);
    return status;
}

/* Art. 9: on a harness timeout the serial log IS the debugger, so say what
 * every thread of the wedged process was doing before giving up on it —
 * its state, whether its wait is alertable, the user RIP its last ring-3
 * entry saved (trapFrame), WHAT it is waiting on (the wait-block chain,
 * with the thread's own tid-alert latch called out by name — a thread
 * parked there is inside ntdll's RtlWaitOnAddress/critical-section slow
 * path), and the return addresses on its user stack. With no ASLR the
 * module layout is deterministic, so the raw values symbolize offline. A
 * silent timeout was just "it hung"; this is a backtrace. */
void PsDumpWedgedProcessLocked(PEPROCESS process)
{
    ASSERT(KiIsDispatcherLockHeld());
    DbgPrint("[KTEST] wedged pid=%lu image=%s\n", (unsigned long)process->uniqueProcessId,
             process->imageName ? process->imageName : "?");
    for (PLIST_ENTRY entry = process->threadListHead.Flink; entry != &process->threadListHead;
         entry = entry->Flink)
    {
        PETHREAD thread = CONTAINING_RECORD(entry, ETHREAD, threadListEntry);
        PKTHREAD tcb = thread->tcb;
        DbgPrint("[KTEST] wedged tid=%lu state=%d alertable=%d rip=%p entry=%p\n",
                 (unsigned long)thread->uniqueThreadId, tcb ? tcb->state : -1,
                 tcb ? (int)tcb->waitAlertable : -1,
                 tcb && tcb->trapFrame ? (void *)tcb->trapFrame->rip : 0,
                 /* the thread's real start routine (RtlUserThreadStart's
                  * first argument) — names an anonymous worker offline */
                 tcb ? (void *)tcb->userStartArg1 : 0);
        if (tcb != 0)
        {
            for (PKWAIT_BLOCK block = tcb->waitBlockList; block != 0; block = block->nextWaitBlock)
            {
                DbgPrint("[KTEST] wedged tid=%lu waits-on=%p%s latch=%ld in=%lu out=%lu\n",
                         (unsigned long)thread->uniqueThreadId, block->object,
                         block->object == &thread->tidAlertEvent ? " (own tid-alert latch)" : "",
                         (long)thread->tidAlertEvent.header.signalState,
                         (unsigned long)thread->tidAlertsIn, (unsigned long)thread->tidAlertsOut);
            }
        }
        if (tcb != 0 && tcb->trapFrame != 0)
        {
            /* A poor man's backtrace: every user-code-looking qword in the
             * top of the user stack: any module-range value is a return
             * address or a function pointer, and either names a frame
             * (PSP_MODULE_FLOOR/CEIL, kernel/ps/ps.h). */
            uint64_t stack[512];
            uint64_t copied = MiCopyFromUserRange(&process->addressSpace, stack,
                                                  tcb->trapFrame->rsp, sizeof(stack));
            int shown = 0;
            for (uint64_t i = 0; i < copied / sizeof(uint64_t) && shown < 16; i++)
            {
                if (stack[i] >= PSP_MODULE_FLOOR && stack[i] < PSP_MODULE_CEIL)
                {
                    DbgPrint("[KTEST] wedged tid=%lu frame=%p\n",
                             (unsigned long)thread->uniqueThreadId, (void *)stack[i]);
                    shown++;
                }
            }
            /* The raw top of the stack too: the blocked call's locals live
             * here (RtlWaitOnAddress's futex entry — the waited address and
             * the tid the waker must alert — sits in this window), and the
             * filter above cannot know which non-code values matter. */
            for (uint64_t i = 0; i + 4 <= copied / sizeof(uint64_t) && i < 32; i += 4)
            {
                DbgPrint("[KTEST] wedged tid=%lu rsp+%03lx: %p %p %p %p\n",
                         (unsigned long)thread->uniqueThreadId, (unsigned long)(i * 8),
                         (void *)stack[i], (void *)stack[i + 1], (void *)stack[i + 2],
                         (void *)stack[i + 3]);
            }
        }
    }
}

static void PspDumpWedgedProcess(PEPROCESS process)
{
    uint64_t flags = KiAcquireDispatcherLock();
    PsDumpWedgedProcessLocked(process);
    KiReleaseDispatcherLock(flags);
}

NTSTATUS PsRunUserImageEx(const WCHAR *exeNtPath, const char *imageDosPath, const char *commandLine,
                          ULONG timeoutMs, NTSTATUS *exitStatusOut)
{
    PEPROCESS process;
    PETHREAD mainThread;
    PSP_CREATE_OPTIONS options;
    memset(&options, 0, sizeof(options));
    options.commandLine = commandLine;
    NTSTATUS status =
        PspCreateUserProcessImage(exeNtPath, imageDosPath, &options, &process, &mainThread);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    LARGE_INTEGER timeout;
    PLARGE_INTEGER timeoutPtr = 0;
    if (timeoutMs != 0)
    {
        timeout.QuadPart = -((LONGLONG)timeoutMs * 10000); /* relative, 100 ns */
        timeoutPtr = &timeout;
    }
    status = KeWaitForSingleObject(process, Executive, KernelMode, FALSE, timeoutPtr);
    if (status == STATUS_TIMEOUT)
    {
        /* Still running; no foreign terminate exists (docs/03), so the
         * creator references stay leaked rather than freeing a live process.
         * Dump what it was doing first (Art. 9). */
        PspDumpWedgedProcess(process);
        return STATUS_TIMEOUT;
    }
    ASSERT(status == STATUS_SUCCESS);
    *exitStatusOut = process->exitStatus;
    ObDereferenceObject(mainThread); /* exited: safe to let the ETHREAD go */
    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

NTSTATUS PsRunBootModule(PKI_RAMDISK_FILE file, NTSTATUS *exitStatusOut)
{
    PEPROCESS process;
    PETHREAD mainThread;
    NTSTATUS status = PspCreateUserProcess(file, &process, &mainThread);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = KeWaitForSingleObject(process, Executive, KernelMode, FALSE, 0);
    ASSERT(status == STATUS_SUCCESS);
    *exitStatusOut = process->exitStatus;
    ObDereferenceObject(mainThread); /* exited: safe to let the ETHREAD go */
    ObDereferenceObject(process);    /* the creator reference; PspDeleteProcess frees it */
    return STATUS_SUCCESS;
}

__attribute__((noreturn)) void PspExitCurrentProcess(NTSTATUS exitStatus)
{
    PKTHREAD self = KeGetCurrentThread();
    PEPROCESS process = self->process;
    ASSERT(process != PsInitialSystemProcess);

    /* CUI-4: exiting the process means every thread dies, not just this one
     * (retires the M10 "abandons blocked siblings" divergence — the crux for
     * a Ctrl+C exit, where the injected ctrl-routine thread ends the process
     * while the original thread is still looping/blocked). Flag the siblings
     * and wake them; each reaps ITSELF at its edge. The last thread to exit
     * — this one or a sibling — runs the process finalization in
     * PspExitCurrentThread (close handles, publish the status, signal the
     * process object). All carry the same exitStatus, so the published code
     * is stable. */
    uint64_t flags = KiAcquireDispatcherLock();
    for (PLIST_ENTRY entry = process->threadListHead.Flink; entry != &process->threadListHead;
         entry = entry->Flink)
    {
        PKTHREAD tcb = CONTAINING_RECORD(entry, ETHREAD, threadListEntry)->tcb;
        if (tcb != self)
        {
            PspFlagThreadTermination(tcb, exitStatus);
        }
    }
    KiReleaseDispatcherLock(flags);

    PspExitCurrentThread(exitStatus); /* never returns */
}

/* --- the Nt* surface -------------------------------------------------------- */

/* Find a live process by its unique id (CLIENT_ID.UniqueProcess); lock held.
 * The only by-id process lookup — NtOpenProcess and the toolhelp/taskkill
 * paths share it (G11). Returns 0 if no live process carries that id. */
static PEPROCESS PspFindProcessByProcessId(uint64_t processId)
{
    ASSERT(KiIsDispatcherLockHeld());
    for (PLIST_ENTRY p = PspActiveProcessListHead.Flink; p != &PspActiveProcessListHead;
         p = p->Flink)
    {
        PEPROCESS process = CONTAINING_RECORD(p, EPROCESS, activeProcessLinks);
        if (process->uniqueProcessId == processId)
        {
            return process;
        }
    }
    return 0;
}

/* The process owning a live thread id (CLIENT_ID.UniqueThread with a zero
 * UniqueProcess); lock held. */
static PEPROCESS PspFindProcessByThreadId(uint64_t threadId)
{
    ASSERT(KiIsDispatcherLockHeld());
    for (PLIST_ENTRY p = PspActiveProcessListHead.Flink; p != &PspActiveProcessListHead;
         p = p->Flink)
    {
        PEPROCESS process = CONTAINING_RECORD(p, EPROCESS, activeProcessLinks);
        for (PLIST_ENTRY t = process->threadListHead.Flink; t != &process->threadListHead;
             t = t->Flink)
        {
            if (CONTAINING_RECORD(t, ETHREAD, threadListEntry)->uniqueThreadId == threadId)
            {
                return process;
            }
        }
    }
    return 0;
}

/* CUI-4: flag one thread for foreign termination and get it moving toward its
 * reaping edge (lock held). A suspended thread must wake to die (drop its
 * holds, open its gate); a waiting thread has its wait aborted; a never-run
 * thread is readied so it descends and self-reaps at first entry. Shared by
 * foreign NtTerminateProcess/Thread, NtTerminateJobObject, and kill-on-job-
 * close (G11). */
void PspFlagThreadTermination(PKTHREAD tcb, NTSTATUS exitStatus)
{
    ASSERT(KiIsDispatcherLockHeld());
    tcb->terminating = TRUE;
    tcb->terminateStatus = exitStatus;
    tcb->suspendCount = 0;                   /* a suspended target must wake to die */
    tcb->suspendGate.header.signalState = 1; /* open the gate */
    KiWaitTest(&tcb->suspendGate.header);    /* wake a thread parked on the gate */
    if (tcb->state == KI_THREAD_STATE_WAITING)
    {
        KiAbortThreadWait(tcb); /* out of the wait, back to its reaping edge */
    }
    else if (tcb->state == KI_THREAD_STATE_INITIALIZED)
    {
        KiReadyThread(tcb); /* never ran: descend and self-reap at first entry */
    }
}

/* CUI-4: console-control delivery. The contract the PE stack expects is the
 * one wineserver implements (server/console.c propagate_console_signal) and
 * ntdll's unix side executes (signal_x86_64.c int_handler): for every process
 * attached to the console, START A NEW THREAD at ntdll's __wine_ctrl_routine
 * with the event code as its argument. That thread calls kernelbase's
 * CtrlRoutine, which raises DBG_CONTROL_C, then walks the process's handler
 * list (cmd's my_event_handler, msvcrt's SIGINT dispatch), defaulting to
 * RtlExitUserProcess(STATUS_CONTROL_C_EXIT). No APC can serve this: a user APC
 * only runs at an alertable wait, so it could never interrupt a busy loop.
 *
 * Attachment is `consoleHandle != 0` — proskrnl has ONE global console
 * (docs/03 M9), so a process either has its handles or it does not. */
#define PSP_MAX_CTRL_TARGETS 32

NTSTATUS PsPropagateConsoleCtrlEvent(ULONG event, uint64_t groupId)
{
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT)
    {
        /* The other CTRL_* codes have no wineserver delivery either
         * (propagate_console_signal maps only these two). */
        DbgPrint("ps: console ctrl event %u unimplemented\n", (unsigned)event);
        return STATUS_NOT_IMPLEMENTED;
    }

    /* Snapshot the targets under the lock, each pinned, so the injections
     * below (which allocate and can block) run with the lock dropped and
     * cannot race a process delete (G11). */
    PEPROCESS targets[PSP_MAX_CTRL_TARGETS];
    ULONG count = 0;
    uint64_t flags = KiAcquireDispatcherLock();
    for (PLIST_ENTRY entry = PspActiveProcessListHead.Flink;
         entry != &PspActiveProcessListHead && count < PSP_MAX_CTRL_TARGETS; entry = entry->Flink)
    {
        PEPROCESS process = CONTAINING_RECORD(entry, EPROCESS, activeProcessLinks);
        if (process->consoleHandle == 0 || process->ctrlRoutine == 0)
        {
            continue; /* not on the console, or no ntdll to deliver through */
        }
        if (process->header.signalState != 0 || process->activeThreadCount == 0)
        {
            continue; /* already exiting: nothing to deliver to */
        }
        if (groupId != 0 && process->processGroupId != groupId)
        {
            continue; /* GenerateConsoleCtrlEvent's group filter */
        }
        ObfReferenceObject(process);
        targets[count++] = process;
    }
    KiReleaseDispatcherLock(flags);

    for (ULONG i = 0; i < count; i++)
    {
        NTSTATUS status = PspInjectUserThread(targets[i], targets[i]->ctrlRoutine, event);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("ps: ctrl-event injection failed %08x\n", (unsigned)status);
        }
        ObDereferenceObject(targets[i]);
    }
    return STATUS_SUCCESS;
}

/* Flag every thread of a foreign process for termination (lock taken here). */
void PspTerminateProcessThreads(PEPROCESS process, NTSTATUS exitStatus)
{
    uint64_t flags = KiAcquireDispatcherLock();
    for (PLIST_ENTRY entry = process->threadListHead.Flink; entry != &process->threadListHead;
         entry = entry->Flink)
    {
        PspFlagThreadTermination(CONTAINING_RECORD(entry, ETHREAD, threadListEntry)->tcb,
                                 exitStatus);
    }
    KiReleaseDispatcherLock(flags);
}

NTSTATUS NtOpenProcess(HANDLE *processHandle, ACCESS_MASK desiredAccess,
                       const OBJECT_ATTRIBUTES *objectAttributes, const CLIENT_ID *clientId)
{
    /* The toolhelp path (dlls/kernelbase/process.c OpenProcess): a
     * CLIENT_ID, never a name. Open-by-name is not built (no baked caller);
     * a name in objectAttributes would refuse loudly. Contract from
     * wineserver's get_process_from_id (server/process.c): an id that never
     * belonged to a process is STATUS_INVALID_CID. Pinned by
     * sem_ps/open_process. */
    NTSTATUS status =
        KiProbeForWrite(processHandle, sizeof(*processHandle), sizeof(*processHandle));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (clientId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    status = KiProbeForRead(clientId, sizeof(*clientId), sizeof(uint64_t));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t processId = (uint64_t)(uintptr_t)clientId->UniqueProcess;
    uint64_t threadId = (uint64_t)(uintptr_t)clientId->UniqueThread;

    ULONG attributes = 0;
    if (objectAttributes != 0)
    {
        status = KiProbeForRead(objectAttributes, sizeof(*objectAttributes), sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        /* A named open is not the toolhelp path — refuse loudly (Art. 12). */
        if (objectAttributes->ObjectName != 0)
        {
            return STATUS_NOT_IMPLEMENTED;
        }
        attributes = objectAttributes->Attributes;
    }

    uint64_t flags = KiAcquireDispatcherLock();
    PEPROCESS process = 0;
    if (processId != 0)
    {
        process = PspFindProcessByProcessId(processId);
    }
    else if (threadId != 0)
    {
        process = PspFindProcessByThreadId(threadId);
    }
    if (process != 0)
    {
        ObfReferenceObject(process); /* pin across the lock drop */
    }
    KiReleaseDispatcherLock(flags);

    if (process == 0)
    {
        return STATUS_INVALID_CID;
    }
    status = ObpCreateHandle(process, ObpMapDesiredAccess(&PspProcessType, desiredAccess),
                             attributes, processHandle);
    ObDereferenceObject(process); /* the handle holds its own reference */
    return status;
}

/* CUI-4: suspend/resume every thread of a target process (server/process.c
 * suspend_process / resume_process). A thread blocked in a kernel wait is NOT
 * pulled out — the suspend takes effect at its next return to user mode
 * (PspSuspendTcb closes its gate, KiProcessPendingUserSignals parks it there),
 * which is exactly NT's "suspend applies on the way back to user mode". */
static NTSTATUS PspSuspendResumeProcess(HANDLE processHandle, BOOLEAN suspend)
{
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(processHandle, PROCESS_SUSPEND_RESUME,
                                                &PspProcessType, ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PEPROCESS process = body;

    uint64_t flags = KiAcquireDispatcherLock();
    for (PLIST_ENTRY entry = process->threadListHead.Flink; entry != &process->threadListHead;
         entry = entry->Flink)
    {
        PKTHREAD tcb = CONTAINING_RECORD(entry, ETHREAD, threadListEntry)->tcb;
        if (suspend)
        {
            PspSuspendTcb(tcb);
        }
        else
        {
            PspResumeTcb(tcb);
        }
    }
    KiReleaseDispatcherLock(flags);
    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

NTSTATUS NtSuspendProcess(HANDLE processHandle)
{
    return PspSuspendResumeProcess(processHandle, TRUE);
}

NTSTATUS NtResumeProcess(HANDLE processHandle)
{
    return PspSuspendResumeProcess(processHandle, FALSE);
}

NTSTATUS NtGetNextProcess(HANDLE processHandle, ACCESS_MASK desiredAccess, ULONG attributes,
                          ULONG flags, HANDLE *handleOut)
{
    /* The handle-returning process walk (the shape NtGetNextThread already
     * uses for threads). Contract from wineserver's get_next_process
     * (server/process.c): flags 0 walks the active list forward, 1 backward,
     * anything else refuses; last = 0 starts at the head/tail; each success
     * is a fresh handle; the walk ends with STATUS_NO_MORE_ENTRIES. The list
     * is re-scanned rather than chained off `last`'s links: a since-exited
     * `last` has left the active list (PspDeleteProcess unlinks it), so a
     * stale reference ends the walk gracefully. Pinned by
     * sem_ps/get_next_process. */
    if (flags > 1)
    {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = KiProbeForWrite(handleOut, sizeof(*handleOut), sizeof(*handleOut));
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PEPROCESS last = 0;
    if (processHandle != 0)
    {
        PVOID body;
        status = ObReferenceObjectByHandle(processHandle, 0, &PspProcessType, ExGetPreviousMode(),
                                           &body, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        last = body;
    }

    PEPROCESS found = 0;
    uint64_t lockFlags = KiAcquireDispatcherLock();
    BOOLEAN seen = (last == 0);
    PLIST_ENTRY head = &PspActiveProcessListHead;
    for (PLIST_ENTRY entry = flags ? head->Blink : head->Flink; entry != head;
         entry = flags ? entry->Blink : entry->Flink)
    {
        PEPROCESS candidate = CONTAINING_RECORD(entry, EPROCESS, activeProcessLinks);
        if (seen)
        {
            found = candidate;
            ObfReferenceObject(found); /* pins it across the lock drop */
            break;
        }
        if (candidate == last)
        {
            seen = TRUE;
        }
    }
    KiReleaseDispatcherLock(lockFlags);

    if (last != 0)
    {
        ObDereferenceObject(last);
    }
    if (found == 0)
    {
        return STATUS_NO_MORE_ENTRIES;
    }
    status = ObpCreateHandle(found, ObpMapDesiredAccess(&PspProcessType, desiredAccess), attributes,
                             handleOut);
    ObDereferenceObject(found); /* the handle holds its own reference */
    return status;
}

NTSTATUS NtTerminateProcess(HANDLE processHandle, LONG exitStatus)
{
    PKTHREAD thread = KeGetCurrentThread();

    /* NT: handle 0 means "every thread of this process but the caller", and
     * the call does not return until they are gone -- which is precisely
     * what RtlExitUserProcess relies on to drain siblings before it runs DLL
     * detach. This used to return STATUS_SUCCESS having terminated nothing:
     * a fabricated answer whose caller then ran detach routines against
     * threads still executing in the DLLs being detached
     * (docs/review-2026-07 §5). The old comment argued that the M7 clients
     * joined their threads first; the M10 Wine userland does not.
     *
     * Under Art. 3 a sibling reaps ITSELF at its next ring-3 edge, so the
     * flag-and-wake is only half the job -- the caller then has to wait for
     * the reaping to happen. The wait is bounded: a sibling wedged in a
     * kernel path that never returns to ring 3 must not hang the exit of
     * every process in the system, and returning after the deadline is no
     * worse than the unconditional success this replaces. */
    if (processHandle == 0)
    {
        PEPROCESS self = thread->process;
        uint64_t lockFlags = KiAcquireDispatcherLock();
        for (PLIST_ENTRY entry = self->threadListHead.Flink; entry != &self->threadListHead;
             entry = entry->Flink)
        {
            PKTHREAD tcb = CONTAINING_RECORD(entry, ETHREAD, threadListEntry)->tcb;
            if (tcb != thread)
            {
                PspFlagThreadTermination(tcb, (NTSTATUS)exitStatus);
            }
        }
        KiReleaseDispatcherLock(lockFlags);

        /* 5 s in 1 ms steps. KeDelayExecutionThread is also the yield that
         * lets the siblings run at all under the no-preemption model. */
        for (int waited = 0; waited < 5000; waited++)
        {
            lockFlags = KiAcquireDispatcherLock();
            LONG remaining = self->activeThreadCount;
            KiReleaseDispatcherLock(lockFlags);
            if (remaining <= 1)
            {
                break;
            }
            LARGE_INTEGER interval;
            interval.QuadPart = -10000; /* 1 ms, relative */
            if (KeDelayExecutionThread(KernelMode, FALSE, &interval) != STATUS_SUCCESS)
            {
                break; /* the caller itself is being terminated */
            }
        }
        return STATUS_SUCCESS;
    }

    PEPROCESS process;
    BOOLEAN referenced = FALSE;
    if (processHandle == NtCurrentProcess())
    {
        process = thread->process;
    }
    else
    {
        PVOID body;
        NTSTATUS status = ObReferenceObjectByHandle(processHandle, PROCESS_TERMINATE,
                                                    &PspProcessType, ExGetPreviousMode(), &body, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        process = body;
        referenced = TRUE;
    }

    if (process == thread->process)
    {
        if (referenced)
        {
            ObDereferenceObject(process);
        }
        PspExitCurrentProcess(exitStatus);
    }

    /* Foreign process (CUI-4 — taskkill): flag every thread and wake it; each
     * reaps ITSELF at its next return to user mode (Art. 3 — never torn down
     * from here). The last one to exit publishes process->exitStatus and
     * signals the process object, so the killer's exit code propagates and a
     * join completes. */
    PspTerminateProcessThreads(process, (NTSTATUS)exitStatus);
    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

/* NtCreateUserProcess (M8 wired the initial chain; M10 the full
 * CreateProcess contract). The caller names the image via
 * PS_ATTRIBUTE_IMAGE_NAME (an NT path, as kernelbase's create_nt_process
 * passes it — third_party/wine dlls/kernelbase/process.c) and gets real
 * process + thread handles, its RTL_USER_PROCESS_PARAMETERS threaded into
 * the child (with the wineserver console/std fixups), handle inheritance
 * (inherit-all or PS_ATTRIBUTE_HANDLE_LIST), a suspended initial thread
 * when THREAD_CREATE_FLAGS_CREATE_SUSPENDED, CLIENT_ID/IMAGE_INFO
 * write-backs, and the PS_CREATE_INFO success state. Pinned by
 * sem_ps/create_process.c + sem_ps/inherit.c. */
NTSTATUS NtCreateUserProcess(HANDLE *processHandle, HANDLE *threadHandle, ACCESS_MASK processAccess,
                             ACCESS_MASK threadAccess, OBJECT_ATTRIBUTES *processAttributes,
                             OBJECT_ATTRIBUTES *threadAttributes, ULONG processFlags,
                             ULONG threadFlags, RTL_USER_PROCESS_PARAMETERS *processParameters,
                             PS_CREATE_INFO *createInfo, PS_ATTRIBUTE_LIST *attributeList)
{
    (void)processAttributes;
    (void)threadAttributes;

    if (processHandle == 0 || threadHandle == 0 || createInfo == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(processHandle, sizeof(*processHandle), sizeof(HANDLE));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(threadHandle, sizeof(*threadHandle), sizeof(HANDLE));
    }
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(createInfo, sizeof(PS_CREATE_INFO), sizeof(uint64_t));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* Flags: INHERIT_HANDLES is real; SUSPENDED is subsumed by the thread's
     * own CREATE_SUSPENDED (kernelbase sets both for CREATE_SUSPENDED and
     * skips its NtResumeThread — dlls/kernelbase/process.c). Anything else a
     * caller sets is named on serial and refused (never faked — docs/03). */
    if ((processFlags &
         ~(ULONG)(PROCESS_CREATE_FLAGS_INHERIT_HANDLES | PROCESS_CREATE_FLAGS_SUSPENDED)) != 0)
    {
        DbgPrint("NtCreateUserProcess: unsupported process flags %#lx\n",
                 (unsigned long)processFlags);
        return STATUS_NOT_IMPLEMENTED;
    }
    BOOLEAN inheritHandles = (processFlags & PROCESS_CREATE_FLAGS_INHERIT_HANDLES) != 0;
    BOOLEAN createSuspended = (threadFlags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED) != 0 ||
                              (processFlags & PROCESS_CREATE_FLAGS_SUSPENDED) != 0;

    /* Walk the attribute list for the image name (+ optional CLIENT_ID
     * write-back); other attributes a Wine client passes are tolerated. */
    if (attributeList == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    status = KiProbeForRead(attributeList, sizeof(SIZE_T), sizeof(SIZE_T));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    SIZE_T totalLength = attributeList->TotalLength;
    SIZE_T listHeader = offsetof(PS_ATTRIBUTE_LIST, Attributes);
    if (totalLength < listHeader || totalLength > 0x1000 ||
        (totalLength - listHeader) % sizeof(PS_ATTRIBUTE) != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    status = KiProbeForRead(attributeList, totalLength, sizeof(SIZE_T));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    const WCHAR *imageNameUser = 0;
    SIZE_T imageNameBytes = 0;
    CLIENT_ID *clientIdOut = 0;
    SECTION_IMAGE_INFORMATION *imageInfoUser = 0;
    SIZE_T imageInfoBytes = 0;
    const HANDLE *handleListUser = 0;
    SIZE_T handleListBytes = 0;
    SIZE_T count = (totalLength - listHeader) / sizeof(PS_ATTRIBUTE);
    for (SIZE_T i = 0; i < count; i++)
    {
        const PS_ATTRIBUTE *attribute = &attributeList->Attributes[i];
        switch (attribute->Attribute)
        {
        case PS_ATTRIBUTE_IMAGE_NAME:
            imageNameUser = attribute->ValuePtr;
            imageNameBytes = attribute->Size;
            break;
        case PS_ATTRIBUTE_CLIENT_ID:
            clientIdOut = attribute->ValuePtr;
            break;
        case PS_ATTRIBUTE_IMAGE_INFO:
            imageInfoUser = attribute->ValuePtr;
            imageInfoBytes = attribute->Size;
            break;
        case PS_ATTRIBUTE_HANDLE_LIST:
            handleListUser = attribute->ValuePtr;
            handleListBytes = attribute->Size;
            break;
        default:
            /* Other input attributes a Wine client passes (PARENT_PROCESS,
             * TOKEN, MACHINE_TYPE, JOB_LIST...) are tolerated, exactly as
             * Wine's own implementation FIXMEs and continues. */
            break;
        }
    }
    if (imageNameUser == 0 || imageNameBytes == 0 || imageNameBytes > 0x8000 ||
        (imageNameBytes & 1) != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    status = KiProbeForRead(imageNameUser, imageNameBytes, 1);
    if (NT_SUCCESS(status) && clientIdOut != 0)
    {
        status = KiProbeForWrite(clientIdOut, sizeof(*clientIdOut), sizeof(uint64_t));
    }
    if (NT_SUCCESS(status) && imageInfoUser != 0)
    {
        status = KiProbeForWrite(imageInfoUser, imageInfoBytes, 1);
    }
    if (NT_SUCCESS(status) && handleListUser != 0 && handleListBytes != 0)
    {
        if (handleListBytes % sizeof(HANDLE) != 0 || handleListBytes > 0x10000)
        {
            status = STATUS_INVALID_PARAMETER;
        }
        else
        {
            status = KiProbeForRead(handleListUser, handleListBytes, sizeof(HANDLE));
        }
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* Kernel copies of the caller's inputs before anything can block. */
    HANDLE *handleList = 0;
    ULONG handleCount = 0;
    if (inheritHandles && handleListUser != 0 && handleListBytes != 0)
    {
        handleList = MiAllocatePool(handleListBytes);
        if (handleList == 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memcpy(handleList, handleListUser, handleListBytes);
        handleCount = (ULONG)(handleListBytes / sizeof(HANDLE));
    }
    PSP_CAPTURED_PARAMS *captured = 0;
    if (processParameters != 0)
    {
        status = PspCaptureProcessParameters(processParameters, &captured);
        if (!NT_SUCCESS(status))
        {
            if (handleList != 0)
            {
                MiFreePool(handleList);
            }
            return status;
        }
    }

    /* Pool copies: the NUL-terminated NT path, and the DOS-path spelling the
     * PEB carries (the NT path minus \??\; ASCII, as the PEB builder takes). */
    SIZE_T imageNameChars = imageNameBytes / sizeof(WCHAR);
    WCHAR *ntPath = MiAllocatePool((imageNameChars + 1) * sizeof(WCHAR));
    if (ntPath == 0)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out_inputs;
    }
    memcpy(ntPath, imageNameUser, imageNameBytes);
    ntPath[imageNameChars] = 0;

    SIZE_T dosSkip = 0;
    if (imageNameChars >= 4 && ntPath[0] == '\\' && ntPath[1] == '?' && ntPath[2] == '?' &&
        ntPath[3] == '\\')
    {
        dosSkip = 4;
    }
    char *dosPath = MiAllocatePool(imageNameChars - dosSkip + 1);
    if (dosPath == 0)
    {
        MiFreePool(ntPath);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out_inputs;
    }
    for (SIZE_T i = dosSkip; i < imageNameChars; i++)
    {
        dosPath[i - dosSkip] = ntPath[i] < 0x80 ? (char)ntPath[i] : '?';
    }
    dosPath[imageNameChars - dosSkip] = 0;

    PEPROCESS process;
    PETHREAD threadObject;
    SECTION_IMAGE_INFORMATION imageInfo;
    memset(&imageInfo, 0, sizeof(imageInfo));
    {
        PSP_CREATE_OPTIONS options;
        memset(&options, 0, sizeof(options));
        options.params = captured; /* ownership moves (freed on every path) */
        options.userParams = captured != 0;
        options.createSuspended = createSuspended;
        options.inheritHandles = inheritHandles;
        options.handleList = handleList;
        options.handleCount = handleCount;
        options.imageInfoOut = &imageInfo;
        captured = 0;
        status = PspCreateUserProcessImage(ntPath, dosPath, &options, &process, &threadObject);
    }
    MiFreePool(ntPath);
    if (handleList != 0)
    {
        MiFreePool(handleList);
        handleList = 0;
    }
    if (!NT_SUCCESS(status))
    {
        MiFreePool(dosPath);
        return status;
    }
    process->imageName = dosPath; /* PsRunUserImageEx stores the caller's
                                   * pointer; keep the pool copy instead */
    process->imageNamePooled = TRUE;

    status = ObpCreateHandle(process, ObpMapDesiredAccess(&PspProcessType, processAccess), 0,
                             processHandle);
    BOOLEAN processHandleMade = NT_SUCCESS(status);
    if (processHandleMade)
    {
        status = ObpCreateHandle(threadObject, ObpMapDesiredAccess(&PspThreadType, threadAccess), 0,
                                 threadHandle);
        if (!NT_SUCCESS(status))
        {
            /* The caller is about to be told the whole call failed, so it
             * will not close a handle it believes was never made -- the
             * process handle would leak for the life of the caller
             * (docs/review-2026-07 §7). Close it here; the process itself
             * runs on unparented, which is the pre-existing behaviour this
             * function documents below. */
            KPROCESSOR_MODE saved = KeGetCurrentThread()->previousMode;
            KeGetCurrentThread()->previousMode = KernelMode;
            NtClose(*processHandle);
            KeGetCurrentThread()->previousMode = saved;
            *processHandle = 0;
        }
    }
    if (NT_SUCCESS(status))
    {
        if (clientIdOut != 0)
        {
            clientIdOut->UniqueProcess = (HANDLE)(uintptr_t)process->uniqueProcessId;
            clientIdOut->UniqueThread = (HANDLE)(uintptr_t)threadObject->uniqueThreadId;
        }
        if (imageInfoUser != 0)
        {
            /* min(Size, actual) write-back, like every PS_ATTRIBUTE output
             * (Wine update_attr_list shape). */
            SIZE_T bytes = imageInfoBytes < sizeof(imageInfo) ? imageInfoBytes : sizeof(imageInfo);
            memcpy(imageInfoUser, &imageInfo, bytes);
        }
        PS_CREATE_INFO info;
        memset(&info, 0, sizeof(info));
        info.Size = sizeof(info);
        info.State = PsCreateSuccess;
        memcpy(createInfo, &info, sizeof(info));
    }
    /* Drop the creator references; the handles (and the thread's process
     * pin) keep everything alive. On a handle failure the process runs on
     * unparented and cleans itself up at exit — the thread's creator
     * reference is deliberately kept then (freeing a RUNNING thread's
     * ETHREAD would delete its live kernel stack; the object outlives the
     * unparented process instead). */
    if (NT_SUCCESS(status))
    {
        ObDereferenceObject(threadObject);
    }
    ObDereferenceObject(process);
    return status;

out_inputs:
    if (handleList != 0)
    {
        MiFreePool(handleList);
    }
    PspFreeCapturedParams(captured);
    return status;
}
