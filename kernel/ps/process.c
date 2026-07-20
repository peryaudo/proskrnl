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
#include "arch/x86_64/mmu.h"

#include "abi/ntimage.h"
#include "abi/ntpsapi.h"

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
    if (process->mainThread != 0)
    {
        KiDeleteThread(process->mainThread);
    }
    if (process->imageNamePooled && process->imageName != 0)
    {
        MiFreePool((void *)process->imageName);
    }
    ObpDeleteHandleTable(&process->handleTable);
    if (process->addressSpace.pml4Physical != 0)
    {
        MiDeleteAddressSpace(&process->addressSpace);
    }
}

OBJECT_TYPE PspProcessType = {
    .name = "Process",
    .validAccess = PROCESS_ALL_ACCESS,
    .waitable = TRUE,
    .deleteProcedure = PspDeleteProcess,
};

/* Zero the M7 fields common to every process body. */
static void PspInitializeProcessCommon(PEPROCESS process)
{
    process->pebBase = 0;
    process->imageBase = 0;
    process->uniqueProcessId = 0;
    process->userExceptionDispatcher = 0;
    process->userApcDispatcher = 0;
    process->ldrInitializeThunk = 0;
    process->rtlUserThreadStart = 0;
    process->ntdllBase = 0;
    process->activeThreadCount = 0;
    process->nextThreadId = 0;
    InitializeListHead(&process->threadListHead);
    process->consoleHandle = 0;
    process->stdInput = 0;
    process->stdOutput = 0;
    process->stdError = 0;
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
    reserve = (reserve + MI_ALLOCATION_GRANULARITY - 1) & ~(MI_ALLOCATION_GRANULARITY - 1);
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

NTSTATUS PspCreateUserProcess(PKI_RAMDISK_FILE file, PEPROCESS *processOut)
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
        status = PspBuildPeb(process, imageBase, process->imageName, process->imageName);
    }
    if (NT_SUCCESS(status) && isPe)
    {
        process->nextThreadId = 0;
        status = PspBuildTeb(process, stackTop, stackLimit, process->uniqueProcessId,
                             ++process->nextThreadId, &tebBase);
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
    process->activeThreadCount = 1; /* the main thread (no ETHREAD wrapper) */

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
    process->mainThread = main;

    KiReadyCreatedThread(main);
    *processOut = process;
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

NTSTATUS PsCreateWineProcess(const WCHAR *exeNtPath, const char *imageDosPath, BOOLEAN console,
                             PEPROCESS *processOut)
{
    PMI_SECTION exeSection;
    NTSTATUS status = IoOpenImageSection(exeNtPath, &exeSection);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PMI_SECTION ntdllSection;
    status = IoOpenImageSection(PSP_NTDLL_PATH, &ntdllSection);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(exeSection);
        return status;
    }

    PVOID body;
    status = ObpAllocateObject(&PspProcessType, sizeof(EPROCESS), &body);
    if (!NT_SUCCESS(status))
    {
        goto out_sections;
    }
    PEPROCESS process = body;
    KiInitializeDispatcherHeader(&process->header, KI_OBJECT_PROCESS, 0);
    ObpInitializeHandleTable(&process->handleTable);
    process->imageName = imageDosPath;
    PspInitializeProcessCommon(process);
    process->uniqueProcessId = PspAllocateProcessId();

    status = MiCreateAddressSpace(&process->addressSpace);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(process);
        goto out_sections;
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
    /* M9: seed the console plumbing BEFORE the PEB so PspBuildPeb can write
     * the handle values into the process parameters. */
    if (NT_SUCCESS(status) && console)
    {
        status = CondrvCreateProcessHandles(process, &process->consoleHandle, &process->stdInput,
                                            &process->stdOutput, &process->stdError);
    }
    if (NT_SUCCESS(status))
    {
        status = PspBuildPeb(process, imageBase, imageDosPath, imageDosPath);
    }
    uint64_t tebBase = 0;
    if (NT_SUCCESS(status))
    {
        process->nextThreadId = 0;
        status = PspBuildTeb(process, stackTop, stackLimit, process->uniqueProcessId,
                             ++process->nextThreadId, &tebBase);
    }
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(process); /* PspDeleteProcess unwinds the rest */
        goto out_sections;
    }

    process->teb = (void *)(uintptr_t)tebBase;
    process->entryRip = entry;
    process->entryRsp = stackTop;
    process->activeThreadCount = 1;

    PKTHREAD main = KiCreateThreadSuspended(8, PspUserThreadStartup, 0, process, process->teb);
    if (main == 0)
    {
        ObDereferenceObject(process);
        status = STATUS_NO_MEMORY;
        goto out_sections;
    }
    /* The NT protocol (PspEnterUserThread): CONTEXT.Rcx = the image entry,
     * CONTEXT.Rdx = the PEB — what Wine's unix loader seeds for the first
     * thread (init_syscall_frame) and RtlUserThreadStart expects. */
    main->userStartRip = 0;
    main->userStartArg1 = entry;
    main->userStartArg2 = process->pebBase;
    main->userStartRsp = (stackTop & ~(uint64_t)0xf) - 0x28;
    process->mainThread = main;

    KiReadyCreatedThread(main);
    *processOut = process;
    status = STATUS_SUCCESS;

out_sections:
    ObDereferenceObject(ntdllSection); /* the views hold their own pins */
    ObDereferenceObject(exeSection);
    return status;
}

/* Run a Wine-loaded PE to completion (the M7 acceptance runner). */
NTSTATUS PsRunWineImage(const WCHAR *exeNtPath, const char *imageDosPath, BOOLEAN console,
                        NTSTATUS *exitStatusOut)
{
    PEPROCESS process;
    NTSTATUS status = PsCreateWineProcess(exeNtPath, imageDosPath, console, &process);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = KeWaitForSingleObject(process, Executive, KernelMode, FALSE, 0);
    ASSERT(status == STATUS_SUCCESS);
    *exitStatusOut = process->exitStatus;
    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

NTSTATUS PsRunBootModule(PKI_RAMDISK_FILE file, NTSTATUS *exitStatusOut)
{
    PEPROCESS process;
    NTSTATUS status = PspCreateUserProcess(file, &process);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = KeWaitForSingleObject(process, Executive, KernelMode, FALSE, 0);
    ASSERT(status == STATUS_SUCCESS);
    *exitStatusOut = process->exitStatus;
    ObDereferenceObject(process); /* the creator reference; PspDeleteProcess frees it */
    return STATUS_SUCCESS;
}

__attribute__((noreturn)) void PspExitCurrentProcess(NTSTATUS exitStatus)
{
    PKTHREAD thread = KeGetCurrentThread();
    PEPROCESS process = thread->process;
    ASSERT(process != PsInitialSystemProcess);

    /* Handles die in thread context (closing can cascade into object deletes,
     * which may take the dispatcher lock). The address space is torn down
     * later by PspDeleteProcess — we are still running on it. */
    ObpCloseAllHandles(&process->handleTable);
    process->exitStatus = exitStatus;
    KiTraceEvent(KiTraceProcessExit, (uint64_t)(uintptr_t)process, (uint64_t)(uint32_t)exitStatus,
                 0);

    uint64_t flags = KiAcquireDispatcherLock();
    process->header.signalState = 1; /* never reset: joins always satisfy */
    KiWaitTest(&process->header);
    KiReleaseDispatcherLock(flags);

    KiTerminateThread();
}

/* --- the Nt* surface -------------------------------------------------------- */

NTSTATUS NtTerminateProcess(HANDLE processHandle, LONG exitStatus)
{
    PKTHREAD thread = KeGetCurrentThread();

    /* NT: handle 0 means "every thread but the caller" (ntdll calls this first
     * when exiting). With the single-CPU no-preemption model foreign threads
     * stop only at their own syscalls; the M7 clients join their threads
     * before exiting, so there is nothing to stop here. */
    if (processHandle == 0)
    {
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

    ObDereferenceObject(process);
    return STATUS_NOT_IMPLEMENTED; /* stopping a foreign process: unbuilt (Art. 3) */
}

/* NtCreateUserProcess: the common single-image spawn, wired for M8's
 * initial process chain (smss-equivalent -> next process). The caller names
 * the image via PS_ATTRIBUTE_IMAGE_NAME (an NT path, as ntdll passes it —
 * wine dlls/ntdll/unix/process.c NtCreateUserProcess reads the same
 * attribute) and gets real process + thread handles, the PS_CREATE_INFO
 * success state, and CLIENT_ID write-back when requested. Still unbuilt
 * (docs/03 M8 notes): caller-supplied process parameters (the PEB's
 * RTL_USER_PROCESS_PARAMETERS are kernel-built from the image path),
 * suspended creation, and the pre-success PS_CREATE_INFO stages — refused
 * loudly, never faked. */
NTSTATUS NtCreateUserProcess(HANDLE *processHandle, HANDLE *threadHandle, ACCESS_MASK processAccess,
                             ACCESS_MASK threadAccess, OBJECT_ATTRIBUTES *processAttributes,
                             OBJECT_ATTRIBUTES *threadAttributes, ULONG processFlags,
                             ULONG threadFlags, RTL_USER_PROCESS_PARAMETERS *processParameters,
                             PS_CREATE_INFO *createInfo, PS_ATTRIBUTE_LIST *attributeList)
{
    (void)processAttributes;
    (void)threadAttributes;
    (void)processParameters; /* PEB params are kernel-built (docs/03) */

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
    if (processFlags != 0 || (threadFlags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED) != 0)
    {
        return STATUS_NOT_IMPLEMENTED; /* suspended/flagged creation: unbuilt */
    }

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
        default:
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
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* Pool copies: the NUL-terminated NT path, and the DOS-path spelling the
     * PEB carries (the NT path minus \??\; ASCII, as the PEB builder takes). */
    SIZE_T imageNameChars = imageNameBytes / sizeof(WCHAR);
    WCHAR *ntPath = MiAllocatePool((imageNameChars + 1) * sizeof(WCHAR));
    if (ntPath == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
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
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    for (SIZE_T i = dosSkip; i < imageNameChars; i++)
    {
        dosPath[i - dosSkip] = ntPath[i] < 0x80 ? (char)ntPath[i] : '?';
    }
    dosPath[imageNameChars - dosSkip] = 0;

    PEPROCESS process;
    /* M9: NtCreateUserProcess children inherit the (single) console —
     * kernelbase in the child binds via the seeded ConsoleHandle. */
    status = PsCreateWineProcess(ntPath, dosPath, TRUE, &process);
    MiFreePool(ntPath);
    if (!NT_SUCCESS(status))
    {
        MiFreePool(dosPath);
        return status;
    }
    process->imageName = dosPath; /* PsCreateWineProcess stored the caller's
                                   * pointer; keep the pool copy instead */
    process->imageNamePooled = TRUE;

    /* Give the (already readied, not yet run — nothing here blocks, Art. 3)
     * main thread its ETHREAD, so the returned thread handle is a real
     * thread object. PsCreateWineProcess pre-counted the thread and stamped
     * the TEB with id 1; reset both so PspCreateThreadObject's bookkeeping
     * recounts to the same values. */
    process->activeThreadCount = 0;
    process->nextThreadId = 0;
    PETHREAD threadObject;
    status = PspCreateThreadObject(process, process->mainThread, (uint64_t)(uintptr_t)process->teb,
                                   0, 0, &threadObject);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(process);
        return status;
    }
    process->mainThread = 0; /* the ETHREAD owns the KTHREAD now */

    status = ObpCreateHandle(process, ObpMapDesiredAccess(&PspProcessType, processAccess), 0,
                             processHandle);
    if (NT_SUCCESS(status))
    {
        status = ObpCreateHandle(threadObject, ObpMapDesiredAccess(&PspThreadType, threadAccess), 0,
                                 threadHandle);
    }
    if (NT_SUCCESS(status))
    {
        if (clientIdOut != 0)
        {
            clientIdOut->UniqueProcess = (HANDLE)(uintptr_t)process->uniqueProcessId;
            clientIdOut->UniqueThread = (HANDLE)(uintptr_t)threadObject->uniqueThreadId;
        }
        PS_CREATE_INFO info;
        memset(&info, 0, sizeof(info));
        info.Size = sizeof(info);
        info.State = PsCreateSuccess;
        memcpy(createInfo, &info, sizeof(info));
    }
    /* Drop the creator references; the handles (and the thread's process
     * pin) keep everything alive. On a handle failure the process runs on
     * unparented and cleans itself up at exit. */
    ObDereferenceObject(threadObject);
    ObDereferenceObject(process);
    return status;
}
