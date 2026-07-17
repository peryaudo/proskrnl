/* kernel/ps/process.c — processes as Ob objects + the M4 process lifecycle.
 *
 * A process is waitable (signalled at termination, never reset), owns the
 * per-process handle table and user address space, and at M4 carries
 * exactly one thread running a flat binary (docs/02). The heavy Ps pieces
 * — byte-exact TEB/PEB, NtCreateUserProcess, the user-mode dispatcher
 * return protocol — are M7; nothing here forecloses them.
 */
#include "kernel/ps/ps.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/pool.h"
#include "kernel/mm/section.h"
#include "kernel/syscall/syscall.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "arch/x86_64/mmu.h"

#include "abi/ntimage.h"

#include <stddef.h>

PEPROCESS PsInitialSystemProcess;

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
}

/* First code of a user thread, on its kernel stack: descend to ring 3 at the
 * flat binary's entry. CR3/GS/RSP0 were programmed by the context switch. */
static void PspUserThreadStartup(void *context)
{
    PEPROCESS process = context;
    KiEnterUserMode(process->entryRip, process->entryRsp);
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

/* Build the NT-shaped main-thread stack (M5, docs/02 "guard-page stack
 * growth"): reserve the whole region, commit `commit` bytes at the top, and
 * arm one PAGE_GUARD page below them; mm/fault.c grows the committed slice
 * downward a guard at a time. Publishes the region on the EPROCESS for the
 * fault path. */
static NTSTATUS PspAllocateUserStack(PEPROCESS process, uint64_t reserve, uint64_t commit,
                                     uint64_t *stackTopOut, uint64_t *stackLimitOut)
{
    reserve = (reserve + MI_ALLOCATION_GRANULARITY - 1) & ~(MI_ALLOCATION_GRANULARITY - 1);
    commit = (commit + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1ULL);
    if (commit < PAGE_SIZE)
    {
        commit = PAGE_SIZE;
    }
    /* Leave room for the guard page and at least one page of growth. */
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

/* Map a PE program through the section machinery — NtCreateSection +
 * NtMapViewOfSection's engines mapping the image IS the M5 milestone
 * artifact (docs/02). Returns the entry point and the image's stack shape. */
static NTSTATUS PspMapImage(PEPROCESS process, PKI_RAMDISK_FILE file, uint64_t *entryOut,
                            uint64_t *stackReserveOut, uint64_t *stackCommitOut)
{
    PMI_SECTION section;
    NTSTATUS status = MiCreateSection(0, PAGE_EXECUTE, SEC_IMAGE, file, &section);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t base = 0;
    uint64_t viewSize = 0;
    status = MiMapViewOfSection(section, &process->addressSpace, &base, 0, &viewSize, PAGE_EXECUTE);
    if (NT_SUCCESS(status)) /* STATUS_IMAGE_NOT_AT_BASE is a success code */
    {
        *entryOut = base + section->image->entryRva;
        *stackReserveOut = section->image->stackReserve;
        *stackCommitOut = section->image->stackCommit;
    }
    ObDereferenceObject(section); /* the view holds its own pin */
    return NT_SUCCESS(status) ? STATUS_SUCCESS : status;
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

    status = MiCreateAddressSpace(&process->addressSpace);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(process);
        return status;
    }

    uint64_t entry = 0;
    uint64_t stackReserve = PSP_STACK_RESERVE;
    uint64_t stackCommit = PSP_STACK_COMMIT;
    const unsigned char *magic = file->data;
    if (file->size >= 2 && magic[0] == 'M' && magic[1] == 'Z')
    {
        /* A PE image: loaded through a SEC_IMAGE section (M5). */
        status = PspMapImage(process, file, &entry, &stackReserve, &stackCommit);
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
        /* An M4 flat binary at its fixed base, RWX (it carries no section
         * table to say better); its entry point is its first byte. */
        uint64_t imageBase;
        status = PspAllocateUserRegion(process, PSP_IMAGE_BASE, file->size, PAGE_EXECUTE_READWRITE,
                                       &imageBase);
        if (NT_SUCCESS(status))
        {
            MiCopyToUserRange(&process->addressSpace, imageBase, file->data, file->size);
            entry = imageBase;
        }
    }

    /* Stack and TEB anywhere convenient (the engine's bottom-up scan). */
    uint64_t stackTop = 0;
    uint64_t stackLimit = 0;
    if (NT_SUCCESS(status))
    {
        status = PspAllocateUserStack(process, stackReserve, stackCommit, &stackTop, &stackLimit);
    }
    uint64_t tebBase = 0;
    if (NT_SUCCESS(status))
    {
        status = PspAllocateUserRegion(process, 0, PAGE_SIZE, PAGE_READWRITE, &tebBase);
    }
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(process); /* PspDeleteProcess unwinds the rest */
        return status;
    }

    /* The TEB begins with the NT_TIB (abi/ntpsapi.h pins the layout). The
     * remaining TEB fields arrive with M7. StackLimit is the lowest
     * committed non-guard page; mm/fault.c lowers it as the stack grows. */
    uint64_t tebFrame = MiTranslateUserPage(process->addressSpace.pml4Physical, tebBase, 0, 0);
    ASSERT(tebFrame != 0);
    NT_TIB *tib = MiPhysicalToVirtual(tebFrame);
    tib->StackBase = (PVOID)(uintptr_t)stackTop;
    tib->StackLimit = (PVOID)(uintptr_t)stackLimit;
    tib->Self = (struct _NT_TIB *)(uintptr_t)tebBase;

    process->teb = (void *)(uintptr_t)tebBase;
    process->entryRip = entry;
    process->entryRsp = stackTop;

    /* Everything the context switch and startup read is final; ready it. */
    process->mainThread = KiCreateThreadEx(8, PspUserThreadStartup, process, process, process->teb);
    *processOut = process;
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
    /* Wait on the process object (signalled at termination). The user thread
     * runs meanwhile; a blocked syscall inside it schedules back here. */
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

    /* Handles die in thread context (closing can cascade into object
     * deletes, which may take the dispatcher lock). The address space is
     * torn down later by PspDeleteProcess — we are still running on it. */
    ObpCloseAllHandles(&process->handleTable);
    process->exitStatus = exitStatus;

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

    /* NT: handle 0 means "every thread but the caller" (ntdll calls this
     * first when exiting). One thread per process at M4 — nothing to do. */
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

    /* Stopping a RUNNING foreign thread needs the M7 machinery (there is no
     * kernel preemption to interrupt it — Art. 3). No M4 caller does this. */
    ObDereferenceObject(process);
    return STATUS_NOT_IMPLEMENTED;
}
