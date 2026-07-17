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
#include "kernel/syscall/syscall.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "arch/x86_64/mmu.h"

#include <stddef.h>

PEPROCESS PsInitialSystemProcess;

#define PSP_USER_STACK_SIZE (64ULL * 1024)

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

/* Copy into user pages through the HHDM (the target may not be the current
 * address space). The range must be freshly committed. */
static void PspCopyToUserPages(PEPROCESS process, uint64_t userBase, const void *source,
                               uint64_t length)
{
    const char *from = source;
    uint64_t copied = 0;
    while (copied < length)
    {
        uint64_t va = userBase + copied;
        uint64_t pageOffset = va & (PAGE_SIZE - 1);
        uint64_t chunk = PAGE_SIZE - pageOffset;
        if (chunk > length - copied)
        {
            chunk = length - copied;
        }
        uint64_t frame =
            MiTranslateUserPage(process->addressSpace.pml4Physical, va - pageOffset, 0, 0);
        ASSERT(frame != 0);
        memcpy((char *)MiPhysicalToVirtual(frame) + pageOffset, from + copied, chunk);
        copied += chunk;
    }
}

NTSTATUS PspCreateUserProcess(const char *imageName, const void *image, uint64_t imageSize,
                              PEPROCESS *processOut)
{
    if (imageSize == 0)
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
    process->imageName = imageName;

    status = MiCreateAddressSpace(&process->addressSpace);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(process);
        return status;
    }

    /* The image at its fixed flat-binary base, RWX (a flat binary carries no
     * section table to say better — the PE loader that will is M5/M7). */
    uint64_t imageBase;
    status = PspAllocateUserRegion(process, PSP_IMAGE_BASE, imageSize, PAGE_EXECUTE_READWRITE,
                                   &imageBase);

    /* Stack and TEB anywhere convenient (the engine's bottom-up scan). */
    uint64_t stackBase = 0;
    if (NT_SUCCESS(status))
    {
        status = PspAllocateUserRegion(process, 0, PSP_USER_STACK_SIZE, PAGE_READWRITE, &stackBase);
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

    PspCopyToUserPages(process, imageBase, image, imageSize);

    /* The TEB begins with the NT_TIB (abi/ntpsapi.h pins the layout). The
     * remaining TEB fields arrive with M7. */
    uint64_t stackTop = stackBase + PSP_USER_STACK_SIZE;
    uint64_t tebFrame = MiTranslateUserPage(process->addressSpace.pml4Physical, tebBase, 0, 0);
    ASSERT(tebFrame != 0);
    NT_TIB *tib = MiPhysicalToVirtual(tebFrame);
    tib->StackBase = (PVOID)(uintptr_t)stackTop;
    tib->StackLimit = (PVOID)(uintptr_t)stackBase;
    tib->Self = (struct _NT_TIB *)(uintptr_t)tebBase;

    process->teb = (void *)(uintptr_t)tebBase;
    process->entryRip = imageBase;
    process->entryRsp = stackTop;

    /* Everything the context switch and startup read is final; ready it. */
    process->mainThread = KiCreateThreadEx(8, PspUserThreadStartup, process, process, process->teb);
    *processOut = process;
    return STATUS_SUCCESS;
}

NTSTATUS PsRunBootModule(const char *imageName, const void *image, uint64_t imageSize,
                         NTSTATUS *exitStatusOut)
{
    PEPROCESS process;
    NTSTATUS status = PspCreateUserProcess(imageName, image, imageSize, &process);
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
