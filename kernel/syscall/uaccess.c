/* kernel/syscall/uaccess.c — user-pointer validation (M4). See uaccess.h for
 * why a page-table walk is a sound probe here (Art. 3: commit maps
 * immediately, and the kernel never blocks between probe and access). */
#include "kernel/syscall/uaccess.h"
#include "kernel/ke/ke.h"
#include "kernel/ps/ps.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "kernel/mm/phys.h"
#include "kernel/lib/dbgprint.h"
#include "arch/x86_64/mmu.h"

KPROCESSOR_MODE ExGetPreviousMode(void)
{
    return KeGetCurrentThread()->previousMode;
}

BOOLEAN KiIsUserRange(uint64_t base, uint64_t size)
{
    if (size == 0)
    {
        return TRUE;
    }
    if (base + size < base) /* wraps past the top of the address space */
    {
        return FALSE;
    }
    return base + size <= KI_USER_SPACE_LIMIT;
}

static NTSTATUS KiProbeRange(const void *address, uint64_t length, uint64_t alignment, int forWrite)
{
    if (ExGetPreviousMode() == KernelMode)
    {
        return STATUS_SUCCESS;
    }
    if (length == 0)
    {
        return STATUS_SUCCESS;
    }
    uint64_t start = (uint64_t)(uintptr_t)address;
    ASSERT(alignment != 0 && (alignment & (alignment - 1)) == 0);
    if ((start & (alignment - 1)) != 0)
    {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    if (!KiIsUserRange(start, length))
    {
        return STATUS_ACCESS_VIOLATION;
    }

    uint64_t pml4 = KeGetCurrentThread()->process->addressSpace.pml4Physical;
    uint64_t end = start + length;
    for (uint64_t page = start & ~(uint64_t)(PAGE_SIZE - 1); page < end; page += PAGE_SIZE)
    {
        int writable = 0;
        int present = 0;
        if (MiTranslateUserPage(pml4, page, &writable, &present) == 0 || !present ||
            (forWrite && !writable))
        {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS KiProbeForRead(const void *address, uint64_t length, uint64_t alignment)
{
    return KiProbeRange(address, length, alignment, 0);
}

NTSTATUS KiProbeForWrite(void *address, uint64_t length, uint64_t alignment)
{
    return KiProbeRange(address, length, alignment, 1);
}

void KiRecoverFromKernelFault(uint64_t faultAddress, uint64_t vector)
{
    PKTHREAD thread = KeGetCurrentThread();
    if (thread == 0 || thread->faultRecovery == 0)
    {
        return; /* nothing armed: a kernel bug, and the caller panics */
    }
    /* Only a USER address unwinds. A ring-0 fault on a kernel address is
     * never a bad-user-pointer bug, and swallowing it would hide exactly the
     * class the panic dump exists to convict (Art. 9). Vector 14 (#PF) and 12
     * (#SS) are the only ones a stray pointer produces; anything else in ring
     * 0 is a control-flow bug, not a data one. */
    if (vector != 14 && vector != 12)
    {
        return;
    }
    if (!KiIsUserRange(faultAddress, 1))
    {
        return;
    }

    PKI_FAULT_RECOVERY frame = (PKI_FAULT_RECOVERY)thread->faultRecovery;
    thread->faultRecovery = 0;
    DbgPrint("[KTEST] uaccess RECOVER va=%#018lx (unwinding the service)\n",
             (unsigned long)faultAddress);
    KiJumpFaultRecovery(frame, (ULONG)STATUS_ACCESS_VIOLATION);
}

NTSTATUS KiCopyFromUser(void *destination, const void *userSource, uint64_t length)
{
    NTSTATUS status = KiProbeForRead(userSource, length, 1);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    memcpy(destination, userSource, length);
    return STATUS_SUCCESS;
}
