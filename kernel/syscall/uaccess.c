/* kernel/syscall/uaccess.c — user-pointer validation (M4). See uaccess.h for
 * why a page-table walk is a sound probe here (Art. 3: commit maps
 * immediately, and the kernel never blocks between probe and access). */
#include "kernel/syscall/uaccess.h"
#include "kernel/ke/ke.h"
#include "kernel/ps/ps.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "kernel/mm/phys.h"
#include "arch/x86_64/mmu.h"

KPROCESSOR_MODE ExGetPreviousMode(void)
{
    return KeGetCurrentThread()->previousMode;
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
    if (start + length < start || start + length > KI_USER_SPACE_LIMIT)
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
