/* kernel/syscall/uaccess.c — user-pointer validation (M4). See uaccess.h for
 * why a page-table walk is a sound probe here (Art. 3: commit maps
 * immediately, and the kernel never blocks between probe and access). */
#include "kernel/syscall/uaccess.h"
#include "kernel/ke/ke.h"
#include "kernel/ps/ps.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/virtual.h"
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

    PMI_ADDRESS_SPACE space = &KeGetCurrentThread()->process->addressSpace;
    uint64_t end = start + length;
    for (uint64_t page = start & ~(uint64_t)(PAGE_SIZE - 1); page < end; page += PAGE_SIZE)
    {
        int writable = 0;
        int present = 0;
        if (MiTranslateUserPage(space->pml4Physical, page, &writable, &present) == 0 || !present)
        {
            return STATUS_ACCESS_VIOLATION;
        }
        if (forWrite && !writable)
        {
            /* CUI-7 write-watch + CUI-9 COW: the probe IS the kernel's
             * write intent, and it is the single chokepoint every service
             * that writes a user buffer passes (Art. 11) — a clean watched
             * page marks here and a shared master page copies here,
             * exactly as the ring-3 store's fault would resolve. A claimed
             * copy that got no frame surfaces its own status
             * (STATUS_IN_PAGE_ERROR), never a silent master write. */
            NTSTATUS resolved;
            if (!MiResolveWriteFault(space, page, &resolved))
            {
                return STATUS_ACCESS_VIOLATION;
            }
            if (!NT_SUCCESS(resolved))
            {
                return resolved;
            }
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

uint64_t KiUserFaultRecoveryCount = 0;
uint64_t KiUserFaultRecoveryUnexpected = 0;

void KiArmFaultRecovery(PKI_FAULT_RECOVERY frame, const char *name, BOOLEAN expected)
{
    PKTHREAD thread = KeGetCurrentThread();
    /* Frames never nest: a service is the outermost thing a ring-3 entry
     * runs (syscalls do not nest — table.c asserts that too), and the kmt
     * arms are sequential. A second arm would silently orphan the first,
     * which is a wedge, so it is fatal here rather than surprising later. */
    ASSERT(thread->faultRecovery == 0);
    thread->faultRecoveryName = name;
    thread->faultRecoveryExpected = expected;
    thread->faultRecovery = frame;
}

void KiDisarmFaultRecovery(void)
{
    PKTHREAD thread = KeGetCurrentThread();
    thread->faultRecovery = 0;
    thread->faultRecoveryName = 0;
    thread->faultRecoveryExpected = FALSE;
}

void KiRecoverFromKernelFault(uint64_t faultAddress, uint64_t vector, uint64_t rip)
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
    const char *name = thread->faultRecoveryName != 0 ? thread->faultRecoveryName : "?";
    BOOLEAN expected = thread->faultRecoveryExpected;
    KiDisarmFaultRecovery();

    /* The ledger (uaccess.h): an unwind is a bug report unless the arming
     * site claimed it, so it is counted and named before the jump — a jump
     * runs no cleanup, so anything owed has to be paid here. */
    KiUserFaultRecoveryCount++;
    if (!expected)
    {
        KiUserFaultRecoveryUnexpected++;
    }
    DbgPrint("[UACCESS]%s %s va=%#018lx rip=%#018lx count=%lu\n", expected ? " expected" : "", name,
             (unsigned long)faultAddress, (unsigned long)rip,
             (unsigned long)KiUserFaultRecoveryCount);
    KiJumpFaultRecovery(frame, (ULONG)STATUS_ACCESS_VIOLATION);
}

/* --- probe tokens (issue #96 C; the contract is in uaccess.h) ------------- */

static KI_PROBE_TOKEN KiMintToken(void *base, uint64_t length)
{
    KI_PROBE_TOKEN token;
    token.base = base;
    token.length = length;
    PKTHREAD thread = KeGetCurrentThread();
    token.generation = thread != 0 ? thread->parkGeneration : 0;
    return token;
}

NTSTATUS KiProbeForReadToken(const void *address, uint64_t length, uint64_t alignment,
                             PKI_PROBE_TOKEN token)
{
    NTSTATUS status = KiProbeForRead(address, length, alignment);
    *token = KiMintToken((void *)(uintptr_t)address, NT_SUCCESS(status) ? length : 0);
    return status;
}

NTSTATUS KiProbeForWriteToken(void *address, uint64_t length, uint64_t alignment,
                              PKI_PROBE_TOKEN token)
{
    NTSTATUS status = KiProbeForWrite(address, length, alignment);
    *token = KiMintToken(address, NT_SUCCESS(status) ? length : 0);
    return status;
}

KI_PROBE_TOKEN KiKernelToken(void *base, uint64_t length)
{
    return KiMintToken(base, length);
}

void KiAssertProbeToken(const KI_PROBE_TOKEN *token, const void *address, uint64_t length)
{
    PKTHREAD thread = KeGetCurrentThread();
    uint64_t generation = thread != 0 ? thread->parkGeneration : 0;
    if (token->generation != generation)
    {
        DbgPrint("[PANIC] stale probe: token generation %lu, thread now at %lu (%lu parks since "
                 "the probe)\n",
                 (unsigned long)token->generation, (unsigned long)generation,
                 (unsigned long)(generation - token->generation));
        KiPanic("KiAssertProbeToken: a probe result was used across a park");
    }
    uint64_t start = (uint64_t)(uintptr_t)address;
    uint64_t base = (uint64_t)(uintptr_t)token->base;
    if (start < base || length > token->length || start - base > token->length - length)
    {
        DbgPrint("[PANIC] copy [%#lx,+%#lx) outside the probed [%#lx,+%#lx)\n",
                 (unsigned long)start, (unsigned long)length, (unsigned long)base,
                 (unsigned long)token->length);
        KiPanic("KiAssertProbeToken: the copy is not inside the probed range");
    }
}

void KiWriteUser(const KI_PROBE_TOKEN *token, void *destination, const void *source,
                 uint64_t length)
{
    KiAssertProbeToken(token, destination, length);
    memcpy(destination, source, length);
}

void KiReadUser(const KI_PROBE_TOKEN *token, void *destination, const void *source, uint64_t length)
{
    KiAssertProbeToken(token, source, length);
    memcpy(destination, source, length);
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
