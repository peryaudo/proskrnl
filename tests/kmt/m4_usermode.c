/* tests/kmt/m4_usermode.c — the M4 in-kernel suite (docs/02).
 *
 * The ring-3 half of M4 ("user-mode code allocates memory and waits on an
 * event via syscalls; a user crash is contained") is proven by the flat-
 * binary boot modules. This suite covers the piece a user binary cannot see
 * from inside: the mm/VAD engine itself, driven in kernel mode against a
 * scratch address space. The behaviours mirror the sem_mm/reserve_commit
 * oracle test (greened on Wine first, Art. 5); here we can also inspect the
 * page tables directly.
 *
 * Runs on a kernel thread; the engine is called directly. The scratch space
 * is never made current (CR3), so committed pages are checked through
 * MiTranslateUserPage, not by dereferencing them.
 */
#include "tests/kmt/kmt.h"
#include "kernel/mm/virtual.h"
#include "kernel/mm/phys.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/ke/ke.h"
#include "kernel/ps/ps.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/string.h"
#include "arch/x86_64/mmu.h"

#include "abi/ntmmapi.h"
#include "abi/ntstatus.h"

static int mapped(PMI_ADDRESS_SPACE space, uint64_t va, int *writable)
{
    int present = 0;
    uint64_t frame = MiTranslateUserPage(space->pml4Physical, va, writable, &present);
    return frame != 0 && present;
}

static void test_reserve_commit_engine(void)
{
    MI_ADDRESS_SPACE space;
    ok(MiCreateAddressSpace(&space) == STATUS_SUCCESS, "create address space");

    /* Reserve 64K; nothing is committed yet. */
    PVOID base = 0;
    SIZE_T size = 0x10000;
    NTSTATUS status = MiAllocateVirtualMemory(&space, &base, &size, MEM_RESERVE, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "reserve -> %08lx", (unsigned long)status);
    ok(((uint64_t)(uintptr_t)base & 0xFFFF) == 0, "reserve 64K aligned");
    ok(size == 0x10000, "reserve size %lx", (unsigned long)size);
    uint64_t vbase = (uint64_t)(uintptr_t)base;
    ok(!mapped(&space, vbase, 0), "reserved page not present");

    MEMORY_BASIC_INFORMATION mbi;
    ok(MiQueryVirtualMemoryBasic(&space, base, &mbi) == STATUS_SUCCESS, "query reserved");
    ok(mbi.State == MEM_RESERVE, "reserved State %lx", (unsigned long)mbi.State);
    ok(mbi.Protect == 0, "reserved Protect %lx", (unsigned long)mbi.Protect);
    ok(mbi.RegionSize == 0x10000, "reserved RegionSize %lx", (unsigned long)mbi.RegionSize);
    ok(mbi.AllocationProtect == PAGE_READWRITE, "reserved AllocationProtect %lx",
       (unsigned long)mbi.AllocationProtect);

    /* Commit the middle two pages (address rounds to a page). */
    PVOID commitAt = (PVOID)(uintptr_t)(vbase + 0x1000 + 0x123);
    size = 0x1000;
    status = MiAllocateVirtualMemory(&space, &commitAt, &size, MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "commit -> %08lx", (unsigned long)status);
    ok(commitAt == (PVOID)(uintptr_t)(vbase + 0x1000), "commit base rounded");
    ok(size == 0x2000, "commit size %lx", (unsigned long)size);

    int writable = 0;
    ok(mapped(&space, vbase + 0x1000, &writable) && writable, "committed page writable");
    ok(mapped(&space, vbase + 0x2000, 0), "second committed page present");
    ok(!mapped(&space, vbase, 0), "head still reserved");
    ok(!mapped(&space, vbase + 0x3000, 0), "tail still reserved");

    ok(MiQueryVirtualMemoryBasic(&space, (PVOID)(uintptr_t)(vbase + 0x1000), &mbi) ==
           STATUS_SUCCESS,
       "query committed");
    ok(mbi.State == MEM_COMMIT && mbi.RegionSize == 0x2000, "committed run State %lx size %lx",
       (unsigned long)mbi.State, (unsigned long)mbi.RegionSize);

    /* PAGE_NOACCESS commit: tracked as committed, mapped not-present. */
    PVOID noaccess = (PVOID)(uintptr_t)(vbase + 0x4000);
    size = 0x1000;
    status = MiAllocateVirtualMemory(&space, &noaccess, &size, MEM_COMMIT, PAGE_NOACCESS);
    ok(status == STATUS_SUCCESS, "commit NOACCESS -> %08lx", (unsigned long)status);
    ok(!mapped(&space, vbase + 0x4000, 0), "NOACCESS page not present");
    ok(MiQueryVirtualMemoryBasic(&space, noaccess, &mbi) == STATUS_SUCCESS, "query NOACCESS");
    ok(mbi.State == MEM_COMMIT && mbi.Protect == PAGE_NOACCESS, "NOACCESS State %lx Protect %lx",
       (unsigned long)mbi.State, (unsigned long)mbi.Protect);

    /* Invalid protection and bad type flags are rejected. */
    PVOID scratch = 0;
    size = 0x1000;
    ok(MiAllocateVirtualMemory(&space, &scratch, &size, MEM_RESERVE, 0xdead) ==
           STATUS_INVALID_PAGE_PROTECTION,
       "bad protect rejected");
    scratch = 0;
    size = 0x1000;
    ok(MiAllocateVirtualMemory(&space, &scratch, &size, MEM_TOP_DOWN, PAGE_READWRITE) ==
           STATUS_INVALID_PARAMETER,
       "no commit/reserve rejected");

    MiDeleteAddressSpace(&space);
}

static void test_free_conventions(void)
{
    /* Snapshot before anything: create + alloc + free + delete must net to
     * zero leaked frames (VADs, committed pages, and page tables all back). */
    uint64_t freeAtStart = MiGetFreePageCount();

    MI_ADDRESS_SPACE space;
    ok(MiCreateAddressSpace(&space) == STATUS_SUCCESS, "create address space");

    PVOID base = 0;
    SIZE_T size = 0x10000;
    NTSTATUS status =
        MiAllocateVirtualMemory(&space, &base, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "reserve+commit -> %08lx", (unsigned long)status);
    uint64_t vbase = (uint64_t)(uintptr_t)base;
    uint64_t freeBefore = MiGetFreePageCount();

    /* Zero-size decommit off base is FREE_VM_NOT_AT_BASE and changes nothing. */
    PVOID addr = (PVOID)(uintptr_t)(vbase + 0x1001);
    size = 0;
    ok(MiFreeVirtualMemory(&space, &addr, &size, MEM_DECOMMIT) == STATUS_FREE_VM_NOT_AT_BASE,
       "zero decommit off base");

    /* Straddling decommit rounds outward to whole pages. */
    addr = (PVOID)(uintptr_t)(vbase + 0x1FFF);
    size = 2;
    status = MiFreeVirtualMemory(&space, &addr, &size, MEM_DECOMMIT);
    ok(status == STATUS_SUCCESS, "decommit straddle -> %08lx", (unsigned long)status);
    ok(size == 0x2000 && addr == (PVOID)(uintptr_t)(vbase + 0x1000), "decommit rounded");
    ok(!mapped(&space, vbase + 0x1000, 0), "decommitted page gone");
    ok(mapped(&space, vbase, 0), "neighbour page survives decommit");
    ok(MiGetFreePageCount() == freeBefore + 2, "decommit returned 2 frames");

    /* Oversize release and off-base release are rejected. */
    addr = base;
    size = 0x20000;
    ok(MiFreeVirtualMemory(&space, &addr, &size, MEM_RELEASE) == STATUS_UNABLE_TO_FREE_VM,
       "oversize release");

    /* Full release frees the region and every remaining frame. */
    addr = (PVOID)(uintptr_t)(vbase + 0xFFF);
    size = 0;
    status = MiFreeVirtualMemory(&space, &addr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "release -> %08lx", (unsigned long)status);
    ok(size == 0x10000 && addr == base, "release whole region");

    MEMORY_BASIC_INFORMATION mbi;
    ok(MiQueryVirtualMemoryBasic(&space, base, &mbi) == STATUS_SUCCESS, "query freed");
    ok(mbi.State == MEM_FREE, "freed State %lx", (unsigned long)mbi.State);
    ok(mbi.AllocationBase == 0, "freed AllocationBase %p", mbi.AllocationBase);

    addr = base;
    size = 0;
    ok(MiFreeVirtualMemory(&space, &addr, &size, MEM_RELEASE) == STATUS_MEMORY_NOT_ALLOCATED,
       "double release");

    /* Deleting the space leaks no frames: the count returns to where it was
     * before MiCreateAddressSpace (KASAN + the free count agree). */
    MiDeleteAddressSpace(&space);
    ok(MiGetFreePageCount() == freeAtStart, "delete leaked frames (%lu vs %lu)",
       (unsigned long)MiGetFreePageCount(), (unsigned long)freeAtStart);
}

/* The bound every ring-3-supplied frame address is held to. Regression for
 * the arbitrary-kernel-write hole: the dispatch paths in kernel/ps/usermode.c
 * run with previousMode == KernelMode, so KiProbeForWrite short-circuits to
 * success there and this bound is the only thing standing between a
 * user-chosen RSP and a kernel-address memcpy. It must therefore hold
 * regardless of previous mode, which is why it is tested here rather than
 * through a probe. */
static void test_user_range_bound(void)
{
    /* Ordinary user addresses pass. */
    ok(KiIsUserRange(0x10000, 0x1000), "user range accepted");
    ok(KiIsUserRange(KI_USER_SPACE_LIMIT - 0x1000, 0x1000), "range ending exactly at the limit");

    /* A zero-length range is vacuously in bounds (the probes treat it as a
     * no-op too), including at an address that would otherwise be refused. */
    ok(KiIsUserRange(0xFFFF800000000000ULL, 0), "zero length is vacuously in bounds");

    /* Kernel addresses are refused. The higher half is mapped in every user
     * PML4 (MiCreateUserPml4 shares the top 256 slots), so a page-table walk
     * alone would have said "present and writable" here. */
    ok(!KiIsUserRange(0xFFFFFFFF80100000ULL, 0x5c0), "kernel image address refused");
    ok(!KiIsUserRange(0xFFFF800000000000ULL, 0x1000), "HHDM address refused");

    /* Straddling the limit is refused even though the base is a user address. */
    ok(!KiIsUserRange(KI_USER_SPACE_LIMIT - 0x800, 0x1000), "range straddling the limit refused");
    ok(!KiIsUserRange(KI_USER_SPACE_LIMIT, 0x1000), "range starting at the limit refused");

    /* base + size wrapping past 2^64 must not read as "small and in bounds".
     * KI_EXC_FRAME_SIZE past the very top of the address space is the shape
     * the exception dispatcher would compute from a hostile RSP. */
    ok(!KiIsUserRange(0xFFFFFFFFFFFFF000ULL, 0x2000), "wrapping range refused");
    ok(!KiIsUserRange(0xFFFFFFFFFFFFFFFFULL, 1), "wrap by one refused");
}

/* Regression for the process-parameter slot-sizing overflow. PspCaptureString
 * computed MaximumLength as (USHORT)(Length + sizeof(WCHAR)); Length is itself
 * a USHORT, so 0xFFFE wrapped to 0 and 0xFFFF to 1. PspBuildPeb then sizes
 * each string's slot in the parameter block from MaximumLength and copies
 * Length bytes into it, so the invariant that matters is
 * MaximumLength >= Length -- at 0 the slot vanished and the string was
 * dropped, at 1 a 16-byte slot took a 65535-byte memcpy into the pool.
 *
 * Driven here rather than from tests/ntapi because CreateProcessW clamps both
 * the command line and the window title to 32766 characters (Length 0xFFFC),
 * one and two bytes short of the wrap -- so no ring-3 caller going through
 * kernelbase can reach these lengths, and the ntapi pin in
 * sem_ps/create_process.c can only cover the largest REACHABLE string.
 * Capturing runs in KernelMode here, where the probes are no-ops by design,
 * which is exactly what lets the test hand over a maximal descriptor. */
static void test_param_capture_saturates(void)
{
    static WCHAR scratch[0x10000 / sizeof(WCHAR)];
    for (unsigned i = 0; i < sizeof(scratch) / sizeof(scratch[0]); i++)
    {
        scratch[i] = 'p';
    }

    /* 0xFFFE and 0xFFFF are the two wrapping lengths; 0xFFFC is the largest
     * that never wrapped, included so the normal case stays covered. */
    static const USHORT lengths[] = {0xFFFC, 0xFFFE, 0xFFFF};
    for (unsigned c = 0; c < sizeof(lengths) / sizeof(lengths[0]); c++)
    {
        RTL_USER_PROCESS_PARAMETERS params;
        memset(&params, 0, sizeof(params));
        params.Size = sizeof(params);
        params.AllocationSize = sizeof(params);
        params.CommandLine.Length = lengths[c];
        params.CommandLine.MaximumLength = lengths[c];
        params.CommandLine.Buffer = scratch;

        PSP_CAPTURED_PARAMS *captured = 0;
        NTSTATUS status = PspCaptureProcessParameters(&params, &captured);
        ok(status == STATUS_SUCCESS, "capture len %x -> %08lx", lengths[c], (unsigned long)status);
        if (!NT_SUCCESS(status) || captured == 0)
        {
            continue;
        }
        const UNICODE_STRING *out = &captured->strings[PSP_PARAM_COMMAND_LINE];
        ok(out->Length == lengths[c], "captured Length %x, wanted %x", out->Length, lengths[c]);
        /* The invariant PspBuildPeb's memcpy depends on. */
        ok(out->MaximumLength >= out->Length, "len %x: MaximumLength %x < Length %x", lengths[c],
           out->MaximumLength, out->Length);
        ok(out->Buffer != 0, "len %x: string dropped", lengths[c]);
        PspFreeCapturedParams(captured);
    }
}

/* The ring-0 fault recovery frame (kernel/syscall/uaccess.h,
 * kernel/syscall/recover.S). The system service dispatcher arms one around
 * every ring-3-originated service so that a fault on a user address inside a
 * service returns STATUS_ACCESS_VIOLATION instead of halting the machine; the
 * mechanism itself is invisible from ring 3, so it is convicted here.
 *
 * Without KiDispatchTrap's unwind hook this test does not fail — it takes the
 * whole kernel down with [PANIC] vector=14, which is exactly the failure mode
 * the review named as its highest-leverage single fix (§1b). The address
 * touched is a low user-space VA that no address space maps.
 *
 * `volatile` on the two locals is load-bearing, not decoration: after an
 * unwind every non-callee-saved local is indeterminate, so anything read on
 * that path has to live in memory. */
#define KMT_UNMAPPED_USER_VA 0x00000000000A5000ULL

static void test_kernel_fault_recovery(void)
{
    volatile int recovered = 0;
    volatile ULONG status = 0;
    PKTHREAD thread = KeGetCurrentThread();
    ok(thread->faultRecovery == 0, "no recovery frame armed on entry");

    /* The unwind ledger (issue #32 A3). This is the ONE place in the tree
     * that unwinds on purpose, so it is the one place that arms `expected`
     * — every other [UACCESS] line on any leg is a missing or stale probe,
     * and tests/run/uacheck.sh turns that leg red. `volatile` for the same
     * reason as the two above: read after an unwind. */
    volatile uint64_t countBefore = KiUserFaultRecoveryCount;
    volatile uint64_t unexpectedBefore = KiUserFaultRecoveryUnexpected;

    KI_FAULT_RECOVERY recovery;
    ULONG unwound = KiSetFaultRecovery(&recovery);
    if (unwound == 0)
    {
        KiArmFaultRecovery(&recovery, "kmt/test_kernel_fault_recovery", TRUE);
        /* A ring-0 read of an unmapped user address: #PF with CPL 0. */
        volatile const unsigned char *victim =
            (volatile const unsigned char *)(uintptr_t)KMT_UNMAPPED_USER_VA;
        unsigned char sink = *victim;
        (void)sink;
        ok(0, "ring-0 access to an unmapped user VA did not fault");
    }
    else
    {
        recovered = 1;
        status = unwound;
    }
    KiDisarmFaultRecovery();

    ok(recovered == 1, "unwound to the recovery frame");
    ok(status == (ULONG)STATUS_ACCESS_VIOLATION,
       "unwind status %08lx, wanted STATUS_ACCESS_VIOLATION", (unsigned long)status);

    /* A write faults the same way, and the frame is re-armable. */
    recovered = 0;
    KI_FAULT_RECOVERY second;
    if (KiSetFaultRecovery(&second) == 0)
    {
        KiArmFaultRecovery(&second, "kmt/test_kernel_fault_recovery", TRUE);
        volatile unsigned char *victim =
            (volatile unsigned char *)(uintptr_t)(KMT_UNMAPPED_USER_VA + 0x1000);
        *victim = 1;
        ok(0, "ring-0 write to an unmapped user VA did not fault");
    }
    else
    {
        recovered = 1;
    }
    KiDisarmFaultRecovery();
    ok(recovered == 1, "unwound to the second recovery frame");
    ok(KeGetCurrentThread()->faultRecovery == 0, "recovery frame disarmed after the unwind");

    /* Both unwinds were counted, and both were claimed. A recovery frame
     * that unwinds without counting is the §1b camouflage the ledger exists
     * to remove, so the count is convicted here rather than assumed: this
     * test is what proves a silent unwind cannot happen anywhere else. */
    ok(KiUserFaultRecoveryCount == countBefore + 2, "both unwinds counted (%lu -> %lu)",
       (unsigned long)countBefore, (unsigned long)KiUserFaultRecoveryCount);
    ok(KiUserFaultRecoveryUnexpected == unexpectedBefore,
       "a claimed unwind is not counted as unexpected (%lu -> %lu)",
       (unsigned long)unexpectedBefore, (unsigned long)KiUserFaultRecoveryUnexpected);

    /* CUI-8: the unwind restores the arm-time RFLAGS. The fault trap enters
     * through an interrupt gate (IF clear) and the jump unwind never
     * iretqs, so without the explicit restore this thread — a KERNEL-mode
     * caller with no sysret to reload flags — ran everything after this
     * test with interrupts masked; nothing noticed until the CUI-8 drain
     * points made the clock load-bearing (cui8_async.c's poll loop starved
     * it). Ring-3 services self-healed at sysret, which is why the M4..M9
     * suites stayed green over the masked clock for so long. */
    uint64_t rflagsAfter;
    __asm__ volatile("pushfq; popq %0" : "=r"(rflagsAfter));
    ok((rflagsAfter & 0x200) != 0, "IF restored across the unwind (rflags %#lx)",
       (unsigned long)rflagsAfter);
}

int kmt_run_m4(void)
{
    int before = kmt_failures;
    KMT_RUN(test_reserve_commit_engine);
    KMT_RUN(test_free_conventions);
    KMT_RUN(test_user_range_bound);
    KMT_RUN(test_param_capture_saturates);
    KMT_RUN(test_kernel_fault_recovery);
    return kmt_failures - before;
}
