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

int kmt_run_m4(void)
{
    int before = kmt_failures;
    KMT_RUN(test_reserve_commit_engine);
    KMT_RUN(test_free_conventions);
    return kmt_failures - before;
}
