/*
 * sem_mm/reserve_commit.c — the NtAllocateVirtualMemory reserve/commit
 * two-step and its NtFreeVirtualMemory / NtQueryVirtualMemory conventions
 * (M4, docs/02).
 *
 * Distilled from Wine's dlls/ntdll/tests/virtual.c (the decommit/release
 * rounding corners are those exact ok()s) plus the parameter and
 * MemoryBasicInformation conventions of Wine's implementation
 * (dlls/ntdll/unix/virtual.c). Everything here is green on the pinned Wine
 * oracle before the kernel implements it (Art. 5).
 */
#include "util.h"

START_TEST(reserve_commit)
{
    NTSTATUS status;
    char *base, *p;
    void *addr;
    SIZE_T size, retlen;
    MEMORY_BASIC_INFORMATION mbi;

    /* --- parameter conventions ------------------------------------------ */

    addr = NULL;
    size = 0;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_RESERVE | MEM_COMMIT,
                                     PAGE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER, "zero size -> %08lx", (unsigned long)status);

    addr = NULL;
    size = 0x1000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, 0, PAGE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER, "type 0 -> %08lx", (unsigned long)status);

    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_DECOMMIT, PAGE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER, "bad type bits -> %08lx", (unsigned long)status);

    /* A size larger than the working-set limit is refused BEFORE any page
     * rounding happens. The oracle's rule is one line: allocate_virtual_memory
     * opens with `if (is_beyond_limit( 0, size, working_set_limit )) return
     * STATUS_WORKING_SET_LIMIT_RANGE;` (third_party/wine
     * dlls/ntdll/unix/virtual.c), and working_set_limit starts at
     * 0x7fffffff0000 -- the same user-space limit the rest of the boundary
     * uses -- so the test is just `size > limit`.
     *
     * Ordering is the whole point. These sizes round up to zero, and proskrnl
     * computed MiRoundUp(base + size, PAGE_SIZE) - base with no overflow
     * guard, while the size==0 rejection above it ran on the PRE-rounding
     * value. A rounded size of 0 therefore reached MiCreateVad and then
     * MiAllocatePool(0), which is a KiPanic: one syscall, any process, whole
     * machine. Note 0x40000002 is not an NT_ERROR, so a caller checking
     * NT_SUCCESS sees this as a (zero-page) success -- pinning the exact
     * value, not just "it failed", is what keeps that faithful. */
    addr = NULL;
    size = ~(SIZE_T)0 - 0xFFE; /* 0xFFFFFFFFFFFFF001: rounds up to 0 */
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_RESERVE | MEM_COMMIT,
                                     PAGE_READWRITE);
    ok(status == STATUS_WORKING_SET_LIMIT_RANGE, "wrapping size (no base) -> %08lx",
       (unsigned long)status);

    addr = (void *)0x10000; /* explicit base: the rounding is base-relative */
    size = ~(SIZE_T)0 - 0xFFE;
    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_RESERVE, PAGE_READWRITE);
    ok(status == STATUS_WORKING_SET_LIMIT_RANGE, "wrapping size (explicit base) -> %08lx",
       (unsigned long)status);

    /* Ordering against the type check. The oracle validates the type mask in
     * NtAllocateVirtualMemory itself (third_party/wine
     * dlls/ntdll/unix/virtual.c, `if (type & ~type_mask) return
     * STATUS_INVALID_PARAMETER;`) and only then calls allocate_virtual_memory,
     * where the working-set test lives -- so a bad type outranks an oversized
     * size. Pinning it because it is easy to get backwards: putting the
     * working-set test first looks equivalent until both arguments are wrong
     * at once. */
    addr = NULL;
    size = ~(SIZE_T)0 - 0xFFE;
    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_DECOMMIT, PAGE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER, "bad type + wrapping size -> %08lx",
       (unsigned long)status);

    /* The boundary itself. is_beyond_limit is `addr >= limit || addr + size >
     * limit` with addr == 0, so it reduces to a strict `size > limit`:
     * exactly the limit is NOT beyond and falls through to an ordinary
     * out-of-memory, one byte over it is. Pinning both sides keeps the
     * comparison from drifting to >= later. */
    addr = NULL;
    size = (SIZE_T)0x7fffffff0000;
    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_RESERVE, PAGE_READWRITE);
    ok(status == STATUS_NO_MEMORY, "size == limit -> %08lx", (unsigned long)status);

    addr = NULL;
    size = (SIZE_T)0x7fffffff0000 + 1;
    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_RESERVE, PAGE_READWRITE);
    ok(status == STATUS_WORKING_SET_LIMIT_RANGE, "size == limit + 1 -> %08lx",
       (unsigned long)status);

    /* --- reserve, then query the reserved region ------------------------- */

    base = NULL;
    size = 0x10000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), (void **)&base, 0, &size, MEM_RESERVE,
                                     PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "reserve -> %08lx", (unsigned long)status);
    ok(((ULONG_PTR)base & 0xFFFF) == 0, "base %p not 64K aligned", base);
    ok(size == 0x10000, "reserve size %lx", (unsigned long)size);

    retlen = 0;
    status = NtQueryVirtualMemory(NtCurrentProcess(), base, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), &retlen);
    ok(status == STATUS_SUCCESS, "query reserved -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(mbi), "query retlen %lu", (unsigned long)retlen);
    ok(mbi.BaseAddress == base, "BaseAddress %p, expected %p", mbi.BaseAddress, base);
    ok(mbi.AllocationBase == base, "AllocationBase %p, expected %p", mbi.AllocationBase, base);
    ok(mbi.AllocationProtect == PAGE_READWRITE, "AllocationProtect %lx",
       (unsigned long)mbi.AllocationProtect);
    ok(mbi.RegionSize == 0x10000, "RegionSize %lx", (unsigned long)mbi.RegionSize);
    ok(mbi.State == MEM_RESERVE, "State %lx", (unsigned long)mbi.State);
    ok(mbi.Protect == 0, "reserved Protect %lx, expected 0", (unsigned long)mbi.Protect);
    ok(mbi.Type == MEM_PRIVATE, "Type %lx", (unsigned long)mbi.Type);

    status = NtQueryVirtualMemory(NtCurrentProcess(), base, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi) - 1, &retlen);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short query buffer -> %08lx", (unsigned long)status);

    /* --- commit inside the reservation; addresses round to pages --------- */

    p = base + 0x1000 + 0x123;
    size = 0x1000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), (void **)&p, 0, &size, MEM_COMMIT,
                                     PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "commit -> %08lx", (unsigned long)status);
    ok(p == base + 0x1000, "commit base %p, expected %p", p, base + 0x1000);
    ok(size == 0x2000, "commit size %lx, expected 2000", (unsigned long)size);

    p[0] = 0x5a; /* the committed pages must be usable... */
    p[0x1FFF] = (char)0xa5;
    ok(p[0] == 0x5a && p[0x1FFF] == (char)0xa5, "committed memory not readable back");
    ok(p[0x100] == 0, "...and demand-zeroed, got %02x", p[0x100]);

    status = NtQueryVirtualMemory(NtCurrentProcess(), base + 0x1000, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), NULL);
    ok(status == STATUS_SUCCESS, "query committed -> %08lx", (unsigned long)status);
    ok(mbi.State == MEM_COMMIT, "committed State %lx", (unsigned long)mbi.State);
    ok(mbi.Protect == PAGE_READWRITE, "committed Protect %lx", (unsigned long)mbi.Protect);
    ok(mbi.AllocationBase == base, "committed AllocationBase %p", mbi.AllocationBase);
    ok(mbi.RegionSize == 0x2000, "committed RegionSize %lx", (unsigned long)mbi.RegionSize);

    /* The still-reserved head and tail runs bracket the committed pages. */
    status = NtQueryVirtualMemory(NtCurrentProcess(), base, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), NULL);
    ok(status == STATUS_SUCCESS, "query head -> %08lx", (unsigned long)status);
    ok(mbi.State == MEM_RESERVE && mbi.RegionSize == 0x1000, "head State %lx RegionSize %lx",
       (unsigned long)mbi.State, (unsigned long)mbi.RegionSize);
    status = NtQueryVirtualMemory(NtCurrentProcess(), base + 0x3000, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), NULL);
    ok(status == STATUS_SUCCESS, "query tail -> %08lx", (unsigned long)status);
    ok(mbi.State == MEM_RESERVE && mbi.RegionSize == 0xD000, "tail State %lx RegionSize %lx",
       (unsigned long)mbi.State, (unsigned long)mbi.RegionSize);

    /* Re-committing committed pages succeeds. */
    p = base + 0x1000;
    size = 0x2000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), (void **)&p, 0, &size, MEM_COMMIT,
                                     PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "re-commit -> %08lx", (unsigned long)status);
    ok(p[0] == 0x5a, "re-commit wiped the page");

    /* A new reservation may not overlap: the 64k rounding makes base+0x1000
     * conflict (Wine's own test case). */
    p = base + 0x1000;
    size = 0x1000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), (void **)&p, 0, &size,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "overlapping reserve -> %08lx",
       (unsigned long)status);

    /* --- the decommit / release rounding corners (Wine's virtual.c) ------ */

    p = base;
    size = 0x10000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), (void **)&p, 0, &size, MEM_COMMIT,
                                     PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "commit whole region -> %08lx", (unsigned long)status);

    size = 2;
    addr = base + 0x1FFF;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_DECOMMIT);
    ok(status == STATUS_SUCCESS, "decommit straddle -> %08lx", (unsigned long)status);
    ok(size == 0x2000, "decommit size %lx, expected 2000", (unsigned long)size);
    ok(addr == base + 0x1000, "decommit addr %p, expected %p", addr, base + 0x1000);

    size = 0;
    addr = base + 0x1001;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_DECOMMIT);
    ok(status == STATUS_FREE_VM_NOT_AT_BASE, "zero-size decommit off base -> %08lx",
       (unsigned long)status);
    ok(size == 0 && addr == base + 0x1001, "failed decommit changed addr/size");

    size = 0;
    addr = base + 0xFFE;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_DECOMMIT);
    ok(status == STATUS_SUCCESS, "zero-size decommit at base -> %08lx", (unsigned long)status);
    ok(size == 0, "zero-size decommit size %lx", (unsigned long)size);
    ok(addr == base, "zero-size decommit addr %p, expected %p", addr, base);

    size = 0;
    addr = base + 0x1001;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(status == STATUS_FREE_VM_NOT_AT_BASE, "release off base -> %08lx", (unsigned long)status);

    size = 0x20000;
    addr = base;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(status == STATUS_UNABLE_TO_FREE_VM, "oversize release -> %08lx", (unsigned long)status);

    size = 0;
    addr = base + 0xFFF;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "release -> %08lx", (unsigned long)status);
    ok(size == 0x10000, "release size %lx, expected 10000", (unsigned long)size);
    ok(addr == base, "release addr %p, expected %p", addr, base);

    /* --- after the release ------------------------------------------------ */

    status = NtQueryVirtualMemory(NtCurrentProcess(), base, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), NULL);
    ok(status == STATUS_SUCCESS, "query freed -> %08lx", (unsigned long)status);
    ok(mbi.State == MEM_FREE, "freed State %lx", (unsigned long)mbi.State);
    ok(mbi.Protect == PAGE_NOACCESS, "freed Protect %lx", (unsigned long)mbi.Protect);
    ok(mbi.AllocationBase == 0, "freed AllocationBase %p", mbi.AllocationBase);
    ok(mbi.AllocationProtect == 0 && mbi.Type == 0, "freed AllocationProtect/Type %lx/%lx",
       (unsigned long)mbi.AllocationProtect, (unsigned long)mbi.Type);

    addr = base;
    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(status == STATUS_MEMORY_NOT_ALLOCATED, "double release -> %08lx", (unsigned long)status);

    /* --- NtProtectVirtualMemory applies to ALL of the range, or none ------
     *
     * NT requires every page in the range to be committed. proskrnl rewrote
     * PTEs page by page and only then discovered an uncommitted one, leaving
     * the range HALF-reprotected while reporting failure -- ntdll's loader
     * flips section protections through this path, so a partly-applied
     * change is a process running with the wrong permissions on part of an
     * image. */
    addr = NULL;
    size = 0x3000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_RESERVE,
                                     PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "reserve for the protect case -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        PVOID region = addr;
        PVOID commitAt = region;
        SIZE_T commitSize = 0x1000;
        ULONG oldProtect = 0;

        /* Commit only the FIRST page of a three-page reservation. */
        status = NtAllocateVirtualMemory(NtCurrentProcess(), &commitAt, 0, &commitSize, MEM_COMMIT,
                                         PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "commit the head page -> %08lx", (unsigned long)status);

        /* Reprotect all three: the second page is not committed, so the call
         * fails -- and the FIRST page must be untouched. */
        addr = region;
        size = 0x3000;
        status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY,
                                        &oldProtect);
        ok(!NT_SUCCESS(status), "protect across an uncommitted page -> %08lx",
           (unsigned long)status);

        status = NtQueryVirtualMemory(NtCurrentProcess(), region, MEMORY_BASIC_INFO_CLASS, &mbi,
                                      sizeof(mbi), NULL);
        ok(status == STATUS_SUCCESS, "query the head page -> %08lx", (unsigned long)status);
        ok(mbi.Protect == PAGE_READWRITE,
           "the failed protect changed the head page: Protect %lx, wanted PAGE_READWRITE",
           (unsigned long)mbi.Protect);

        addr = region;
        size = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    }

    /* --- a RegionSize whose page rounding wraps -------------------------
     *
     * ROUND_SIZE(addr, size) overflows SIZE_T for a size near 2^64 and comes
     * out as 0 -- which is MEM_RELEASE's sentinel for "the whole region". So
     * a crafted length releases an entire reservation and reports success,
     * with the reported size being the region's, not the caller's. That
     * reads like a bug and is not one to fix here: it is exactly what the
     * pinned oracle does (third_party/wine dlls/ntdll/unix/virtual.c
     * NtFreeVirtualMemory, `if (size) size = ROUND_SIZE(...)` then
     * `if (!size) size = view->size`), so the divergence would be to
     * validate it. Pinned so the agreement is deliberate rather than
     * incidental -- and so that a future decision to refuse it shows up here
     * as a failure against the oracle first (Art. 6). */
    addr = NULL;
    size = 0x10000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "wrap-case reserve -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        PVOID wrapBase = addr;
        size = (SIZE_T)0 - 0x800; /* rounds up to exactly 0 */
        status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
        ok(status == STATUS_SUCCESS, "release with a wrapping size -> %08lx",
           (unsigned long)status);
        ok(addr == wrapBase, "wrap release addr %p, expected %p", addr, wrapBase);
        ok(size == 0x10000, "wrap release size %lx, expected the whole region 10000",
           (unsigned long)size);
        status = NtQueryVirtualMemory(NtCurrentProcess(), wrapBase, MEMORY_BASIC_INFO_CLASS, &mbi,
                                      sizeof(mbi), NULL);
        ok(status == STATUS_SUCCESS, "query after wrap release -> %08lx", (unsigned long)status);
        ok(mbi.State == MEM_FREE, "after wrap release State %lx", (unsigned long)mbi.State);
    }

    /* An explicit-base reserve rounds the base down to the granularity. */
    addr = base + 0x1234;
    size = 0x1000;
    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_RESERVE, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "explicit reserve -> %08lx", (unsigned long)status);
    ok(addr == base, "explicit reserve base %p, expected %p", addr, base);
    ok(size == 0x3000, "explicit reserve size %lx, expected 3000", (unsigned long)size);
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "cleanup release -> %08lx", (unsigned long)status);
}
