/*
 * sem_mm/alloc_ex.c — NtAllocateVirtualMemoryEx and NtCreateSectionEx
 * (CUI-7): the VirtualAlloc2/CreateFileMapping2 entry points.
 *
 * Oracle behaviour pinned from the pinned tree (wine
 * dlls/ntdll/unix/virtual.c get_extended_params + NtAllocateVirtualMemoryEx;
 * dlls/ntdll/unix/sync.c NtCreateSectionEx):
 *
 *   - get_extended_params: a nonzero count with a NULL array, a Type >= 32,
 *     a duplicated Type, or an unknown-but-small Type all refuse
 *     STATUS_INVALID_PARAMETER. MemExtendedParameterAddressRequirements
 *     validates: Alignment a power of two and >= 64K;
 *     LowestStartingAddress 64K-aligned below the user-space limit;
 *     HighestEndingAddress page-end-aligned, above Lowest, within the
 *     limit. NumaNode/PartitionHandle/UserPhysicalHandle are FIXME-ignored;
 *     AttributeFlags/ImageMachine are consumed.
 *   - NtAllocateVirtualMemoryEx: after the parameters, the type mask
 *     (placeholder bits are legal in the ORACLE's mask; deliberately not
 *     exercised — unbuilt on proskrnl, docs/03 "CUI-7"), then an explicit
 *     base combined with any requirement -> INVALID_PARAMETER, then a zero
 *     size -> INVALID_PARAMETER. Honored requirements place the block
 *     inside [Lowest, Highest] at the requested alignment. count == 0
 *     behaves exactly like classic NtAllocateVirtualMemory.
 *   - NtCreateSectionEx is NtCreateSection with the parameter array
 *     accepted-and-ignored (the oracle FIXMEs and proceeds; docs/03).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemoryEx(HANDLE, PVOID *, SIZE_T *, ULONG, ULONG, PVOID,
                                                  ULONG);
NTSYSAPI NTSTATUS NTAPI NtCreateSectionEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                          const LARGE_INTEGER *, ULONG, ULONG, HANDLE, PVOID,
                                          ULONG);

/* MEM_EXTENDED_PARAMETER, local 16-byte mirror (wine/include/winnt.h; the
 * Type lives in the low 8 bits of the first qword), so the test does not
 * depend on which mingw header revision defines it. */
typedef struct
{
    ULONGLONG type_bits; /* low 8 bits: MEM_EXTENDED_PARAMETER_TYPE */
    union
    {
        ULONGLONG u64;
        PVOID pointer;
    } u;
} mm_ext_param;

typedef struct
{
    PVOID lowest;
    PVOID highest;
    SIZE_T alignment;
} mm_addr_req;

/* MEM_EXTENDED_PARAMETER_TYPE values (wine/include/winnt.h). */
#define EXT_INVALID              0
#define EXT_ADDRESS_REQUIREMENTS 1
#define EXT_NUMA_NODE            2
#define EXT_ATTRIBUTE_FLAGS      5

/* MEM_EXTENDED_PARAMETER_EC_CODE (wine/include/winnt.h). */
#define MEM_EXT_EC_CODE 0x00000040

#ifndef MEM_WRITE_WATCH
#define MEM_WRITE_WATCH 0x00200000
#endif

START_TEST(alloc_ex)
{
    NTSTATUS status;
    PVOID base;
    SIZE_T size;
    mm_ext_param params[2];
    mm_addr_req req;

    /* --- the parameter-array ladder ---------------------------------------- */
    base = NULL;
    size = 0x10000;
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE, NULL, 1);
    ok(status == STATUS_INVALID_PARAMETER, "count without array -> %08lx", (unsigned long)status);

    memset(params, 0, sizeof(params));
    params[0].type_bits = 32; /* Type >= 32 */
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE, params, 1);
    ok(status == STATUS_INVALID_PARAMETER, "type 32 -> %08lx", (unsigned long)status);

    params[0].type_bits = 7; /* MemExtendedParameterMax: unknown */
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE, params, 1);
    ok(status == STATUS_INVALID_PARAMETER, "unknown type -> %08lx", (unsigned long)status);

    memset(&req, 0, sizeof(req));
    params[0].type_bits = EXT_ADDRESS_REQUIREMENTS;
    params[0].u.pointer = &req;
    params[1].type_bits = EXT_ADDRESS_REQUIREMENTS;
    params[1].u.pointer = &req;
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE, params, 2);
    ok(status == STATUS_INVALID_PARAMETER, "duplicate type -> %08lx", (unsigned long)status);

    /* --- AddressRequirements validation ------------------------------------ */
    memset(&req, 0, sizeof(req));
    req.alignment = 0x8000; /* below the 64K granularity */
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE, params, 1);
    ok(status == STATUS_INVALID_PARAMETER, "small alignment -> %08lx", (unsigned long)status);

    req.alignment = 0x30000; /* not a power of two */
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE, params, 1);
    ok(status == STATUS_INVALID_PARAMETER, "non-pow2 alignment -> %08lx", (unsigned long)status);

    memset(&req, 0, sizeof(req));
    req.lowest = (PVOID)(ULONG_PTR)0x20001000; /* not 64K-aligned */
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE, params, 1);
    ok(status == STATUS_INVALID_PARAMETER, "unaligned lowest -> %08lx", (unsigned long)status);

    memset(&req, 0, sizeof(req));
    req.lowest = (PVOID)(ULONG_PTR)0x20000000;
    req.highest = (PVOID)(ULONG_PTR)0x20000100; /* not page-end aligned */
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE, params, 1);
    ok(status == STATUS_INVALID_PARAMETER, "unaligned highest -> %08lx", (unsigned long)status);

    memset(&req, 0, sizeof(req));
    req.lowest = (PVOID)(ULONG_PTR)0x30000000;
    req.highest = (PVOID)(ULONG_PTR)0x2fffffff; /* below lowest */
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE, params, 1);
    ok(status == STATUS_INVALID_PARAMETER, "highest below lowest -> %08lx", (unsigned long)status);

    /* --- honored requirements ---------------------------------------------- */
    memset(&req, 0, sizeof(req));
    req.lowest = (PVOID)(ULONG_PTR)0x20000000;
    req.highest = (PVOID)(ULONG_PTR)0x2fffffff;
    req.alignment = 0x20000;
    base = NULL;
    size = 0x10000;
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE, params, 1);
    ok(status == STATUS_SUCCESS, "constrained alloc -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ok((ULONG_PTR)base >= 0x20000000 && (ULONG_PTR)base + size <= 0x30000000,
           "block inside range (%p)", base);
        ok(((ULONG_PTR)base & 0x1ffff) == 0, "block aligned (%p)", base);
        *(volatile unsigned char *)base = 0xab; /* committed and writable */
        {
            SIZE_T freeSize = 0;
            PVOID freeBase = base;
            status = NtFreeVirtualMemory(NtCurrentProcess(), &freeBase, &freeSize, MEM_RELEASE);
            ok(status == STATUS_SUCCESS, "free constrained -> %08lx", (unsigned long)status);
        }
    }

    /* --- explicit base excludes requirements; zero size refuses ------------- */
    base = NULL;
    size = 0x10000;
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE,
                                       PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_SUCCESS, "plain reserve -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        PVOID commitBase = base;
        SIZE_T commitSize = 0x1000;
        memset(&req, 0, sizeof(req));
        req.alignment = 0x10000;
        status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &commitBase, &commitSize, MEM_COMMIT,
                                           PAGE_READWRITE, params, 1);
        ok(status == STATUS_INVALID_PARAMETER, "base + requirements -> %08lx",
           (unsigned long)status);
        /* count == 0 with a base behaves exactly like the classic form. */
        status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &commitBase, &commitSize, MEM_COMMIT,
                                           PAGE_READWRITE, NULL, 0);
        ok(status == STATUS_SUCCESS, "commit into reservation -> %08lx", (unsigned long)status);
        {
            SIZE_T freeSize = 0;
            PVOID freeBase = base;
            status = NtFreeVirtualMemory(NtCurrentProcess(), &freeBase, &freeSize, MEM_RELEASE);
            ok(status == STATUS_SUCCESS, "free reservation -> %08lx", (unsigned long)status);
        }
    }
    base = NULL;
    size = 0;
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "zero size -> %08lx", (unsigned long)status);

    /* --- invalid type bit; ignored/consumed parameter types ----------------- */
    base = NULL;
    size = 0x1000;
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_COMMIT | 0x40,
                                       PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "bad type bit -> %08lx", (unsigned long)status);

    memset(params, 0, sizeof(params));
    params[0].type_bits = EXT_ATTRIBUTE_FLAGS;
    params[0].u.u64 = 0;
    base = NULL;
    size = 0x1000;
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE, params, 1);
    ok(status == STATUS_SUCCESS, "attribute flags accepted -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        SIZE_T freeSize = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &base, &freeSize, MEM_RELEASE);
        ok(status == STATUS_SUCCESS, "free attr alloc -> %08lx", (unsigned long)status);
    }

    params[0].type_bits = EXT_NUMA_NODE;
    params[0].u.u64 = 0;
    base = NULL;
    size = 0x1000;
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE, params, 1);
    ok(status == STATUS_SUCCESS, "numa node ignored -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        SIZE_T freeSize = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &base, &freeSize, MEM_RELEASE);
        ok(status == STATUS_SUCCESS, "free numa alloc -> %08lx", (unsigned long)status);
    }

    /* --- write-watch through the Ex form ------------------------------------ */
    base = NULL;
    size = 0x4000;
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size,
                                       MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE,
                                       NULL, 0);
    ok(status == STATUS_SUCCESS, "write-watch alloc -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        SIZE_T freeSize = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &base, &freeSize, MEM_RELEASE);
        ok(status == STATUS_SUCCESS, "free watch alloc -> %08lx", (unsigned long)status);
    }

    /* --- MEM_EXTENDED_PARAMETER_EC_CODE, the one attribute bit that refuses ---
     * ARM64EC code memory. The oracle refuses it on anything that is not an
     * ARM64EC image (wine dlls/ntdll/unix/virtual.c allocate_virtual_memory:
     * `if (!arm64ec_view && (attributes & MEM_EXTENDED_PARAMETER_EC_CODE))
     * return STATUS_INVALID_PARAMETER;`). proskrnl is x86_64-only
     * (docs/adr/0006-x64-only.md), so its refusal is unconditional.
     *
     * ntdll:unwind's test_virtual_unwind_arm64 uses exactly this call as its
     * "am I an ARM64EC host" probe and runs ARM64 unwinding over the x86_64
     * code it allocated when the call succeeds, so an accepted-and-dropped
     * bit here is not a wrong answer, it is a crash a page later. */
    memset(params, 0, sizeof(params));
    params[0].type_bits = EXT_ATTRIBUTE_FLAGS;
    params[0].u.u64 = MEM_EXT_EC_CODE;
    base = NULL;
    size = 0x10000;
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE | MEM_COMMIT,
                                       PAGE_EXECUTE_READWRITE, params, 1);
    ok(status == STATUS_INVALID_PARAMETER, "EC_CODE reserve+commit -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        SIZE_T freeSize = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &base, &freeSize, MEM_RELEASE);
    }

    /* The guard reads exactly bit 0x40 and nothing else: every OTHER bit of
     * the attribute word is accepted and dropped, so an implementation that
     * refused a nonzero attribute word would pass the arm above and fail
     * here.
     *
     * This arm pins the ORACLE, and the oracle is laxer than NT here on
     * purpose: get_extended_params stores the word and validates no bit of
     * it, so MEM_EXTENDED_PARAMETER_NONPAGED{,_LARGE,_HUGE} — which real NT
     * plausibly gates on SeLockMemoryPrivilege — ride along in this mask.
     * If this assertion ever fires on Windows, that is an oracle gap to
     * re-pin, not a kernel regression. */
    params[0].u.u64 = (ULONGLONG)0xffffffffu & ~(ULONGLONG)MEM_EXT_EC_CODE;
    base = NULL;
    size = 0x1000;
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE, params, 1);
    ok(status == STATUS_SUCCESS, "every non-EC_CODE attribute bit -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        SIZE_T freeSize = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &base, &freeSize, MEM_RELEASE);
        ok(status == STATUS_SUCCESS, "free non-EC_CODE alloc -> %08lx", (unsigned long)status);
    }

    /* The bit is refused on the COMMIT path too, not just on reservation: the
     * guard sits inside the allocation engine below the type-flag ladder, so
     * a commit that would otherwise succeed refuses when it carries EC_CODE.
     * (Same site in the oracle; there is one guard, not one per path.) */
    base = NULL;
    size = 0x10000;
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE,
                                       PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_SUCCESS, "reserve for EC_CODE commit -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        PVOID commitBase = base;
        SIZE_T commitSize = 0x1000;
        SIZE_T freeSize = 0;
        params[0].u.u64 = MEM_EXT_EC_CODE;
        status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &commitBase, &commitSize, MEM_COMMIT,
                                           PAGE_EXECUTE_READWRITE, params, 1);
        ok(status == STATUS_INVALID_PARAMETER, "EC_CODE commit -> %08lx", (unsigned long)status);
        commitBase = base;
        commitSize = 0x1000;
        status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &commitBase, &commitSize, MEM_COMMIT,
                                           PAGE_READWRITE, NULL, 0);
        ok(status == STATUS_SUCCESS, "same commit without EC_CODE -> %08lx", (unsigned long)status);
        status = NtFreeVirtualMemory(NtCurrentProcess(), &base, &freeSize, MEM_RELEASE);
        ok(status == STATUS_SUCCESS, "free EC_CODE reservation -> %08lx", (unsigned long)status);
    }

    /* Where the guard sits, pinned the way sem_mm/reserve_commit pins the
     * rest of this ladder. The oracle's EC_CODE test is the LAST line of
     * allocate_virtual_memory's prologue, below the working-set test that
     * opens it — so an oversized request carrying EC_CODE reports
     * STATUS_WORKING_SET_LIMIT_RANGE, not STATUS_INVALID_PARAMETER. An
     * implementation that refused the bit up in the syscall wrapper, before
     * the allocation engine, would answer this one backwards. */
    params[0].u.u64 = MEM_EXT_EC_CODE;
    base = NULL;
    size = (SIZE_T)0x7fffffff0000 + 1;
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE, params, 1);
    ok(status == STATUS_WORKING_SET_LIMIT_RANGE, "EC_CODE + oversized size -> %08lx",
       (unsigned long)status);

    /* NOTE: MEM_RESERVE_PLACEHOLDER / MEM_REPLACE_PLACEHOLDER are legal bits
     * in the oracle's type mask but the placeholder machinery is deliberately
     * unbuilt on proskrnl (loud refusal; no baked consumer — docs/03
     * "CUI-7"), so no placeholder arm is exercised here. */

    /* --- NtCreateSectionEx --------------------------------------------------- */
    {
        HANDLE section = NULL;
        LARGE_INTEGER sectionSize;
        sectionSize.QuadPart = 0x10000;
        status = NtCreateSectionEx(&section, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_READWRITE,
                                   SEC_COMMIT, NULL, NULL, 0);
        ok(status == STATUS_SUCCESS, "section ex (no params) -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            PVOID view = NULL;
            SIZE_T viewSize = 0;
            status = NtMapViewOfSection(section, NtCurrentProcess(), &view, 0, 0, NULL, &viewSize,
                                        ViewShare, 0, PAGE_READWRITE);
            ok(status == STATUS_SUCCESS, "map ex section -> %08lx", (unsigned long)status);
            if (NT_SUCCESS(status))
            {
                *(volatile unsigned char *)view = 0x5a;
                NtUnmapViewOfSection(NtCurrentProcess(), view);
            }
            NtClose(section);
        }

        /* A parameter array is accepted and ignored (the pinned oracle
         * FIXME behaviour). */
        memset(params, 0, sizeof(params));
        memset(&req, 0, sizeof(req));
        req.lowest = (PVOID)(ULONG_PTR)0x20000000;
        req.highest = (PVOID)(ULONG_PTR)0x2fffffff;
        params[0].type_bits = EXT_ADDRESS_REQUIREMENTS;
        params[0].u.pointer = &req;
        section = NULL;
        status = NtCreateSectionEx(&section, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_READWRITE,
                                   SEC_COMMIT, NULL, params, 1);
        ok(status == STATUS_SUCCESS, "section ex (params ignored) -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(section);
    }
}
