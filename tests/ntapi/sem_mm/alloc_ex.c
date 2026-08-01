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
