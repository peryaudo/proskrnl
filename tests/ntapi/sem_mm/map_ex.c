/*
 * sem_mm/map_ex.c — NtMapViewOfSectionEx and NtUnmapViewOfSectionEx
 * (CUI-7): the MapViewOfFile3/UnmapViewOfFile2 entry points.
 *
 * Oracle behaviour pinned from the pinned tree (wine
 * dlls/ntdll/unix/virtual.c NtMapViewOfSectionEx / NtUnmapViewOfSectionEx):
 * the extended parameters run the same get_extended_params ladder as
 * allocation, then an Alignment requirement refuses STATUS_INVALID_PARAMETER
 * outright (mapping has no alignment parameter), an explicit address
 * combined with limits refuses, AT_ROUND_TO_PAGE refuses on win64, and an
 * offset or address off the 64K granularity is STATUS_MAPPED_ALIGNMENT.
 * Placement limits are honored for a NULL-base map. Unmap validates its
 * flag mask (STATUS_INVALID_PARAMETER otherwise) and ignores
 * MEM_UNMAP_WITH_TRANSIENT_BOOST; MEM_PRESERVE_PLACEHOLDER is deliberately
 * not exercised (placeholders unbuilt on proskrnl — docs/03 "CUI-7").
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtMapViewOfSectionEx(HANDLE, HANDLE, PVOID *, const LARGE_INTEGER *,
                                             SIZE_T *, ULONG, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSectionEx(HANDLE, PVOID, ULONG);

/* Local MEM_EXTENDED_PARAMETER mirror (see alloc_ex.c). */
typedef struct
{
    ULONGLONG type_bits;
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

#define EXT_ADDRESS_REQUIREMENTS 1

#ifndef AT_ROUND_TO_PAGE
#define AT_ROUND_TO_PAGE 0x40000000
#endif
#ifndef MEM_UNMAP_WITH_TRANSIENT_BOOST
#define MEM_UNMAP_WITH_TRANSIENT_BOOST 0x00000001
#endif

START_TEST(map_ex)
{
    NTSTATUS status;
    HANDLE section = NULL;
    LARGE_INTEGER sectionSize, offset;
    PVOID view;
    SIZE_T viewSize;
    mm_ext_param param;
    mm_addr_req req;

    sectionSize.QuadPart = 0x20000;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_READWRITE,
                             SEC_COMMIT, NULL);
    ok(status == STATUS_SUCCESS, "create section -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* --- an Alignment requirement refuses outright -------------------------- */
    memset(&param, 0, sizeof(param));
    memset(&req, 0, sizeof(req));
    req.alignment = 0x20000;
    param.type_bits = EXT_ADDRESS_REQUIREMENTS;
    param.u.pointer = &req;
    view = NULL;
    viewSize = 0;
    status = NtMapViewOfSectionEx(section, NtCurrentProcess(), &view, NULL, &viewSize, 0,
                                  PAGE_READWRITE, &param, 1);
    ok(status == STATUS_INVALID_PARAMETER, "alignment requirement -> %08lx", (unsigned long)status);

    /* --- an explicit address combined with limits refuses ------------------- */
    memset(&req, 0, sizeof(req));
    req.lowest = (PVOID)(ULONG_PTR)0x20000000;
    req.highest = (PVOID)(ULONG_PTR)0x2fffffff;
    view = (PVOID)(ULONG_PTR)0x40000000;
    viewSize = 0;
    status = NtMapViewOfSectionEx(section, NtCurrentProcess(), &view, NULL, &viewSize, 0,
                                  PAGE_READWRITE, &param, 1);
    ok(status == STATUS_INVALID_PARAMETER, "address + limits -> %08lx", (unsigned long)status);

    /* --- AT_ROUND_TO_PAGE refuses on win64 ---------------------------------- */
    view = NULL;
    viewSize = 0;
    status = NtMapViewOfSectionEx(section, NtCurrentProcess(), &view, NULL, &viewSize,
                                  AT_ROUND_TO_PAGE, PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "AT_ROUND_TO_PAGE -> %08lx", (unsigned long)status);

    /* --- 64K granularity on the offset and the address ---------------------- */
    offset.QuadPart = 0x1000;
    view = NULL;
    viewSize = 0;
    status = NtMapViewOfSectionEx(section, NtCurrentProcess(), &view, &offset, &viewSize, 0,
                                  PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_MAPPED_ALIGNMENT, "unaligned offset -> %08lx", (unsigned long)status);
    view = (PVOID)(ULONG_PTR)0x40001000;
    viewSize = 0;
    status = NtMapViewOfSectionEx(section, NtCurrentProcess(), &view, NULL, &viewSize, 0,
                                  PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_MAPPED_ALIGNMENT, "unaligned address -> %08lx", (unsigned long)status);

    /* --- a plain parameter-free map/unmap round-trips ------------------------ */
    view = NULL;
    viewSize = 0;
    status = NtMapViewOfSectionEx(section, NtCurrentProcess(), &view, NULL, &viewSize, 0,
                                  PAGE_READWRITE, NULL, 0);
    ok(status == STATUS_SUCCESS, "plain map -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ok(viewSize >= 0x20000, "view size (%lx)", (unsigned long)viewSize);
        *(volatile unsigned char *)view = 0x11;
        status = NtUnmapViewOfSectionEx(NtCurrentProcess(), view, 0);
        ok(status == STATUS_SUCCESS, "plain unmap ex -> %08lx", (unsigned long)status);
    }

    /* --- placement limits honored ------------------------------------------- */
    view = NULL;
    viewSize = 0;
    status = NtMapViewOfSectionEx(section, NtCurrentProcess(), &view, NULL, &viewSize, 0,
                                  PAGE_READWRITE, &param, 1);
    ok(status == STATUS_SUCCESS, "constrained map -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ok((ULONG_PTR)view >= 0x20000000 && (ULONG_PTR)view + viewSize <= 0x30000000,
           "view inside range (%p)", view);
        *(volatile unsigned char *)view = 0x22;

        /* --- the unmap flag mask; the boost flag is an ignored no-op -------- */
        status = NtUnmapViewOfSectionEx(NtCurrentProcess(), view, 0x4);
        ok(status == STATUS_INVALID_PARAMETER, "bad unmap flag -> %08lx", (unsigned long)status);
        status = NtUnmapViewOfSectionEx(NtCurrentProcess(), view, MEM_UNMAP_WITH_TRANSIENT_BOOST);
        ok(status == STATUS_SUCCESS, "boost unmap -> %08lx", (unsigned long)status);
    }

    NtClose(section);
}
