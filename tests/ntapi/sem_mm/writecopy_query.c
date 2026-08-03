/*
 * sem_mm/writecopy_query.c — what NtQueryVirtualMemory and
 * NtProtectVirtualMemory observe of PAGE_WRITECOPY (CUI-9 hazard D,
 * docs/17 §6D: "decide, then pin").
 *
 * The decision, recorded in docs/03 "CUI-9 COW notes": pin the PINNED
 * ORACLE's shape, which is NO transition. Real NT flips a written
 * writecopy page's Protect to PAGE_(EXECUTE_)READWRITE and splits the
 * region; the pinned Wine does not — it realizes writecopy silently
 * through MAP_PRIVATE + PROT_WRITE (dlls/ntdll/unix/virtual.c
 * map_image_into_view / virtual_map_section), so the store never faults,
 * never reaches wine, and get_win32_prot keeps answering WRITECOPY.
 * Verified against the pinned tree by running this test's earlier
 * transition-asserting revision: Protect stays 8 (PAGE_WRITECOPY) after
 * the store, RegionSize does not split, and NtProtectVirtualMemory's old
 * protection stays WRITECOPY too. Diverging from the oracle toward NT
 * here would turn this green pair red (Art. 6), so proskrnl pins:
 *
 *   - an image view's writable run reports Protect = PAGE_WRITECOPY
 *     before AND after a store; AllocationProtect =
 *     PAGE_EXECUTE_WRITECOPY and State = MEM_COMMIT throughout; the
 *     region does not split on a write;
 *   - NtProtectVirtualMemory reports old protection PAGE_WRITECOPY on
 *     written and unwritten pages alike, and accepts PAGE_WRITECOPY as a
 *     new protection on an image view;
 *   - a data-section PAGE_WRITECOPY view answers identically, and the
 *     write never reaches the file.
 */
#include "../sem_file/util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, LPCVOID, ULONG, PVOID, SIZE_T, SIZE_T *);
NTSYSAPI NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG, ULONG *);
NTSYSAPI NTSTATUS NTAPI NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                        const LARGE_INTEGER *, ULONG, ULONG, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T,
                                           const LARGE_INTEGER *, SIZE_T *, ULONG, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
#ifndef ViewShare
#define ViewShare 1
#endif
#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif
#define MEMORY_BASIC_INFO_CLASS 0

#define PAGE_BYTES 0x1000u

static NTSTATUS query(const void *address, MEMORY_BASIC_INFORMATION *info)
{
    SIZE_T returned = 0;
    return NtQueryVirtualMemory(NtCurrentProcess(), address, MEMORY_BASIC_INFO_CLASS, info,
                                sizeof(*info), &returned);
}

/* The first writable non-executable PE segment of >= min_pages virtual
 * size; returns the RVA or 0, and its page count. */
static ULONG find_writable_run(const char *view, ULONG min_pages, ULONG *pages)
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)view;
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)(view + dos->e_lfanew);
    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    ULONG i;
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if ((sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0 &&
            (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 &&
            sec[i].Misc.VirtualSize >= min_pages * PAGE_BYTES)
        {
            *pages = (sec[i].Misc.VirtualSize + PAGE_BYTES - 1) / PAGE_BYTES;
            return sec[i].VirtualAddress;
        }
    }
    return 0;
}

START_TEST(writecopy_query)
{
    NTSTATUS status;
    MEMORY_BASIC_INFORMATION info;
    HANDLE file, section;
    LARGE_INTEGER offset;
    SIZE_T view_size;
    char path[MAX_PATH];
    char *view, *run;
    ULONG run_pages = 0, run_rva;

    GetSystemDirectoryA(path, sizeof(path));
    strcat(path, "\\ntdll.dll");
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
    ok(file != INVALID_HANDLE_VALUE, "cannot open %s", path);

    section = NULL;
    status =
        NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file);
    ok(status == STATUS_SUCCESS, "create image section -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    view = NULL;
    view_size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view, 0, 0, &offset,
                                &view_size, ViewShare, 0, PAGE_READONLY);
    ok(status == STATUS_IMAGE_NOT_AT_BASE || status == STATUS_SUCCESS, "map image -> %08lx",
       (unsigned long)status);

    run_rva = find_writable_run(view, 3, &run_pages);
    ok(run_rva != 0, "no 3-page writable run in ntdll");
    if (run_rva == 0)
        return;
    run = view + run_rva;

    /* --- before the first write --------------------------------------------- */
    status = query(run, &info);
    ok(status == STATUS_SUCCESS, "query fresh run -> %08lx", (unsigned long)status);
    ok(info.BaseAddress == run, "fresh run base %p, expected %p", info.BaseAddress, run);
    ok(info.Protect == PAGE_WRITECOPY, "fresh run Protect %lx", (unsigned long)info.Protect);
    ok(info.AllocationProtect == PAGE_EXECUTE_WRITECOPY, "AllocationProtect %lx",
       (unsigned long)info.AllocationProtect);
    ok(info.State == MEM_COMMIT, "fresh run State %lx", (unsigned long)info.State);
    ok(info.Type == MEM_IMAGE, "fresh run Type %lx", (unsigned long)info.Type);
    ok(info.RegionSize == (SIZE_T)run_pages * PAGE_BYTES, "fresh run RegionSize %lx (%lu pages)",
       (unsigned long)info.RegionSize, (unsigned long)run_pages);

    /* --- a store does NOT move Protect and does NOT split the region
     * (hazard D, pinned to the oracle's no-transition shape) ------------------ */
    *(volatile char *)(run + PAGE_BYTES) = 1;

    status = query(run, &info);
    ok(status == STATUS_SUCCESS && info.Protect == PAGE_WRITECOPY && info.BaseAddress == run &&
           info.RegionSize == (SIZE_T)run_pages * PAGE_BYTES,
       "head after store -> %08lx Protect %lx region %p+%lx", (unsigned long)status,
       (unsigned long)info.Protect, info.BaseAddress, (unsigned long)info.RegionSize);
    status = query(run + PAGE_BYTES, &info);
    ok(status == STATUS_SUCCESS && info.Protect == PAGE_WRITECOPY &&
           info.BaseAddress == run + PAGE_BYTES &&
           info.RegionSize == (SIZE_T)(run_pages - 1) * PAGE_BYTES,
       "written page -> %08lx Protect %lx region %p+%lx", (unsigned long)status,
       (unsigned long)info.Protect, info.BaseAddress, (unsigned long)info.RegionSize);

    /* State and AllocationProtect never move (docs/17 §7: sharing is
     * invisible to the commit model). */
    status = query(run + PAGE_BYTES, &info);
    ok(status == STATUS_SUCCESS && info.State == MEM_COMMIT &&
           info.AllocationProtect == PAGE_EXECUTE_WRITECOPY,
       "written page State %lx AllocationProtect %lx", (unsigned long)info.State,
       (unsigned long)info.AllocationProtect);

    /* --- NtProtectVirtualMemory's old-protection exposure -------------------- */
    {
        PVOID protBase;
        SIZE_T protSize;
        ULONG oldProtect;

        /* Unwritten page: the old protection is still WRITECOPY. */
        protBase = run + 2 * PAGE_BYTES;
        protSize = PAGE_BYTES;
        oldProtect = 0;
        status = NtProtectVirtualMemory(NtCurrentProcess(), &protBase, &protSize, PAGE_READONLY,
                                        &oldProtect);
        ok(status == STATUS_SUCCESS && oldProtect == PAGE_WRITECOPY,
           "protect unwritten -> %08lx old %lx", (unsigned long)status, (unsigned long)oldProtect);
        protBase = run + 2 * PAGE_BYTES;
        protSize = PAGE_BYTES;
        status = NtProtectVirtualMemory(NtCurrentProcess(), &protBase, &protSize, PAGE_WRITECOPY,
                                        &oldProtect);
        /* todo: proskrnl's MiProtectVirtualMemory refuses WRITECOPY as a
         * NEW protection today (STATUS_INVALID_PAGE_PROTECTION); the CUI-9
         * kernel commit accepts it on mapped views, as the oracle does. */
        todo_proskrnl ok(status == STATUS_SUCCESS && oldProtect == PAGE_READONLY,
                         "re-arm writecopy -> %08lx old %lx", (unsigned long)status,
                         (unsigned long)oldProtect);
        /* (Nothing below touches this page again, so the refused side's
         * leftover READONLY protection is harmless.) */

        /* Written page: the old protection is STILL writecopy (the pinned
         * no-transition shape). */
        protBase = run + PAGE_BYTES;
        protSize = PAGE_BYTES;
        oldProtect = 0;
        status = NtProtectVirtualMemory(NtCurrentProcess(), &protBase, &protSize, PAGE_READONLY,
                                        &oldProtect);
        ok(status == STATUS_SUCCESS && oldProtect == PAGE_WRITECOPY,
           "protect written -> %08lx old %lx", (unsigned long)status, (unsigned long)oldProtect);
        protBase = run + PAGE_BYTES;
        protSize = PAGE_BYTES;
        status = NtProtectVirtualMemory(NtCurrentProcess(), &protBase, &protSize, PAGE_READWRITE,
                                        &oldProtect);
        ok(status == STATUS_SUCCESS && oldProtect == PAGE_READONLY,
           "restore written -> %08lx old %lx", (unsigned long)status, (unsigned long)oldProtect);
        /* On an image view PAGE_READWRITE canonicalizes to writecopy (the
         * oracle's get_vprot_flags with image=TRUE: READWRITE ->
         * VPROT_READ|VPROT_WRITECOPY), so the query answers WRITECOPY. */
        todo_proskrnl
        {
            status = query(run + PAGE_BYTES, &info);
            ok(status == STATUS_SUCCESS && info.Protect == PAGE_WRITECOPY,
               "queried after rw restore -> %08lx Protect %lx", (unsigned long)status,
               (unsigned long)info.Protect);
        }
    }

    status = NtUnmapViewOfSection(NtCurrentProcess(), view);
    ok(status == STATUS_SUCCESS, "unmap image -> %08lx", (unsigned long)status);
    NtClose(section);
    CloseHandle(file);

    /* --- a data-section PAGE_WRITECOPY view transitions identically, and
     * the write never reaches the file (docs/17 §5: data-section writecopy
     * keeps its eager-private-copy form; the OBSERVABLE contract is the
     * same either way) --------------------------------------------------- */
    {
        HANDLE dir, data_file, data_section;
        IO_STATUS_BLOCK iosb;
        LARGE_INTEGER size, byte_offset;
        static UCHAR pattern[3 * PAGE_BYTES];
        UCHAR page_buffer[PAGE_BYTES];
        char *data_view;
        SIZE_T data_size;
        ULONG i;

        dir = open_test_dir(W("\\??\\C:\\prstest\\mmwcq"));
        ok(dir != NULL, "test dir");
        if (dir == NULL)
            return;
        scrub_file(dir, W("wcq.dat"));
        status = open_file(&data_file, dir, W("wcq.dat"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
        ok(status == STATUS_SUCCESS, "create wcq.dat -> %08lx", (unsigned long)status);
        for (i = 0; i < sizeof(pattern); i++)
            pattern[i] = (UCHAR)(0xA0 ^ (i >> 8) ^ i);
        byte_offset.QuadPart = 0;
        status = NtWriteFile(data_file, NULL, NULL, NULL, &iosb, pattern, sizeof(pattern),
                             &byte_offset, NULL);
        ok(status == STATUS_SUCCESS, "seed wcq.dat -> %08lx", (unsigned long)status);

        data_section = NULL;
        size.QuadPart = sizeof(pattern);
        status = NtCreateSection(&data_section, SECTION_ALL_ACCESS, NULL, &size, PAGE_READONLY,
                                 SEC_COMMIT, data_file);
        ok(status == STATUS_SUCCESS, "create data section -> %08lx", (unsigned long)status);
        data_view = NULL;
        data_size = 0;
        byte_offset.QuadPart = 0;
        status = NtMapViewOfSection(data_section, NtCurrentProcess(), (void **)&data_view, 0, 0,
                                    &byte_offset, &data_size, ViewShare, 0, PAGE_WRITECOPY);
        ok(status == STATUS_SUCCESS, "map writecopy data view -> %08lx", (unsigned long)status);
        if (!NT_SUCCESS(status))
            return;

        status = query(data_view, &info);
        ok(status == STATUS_SUCCESS && info.Protect == PAGE_WRITECOPY &&
               info.AllocationProtect == PAGE_WRITECOPY && info.RegionSize == sizeof(pattern) &&
               info.Type == MEM_MAPPED,
           "fresh data view -> %08lx Protect %lx alloc %lx size %lx type %lx",
           (unsigned long)status, (unsigned long)info.Protect,
           (unsigned long)info.AllocationProtect, (unsigned long)info.RegionSize,
           (unsigned long)info.Type);

        *(volatile UCHAR *)(data_view + PAGE_BYTES) ^= 0xFF;

        status = query(data_view + PAGE_BYTES, &info);
        ok(status == STATUS_SUCCESS && info.Protect == PAGE_WRITECOPY &&
               info.BaseAddress == data_view + PAGE_BYTES &&
               info.RegionSize == sizeof(pattern) - PAGE_BYTES,
           "written data page -> %08lx Protect %lx region %p+%lx", (unsigned long)status,
           (unsigned long)info.Protect, info.BaseAddress, (unsigned long)info.RegionSize);

        /* The write never reaches the file. */
        byte_offset.QuadPart = PAGE_BYTES;
        status = NtReadFile(data_file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES,
                            &byte_offset, NULL);
        ok(status == STATUS_SUCCESS, "re-read wcq.dat -> %08lx", (unsigned long)status);
        ok(memcmp(page_buffer, pattern + PAGE_BYTES, PAGE_BYTES) == 0,
           "the FILE saw a writecopy store");

        status = NtUnmapViewOfSection(NtCurrentProcess(), data_view);
        ok(status == STATUS_SUCCESS, "unmap data view -> %08lx", (unsigned long)status);
        NtClose(data_section);
        NtClose(data_file);
        scrub_file(dir, W("wcq.dat"));
        NtClose(dir);
    }
}
