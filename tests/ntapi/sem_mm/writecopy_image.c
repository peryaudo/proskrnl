/*
 * sem_mm/writecopy_image.c — PAGE_WRITECOPY semantics of SEC_IMAGE views
 * (CUI-9, docs/17 §8; the G5 pin preceding the kernel's shared-master and
 * COW work).
 *
 * Oracle behaviour pinned from the pinned tree (wine
 * dlls/ntdll/unix/virtual.c map_image_into_view maps every PE section
 * MAP_PRIVATE with VPROT_WRITECOPY on the writable ones; the fault /
 * uninterrupted-write paths resolve the copy): a store into a writable
 * image page succeeds and stays private — the other view of the same
 * section does not see it, the FILE does not see it, and the private page
 * outlives the other view. A store into a read-only image page is still
 * an access violation (hazard B's boundary case: the COW machinery must
 * never resurrect a real AV).
 *
 * The kernel-side pair are clones of sem_mm/write_watch.c's "kernel-side
 * writes mark too" block, re-pointed at writecopy (docs/17 §8 "the
 * hazard-A tests already exist — as write-watch's"):
 *   1. NtWriteVirtualMemory into a writecopy image page copies+completes;
 *   2. a syscall out-buffer inside a writecopy image page succeeds;
 *   3. both still FAIL on a genuinely read-only image page — the one case
 *      write-watch never faces (a watched page's recorded protection is
 *      writable by definition).
 */
#include "util.h"

#include <windows.h>
#include <string.h> /* declarations only: the .exe links no CRT (ntapi.c) */

NTSYSAPI NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, void *, const void *, SIZE_T, SIZE_T *);

#define PAGE_BYTES 0x1000u

/* Expected-AV plumbing: the handler records the fault and steers execution
 * to a recovery label (breakpoint.c/continue_bad_rip.c precedent — the
 * faulting store cannot be re-executed, unlike a guard touch). Only static
 * volatiles are read after the abnormal jump. */
static volatile LONG av_count;
static void *volatile av_addr;
static void *volatile av_recover;

static LONG CALLBACK av_veh(EXCEPTION_POINTERS *info)
{
    if (info->ExceptionRecord->ExceptionCode == (DWORD)STATUS_ACCESS_VIOLATION &&
        av_recover != NULL)
    {
        av_count++;
        av_addr = (void *)info->ExceptionRecord->ExceptionInformation[1];
        info->ContextRecord->Rip = (DWORD64)(ULONG_PTR)av_recover;
        av_recover = NULL;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* First PE section in the mapped view matching want/reject on its
 * characteristics, with at least min_pages of virtual size; returns the RVA
 * or 0. raw_off/raw_size report its file backing. */
static ULONG find_segment(const char *view, ULONG want, ULONG reject, ULONG min_pages,
                          ULONG *raw_off, ULONG *raw_size)
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)view;
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)(view + dos->e_lfanew);
    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    ULONG i;
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        ULONG ch = sec[i].Characteristics;
        if ((ch & want) == want && (ch & reject) == 0 &&
            sec[i].Misc.VirtualSize >= min_pages * PAGE_BYTES)
        {
            if (raw_off != NULL)
                *raw_off = sec[i].PointerToRawData;
            if (raw_size != NULL)
                *raw_size = sec[i].SizeOfRawData;
            return sec[i].VirtualAddress;
        }
    }
    return 0;
}

START_TEST(writecopy_image)
{
    NTSTATUS status;
    HANDLE file, section;
    LARGE_INTEGER offset;
    SIZE_T view_size, view2_size;
    char path[MAX_PATH];
    char *view1, *view2;
    void *handler;
    ULONG data_rva, data_raw_off, data_raw_size, bss_rva, ro_rva, ro_raw_size;

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

    view1 = NULL;
    view_size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view1, 0, 0, &offset,
                                &view_size, ViewShare, 0, PAGE_READONLY);
    ok(status == STATUS_IMAGE_NOT_AT_BASE || status == STATUS_SUCCESS, "map view1 -> %08lx",
       (unsigned long)status);
    view2 = NULL;
    view2_size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view2, 0, 0, &offset,
                                &view2_size, ViewShare, 0, PAGE_READONLY);
    ok(status == STATUS_IMAGE_NOT_AT_BASE || status == STATUS_SUCCESS, "map view2 -> %08lx",
       (unsigned long)status);

    /* A raw-backed writable segment (.data: the file-unchanged check needs
     * real file bytes behind the page), a zero-fill writable run (.bss),
     * and a read-only data segment (.rdata). ntdll has all three; the scan
     * keeps the test honest if its layout moves. */
    data_rva = find_segment(view1, IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA,
                            IMAGE_SCN_MEM_EXECUTE, 0, &data_raw_off, &data_raw_size);
    bss_rva = find_segment(view1, IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_UNINITIALIZED_DATA,
                           IMAGE_SCN_MEM_EXECUTE, 2, NULL, NULL);
    ro_rva = find_segment(view1, IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
                          IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE, 1, NULL, &ro_raw_size);
    ok(data_rva != 0 && data_raw_size != 0, "no raw-backed writable segment");
    ok(bss_rva != 0, "no zero-fill writable segment");
    ok(ro_rva != 0, "no read-only data segment");
    if (data_rva == 0 || bss_rva == 0 || ro_rva == 0)
        return;

    handler = AddVectoredExceptionHandler(1, av_veh);
    ok(handler != NULL, "no vectored handler");

    /* --- ring-3 store: succeeds, private to this view, invisible in the
     * file ------------------------------------------------------------------ */
    {
        volatile char *wc = (volatile char *)(view1 + data_rva);
        /* Compare against the VIEW's own pre-store bytes, not the file's:
         * both views are relocated, so .data pointers differ from the raw
         * file bytes (and from each other's view). */
        char before1 = view1[data_rva];
        char before2 = view2[data_rva];
        char raw_before[16], raw_after[16];
        DWORD moved = 0;
        BOOL bok;

        bok =
            SetFilePointer(file, (LONG)data_raw_off, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER;
        ok(bok, "seek to raw data");
        bok = ReadFile(file, raw_before, sizeof(raw_before), &moved, NULL);
        ok(bok && moved == sizeof(raw_before), "read raw before (%lu)", (unsigned long)moved);

        av_count = 0;
        wc[0] = (char)(wc[0] + 0x21);
        ok(av_count == 0, "writecopy store raised %ld exceptions", (long)av_count);
        ok(view1[data_rva] == (char)(before1 + 0x21), "store did not stick");
        ok(view2[data_rva] == before2, "other view saw the private store");

        bok =
            SetFilePointer(file, (LONG)data_raw_off, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER;
        ok(bok, "re-seek to raw data");
        bok = ReadFile(file, raw_after, sizeof(raw_after), &moved, NULL);
        ok(bok && moved == sizeof(raw_after), "read raw after (%lu)", (unsigned long)moved);
        ok(memcmp(raw_before, raw_after, sizeof(raw_before)) == 0, "the FILE changed");
    }

    /* --- hazard-A case 1: NtWriteVirtualMemory into a fresh writecopy page
     * copies and completes, still privately --------------------------------- */
    {
        static const unsigned char payload[4] = {0xC0, 0x11, 0xEE, 0x7A};
        SIZE_T written = 0;
        status = NtWriteVirtualMemory(NtCurrentProcess(), view1 + bss_rva, payload, sizeof(payload),
                                      &written);
        ok(status == STATUS_SUCCESS && written == sizeof(payload),
           "write vm into writecopy -> %08lx (%lu)", (unsigned long)status, (unsigned long)written);
        ok(memcmp(view1 + bss_rva, payload, sizeof(payload)) == 0, "kernel write did not stick");
        ok(view2[bss_rva] == 0, "other view saw the kernel write");
    }

    /* --- hazard-A case 2: a syscall out-buffer inside a fresh writecopy
     * page succeeds ---------------------------------------------------------- */
    {
        MEMORY_BASIC_INFORMATION *info = (MEMORY_BASIC_INFORMATION *)(view1 + bss_rva + PAGE_BYTES);
        SIZE_T returned = 0;
        status = NtQueryVirtualMemory(NtCurrentProcess(), view1, MEMORY_BASIC_INFO_CLASS, info,
                                      sizeof(*info), &returned);
        ok(status == STATUS_SUCCESS, "query into writecopy -> %08lx", (unsigned long)status);
        ok(info->State == MEM_COMMIT, "queried State %lx", (unsigned long)info->State);
    }

    /* --- hazard-A case 3 + the ring-3 neighbour: a genuinely read-only
     * image page still refuses all three ------------------------------------ */
    {
        volatile char *ro = (volatile char *)(view1 + ro_rva);
        char before = view1[ro_rva];
        static const unsigned char payload[4] = {1, 2, 3, 4};
        SIZE_T written = (SIZE_T)-1;
        MEMORY_BASIC_INFORMATION *info = (MEMORY_BASIC_INFORMATION *)(view1 + ro_rva);
        SIZE_T returned = 0;

        av_count = 0;
        av_addr = NULL;
        av_recover = &&ro_recover;
        ro[0] = 1; /* must fault; the handler steers past the store */
    ro_recover:
        ok(av_count == 1, "read-only store raised %ld AVs", (long)av_count);
        ok(av_addr == view1 + ro_rva, "AV address %p, expected %p", av_addr, view1 + ro_rva);
        ok(view1[ro_rva] == before, "read-only page changed");

        status = NtWriteVirtualMemory(NtCurrentProcess(), view1 + ro_rva, payload, sizeof(payload),
                                      &written);
        ok(status == STATUS_PARTIAL_COPY && written == 0, "write vm into read-only -> %08lx (%lu)",
           (unsigned long)status, (unsigned long)written);
        ok(view1[ro_rva] == before, "read-only page changed via NtWriteVirtualMemory");

        status = NtQueryVirtualMemory(NtCurrentProcess(), view1, MEMORY_BASIC_INFO_CLASS, info,
                                      sizeof(*info), &returned);
        ok(status == STATUS_ACCESS_VIOLATION, "query into read-only -> %08lx",
           (unsigned long)status);
        ok(view1[ro_rva] == before, "read-only page changed via a syscall out-buffer");
    }

    /* --- the private pages outlive the other view --------------------------- */
    status = NtUnmapViewOfSection(NtCurrentProcess(), view2);
    ok(status == STATUS_SUCCESS, "unmap view2 -> %08lx", (unsigned long)status);
    ok((unsigned char)view1[bss_rva] == 0xC0, "private page lost after the other unmap");

    RemoveVectoredExceptionHandler(handler);
    status = NtUnmapViewOfSection(NtCurrentProcess(), view1);
    ok(status == STATUS_SUCCESS, "unmap view1 -> %08lx", (unsigned long)status);
    NtClose(section);
    CloseHandle(file);
}
