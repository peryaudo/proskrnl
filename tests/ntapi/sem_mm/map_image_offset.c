/*
 * sem_mm/map_image_offset.c — NtMapViewOfSection with a NON-ZERO offset into
 * an IMAGE section: the view is the image's TAIL, and every view of one image
 * section holds the same bytes.
 *
 * docs/21 W5's tail, and the last subject in `ntdll:virtual`
 * (:1728-:1752). Two rules, and only the first is guessable from the
 * argument's name.
 *
 *   1. The offset TRIMS the image's head. The pinned oracle
 *      (third_party/wine dlls/ntdll/unix/virtual.c, virtual_map_image) maps
 *      the WHOLE image and then unmaps the front of it:
 *
 *          if (offset) { free_pages( view, view->base, offset ); size -= offset; }
 *
 *      so the answer is base+offset with size = map_size - offset, and the
 *      head is FREE rather than reserved. An implementation that returned the
 *      whole image and merely reported a shorter size satisfies the size
 *      assertion and fails the query below it. `offset >= map_size` is
 *      STATUS_INVALID_PARAMETER, and it is the FIRST thing virtual_map_image
 *      does — before the fd, before placement.
 *
 *   2. Two views of one image section hold IDENTICAL bytes, at different
 *      addresses. That does not follow from (1): an image is RELOCATED when
 *      it is mapped, and a mapper that relocated each view for the address
 *      that view landed at would produce two copies that differ wherever a
 *      relocation applies. The oracle relocates to the image's ONE dynamic
 *      base instead of to the view's (map_image_into_view: `delta =
 *      image_info->map_addr - image_info->base`), and the server states the
 *      same thing in its at-base test — `view->base != (map_addr ? map_addr :
 *      base) + offset` (third_party/wine server/mapping.c,
 *      DECL_HANDLER(map_image_view)). So an image section is relocated ONCE
 *      and every view shares that copy; the loader fixes up the residual
 *      privately (dlls/ntdll/loader.c perform_relocations, which is a no-op
 *      exactly when the view sits at the header's ImageBase).
 *
 * The winetest reaches (2) only through a memcmp of two views read out of a
 * CHILD, so the remote arm is measured here too rather than argued from "both
 * arms reach the same engine" (docs/21 §4 trap 4, the correction
 * sem_mm/map_image_machine.c had to make).
 *
 * Every extent here is DERIVED from the image's own measured map size: the
 * same ntdll.dll is 0x41a000 on the oracle and 0xba000 on proskrnl, so a
 * written-down offset would have measured one runner and skipped the block on
 * the other (docs/21 W5, the shape map_zero_bits.c paid for).
 *
 * Oracle-first (G5): every case here is measured on the pinned Wine.
 */
#include "util.h"

#include <windows.h>
#include <string.h> /* declarations only: the .exe links no CRT (ntapi.c) */

/* A value no view size can be, so a refusal that quietly wrote the size slot
 * is visible (the oracle writes *size_ptr on success only). */
#define SENTINEL_SIZE ((SIZE_T)0xd0d0d0d0)

/* An image view of a DLL already loaded in this process lands away from its
 * preferred base, so a success answers STATUS_IMAGE_NOT_AT_BASE. Both are
 * successes and the winetest accepts either. */
static int mapped_ok(NTSTATUS status)
{
    return status == STATUS_SUCCESS || status == (NTSTATUS)STATUS_IMAGE_NOT_AT_BASE;
}

static NTSTATUS map_at_offset(HANDLE section, HANDLE process, ULONGLONG offset, PVOID *viewOut,
                              SIZE_T *sizeOut)
{
    LARGE_INTEGER off;
    NTSTATUS status;

    off.QuadPart = (LONGLONG)offset;
    /* *viewOut must be NULL going in — a non-zero value is a NAMED BASE, a
     * different arm. *sizeOut is not an input for an image view (the oracle's
     * image path never reads *size_ptr), so the refusal cases below seed it
     * with a sentinel instead and assert it survives; the slot is never
     * re-zeroed here. */
    *viewOut = NULL;
    status = NtMapViewOfSection(section, process, viewOut, 0, 0, &off, sizeOut, ViewShare, 0,
                                PAGE_READONLY);
    return status;
}

/* Report WHERE two buffers first differ, not just that they do: a relocation
 * mismatch lands at one word inside .text and the offset is what names it. */
static void ok_same_bytes(const void *a, const void *b, SIZE_T size, const char *what)
{
    const unsigned char *pa = a, *pb = b;
    SIZE_T i;

    for (i = 0; i < size; i++)
        if (pa[i] != pb[i])
            break;
    ok(i == size, "%s: first difference at +%llx of %llx (%02x vs %02x)", what,
       (unsigned long long)i, (unsigned long long)size, i < size ? pa[i] : 0, i < size ? pb[i] : 0);
}

/* Local wide-string helper: the harness is -nostdlib and links only
 * ntdll/kernel32/kernelbase, so no CRT wcs* (as sem_mm/map_image_machine.c). */
static int wstr_contains(const WCHAR *haystack, const WCHAR *needle)
{
    size_t nlen = 0;
    while (needle[nlen])
        nlen++;
    for (; *haystack; haystack++)
    {
        size_t i = 0;
        while (i < nlen && haystack[i] == needle[i])
            i++;
        if (i == nlen)
            return 1;
    }
    return 0;
}

/* The winetest maps into a CHILD (virtual.c:1796's create_target_process) and
 * compares the two views through ReadProcessMemory. Re-exec ourselves as an
 * idle target and do the same: on the oracle a remote map rides an APC into
 * that process, so this is the same rule over a different transport. */
static void test_remote_target(HANDLE section, SIZE_T granularity)
{
    WCHAR self[512], cmdline[600];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    const WCHAR *tail = L" --mio-child";
    PVOID whole = NULL, tailView = NULL;
    SIZE_T wholeSize = 0, tailSize = 0, read = 0;
    void *copyA = NULL, *copyB = NULL;
    NTSTATUS status;
    int n = 0, i;

    ok(GetModuleFileNameW(NULL, self, 512) != 0, "GetModuleFileNameW");
    cmdline[n++] = L'"';
    for (i = 0; self[i] && n < 560; i++)
        cmdline[n++] = self[i];
    cmdline[n++] = L'"';
    for (i = 0; tail[i]; i++)
        cmdline[n++] = tail[i];
    cmdline[n] = 0;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    ok(CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi),
       "CreateProcessW child");
    if (!pi.hProcess)
        return;

    status = map_at_offset(section, pi.hProcess, 0, &whole, &wholeSize);
    ok(mapped_ok(status), "remote whole map -> %08lx", (unsigned long)status);
    status = map_at_offset(section, pi.hProcess, granularity, &tailView, &tailSize);
    ok(mapped_ok(status), "remote tail map -> %08lx", (unsigned long)status);
    ok(tailSize == wholeSize - granularity, "remote tail size %llx want %llx",
       (unsigned long long)tailSize, (unsigned long long)(wholeSize - granularity));
    ntapi_printf("map_image_offset: child whole %p (%llx), tail %p (%llx)\n", whole,
                 (unsigned long long)wholeSize, tailView, (unsigned long long)tailSize);

    if (whole && tailView && tailSize != 0 && tailSize == wholeSize - granularity)
    {
        copyA = VirtualAlloc(NULL, tailSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        copyB = VirtualAlloc(NULL, tailSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        ok(copyA != NULL && copyB != NULL, "scratch buffers");
    }
    if (copyA != NULL && copyB != NULL)
    {
        ok(ReadProcessMemory(pi.hProcess, (char *)whole + granularity, copyA, tailSize, &read),
           "ReadProcessMemory whole+granularity (%lu)", (unsigned long)GetLastError());
        ok(read == tailSize, "read %llx of %llx", (unsigned long long)read,
           (unsigned long long)tailSize);
        ok(ReadProcessMemory(pi.hProcess, tailView, copyB, tailSize, &read),
           "ReadProcessMemory tail view (%lu)", (unsigned long)GetLastError());
        ok(read == tailSize, "read %llx of %llx", (unsigned long long)read,
           (unsigned long long)tailSize);
        ok_same_bytes(copyA, copyB, tailSize, "remote views");
    }
    if (copyA)
        VirtualFree(copyA, 0, MEM_RELEASE);
    if (copyB)
        VirtualFree(copyB, 0, MEM_RELEASE);

    if (tailView)
    {
        status = NtUnmapViewOfSection(pi.hProcess, tailView);
        ok(status == STATUS_SUCCESS, "remote unmap tail -> %08lx", (unsigned long)status);
    }
    if (whole)
    {
        status = NtUnmapViewOfSection(pi.hProcess, whole);
        ok(status == STATUS_SUCCESS, "remote unmap whole -> %08lx", (unsigned long)status);
    }

    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 10000);
    NtClose(pi.hProcess);
    NtClose(pi.hThread);
}

START_TEST(map_image_offset)
{
    char path[MAX_PATH];
    HANDLE file, section = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    SYSTEM_INFO si;
    SIZE_T granularity, wholeSize = 0, tailSize = 0, lastSize = 0, refusedSize;
    PVOID whole = NULL, tailView = NULL, lastView = NULL, view = NULL;
    ULONGLONG lastGranule, pastImage;
    NTSTATUS status;

    if (wstr_contains(GetCommandLineW(), L"--mio-child"))
    {
        /* The idle target test_remote_target maps into. Bounded, and the
         * parent terminates and joins us. */
        Sleep(10000);
        ExitProcess(0);
    }

    GetSystemInfo(&si);
    granularity = si.dwAllocationGranularity;
    ok(granularity == 0x10000, "allocation granularity %llx", (unsigned long long)granularity);

    GetSystemDirectoryA(path, sizeof(path));
    strcat(path, "\\ntdll.dll");
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
    ok(file != INVALID_HANDLE_VALUE, "cannot open %s", path);
    if (file == INVALID_HANDLE_VALUE)
        return;

    status =
        NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file);
    ok(status == STATUS_SUCCESS, "create image section -> %08lx", (unsigned long)status);
    CloseHandle(file);
    if (!NT_SUCCESS(status))
        return;

    /* --- the whole image, to learn the extent every case below derives from -- */
    status = map_at_offset(section, NtCurrentProcess(), 0, &whole, &wholeSize);
    ok(mapped_ok(status), "whole image map -> %08lx", (unsigned long)status);
    if (!whole)
    {
        NtClose(section);
        return;
    }
    ok(wholeSize > 2 * granularity, "image map size %llx", (unsigned long long)wholeSize);
    ntapi_printf("map_image_offset: %s maps %llx bytes at %p\n", path,
                 (unsigned long long)wholeSize, whole);

    /* --- a non-zero offset maps the TAIL ------------------------------------ */
    status = map_at_offset(section, NtCurrentProcess(), granularity, &tailView, &tailSize);
    ok(mapped_ok(status), "tail map -> %08lx", (unsigned long)status);
    ok(tailSize == wholeSize - granularity, "tail size %llx want %llx",
       (unsigned long long)tailSize, (unsigned long long)(wholeSize - granularity));
    ok(tailView != NULL && ((ULONG_PTR)tailView & (granularity - 1)) == 0,
       "tail view %p is not 64K aligned", tailView);

    if (tailView)
    {
        /* The view starts where it says it does: an implementation that
         * mapped the whole image and only REPORTED a shorter size answers the
         * size assertion above and fails this one. */
        memset(&mbi, 0, sizeof(mbi));
        status = NtQueryVirtualMemory(NtCurrentProcess(), tailView, MEMORY_BASIC_INFO_CLASS, &mbi,
                                      sizeof(mbi), NULL);
        ok(status == STATUS_SUCCESS, "query tail view -> %08lx", (unsigned long)status);
        ok(mbi.AllocationBase == tailView, "tail AllocationBase %p want %p", mbi.AllocationBase,
           tailView);
        ok(mbi.Type == MEM_IMAGE, "tail Type %lx", (unsigned long)mbi.Type);

        /* ...and the trimmed head is FREE, not a reserved stub of the view.
         * free_pages removes those pages from the address space. */
        memset(&mbi, 0, sizeof(mbi));
        status = NtQueryVirtualMemory(NtCurrentProcess(), (char *)tailView - 0x1000,
                                      MEMORY_BASIC_INFO_CLASS, &mbi, sizeof(mbi), NULL);
        ok(status == STATUS_SUCCESS, "query trimmed head -> %08lx", (unsigned long)status);
        ok(mbi.State == MEM_FREE, "trimmed head State %lx", (unsigned long)mbi.State);

        status = NtUnmapViewOfSection(NtCurrentProcess(), (char *)tailView - 0x1000);
        ok(status == STATUS_NOT_MAPPED_VIEW, "unmap the trimmed head -> %08lx",
           (unsigned long)status);

        /* --- rule 2: the two views hold the SAME bytes ---------------------- */
        ok_same_bytes((char *)whole + granularity, tailView, tailSize, "local views");

        status = NtUnmapViewOfSection(NtCurrentProcess(), tailView);
        ok(status == STATUS_SUCCESS, "unmap tail view -> %08lx", (unsigned long)status);
    }

    /* --- the LAST granule of the image still maps ---------------------------
     * The bound is `offset >= map_size`, so the highest legal offset is the
     * last granularity boundary strictly inside the image — one granule of
     * view, not a refusal. An implementation bounding the offset by a segment
     * or by the file's raw size refuses here. */
    lastGranule = (ULONGLONG)((wholeSize - 1) & ~(SIZE_T)(granularity - 1));
    status = map_at_offset(section, NtCurrentProcess(), lastGranule, &lastView, &lastSize);
    ok(mapped_ok(status), "last-granule map (+%llx) -> %08lx", lastGranule, (unsigned long)status);
    ok(lastSize == wholeSize - lastGranule, "last-granule size %llx want %llx",
       (unsigned long long)lastSize, (unsigned long long)(wholeSize - lastGranule));
    if (lastView)
    {
        ok_same_bytes((char *)whole + lastGranule, lastView, lastSize, "last granule");
        status = NtUnmapViewOfSection(NtCurrentProcess(), lastView);
        ok(status == STATUS_SUCCESS, "unmap last granule -> %08lx", (unsigned long)status);
    }

    /* --- an offset AT or past the image's end is STATUS_INVALID_PARAMETER ---
     * The next granularity boundary is at or above map_size for every image
     * (it is equal only when the map size is itself a multiple of 64K, and
     * `>=` covers both). */
    pastImage = (ULONGLONG)((wholeSize + granularity - 1) & ~(SIZE_T)(granularity - 1));
    refusedSize = SENTINEL_SIZE;
    status = map_at_offset(section, NtCurrentProcess(), pastImage, &view, &refusedSize);
    ok(status == STATUS_INVALID_PARAMETER, "offset %llx past a %llx image -> %08lx", pastImage,
       (unsigned long long)wholeSize, (unsigned long)status);
    /* The BASE slot is untouched. The SIZE slot deliberately is not pinned
     * here, and the reason is measured rather than assumed: ntdll.dll is a
     * Wine BUILTIN, so on the oracle this call reaches
     * virtual_map_builtin_module (dlls/ntdll/unix/virtual.c) — whose second
     * statement is `*size = 0;` — before virtual_map_image's offset check
     * ever runs. That zero is the builtin loader's, not the refusal's, and
     * proskrnl has no builtin path to reproduce it with. */
    ok(view == NULL, "refused map wrote a base %p", view);

    /* --- and an offset that is not granularity-aligned is an ALIGNMENT fault -
     * Checked in NtMapViewOfSection itself, above everything virtual_map_image
     * does, so a page-aligned offset inside the image never reaches the trim. */
    refusedSize = SENTINEL_SIZE;
    status = map_at_offset(section, NtCurrentProcess(), 0x1000, &view, &refusedSize);
    ok(status == STATUS_MAPPED_ALIGNMENT, "page-aligned offset -> %08lx", (unsigned long)status);
    /* This one refuses in NtMapViewOfSection itself, above everything the
     * builtin path does, so BOTH slots survive — which is what makes the
     * pair worth measuring: the two refusals differ in exactly that. */
    ok(view == NULL && refusedSize == SENTINEL_SIZE, "misaligned map wrote back %p / %llx", view,
       (unsigned long long)refusedSize);

    test_remote_target(section, granularity);

    status = NtUnmapViewOfSection(NtCurrentProcess(), whole);
    ok(status == STATUS_SUCCESS, "unmap whole image -> %08lx", (unsigned long)status);
    NtClose(section);
}
