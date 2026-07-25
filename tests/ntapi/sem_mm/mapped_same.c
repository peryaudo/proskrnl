/*
 * sem_mm/mapped_same.c — NtAreMappedFilesTheSame: the loader's
 * find_existing_module probe (dlls/ntdll/loader.c uses it to recognise a
 * module image already loaded from the same file). Statuses distilled from
 * Wine's dlls/ntdll/unix/virtual.c NtAreMappedFilesTheSame plus
 * server/mapping.c is_same_mapping:
 *
 *   unmapped address (either)          -> STATUS_INVALID_ADDRESS
 *   VirtualAlloc'd (non-view) memory   -> STATUS_CONFLICTING_ADDRESSES
 *   both addresses in ONE view         -> STATUS_SUCCESS
 *   two views: same only when both are file-backed, the FIRST view is
 *   SEC_IMAGE, and the backing file is the same file; anything else
 *   (data-section first view included) -> STATUS_NOT_SAME_DEVICE
 *
 * Green on the pinned Wine oracle first (Art. 5).
 */
#include "util.h"

#include <windows.h>
#include <string.h> /* declarations only: the .exe links no CRT (ntapi.c) */

NTSYSAPI NTSTATUS NTAPI NtAreMappedFilesTheSame(PVOID, PVOID);

START_TEST(mapped_same)
{
    NTSTATUS status;
    char path[MAX_PATH];
    HANDLE file, file2, section, section2, data_section;
    char *image1 = NULL, *image2 = NULL, *data1 = NULL;
    SIZE_T view_size;
    void *alloc = NULL;
    SIZE_T alloc_size = 0x1000;

    /* --- unmapped addresses --------------------------------------------- */
    status = NtAreMappedFilesTheSame(NULL, NULL);
    ok(status == STATUS_INVALID_ADDRESS, "NULL/NULL -> %08lx", (unsigned long)status);
    status = NtAreMappedFilesTheSame((void *)0x1000, (void *)0x1000);
    ok(status == STATUS_INVALID_ADDRESS, "low unmapped -> %08lx", (unsigned long)status);

    /* --- VirtualAlloc'd memory is not a mapped file ---------------------- */
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &alloc, 0, &alloc_size,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "allocate -> %08lx", (unsigned long)status);
    status = NtAreMappedFilesTheSame(alloc, alloc);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "valloc/valloc -> %08lx", (unsigned long)status);

    /* --- two image views of the same file: the loader's actual question --
     * Two separate opens + two separate SEC_IMAGE sections over the same
     * DLL, each mapped once — exactly what a module loaded twice looks
     * like. */
    GetSystemDirectoryA(path, sizeof(path));
    strcat(path, "\\ntdll.dll");
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
    ok(file != INVALID_HANDLE_VALUE, "cannot open %s (%lu)", path, (unsigned long)GetLastError());
    file2 = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
    ok(file2 != INVALID_HANDLE_VALUE, "cannot open %s (2) (%lu)", path,
       (unsigned long)GetLastError());

    section = NULL;
    status =
        NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file);
    ok(status == STATUS_SUCCESS, "image section 1 -> %08lx", (unsigned long)status);
    section2 = NULL;
    status =
        NtCreateSection(&section2, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file2);
    ok(status == STATUS_SUCCESS, "image section 2 -> %08lx", (unsigned long)status);

    view_size = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), (PVOID *)&image1, 0, 0, NULL,
                                &view_size, ViewShare, 0, PAGE_READONLY);
    ok(NT_SUCCESS(status), "map image 1 -> %08lx", (unsigned long)status);
    view_size = 0;
    status = NtMapViewOfSection(section2, NtCurrentProcess(), (PVOID *)&image2, 0, 0, NULL,
                                &view_size, ViewShare, 0, PAGE_READONLY);
    ok(NT_SUCCESS(status), "map image 2 -> %08lx", (unsigned long)status);
    ok(image1 != image2, "two views at one base (%p)", image1);

    /* Both addresses inside ONE view. */
    status = NtAreMappedFilesTheSame(image1, image1 + 0x1000);
    ok(status == STATUS_SUCCESS, "same view -> %08lx", (unsigned long)status);

    /* Two image views of the same file. */
    status = NtAreMappedFilesTheSame(image1, image2);
    ok(status == STATUS_SUCCESS, "image/image same file -> %08lx", (unsigned long)status);

    /* An image view against private memory. */
    status = NtAreMappedFilesTheSame(image1, alloc);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "image/valloc -> %08lx", (unsigned long)status);

    /* --- a DATA view is never "the same" (first-view SEC_IMAGE rule) -----
     * server/mapping.c is_same_mapping tests only view1's SEC_IMAGE flag:
     * a data-section first view refuses even against the same file. */
    data_section = NULL;
    status = NtCreateSection(&data_section, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_COMMIT,
                             file);
    ok(status == STATUS_SUCCESS, "data section -> %08lx", (unsigned long)status);
    view_size = 0;
    status = NtMapViewOfSection(data_section, NtCurrentProcess(), (PVOID *)&data1, 0, 0, NULL,
                                &view_size, ViewShare, 0, PAGE_READONLY);
    ok(NT_SUCCESS(status), "map data -> %08lx", (unsigned long)status);

    status = NtAreMappedFilesTheSame(data1, image1);
    ok(status == STATUS_NOT_SAME_DEVICE, "data/image -> %08lx", (unsigned long)status);
    status = NtAreMappedFilesTheSame(data1, data1 + 0x200);
    ok(status == STATUS_SUCCESS, "one data view -> %08lx", (unsigned long)status);

    NtUnmapViewOfSection(NtCurrentProcess(), data1);
    NtUnmapViewOfSection(NtCurrentProcess(), image2);
    NtUnmapViewOfSection(NtCurrentProcess(), image1);
    NtClose(data_section);
    NtClose(section2);
    NtClose(section);
    CloseHandle(file2);
    CloseHandle(file);

    SIZE_T free_size = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), &alloc, &free_size, MEM_RELEASE);
}
