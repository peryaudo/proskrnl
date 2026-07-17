/*
 * sem_mm/anonymous_section.c — pagefile-backed (anonymous) section objects:
 * NtCreateSection / NtOpenSection / NtMapViewOfSection / NtUnmapViewOfSection
 * / NtQuerySection (M5, docs/02).
 *
 * Distilled from Wine's dlls/ntdll/tests/virtual.c test_NtMapViewOfSection
 * (the alignment/conflict corners are those exact ok()s) plus the parameter
 * conventions of Wine's implementation (server/mapping.c get_mapping_flags /
 * create_mapping and dlls/ntdll/unix/virtual.c virtual_map_section — the
 * reference for behaviour, not code). Green on the pinned Wine oracle before
 * the kernel implements it (Art. 5).
 */
#include "util.h"

START_TEST(anonymous_section)
{
    NTSTATUS status;
    HANDLE section, section2;
    LARGE_INTEGER max_size, offset;
    SIZE_T view_size, retlen;
    mm_section_basic_info sbi;
    MEMORY_BASIC_INFORMATION mbi;
    char *view1, *view2, *view3;
    void *addr;

    /* --- creation parameter conventions ---------------------------------- */

    /* An anonymous section must be given a size. */
    section = NULL;
    status =
        NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READWRITE, SEC_COMMIT, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "no size -> %08lx", (unsigned long)status);

    max_size.QuadPart = 0;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max_size, PAGE_READWRITE,
                             SEC_COMMIT, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "zero size -> %08lx", (unsigned long)status);

    /* Exactly one of SEC_COMMIT/SEC_RESERVE/SEC_IMAGE must be given. */
    max_size.QuadPart = 0x10000;
    status =
        NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max_size, PAGE_READWRITE, 0, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "no SEC_ flag -> %08lx", (unsigned long)status);

    /* Protection 0 is not a valid page protection. */
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max_size, 0, SEC_COMMIT, NULL);
    ok(status == STATUS_INVALID_PAGE_PROTECTION, "protect 0 -> %08lx", (unsigned long)status);

    /* SEC_IMAGE requires a file. */
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max_size, PAGE_READWRITE,
                             SEC_IMAGE, NULL);
    ok(status == STATUS_INVALID_FILE_FOR_SECTION, "SEC_IMAGE without file -> %08lx",
       (unsigned long)status);

    /* --- create + NtQuerySection ------------------------------------------ */

    max_size.QuadPart = 0x20000;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max_size, PAGE_READWRITE,
                             SEC_COMMIT, NULL);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);

    retlen = 0;
    status = NtQuerySection(section, SECTION_BASIC_INFO_CLASS, &sbi, sizeof(sbi), &retlen);
    ok(status == STATUS_SUCCESS, "query basic -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(sbi), "query retlen %lu", (unsigned long)retlen);
    ok(sbi.base_address == NULL, "BaseAddress %p", sbi.base_address);
    ok(sbi.attributes == SEC_COMMIT, "Attributes %08lx", (unsigned long)sbi.attributes);
    ok(sbi.size.QuadPart == 0x20000, "Size %lx", (unsigned long)sbi.size.QuadPart);

    status = NtQuerySection(section, SECTION_BASIC_INFO_CLASS, &sbi, sizeof(sbi) - 1, &retlen);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short query -> %08lx", (unsigned long)status);

    /* A data section has no image information. */
    {
        char image_info[64];
        status =
            NtQuerySection(section, SECTION_IMAGE_INFO_CLASS, image_info, sizeof(image_info), NULL);
        ok(status == STATUS_SECTION_NOT_IMAGE, "image query on data section -> %08lx",
           (unsigned long)status);
    }

    /* --- map a view -------------------------------------------------------- */

    view1 = NULL;
    view_size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view1, 0, 0, &offset,
                                &view_size, ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "map -> %08lx", (unsigned long)status);
    ok(((ULONG_PTR)view1 & 0xFFFF) == 0, "view %p not 64K aligned", view1);
    ok(view_size == 0x20000, "view size %lx", (unsigned long)view_size);
    ok(view1[0] == 0 && view1[0x1FFFF] == 0, "view not zero-initialized");

    status = NtQueryVirtualMemory(NtCurrentProcess(), view1, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), NULL);
    ok(status == STATUS_SUCCESS, "query view -> %08lx", (unsigned long)status);
    ok(mbi.State == MEM_COMMIT, "view State %lx", (unsigned long)mbi.State);
    ok(mbi.Protect == PAGE_READWRITE, "view Protect %lx", (unsigned long)mbi.Protect);
    ok(mbi.AllocationProtect == PAGE_READWRITE, "view AllocationProtect %lx",
       (unsigned long)mbi.AllocationProtect);
    ok(mbi.Type == MEM_MAPPED, "view Type %lx", (unsigned long)mbi.Type);
    ok(mbi.AllocationBase == view1, "view AllocationBase %p", mbi.AllocationBase);
    ok(mbi.RegionSize == 0x20000, "view RegionSize %lx", (unsigned long)mbi.RegionSize);

    view1[0] = 0x11;
    view1[0x10000] = 0x22;
    view1[0x1FFFF] = 0x33;

    /* --- a second view shares the pages ----------------------------------- */

    view2 = NULL;
    view_size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view2, 0, 0, &offset,
                                &view_size, ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "map second view -> %08lx", (unsigned long)status);
    ok(view2 != view1, "second view at the same address");
    ok(view2[0] == 0x11 && view2[0x1FFFF] == 0x33, "second view sees other view's writes");
    view2[1] = 0x44;
    ok(view1[1] == 0x44, "first view sees second view's writes");

    /* --- an offset view maps the section tail ----------------------------- */

    view3 = NULL;
    view_size = 0;
    offset.QuadPart = 0x10000;
    status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view3, 0, 0, &offset,
                                &view_size, ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "map offset view -> %08lx", (unsigned long)status);
    ok(view_size == 0x10000, "offset view size %lx", (unsigned long)view_size);
    ok(view3[0] == 0x22, "offset view content %02x", view3[0]);
    view3[2] = 0x55;
    ok(view1[0x10002] == 0x55, "offset view shares pages");

    /* --- mapping conventions ----------------------------------------------- */

    /* Offset at (or past) the end of the section. */
    addr = NULL;
    view_size = 0;
    offset.QuadPart = 0x20000;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &addr, 0, 0, &offset, &view_size,
                                ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER, "offset at end -> %08lx", (unsigned long)status);

    /* View larger than the section. */
    addr = NULL;
    view_size = 0x30000;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &addr, 0, 0, &offset, &view_size,
                                ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_INVALID_VIEW_SIZE, "oversize view -> %08lx", (unsigned long)status);

    /* Offset must be granularity-aligned. */
    addr = NULL;
    view_size = 0;
    offset.QuadPart = 1;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &addr, 0, 0, &offset, &view_size,
                                ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_MAPPED_ALIGNMENT, "byte offset -> %08lx", (unsigned long)status);

    addr = NULL;
    view_size = 0;
    offset.QuadPart = 0x1000;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &addr, 0, 0, &offset, &view_size,
                                ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_MAPPED_ALIGNMENT, "page offset -> %08lx", (unsigned long)status);

    /* An explicit address must be granularity-aligned too. */
    addr = view1 + 0x1000;
    view_size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &addr, 0, 0, &offset, &view_size,
                                ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_MAPPED_ALIGNMENT, "unaligned address -> %08lx", (unsigned long)status);

    /* Mapping over an existing view conflicts. */
    addr = view1;
    view_size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &addr, 0, 0, &offset, &view_size,
                                ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "conflicting map -> %08lx", (unsigned long)status);

    /* zero_bits between 22 and 31 is invalid (Wine's exact check). */
    addr = NULL;
    view_size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &addr, 25, 0, &offset, &view_size,
                                ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER_4, "zero_bits 25 -> %08lx", (unsigned long)status);

    /* --- a view is unmapped, never freed ----------------------------------- */

    addr = view1;
    view_size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &view_size, MEM_RELEASE);
    ok(status == STATUS_INVALID_PARAMETER, "free view -> %08lx", (unsigned long)status);

    /* Unmapping accepts any address inside the view. */
    status = NtUnmapViewOfSection(NtCurrentProcess(), view1 + 0x1000);
    ok(status == STATUS_SUCCESS, "unmap interior -> %08lx", (unsigned long)status);

    status = NtQueryVirtualMemory(NtCurrentProcess(), view1, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), NULL);
    ok(status == STATUS_SUCCESS, "query unmapped -> %08lx", (unsigned long)status);
    ok(mbi.State == MEM_FREE, "unmapped State %lx", (unsigned long)mbi.State);

    status = NtUnmapViewOfSection(NtCurrentProcess(), view1);
    ok(status == STATUS_NOT_MAPPED_VIEW, "unmap again -> %08lx", (unsigned long)status);

    /* --- views outlive the section handle ---------------------------------- */

    status = NtClose(section);
    ok(status == STATUS_SUCCESS, "close section -> %08lx", (unsigned long)status);
    ok(view2[0] == 0x11 && view2[1] == 0x44, "view dead after handle close");
    view2[3] = 0x66;
    ok(view3[0] == 0x22, "offset view dead after handle close");

    status = NtUnmapViewOfSection(NtCurrentProcess(), view2);
    ok(status == STATUS_SUCCESS, "unmap view2 -> %08lx", (unsigned long)status);
    status = NtUnmapViewOfSection(NtCurrentProcess(), view3);
    ok(status == STATUS_SUCCESS, "unmap view3 -> %08lx", (unsigned long)status);

    /* --- read-only views ---------------------------------------------------- */

    max_size.QuadPart = 0x1000;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max_size, PAGE_READWRITE,
                             SEC_COMMIT, NULL);
    ok(status == STATUS_SUCCESS, "create small -> %08lx", (unsigned long)status);

    view1 = NULL;
    view_size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view1, 0, 0, &offset,
                                &view_size, ViewShare, 0, PAGE_READONLY);
    ok(status == STATUS_SUCCESS, "map read-only -> %08lx", (unsigned long)status);
    ok(view_size == 0x1000, "read-only view size %lx", (unsigned long)view_size);

    status = NtQueryVirtualMemory(NtCurrentProcess(), view1, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), NULL);
    ok(status == STATUS_SUCCESS, "query read-only view -> %08lx", (unsigned long)status);
    ok(mbi.Protect == PAGE_READONLY, "read-only Protect %lx", (unsigned long)mbi.Protect);
    ok(mbi.AllocationProtect == PAGE_READONLY, "read-only AllocationProtect %lx",
       (unsigned long)mbi.AllocationProtect);
    ok(mbi.Type == MEM_MAPPED, "read-only Type %lx", (unsigned long)mbi.Type);

    status = NtUnmapViewOfSection(NtCurrentProcess(), view1);
    ok(status == STATUS_SUCCESS, "unmap read-only -> %08lx", (unsigned long)status);
    NtClose(section);

    /* --- named sections through the namespace ------------------------------ */

    {
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;

        init_ustr(&name, W("\\BaseNamedObjects\\proskrnl_sem_sec"));
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);

        max_size.QuadPart = 0x1000;
        status = NtCreateSection(&section, SECTION_ALL_ACCESS, &attr, &max_size, PAGE_READWRITE,
                                 SEC_COMMIT, NULL);
        ok(status == STATUS_SUCCESS, "create named -> %08lx", (unsigned long)status);

        /* Same name again: collision, or the existing object under OBJ_OPENIF. */
        status = NtCreateSection(&section2, SECTION_ALL_ACCESS, &attr, &max_size, PAGE_READWRITE,
                                 SEC_COMMIT, NULL);
        ok(status == STATUS_OBJECT_NAME_COLLISION, "named collision -> %08lx",
           (unsigned long)status);

        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE | OBJ_OPENIF);
        status = NtCreateSection(&section2, SECTION_ALL_ACCESS, &attr, &max_size, PAGE_READWRITE,
                                 SEC_COMMIT, NULL);
        ok(status == STATUS_OBJECT_NAME_EXISTS, "OBJ_OPENIF collision -> %08lx",
           (unsigned long)status);
        NtClose(section2);

        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        status = NtOpenSection(&section2, SECTION_MAP_READ | SECTION_MAP_WRITE, &attr);
        ok(status == STATUS_SUCCESS, "open named -> %08lx", (unsigned long)status);

        /* Both handles resolve to one object: views share pages. */
        view1 = NULL;
        view_size = 0;
        offset.QuadPart = 0;
        status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view1, 0, 0, &offset,
                                    &view_size, ViewShare, 0, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "map created handle -> %08lx", (unsigned long)status);
        view2 = NULL;
        view_size = 0;
        offset.QuadPart = 0;
        status = NtMapViewOfSection(section2, NtCurrentProcess(), (void **)&view2, 0, 0, &offset,
                                    &view_size, ViewShare, 0, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "map opened handle -> %08lx", (unsigned long)status);
        view1[42] = 0x5a;
        ok(view2[42] == 0x5a, "named section views do not share pages");

        NtUnmapViewOfSection(NtCurrentProcess(), view1);
        NtUnmapViewOfSection(NtCurrentProcess(), view2);
        NtClose(section);
        NtClose(section2);

        /* The name is gone once the last handle closes. */
        status = NtOpenSection(&section2, SECTION_MAP_READ, &attr);
        ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "open after close -> %08lx",
           (unsigned long)status);
    }
}
