/*
 * sem_mm/image_info.c — NtQueryVirtualMemory(MemoryImageInformation).
 *
 * docs/21 W5's tail, and the last unbuilt class in the region cluster
 * (ntdll:virtual's test_query_image_information, which win_skips the whole
 * function when the class is refused).
 *
 * Transcribed from the pinned oracle's get_memory_image_info
 * (third_party/wine dlls/ntdll/unix/virtual.c) and the server handler it
 * calls (server/mapping.c DECL_HANDLER(get_image_view_info), whose
 * find_mapped_addr sets STATUS_NOT_MAPPED_VIEW). The order there is: LENGTH
 * first, then "is there an image view here", and only on
 * STATUS_NOT_MAPPED_VIEW a fall-back to MemoryBasicInformation which decides
 * between "success, all zeroes" and STATUS_INVALID_ADDRESS.
 *
 * The three things an implementation gets plausibly wrong, all measured here:
 *
 *   - the class answers SUCCESS with an ALL-ZERO struct for an address that
 *     is mapped but is not an image (a private allocation, a data view, a
 *     pagefile view). It is not a refusal, and the zeroes are the answer;
 *   - the length is checked BEFORE the address, so a free address with a
 *     short buffer is STATUS_INFO_LENGTH_MISMATCH and not
 *     STATUS_INVALID_ADDRESS;
 *   - an address ABOVE the user range is STATUS_INVALID_ADDRESS here, where
 *     MemoryRegionInformation answers STATUS_INVALID_PARAMETER for the same
 *     address (sem_mm/region_info.c test_out_of_range). The fall-back folds
 *     every basic-info error into one status.
 */
#include "util.h"

#include <string.h> /* declarations only: the .exe links no CRT (ntapi.c) */

/* MEMORY_INFORMATION_CLASS value, as wine/include/winternl.h. */
#define MEMORY_IMAGE_INFO_CLASS 6

/* wine/include/winternl.h _MEMORY_IMAGE_INFORMATION. Declared locally for the
 * same reason the rest of this bucket declares its shapes: mingw's
 * winternl.h does not carry it. The oracle run validates the layout — a wrong
 * offset would move every field's value. */
typedef struct
{
    PVOID ImageBase;
    SIZE_T SizeOfImage;
    union
    {
        ULONG ImageFlags;
        struct
        {
            ULONG ImagePartialMap : 1;
            ULONG ImageNotExecutable : 1;
            ULONG ImageSigningLevel : 4;
            ULONG Reserved : 26;
        } bits;
    } u;
} SEM_MEMORY_IMAGE_INFORMATION;

static NTSTATUS query_image(void *addr, SEM_MEMORY_IMAGE_INFORMATION *info, SIZE_T length,
                            SIZE_T *lengthOut)
{
    memset(info, 0xcc, sizeof(*info));
    *lengthOut = (SIZE_T)0xdead;
    return NtQueryVirtualMemory(NtCurrentProcess(), addr, MEMORY_IMAGE_INFO_CLASS, info, length,
                                lengthOut);
}

/* The signing level is the ONE field the two runners are allowed to disagree
 * on, and the winetest says so itself: it accepts 0 or 12 for every image it
 * queries (dlls/ntdll/tests/virtual.c test_query_image_information). The
 * pinned oracle reports 12 unconditionally; proskrnl reports 0, because
 * nothing on this system checks an image signature and 12 would be a claim
 * about a check that never ran. Both are inside the boundary's own tolerance
 * — docs/03 "`MemoryImageInformation` reports signing level ZERO" has the
 * trade. */
static void check_signing_level(const SEM_MEMORY_IMAGE_INFORMATION *info, const char *what)
{
    ok(info->u.bits.ImageSigningLevel == 0 || info->u.bits.ImageSigningLevel == 12,
       "%s signing level %lu", what, (unsigned long)info->u.bits.ImageSigningLevel);
}

/* A private allocation is MAPPED but is not an image: SUCCESS, every field
 * zero, ReturnLength the whole struct. An implementation that refused a
 * non-image address would fail here and pass every image case below. */
static void test_private(void)
{
    SEM_MEMORY_IMAGE_INFORMATION info;
    SIZE_T size = 0x8000, len = 0;
    void *ptr = NULL;
    NTSTATUS status;

    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &ptr, 0, &size, MEM_RESERVE, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "reserve -> %08lx", (unsigned long)status);

    status = query_image(ptr, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "private -> %08lx", (unsigned long)status);
    ok(len == sizeof(info), "ReturnLength %llx", (unsigned long long)len);
    ok(info.ImageBase == NULL, "private base %p", info.ImageBase);
    ok(info.SizeOfImage == 0, "private size %llx", (unsigned long long)info.SizeOfImage);
    ok(info.u.ImageFlags == 0, "private flags %lx", (unsigned long)info.u.ImageFlags);

    /* An unaligned address INSIDE the same allocation answers identically —
     * the address is rounded down to its page, not required to be a base. */
    status = query_image((char *)ptr + 0x1234, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "private mid -> %08lx", (unsigned long)status);
    ok(info.ImageBase == NULL, "private mid base %p", info.ImageBase);
    ok(info.SizeOfImage == 0, "private mid size %llx", (unsigned long long)info.SizeOfImage);
    ok(info.u.ImageFlags == 0, "private mid flags %lx", (unsigned long)info.u.ImageFlags);

    /* Past its end is FREE, and free is a REFUSAL — but NOT a refusal that
     * leaves the caller's buffer alone. THE ORACLE REFUTED THAT GUESS: the
     * struct is ZEROED and the refusal is decided afterwards, because the
     * memset sits between the length check and the lookup
     * (get_memory_image_info). ReturnLength is the field that survives, and
     * only because it is written on success alone. So this class differs
     * from MemoryRegionInformation on BOTH halves of the same question —
     * that one leaves every byte of the buffer intact on its refusal
     * (sem_mm/region_info.c test_free_address). */
    status = query_image((char *)ptr + size, &info, sizeof(info), &len);
    ok(status == STATUS_INVALID_ADDRESS, "free -> %08lx", (unsigned long)status);
    ok(len == (SIZE_T)0xdead, "free ReturnLength %llx", (unsigned long long)len);
    ok(info.ImageBase == NULL, "free base not zeroed %p", info.ImageBase);
    ok(info.SizeOfImage == 0, "free size not zeroed %llx", (unsigned long long)info.SizeOfImage);
    ok(info.u.ImageFlags == 0, "free flags not zeroed %lx", (unsigned long)info.u.ImageFlags);

    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &ptr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "release -> %08lx", (unsigned long)status);
}

/* The LENGTH rule, and the ORDER it sits in. Unlike
 * MemoryRegionInformation, this class's minimum IS its own size: one byte
 * short is a mismatch and there is no partial fill. And the check runs
 * BEFORE the address is looked at — the oracle returns on `len <
 * sizeof(*info)` before it ever reaches the server — so a FREE address with
 * a short buffer reports the LENGTH, not the address. */
static void test_length_rule(void)
{
    SEM_MEMORY_IMAGE_INFORMATION info;
    SIZE_T size = 0x8000, len = 0;
    void *ptr = NULL, *freed;
    NTSTATUS status;

    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &ptr, 0, &size, MEM_RESERVE, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "reserve -> %08lx", (unsigned long)status);

    /* The poison SURVIVES this one, where the free-address refusal above
     * zeroes it — which is the evidence for where the memset sits: after the
     * length check and before the lookup, so exactly one of the two refusals
     * has run it. */
    status = query_image(ptr, &info, sizeof(info) - 1, &len);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short -> %08lx", (unsigned long)status);
    ok(len == (SIZE_T)0xdead, "short ReturnLength %llx", (unsigned long long)len);
    ok(info.ImageBase == (void *)(ULONG_PTR)0xccccccccccccccccULL, "short base overwritten %p",
       info.ImageBase);

    /* A buffer LARGER than the struct is accepted, and ReturnLength still
     * reports the struct rather than the buffer. */
    status = query_image(ptr, &info, sizeof(info) + 2, &len);
    ok(status == STATUS_SUCCESS, "oversize -> %08lx", (unsigned long)status);
    ok(len == sizeof(info), "oversize ReturnLength %llx", (unsigned long long)len);

    /* NULL ReturnLength is served, not refused. */
    memset(&info, 0xcc, sizeof(info));
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MEMORY_IMAGE_INFO_CLASS, &info,
                                  sizeof(info), NULL);
    ok(status == STATUS_SUCCESS, "null ReturnLength -> %08lx", (unsigned long)status);
    ok(info.u.ImageFlags == 0, "null ReturnLength flags %lx", (unsigned long)info.u.ImageFlags);

    freed = ptr;
    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &ptr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "release -> %08lx", (unsigned long)status);

    /* LENGTH before ADDRESS: the same freed address that answers
     * STATUS_INVALID_ADDRESS at full size answers the length mismatch when
     * the buffer is short. */
    status = query_image(freed, &info, sizeof(info), &len);
    ok(status == STATUS_INVALID_ADDRESS, "freed, full buffer -> %08lx", (unsigned long)status);
    status = query_image(freed, &info, sizeof(info) - 1, &len);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "freed, short buffer -> %08lx",
       (unsigned long)status);
}

/* An address above the user range. THIS CLASS ANSWERS STATUS_INVALID_ADDRESS
 * where MemoryRegionInformation answers STATUS_INVALID_PARAMETER for the very
 * same address, because the fall-back folds every MemoryBasicInformation
 * error into one status (`if (status || basic_info.State == MEM_FREE) status
 * = STATUS_INVALID_ADDRESS;`). Reusing the region class's range check
 * verbatim would fail exactly this assertion and nothing else. */
static void test_out_of_range(void)
{
    SEM_MEMORY_IMAGE_INFORMATION info;
    SIZE_T len = 0;
    NTSTATUS status;

    status = query_image((void *)((ULONG_PTR)0x7fffffff0000ULL + 0x100000000000ULL), &info,
                         sizeof(info), &len);
    ok(status == STATUS_INVALID_ADDRESS, "kernel address -> %08lx", (unsigned long)status);
    ok(len == (SIZE_T)0xdead, "kernel address ReturnLength %llx", (unsigned long long)len);
}

/* A DATA view of a real file and a PAGEFILE-backed view: both are mapped,
 * neither is an image, so both answer SUCCESS with zeroes. Without these two
 * an implementation that reported any mapped view as an image would pass
 * every other case in this file. */
static void test_data_views(void)
{
    SEM_MEMORY_IMAGE_INFORMATION info;
    LARGE_INTEGER sectionSize;
    SIZE_T viewSize = 0, len = 0;
    HANDLE section = NULL, file;
    void *ptr = NULL;
    NTSTATUS status;
    char path[MAX_PATH];

    GetSystemDirectoryA(path, sizeof(path));
    strcat(path, "\\ntdll.dll");
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
    ok(file != INVALID_HANDLE_VALUE, "cannot open %s", path);

    sectionSize.QuadPart = 0x10000;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_READONLY,
                             SEC_COMMIT, file);
    ok(status == STATUS_SUCCESS, "create data section -> %08lx", (unsigned long)status);

    status = NtMapViewOfSection(section, NtCurrentProcess(), &ptr, 0, 0, NULL, &viewSize, ViewShare,
                                0, PAGE_READONLY);
    ok(status == STATUS_SUCCESS, "map data view -> %08lx", (unsigned long)status);

    status = query_image((char *)ptr + 0x1234, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "data view -> %08lx", (unsigned long)status);
    ok(len == sizeof(info), "data view ReturnLength %llx", (unsigned long long)len);
    ok(info.ImageBase == NULL, "data view base %p (view %p)", info.ImageBase, ptr);
    ok(info.SizeOfImage == 0, "data view size %llx", (unsigned long long)info.SizeOfImage);
    ok(info.u.ImageFlags == 0, "data view flags %lx", (unsigned long)info.u.ImageFlags);

    status = NtUnmapViewOfSection(NtCurrentProcess(), ptr);
    ok(status == STATUS_SUCCESS, "unmap data view -> %08lx", (unsigned long)status);
    NtClose(section);
    CloseHandle(file);

    section = NULL;
    ptr = NULL;
    viewSize = 0;
    sectionSize.QuadPart = 0x10000;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_READWRITE,
                             SEC_COMMIT, NULL);
    ok(status == STATUS_SUCCESS, "create pagefile section -> %08lx", (unsigned long)status);

    status = NtMapViewOfSection(section, NtCurrentProcess(), &ptr, 0, 0, NULL, &viewSize, ViewShare,
                                0, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "map pagefile view -> %08lx", (unsigned long)status);

    status = query_image(ptr, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "pagefile view -> %08lx", (unsigned long)status);
    ok(info.ImageBase == NULL, "pagefile view base %p (view %p)", info.ImageBase, ptr);
    ok(info.SizeOfImage == 0, "pagefile view size %llx", (unsigned long long)info.SizeOfImage);
    ok(info.u.ImageFlags == 0, "pagefile view flags %lx", (unsigned long)info.u.ImageFlags);

    status = NtUnmapViewOfSection(NtCurrentProcess(), ptr);
    ok(status == STATUS_SUCCESS, "unmap pagefile view -> %08lx", (unsigned long)status);
    NtClose(section);
}

/* The LOADED ntdll: an image view nothing in this test created, so it also
 * proves the answer comes from the view's own record rather than from
 * whatever the last NtMapViewOfSection happened to leave behind. SizeOfImage
 * is the PE optional header's own SizeOfImage — a view size that merely
 * looked right for a section created here would diverge on this one. */
static void test_loaded_module(void)
{
    SEM_MEMORY_IMAGE_INFORMATION info;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    SIZE_T len = 0;
    NTSTATUS status;
    void *base;

    base = (void *)GetModuleHandleA("ntdll.dll");
    ok(base != NULL, "no ntdll.dll module handle");
    dos = (IMAGE_DOS_HEADER *)base;
    nt = (IMAGE_NT_HEADERS64 *)((char *)base + dos->e_lfanew);

    status = query_image((char *)base + 0x1234, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "loaded module -> %08lx", (unsigned long)status);
    ok(len == sizeof(info), "loaded module ReturnLength %llx", (unsigned long long)len);
    ok(info.ImageBase == base, "loaded module base %p want %p", info.ImageBase, base);
    ok(info.SizeOfImage == nt->OptionalHeader.SizeOfImage, "loaded module size %llx want %lx",
       (unsigned long long)info.SizeOfImage, (unsigned long)nt->OptionalHeader.SizeOfImage);
    ok(info.u.bits.ImagePartialMap == 0, "loaded module partial map");
    ok(info.u.bits.ImageNotExecutable == 0, "loaded module not executable");
    check_signing_level(&info, "loaded module");
}

/* An image view this test creates and maps. The whole image is mapped
 * whatever view size was asked for, so SizeOfImage is the optional header's
 * SizeOfImage and ImagePartialMap stays clear — and the query from the
 * middle of the view reports the view's BASE, not the queried page. */
static void test_image_view(void)
{
    SEM_MEMORY_IMAGE_INFORMATION info;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    SIZE_T viewSize = 0, len = 0;
    HANDLE section = NULL, file;
    void *ptr = NULL;
    NTSTATUS status;
    char path[MAX_PATH];

    GetSystemDirectoryA(path, sizeof(path));
    strcat(path, "\\kernel32.dll");
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
    ok(file != INVALID_HANDLE_VALUE, "cannot open %s", path);

    status =
        NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file);
    ok(status == STATUS_SUCCESS, "create image section -> %08lx", (unsigned long)status);

    /* kernel32 is already loaded at its preferred base, so this second view
     * lands elsewhere and the map reports STATUS_IMAGE_NOT_AT_BASE. Both
     * runners answer that; it is not the subject here, only the reason the
     * status is not plain SUCCESS. */
    status = NtMapViewOfSection(section, NtCurrentProcess(), &ptr, 0, 0, NULL, &viewSize, ViewShare,
                                0, PAGE_READONLY);
    ok(status == STATUS_IMAGE_NOT_AT_BASE || status == STATUS_SUCCESS, "map image -> %08lx",
       (unsigned long)status);

    dos = (IMAGE_DOS_HEADER *)ptr;
    nt = (IMAGE_NT_HEADERS64 *)((char *)ptr + dos->e_lfanew);

    status = query_image((char *)ptr + 0x1234, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "image view -> %08lx", (unsigned long)status);
    ok(len == sizeof(info), "image view ReturnLength %llx", (unsigned long long)len);
    ok(info.ImageBase == ptr, "image view base %p want %p", info.ImageBase, ptr);
    ok(info.SizeOfImage == nt->OptionalHeader.SizeOfImage, "image view size %llx want %lx",
       (unsigned long long)info.SizeOfImage, (unsigned long)nt->OptionalHeader.SizeOfImage);
    ok(info.SizeOfImage == viewSize, "image view size %llx want view %llx",
       (unsigned long long)info.SizeOfImage, (unsigned long long)viewSize);
    ok(info.u.bits.ImagePartialMap == 0, "image view partial map");
    ok(info.u.bits.ImageNotExecutable == 0, "image view not executable");
    check_signing_level(&info, "image view");

    /* The FIRST page of the view answers the same, and the LAST byte of it
     * too — the whole reservation belongs to the image, so there is no tail
     * the class stops describing. */
    status = query_image(ptr, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "image view base page -> %08lx", (unsigned long)status);
    ok(info.ImageBase == ptr, "image view base page %p want %p", info.ImageBase, ptr);

    status = query_image((char *)ptr + viewSize - 1, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "image view last byte -> %08lx", (unsigned long)status);
    ok(info.ImageBase == ptr, "image view last byte %p want %p", info.ImageBase, ptr);

    /* One byte PAST the view is free again, and free is the refusal — so the
     * image answer is bounded by the view and does not leak into the hole
     * after it. */
    status = query_image((char *)ptr + viewSize, &info, sizeof(info), &len);
    ok(status == STATUS_INVALID_ADDRESS || status == STATUS_SUCCESS, "past image view -> %08lx",
       (unsigned long)status);
    if (status == STATUS_SUCCESS)
    {
        /* Something else is mapped immediately after the view; then it is at
         * least not THIS image. */
        ok(info.ImageBase != ptr, "past image view still reports %p", info.ImageBase);
    }

    status = NtUnmapViewOfSection(NtCurrentProcess(), ptr);
    ok(status == STATUS_SUCCESS, "unmap image -> %08lx", (unsigned long)status);
    NtClose(section);
    CloseHandle(file);
}

START_TEST(image_info)
{
    test_private();
    test_length_rule();
    test_out_of_range();
    test_data_views();
    test_loaded_module();
    test_image_view();
}
