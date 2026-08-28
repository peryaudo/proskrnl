/*
 * sem_mm/image_section_table.c — where a PE's SECTION TABLE is allowed to
 * live, and what SizeOfHeaders means once it has been found.
 *
 * A linker writes SizeOfHeaders rounded up to FileAlignment, so the section
 * table always sits comfortably inside it and the question never comes up.
 * A HAND-BUILT PE is where it does: set SizeOfHeaders to exactly
 * sizeof(DOS) + sizeof(NT) and the table starts on the byte after the
 * headers end. That is not malformed — the image simply declares a header
 * region smaller than its own table, and NT loads it.
 *
 * The pinned oracle says so in two lines (third_party/wine server/mapping.c
 * get_image_params, the "load the section headers" block):
 *
 *     if (pos + size > mapping->image.map_size) return STATUS_INVALID_FILE_FOR_SECTION;
 *     if (pos + size > mapping->image.header_size) mapping->image.header_size = pos + size;
 *
 * — so the table is bounded by the IMAGE (SizeOfImage, rounded), never by
 * SizeOfHeaders, and where it overruns SizeOfHeaders the header region GROWS
 * to cover it. Both halves are observable from ring 3 and both are pinned
 * below:
 *
 *   - the bound, because NtCreateSection either accepts the image or does
 *     not, and with which status;
 *   - the growth, because dlls/ntdll/unix/virtual.c map_image_into_view
 *     zeroes the mapped view from `header_size` to the end of the header
 *     page (`memset( ptr + header_size, 0, header_end - (ptr + header_size) )`)
 *     before mapping the sections over it. Whether the section table is
 *     READABLE IN THE VIEW is therefore exactly the question of whether
 *     header_size grew — the bytes are inside the first page either way, and
 *     an implementation that copies only the declared SizeOfHeaders leaves
 *     zeroes where the table should be.
 *
 * CONVICTED BY THE WINETEST GATE. kernel32:resource's test_mui builds this
 * image by hand (third_party/wine dlls/kernel32/tests/resource.c, the
 * `dll_image` struct at :523 and create_test_dll at :592): SizeOfHeaders is
 * spelled `sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)`, one section
 * follows it, and the file is extended to SizeOfImage. proskrnl refused it
 * (kernel/mm/pecoff.c bounded the table by SizeOfHeaders), so
 * GetFileMUIInfo's LOAD_LIBRARY_AS_IMAGE_RESOURCE mapping — which is a plain
 * CreateFileMapping(PAGE_READONLY | SEC_IMAGE), dlls/kernelbase/loader.c
 * load_library_as_datafile — failed with ERROR_BAD_EXE_FORMAT, and all 21 of
 * the pair's remaining failures were resource.c:680 and the 0xfe fill
 * cascading out of it. The header geometry below is that image's; its
 * SECTION's raw fields are a second rule and are pinned separately, at the
 * end of this file.
 *
 * Oracle-first (G5): every assertion here was green on the pinned Wine
 * before any kernel code changed.
 */
#include "../sem_file/util.h"

/* The section surface (as sem_mm/util.h; redeclared here because this test
 * also needs the file surface from sem_file/util.h — the view_close_reopen.c
 * arrangement). */
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

#define PAGE_BYTES      0x1000u
#define IMAGE_BYTES     0x3000u
#define IMAGE_PREFERRED 0x10000000ULL

/* Where the section table starts in this layout, and the SizeOfHeaders that
 * ends exactly where it starts. Derived, never written down: the winetest
 * spells its SizeOfHeaders the same way (`sizeof(IMAGE_DOS_HEADER) +
 * sizeof(IMAGE_NT_HEADERS)`), and a literal here would only be right for one
 * toolchain's padding. */
#define TIGHT_HEADERS (ULONG)(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64))
#define TABLE_OFF                                                                                  \
    (ULONG)(sizeof(IMAGE_DOS_HEADER) + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +          \
            sizeof(IMAGE_OPTIONAL_HEADER64))

/* 96 is the Windows loader's own per-image section limit (MS "PE Format",
 * COFF File Header / NumberOfSections), so a refusal at this count is about
 * the TABLE'S EXTENT and not about the count being out of range — which is
 * what the two refusal cases need it to be. */
#define MANY_SECTIONS 96u

static UCHAR image_bytes[IMAGE_BYTES];

/* Lay a minimal PE into image_bytes: `headers` is what SizeOfHeaders will
 * claim, `count` what NumberOfSections will claim (and how many section
 * headers are really written), `image` what SizeOfImage will claim. Returns
 * the file offset one past the section table. */
static ULONG build_image(ULONG headers, ULONG count, ULONG image)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)image_bytes;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sec;
    ULONG i;

    memset(image_bytes, 0, sizeof(image_bytes));
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = (LONG)sizeof(*dos);

    nt = (IMAGE_NT_HEADERS64 *)(image_bytes + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = (USHORT)count;
    nt->FileHeader.SizeOfOptionalHeader = (USHORT)sizeof(nt->OptionalHeader);
    nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL;

    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.MajorLinkerVersion = 1;
    nt->OptionalHeader.BaseOfCode = PAGE_BYTES;
    nt->OptionalHeader.ImageBase = IMAGE_PREFERRED;
    nt->OptionalHeader.SectionAlignment = PAGE_BYTES;
    nt->OptionalHeader.FileAlignment = PAGE_BYTES;
    nt->OptionalHeader.MajorOperatingSystemVersion = 4;
    nt->OptionalHeader.MajorImageVersion = 1;
    nt->OptionalHeader.MajorSubsystemVersion = 4;
    nt->OptionalHeader.SizeOfImage = image;
    nt->OptionalHeader.SizeOfHeaders = headers;
    nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    /* The AMD64 arm of get_image_params does not require these, but the
     * winetest's image carries them and a pin that drifts from the shape it
     * is pinning measures a different image. */
    nt->OptionalHeader.DllCharacteristics =
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_DIRECTORY_ENTRY_RESOURCE + 1;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = PAGE_BYTES;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = PAGE_BYTES;

    sec =
        (IMAGE_SECTION_HEADER *)((char *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    for (i = 0; i < count; i++)
    {
        memcpy(sec[i].Name, ".rsrc", 6);
        /* Wholly uninitialized: no raw extent and no raw offset. The header
         * cases below only care about the TABLE, so they use the section
         * shape that says the least; what the winetest's own raw fields mean
         * is the separate rule at the end of this file. */
        sec[i].Misc.VirtualSize = PAGE_BYTES;
        sec[i].VirtualAddress = PAGE_BYTES * (i + 1);
        sec[i].SizeOfRawData = 0;
        sec[i].PointerToRawData = 0;
        sec[i].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    }
    return (ULONG)((char *)(sec + count) - (char *)image_bytes);
}

/* Write the first `bytes` of image_bytes to `name` and open a SEC_IMAGE
 * section over it. Returns the NtCreateSection status; *section is NULL on
 * anything but success. */
static NTSTATUS make_image_section(HANDLE dir, const void *name, ULONG bytes, HANDLE *section)
{
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    NTSTATUS status;
    HANDLE file;

    *section = NULL;
    scrub_file(dir, name);
    status = open_file(&file, dir, name, FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create image file -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return status;
    offset.QuadPart = 0;
    status = NtWriteFile(file, NULL, NULL, NULL, &iosb, image_bytes, bytes, &offset, NULL);
    ok(status == STATUS_SUCCESS && iosb.Information == bytes, "write image -> %08lx/%lu",
       (unsigned long)status, (unsigned long)iosb.Information);
    NtClose(file);
    if (status != STATUS_SUCCESS)
        return status;

    status =
        open_file(&file, dir, name, FILE_GENERIC_READ | FILE_EXECUTE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "reopen image file -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return status;
    status =
        NtCreateSection(section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file);
    NtClose(file);
    if (!NT_SUCCESS(status))
        *section = NULL;
    return status;
}

/* An image with no relocation directory that cannot take its preferred base
 * still maps; both statuses are successes (as sem_mm/map_image_machine.c). */
static int mapped_ok(NTSTATUS status)
{
    return status == STATUS_SUCCESS || status == (NTSTATUS)STATUS_IMAGE_NOT_AT_BASE;
}

/* Map `section` and check the three things the header region decides:
 * the DOS stub is there, the SECTION TABLE is there (which is the growth),
 * and the section's own page is committed and zero-filled. */
static void check_mapped_image(HANDLE section, const char *what)
{
    const IMAGE_SECTION_HEADER *sec;
    SIZE_T view_size = 0;
    NTSTATUS status;
    ULONG i, nonzero;
    UCHAR *view = NULL;

    status = NtMapViewOfSection(section, NtCurrentProcess(), (PVOID *)&view, 0, 0, NULL, &view_size,
                                ViewShare, 0, PAGE_READONLY);
    ok(mapped_ok(status), "%s: map -> %08lx", what, (unsigned long)status);
    if (!mapped_ok(status))
        return;
    ok(view_size == IMAGE_BYTES, "%s: view size %llx", what, (unsigned long long)view_size);

    ok(view[0] == 'M' && view[1] == 'Z', "%s: no MZ at the view base", what);

    /* THE GROWTH. These bytes live past the image's declared SizeOfHeaders
     * and inside the first page either way, so a mapper that copies only
     * SizeOfHeaders and zeroes the rest of the page leaves them zero. */
    sec = (const IMAGE_SECTION_HEADER *)(view + TABLE_OFF);
    ok(memcmp(sec->Name, ".rsrc", 6) == 0, "%s: section name %.8s", what, (const char *)sec->Name);
    ok(sec->VirtualAddress == PAGE_BYTES, "%s: section RVA %lx", what,
       (unsigned long)sec->VirtualAddress);

    /* ...and no FURTHER: the header page past the table is zero, which is
     * what the oracle's memset leaves and what says the growth stopped where
     * the table ended rather than mapping the whole file page. */
    nonzero = 0;
    for (i = TABLE_OFF + (ULONG)sizeof(*sec); i < PAGE_BYTES; i++)
        if (view[i] != 0)
            nonzero++;
    ok(nonzero == 0, "%s: %lu non-zero bytes past the section table", what, (unsigned long)nonzero);

    /* The section itself declares no raw bytes: a committed, readable,
     * zero-filled page, not an unmapped hole. */
    nonzero = 0;
    for (i = 0; i < PAGE_BYTES; i++)
        if (view[PAGE_BYTES + i] != 0)
            nonzero++;
    ok(nonzero == 0, "%s: %lu non-zero bytes in the uninitialized section", what,
       (unsigned long)nonzero);

    NtUnmapViewOfSection(NtCurrentProcess(), view);
}

/* ---- the second rule: what PointerToRawData == 0 means --------------------
 *
 * The winetest's section header (dlls/kernel32/tests/resource.c:588) is
 *
 *     { ".rsrc\0\0", { 0 }, 0x1000, 0x1000, 0, 0, 0, 0, 0, ... }
 *
 * — VirtualSize ZERO, SizeOfRawData 0x1000, PointerToRawData ZERO. So it
 * declares a page of raw data and then declares that it lives at file offset
 * 0, which is the DOS header. The oracle refuses to believe the extent
 * without the offset: dlls/ntdll/unix/virtual.c map_image_into_view maps no
 * file bytes for such a section at all —
 *
 *     if (!sec[i].PointerToRawData || !file_size) continue;
 *
 * — leaving the reserved, zero-filled view page where it stands. An
 * implementation that keys only on SizeOfRawData copies the image's own
 * HEADERS into the section's page instead, which is the difference between
 * an empty resource directory and a resource directory read out of a DOS
 * stub. VirtualSize still comes from SizeOfRawData when it is zero (that is
 * how the page gets its 0x1000 extent), so the two fields are read for
 * different questions and only one of them is enough on its own.
 */

/* Patch the single section's raw fields in the image build_image just laid
 * down. VirtualSize is left addressable so the winetest's literal zero can
 * be reproduced. */
static void set_section_raw(ULONG virtualSize, ULONG rawSize, ULONG rawOffset)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)image_bytes;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(image_bytes + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec =
        (IMAGE_SECTION_HEADER *)((char *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    sec->Misc.VirtualSize = virtualSize;
    sec->SizeOfRawData = rawSize;
    sec->PointerToRawData = rawOffset;
}

/* The section's page carries `payload` at file offset RAW_AT, or zeroes. */
#define RAW_AT 0x2000u

static void check_section_page(HANDLE section, const char *what, int wantPayload)
{
    SIZE_T view_size = 0;
    NTSTATUS status;
    ULONG i, wrong = 0;
    UCHAR *view = NULL;

    status = NtMapViewOfSection(section, NtCurrentProcess(), (PVOID *)&view, 0, 0, NULL, &view_size,
                                ViewShare, 0, PAGE_READONLY);
    ok(mapped_ok(status), "%s: map -> %08lx", what, (unsigned long)status);
    if (!mapped_ok(status))
        return;

    for (i = 0; i < PAGE_BYTES; i++)
    {
        UCHAR want = wantPayload ? (UCHAR)(i ^ 0x5a) : 0;
        if (view[PAGE_BYTES + i] != want)
            wrong++;
    }
    ok(wrong == 0, "%s: %lu of %u section bytes wrong (first %02x %02x)", what,
       (unsigned long)wrong, PAGE_BYTES, (unsigned)view[PAGE_BYTES],
       (unsigned)view[PAGE_BYTES + 1]);

    NtUnmapViewOfSection(NtCurrentProcess(), view);
}

static void test_section_raw_fields(HANDLE dir)
{
    NTSTATUS status;
    HANDLE section;
    ULONG i;

    /* --- 5. the winetest's literal section: an extent with no offset.
     * Nothing is read out of the file, so the page stays zero even though
     * SizeOfRawData names a whole page of it. */
    build_image(TIGHT_HEADERS, 1, IMAGE_BYTES);
    set_section_raw(0, PAGE_BYTES, 0);
    /* Poison the whole file so "zero" cannot be an accident of the bytes: a
     * mapper that reads file offset 0 lands on the headers, and one that
     * reads RAW_AT lands on the pattern. Everything past the headers is
     * fair game — the section table is rewritten by build_image above. */
    for (i = RAW_AT; i < IMAGE_BYTES; i++)
        image_bytes[i] = (UCHAR)(i - RAW_AT) ^ 0x5a;
    status = make_image_section(dir, W("noraw.dll"), IMAGE_BYTES, &section);
    ok(status == STATUS_SUCCESS, "extent without offset -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        check_section_page(section, "noraw", 0);
        NtClose(section);
    }

    /* --- 6. ...and the same section WITH an offset, so "map nothing" is not
     * a passing answer either. */
    build_image(TIGHT_HEADERS, 1, IMAGE_BYTES);
    set_section_raw(PAGE_BYTES, PAGE_BYTES, RAW_AT);
    for (i = RAW_AT; i < IMAGE_BYTES; i++)
        image_bytes[i] = (UCHAR)(i - RAW_AT) ^ 0x5a;
    status = make_image_section(dir, W("raw.dll"), IMAGE_BYTES, &section);
    ok(status == STATUS_SUCCESS, "extent with offset -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        check_section_page(section, "raw", 1);
        NtClose(section);
    }

    scrub_file(dir, W("noraw.dll"));
    scrub_file(dir, W("raw.dll"));
}

START_TEST(image_section_table)
{
    NTSTATUS status;
    HANDLE dir, section;
    ULONG table_end;

    dir = open_test_dir(W("\\??\\C:\\prstest\\mmist"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;

    /* --- 1. the winetest's own header geometry: the table starts where the
     * headers end. SizeOfHeaders is exactly sizeof(DOS) + sizeof(NT), so
     * every one of the table's bytes is past it. NT loads this. */
    table_end = build_image(TIGHT_HEADERS, 1, IMAGE_BYTES);
    ok(table_end > TIGHT_HEADERS, "the table must overrun SizeOfHeaders (%lu vs %lu)",
       (unsigned long)table_end, (unsigned long)TIGHT_HEADERS);
    ntapi_printf("image_section_table: headers %lu, table %lu..%lu\n", (unsigned long)TIGHT_HEADERS,
                 (unsigned long)TABLE_OFF, (unsigned long)table_end);
    status = make_image_section(dir, W("tight.dll"), IMAGE_BYTES, &section);
    ok(status == STATUS_SUCCESS, "tight headers -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        check_mapped_image(section, "tight");
        NtClose(section);
    }

    /* --- 2. the ordinary shape, as a control: SizeOfHeaders covers the table.
     * Everything case 1 asserts must hold here too, or case 1 is measuring
     * the mapper rather than the header rule. */
    build_image(PAGE_BYTES, 1, IMAGE_BYTES);
    status = make_image_section(dir, W("roomy.dll"), IMAGE_BYTES, &section);
    ok(status == STATUS_SUCCESS, "roomy headers -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        check_mapped_image(section, "roomy");
        NtClose(section);
    }

    /* --- 3. the bound that IS enforced: the table must fit inside the image.
     * 96 sections put the table's end past a one-page SizeOfImage while the
     * FILE still holds every byte of it, so this isolates the image bound
     * from the file one below. */
    table_end = build_image(TIGHT_HEADERS, MANY_SECTIONS, PAGE_BYTES);
    ok(table_end > PAGE_BYTES, "the table must overrun SizeOfImage (%lu)",
       (unsigned long)table_end);
    status = make_image_section(dir, W("overrun.dll"), IMAGE_BYTES, &section);
    ok(status == (NTSTATUS)STATUS_INVALID_FILE_FOR_SECTION, "table past SizeOfImage -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(section);

    /* --- 4. ...and inside the FILE. Same 96-section table, an image big
     * enough to hold it, and a file truncated before it. Nothing may read
     * section headers that were never written. */
    build_image(TIGHT_HEADERS, MANY_SECTIONS, IMAGE_BYTES);
    status = make_image_section(dir, W("short.dll"), PAGE_BYTES / 2, &section);
    ok(status == (NTSTATUS)STATUS_INVALID_FILE_FOR_SECTION, "table past EOF -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(section);

    scrub_file(dir, W("tight.dll"));
    scrub_file(dir, W("roomy.dll"));
    scrub_file(dir, W("overrun.dll"));
    scrub_file(dir, W("short.dll"));

    test_section_raw_fields(dir);

    NtClose(dir);
}
