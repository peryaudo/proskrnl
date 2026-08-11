/*
 * sem_mm/section_sec_flags.c — the SEC_* MODIFIER flags on a section:
 * which combinations exist, what a section KEEPS of the word it was given,
 * and which of the kept bits a VIEW then reports.
 *
 * Three separate rules live in one twenty-line oracle function
 * (third_party/wine server/mapping.c get_mapping_flags), and an
 * implementation can satisfy any two of them while failing the third:
 *
 *     switch (flags & (SEC_IMAGE | SEC_RESERVE | SEC_COMMIT | SEC_FILE))
 *     {
 *     case SEC_IMAGE:
 *         if (flags & (SEC_WRITECOMBINE | SEC_LARGE_PAGES)) break;
 *         if (handle) return SEC_FILE | SEC_IMAGE;
 *         set_error( STATUS_INVALID_FILE_FOR_SECTION );
 *         return 0;
 *     case SEC_COMMIT:
 *         if (!handle) return flags;
 *         // fall through
 *     case SEC_RESERVE:
 *         if (flags & SEC_LARGE_PAGES) break;
 *         if (handle) return SEC_FILE | (flags & (SEC_NOCACHE | SEC_WRITECOMBINE));
 *         return flags;
 *     }
 *     set_error( STATUS_INVALID_PARAMETER );
 *
 *   1. WHICH COMBINATIONS REFUSE. SEC_LARGE_PAGES and SEC_WRITECOMBINE are
 *      not uniformly legal or uniformly illegal: SEC_LARGE_PAGES refuses on
 *      an image, on any file-backed section and on an anonymous SEC_RESERVE
 *      — and SUCCEEDS on an anonymous SEC_COMMIT, which is the one arm that
 *      returns before the SEC_LARGE_PAGES guard. SEC_WRITECOMBINE refuses
 *      only on an image. No winetest asks the anonymous-commit case; an
 *      implementation reading "SEC_LARGE_PAGES is unsupported" as one rule
 *      passes kernel32:virtual's whole matrix and diverges there.
 *
 *   2. WHICH BITS SURVIVE, and it differs by arm. A file-backed section
 *      keeps SEC_NOCACHE and SEC_WRITECOMBINE and NOTHING else (its
 *      SEC_RESERVE/SEC_COMMIT is replaced by SEC_FILE); an image keeps
 *      neither, so SEC_IMAGE|SEC_NOCACHE reports SEC_FILE|SEC_IMAGE; an
 *      anonymous section keeps the caller's word WHOLE.
 *
 *   3. WHERE THE CHECK SITS. get_mapping_flags runs above create_mapping's
 *      `get_file_obj`, so a refused combination is reported for a file
 *      handle that names nothing — the ordering an implementation that
 *      resolves the backing first inverts.
 *
 * ...and then one rule from the other half of the oracle: a view's protect
 * word is `vprot |= sec_flags` (dlls/ntdll/unix/virtual.c
 * virtual_map_section) over the section's RESOLVED flags, and get_win32_prot
 * reads exactly one modifier back out of it —
 * `if (map_prot & SEC_NOCACHE) ret |= PAGE_NOCACHE;`. So SEC_NOCACHE reaches
 * MEMORY_BASIC_INFORMATION.Protect for every page of every view, SEC_WRITECOMBINE
 * reaches nothing, and an image view reports no modifier at all because the
 * bit never survived rule 2.
 *
 * kernel32:virtual convicts 25 of these (its sec_flag_tests matrix at
 * :1616/:1617/:1638, plus the SEC_NOCACHE section at :1014). This file pins
 * the rules instead of those points, and adds the four cases the winetest
 * cannot reach: the anonymous SEC_COMMIT|SEC_LARGE_PAGES success, the
 * ordering against a junk file handle, a view of a SEC_WRITECOMBINE section,
 * and a view of an image section created with SEC_NOCACHE.
 */
#include "imagefile.h"

NTSYSAPI NTSTATUS NTAPI NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                        const LARGE_INTEGER *, ULONG, ULONG, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T,
                                           const LARGE_INTEGER *, SIZE_T *, ULONG, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
NTSYSAPI NTSTATUS NTAPI NtQuerySection(HANDLE, ULONG, PVOID, SIZE_T, SIZE_T *);
NTSYSAPI NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, LPCVOID, ULONG, PVOID, SIZE_T, SIZE_T *);
NTSYSAPI NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG, ULONG *);

/* Re-declared here rather than taken from sem_mm/util.h, which this file
 * cannot include beside sem_file/util.h (the arrangement sem_mm/
 * reserve_section.c and section_file_access.c already use). Every value is
 * wine/include/winternl.h's: SECTION_INHERIT's ViewShare, the
 * NtCurrentProcess pseudo-handle mingw's winternl.h omits, and the two info
 * classes (MEMORY_INFORMATION_CLASS MemoryBasicInformation,
 * SECTION_INFORMATION_CLASS SectionBasicInformation), both first. */
#ifndef ViewShare
#define ViewShare 1
#endif
#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif

#define MEMORY_BASIC_INFO_CLASS  0
#define SECTION_BASIC_INFO_CLASS 0

/* SECTION_BASIC_INFORMATION, byte-for-byte, in this suite's spelling. */
typedef struct
{
    PVOID base_address;
    ULONG attributes;
    LARGE_INTEGER size;
} mm_section_basic_info;

static const void *data_name = W("secflags.bin");
static const void *image_name = W("secflags.dll");

#define SECTION_BYTES 0x100000u
#define PROTECT_BYTES 0x10000u

/* Which backing a matrix row uses. */
#define BACK_NONE  0
#define BACK_DATA  1
#define BACK_IMAGE 2

struct sec_case
{
    int backing;
    ULONG flags;
    NTSTATUS status;
    ULONG attributes; /* expected NtQuerySection Attributes on success */
};

/* The matrix. Every row is get_mapping_flags read once; the comments name
 * only the rows whose answer does not follow from the row above it. */
static const struct sec_case sec_cases[] = {
    /* --- anonymous: the caller's word survives whole --------------------- */
    {BACK_NONE, SEC_RESERVE, STATUS_SUCCESS, SEC_RESERVE},
    {BACK_NONE, SEC_RESERVE | SEC_NOCACHE, STATUS_SUCCESS, SEC_RESERVE | SEC_NOCACHE},
    {BACK_NONE, SEC_RESERVE | SEC_WRITECOMBINE, STATUS_SUCCESS, SEC_RESERVE | SEC_WRITECOMBINE},
    {BACK_NONE, SEC_RESERVE | SEC_LARGE_PAGES, STATUS_INVALID_PARAMETER, 0},
    {BACK_NONE, SEC_COMMIT, STATUS_SUCCESS, SEC_COMMIT},
    {BACK_NONE, SEC_COMMIT | SEC_NOCACHE, STATUS_SUCCESS, SEC_COMMIT | SEC_NOCACHE},
    {BACK_NONE, SEC_COMMIT | SEC_WRITECOMBINE, STATUS_SUCCESS, SEC_COMMIT | SEC_WRITECOMBINE},
    /* The asymmetry rule 1 is about: this is the ONLY arm that returns
     * before the SEC_LARGE_PAGES guard, so it succeeds and keeps the bit. */
    {BACK_NONE, SEC_COMMIT | SEC_LARGE_PAGES, STATUS_SUCCESS, SEC_COMMIT | SEC_LARGE_PAGES},
    {BACK_NONE, SEC_COMMIT | SEC_NOCACHE | SEC_WRITECOMBINE | SEC_LARGE_PAGES, STATUS_SUCCESS,
     SEC_COMMIT | SEC_NOCACHE | SEC_WRITECOMBINE | SEC_LARGE_PAGES},
    /* `return flags` is literal: a bit the switch never looked at rides
     * through into what the section reports. Nothing in the baked stack
     * sends one — kernelbase masks the word down to the SEC_* set
     * (dlls/kernelbase/sync.c CreateFileMappingW) — so this row exists to
     * separate a transcription from a re-derivation that keeps "the flags
     * it knows". 0x10 has one requirement and it is external: it must name
     * no SEC_* flag. wine/include/winnt.h's lowest is SEC_FILE 0x00800000
     * and abi/ntmmapi.h agrees, so the whole low half-word is free. */
    {BACK_NONE, SEC_COMMIT | 0x10u, STATUS_SUCCESS, SEC_COMMIT | 0x10u},
    /* The switch is over the FOUR bits as a whole, so naming two of them
     * matches no case at all. */
    {BACK_NONE, SEC_RESERVE | SEC_COMMIT, STATUS_INVALID_PARAMETER, 0},
    {BACK_NONE, SEC_FILE, STATUS_INVALID_PARAMETER, 0},
    {BACK_NONE, SEC_FILE | SEC_COMMIT, STATUS_INVALID_PARAMETER, 0},
    {BACK_NONE, SEC_FILE | SEC_RESERVE, STATUS_INVALID_PARAMETER, 0},
    /* A modifier with no section KIND beside it names no arm either. */
    {BACK_NONE, SEC_NOCACHE, STATUS_INVALID_PARAMETER, 0},
    {BACK_NONE, SEC_WRITECOMBINE, STATUS_INVALID_PARAMETER, 0},
    {BACK_NONE, SEC_LARGE_PAGES, STATUS_INVALID_PARAMETER, 0},
    /* ...including no flags at all. kernel32's matrix cannot see this:
     * CreateFileMappingW substitutes SEC_COMMIT for an empty word before the
     * syscall ever runs. */
    {BACK_NONE, 0, STATUS_INVALID_PARAMETER, 0},
    /* SEC_IMAGE with no file: the flags guard is ABOVE the handle test, so
     * two of these three report the combination and not the missing file. */
    {BACK_NONE, SEC_IMAGE, STATUS_INVALID_FILE_FOR_SECTION, 0},
    {BACK_NONE, SEC_IMAGE | SEC_NOCACHE, STATUS_INVALID_FILE_FOR_SECTION, 0},
    {BACK_NONE, SEC_IMAGE | SEC_WRITECOMBINE, STATUS_INVALID_PARAMETER, 0},
    {BACK_NONE, SEC_IMAGE | SEC_LARGE_PAGES, STATUS_INVALID_PARAMETER, 0},
    {BACK_NONE, SEC_IMAGE | SEC_RESERVE, STATUS_INVALID_PARAMETER, 0},
    {BACK_NONE, SEC_IMAGE | SEC_COMMIT, STATUS_INVALID_PARAMETER, 0},

    /* --- a data file: SEC_FILE replaces the kind, two modifiers survive --- */
    {BACK_DATA, SEC_RESERVE, STATUS_SUCCESS, SEC_FILE},
    {BACK_DATA, SEC_RESERVE | SEC_NOCACHE, STATUS_SUCCESS, SEC_FILE | SEC_NOCACHE},
    {BACK_DATA, SEC_RESERVE | SEC_WRITECOMBINE, STATUS_SUCCESS, SEC_FILE | SEC_WRITECOMBINE},
    {BACK_DATA, SEC_RESERVE | SEC_LARGE_PAGES, STATUS_INVALID_PARAMETER, 0},
    {BACK_DATA, SEC_COMMIT, STATUS_SUCCESS, SEC_FILE},
    {BACK_DATA, SEC_COMMIT | SEC_NOCACHE, STATUS_SUCCESS, SEC_FILE | SEC_NOCACHE},
    {BACK_DATA, SEC_COMMIT | SEC_WRITECOMBINE, STATUS_SUCCESS, SEC_FILE | SEC_WRITECOMBINE},
    /* ...and here SEC_COMMIT does NOT return early — a file handle sends it
     * through the SEC_RESERVE arm's guard, so the same word that succeeds
     * anonymously refuses. */
    {BACK_DATA, SEC_COMMIT | SEC_LARGE_PAGES, STATUS_INVALID_PARAMETER, 0},
    {BACK_DATA, SEC_COMMIT | SEC_NOCACHE | SEC_WRITECOMBINE, STATUS_SUCCESS,
     SEC_FILE | SEC_NOCACHE | SEC_WRITECOMBINE},
    /* An unknown bit is dropped here where the anonymous arm keeps it: this
     * arm builds its answer from a MASK rather than returning the word. */
    {BACK_DATA, SEC_COMMIT | 0x10u, STATUS_SUCCESS, SEC_FILE},
    {BACK_DATA, SEC_RESERVE | SEC_COMMIT, STATUS_INVALID_PARAMETER, 0},
    {BACK_DATA, SEC_FILE, STATUS_INVALID_PARAMETER, 0},
    {BACK_DATA, 0, STATUS_INVALID_PARAMETER, 0},

    /* --- a PE image: no modifier survives, and two of them refuse -------- */
    {BACK_IMAGE, SEC_IMAGE, STATUS_SUCCESS, SEC_FILE | SEC_IMAGE},
    /* SEC_NOCACHE is legal on an image and is then DROPPED — the one bit
     * that is accepted-and-not-kept anywhere in this function. */
    {BACK_IMAGE, SEC_IMAGE | SEC_NOCACHE, STATUS_SUCCESS, SEC_FILE | SEC_IMAGE},
    {BACK_IMAGE, SEC_IMAGE | SEC_WRITECOMBINE, STATUS_INVALID_PARAMETER, 0},
    {BACK_IMAGE, SEC_IMAGE | SEC_LARGE_PAGES, STATUS_INVALID_PARAMETER, 0},
    {BACK_IMAGE, SEC_IMAGE | SEC_FILE, STATUS_INVALID_PARAMETER, 0},
    {BACK_IMAGE, SEC_IMAGE | SEC_RESERVE, STATUS_INVALID_PARAMETER, 0},
    {BACK_IMAGE, SEC_IMAGE | SEC_COMMIT, STATUS_INVALID_PARAMETER, 0},
    /* The same file mapped as DATA takes the file arm and keeps its
     * modifiers: the drop belongs to the SEC_IMAGE arm, not to the file. */
    {BACK_IMAGE, SEC_COMMIT | SEC_NOCACHE, STATUS_SUCCESS, SEC_FILE | SEC_NOCACHE},
};

/* MemoryBasicInformation for one address; a refusal shows up as every field
 * being wrong at once, which the callers assert. */
static MEMORY_BASIC_INFORMATION query(const void *address)
{
    MEMORY_BASIC_INFORMATION mbi;
    NTSTATUS status;

    memset(&mbi, 0, sizeof(mbi));
    status = NtQueryVirtualMemory(NtCurrentProcess(), address, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), NULL);
    ok(status == STATUS_SUCCESS, "query %p -> %08lx", address, (unsigned long)status);
    return mbi;
}

/* Create an anonymous section with `flags` and map the whole of it
 * PAGE_READWRITE. Returns the view, with the section handle in *sectionOut. */
static void *map_anonymous(ULONG flags, HANDLE *sectionOut)
{
    LARGE_INTEGER max_size;
    NTSTATUS status;
    HANDLE section = NULL;
    SIZE_T view_size = 0;
    void *addr = NULL;

    *sectionOut = NULL;
    max_size.QuadPart = SECTION_BYTES;
    status =
        NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max_size, PAGE_READWRITE, flags, NULL);
    ok(status == STATUS_SUCCESS, "create %08lx -> %08lx", (unsigned long)flags,
       (unsigned long)status);
    if (!NT_SUCCESS(status))
        return NULL;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &addr, 0, 0, NULL, &view_size,
                                ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "map %08lx -> %08lx", (unsigned long)flags, (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(section);
        return NULL;
    }
    *sectionOut = section;
    return addr;
}

START_TEST(section_sec_flags)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, data = NULL, image = NULL, section;
    LARGE_INTEGER max_size;
    mm_section_basic_info sbi;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T size;
    ULONG old_protect;
    void *view, *addr;
    unsigned int i;

    dir = open_test_dir(W("\\??\\C:\\prstest\\secflags"));
    if (!dir)
        return;

    /* A plain data file with room for the matrix's 0x1000 sections... */
    scrub_file(dir, data_name);
    status = open_file(&data, dir, data_name, FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create data file -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        static char zeros[0x2000];
        status = NtWriteFile(data, NULL, NULL, NULL, &iosb, zeros, sizeof(zeros), NULL, NULL);
        ok(status == STATUS_SUCCESS, "fill data file -> %08lx", (unsigned long)status);
    }

    /* ...and a real PE of the test's own (sem_mm/imagefile.h). */
    if (copy_system_image(dir, image_name))
    {
        status = open_file(&image, dir, image_name, FILE_GENERIC_READ | FILE_EXECUTE,
                           FILE_SHARE_READ, FILE_OPEN, 0, &iosb);
        ok(status == STATUS_SUCCESS, "open image copy -> %08lx", (unsigned long)status);
    }

    /* --- 1 + 2: the matrix --------------------------------------------
     *
     * The floor first: two thirds of the rows below are skipped when a
     * backing is missing, and a skipped row scores as a pass. */
    ok(data != NULL, "no data backing: the matrix's file rows did not run");
    ok(image != NULL, "no image backing: the matrix's image rows did not run");

    for (i = 0; i < sizeof(sec_cases) / sizeof(sec_cases[0]); i++)
    {
        const struct sec_case *c = &sec_cases[i];
        HANDLE backing = NULL;

        if (c->backing == BACK_DATA)
            backing = data;
        else if (c->backing == BACK_IMAGE)
            backing = image;
        if (c->backing != BACK_NONE && backing == NULL)
            continue; /* the backing itself failed above and said so */

        section = NULL;
        max_size.QuadPart = 0x1000;
        /* An image section takes its size from the file, and naming one is
         * a separate refusal (STATUS_INVALID_PARAMETER_4 on some arms) that
         * this matrix is not about. */
        status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL,
                                 (c->flags & SEC_IMAGE) ? NULL : &max_size, PAGE_READONLY, c->flags,
                                 backing);
        ok(status == c->status, "%u: create %08lx -> %08lx, want %08lx", i, (unsigned long)c->flags,
           (unsigned long)status, (unsigned long)c->status);
        if (!NT_SUCCESS(status))
        {
            ok(section == NULL, "%u: refused create left handle %p", i, section);
            continue;
        }
        memset(&sbi, 0, sizeof(sbi));
        status = NtQuerySection(section, SECTION_BASIC_INFO_CLASS, &sbi, sizeof(sbi), NULL);
        ok(status == STATUS_SUCCESS, "%u: query -> %08lx", i, (unsigned long)status);
        ok(sbi.attributes == c->attributes, "%u: flags %08lx -> Attributes %08lx, want %08lx", i,
           (unsigned long)c->flags, (unsigned long)sbi.attributes, (unsigned long)c->attributes);
        NtClose(section);
    }

    /* --- 3: the combination is refused ABOVE the file handle ------------
     *
     * get_mapping_flags runs before create_mapping resolves the handle, so a
     * junk handle beside a refused combination reports the COMBINATION. The
     * control below shows the same handle is genuinely junk. */
    section = NULL;
    max_size.QuadPart = 0x1000;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max_size, PAGE_READONLY,
                             SEC_COMMIT | SEC_LARGE_PAGES, (HANDLE)(ULONG_PTR)0xdeadbeef);
    ok(status == STATUS_INVALID_PARAMETER, "bad flags + junk handle -> %08lx",
       (unsigned long)status);
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max_size, PAGE_READONLY,
                             SEC_IMAGE | SEC_WRITECOMBINE, (HANDLE)(ULONG_PTR)0xdeadbeef);
    ok(status == STATUS_INVALID_PARAMETER, "bad image flags + junk handle -> %08lx",
       (unsigned long)status);
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max_size, PAGE_READONLY,
                             SEC_COMMIT, (HANDLE)(ULONG_PTR)0xdeadbeef);
    ok(status == STATUS_INVALID_HANDLE, "good flags + junk handle -> %08lx", (unsigned long)status);

    /* --- 4: what a VIEW reports ----------------------------------------
     *
     * SEC_NOCACHE is the only modifier get_win32_prot reads, and it reads it
     * out of the VIEW's word for every page — so it decorates the current
     * protection and the allocation protection alike, and survives a
     * re-protect of part of the view. kernel32:virtual:1014's block. */
    view = map_anonymous(SEC_COMMIT | SEC_NOCACHE, &section);
    if (view != NULL)
    {
        mbi = query(view);
        ok(mbi.BaseAddress == view, "nocache base %p != %p", mbi.BaseAddress, view);
        ok(mbi.State == MEM_COMMIT, "nocache state %lx", (unsigned long)mbi.State);
        ok(mbi.Type == MEM_MAPPED, "nocache type %lx", (unsigned long)mbi.Type);
        ok(mbi.RegionSize == SECTION_BYTES, "nocache region %llx",
           (unsigned long long)mbi.RegionSize);
        ok(mbi.Protect == (PAGE_READWRITE | PAGE_NOCACHE), "nocache protect %lx",
           (unsigned long)mbi.Protect);
        ok(mbi.AllocationProtect == (PAGE_READWRITE | PAGE_NOCACHE), "nocache alloc protect %lx",
           (unsigned long)mbi.AllocationProtect);

        addr = view;
        size = PROTECT_BYTES;
        old_protect = 0;
        status =
            NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY, &old_protect);
        ok(status == STATUS_SUCCESS, "nocache re-protect -> %08lx", (unsigned long)status);
        /* The reported OLD protection carries the modifier too — the oracle
         * builds it with the same get_win32_prot( vprot, view->protect ). */
        ok(old_protect == (PAGE_READWRITE | PAGE_NOCACHE), "nocache old protect %lx",
           (unsigned long)old_protect);

        mbi = query(view);
        ok(mbi.RegionSize == PROTECT_BYTES, "nocache split region %llx",
           (unsigned long long)mbi.RegionSize);
        ok(mbi.Protect == (PAGE_READONLY | PAGE_NOCACHE), "nocache split protect %lx",
           (unsigned long)mbi.Protect);
        /* ...and the allocation protection is still the view's own, still
         * decorated: the modifier belongs to the VIEW, so the split cannot
         * lose it on either piece. */
        ok(mbi.AllocationProtect == (PAGE_READWRITE | PAGE_NOCACHE),
           "nocache split alloc protect %lx", (unsigned long)mbi.AllocationProtect);
        mbi = query((const char *)view + PROTECT_BYTES);
        ok(mbi.Protect == (PAGE_READWRITE | PAGE_NOCACHE), "nocache tail protect %lx",
           (unsigned long)mbi.Protect);

        NtUnmapViewOfSection(NtCurrentProcess(), view);
        NtClose(section);
    }

    /* SEC_WRITECOMBINE is KEPT by the section and read by nothing: a view of
     * one reports a bare protection. An implementation that decorates the
     * reported protection with every modifier it kept fails only here. */
    view = map_anonymous(SEC_COMMIT | SEC_WRITECOMBINE, &section);
    if (view != NULL)
    {
        mbi = query(view);
        ok(mbi.Protect == PAGE_READWRITE, "writecombine protect %lx", (unsigned long)mbi.Protect);
        ok(mbi.AllocationProtect == PAGE_READWRITE, "writecombine alloc protect %lx",
           (unsigned long)mbi.AllocationProtect);
        NtUnmapViewOfSection(NtCurrentProcess(), view);
        NtClose(section);
    }

    /* A file-backed section keeps SEC_NOCACHE (rule 2), so its views carry
     * the modifier exactly as an anonymous one's do. */
    if (data != NULL)
    {
        section = NULL;
        max_size.QuadPart = 0x1000;
        status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max_size, PAGE_READWRITE,
                                 SEC_COMMIT | SEC_NOCACHE, data);
        ok(status == STATUS_SUCCESS, "create file nocache -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            SIZE_T view_size = 0;
            addr = NULL;
            status = NtMapViewOfSection(section, NtCurrentProcess(), &addr, 0, 0, NULL, &view_size,
                                        ViewShare, 0, PAGE_READWRITE);
            ok(status == STATUS_SUCCESS, "map file nocache -> %08lx", (unsigned long)status);
            if (NT_SUCCESS(status))
            {
                mbi = query(addr);
                ok(mbi.Protect == (PAGE_READWRITE | PAGE_NOCACHE), "file nocache protect %lx",
                   (unsigned long)mbi.Protect);
                NtUnmapViewOfSection(NtCurrentProcess(), addr);
            }
            NtClose(section);
        }
    }

    /* ...and an IMAGE section created with SEC_NOCACHE has none to inherit,
     * because rule 2 dropped the bit at create time. This is the case that
     * separates "read the section's resolved attributes" from "read the
     * flags the caller passed": both answer every other case here. */
    if (image != NULL)
    {
        section = NULL;
        status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY,
                                 SEC_IMAGE | SEC_NOCACHE, image);
        ok(status == STATUS_SUCCESS, "create image nocache -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            SIZE_T view_size = 0;
            addr = NULL;
            status = NtMapViewOfSection(section, NtCurrentProcess(), &addr, 0, 0, NULL, &view_size,
                                        ViewShare, 0, PAGE_READONLY);
            /* NT_SUCCESS, not STATUS_SUCCESS: a relocated image view answers
             * STATUS_IMAGE_NOT_AT_BASE, which is a success code. */
            ok(NT_SUCCESS(status), "map image nocache -> %08lx", (unsigned long)status);
            if (NT_SUCCESS(status))
            {
                mbi = query(addr);
                ok((mbi.Protect & PAGE_NOCACHE) == 0, "image view protect %lx",
                   (unsigned long)mbi.Protect);
                ok((mbi.AllocationProtect & PAGE_NOCACHE) == 0, "image view alloc protect %lx",
                   (unsigned long)mbi.AllocationProtect);
                ok(mbi.Type == MEM_IMAGE, "image view type %lx", (unsigned long)mbi.Type);
                NtUnmapViewOfSection(NtCurrentProcess(), addr);
            }
            NtClose(section);
        }
    }

    if (image != NULL)
        NtClose(image);
    if (data != NULL)
        NtClose(data);
    scrub_file(dir, image_name);
    scrub_file(dir, data_name);
    NtClose(dir);
}
