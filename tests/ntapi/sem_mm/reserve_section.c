/*
 * sem_mm/reserve_section.c — SEC_RESERVE sections: a commit ledger that
 * belongs to the SECTION, not to the view.
 *
 * A SEC_RESERVE section's views start entirely uncommitted, and a
 * NtAllocateVirtualMemory(MEM_COMMIT) through ONE view commits the pages for
 * every view of that section — while each view keeps its own page
 * PROTECTION. Two records, two owners, and an implementation that puts
 * either on the wrong side passes half of this file.
 *
 * The rules are the pinned oracle's, and they are split across its two
 * halves:
 *
 *   - third_party/wine server/mapping.c get_mapping_flags: SEC_RESERVE is a
 *     property of an ANONYMOUS mapping only. Handed a file handle the whole
 *     flag is dropped and the answer is SEC_FILE, so a file-backed
 *     "reserve" section is an ordinary, fully committed data section.
 *   - server/mapping.c create_mapping: `if ((flags & SEC_RESERVE) &&
 *     !(mapping->committed = create_ranges()))` — the ledger hangs off the
 *     MAPPING, and every view grabs a reference to that one object
 *     (`view->committed = mapping->committed ? grab_object(...)`, the
 *     DECL_HANDLER(map_view) arm).
 *   - dlls/ntdll/unix/virtual.c virtual_map_section: `if (!(sec_flags &
 *     SEC_RESERVE)) vprot |= VPROT_COMMITTED;` — the view's pages are
 *     uncommitted at map time, and only for this section kind.
 *   - allocate_virtual_memory's commit arm: `set_protection(view, base,
 *     size, protect)` — which touches THIS view's per-page protection only —
 *     and then `add_mapping_committed_range`, which is shared.
 *   - get_committed_size: a query over a SEC_RESERVE view asks the shared
 *     ledger for the state and reads the LOCAL page protection for the
 *     value, which is why the two views below disagree about Protect while
 *     agreeing about State.
 *
 * kernel32:virtual:869 is what wants this (its test_MapViewOfFile block, and
 * proskrnl stopped dead there: NtCreateSection answered
 * STATUS_NOT_IMPLEMENTED for SEC_RESERVE and the armed panic flag made that
 * fatal). Everything the winetest asserts is here, plus the cases it does
 * not reach — the file-backed drop, a second commit through the other view,
 * and the genuine frame sharing underneath.
 *
 * ONE thing is deliberately NOT asserted: what an ACCESS to an uncommitted
 * page does. NT raises an access violation; the oracle mmaps the whole view
 * accessible and lets the read through (virtual_map_section's "file mappings
 * must always be accessible" mprotect_range), so the two authorities
 * disagree and no assertion here can be green on both. docs/03 "A
 * SEC_RESERVE section's commit ledger" carries it.
 */
#include "../sem_file/util.h"

/* The section + virtual-memory surface (as sem_mm/util.h; redeclared here
 * because this test also needs the file surface from sem_file/util.h — the
 * same arrangement sem_mm/file_coherence.c uses). */
NTSYSAPI NTSTATUS NTAPI NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                        const LARGE_INTEGER *, ULONG, ULONG, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T,
                                           const LARGE_INTEGER *, SIZE_T *, ULONG, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
NTSYSAPI NTSTATUS NTAPI NtQuerySection(HANDLE, ULONG, PVOID, SIZE_T, SIZE_T *);
NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR, SIZE_T *, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG);
NTSYSAPI NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, LPCVOID, ULONG, PVOID, SIZE_T, SIZE_T *);

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

#define SECTION_BYTES 0x100000u /* kernel32:virtual's own MAPPING_SIZE */
#define COMMIT_BYTES  0x10000u

static const void *file_name = W("prsk_secreserve.bin");

/* MemoryBasicInformation for one address, or a zeroed struct on refusal (no
 * assertion here — the callers assert the fields, and a refusal shows up as
 * every one of them being wrong at once). */
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

START_TEST(reserve_section)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE section = NULL, dir, file;
    LARGE_INTEGER max_size;
    mm_section_basic_info sbi;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T view_size, size, retlen;
    char *view1 = NULL, *view2 = NULL;
    void *addr;

    /* --- creation ---------------------------------------------------------
     *
     * SEC_RESERVE and SEC_COMMIT are alternatives, not a pair: the oracle's
     * switch is over `flags & (SEC_IMAGE | SEC_RESERVE | SEC_COMMIT |
     * SEC_FILE)` as a WHOLE, so naming two of them matches no case at all. */
    max_size.QuadPart = SECTION_BYTES;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max_size, PAGE_READWRITE,
                             SEC_RESERVE | SEC_COMMIT, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "SEC_RESERVE|SEC_COMMIT -> %08lx",
       (unsigned long)status);

    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max_size, PAGE_READWRITE,
                             SEC_IMAGE | SEC_RESERVE, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "SEC_IMAGE|SEC_RESERVE -> %08lx", (unsigned long)status);

    /* An anonymous section still must be given a size, reserve or not. */
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READWRITE, SEC_RESERVE,
                             NULL);
    ok(status == STATUS_INVALID_PARAMETER, "SEC_RESERVE without size -> %08lx",
       (unsigned long)status);

    section = NULL;
    max_size.QuadPart = SECTION_BYTES;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max_size, PAGE_READWRITE,
                             SEC_RESERVE, NULL);
    ok(status == STATUS_SUCCESS, "create SEC_RESERVE -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* The flag survives into what the section REPORTS — SEC_RESERVE where an
     * anonymous section otherwise reports SEC_COMMIT. kernel32:virtual:874. */
    memset(&sbi, 0, sizeof(sbi));
    retlen = 0;
    status = NtQuerySection(section, SECTION_BASIC_INFO_CLASS, &sbi, sizeof(sbi), &retlen);
    ok(status == STATUS_SUCCESS, "query section -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(sbi), "query retlen %lu", (unsigned long)retlen);
    ok(sbi.attributes == SEC_RESERVE, "Attributes %08lx", (unsigned long)sbi.attributes);
    ok(sbi.base_address == NULL, "BaseAddress %p", sbi.base_address);
    ok(sbi.size.QuadPart == SECTION_BYTES, "Size %lx", (unsigned long)sbi.size.QuadPart);

    /* --- two views, both entirely uncommitted ---------------------------- */

    view_size = 0;
    addr = NULL;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &addr, 0, 0, NULL, &view_size,
                                ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "map view1 -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    view1 = addr;
    ok(view_size == SECTION_BYTES, "view1 size %llx", (unsigned long long)view_size);

    view_size = 0;
    addr = NULL;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &addr, 0, 0, NULL, &view_size,
                                ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "map view2 -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    view2 = addr;
    ok(view2 != view1, "two views at one address %p", view1);

    /* MEM_RESERVE with Protect 0 — the state a private reservation reports —
     * over a MEM_MAPPED region whose AllocationProtect is the VIEW's. The
     * whole view is one run, because nothing in it is committed. */
    mbi = query(view1);
    ok(mbi.BaseAddress == view1, "view1 base %p != %p", mbi.BaseAddress, view1);
    ok(mbi.AllocationBase == view1, "view1 alloc base %p != %p", mbi.AllocationBase, view1);
    ok(mbi.State == MEM_RESERVE, "view1 state %lx", (unsigned long)mbi.State);
    ok(mbi.Protect == 0, "view1 protect %lx", (unsigned long)mbi.Protect);
    ok(mbi.AllocationProtect == PAGE_READWRITE, "view1 alloc protect %lx",
       (unsigned long)mbi.AllocationProtect);
    ok(mbi.Type == MEM_MAPPED, "view1 type %lx", (unsigned long)mbi.Type);
    ok(mbi.RegionSize == SECTION_BYTES, "view1 region %llx", (unsigned long long)mbi.RegionSize);

    mbi = query(view2);
    ok(mbi.State == MEM_RESERVE, "view2 state %lx", (unsigned long)mbi.State);
    ok(mbi.Protect == 0, "view2 protect %lx", (unsigned long)mbi.Protect);
    ok(mbi.RegionSize == SECTION_BYTES, "view2 region %llx", (unsigned long long)mbi.RegionSize);

    /* --- commit through view1, and watch view2 ---------------------------
     *
     * PAGE_READONLY deliberately: it is not the view's protection, so the
     * two records below cannot be confused for one another. */
    addr = view1;
    size = COMMIT_BYTES;
    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READONLY);
    ok(status == STATUS_SUCCESS, "commit through view1 -> %08lx", (unsigned long)status);
    ok(addr == view1, "commit moved base to %p", addr);
    ok(size == COMMIT_BYTES, "commit size %llx", (unsigned long long)size);

    mbi = query(view1);
    ok(mbi.State == MEM_COMMIT, "view1 committed state %lx", (unsigned long)mbi.State);
    ok(mbi.Protect == PAGE_READONLY, "view1 committed protect %lx", (unsigned long)mbi.Protect);
    ok(mbi.AllocationProtect == PAGE_READWRITE, "view1 alloc protect after commit %lx",
       (unsigned long)mbi.AllocationProtect);
    ok(mbi.RegionSize == COMMIT_BYTES, "view1 committed region %llx",
       (unsigned long long)mbi.RegionSize);

    /* THE assertion this whole case exists for: view2 never asked for
     * anything and its pages are committed, with ITS protection. */
    mbi = query(view2);
    ok(mbi.State == MEM_COMMIT, "view2 state after view1's commit %lx", (unsigned long)mbi.State);
    ok(mbi.Protect == PAGE_READWRITE, "view2 protect after view1's commit %lx",
       (unsigned long)mbi.Protect);
    ok(mbi.RegionSize == COMMIT_BYTES, "view2 region after view1's commit %llx",
       (unsigned long long)mbi.RegionSize);

    /* ...and the run STOPS there: the rest of the section is still reserved,
     * in both views. */
    mbi = query(view1 + COMMIT_BYTES);
    ok(mbi.State == MEM_RESERVE, "view1 tail state %lx", (unsigned long)mbi.State);
    ok(mbi.RegionSize == SECTION_BYTES - COMMIT_BYTES, "view1 tail region %llx",
       (unsigned long long)mbi.RegionSize);
    mbi = query(view2 + COMMIT_BYTES);
    ok(mbi.State == MEM_RESERVE, "view2 tail state %lx", (unsigned long)mbi.State);
    ok(mbi.RegionSize == SECTION_BYTES - COMMIT_BYTES, "view2 tail region %llx",
       (unsigned long long)mbi.RegionSize);

    /* The pages are genuinely SHARED, not merely reported alike: a store
     * through view2 (writable) is visible through view1 (read-only). The
     * last committed page as well as the first, so a one-page implementation
     * cannot pass. */
    view2[0] = 0x5a;
    view2[COMMIT_BYTES - 1] = 0x3c;
    ok(view1[0] == 0x5a, "view1[0] = %02x", (unsigned char)view1[0]);
    ok(view1[COMMIT_BYTES - 1] == 0x3c, "view1[last] = %02x",
       (unsigned char)view1[COMMIT_BYTES - 1]);

    /* --- commit a SECOND range, through the other view -------------------
     *
     * Same rule mirrored: view2 names PAGE_READONLY and view1 — which asked
     * for nothing — reports its own PAGE_READWRITE over the same pages. */
    addr = view2 + COMMIT_BYTES;
    size = COMMIT_BYTES;
    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READONLY);
    ok(status == STATUS_SUCCESS, "commit through view2 -> %08lx", (unsigned long)status);

    mbi = query(view2 + COMMIT_BYTES);
    ok(mbi.State == MEM_COMMIT, "view2 second range state %lx", (unsigned long)mbi.State);
    ok(mbi.Protect == PAGE_READONLY, "view2 second range protect %lx", (unsigned long)mbi.Protect);
    mbi = query(view1 + COMMIT_BYTES);
    ok(mbi.State == MEM_COMMIT, "view1 second range state %lx", (unsigned long)mbi.State);
    ok(mbi.Protect == PAGE_READWRITE, "view1 second range protect %lx", (unsigned long)mbi.Protect);

    /* view1's FIRST range keeps the PAGE_READONLY it was committed with —
     * a later commit elsewhere does not restate it. */
    mbi = query(view1);
    ok(mbi.Protect == PAGE_READONLY, "view1 first range protect after second commit %lx",
       (unsigned long)mbi.Protect);
    ok(mbi.RegionSize == COMMIT_BYTES, "view1 first range region after second commit %llx",
       (unsigned long long)mbi.RegionSize);

    /* Re-committing a range that is ALREADY in the ledger is not an error,
     * it is a re-protect of the caller's own view — and it leaves the other
     * view alone. */
    addr = view1;
    size = COMMIT_BYTES;
    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "re-commit through view1 -> %08lx", (unsigned long)status);
    mbi = query(view1);
    ok(mbi.Protect == PAGE_READWRITE, "view1 protect after re-commit %lx",
       (unsigned long)mbi.Protect);
    mbi = query(view2);
    ok(mbi.Protect == PAGE_READWRITE, "view2 protect after view1's re-commit %lx",
       (unsigned long)mbi.Protect);

    /* --- what a reserve view is NOT ---------------------------------------
     *
     * MEM_RESET is accepted over it (the oracle's reset arm only asks that
     * the range sit in a view), while MEM_DECOMMIT and MEM_RELEASE are
     * refused for every mapped view alike — is_view_valloc's
     * `!(view->protect & (SEC_FILE | SEC_RESERVE | SEC_COMMIT))`. That is
     * the ERROR_INVALID_PARAMETER kernel32:virtual asserts after its
     * commit. */
    addr = view1;
    size = SECTION_BYTES;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_RESET, PAGE_READONLY);
    ok(status == STATUS_SUCCESS, "MEM_RESET over a reserve view -> %08lx", (unsigned long)status);

    addr = view1;
    size = COMMIT_BYTES;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_DECOMMIT);
    ok(status == STATUS_INVALID_PARAMETER, "MEM_DECOMMIT over a reserve view -> %08lx",
       (unsigned long)status);

    addr = view1;
    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(status == STATUS_INVALID_PARAMETER, "MEM_RELEASE over a reserve view -> %08lx",
       (unsigned long)status);

    /* A commit whose range runs off the end of the view is not clipped. */
    addr = view1 + SECTION_BYTES - 0x1000;
    size = 0x2000;
    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_NOT_MAPPED_VIEW, "commit past the view -> %08lx", (unsigned long)status);

    /* --- a fresh view sees the ledger it never wrote ---------------------- */
    view_size = 0;
    addr = NULL;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &addr, 0, 0, NULL, &view_size,
                                ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "map view3 -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        char *view3 = addr;
        mbi = query(view3);
        ok(mbi.State == MEM_COMMIT, "view3 state %lx", (unsigned long)mbi.State);
        ok(mbi.Protect == PAGE_READWRITE, "view3 protect %lx", (unsigned long)mbi.Protect);
        ok(mbi.RegionSize == 2 * COMMIT_BYTES, "view3 region %llx",
           (unsigned long long)mbi.RegionSize);
        ok(view3[0] == 0x5a, "view3[0] = %02x", (unsigned char)view3[0]);
        mbi = query(view3 + 2 * COMMIT_BYTES);
        ok(mbi.State == MEM_RESERVE, "view3 tail state %lx", (unsigned long)mbi.State);
        status = NtUnmapViewOfSection(NtCurrentProcess(), view3);
        ok(status == STATUS_SUCCESS, "unmap view3 -> %08lx", (unsigned long)status);
    }

    status = NtUnmapViewOfSection(NtCurrentProcess(), view2);
    ok(status == STATUS_SUCCESS, "unmap view2 -> %08lx", (unsigned long)status);
    status = NtUnmapViewOfSection(NtCurrentProcess(), view1);
    ok(status == STATUS_SUCCESS, "unmap view1 -> %08lx", (unsigned long)status);
    NtClose(section);

    /* --- SEC_RESERVE over a FILE is not a reserve section at all ----------
     *
     * get_mapping_flags drops the flag whole (`if (handle) return SEC_FILE |
     * (flags & (SEC_NOCACHE | SEC_WRITECOMBINE));`), so the section reports
     * SEC_FILE and its views are committed from the moment they are mapped.
     * An implementation that routed the flag rather than the (handle, flag)
     * PAIR builds a reserve section over a file and fails only here. */
    dir = open_test_dir(W("\\??\\C:\\prstest\\secreserve"));
    if (!dir)
        return;
    scrub_file(dir, file_name);

    status = open_file(&file, dir, file_name, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OVERWRITE_IF, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create backing file -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        char buf[0x1000];
        HANDLE fileSection = NULL;

        memset(buf, 'r', sizeof(buf));
        status = NtWriteFile(file, NULL, NULL, NULL, &iosb, buf, sizeof(buf), NULL, NULL);
        ok(status == STATUS_SUCCESS, "write backing file -> %08lx", (unsigned long)status);

        max_size.QuadPart = 0x1000;
        status = NtCreateSection(&fileSection, SECTION_ALL_ACCESS, NULL, &max_size, PAGE_READWRITE,
                                 SEC_RESERVE, file);
        ok(status == STATUS_SUCCESS, "create SEC_RESERVE over a file -> %08lx",
           (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            memset(&sbi, 0, sizeof(sbi));
            status = NtQuerySection(fileSection, SECTION_BASIC_INFO_CLASS, &sbi, sizeof(sbi), NULL);
            ok(status == STATUS_SUCCESS, "query file section -> %08lx", (unsigned long)status);
            ok(sbi.attributes == SEC_FILE, "file section Attributes %08lx",
               (unsigned long)sbi.attributes);

            view_size = 0;
            addr = NULL;
            status = NtMapViewOfSection(fileSection, NtCurrentProcess(), &addr, 0, 0, NULL,
                                        &view_size, ViewShare, 0, PAGE_READWRITE);
            ok(status == STATUS_SUCCESS, "map file section -> %08lx", (unsigned long)status);
            if (NT_SUCCESS(status))
            {
                mbi = query(addr);
                ok(mbi.State == MEM_COMMIT, "file section view state %lx",
                   (unsigned long)mbi.State);
                ok(mbi.Protect == PAGE_READWRITE, "file section view protect %lx",
                   (unsigned long)mbi.Protect);
                ok(((char *)addr)[0] == 'r', "file section view[0] = %02x",
                   (unsigned char)((char *)addr)[0]);
                /* ...and it is a file view, so a commit over it is refused
                 * the way every file-backed view's is. */
                size = 0x1000;
                status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT,
                                                 PAGE_READWRITE);
                ok(status == STATUS_ALREADY_COMMITTED, "commit over a file view -> %08lx",
                   (unsigned long)status);
                NtUnmapViewOfSection(NtCurrentProcess(), addr);
            }
            NtClose(fileSection);
        }
        NtClose(file);
    }
    scrub_file(dir, file_name);
    NtClose(dir);
}
