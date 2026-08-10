/*
 * sem_mm/protect_modifier_bits.c — the page-protection bits NT IGNORES on the
 * private-memory surface, and the surface where the same bits are REFUSED.
 *
 * kernel32:virtual:236 is `WriteProcessMemory failed GetLastError()=87` over a
 * PAGE_EXECUTE_READ range. Nothing in that assertion is about a modifier bit,
 * and the cause is entirely one: kernelbase's WriteProcessMemory makes a
 * non-writable range writable for the duration of the copy, and it asks for
 *
 *     DWORD prot = PAGE_TARGETS_NO_UPDATE | PAGE_ENCLAVE_NO_CHANGE;
 *     ...
 *     prot |= (info.Type == MEM_PRIVATE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_WRITECOPY;
 *     status = NtProtectVirtualMemory( process, &base_addr, &region_size, prot, &old_prot );
 *
 * (third_party/wine dlls/kernelbase/memory.c, WriteProcessMemory). proskrnl
 * refused the whole word with STATUS_INVALID_PAGE_PROTECTION, which
 * RtlNtStatusToDosError reports as ERROR_INVALID_PARAMETER (87), so every
 * WriteProcessMemory into a read-only or executable range failed — an entire
 * Win32 API, convicted by one MASK and no wrong value anywhere (docs/21 W11's
 * "every defect in this item was an ORDER or a MASK").
 *
 * THE RULE is the pinned oracle's, and it is one expression: the private
 * surface switches on `protect & 0xff` and then looks at exactly one bit above
 * that byte (third_party/wine dlls/ntdll/unix/virtual.c, get_vprot_flags):
 *
 *     switch (protect & 0xff) { ... default: return STATUS_INVALID_PAGE_PROTECTION; }
 *     if (protect & PAGE_GUARD) *vprot |= VPROT_GUARD;
 *
 * so PAGE_WRITECOMBINE, PAGE_TARGETS_NO_UPDATE and PAGE_ENCLAVE_NO_CHANGE are
 * accepted and DISCARDED. Discarded, not stored: what a later query reports is
 * rebuilt from the kept flags alone (get_win32_prot:
 * `VIRTUAL_Win32Flags[vprot & 0x0f]`, plus PAGE_GUARD). An implementation that
 * widens its validation but stores the caller's word unchanged passes every
 * status assertion here and hands MEMORY_BASIC_INFORMATION.Protect a value no
 * NT ever reports.
 *
 * PAGE_NOCACHE IS NOT ONE OF THEM, and the first draft of this pin said it was
 * — the oracle refuted it (Art. 6). It is kept, but as a property of the
 * RESERVATION rather than of the page:
 *
 *     if (protect & PAGE_NOCACHE) vprot |= SEC_NOCACHE;    (allocate_virtual_memory)
 *     if (map_prot & SEC_NOCACHE) ret |= PAGE_NOCACHE;     (get_win32_prot)
 *
 * — and that assignment sits inside the `(type & MEM_RESERVE) || !base` branch,
 * where `vprot` becomes the VIEW's own protect word. So it is sticky and
 * write-once in the two directions a per-page implementation cannot reproduce:
 * a later NtProtectVirtualMemory can neither REMOVE it (set_protection never
 * touches view->protect) nor ADD it (same reason), and neither can a
 * MEM_COMMIT into an existing reservation, which takes the other branch. Both
 * directions are measured below.
 *
 * AND THE RULE STOPS AT THE SECTION SURFACE, which is the half no status table
 * shows and the reason this pin exists rather than a one-line fix:
 *
 *   - NtCreateSection has the same `switch (protect & 0xff)`
 *     (dlls/ntdll/unix/sync.c), so a section may be created with the modifier
 *     bits set;
 *   - NtMapViewOfSection has NO mask at all — `switch (protect)` over the
 *     eight bare protections, default STATUS_INVALID_PAGE_PROTECTION
 *     (dlls/ntdll/unix/virtual.c, virtual_map_section) — so the SAME word that
 *     allocates private memory refuses a view. Even PAGE_GUARD, which the
 *     private path keeps, is refused there.
 *
 * So "mask the modifier bits off wherever a protection is captured" is wrong
 * in exactly the map case, and an implementation that reached for that tidy
 * rule would pass kernel32:virtual and diverge on a call no assertion in it
 * makes.
 *
 * Oracle-first (G5): every case here is measured on the pinned Wine.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemoryEx(HANDLE, PVOID *, SIZE_T *, ULONG, ULONG, PVOID,
                                                  ULONG);

/* PAGE_ENCLAVE_NO_CHANGE is absent from mingw-w64's winnt.h; the value is the
 * pinned tree's (third_party/wine include/winnt.h:821), which is also what
 * kernelbase compiles against when it builds the word above. PAGE_WRITECOMBINE
 * (0x400) and PAGE_TARGETS_NO_UPDATE (0x40000000) come from the system header.
 */
#ifndef PAGE_ENCLAVE_NO_CHANGE
#define PAGE_ENCLAVE_NO_CHANGE 0x20000000
#endif

/* The exact word kernelbase's WriteProcessMemory builds. */
#define WPM_MODIFIERS (PAGE_TARGETS_NO_UPDATE | PAGE_ENCLAVE_NO_CHANGE)

/* Reserve+commit four pages with `protect`, report what a query then says the
 * pages and the allocation are protected with, and release. */
static void check_alloc(ULONG protect, NTSTATUS wantStatus, ULONG wantReported, const char *what)
{
    MEMORY_BASIC_INFORMATION mbi;
    PVOID base = NULL;
    SIZE_T size = 0x4000;
    NTSTATUS status;

    status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_RESERVE | MEM_COMMIT,
                                     protect);
    ok(status == wantStatus, "%s: alloc -> %08lx, expected %08lx", what, (unsigned long)status,
       (unsigned long)wantStatus);
    if (!NT_SUCCESS(status))
        return;

    memset(&mbi, 0, sizeof(mbi));
    status = NtQueryVirtualMemory(NtCurrentProcess(), base, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), NULL);
    ok(status == STATUS_SUCCESS, "%s: query -> %08lx", what, (unsigned long)status);
    ok(mbi.Protect == wantReported, "%s: Protect %lx, expected %lx", what,
       (unsigned long)mbi.Protect, (unsigned long)wantReported);
    /* AllocationProtect is the SAME captured word one field over, and an
     * implementation can easily canonicalize one and not the other. */
    ok(mbi.AllocationProtect == wantReported, "%s: AllocationProtect %lx, expected %lx", what,
       (unsigned long)mbi.AllocationProtect, (unsigned long)wantReported);

    size = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);
}

START_TEST(protect_modifier_bits)
{
    MEMORY_BASIC_INFORMATION mbi;
    NTSTATUS status;
    PVOID base, addr;
    SIZE_T size;
    ULONG oldProtect;

    /* --- the ALLOCATION path: accepted, and not reported back ------------- */

    /* The control: without a modifier, the reported protection is the asked
     * one. Without this every case below would also pass on a kernel that
     * reported PAGE_READWRITE for everything. */
    check_alloc(PAGE_READWRITE, STATUS_SUCCESS, PAGE_READWRITE, "plain");

    check_alloc(PAGE_READWRITE | WPM_MODIFIERS, STATUS_SUCCESS, PAGE_READWRITE,
                "targets-no-update + enclave-no-change");
    check_alloc(PAGE_READWRITE | PAGE_WRITECOMBINE, STATUS_SUCCESS, PAGE_READWRITE, "writecombine");
    check_alloc(PAGE_EXECUTE_READ | WPM_MODIFIERS, STATUS_SUCCESS, PAGE_EXECUTE_READ,
                "execute-read + modifiers");

    /* The two bits above the byte that DO survive a reservation, and they
     * survive by different mechanisms — PAGE_GUARD is the page's, PAGE_NOCACHE
     * is the view's (see the header). */
    check_alloc(PAGE_READWRITE | PAGE_GUARD, STATUS_SUCCESS, PAGE_READWRITE | PAGE_GUARD, "guard");
    check_alloc(PAGE_READWRITE | PAGE_NOCACHE, STATUS_SUCCESS, PAGE_READWRITE | PAGE_NOCACHE,
                "nocache");
    check_alloc(PAGE_READWRITE | PAGE_GUARD | PAGE_NOCACHE, STATUS_SUCCESS,
                PAGE_READWRITE | PAGE_GUARD | PAGE_NOCACHE, "guard + nocache");

    /* A modifier cannot SUPPLY a protection: the low byte still has to name
     * one, so these are refusals and not "0 plus a flag". */
    check_alloc(PAGE_GUARD, STATUS_INVALID_PAGE_PROTECTION, 0, "guard alone");
    check_alloc(WPM_MODIFIERS, STATUS_INVALID_PAGE_PROTECTION, 0, "modifiers alone");
    check_alloc(PAGE_READWRITE | 0x80, STATUS_INVALID_PAGE_PROTECTION, 0, "junk inside the byte");

    /* --- the PROTECT path: the same word kernelbase actually sends -------- */
    base = NULL;
    size = 0x4000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_RESERVE | MEM_COMMIT,
                                     PAGE_EXECUTE_READ);
    ok(status == STATUS_SUCCESS, "commit 4 pages PAGE_EXECUTE_READ -> %08lx",
       (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    addr = base;
    size = 0x4000;
    oldProtect = 0xdeadbeef;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size,
                                    PAGE_EXECUTE_READWRITE | WPM_MODIFIERS, &oldProtect);
    ok(status == STATUS_SUCCESS, "protect with the WriteProcessMemory word -> %08lx",
       (unsigned long)status);
    /* The PREVIOUS protection is reported canonically too — it comes from
     * stored state, so a kernel that kept the caller's word would report the
     * modifiers back here on the NEXT call. */
    ok(oldProtect == PAGE_EXECUTE_READ, "old_prot %lx, expected %lx", (unsigned long)oldProtect,
       (unsigned long)PAGE_EXECUTE_READ);

    memset(&mbi, 0, sizeof(mbi));
    status = NtQueryVirtualMemory(NtCurrentProcess(), base, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), NULL);
    ok(status == STATUS_SUCCESS, "query after protect -> %08lx", (unsigned long)status);
    ok(mbi.Protect == PAGE_EXECUTE_READWRITE, "Protect after protect %lx, expected %lx",
       (unsigned long)mbi.Protect, (unsigned long)PAGE_EXECUTE_READWRITE);

    /* ...and read back through old_prot on a second call, which is the field
     * kernelbase then uses to RESTORE the range. */
    addr = base;
    size = 0x4000;
    oldProtect = 0xdeadbeef;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size,
                                    PAGE_EXECUTE_READ | WPM_MODIFIERS, &oldProtect);
    ok(status == STATUS_SUCCESS, "restore with the WriteProcessMemory word -> %08lx",
       (unsigned long)status);
    ok(oldProtect == PAGE_EXECUTE_READWRITE, "restore old_prot %lx, expected %lx",
       (unsigned long)oldProtect, (unsigned long)PAGE_EXECUTE_READWRITE);

    /* The refusals the protect path keeps: the low byte still decides. */
    addr = base;
    size = 0x4000;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, WPM_MODIFIERS, &oldProtect);
    ok(status == STATUS_INVALID_PAGE_PROTECTION, "protect with modifiers alone -> %08lx",
       (unsigned long)status);

    /* PAGE_NOCACHE cannot be ADDED by a protect: it is the view's, written
     * once at reserve time, and this reservation did not ask for it. */
    addr = base;
    size = 0x4000;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY | PAGE_NOCACHE,
                                    &oldProtect);
    ok(status == STATUS_SUCCESS, "protect with nocache -> %08lx", (unsigned long)status);
    memset(&mbi, 0, sizeof(mbi));
    NtQueryVirtualMemory(NtCurrentProcess(), base, MEMORY_BASIC_INFO_CLASS, &mbi, sizeof(mbi),
                         NULL);
    ok(mbi.Protect == PAGE_READONLY, "protect could add nocache: Protect %lx",
       (unsigned long)mbi.Protect);

    size = 0;
    addr = base;
    NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);

    /* ...nor REMOVED by one. Same call, over a reservation that DID ask. */
    base = NULL;
    size = 0x4000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_RESERVE | MEM_COMMIT,
                                     PAGE_READWRITE | PAGE_NOCACHE);
    ok(status == STATUS_SUCCESS, "commit 4 pages nocache -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    addr = base;
    size = 0x4000;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY, &oldProtect);
    ok(status == STATUS_SUCCESS, "protect a nocache view -> %08lx", (unsigned long)status);
    ok(oldProtect == (PAGE_READWRITE | PAGE_NOCACHE), "nocache view old_prot %lx, expected %lx",
       (unsigned long)oldProtect, (unsigned long)(PAGE_READWRITE | PAGE_NOCACHE));
    memset(&mbi, 0, sizeof(mbi));
    NtQueryVirtualMemory(NtCurrentProcess(), base, MEMORY_BASIC_INFO_CLASS, &mbi, sizeof(mbi),
                         NULL);
    ok(mbi.Protect == (PAGE_READONLY | PAGE_NOCACHE), "protect dropped nocache: Protect %lx",
       (unsigned long)mbi.Protect);
    ok(mbi.AllocationProtect == (PAGE_READWRITE | PAGE_NOCACHE),
       "protect moved AllocationProtect to %lx", (unsigned long)mbi.AllocationProtect);
    size = 0;
    addr = base;
    NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);

    /* ...nor added by a MEM_COMMIT into an existing reservation, which is the
     * OTHER branch of the same syscall — the assignment is inside
     * `(type & MEM_RESERVE) || !base` and a commit-only call is the `else`. */
    base = NULL;
    size = 0x4000;
    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_RESERVE, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "reserve 4 pages -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    addr = base;
    size = 0x4000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT,
                                     PAGE_READWRITE | PAGE_NOCACHE);
    ok(status == STATUS_SUCCESS, "commit into the reservation with nocache -> %08lx",
       (unsigned long)status);
    memset(&mbi, 0, sizeof(mbi));
    NtQueryVirtualMemory(NtCurrentProcess(), base, MEMORY_BASIC_INFO_CLASS, &mbi, sizeof(mbi),
                         NULL);
    ok(mbi.Protect == PAGE_READWRITE, "commit could add nocache: Protect %lx",
       (unsigned long)mbi.Protect);
    size = 0;
    addr = base;
    NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);

    /* --- a placeholder REPLACEMENT is a reserve, so it re-states nocache ---
     * MEM_REPLACE_PLACEHOLDER runs through the same reserve arm (map_view's
     * replacement branch takes the `vprot` that `vprot |= SEC_NOCACHE` was
     * applied to), so the bit comes from the REPLACING call. The placeholder
     * itself can never carry it — MEM_RESERVE_PLACEHOLDER compares the whole
     * word against PAGE_NOACCESS, unmasked, which is the third distinct mask
     * on this surface and is measured first so the rest is unambiguous. */
    base = NULL;
    size = 0x10000; /* one allocation granule: a placeholder's unit */
    status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size,
                                       MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
                                       PAGE_NOACCESS | PAGE_NOCACHE, NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "placeholder reserve with nocache -> %08lx",
       (unsigned long)status);

    for (unsigned i = 0; i < 2; i++)
    {
        ULONG replaceProtect = i == 0 ? (PAGE_READWRITE | PAGE_NOCACHE) : PAGE_READWRITE;
        ULONG wantReported = i == 0 ? (PAGE_READWRITE | PAGE_NOCACHE) : PAGE_READWRITE;

        base = NULL;
        size = 0x10000;
        status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size,
                                           MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS,
                                           NULL, 0);
        ok(status == STATUS_SUCCESS, "reserve a placeholder -> %08lx", (unsigned long)status);
        if (!NT_SUCCESS(status))
            break;

        addr = base;
        size = 0x10000;
        status = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &addr, &size,
                                           MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER,
                                           replaceProtect, NULL, 0);
        ok(status == STATUS_SUCCESS, "replace a placeholder with %lx -> %08lx",
           (unsigned long)replaceProtect, (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            memset(&mbi, 0, sizeof(mbi));
            NtQueryVirtualMemory(NtCurrentProcess(), base, MEMORY_BASIC_INFO_CLASS, &mbi,
                                 sizeof(mbi), NULL);
            ok(mbi.Protect == wantReported, "replacement Protect %lx, expected %lx",
               (unsigned long)mbi.Protect, (unsigned long)wantReported);
            ok(mbi.AllocationProtect == wantReported,
               "replacement AllocationProtect %lx, expected %lx",
               (unsigned long)mbi.AllocationProtect, (unsigned long)wantReported);
        }
        size = 0;
        addr = base;
        NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    }

    /* --- where the rule STOPS: create takes the bits, map refuses them ---- */
    LARGE_INTEGER sectionSize;
    HANDLE section = NULL;

    sectionSize.QuadPart = 0x4000;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &sectionSize,
                             PAGE_READWRITE | PAGE_NOCACHE | WPM_MODIFIERS, SEC_COMMIT, NULL);
    ok(status == STATUS_SUCCESS, "create a section with the modifier bits -> %08lx",
       (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* Every one of these is INVALID_PAGE_PROTECTION at the map, including the
     * bit the allocation path keeps. */
    static const struct
    {
        ULONG protect;
        const char *what;
    } mapCases[] = {
        {PAGE_READWRITE | PAGE_NOCACHE, "nocache"},
        {PAGE_READWRITE | PAGE_WRITECOMBINE, "writecombine"},
        {PAGE_READWRITE | WPM_MODIFIERS, "targets-no-update + enclave-no-change"},
        {PAGE_READWRITE | PAGE_GUARD, "guard"},
    };
    for (unsigned i = 0; i < sizeof(mapCases) / sizeof(mapCases[0]); i++)
    {
        PVOID view = NULL;
        SIZE_T viewSize = 0;
        status = NtMapViewOfSection(section, NtCurrentProcess(), &view, 0, 0, NULL, &viewSize,
                                    ViewShare, 0, mapCases[i].protect);
        ok(status == STATUS_INVALID_PAGE_PROTECTION, "map with %s -> %08lx", mapCases[i].what,
           (unsigned long)status);
        if (NT_SUCCESS(status))
            NtUnmapViewOfSection(NtCurrentProcess(), view);
    }

    /* The control for the loop: the bare protection maps. */
    PVOID view = NULL;
    SIZE_T viewSize = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &view, 0, 0, NULL, &viewSize,
                                ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "map with the bare protection -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        memset(&mbi, 0, sizeof(mbi));
        status = NtQueryVirtualMemory(NtCurrentProcess(), view, MEMORY_BASIC_INFO_CLASS, &mbi,
                                      sizeof(mbi), NULL);
        ok(status == STATUS_SUCCESS, "query the view -> %08lx", (unsigned long)status);
        ok(mbi.Protect == PAGE_READWRITE, "view Protect %lx", (unsigned long)mbi.Protect);
        NtUnmapViewOfSection(NtCurrentProcess(), view);
    }
    NtClose(section);
}
