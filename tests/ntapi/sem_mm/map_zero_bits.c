/*
 * sem_mm/map_zero_bits.c — NtMapViewOfSection's `zero_bits` is a placement
 * constraint on the VIEW, and its rules are NOT the ones sem_mm/zero_bits.c
 * pinned for NtAllocateVirtualMemory.
 *
 * Both syscalls read the argument through the same definition
 * (third_party/wine dlls/ntdll/unix/unix_private.h, get_zero_bits_limit):
 * 0 is unconstrained, 1..31 is a COUNT of leading zero bits in a 32-bit
 * window (the address must be below 2^(32 - zero_bits)), >= 32 is a MASK of
 * acceptable address bits. Everything around that definition differs, and
 * each difference is a way an implementation that reuses the allocation
 * path's rules answers wrongly:
 *
 *   - the INVALID band is 22..31 only (dlls/ntdll/unix/virtual.c,
 *     NtMapViewOfSection). NtAllocateVirtualMemory additionally refuses
 *     33..0xfffe; mapping does not, so 33 is a legal 63-byte MASK that
 *     simply cannot be satisfied — STATUS_NO_MEMORY, not a parameter error.
 *   - the refusal names argument FOUR (STATUS_INVALID_PARAMETER_4), because
 *     zero_bits is the fourth parameter here and the third there.
 *   - a NAMED base does NOT drop the constraint. The allocation path does
 *     (`if (!*ret) limit = get_zero_bits_limit( zero_bits ); else limit = 0;`
 *     — pinned in sem_mm/zero_bits.c); NtMapViewOfSection passes
 *     `get_zero_bits_limit( zero_bits )` down unconditionally, and map_view
 *     then tests the whole EXTENT of the view against it
 *     (`is_beyond_limit( base, size, limit_high )`). So a base that is
 *     itself under the ceiling, mapping a view that ENDS above it, is
 *     STATUS_CONFLICTING_ADDRESSES — while the same base with a looser
 *     zero_bits succeeds. Only a pair of calls that differ in nothing but
 *     zero_bits can see that.
 *
 * The winetest that convicts the plain constraint is ntdll:virtual's
 * test_NtMapViewOfSection (virtual.c:1507-:1531): it sweeps zero_bits 2..20
 * and asserts `(UINT_PTR)ptr >> (32 - zero_bits)` is 0, then that 21 zero
 * bits never succeeds. proskrnl validated the argument and dropped it, so
 * every one of those maps landed wherever the bottom-up search put it.
 *
 * Oracle-first (G5).
 */
#include "util.h"

#include <string.h> /* declarations only: the .exe links no CRT (ntapi.c) */

/* The section this test maps: two allocation granules, so a view based at
 * the lowest usable 64K address still ENDS above a 2^17 ceiling. */
#define MZB_SECTION_SIZE 0x20000

/* The allocation granularity every view base is rounded to. */
#define MZB_GRANULE 0x10000

/* An IMAGE view is placed by a different arm of the same engine — the
 * preferred base first, then a bounded search — and the limit binds both
 * (dlls/ntdll/unix/virtual.c map_image_view, which takes limit_low/limit_high
 * and passes them to map_view for the preferred base and again for the
 * fall-back range). A kernel that honours zero_bits for a data view and drops
 * it for an image view answers every assertion above and none of these. */
static void test_image_view(void)
{
    HANDLE file, section;
    NTSTATUS status;
    SIZE_T view_size;
    void *ptr;
    char path[MAX_PATH];

    GetSystemDirectoryA(path, sizeof(path));
    strcat(path, "\\kernel32.dll");
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
    ok(file != INVALID_HANDLE_VALUE, "cannot open %s", path);
    if (file == INVALID_HANDLE_VALUE)
    {
        return;
    }

    section = NULL;
    status =
        NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file);
    ok(status == STATUS_SUCCESS, "create the image section -> %08lx", (unsigned long)status);
    CloseHandle(file);
    if (!NT_SUCCESS(status))
    {
        return;
    }

    /* A ceiling BELOW the lowest usable address is a parameter error, not an
     * out-of-memory, and this is the one place the image arm answers
     * differently from the data arm for the same zero_bits. map_image_view
     * raises limit_low to `address_space_start` first ("make sure the DOS
     * area remains free"), and map_view then refuses `limit_low >=
     * limit_high` outright. The data arm passes limit_low 0, so the same
     * ceiling reaches its search and comes back STATUS_NO_MEMORY (the sweep
     * above measures exactly that at zero_bits 16..21). */
    ptr = NULL;
    view_size = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &ptr, 17, 0, NULL, &view_size,
                                ViewShare, 0, PAGE_READONLY);
    ok(status == STATUS_INVALID_PARAMETER, "image view with zero_bits 17 -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        NtUnmapViewOfSection(NtCurrentProcess(), ptr);
    }

    /* Above that floor the ordinary out-of-memory comes back: 2^17 - 1 is a
     * 128 KiB ceiling and no PE on this volume is that small. */
    ptr = NULL;
    view_size = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &ptr, 15, 0, NULL, &view_size,
                                ViewShare, 0, PAGE_READONLY);
    ok(status == STATUS_NO_MEMORY, "image view with zero_bits 15 -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        NtUnmapViewOfSection(NtCurrentProcess(), ptr);
    }

    /* And a ceiling that a PE fits under but kernel32's preferred base does
     * not: the view must be RELOCATED below it rather than placed where the
     * image asked. STATUS_IMAGE_NOT_AT_BASE is the success that says so. */
    ptr = NULL;
    view_size = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &ptr, 4, 0, NULL, &view_size,
                                ViewShare, 0, PAGE_READONLY);
    ok(status == STATUS_IMAGE_NOT_AT_BASE || status == STATUS_SUCCESS || status == STATUS_NO_MEMORY,
       "image view with zero_bits 4 -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ok(((ULONG_PTR)ptr >> 28) == 0,
           "zero_bits 4 put the image view at %p, above the 2^28 ceiling", ptr);
        NtUnmapViewOfSection(NtCurrentProcess(), ptr);
    }

    NtClose(section);
}

START_TEST(map_zero_bits)
{
    NTSTATUS status;
    HANDLE section;
    LARGE_INTEGER max_size, offset;
    SIZE_T view_size;
    void *ptr;
    ULONG_PTR bits;

    offset.QuadPart = 0;
    max_size.QuadPart = MZB_SECTION_SIZE;
    section = NULL;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max_size, PAGE_READWRITE,
                             SEC_COMMIT, NULL);
    ok(status == STATUS_SUCCESS, "create the section -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        return;
    }

    /* --- the count form: 1 .. 21 ----------------------------------------
     * From 16 up the ceiling (2^16 - 1 and below) is SMALLER THAN THE VIEW,
     * so no address in any address space can hold it and the answer is an
     * out-of-memory rather than a parameter error — 21, the largest value
     * the validation accepts, is only the extreme case of that. Those are
     * the assertions that convict a kernel which validates zero_bits and
     * then drops it: they hold whatever the process's layout is, whereas
     * `the view landed under the ceiling` is satisfied for free by any
     * bottom-up search whose lowest hole happens to be low enough. */
    for (bits = 1; bits <= 21; bits++)
    {
        ptr = NULL;
        view_size = 0;
        status = NtMapViewOfSection(section, NtCurrentProcess(), &ptr, bits, 0, &offset, &view_size,
                                    ViewShare, 0, PAGE_READWRITE);
        if ((ULONG_PTR)1 << (32 - bits) < MZB_SECTION_SIZE)
        {
            ok(status == STATUS_NO_MEMORY, "zero_bits %u (ceiling below the view size) -> %08lx",
               (unsigned)bits, (unsigned long)status);
            if (NT_SUCCESS(status))
            {
                NtUnmapViewOfSection(NtCurrentProcess(), ptr);
            }
            continue;
        }

        ok(status == STATUS_SUCCESS || status == STATUS_NO_MEMORY, "zero_bits %u -> %08lx",
           (unsigned)bits, (unsigned long)status);
        if (!NT_SUCCESS(status))
        {
            continue;
        }
        ok(((ULONG_PTR)ptr >> (32 - bits)) == 0,
           "zero_bits %u put the view at %p, above the 2^%u ceiling", (unsigned)bits, ptr,
           (unsigned)(32 - bits));
        status = NtUnmapViewOfSection(NtCurrentProcess(), ptr);
        ok(status == STATUS_SUCCESS, "unmap the zero_bits %u view -> %08lx", (unsigned)bits,
           (unsigned long)status);
    }

    /* --- the invalid band: 22 .. 31 -------------------------------------
     * Malformed, not unsatisfiable, and the status names the ARGUMENT — it
     * must not decay into the generic STATUS_INVALID_PARAMETER, and it must
     * not be the _3 the allocation path answers. */
    ptr = NULL;
    view_size = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &ptr, 22, 0, &offset, &view_size,
                                ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER_4, "zero_bits 22 -> %08lx", (unsigned long)status);

    ptr = NULL;
    view_size = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &ptr, 31, 0, &offset, &view_size,
                                ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER_4, "zero_bits 31 -> %08lx", (unsigned long)status);

    /* --- and 33 is NOT invalid here ------------------------------------
     * NtAllocateVirtualMemory refuses it (STATUS_INVALID_PARAMETER_3, pinned
     * by sem_mm/zero_bits.c); NtMapViewOfSection has no such band, so 33 is
     * read as a mask whose highest set bit is 5 — a 63-byte ceiling, which
     * no view fits under. A kernel that copied the allocation path's
     * validation answers a parameter error and a kernel that dropped the
     * argument answers SUCCESS; both are wrong in the same place. */
    ptr = NULL;
    view_size = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &ptr, 33, 0, &offset, &view_size,
                                ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_NO_MEMORY, "zero_bits 33 -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        NtUnmapViewOfSection(NtCurrentProcess(), ptr);
    }

    /* --- the mask form --------------------------------------------------
     * Every address bit up to and including the highest set one is allowed,
     * so 0xffffff is a 0xffffff ceiling. */
    ptr = NULL;
    view_size = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &ptr, 0xffffff, 0, &offset, &view_size,
                                ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS || status == STATUS_NO_MEMORY, "zero_bits mask 0xffffff -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ok((ULONG_PTR)ptr <= 0xffffff, "the 0xffffff mask put the view at %p", ptr);
        NtUnmapViewOfSection(NtCurrentProcess(), ptr);
    }

    /* --- a NAMED base, and the three ways it can go ---------------------
     * Every ceiling zero_bits can express is a power of two minus one, so a
     * base and a view size have to be CHOSEN to sit against one — and the
     * two runners' lowest free address is nowhere near each other (0x10000
     * under the oracle, ~0x7c0000 on proskrnl, both measured), so they are
     * derived here instead of written down. Reserve a granule to find the
     * lowest hole, take the next power of two above it, and size a section
     * so that a view based at that hole ENDS exactly there. Then one bit
     * either side of that ceiling gives the other two answers.
     *
     * The probe reservation carries zero_bits 1 — a 2 GiB ceiling, far above
     * anything this asks about — because an UNCONSTRAINED reservation is not
     * bottom-up on the oracle: measured, it comes back at 0x7ffffe8c0000,
     * and only a limit puts it on the low-address search
     * (dlls/ntdll/unix/virtual.c map_view: a limit is what selects
     * map_free_area over plain anon mmap). */
    {
        void *scratch = NULL;
        SIZE_T scratch_size = MZB_GRANULE;
        ULONG_PTR hole, top;
        unsigned top_bit, at_edge;

        status = NtAllocateVirtualMemory(NtCurrentProcess(), &scratch, 1, &scratch_size,
                                         MEM_RESERVE, PAGE_READWRITE);
        /* Not `SUCCESS || NO_MEMORY`: an out-of-memory here would silently
         * skip every assertion below it, which is how this block first ran
         * green while measuring nothing. */
        ok(status == STATUS_SUCCESS, "reserve a probe granule -> %08lx", (unsigned long)status);
        if (!NT_SUCCESS(status))
        {
            NtClose(section);
            return;
        }
        hole = (ULONG_PTR)scratch;
        scratch_size = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &scratch, &scratch_size, MEM_RELEASE);
        ok(status == STATUS_SUCCESS, "release the probe granule -> %08lx", (unsigned long)status);

        top = MZB_GRANULE;
        top_bit = 16;
        while (top_bit < 30 && top < hole + MZB_GRANULE)
        {
            top <<= 1;
            top_bit++;
        }
        /* `top` is now the lowest power of two strictly above `hole`, so a
         * view of `top - hole` bytes based at `hole` ends exactly at it, and
         * `at_edge` is the zero_bits value whose ceiling is top - 1. The
         * band keeps at_edge - 1 .. at_edge + 1 all inside the legal 1..21. */
        at_edge = 32 - top_bit;
        if (top < hole + MZB_GRANULE || top_bit < 12)
        {
            skip("the lowest hole at %llx puts the edge zero_bits outside 2..20",
                 (unsigned long long)hole);
        }
        else
        {
            HANDLE edge_section = NULL;
            SIZE_T edge_size = (SIZE_T)(top - hole);

            max_size.QuadPart = (LONGLONG)edge_size;
            status = NtCreateSection(&edge_section, SECTION_ALL_ACCESS, NULL, &max_size,
                                     PAGE_READWRITE, SEC_COMMIT, NULL);
            ok(status == STATUS_SUCCESS, "create the edge section -> %08lx", (unsigned long)status);

            /* One bit TIGHTER puts the ceiling at top/2 - 1, below the base
             * itself: refused on the argument, before anything looks at the
             * address space. */
            ptr = (void *)hole;
            view_size = 0;
            status = NtMapViewOfSection(edge_section, NtCurrentProcess(), &ptr, at_edge + 1, 0,
                                        &offset, &view_size, ViewShare, 0, PAGE_READWRITE);
            ok(status == STATUS_INVALID_PARAMETER_4, "base %llx with zero_bits %u -> %08lx",
               (unsigned long long)hole, at_edge + 1, (unsigned long)status);

            /* The edge itself, and the one place the two readings of the
             * ceiling disagree. `get_zero_bits_limit` returns the INCLUSIVE
             * top address and the free-range search treats it that way
             * (`end = limit_high + 1`, dlls/ntdll/unix/virtual.c map_view);
             * the named-base guard beside it does NOT — `is_beyond_limit`
             * refuses at `base + size > limit_high` — so a view whose LAST
             * BYTE is exactly the ceiling is one byte too long. This is also
             * the assertion that separates the syscall from
             * NtAllocateVirtualMemory, which drops the constraint entirely
             * once a base is named (sem_mm/zero_bits.c). Measured, not
             * reasoned: either convention is defensible and only this case
             * says which one NT picked. */
            ptr = (void *)hole;
            view_size = 0;
            status = NtMapViewOfSection(edge_section, NtCurrentProcess(), &ptr, at_edge, 0, &offset,
                                        &view_size, ViewShare, 0, PAGE_READWRITE);
            ok(status == STATUS_CONFLICTING_ADDRESSES,
               "a view ending exactly at the zero_bits %u ceiling -> %08lx", at_edge,
               (unsigned long)status);
            if (NT_SUCCESS(status))
            {
                NtUnmapViewOfSection(NtCurrentProcess(), ptr);
            }

            /* One bit LOOSER holds the whole extent with room to spare.
             * Without this control the assertion above passes on a kernel
             * that refuses every named base outright. */
            ptr = (void *)hole;
            view_size = 0;
            status = NtMapViewOfSection(edge_section, NtCurrentProcess(), &ptr, at_edge - 1, 0,
                                        &offset, &view_size, ViewShare, 0, PAGE_READWRITE);
            ok(status == STATUS_SUCCESS, "base %llx with zero_bits %u -> %08lx",
               (unsigned long long)hole, at_edge - 1, (unsigned long)status);
            if (NT_SUCCESS(status))
            {
                ok((ULONG_PTR)ptr == hole, "the named base moved: %p vs %llx", ptr,
                   (unsigned long long)hole);
                ok(view_size == edge_size, "view size %llx vs %llx", (unsigned long long)view_size,
                   (unsigned long long)edge_size);
                NtUnmapViewOfSection(NtCurrentProcess(), ptr);
            }
            NtClose(edge_section);
        }
    }

    test_image_view();

    NtClose(section);
}
