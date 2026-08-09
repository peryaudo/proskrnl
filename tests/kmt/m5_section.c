/* tests/kmt/m5_section.c — the M5 in-kernel suite (docs/02).
 *
 * The ring-3 half of M5 (section syscalls, guard-page stack growth, the PE
 * client) is proven by the boot modules and the sem_mm manifest tests. This
 * suite covers what a user binary cannot see from inside: the section/image
 * engines driven against a scratch address space — frame sharing between
 * views, mapped-view/read consistency through the RAM-disk page cache
 * (docs/02's consistency test), PE image copies with relocation deltas, and
 * guard-page bookkeeping. Behaviours mirror the sem_mm oracle tests
 * (greened on Wine first, Art. 5); here we can also inspect page tables and
 * physical frames directly.
 *
 * Runs on a kernel thread; the scratch space is never made current (CR3),
 * so mapped content is checked through MiTranslateUserPage + the HHDM.
 */
#include "tests/kmt/kmt.h"
#include "kernel/mm/section.h"
#include "kernel/mm/virtual.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/pool.h"
#include "kernel/init/initrd.h"
#include "kernel/ob/ob.h"
#include "kernel/lib/string.h"
#include "arch/x86_64/mmu.h"

#include "abi/ntimage.h"
#include "abi/ntmmapi.h"
#include "abi/ntstatus.h"

/* Read one byte of a mapped (committed) page through the HHDM. */
static unsigned char mapped_byte(PMI_ADDRESS_SPACE space, uint64_t va)
{
    uint64_t frame = MiTranslateUserPage(space->pml4Physical, va & ~(PAGE_SIZE - 1ULL), 0, 0);
    ok(frame != 0, "mapped_byte: %lx not mapped", (unsigned long)va);
    if (frame == 0)
        return 0;
    return ((unsigned char *)MiPhysicalToVirtual(frame))[va & (PAGE_SIZE - 1)];
}

static uint64_t mapped_qword(PMI_ADDRESS_SPACE space, uint64_t va)
{
    uint64_t value = 0;
    for (int i = 0; i < 8; i++)
        value |= (uint64_t)mapped_byte(space, va + i) << (i * 8);
    return value;
}

static void test_anonymous_section_engine(void)
{
    uint64_t free_at_start = MiGetFreePageCount();
    {
        MI_ADDRESS_SPACE space;
        ok(MiCreateAddressSpace(&space) == STATUS_SUCCESS, "create address space");

        LARGE_INTEGER max_size;
        max_size.QuadPart = 0x3000;
        PMI_SECTION section = 0;
        NTSTATUS status = MiCreateSection(&max_size, PAGE_READWRITE, SEC_COMMIT, 0, &section);
        ok(status == STATUS_SUCCESS, "create section -> %08lx", (unsigned long)status);
        ok(section->attributes == SEC_COMMIT, "attributes %08lx",
           (unsigned long)section->attributes);
        ok(section->size == 0x3000 && section->pageCount == 3, "size %lx pages %lu",
           (unsigned long)section->size, (unsigned long)section->pageCount);

        /* Two views share the section's frames — writes cross over. */
        uint64_t base1 = 0, size1 = 0;
        status = MiMapViewOfSection(section, &space, &base1, 0, &size1, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "map view1 -> %08lx", (unsigned long)status);
        ok((base1 & 0xFFFF) == 0 && size1 == 0x3000, "view1 base %lx size %lx",
           (unsigned long)base1, (unsigned long)size1);
        ok(mapped_byte(&space, base1) == 0, "view not zero-initialized");

        uint64_t frame1 = MiTranslateUserPage(space.pml4Physical, base1, 0, 0);
        ok(frame1 == section->frames[0], "view1 does not map the section frame");
        ((unsigned char *)MiPhysicalToVirtual(frame1))[7] = 0x5a;

        uint64_t base2 = 0, size2 = 0;
        status = MiMapViewOfSection(section, &space, &base2, 0, &size2, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "map view2 -> %08lx", (unsigned long)status);
        ok(base2 != base1, "views at one address");
        ok(mapped_byte(&space, base2 + 7) == 0x5a, "views do not share frames");

        /* Mapping over an occupied base conflicts. */
        uint64_t conflict = base1, conflict_size = 0;
        status = MiMapViewOfSection(section, &space, &conflict, 0, &conflict_size, PAGE_READWRITE);
        ok(status == STATUS_CONFLICTING_ADDRESSES, "conflicting map -> %08lx",
           (unsigned long)status);

        /* Offset past the end is invalid; an oversized view too. */
        uint64_t scratch_base = 0, scratch_size = 0;
        status = MiMapViewOfSection(section, &space, &scratch_base, 0x3000, &scratch_size,
                                    PAGE_READWRITE);
        ok(status == STATUS_INVALID_PARAMETER, "offset at end -> %08lx", (unsigned long)status);
        scratch_base = 0;
        scratch_size = 0x4000;
        status =
            MiMapViewOfSection(section, &space, &scratch_base, 0, &scratch_size, PAGE_READWRITE);
        ok(status == STATUS_INVALID_VIEW_SIZE, "oversize view -> %08lx", (unsigned long)status);

        /* Unmap view1; the frames live on in the section and view2. */
        ok(MiUnmapView(&space, base1 + 0x1000) == STATUS_SUCCESS, "unmap view1");
        ok(MiUnmapView(&space, base1) == STATUS_NOT_MAPPED_VIEW, "unmap view1 again");
        ok(mapped_byte(&space, base2 + 7) == 0x5a, "frames died with view1");

        /* Free rejects views (they are unmapped instead). */
        PVOID addr = (PVOID)(uintptr_t)base2;
        SIZE_T free_size = 0;
        ok(MiFreeVirtualMemory(&space, &addr, &free_size, MEM_RELEASE) == STATUS_INVALID_PARAMETER,
           "free view");
        ok(MiUnmapView(&space, base2) == STATUS_SUCCESS, "unmap view2");

        ObDereferenceObject(section); /* frees the section's frames */
        MiDeleteAddressSpace(&space);
    }
    ok(MiGetFreePageCount() == free_at_start, "leaked frames (%lu vs %lu)",
       (unsigned long)MiGetFreePageCount(), (unsigned long)free_at_start);
}

static void test_file_section_consistency(void)
{
    PKI_RAMDISK_FILE file = KiFindRamdiskFile("sample.dat");
    if (file == 0)
    {
        DbgPrint("  (sample.dat not in the RAM-disk; skipping)\n");
        return;
    }

    /* Warm up first: fill the file's page cache (which then persists — no
     * eviction, Art. 3) and the pool's high-water mark, so the measured
     * round below balances exactly. */
    char *buffer = MiAllocatePool(file->size);
    ok(buffer != 0, "no pool for the read buffer");
    {
        PMI_SECTION warmup = 0;
        ok(MiCreateSection(0, PAGE_READONLY, SEC_COMMIT, file, &warmup) == STATUS_SUCCESS,
           "warm-up section");
        ok(file->cache.frames != 0, "no page cache after file section creation");
        ObDereferenceObject(warmup);
    }

    uint64_t free_after_cache = MiGetFreePageCount();

    MI_ADDRESS_SPACE space;
    ok(MiCreateAddressSpace(&space) == STATUS_SUCCESS, "create address space");
    PMI_SECTION section = 0;
    NTSTATUS status = MiCreateSection(0, PAGE_READONLY, SEC_COMMIT, file, &section);
    ok(status == STATUS_SUCCESS, "create file section -> %08lx", (unsigned long)status);
    ok(section->attributes == SEC_FILE, "attributes %08lx", (unsigned long)section->attributes);
    ok(section->size == file->size, "section size %lx, file %lx", (unsigned long)section->size,
       (unsigned long)file->size);

    uint64_t base = 0, view_size = 0;
    status = MiMapViewOfSection(section, &space, &base, 0, &view_size, PAGE_READONLY);
    ok(status == STATUS_SUCCESS, "map file view -> %08lx", (unsigned long)status);

    /* THE M5 consistency test (docs/02): the mapped view and the read path
     * see identical bytes — structurally, both are the page cache. */
    uint64_t read = 0;
    ok(KiReadRamdiskFile(file, 0, buffer, file->size, &read) == STATUS_SUCCESS &&
           read == file->size,
       "ramdisk read failed");
    int mismatch = 0;
    for (uint64_t i = 0; i < file->size && mismatch == 0; i++)
    {
        if (mapped_byte(&space, base + i) != (unsigned char)buffer[i])
            mismatch = 1;
    }
    ok(mismatch == 0, "mapped view and file read disagree");

    /* The tail page reads zero past EOF (the NT rule the cache implements). */
    if ((file->size & (PAGE_SIZE - 1)) != 0)
    {
        uint64_t eof = base + file->size;
        uint64_t page_end = (eof + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1ULL);
        int dirty = 0;
        for (uint64_t va = eof; va < page_end; va++)
        {
            if (mapped_byte(&space, va) != 0)
                dirty = 1;
        }
        ok(dirty == 0, "tail page not zero-filled past EOF");
    }

    /* A shared data view frees NO frames at unmap — they are the cache's. */
    ok(MiUnmapView(&space, base) == STATUS_SUCCESS, "unmap file view");
    ObDereferenceObject(section);
    MiDeleteAddressSpace(&space);
    ok(MiGetFreePageCount() == free_after_cache, "file view leaked frames (%lu vs %lu)",
       (unsigned long)MiGetFreePageCount(), (unsigned long)free_after_cache);
    MiFreePool(buffer);
}

/* The first DIR64 relocation in the image's .reloc directory, as an RVA;
 * ~0 when there is none. Walks the FILE bytes, like the mapper. */
static uint64_t first_dir64_reloc(PKI_RAMDISK_FILE file, const MI_IMAGE_INFO *image)
{
    if (image->relocRva == 0)
        return ~0ULL;
    for (ULONG i = 0; i < image->segmentCount; i++)
    {
        const MI_IMAGE_SEGMENT *seg = &image->segments[i];
        if (image->relocRva < seg->virtualAddress ||
            image->relocRva + image->relocSize > seg->virtualAddress + seg->rawSize)
            continue;
        const char *cursor =
            (const char *)file->data + seg->rawOffset + (image->relocRva - seg->virtualAddress);
        const char *end = cursor + image->relocSize;
        while (cursor + sizeof(IMAGE_BASE_RELOCATION) <= end)
        {
            IMAGE_BASE_RELOCATION block;
            /* NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
             */
            memcpy(&block, cursor, sizeof(block));
            if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                cursor + block.SizeOfBlock > end)
                return ~0ULL;
            ULONG count = (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
            const USHORT *entries = (const USHORT *)(cursor + sizeof(IMAGE_BASE_RELOCATION));
            for (ULONG j = 0; j < count; j++)
            {
                if ((entries[j] >> 12) == IMAGE_REL_BASED_DIR64)
                    return block.VirtualAddress + (entries[j] & 0xFFF);
            }
            cursor += block.SizeOfBlock;
        }
    }
    return ~0ULL;
}

static void test_image_section(void)
{
    PKI_RAMDISK_FILE file = KiFindRamdiskFile("pe_smoke.exe");
    if (file == 0)
    {
        DbgPrint("  (pe_smoke.exe not in the RAM-disk; skipping)\n");
        return;
    }

    uint64_t free_at_start = MiGetFreePageCount();
    {
        MI_ADDRESS_SPACE space;
        ok(MiCreateAddressSpace(&space) == STATUS_SUCCESS, "create address space");

        PMI_SECTION section = 0;
        NTSTATUS status = MiCreateSection(0, PAGE_EXECUTE, SEC_IMAGE, file, &section);
        ok(status == STATUS_SUCCESS, "create image section -> %08lx", (unsigned long)status);
        ok(section->image != 0, "no image info");
        if (section->image == 0)
        {
            ObDereferenceObject(section);
            MiDeleteAddressSpace(&space);
            return;
        }
        ok(section->attributes == (SEC_FILE | SEC_IMAGE), "attributes %08lx",
           (unsigned long)section->attributes);
        const MI_IMAGE_INFO *image = section->image;
        ok(image->machine == IMAGE_FILE_MACHINE_AMD64, "machine %04x", image->machine);
        ok(image->containsCode, "no code in the test PE");
        ok(image->entryRva != 0, "entry RVA 0");

        /* First view lands at the preferred base — plain success. */
        uint64_t base1 = 0, size1 = 0;
        status = MiMapViewOfSection(section, &space, &base1, 0, &size1, PAGE_EXECUTE);
        ok(status == STATUS_SUCCESS, "map at base -> %08lx", (unsigned long)status);
        ok(base1 == image->preferredBase, "mapped at %lx, preferred %lx", (unsigned long)base1,
           (unsigned long)image->preferredBase);
        ok(size1 == image->sizeOfImage, "view size %lx", (unsigned long)size1);
        ok(mapped_byte(&space, base1) == 'M' && mapped_byte(&space, base1 + 1) == 'Z',
           "mapped header is not MZ");

        /* Per-PE-section protection: every page starts on the shared master
         * frame, hardware-READ-ONLY — writable (writecopy) segments too;
         * their first store resolves through the CUI-9 COW arm
         * (MiResolveWriteFault: tests/kmt/cui9_cow.c owns that half). The
         * copied bytes match the file's raw data. */
        for (ULONG i = 0; i < image->segmentCount; i++)
        {
            const MI_IMAGE_SEGMENT *seg = &image->segments[i];
            int writable = 0, present = 0;
            uint64_t frame = MiTranslateUserPage(space.pml4Physical, base1 + seg->virtualAddress,
                                                 &writable, &present);
            ok(frame != 0 && present, "segment %lu not mapped", (unsigned long)i);
            ok(!writable, "segment %lu hardware-writable while shared (protect %lx)",
               (unsigned long)i, (unsigned long)seg->protect);
            if (seg->rawSize != 0 && frame != 0)
            {
                uint64_t chunk = seg->rawSize < PAGE_SIZE ? seg->rawSize : PAGE_SIZE;
                ok(memcmp(MiPhysicalToVirtual(frame), (const char *)file->data + seg->rawOffset,
                          chunk) == 0,
                   "segment %lu content mismatch", (unsigned long)i);
            }
        }

        /* Second view: the base is taken, so the copy is relocated. */
        uint64_t base2 = 0, size2 = 0;
        status = MiMapViewOfSection(section, &space, &base2, 0, &size2, PAGE_EXECUTE);
        if (image->relocsStripped)
        {
            ok(status == STATUS_CONFLICTING_ADDRESSES, "stripped image remap -> %08lx",
               (unsigned long)status);
        }
        else
        {
            ok(status == STATUS_IMAGE_NOT_AT_BASE, "relocated map -> %08lx", (unsigned long)status);
            ok(base2 != 0 && base2 != base1, "relocated to %lx", (unsigned long)base2);

            /* An image section is relocated ONCE and every view shares that
             * copy, so the two views hold IDENTICAL bytes — a DIR64 fixup
             * site included. The residual for a view away from the copy's
             * base belongs to the PE loader, which keys off the stamped
             * ImageBase (docs/03 "An image section is relocated once"; the
             * oracle memcmps exactly this at ntdll:virtual:1743). This
             * assertion used to require the two to DIFFER by the load delta;
             * test_image_relocation below is what convicts the relocation
             * pass now. */
            uint64_t reloc_rva = first_dir64_reloc(file, image);
            ok(reloc_rva != ~0ULL, "PE has no DIR64 relocation to verify");
            if (reloc_rva != ~0ULL)
            {
                uint64_t at_base = mapped_qword(&space, base1 + reloc_rva);
                uint64_t second = mapped_qword(&space, base2 + reloc_rva);
                ok(second == at_base, "reloc site: %lx in view 1, %lx in view 2",
                   (unsigned long)at_base, (unsigned long)second);
            }
            ok(MiUnmapView(&space, base2) == STATUS_SUCCESS, "unmap relocated view");
        }

        ok(MiUnmapView(&space, base1) == STATUS_SUCCESS, "unmap image view");
        ObDereferenceObject(section);
        MiDeleteAddressSpace(&space);
    }
    /* Image views are private full copies: everything comes back. */
    ok(MiGetFreePageCount() == free_at_start, "image mapping leaked frames (%lu vs %lu)",
       (unsigned long)MiGetFreePageCount(), (unsigned long)free_at_start);
}

/* A commit REFUSES when its page tables cannot be charged, and does not
 * panic. MiMapUserPage is infallible by contract, so the tables were the one
 * allocation inside the commit that could fail — and it panicked
 * (MiEnsureTable) rather than refusing, i.e. ring 3 running the machine out
 * of memory could bring the kernel down (docs/03 "Page tables are CHARGED").
 *
 * The knob is why this is a test and not a hope: the only other way to reach
 * the refusal is to exhaust the machine, and WHICH allocation loses at that
 * ceiling is not a property to build a conviction on (the cui9 leg re-rolls
 * it whenever per-process cost moves). Both arms are covered — private
 * memory through MiCommitPages, a view through MiCreateMappedVad. */
static void test_page_table_charge(void)
{
    uint64_t free_at_start = MiGetFreePageCount();
    {
        MI_ADDRESS_SPACE space;
        ok(MiCreateAddressSpace(&space) == STATUS_SUCCESS, "create address space");

        /* --- the private-commit arm ------------------------------------- */
        PVOID base = 0;
        SIZE_T size = 0x2000;
        MiChargeFailNextTable = 1;
        NTSTATUS status =
            MiAllocateVirtualMemory(&space, &base, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        ok(status == STATUS_NO_MEMORY, "commit under a table shortage -> %08lx",
           (unsigned long)status);
        ok(MiChargeFailNextTable == 0, "knob did not self-clear (no table was needed)");
        MiChargeFailNextTable = 0;

        /* The same request succeeds with the knob down, so the refusal above
         * was the charge and not the arguments. */
        base = 0;
        size = 0x2000;
        status =
            MiAllocateVirtualMemory(&space, &base, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "commit without the knob -> %08lx", (unsigned long)status);

        /* --- the view arm ------------------------------------------------ */
        PKI_RAMDISK_FILE file = KiFindRamdiskFile("pe_smoke.exe");
        if (file != 0)
        {
            PMI_SECTION section = 0;
            ok(MiCreateSection(0, PAGE_EXECUTE, SEC_IMAGE, file, &section) == STATUS_SUCCESS,
               "create image section");
            if (section != 0)
            {
                uint64_t viewBase = 0, viewSize = 0;
                MiChargeFailNextTable = 1;
                status = MiMapViewOfSection(section, &space, &viewBase, 0, &viewSize, PAGE_EXECUTE);
                ok(status == STATUS_NO_MEMORY, "image map under a table shortage -> %08lx",
                   (unsigned long)status);
                ok(MiChargeFailNextTable == 0, "knob did not self-clear (view arm)");
                MiChargeFailNextTable = 0;
                ObDereferenceObject(section);
            }
        }

        MiDeleteAddressSpace(&space);
    }
    ok(MiGetFreePageCount() == free_at_start, "refused commits leaked frames (%lu vs %lu)",
       (unsigned long)MiGetFreePageCount(), (unsigned long)free_at_start);
}

/* The raw file bytes behind an image RVA, or 0 when no segment covers it. */
static const char *raw_at_rva(PKI_RAMDISK_FILE file, const MI_IMAGE_INFO *image, uint64_t rva,
                              uint64_t length)
{
    for (ULONG i = 0; i < image->segmentCount; i++)
    {
        const MI_IMAGE_SEGMENT *seg = &image->segments[i];
        if (rva >= seg->virtualAddress && rva + length <= seg->virtualAddress + seg->rawSize)
            return (const char *)file->data + seg->rawOffset + (rva - seg->virtualAddress);
    }
    return 0;
}

/* The relocation pass itself, which the shared-copy rule made harder to
 * reach: an image's ONE copy is relocated for the base its FIRST view got, so
 * with the preferred base free nothing relocates at all. Take the preferred
 * base away first, and the copy must be built somewhere else — the DIR64
 * fixup site then sits exactly (base - preferredBase) above the value in the
 * FILE, and a second view SHARES that one relocated copy instead of getting
 * its own. (Before docs/03 "An image section is relocated once" the pass was
 * convicted by comparing two views, which now hold identical bytes by
 * design.) */
static void test_image_relocation(void)
{
    PKI_RAMDISK_FILE file = KiFindRamdiskFile("pe_smoke.exe");
    if (file == 0)
    {
        return;
    }

    uint64_t free_at_start = MiGetFreePageCount();
    {
        MI_ADDRESS_SPACE space;
        ok(MiCreateAddressSpace(&space) == STATUS_SUCCESS, "create address space");
        PMI_SECTION section = 0;
        NTSTATUS status = MiCreateSection(0, PAGE_EXECUTE, SEC_IMAGE, file, &section);
        ok(status == STATUS_SUCCESS, "create image section -> %08lx", (unsigned long)status);
        if (section == 0 || section->image == 0)
        {
            if (section != 0)
            {
                ObDereferenceObject(section);
            }
            MiDeleteAddressSpace(&space);
            return;
        }
        const MI_IMAGE_INFO *image = section->image;

        /* Hold the preferred base so the copy cannot be built at it. */
        PVOID hold = (PVOID)(uintptr_t)image->preferredBase;
        SIZE_T holdSize = image->sizeOfImage;
        status = MiAllocateVirtualMemory(&space, &hold, &holdSize, MEM_RESERVE, PAGE_NOACCESS);
        ok(status == STATUS_SUCCESS && (uint64_t)(uintptr_t)hold == image->preferredBase,
           "reserve the preferred base -> %08lx at %lx", (unsigned long)status,
           (unsigned long)(uintptr_t)hold);

        ULONG builds0, hits0, live0, builds1, hits1, live1;
        uint64_t mframes0, mframes1;
        MiGetImageMasterStats(&builds0, &hits0, &live0, &mframes0);

        uint64_t base1 = 0, size1 = 0;
        status = MiMapViewOfSection(section, &space, &base1, 0, &size1, PAGE_EXECUTE);
        ok(status == STATUS_IMAGE_NOT_AT_BASE, "rebased map -> %08lx", (unsigned long)status);
        ok(base1 != 0 && base1 != image->preferredBase, "mapped at the preferred base %lx",
           (unsigned long)base1);

        /* The precondition is asserted, never assumed: only a copy built HERE
         * can be relocated for base1. A hit would mean an earlier view of
         * pe_smoke.exe outlived its test, which is itself the finding. */
        MiGetImageMasterStats(&builds1, &hits1, &live1, &mframes1);
        ok(builds1 == builds0 + 1, "the copy was reused, not built (builds %lu, hits %lu)",
           (unsigned long)(builds1 - builds0), (unsigned long)(hits1 - hits0));

        uint64_t reloc_rva = first_dir64_reloc(file, image);
        ok(reloc_rva != ~0ULL, "PE has no DIR64 relocation to verify");
        const char *raw = reloc_rva == ~0ULL ? 0 : raw_at_rva(file, image, reloc_rva, 8);
        ok(raw != 0, "no raw bytes behind the fixup site");
        if (builds1 == builds0 + 1 && raw != 0 && base1 != 0)
        {
            uint64_t fromFile = 0;
            for (int i = 0; i < 8; i++)
            {
                fromFile |= (uint64_t)(unsigned char)raw[i] << (i * 8);
            }
            uint64_t mapped = mapped_qword(&space, base1 + reloc_rva);
            ok(mapped == fromFile + (base1 - image->preferredBase),
               "reloc site: file %lx, mapped %lx, delta %lx", (unsigned long)fromFile,
               (unsigned long)mapped, (unsigned long)(base1 - image->preferredBase));

            /* THE assertion the shared-copy rule rests on, and the only place
             * in the tree where it is not vacuous: the copy's stamped
             * ImageBase must name the base it was RELOCATED for, because
             * that is what ntdll's perform_relocations subtracts to fix up a
             * view sitting anywhere else (docs/17 §6F's surviving half). A
             * copy at its preferred base cannot see this — the file already
             * holds the right value there. */
            uint64_t stamped =
                mapped_qword(&space, base1 + image->ntHeaderOffset +
                                         offsetof(IMAGE_NT_HEADERS64, OptionalHeader.ImageBase));
            ok(stamped == base1, "ImageBase stamp %lx, expected the copy's base %lx",
               (unsigned long)stamped, (unsigned long)base1);

            /* A second view shares that one relocated copy. */
            uint64_t base2 = 0, size2 = 0;
            status = MiMapViewOfSection(section, &space, &base2, 0, &size2, PAGE_EXECUTE);
            ok(status == STATUS_IMAGE_NOT_AT_BASE, "second view -> %08lx", (unsigned long)status);
            ok(base2 != 0 && base2 != base1, "second view at %lx", (unsigned long)base2);
            if (base2 != 0)
            {
                ok(mapped_qword(&space, base2 + reloc_rva) == mapped,
                   "second view relocated separately");
                ok(MiUnmapView(&space, base2) == STATUS_SUCCESS, "unmap second view");
            }
        }

        if (base1 != 0)
        {
            ok(MiUnmapView(&space, base1) == STATUS_SUCCESS, "unmap rebased view");
        }
        ObDereferenceObject(section);
        MiDeleteAddressSpace(&space);
    }
    ok(MiGetFreePageCount() == free_at_start, "relocated mapping leaked frames (%lu vs %lu)",
       (unsigned long)MiGetFreePageCount(), (unsigned long)free_at_start);
}

static void test_guard_bookkeeping(void)
{
    uint64_t free_at_start = MiGetFreePageCount();
    {
        MI_ADDRESS_SPACE space;
        ok(MiCreateAddressSpace(&space) == STATUS_SUCCESS, "create address space");

        PVOID base = 0;
        SIZE_T size = 0x2000;
        NTSTATUS status = MiAllocateVirtualMemory(&space, &base, &size, MEM_RESERVE | MEM_COMMIT,
                                                  PAGE_READWRITE | PAGE_GUARD);
        ok(status == STATUS_SUCCESS, "commit guarded -> %08lx", (unsigned long)status);
        uint64_t va = (uint64_t)(uintptr_t)base;

        /* Committed (the frame exists) but not present (the touch traps). */
        int present = 1;
        uint64_t frame = MiTranslateUserPage(space.pml4Physical, va, 0, &present);
        ok(frame != 0 && !present, "guard page frame %lx present %d", (unsigned long)frame,
           present);

        MEMORY_BASIC_INFORMATION mbi;
        ok(MiQueryVirtualMemoryBasic(&space, base, &mbi) == STATUS_SUCCESS, "query guarded");
        ok(mbi.State == MEM_COMMIT, "guarded State %lx", (unsigned long)mbi.State);
        ok(mbi.Protect == (PAGE_READWRITE | PAGE_GUARD), "guarded Protect %lx",
           (unsigned long)mbi.Protect);

        /* One-shot: the clear makes an ordinary writable page. */
        ok(MiClearGuardPage(&space, va), "clear guard");
        int writable = 0;
        frame = MiTranslateUserPage(space.pml4Physical, va, &writable, &present);
        ok(frame != 0 && present && writable, "cleared page not present+writable");
        ok(!MiClearGuardPage(&space, va), "guard cleared twice");
        ok(MiQueryVirtualMemoryBasic(&space, base, &mbi) == STATUS_SUCCESS, "query cleared");
        ok(mbi.Protect == PAGE_READWRITE, "cleared Protect %lx", (unsigned long)mbi.Protect);

        /* The second page keeps its own guard until touched. */
        ok(MiQueryVirtualMemoryBasic(&space, (char *)base + PAGE_SIZE, &mbi) == STATUS_SUCCESS,
           "query second page");
        ok(mbi.Protect == (PAGE_READWRITE | PAGE_GUARD), "second page Protect %lx",
           (unsigned long)mbi.Protect);

        MiDeleteAddressSpace(&space);
    }
    ok(MiGetFreePageCount() == free_at_start, "guard pages leaked frames (%lu vs %lu)",
       (unsigned long)MiGetFreePageCount(), (unsigned long)free_at_start);
}

int kmt_run_m5(void)
{
    int before = kmt_failures;
    KMT_RUN(test_anonymous_section_engine);
    KMT_RUN(test_file_section_consistency);
    KMT_RUN(test_image_section);
    KMT_RUN(test_image_relocation);
    KMT_RUN(test_page_table_charge);
    KMT_RUN(test_guard_bookkeeping);
    return kmt_failures - before;
}
