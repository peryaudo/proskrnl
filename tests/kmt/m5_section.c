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
        ok(file->pageCache != 0, "no page cache after file section creation");
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
            /* NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling) */
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

        /* Per-PE-section protection: text executable and read-only, data
         * writable; the copied bytes match the file's raw data. */
        for (ULONG i = 0; i < image->segmentCount; i++)
        {
            const MI_IMAGE_SEGMENT *seg = &image->segments[i];
            int writable = 0, present = 0;
            uint64_t frame = MiTranslateUserPage(space.pml4Physical, base1 + seg->virtualAddress,
                                                 &writable, &present);
            ok(frame != 0 && present, "segment %lu not mapped", (unsigned long)i);
            int wants_write =
                seg->protect == PAGE_WRITECOPY || seg->protect == PAGE_EXECUTE_WRITECOPY ||
                seg->protect == PAGE_READWRITE || seg->protect == PAGE_EXECUTE_READWRITE;
            ok(writable == wants_write, "segment %lu writability %d, protect %lx", (unsigned long)i,
               writable, (unsigned long)seg->protect);
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

            /* The relocation copy really ran: a DIR64 fixup site differs
             * between the two views by exactly the load delta. */
            uint64_t reloc_rva = first_dir64_reloc(file, image);
            ok(reloc_rva != ~0ULL, "PE has no DIR64 relocation to verify");
            if (reloc_rva != ~0ULL)
            {
                uint64_t at_base = mapped_qword(&space, base1 + reloc_rva);
                uint64_t relocated = mapped_qword(&space, base2 + reloc_rva);
                ok(relocated == at_base + (base2 - base1),
                   "reloc site: %lx at base, %lx relocated, delta %lx", (unsigned long)at_base,
                   (unsigned long)relocated, (unsigned long)(base2 - base1));
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
    KMT_RUN(test_guard_bookkeeping);
    return kmt_failures - before;
}
