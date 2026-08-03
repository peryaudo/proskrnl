/* tests/kmt/cui9_cow.c — the CUI-9 shared-image-master machine verdicts
 * (docs/17 §8: "a non-sharing implementation passes every semantic test",
 * so the sharing itself is convicted here, in kernel mode, as counters and
 * frame arithmetic — never inferred from boundary behaviour).
 *
 * What this convicts:
 *  - the (identity, base) key: two sections over the SAME ramdisk file bind
 *    one master (builds+1 then hits+1), a different base builds another;
 *  - the sharing metric: the second view's frame cost is bounded by its
 *    writable pages (+ page-table overhead), nowhere near the whole image;
 *  - refcount transitions: the master survives its first view's death,
 *    dies with its last, and every frame — master and private — returns to
 *    the allocator (the free-page count round-trips exactly);
 *  - the docs/17 §8 sweep: no writable PTE at a master frame, shared PTEs
 *    exactly at their master frame.
 */
#include "tests/kmt/kmt.h"

#include "kernel/mm/section.h"
#include "kernel/mm/virtual.h"
#include "kernel/mm/phys.h"
#include "kernel/init/initrd.h"
#include "kernel/ob/ob.h"
#include "arch/x86_64/mmu.h"

#include "abi/ntstatus.h"

static ULONG writable_image_pages(const MI_IMAGE_INFO *image)
{
    ULONG pages = 0;
    for (ULONG i = 0; i < image->segmentCount; i++)
    {
        const MI_IMAGE_SEGMENT *seg = &image->segments[i];
        if (seg->protect == PAGE_WRITECOPY || seg->protect == PAGE_EXECUTE_WRITECOPY ||
            seg->protect == PAGE_READWRITE || seg->protect == PAGE_EXECUTE_READWRITE)
        {
            pages += (seg->virtualSize + PAGE_SIZE - 1) / PAGE_SIZE;
        }
    }
    return pages;
}

static void test_shared_master(void)
{
    PKI_RAMDISK_FILE file = KiFindRamdiskFile("pe_smoke.exe");
    if (file == 0)
    {
        DbgPrint("  (pe_smoke.exe not in the RAM-disk; skipping)\n");
        return;
    }

    ULONG builds0, hits0, live0;
    uint64_t mframes0;
    MiGetImageMasterStats(&builds0, &hits0, &live0, &mframes0);
    uint64_t free0 = MiGetFreePageCount();

    MI_ADDRESS_SPACE space1, space2;
    ok(MiCreateAddressSpace(&space1) == STATUS_SUCCESS, "create space1");
    ok(MiCreateAddressSpace(&space2) == STATUS_SUCCESS, "create space2");

    PMI_SECTION section1 = 0, section2 = 0;
    ok(MiCreateSection(0, PAGE_EXECUTE, SEC_IMAGE, file, &section1) == STATUS_SUCCESS,
       "create section1");
    ok(MiCreateSection(0, PAGE_EXECUTE, SEC_IMAGE, file, &section2) == STATUS_SUCCESS,
       "create section2");
    if (section1 == 0 || section2 == 0)
    {
        return;
    }
    const MI_IMAGE_INFO *image = section1->image;
    ULONG imagePages = (ULONG)(image->sizeOfImage / PAGE_SIZE);
    ULONG writablePages = writable_image_pages(image);
    ok(writablePages < imagePages, "image has no shareable pages");

    /* --- first view: resolves the (file, preferredBase) master. A master
     * for this key may ALREADY be alive (a boot-module process's view), so
     * every assertion below is a DELTA against the map before it — exactly
     * one resolution per map, and the second map of the same key must be a
     * hit whatever the first was. ------------------------------------------- */
    uint64_t base1 = 0, size1 = 0;
    NTSTATUS status = MiMapViewOfSection(section1, &space1, &base1, 0, &size1, PAGE_EXECUTE);
    ok(status == STATUS_SUCCESS, "map view1 -> %08lx", (unsigned long)status);
    ok(base1 == image->preferredBase, "view1 not at the preferred base");

    ULONG builds1, hits1, live1, builds, hits, live;
    uint64_t mframes1, mframes;
    MiGetImageMasterStats(&builds1, &hits1, &live1, &mframes1);
    ok(builds1 + hits1 == builds0 + hits0 + 1, "first map resolved %lu times",
       (unsigned long)(builds1 + hits1 - builds0 - hits0));

    uint64_t free_after_first = MiGetFreePageCount();

    /* --- second view, SECOND section, other space: binds the same master ---- */
    uint64_t base2 = 0, size2 = 0;
    status = MiMapViewOfSection(section2, &space2, &base2, 0, &size2, PAGE_EXECUTE);
    ok(status == STATUS_SUCCESS, "map view2 -> %08lx", (unsigned long)status);
    ok(base2 == base1, "view2 not at the preferred base");

    MiGetImageMasterStats(&builds, &hits, &live, &mframes);
    ok(builds == builds1, "second map built a master (no sharing)");
    ok(hits == hits1 + 1, "second map did not hit the master");
    ok(live == live1, "second map changed the live count");

    /* The sharing metric: the second view pays only its writable pages plus
     * page-table overhead — a whole-image cost means sharing is inert
     * (docs/17 §8's "correct-but-inert" failure mode). */
    uint64_t secondCost = free_after_first - MiGetFreePageCount();
    ok(secondCost <= (uint64_t)writablePages + 8,
       "second view cost %lu pages (writable %lu, image %lu)", (unsigned long)secondCost,
       (unsigned long)writablePages, (unsigned long)imagePages);

    /* Shared pages map the SAME frame; writable pages map different ones. */
    {
        uint64_t sharedFrame1 = MiTranslateUserPage(space1.pml4Physical, base1, 0, 0);
        uint64_t sharedFrame2 = MiTranslateUserPage(space2.pml4Physical, base2, 0, 0);
        ok(sharedFrame1 != 0 && sharedFrame1 == sharedFrame2, "headers not shared (%lx vs %lx)",
           (unsigned long)sharedFrame1, (unsigned long)sharedFrame2);
        for (ULONG i = 0; i < image->segmentCount; i++)
        {
            const MI_IMAGE_SEGMENT *seg = &image->segments[i];
            uint64_t va1 = base1 + seg->virtualAddress;
            uint64_t va2 = base2 + seg->virtualAddress;
            uint64_t f1 = MiTranslateUserPage(space1.pml4Physical, va1, 0, 0);
            uint64_t f2 = MiTranslateUserPage(space2.pml4Physical, va2, 0, 0);
            BOOLEAN writable =
                seg->protect == PAGE_WRITECOPY || seg->protect == PAGE_EXECUTE_WRITECOPY ||
                seg->protect == PAGE_READWRITE || seg->protect == PAGE_EXECUTE_READWRITE;
            if (writable)
            {
                ok(f1 != f2, "segment %lu writable page shared", (unsigned long)i);
            }
            else
            {
                ok(f1 == f2, "segment %lu read-only page not shared", (unsigned long)i);
            }
        }
    }

    /* --- the docs/17 §8 sweep on both spaces --------------------------------- */
    MiAssertNoWritableMasterPte(&space1);
    MiAssertNoWritableMasterPte(&space2);

    /* --- refcount transitions: a bound view keeps the master alive; once
     * OUR views are gone the counters return exactly to the baseline (a
     * pre-existing holder keeps its master — that too is the baseline), and
     * EVERY frame comes home ------------------------------------------------- */
    ok(MiUnmapView(&space1, base1) == STATUS_SUCCESS, "unmap view1");
    MiGetImageMasterStats(&builds, &hits, &live, &mframes);
    ok(live == live1, "master died with a view still bound");

    ok(MiUnmapView(&space2, base2) == STATUS_SUCCESS, "unmap view2");
    MiGetImageMasterStats(&builds, &hits, &live, &mframes);
    ok(live == live0, "master count did not return to baseline");
    ok(mframes == mframes0, "master frames leaked (%lu vs %lu)", (unsigned long)mframes,
       (unsigned long)mframes0);

    ObDereferenceObject(section1);
    ObDereferenceObject(section2);
    MiDeleteAddressSpace(&space1);
    MiDeleteAddressSpace(&space2);
    ok(MiGetFreePageCount() == free0, "frames leaked: %lu -> %lu", (unsigned long)free0,
       (unsigned long)MiGetFreePageCount());

    MiGetImageMasterStats(&builds, &hits, &live, &mframes);
    DbgPrint("[KTEST] cui9 masters builds=%lu hits=%lu live=%lu frames=%lu\n",
             (unsigned long)builds, (unsigned long)hits, (unsigned long)live,
             (unsigned long)mframes);
}

/* A view mapped at a DIFFERENT base builds a second, separately relocated
 * master — the base is in the key because its fixups differ (docs/17 §6F:
 * omitting it is "the worst bug available in this design"). */
static void test_master_base_key(void)
{
    PKI_RAMDISK_FILE file = KiFindRamdiskFile("pe_smoke.exe");
    if (file == 0)
    {
        return;
    }

    ULONG builds0, hits0, live0;
    uint64_t mframes0;
    MiGetImageMasterStats(&builds0, &hits0, &live0, &mframes0);
    uint64_t free0 = MiGetFreePageCount();

    MI_ADDRESS_SPACE space;
    ok(MiCreateAddressSpace(&space) == STATUS_SUCCESS, "create space");
    PMI_SECTION section = 0;
    ok(MiCreateSection(0, PAGE_EXECUTE, SEC_IMAGE, file, &section) == STATUS_SUCCESS,
       "create section");
    if (section == 0)
    {
        return;
    }
    const MI_IMAGE_INFO *image = section->image;

    /* Two views in ONE space: the second cannot land at the preferred base,
     * so it relocates — and must NOT share the at-base master's frames. */
    uint64_t base1 = 0, size1 = 0;
    NTSTATUS status = MiMapViewOfSection(section, &space, &base1, 0, &size1, PAGE_EXECUTE);
    ok(status == STATUS_SUCCESS, "map at base -> %08lx", (unsigned long)status);
    uint64_t base2 = 0, size2 = 0;
    status = MiMapViewOfSection(section, &space, &base2, 0, &size2, PAGE_EXECUTE);
    ok(status == STATUS_IMAGE_NOT_AT_BASE, "relocated map -> %08lx", (unsigned long)status);
    ok(base2 != base1, "second view at the same base");

    ULONG builds, hits, live;
    uint64_t mframes;
    MiGetImageMasterStats(&builds, &hits, &live, &mframes);
    ok(builds + hits == builds0 + hits0 + 2, "two maps resolved %lu times",
       (unsigned long)(builds + hits - builds0 - hits0));

    /* The base-key conviction itself: the two views' frames must DIFFER —
     * a base2 view reading base1's fixups is docs/17 §6F's silent
     * non-local corruption. (Whether the base2 master was built here or
     * pre-existed from an earlier holder is immaterial; the key is.) */
    {
        uint64_t f1 = MiTranslateUserPage(space.pml4Physical, base1, 0, 0);
        uint64_t f2 = MiTranslateUserPage(space.pml4Physical, base2, 0, 0);
        ok(f1 != 0 && f2 != 0 && f1 != f2, "views at different bases share a header frame");
    }

    /* The relocated master's header claims the ACTUAL base (the ImageBase
     * stamp — ntdll's loader keys perform_relocations off it). */
    if (base2 != 0)
    {
        uint64_t va =
            base2 + image->ntHeaderOffset + offsetof(IMAGE_NT_HEADERS64, OptionalHeader.ImageBase);
        uint64_t stamped = 0;
        for (int i = 0; i < 8; i++)
        {
            uint64_t frame =
                MiTranslateUserPage(space.pml4Physical, (va + i) & ~(PAGE_SIZE - 1ULL), 0, 0);
            ok(frame != 0, "header page not mapped");
            stamped |=
                (uint64_t)((unsigned char *)MiPhysicalToVirtual(frame))[(va + i) & (PAGE_SIZE - 1)]
                << (i * 8);
        }
        ok(stamped == base2, "ImageBase stamp %lx, expected %lx", (unsigned long)stamped,
           (unsigned long)base2);
    }

    MiAssertNoWritableMasterPte(&space);

    ObDereferenceObject(section);
    MiDeleteAddressSpace(&space);
    MiGetImageMasterStats(&builds, &hits, &live, &mframes);
    ok(live == live0 && mframes == mframes0, "masters leaked");
    ok(MiGetFreePageCount() == free0, "frames leaked");
}

int kmt_run_cui9(void)
{
    int before = kmt_failures;
    KMT_RUN(test_shared_master);
    KMT_RUN(test_master_base_key);
    return kmt_failures - before;
}
