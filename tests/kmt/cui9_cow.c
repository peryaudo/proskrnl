/* tests/kmt/cui9_cow.c — the CUI-9 shared-image-master machine verdicts
 * (docs/17 §8: "a non-sharing implementation passes every semantic test",
 * so the sharing itself is convicted here, in kernel mode, as counters and
 * frame arithmetic — never inferred from boundary behaviour).
 *
 * What this convicts:
 *  - the identity key: two sections over the SAME ramdisk file bind one
 *    master (builds+1 then hits+1), and so does a view at a DIFFERENT base —
 *    an image is relocated once and every view shares that copy;
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
        if (section1 != 0)
        {
            ObDereferenceObject(section1);
        }
        if (section2 != 0)
        {
            ObDereferenceObject(section2);
        }
        MiDeleteAddressSpace(&space1);
        MiDeleteAddressSpace(&space2);
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

    /* The sharing metric: with the COW arm every page — writable included —
     * shares until written, so the second view pays only page-table
     * overhead. A whole-image cost means sharing is inert (docs/17 §8's
     * "correct-but-inert" failure mode); writablePages is printed for the
     * post-mortem's sense of scale. The bound SCALES with the image (one PT
     * page per 512 mapped pages + a fixed directory/pool allowance) so a
     * grown fixture tightens nothing and loosens nothing — a fixed "8" was
     * pe_smoke geometry in disguise. */
    uint64_t secondCost = free_after_first - MiGetFreePageCount();
    ok(secondCost <= imagePages / 512 + 8, "second view cost %lu pages (writable %lu, image %lu)",
       (unsigned long)secondCost, (unsigned long)writablePages, (unsigned long)imagePages);

    /* EVERY committed page of both views maps the same master frame; the
     * writable ones are hardware-read-only until the COW arm opens them. */
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
            int w1 = 0, w2 = 0;
            uint64_t f1 = MiTranslateUserPage(space1.pml4Physical, va1, &w1, 0);
            uint64_t f2 = MiTranslateUserPage(space2.pml4Physical, va2, &w2, 0);
            ok(f1 == f2, "segment %lu page not shared", (unsigned long)i);
            ok(!w1 && !w2, "segment %lu shared page hardware-writable", (unsigned long)i);
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

/* A view mapped at a DIFFERENT base SHARES the section's one relocated copy:
 * an image is relocated once, and the residual for a view that does not sit
 * at that copy's base belongs to the PE loader, which keys off the ImageBase
 * the copy stamps into its header. This is the reverse of docs/17 §6F's
 * original rule ("include the base in the key"), and the oracle is what
 * settled it — sem_mm/map_image_offset.c memcmps two views of one section on
 * the pinned Wine and they are identical (docs/03 "An image section is
 * relocated once"). The corruption §6F named is real and now sits one step
 * over: a copy whose stamped ImageBase disagrees with the base it was
 * relocated for, which is what the stamp assertion below convicts. */
static void test_master_identity_key(void)
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
        MiDeleteAddressSpace(&space);
        return;
    }
    const MI_IMAGE_INFO *image = section->image;

    /* Two views in ONE space: the second cannot land at the preferred base,
     * so it is not at base — and must share the first's frames anyway. */
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
    ok(live == live0 + 1 || live == live0, "a second copy of one image (%lu -> %lu)",
       (unsigned long)live0, (unsigned long)live);

    /* The identity-key conviction: the two views' frames are the SAME, so
     * the second view costs nothing but page tables and the memcmp the
     * oracle pins holds. */
    {
        uint64_t f1 = MiTranslateUserPage(space.pml4Physical, base1, 0, 0);
        uint64_t f2 = MiTranslateUserPage(space.pml4Physical, base2, 0, 0);
        ok(f1 != 0 && f2 != 0 && f1 == f2, "views at different bases do not share a header frame");
    }

    /* The copy's header claims the base it was relocated FOR — base1 here,
     * because the first view is what fixed it. ntdll's loader keys
     * perform_relocations off this field, so it is what fixes up the second
     * view's residual; a stamp naming anything else is §6F's corruption in
     * its remaining form — though NOT here, where base1 is the preferred base
     * and the delta is zero, so the file already holds this value;
     * tests/kmt/m5_section.c test_image_relocation is where the stamp is
     * convicted. Read through view TWO, which shares the frame. */
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
        ok(stamped == base1, "ImageBase stamp %lx, expected the copy's base %lx",
           (unsigned long)stamped, (unsigned long)base1);
    }

    MiAssertNoWritableMasterPte(&space);

    ObDereferenceObject(section);
    MiDeleteAddressSpace(&space);
    MiGetImageMasterStats(&builds, &hits, &live, &mframes);
    ok(live == live0 && mframes == mframes0, "masters leaked");
    ok(MiGetFreePageCount() == free0, "frames leaked");
}

/* The COW arm itself (docs/17 §10 step 5), driven through the ONE
 * authority the ring-3 fault, the checked copy and the probe all consult:
 * a writable image page starts hardware-read-only on the shared master
 * frame; MiResolveWriteFault copies, repoints and opens; a read-only page
 * is declined (hazard B); the injected out-of-frames failure resolves to
 * STATUS_IN_PAGE_ERROR with ZERO state touched (hazard E); NX survives
 * the copy (hazard C); the invlpg count moves (hazard H). */
static void test_cow_arm(void)
{
    PKI_RAMDISK_FILE file = KiFindRamdiskFile("pe_smoke.exe");
    if (file == 0)
    {
        return;
    }

    uint64_t free0 = MiGetFreePageCount();
    MI_ADDRESS_SPACE space;
    ok(MiCreateAddressSpace(&space) == STATUS_SUCCESS, "create space");
    PMI_SECTION section = 0;
    ok(MiCreateSection(0, PAGE_EXECUTE, SEC_IMAGE, file, &section) == STATUS_SUCCESS,
       "create section");
    if (section == 0)
    {
        MiDeleteAddressSpace(&space);
        return;
    }
    const MI_IMAGE_INFO *image = section->image;
    uint64_t base = 0, size = 0;
    NTSTATUS status = MiMapViewOfSection(section, &space, &base, 0, &size, PAGE_EXECUTE);
    ok(status == STATUS_SUCCESS, "map -> %08lx", (unsigned long)status);

    /* Find one writable and one read-only page. */
    uint64_t writableVa = 0, readonlyVa = 0;
    for (ULONG i = 0; i < image->segmentCount; i++)
    {
        const MI_IMAGE_SEGMENT *seg = &image->segments[i];
        BOOLEAN w = seg->protect == PAGE_WRITECOPY || seg->protect == PAGE_EXECUTE_WRITECOPY ||
                    seg->protect == PAGE_READWRITE || seg->protect == PAGE_EXECUTE_READWRITE;
        if (w && writableVa == 0)
        {
            writableVa = base + seg->virtualAddress;
        }
        if (!w && readonlyVa == 0 && seg->protect != 0)
        {
            readonlyVa = base + seg->virtualAddress;
        }
    }
    ok(writableVa != 0 && readonlyVa != 0, "test PE lacks a writable/read-only pair");
    if (writableVa == 0 || readonlyVa == 0)
    {
        MiUnmapView(&space, base);
        ObDereferenceObject(section);
        MiDeleteAddressSpace(&space);
        return;
    }

    /* Step 5's map shape: the writable page is hardware-READ-ONLY on the
     * shared master frame until written. */
    int writable = 0, present = 0;
    uint64_t before = MiTranslateUserPage(space.pml4Physical, writableVa, &writable, &present);
    ok(before != 0 && present && !writable, "writable page not read-only-shared (w=%d)", writable);
    unsigned char masterByte = *(unsigned char *)MiPhysicalToVirtual(before);

    /* Declines: a genuinely read-only page (hazard B), and an unmapped one. */
    NTSTATUS resolved;
    ok(!MiResolveWriteFault(&space, readonlyVa, &resolved), "resolver claimed a read-only page");
    ok(!MiResolveWriteFault(&space, base + image->sizeOfImage, &resolved),
       "resolver claimed an unmapped page");

    /* Hazard E first, on the SAME page the real copy will use: the injected
     * allocation failure is claimed, answers STATUS_IN_PAGE_ERROR, and
     * leaves no trace — still the master frame, still read-only. */
    MiCowFailNextAllocation = TRUE;
    BOOLEAN claimed = MiResolveWriteFault(&space, writableVa, &resolved);
    ok(claimed && resolved == STATUS_IN_PAGE_ERROR, "injected OOM -> claimed=%d status=%08lx",
       (int)claimed, (unsigned long)resolved);
    ok(MiCowFailNextAllocation == FALSE, "knob did not self-clear");
    uint64_t after = MiTranslateUserPage(space.pml4Physical, writableVa, &writable, &present);
    ok(after == before && !writable, "failed copy left state behind (frame %lx->%lx w=%d)",
       (unsigned long)before, (unsigned long)after, writable);
    MiAssertNoWritableMasterPte(&space);

    /* The copy: claimed, SUCCESS, private frame, gate open, master intact,
     * recorded protection untouched (the pinned no-transition shape), and
     * the TLB flushed — the invlpg count moves (hazard H: a green boot
     * under QEMU is NOT evidence the flush exists; this counter is). */
    ULONG copies0 = MiGetCowCopyCount();
    uint64_t invlpg0 = MiInvlpgCount;
    ok(MiResolveWriteFault(&space, writableVa, &resolved) && resolved == STATUS_SUCCESS,
       "resolve -> %08lx", (unsigned long)resolved);
    ok(MiGetCowCopyCount() == copies0 + 1, "copy counter did not move");
    ok(MiInvlpgCount >= invlpg0 + 2, "invlpg count moved %lu (unmap+map is 2)",
       (unsigned long)(MiInvlpgCount - invlpg0));
    after = MiTranslateUserPage(space.pml4Physical, writableVa, &writable, &present);
    ok(after != 0 && after != before && writable && present,
       "copy did not repoint/open (frame %lx->%lx w=%d)", (unsigned long)before,
       (unsigned long)after, writable);
    ok(*(unsigned char *)MiPhysicalToVirtual(after) == masterByte, "copy differs from master");

    /* Corrupt-the-copy check: write the private frame, the master byte must
     * not move (the write-watch tests' kernel-write shape, hazard A). */
    *(unsigned char *)MiPhysicalToVirtual(after) ^= 0xFF;
    ok(*(unsigned char *)MiPhysicalToVirtual(before) == masterByte, "the MASTER took the write");

    /* A second resolve on the now-private page declines (already open). */
    ok(!MiResolveWriteFault(&space, writableVa, &resolved), "resolver reclaimed a private page");
    MiAssertNoWritableMasterPte(&space);

    ok(MiUnmapView(&space, base) == STATUS_SUCCESS, "unmap");
    ObDereferenceObject(section);
    MiDeleteAddressSpace(&space);
    ok(MiGetFreePageCount() == free0, "frames leaked");

    DbgPrint("[KTEST] cui9 cow copies=%lu invlpg=%lu\n", (unsigned long)MiGetCowCopyCount(),
             (unsigned long)MiInvlpgCount);
}

/* The guard-clear PTE-writing site goes through the ONE hardware-writability
 * rule like every other map site: clearing PAGE_GUARD on a still-shared
 * writecopy page must NOT hand out a writable PTE onto the master frame
 * (ring 3 reaches this with NtProtectVirtualMemory(WRITECOPY|GUARD) + a
 * touch — the docs/17 §6B cross-process corruption if the raw bit wins),
 * and clearing it on a clean watched page must not open the gate without a
 * dirty mark (a page silently lost from NtGetWriteWatch). In both shapes
 * the retried store then resolves through MiResolveWriteFault — hazard G's
 * ordering, now convicted rather than asserted in a comment. */
static void test_guard_clear_authority(void)
{
    PKI_RAMDISK_FILE file = KiFindRamdiskFile("pe_smoke.exe");
    if (file == 0)
    {
        return;
    }

    uint64_t free0 = MiGetFreePageCount();
    MI_ADDRESS_SPACE space;
    ok(MiCreateAddressSpace(&space) == STATUS_SUCCESS, "create space");
    PMI_SECTION section = 0;
    ok(MiCreateSection(0, PAGE_EXECUTE, SEC_IMAGE, file, &section) == STATUS_SUCCESS,
       "create section");
    if (section == 0)
    {
        MiDeleteAddressSpace(&space);
        return;
    }
    const MI_IMAGE_INFO *image = section->image;
    uint64_t base = 0, size = 0;
    NTSTATUS status = MiMapViewOfSection(section, &space, &base, 0, &size, PAGE_EXECUTE);
    ok(status == STATUS_SUCCESS, "map -> %08lx", (unsigned long)status);

    uint64_t writableVa = 0;
    for (ULONG i = 0; i < image->segmentCount && writableVa == 0; i++)
    {
        const MI_IMAGE_SEGMENT *seg = &image->segments[i];
        if (seg->protect == PAGE_WRITECOPY || seg->protect == PAGE_EXECUTE_WRITECOPY ||
            seg->protect == PAGE_READWRITE || seg->protect == PAGE_EXECUTE_READWRITE)
        {
            writableVa = base + seg->virtualAddress;
        }
    }
    ok(writableVa != 0, "test PE lacks a writable segment");
    if (writableVa == 0)
    {
        MiUnmapView(&space, base);
        ObDereferenceObject(section);
        MiDeleteAddressSpace(&space);
        return;
    }
    uint64_t masterFrame = MiTranslateUserPage(space.pml4Physical, writableVa, 0, 0);

    /* Ring 3's sequence: guard the still-shared writecopy page... */
    uint64_t protBase = writableVa;
    uint64_t protSize = PAGE_SIZE;
    ULONG oldProtect = 0;
    status = MiProtectVirtualMemory(&space, &protBase, &protSize, PAGE_WRITECOPY | PAGE_GUARD,
                                    &oldProtect);
    ok(status == STATUS_SUCCESS, "guard the writecopy page -> %08lx", (unsigned long)status);
    int writable = 0, present = 0;
    MiTranslateUserPage(space.pml4Physical, writableVa, &writable, &present);
    ok(!present, "guarded page still present");

    /* ...consume the guard: the page comes back PRESENT but READ-ONLY on
     * the SAME master frame — the shared-master gate outranks the raw
     * protection bit at this site too. */
    ok(MiClearGuardPage(&space, writableVa), "guard did not clear");
    uint64_t after = MiTranslateUserPage(space.pml4Physical, writableVa, &writable, &present);
    ok(after == masterFrame && present && !writable,
       "guard clear leaked a writable master PTE (frame %lx->%lx w=%d p=%d)",
       (unsigned long)masterFrame, (unsigned long)after, writable, present);
    MiAssertNoWritableMasterPte(&space);

    /* The retried store resolves through the COW arm: copy, repoint, open. */
    NTSTATUS resolved;
    ok(MiResolveWriteFault(&space, writableVa, &resolved) && resolved == STATUS_SUCCESS,
       "post-guard store did not copy -> %08lx", (unsigned long)resolved);
    after = MiTranslateUserPage(space.pml4Physical, writableVa, &writable, &present);
    ok(after != 0 && after != masterFrame && writable, "copy did not repoint/open");
    MiAssertNoWritableMasterPte(&space);

    ok(MiUnmapView(&space, base) == STATUS_SUCCESS, "unmap");
    ObDereferenceObject(section);

    /* The watch shape: a guarded CLEAN watched page clears to read-only —
     * the mark stays the write's job, taken by the resolver on the retry. */
    PVOID watchBase = 0;
    SIZE_T watchSize = PAGE_SIZE;
    status = MiAllocateVirtualMemory(&space, &watchBase, &watchSize,
                                     MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "watch alloc -> %08lx", (unsigned long)status);
    uint64_t watchVa = (uint64_t)(uintptr_t)watchBase;
    protBase = watchVa;
    protSize = PAGE_SIZE;
    status = MiProtectVirtualMemory(&space, &protBase, &protSize, PAGE_READWRITE | PAGE_GUARD,
                                    &oldProtect);
    ok(status == STATUS_SUCCESS, "guard the watched page -> %08lx", (unsigned long)status);
    ok(MiClearGuardPage(&space, watchVa), "watch guard did not clear");
    MiTranslateUserPage(space.pml4Physical, watchVa, &writable, &present);
    ok(present && !writable, "guard clear opened a clean watched page (w=%d)", writable);
    ok(MiResolveWriteFault(&space, watchVa, &resolved) && resolved == STATUS_SUCCESS,
       "watch retry did not mark -> %08lx", (unsigned long)resolved);
    MiTranslateUserPage(space.pml4Physical, watchVa, &writable, &present);
    ok(writable, "marked watched page still closed");

    MiDeleteAddressSpace(&space);
    ok(MiGetFreePageCount() == free0, "frames leaked");
}

int kmt_run_cui9(void)
{
    int before = kmt_failures;
    KMT_RUN(test_shared_master);
    KMT_RUN(test_master_identity_key);
    KMT_RUN(test_cow_arm);
    KMT_RUN(test_guard_clear_authority);
    /* The hazard-E knob must not outlive the suite: left armed (a case that
     * set it but never reached the COW arm), the next REAL resolve would
     * answer STATUS_IN_PAGE_ERROR (the review's sticky-global hazard). */
    MiCowFailNextAllocation = FALSE;
    return kmt_failures - before;
}
