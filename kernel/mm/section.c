/* kernel/mm/section.c — section objects + their Nt* surface (M5). See
 * section.h for the Art. 3 shape.
 *
 * The boundary semantics — creation parameter conventions, mapping
 * alignment/conflict statuses, view sharing, unmap-vs-free, NtQuerySection —
 * are pinned by tests/ntapi/sem_mm/anonymous_section.c and image_section.c,
 * green on the pinned Wine oracle; where this file makes a choice it is the
 * one Wine's implementation makes (server/mapping.c and
 * dlls/ntdll/unix/virtual.c are the reference for behaviour, not code).
 */
#include "kernel/mm/section.h"
#include "kernel/mm/pagecache.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/pool.h"
#include "kernel/ps/ps.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "arch/x86_64/mmu.h"

#include "abi/ntstatus.h"

/* kernel/io/file.c: the Mm<->Io seam for file-backed sections (M6). NT has
 * the same layering: Mm calls into Io for the file side of a section.
 * IopBuildSectionBacking resolves a file HANDLE into an MI_SECTION_BACKING
 * (cache loaded, raw bytes snapshotted for SEC_IMAGE, File referenced,
 * mapping-count raised); IopSectionBackingReleased drops the mapping count
 * when a section (or a failed create) lets go. */
NTSTATUS IopBuildSectionBacking(HANDLE fileHandle, ULONG sectionAttributes, ULONG pageProtection,
                                const LARGE_INTEGER *maximumSize, MI_SECTION_BACKING *backing);
void IopSectionBackingReleased(PVOID fileObjectBody, ULONG sectionAttributes, ULONG pageProtection);

static void MipDeleteSection(PVOID body)
{
    PMI_SECTION section = body;
    /* Every view holds a reference on its section, so nothing can be mapped
     * here (the G11 ownership audit for the SEC_RESERVE view list). */
    ASSERT(IsListEmpty(&section->viewListHead));
    if (section->frames != 0)
    {
        for (ULONG i = 0; i < section->pageCount; i++)
        {
            if (section->frames[i] != 0)
            {
                MiFreePage(section->frames[i]);
            }
        }
        MiFreePool(section->frames);
    }
    if (section->rawData != 0 && section->ownsRawData)
    {
        MiFreePool((void *)(uintptr_t)section->rawData);
    }
    if (section->image != 0)
    {
        MiFreePool(section->image);
    }
    if (section->fileObject != 0)
    {
        IopSectionBackingReleased(section->fileObject, section->attributes,
                                  section->pageProtection);
        ObDereferenceObject(section->fileObject);
    }
}

OBJECT_TYPE MiSectionType = {
    .name = "Section",
    .validAccess = SECTION_ALL_ACCESS,
    .waitable = FALSE,
    .deleteProcedure = MipDeleteSection,
};

/* --- creation --------------------------------------------------------------- */

/* Build a section's contents into `scratch` (nothing Ob-visible yet, so
 * every failure unwinds cleanly — including a backing whose rawData we were
 * handed ownership of). Validation order and statuses follow Wine's
 * server/mapping.c get_mapping_flags + create_mapping. */
static NTSTATUS MipBuildSection(MI_SECTION *scratch, const LARGE_INTEGER *maximumSize,
                                ULONG pageProtection, ULONG attributes,
                                const MI_SECTION_BACKING *backing)
{
    memset(scratch, 0, sizeof(*scratch));
    InitializeListHead(&scratch->viewListHead);
    scratch->pageProtection = pageProtection;
    /* An anonymous section has no backing file to constrain it. */
    scratch->backingWritable = backing == 0 || backing->fileObject == 0 || backing->writable;

    /* The one statement of "does this section take the FILE arm", because
     * SEC_RESERVE's whole meaning turns on it (below). */
    BOOLEAN fileBacked = backing != 0 && backing->cache != 0;
    BOOLEAN reserve = FALSE;

    switch (attributes & (SEC_IMAGE | SEC_RESERVE | SEC_COMMIT | SEC_FILE))
    {
    case SEC_IMAGE:
        if (backing == 0 || backing->rawData == 0)
        {
            return STATUS_INVALID_FILE_FOR_SECTION;
        }
        scratch->attributes = SEC_FILE | SEC_IMAGE;
        scratch->rawData = backing->rawData;
        scratch->rawSize = backing->rawSize;
        scratch->ownsRawData = backing->ownsRawData;
        scratch->masterIdentity = backing->fcb;
        /* Keep the file's cache reachable so the snapshot can be released
         * after the first master bind and re-read for a later
         * different-base build (image VIEWS never map it — data views do). */
        scratch->cache = backing->cache;
        scratch->image = MiAllocatePool(sizeof(MI_IMAGE_INFO));
        if (scratch->image == 0)
        {
            return STATUS_NO_MEMORY;
        }
        NTSTATUS status = MiParseImage(backing->rawData, backing->rawSize, scratch->image);
        if (!NT_SUCCESS(status))
        {
            MiFreePool(scratch->image);
            scratch->image = 0;
            return status;
        }
        scratch->size = scratch->image->sizeOfImage;
        scratch->pageCount = (ULONG)(scratch->size / PAGE_SIZE);
        return STATUS_SUCCESS;

    case SEC_COMMIT:
        break;

    case SEC_RESERVE:
        /* SEC_RESERVE describes an ANONYMOUS mapping. Handed a file handle
         * the oracle drops the whole flag and answers SEC_FILE
         * (third_party/wine server/mapping.c get_mapping_flags: SEC_COMMIT
         * falls THROUGH into this case, and both return
         * `SEC_FILE | (flags & (SEC_NOCACHE | SEC_WRITECOMBINE))` when a
         * handle is present) — so a file-backed "reserve" section is an
         * ordinary, fully committed data section and only the anonymous one
         * carries a ledger. Pinned both ways by sem_mm/reserve_section.c. */
        reserve = !fileBacked;
        break;

    default:
        return STATUS_INVALID_PARAMETER;
    }

    if (fileBacked)
    {
        /* File-backed data section: views map the file's unified page cache,
         * so a view and a read/write can never disagree (docs/02's
         * consistency test — structural under Art. 3). */
        PMI_PAGE_CACHE cache = backing->cache;
        uint64_t size = cache->fileSize;
        if (maximumSize != 0 && maximumSize->QuadPart != 0)
        {
            if (maximumSize->QuadPart < 0)
            {
                return STATUS_SECTION_TOO_BIG;
            }
            if ((uint64_t)maximumSize->QuadPart > cache->fileSize)
            {
                /* Io already extended the file (or refused) before handing
                 * the cache over -- see IopBuildSectionBacking. Reaching
                 * here means the extension did not take. */
                return STATUS_SECTION_TOO_BIG;
            }
            size = (uint64_t)maximumSize->QuadPart;
        }
        if (size == 0)
        {
            return STATUS_MAPPED_FILE_SIZE_ZERO;
        }
        scratch->attributes = SEC_FILE;
        scratch->size = size;
        scratch->pageCount = (ULONG)((size + PAGE_SIZE - 1) / PAGE_SIZE);
        scratch->cache = cache;
        return STATUS_SUCCESS;
    }

    /* Anonymous (pagefile-backed): SEC_COMMIT means all frames exist, zeroed,
     * from the start (Art. 3: no demand paging) and are shared by every view.
     * SEC_RESERVE means the same array with nothing in it yet — it is the
     * commit LEDGER, filled a range at a time by
     * MiCommitReserveSectionRange (mm/virtual.c). */
    if (maximumSize == 0 || maximumSize->QuadPart <= 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    scratch->attributes = reserve ? SEC_RESERVE : SEC_COMMIT;
    scratch->size = ((uint64_t)maximumSize->QuadPart + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1ULL);
    scratch->pageCount = (ULONG)(scratch->size / PAGE_SIZE);
    scratch->frames = MiAllocatePool((uint64_t)scratch->pageCount * sizeof(uint64_t));
    if (scratch->frames == 0)
    {
        return STATUS_NO_MEMORY;
    }
    if (reserve)
    {
        return STATUS_SUCCESS; /* the pool zeroes: every page uncommitted */
    }
    for (ULONG i = 0; i < scratch->pageCount; i++)
    {
        scratch->frames[i] = MiAllocatePage();
        if (scratch->frames[i] == 0)
        {
            while (i > 0)
            {
                MiFreePage(scratch->frames[--i]);
            }
            MiFreePool(scratch->frames);
            scratch->frames = 0;
            return STATUS_NO_MEMORY;
        }
        memset(MiPhysicalToVirtual(scratch->frames[i]), 0, PAGE_SIZE);
    }
    return STATUS_SUCCESS;
}

/* Move a built section from the caller's stack into its object body. This is
 * a function rather than a memcpy at each site because MI_SECTION carries a
 * LIST_ENTRY, and a list head is SELF-REFERENTIAL: a straight copy leaves the
 * object's head pointing at the scratch that is about to go out of scope. The
 * list is empty either way — nothing can map a section that has no name and
 * no handle yet — so re-seating it is the whole job, and doing it here means
 * a third publish site added later cannot forget. */
static void MipPublishSection(PMI_SECTION body, const MI_SECTION *scratch)
{
    memcpy(body, scratch, sizeof(*body));
    InitializeListHead(&body->viewListHead);
}

NTSTATUS MiCreateBackedSection(const LARGE_INTEGER *maximumSize, ULONG pageProtection,
                               ULONG attributes, const MI_SECTION_BACKING *backing,
                               PMI_SECTION *sectionOut)
{
    MI_SECTION scratch;
    NTSTATUS status = MipBuildSection(&scratch, maximumSize, pageProtection, attributes, backing);
    if (!NT_SUCCESS(status))
    {
        /* rawData ownership passed on call: free it on the paths that did
         * not stash it in scratch (a stashed copy is freed below). */
        if (backing != 0 && backing->ownsRawData && scratch.rawData == 0)
        {
            MiFreePool((void *)(uintptr_t)backing->rawData);
        }
        else if (scratch.rawData != 0)
        {
            MipDeleteSection(&scratch);
        }
        return status;
    }
    PVOID body;
    status = ObpAllocateObject(&MiSectionType, sizeof(MI_SECTION), &body);
    if (!NT_SUCCESS(status))
    {
        MipDeleteSection(&scratch);
        return status;
    }
    if (backing != 0 && backing->fileObject != 0)
    {
        scratch.fileObject = backing->fileObject;
        ObfReferenceObject(scratch.fileObject);
    }
    MipPublishSection(body, &scratch);
    *sectionOut = body;
    return STATUS_SUCCESS;
}

NTSTATUS MiCreateSection(const LARGE_INTEGER *maximumSize, ULONG pageProtection, ULONG attributes,
                         PKI_RAMDISK_FILE file, PMI_SECTION *sectionOut)
{
    MI_SECTION_BACKING backing;
    memset(&backing, 0, sizeof(backing));
    if (file != 0)
    {
        if ((attributes & SEC_IMAGE) == 0)
        {
            /* Data sections map the file's cache; image sections read the
             * raw module bytes directly and need no cache. */
            NTSTATUS status = KiEnsureRamdiskCache(file);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            backing.cache = &file->cache;
        }
        backing.rawData = file->data; /* borrowed: the module outlives everything */
        backing.rawSize = file->size;
        backing.fcb = file; /* the ramdisk file IS the on-disk identity here */
    }
    if (file == 0 && (attributes & SEC_IMAGE) != 0)
    {
        return STATUS_INVALID_FILE_FOR_SECTION;
    }
    return MiCreateBackedSection(maximumSize, pageProtection, attributes, file != 0 ? &backing : 0,
                                 sectionOut);
}

/* --- mapping: the shared image masters (CUI-9) ------------------------------- */

/* The one master list, keyed on the identity by pointer equality. No
 * lock: nothing on the build/lookup/teardown path parks (pool and frame
 * allocation never block), so under the uniprocessor no-preemption mandate
 * every traversal runs to completion (docs/18 inherits these as shootdown
 * sites the day SMP lands — docs/17 §11). */
static LIST_ENTRY MipImageMasterList = {&MipImageMasterList, &MipImageMasterList};
static ULONG MipMasterBuilds;    /* masters ever built */
static ULONG MipMasterHits;      /* views bound to an existing master */
static ULONG MipMasterLive;      /* masters currently alive */
static uint64_t MipMasterFrames; /* frames currently owned by masters */

/* Byte-accurate write into a master's frames — reloc fixups may straddle a
 * page boundary. */
static void MipMasterAddDelta(PMI_IMAGE_MASTER master, uint64_t rva, int width, int64_t delta)
{
    unsigned char raw[8] = {0};
    ASSERT(width == 4 || width == 8);
    for (int i = 0; i < width; i++)
    {
        uint64_t frame = master->frames[(rva + i) / PAGE_SIZE];
        ASSERT(frame != 0);
        raw[i] = ((unsigned char *)MiPhysicalToVirtual(frame))[(rva + i) & (PAGE_SIZE - 1)];
    }
    if (width == 4)
    {
        uint32_t value;
        memcpy(&value, raw, 4);
        value += (uint32_t)delta;
        memcpy(raw, &value, 4);
    }
    else
    {
        uint64_t value;
        memcpy(&value, raw, 8);
        value += (uint64_t)delta;
        memcpy(raw, &value, 8);
    }
    for (int i = 0; i < width; i++)
    {
        uint64_t frame = master->frames[(rva + i) / PAGE_SIZE];
        ((unsigned char *)MiPhysicalToVirtual(frame))[(rva + i) & (PAGE_SIZE - 1)] = raw[i];
    }
}

/* The file offset of an RVA range, or -1 when it has no initialized bytes. */
static int64_t MipRvaToFileOffset(const MI_IMAGE_INFO *image, ULONG rva, ULONG length)
{
    for (ULONG i = 0; i < image->segmentCount; i++)
    {
        const MI_IMAGE_SEGMENT *seg = &image->segments[i];
        if (rva >= seg->virtualAddress && rva + length <= seg->virtualAddress + seg->rawSize)
        {
            return (int64_t)seg->rawOffset + (rva - seg->virtualAddress);
        }
    }
    return -1;
}

/* Apply the .reloc directory to a freshly built master whose base sits
 * `delta` bytes from the preferred base. Blocks are read from the FILE
 * bytes (linear); fixups are applied to the master's frames — ONCE per
 * master, which closes docs/17 §6F's non-idempotence hazard by
 * construction: a view never relocates. Shape as LdrProcessRelocationBlock
 * (Wine's reimplementation is the reference). */
static NTSTATUS MipRelocateImage(PMI_IMAGE_MASTER master, PMI_SECTION section, const void *rawData,
                                 int64_t delta)
{
    const MI_IMAGE_INFO *image = section->image;
    if (image->relocRva == 0 || image->relocSize == 0)
    {
        return STATUS_SUCCESS; /* nothing to fix up */
    }
    int64_t fileOffset = MipRvaToFileOffset(image, image->relocRva, image->relocSize);
    if (fileOffset < 0)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    const char *cursor = (const char *)rawData + fileOffset;
    const char *end = cursor + image->relocSize;

    while (cursor + sizeof(IMAGE_BASE_RELOCATION) <= end)
    {
        IMAGE_BASE_RELOCATION block;
        memcpy(&block, cursor, sizeof(block));
        if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || cursor + block.SizeOfBlock > end)
        {
            break;
        }
        ULONG count = (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        const USHORT *entries = (const USHORT *)(cursor + sizeof(IMAGE_BASE_RELOCATION));
        for (ULONG i = 0; i < count; i++)
        {
            /* Each entry is 16 bits: type in bits 15:12, page offset in bits
             * 11:0 (Microsoft PE Format spec, "The .reloc Section";
             * https://learn.microsoft.com/en-us/windows/win32/debug/pe-format). */
            USHORT entry = entries[i];
            ULONG offset = entry & 0xFFF;
            /* block.VirtualAddress comes straight out of a user-supplied
             * PE's .reloc and was never bounded. Out of the image it is
             * either an uncommitted page -- MipMasterAddDelta's
             * ASSERT(frame != 0), i.e. any process halting the kernel by
             * mapping a crafted image -- or a committed one, i.e. silent
             * corruption elsewhere in the master (docs/review-2026-07 §2).
             * A fixup outside the image is a malformed image, and NT says
             * so. */
            uint64_t rva = (uint64_t)block.VirtualAddress + offset;
            int width;
            switch (entry >> 12)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                continue; /* the padding entry: no fixup, no bound to check */
            case IMAGE_REL_BASED_HIGHLOW:
                width = 4;
                break;
            case IMAGE_REL_BASED_DIR64:
                width = 8;
                break;
            default:
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            if (rva + (uint64_t)width > image->sizeOfImage)
            {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            /* Inside sizeOfImage is not enough: a crafted .reloc can land
             * in a GAP between segments (or past the last one), where the
             * master committed no frame — MipMasterAddDelta's
             * ASSERT(frame != 0) then halts the kernel on a ring-3-supplied
             * image. A fixup into uncommitted image space is the same
             * malformed image the bounds check refuses. */
            if (master->frames[rva / PAGE_SIZE] == 0 ||
                master->frames[(rva + (uint64_t)width - 1) / PAGE_SIZE] == 0)
            {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            MipMasterAddDelta(master, rva, width, delta);
        }
        cursor += block.SizeOfBlock;
    }
    return STATUS_SUCCESS;
}

/* Commit `pageCount` fresh zeroed master frames for the RVA range, then copy
 * `rawSize` initialized bytes from the file at `rawOffset`. */
static NTSTATUS MipMasterCommitRange(PMI_IMAGE_MASTER master, const void *rawData, ULONG rvaStart,
                                     ULONG pageCount, ULONG rawOffset, ULONG rawSize)
{
    ASSERT((rvaStart & (PAGE_SIZE - 1)) == 0);
    ULONG first = rvaStart / PAGE_SIZE;
    for (ULONG i = 0; i < pageCount; i++)
    {
        ASSERT(first + i < master->pageCount && master->frames[first + i] == 0);
        uint64_t frame = MiAllocatePage();
        if (frame == 0)
        {
            return STATUS_NO_MEMORY;
        }
        memset(MiPhysicalToVirtual(frame), 0, PAGE_SIZE);
        master->frames[first + i] = frame;
        MipMasterFrames++;
    }
    const char *from = (const char *)rawData + rawOffset;
    for (ULONG copied = 0; copied < rawSize;)
    {
        ULONG chunk = PAGE_SIZE;
        if (chunk > rawSize - copied)
        {
            chunk = rawSize - copied;
        }
        memcpy(MiPhysicalToVirtual(master->frames[first + copied / PAGE_SIZE]), from + copied,
               chunk);
        copied += chunk;
    }
    return STATUS_SUCCESS;
}

static void MipFreeImageMaster(PMI_IMAGE_MASTER master)
{
    for (ULONG i = 0; i < master->pageCount; i++)
    {
        if (master->frames[i] != 0)
        {
            MiFreePage(master->frames[i]);
            ASSERT(MipMasterFrames > 0);
            MipMasterFrames--;
        }
    }
    MiFreePool(master->frames);
    MiFreePool(master);
}

/* Build the identity's master, relocated for `base`: fresh frames, raw bytes
 * copied in, the whole relocation pass applied ONCE, the header's ImageBase
 * stamped with that base — which is what lets a view placed ELSEWHERE fix up
 * its residual (dlls/ntdll/loader.c perform_relocations). Failure unwinds
 * completely — no half-built master is ever linked. */
/* Borrow an image section's raw file bytes: the create-time snapshot while
 * the section still holds one, else a transient page-cache re-read — the
 * cache is fully resident (Art. 3, no eviction), so this is memcpy, never
 * I/O, and the deny-write share gate keeps the bytes the ones the section
 * was created over. THE one re-source authority (Art. 11): the master
 * build and Ps's dispatcher-export resolution both come here. *tempOut is
 * the caller's to free (MiReleaseImageRawBytes) when non-0. */
NTSTATUS MiAcquireImageRawBytes(PMI_SECTION section, const void **rawOut, void **tempOut)
{
    *tempOut = 0;
    if (section->rawData != 0)
    {
        *rawOut = section->rawData;
        return STATUS_SUCCESS;
    }
    PMI_PAGE_CACHE cache = section->cache;
    ASSERT(cache != 0); /* only the released-snapshot path clears rawData */
    if (cache->fileSize < section->rawSize)
    {
        return STATUS_INVALID_IMAGE_FORMAT; /* truncated under the section */
    }
    void *temp = MiAllocatePool(section->rawSize);
    if (temp == 0)
    {
        return STATUS_NO_MEMORY;
    }
    KI_PROBE_TOKEN token = KiKernelToken(temp, section->rawSize);
    MiCacheRead(cache, 0, &token, temp, section->rawSize);
    *rawOut = temp;
    *tempOut = temp;
    return STATUS_SUCCESS;
}

void MiReleaseImageRawBytes(void *temp)
{
    if (temp != 0)
    {
        MiFreePool(temp);
    }
}

static NTSTATUS MipBuildImageMaster(PMI_SECTION section, uint64_t base, PMI_IMAGE_MASTER *out)
{
    const MI_IMAGE_INFO *image = section->image;

    const void *rawData;
    void *tempRaw;
    NTSTATUS acquire = MiAcquireImageRawBytes(section, &rawData, &tempRaw);
    if (!NT_SUCCESS(acquire))
    {
        return acquire;
    }

    PMI_IMAGE_MASTER master = MiAllocatePool(sizeof(MI_IMAGE_MASTER));
    if (master == 0)
    {
        if (tempRaw != 0)
        {
            MiFreePool(tempRaw);
        }
        return STATUS_NO_MEMORY;
    }
    master->identity = section->masterIdentity;
    master->base = base;
    master->pageCount = (ULONG)(image->sizeOfImage / PAGE_SIZE);
    master->refCount = 0;
    master->frames = MiAllocatePool((uint64_t)master->pageCount * sizeof(uint64_t)); /* zeroed */
    if (master->frames == 0)
    {
        MiFreePool(master);
        if (tempRaw != 0)
        {
            MiFreePool(tempRaw);
        }
        return STATUS_NO_MEMORY;
    }

    /* Headers first, then each PE section — the same ranges the view
     * commits, so every view page has a master frame behind it. */
    ULONG headerBytes = image->sizeOfHeaders;
    if (headerBytes > section->rawSize)
    {
        headerBytes = (ULONG)section->rawSize;
    }
    ULONG headerPages = (headerBytes + PAGE_SIZE - 1) / PAGE_SIZE;
    NTSTATUS status = MipMasterCommitRange(master, rawData, 0, headerPages, 0, headerBytes);
    for (ULONG i = 0; NT_SUCCESS(status) && i < image->segmentCount; i++)
    {
        const MI_IMAGE_SEGMENT *seg = &image->segments[i];
        ULONG pages = (seg->virtualSize + PAGE_SIZE - 1) / PAGE_SIZE;
        status = MipMasterCommitRange(master, rawData, seg->virtualAddress, pages, seg->rawOffset,
                                      seg->rawSize);
    }
    if (NT_SUCCESS(status) && base != image->preferredBase)
    {
        int64_t delta = (int64_t)(base - image->preferredBase);
        status = MipRelocateImage(master, section, rawData, delta);
        if (NT_SUCCESS(status))
        {
            /* The header now claims the ACTUAL base — exactly what Wine's
             * own mapper does after relocating (dlls/ntdll/unix/virtual.c
             * map_image_into_view: OptionalHeader.ImageBase = map_addr).
             * ntdll's PE-side loader keys its own perform_relocations off
             * this field (loader.c: module == base → nothing to do), so
             * leaving the preferred base here would relocate the image a
             * SECOND time. Adding the delta to the stored preferred base
             * lands on `base`. The field's offset and WIDTH follow the
             * image's own optional-header form — a PE32 guest image keeps
             * its ImageBase in 4 bytes, 16 earlier. */
            BOOLEAN pe32 = image->machine == IMAGE_FILE_MACHINE_I386;
            MipMasterAddDelta(master,
                              (uint64_t)image->ntHeaderOffset +
                                  (pe32 ? offsetof(IMAGE_NT_HEADERS32, OptionalHeader.ImageBase)
                                        : offsetof(IMAGE_NT_HEADERS64, OptionalHeader.ImageBase)),
                              pe32 ? 4 : 8, delta);
        }
    }
    if (tempRaw != 0)
    {
        MiFreePool(tempRaw);
    }
    if (!NT_SUCCESS(status))
    {
        MipFreeImageMaster(master);
        return status;
    }
    InsertTailList(&MipImageMasterList, &master->listEntry);
    MipMasterBuilds++;
    MipMasterLive++;
    *out = master;
    return STATUS_SUCCESS;
}

/* The identity's ONE relocated copy, or 0 when it has none yet. No reference
 * is taken; the caller takes one only once it has decided to bind a view.
 *
 * The key is the IDENTITY ALONE. An image section is relocated once and every
 * view of it shares that copy, however the view is placed: the oracle
 * relocates to the mapping's own dynamic base rather than to where the view
 * landed (`delta = image_info->map_addr - image_info->base`, third_party/wine
 * dlls/ntdll/unix/virtual.c map_image_into_view), and the server states the
 * same thing in its at-base test (server/mapping.c DECL_HANDLER(map_image_view):
 * `view->base != (map_addr ? map_addr : base) + offset`). Keying on
 * (identity, base) instead — docs/17 §6F's original rule — gave one relocated
 * copy PER base, so two views of one section differed wherever a relocation
 * applied, which is exactly what ntdll:virtual:1743 memcmps. The residual for
 * a view that does NOT sit at the copy's base belongs to the PE loader, which
 * keys off the ImageBase this build stamps into the header
 * (dlls/ntdll/loader.c perform_relocations); docs/17 §6F carries the trade. */
static PMI_IMAGE_MASTER MipFindImageMaster(PMI_SECTION section)
{
    ASSERT(section->masterIdentity != 0); /* every image backing carries one */
    for (PLIST_ENTRY entry = MipImageMasterList.Flink; entry != &MipImageMasterList;
         entry = entry->Flink)
    {
        PMI_IMAGE_MASTER master = CONTAINING_RECORD(entry, MI_IMAGE_MASTER, listEntry);
        if (master->identity == section->masterIdentity)
        {
            return master;
        }
    }
    return 0;
}

void MiDereferenceImageMaster(PVOID body)
{
    PMI_IMAGE_MASTER master = body;
    ASSERT(master->refCount > 0);
    master->refCount--;
    if (master->refCount == 0)
    {
        RemoveEntryList(&master->listEntry);
        ASSERT(MipMasterLive > 0);
        MipMasterLive--;
        MipFreeImageMaster(master);
    }
}

uint64_t MiImageMasterFrame(PVOID body, ULONG index)
{
    PMI_IMAGE_MASTER master = body;
    ASSERT(index < master->pageCount);
    return master->frames[index];
}

void MiGetImageMasterStats(ULONG *builds, ULONG *hits, ULONG *live, uint64_t *masterFrames)
{
    *builds = MipMasterBuilds;
    *hits = MipMasterHits;
    *live = MipMasterLive;
    *masterFrames = MipMasterFrames;
}

/* Commit one RVA range of an image view from its master: EVERY page maps
 * the master's already-relocated frame — writable (writecopy) pages
 * hardware-read-only, so the first store resolves through the COW arm
 * (MiResolveWriteFault: copy, repoint, open; docs/17 §10 step 5). Nothing
 * here can fail: the frames all exist in the master. */
static void MipCommitViewRange(PMI_ADDRESS_SPACE space, PMI_VAD vad, PMI_IMAGE_MASTER master,
                               uint64_t imageBase, ULONG rvaStart, ULONG pageCount, ULONG protect,
                               ULONG rvaFloor)
{
    for (ULONG i = 0; i < pageCount; i++)
    {
        ULONG rva = rvaStart + i * PAGE_SIZE;
        if (rva < rvaFloor)
        {
            continue; /* the trimmed head: below this view's first page */
        }
        uint64_t frame = master->frames[rva / PAGE_SIZE];
        ASSERT(frame != 0);
        MiCommitFrameInVad(space, vad, imageBase + rva, frame, protect,
                           FALSE /* the master's frame */);
    }
}

/* Map an image view over the identity's shared master: read-only pages
 * (headers, .text, .rdata — the bulk of a DLL) map the master's relocated
 * frames outright; writable pages are private copies of them, per-PE-section
 * protection throughout (docs/02, docs/17 §4).
 *
 * `offset` names where in the IMAGE the view starts. `base` stays the whole
 * image's placement all the way down, because every RVA below is an image
 * RVA; the view is the tail [base+offset, base+SizeOfImage). */
static NTSTATUS MipMapImageView(PMI_SECTION section, PMI_ADDRESS_SPACE space, uint64_t *baseInOut,
                                uint64_t offset, uint64_t *viewSizeInOut, uint64_t limitLow,
                                uint64_t limitHigh, USHORT machine)
{
    const MI_IMAGE_INFO *image = section->image;
    uint64_t size = image->sizeOfImage;
    uint64_t base = *baseInOut;

    /* The oracle's virtual_map_image opens with exactly this, above the fd
     * and above placement (dlls/ntdll/unix/virtual.c: `if (offset >= size)
     * return STATUS_INVALID_PARAMETER;`, where size is the image's map size).
     * The syscall has already refused an offset that is not
     * allocation-granularity aligned (STATUS_MAPPED_ALIGNMENT), so what
     * reaches here is a granule boundary inside the image. */
    if (offset >= size)
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* Where this section's ONE relocated copy lives, and therefore the base
     * this view PREFERS: the copy's own base once it exists, else the PE's
     * preferred base (proskrnl assigns no other — it has no ASLR). The oracle
     * prefers the same address for the same reason, and states it the same
     * way (map_image_view: `if (image_info->map_addr) base =
     * wine_server_get_ptr( image_info->map_addr );` before falling through to
     * a search). A view that lands elsewhere still shares the copy —
     * MipFindImageMaster has why. */
    PMI_IMAGE_MASTER existing = MipFindImageMaster(section);
    uint64_t mapBase = existing != 0 ? existing->base : image->preferredBase;

    /* The placement limits bind an image view too — dropping them here would
     * make zero_bits and MEM_ADDRESS_REQUIREMENTS mean one thing for a data
     * section and nothing for an image, which is the accepted-and-dropped
     * shape this whole item is about.
     *
     * The oracle's map_image_view (dlls/ntdll/unix/virtual.c) is the
     * reference for TWO of the three arms: it tries the PREFERRED base under
     * the limits and, when that fails, falls through to a search bounded by
     * them. It has no third arm, because it never sees a caller-supplied
     * address at all — virtual_map_section hands `addr_ptr` to the image
     * path as an out-parameter only, so an explicit base is silently ignored
     * there. proskrnl honours one (pre-existing, and outside this change),
     * and the limits are applied to it for the same reason the data path
     * applies them to its named base — an arm no oracle run can measure,
     * because the oracle has no such arm (docs/03 records it). */
    if (base != 0)
    {
        if (!MiRangeWithinLimits(base, size, limitLow, limitHigh) ||
            !MiViewRangeIsFree(space, base, size))
        {
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }
    else if (mapBase >= MI_ALLOCATION_GRANULARITY &&
             MiRangeWithinLimits(mapBase, size, limitLow, limitHigh) &&
             MiViewRangeIsFree(space, mapBase, size))
    {
        base = mapBase;
    }
    else
    {
        base = MiFindFreeViewBaseEx(space, size, limitLow, limitHigh, 0);
        if (base == 0)
        {
            return STATUS_NO_MEMORY;
        }
    }
    /* MemExtendedParameterImageMachine bounds the machine of the image a view
     * may be created over: zero is "no constraint", anything else must be the
     * machine the PE header declares, or STATUS_NOT_SUPPORTED (the oracle's
     * map_image_into_view, dlls/ntdll/unix/virtual.c: `if (machine && machine
     * != nt->FileHeader.Machine)` — note that is a DIFFERENT function from
     * the map_image_view cited below for the floor). Its POSITION is pinned
     * as well as its status: virtual_map_image places the view with
     * map_image_view and only then calls map_image_into_view, whose machine
     * check is its last act before the relocation — so a view that cannot be
     * PLACED reports the placement failure and never reaches here
     * (sem_mm/map_image_machine.c). */
    if (machine != 0 && machine != image->machine)
    {
        return STATUS_NOT_SUPPORTED;
    }

    /* "At base" is measured against the image's DYNAMIC base, not against the
     * PE header's preferred one — the server's own test (server/mapping.c
     * DECL_HANDLER(map_image_view): `view->base != (map_addr ? map_addr :
     * base) + offset`), where the `+ offset` is this trim. For a
     * relocs-stripped image the two are always the same address: such an
     * image can only ever have been copied at its preferred base, because the
     * refusal below is what stops any other build. */
    BOOLEAN atBase = base == mapBase;
    if (base != image->preferredBase && image->relocsStripped)
    {
        return STATUS_CONFLICTING_ADDRESSES; /* nailed-down image, base taken */
    }

    PMI_IMAGE_MASTER master = existing;
    NTSTATUS status = STATUS_SUCCESS;
    if (master != 0)
    {
        master->refCount++;
        MipMasterHits++;
    }
    else
    {
        /* Nothing between MipFindImageMaster above and this build can park —
         * placement only walks the VAD list, and the raw-byte source is
         * resident by Art. 3 (MiAcquireImageRawBytes: "memcpy, never I/O") —
         * so this identity cannot have gained a second copy in between, which
         * would be two relocation bases for one section. */
        status = MipBuildImageMaster(section, base, &master);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        master->refCount = 1;
    }

    /* The section's raw-byte snapshot has served its purpose (parse at
     * create, first master build): release it — it is a WHOLE second copy
     * of the file per section, i.e. per process, and half the measured
     * per-process cost (docs/17 §1). A later different-base build re-reads
     * through the file's resident cache (MipBuildImageMaster); the ramdisk
     * path borrows immortal bytes and keeps them. */
    if (section->ownsRawData && section->rawData != 0 && section->cache != 0)
    {
        MiFreePool((void *)(uintptr_t)section->rawData);
        section->rawData = 0;
        section->ownsRawData = FALSE;
    }

    /* The offset TRIMS the image's head. The oracle maps the whole image and
     * then removes the front of the view (virtual_map_image: `if (offset) {
     * free_pages( view, view->base, offset ); size -= offset; }`), so the
     * answer is base+offset with size = map_size - offset and the head is
     * FREE rather than a reserved stub. Here the VAD is created over the tail
     * directly — the same extent, and no page is ever mapped only to be
     * unmapped. `sectionOffset` is what tells the master's frame index apart
     * from this VAD's page index (virtual.c MipVadMasterIndex). */
    uint64_t viewBase = base + offset;
    uint64_t viewSize = size - offset;

    ObfReferenceObject(section); /* the view's pin, owned by the VAD */
    PMI_VAD vad =
        MiCreateMappedVad(space, viewBase, viewSize, PAGE_EXECUTE_WRITECOPY, MEM_IMAGE, section,
                          FALSE /* frames are the master's, or per-page private */, offset);
    if (vad == 0)
    {
        ObDereferenceObject(section);
        MiDereferenceImageMaster(master);
        return STATUS_NO_MEMORY;
    }
    status = MiBindVadImageMaster(vad, master); /* on success the VAD owns the ref */
    if (!NT_SUCCESS(status))
    {
        MiDeleteMappedVad(space, vad); /* drops the section pin; no master bound yet */
        MiDereferenceImageMaster(master);
        return status;
    }

    /* Headers first (read-only), then each PE section with its own
     * protection — every page backed by a frame before user mode can touch
     * it (no demand paging; sharing is invisible to the commit model,
     * docs/17 §7). */
    ULONG headerBytes = image->sizeOfHeaders;
    if (headerBytes > section->rawSize)
    {
        headerBytes = (ULONG)section->rawSize;
    }
    ULONG headerPages = (headerBytes + PAGE_SIZE - 1) / PAGE_SIZE;
    ULONG rvaFloor = (ULONG)offset;
    MipCommitViewRange(space, vad, master, base, 0, headerPages, PAGE_READONLY, rvaFloor);
    for (ULONG i = 0; i < image->segmentCount; i++)
    {
        const MI_IMAGE_SEGMENT *seg = &image->segments[i];
        ULONG pages = (seg->virtualSize + PAGE_SIZE - 1) / PAGE_SIZE;
        MipCommitViewRange(space, vad, master, base, seg->virtualAddress, pages, seg->protect,
                           rvaFloor);
    }

    /* docs/17 §8's highest-value check, scoped to the view just built —
     * the full-space sweep here walked every earlier image VAD per map,
     * quadratic in module count on the loader path. */
    MiAssertVadNoWritableMasterPteRange(space, vad, viewBase, viewSize);

    *baseInOut = viewBase;
    *viewSizeInOut = viewSize;
    /* The machine check comes LAST and overrides the not-at-base report,
     * because the server sets both with the same set_error and this one runs
     * second (server/mapping.c DECL_HANDLER(map_view)). A 32-bit process is
     * allowed to map the NATIVE 64-bit machine — that is how a WOW64 process
     * maps the 64-bit ntdll and the wow64 host DLLs — but no other crossing
     * passes silently. Success-class, so the view stands either way; a
     * kernel answering plain STATUS_SUCCESS looks right to every
     * NT_SUCCESS() check and is still wrong (sem_mm/map_image_machine.c,
     * ntdll:wow64 test_image_mappings). */
    if (space->machine != 0 && image->machine != space->machine)
    {
        BOOLEAN spaceIs64 = space->machine == IMAGE_FILE_MACHINE_AMD64;
        if (spaceIs64 || image->machine != IMAGE_FILE_MACHINE_AMD64)
        {
            return STATUS_IMAGE_MACHINE_TYPE_MISMATCH;
        }
    }
    return atBase ? STATUS_SUCCESS : STATUS_IMAGE_NOT_AT_BASE;
}

NTSTATUS MiMapViewOfSection(PMI_SECTION section, PMI_ADDRESS_SPACE space, uint64_t *baseInOut,
                            uint64_t offset, uint64_t *viewSizeInOut, ULONG protect)
{
    return MiMapViewOfSectionEx(section, space, baseInOut, offset, viewSizeInOut, protect, 0, 0, 0);
}

/* CUI-7 constrained form (NtMapViewOfSectionEx placement limits); the
 * classic entry delegates with zeros — one mapping engine (Art. 11). */
NTSTATUS MiMapViewOfSectionEx(PMI_SECTION section, PMI_ADDRESS_SPACE space, uint64_t *baseInOut,
                              uint64_t offset, uint64_t *viewSizeInOut, ULONG protect,
                              uint64_t limitLow, uint64_t limitHigh, USHORT machine)
{
    /* An IMAGE view's floor is its own — the oracle's map_image_view raises
     * limit_low to `address_space_start` before it does anything else ("make
     * sure the DOS area remains free", dlls/ntdll/unix/virtual.c) — but the
     * refusal that follows from it belongs to map_view, i.e. to the arm
     * BOTH kinds of view funnel through, so it is stated once here rather
     * than inside one arm (Art. 11).
     *
     * Its visible consequence is that the two arms answer DIFFERENTLY for
     * the same zero_bits: a ceiling below 64K is STATUS_INVALID_PARAMETER
     * for an image view, where the data arm — which keeps limit_low 0 —
     * lets the same ceiling reach its search and answers STATUS_NO_MEMORY.
     * Both measured (sem_mm/map_zero_bits.c). The data arm cannot reach the
     * refusal from either syscall today (zero_bits supplies no limitLow, and
     * MiCaptureExtendedParams already refuses a MEM_ADDRESS_REQUIREMENTS
     * whose Highest is at or below its Lowest); it is written where the
     * oracle writes it so the two cannot drift apart later. */
    if (section->image != 0 && limitLow < MI_LOWEST_USER_ADDRESS)
    {
        limitLow = MI_LOWEST_USER_ADDRESS;
    }
    if (limitHigh != 0 && limitLow >= limitHigh)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (section->image != 0)
    {
        /* The requested view SIZE is deliberately not read here: the oracle's
         * image arm never looks at *size_ptr (virtual_map_section hands
         * virtual_map_image the offset and nothing else), so an image view is
         * always the whole tail from `offset`. */
        return MipMapImageView(section, space, baseInOut, offset, viewSizeInOut, limitLow,
                               limitHigh, machine);
    }

    /* Data view: offset/size against the section (Wine's virtual_map_section
     * shape, pinned by anonymous_section.c). It ignores `machine` entirely —
     * the oracle's word reaches map_image_into_view and nothing else, so
     * virtual_map_section's data arm never sees it (pinned by
     * sem_mm/map_image_machine.c, for the same reason sem_mm/map_ex.c pins
     * MEM_EXTENDED_PARAMETER_EC_CODE's acceptance here: a guard written into
     * the shared parameter parser would refuse a mapping the oracle
     * admits). */
    if (offset >= section->size)
    {
        return STATUS_INVALID_PARAMETER;
    }
    uint64_t size = *viewSizeInOut;
    if (size == 0)
    {
        size = section->size - offset;
    }
    else if (size > section->size - offset)
    {
        return STATUS_INVALID_VIEW_SIZE;
    }
    size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1ULL);

    /* WRITECOPY data views become private full copies on map (Art. 3);
     * everything else shares the section's frames. */
    ULONG bits = protect & ~(PAGE_GUARD | PAGE_NOCACHE);
    BOOLEAN privateCopy = bits == PAGE_WRITECOPY || bits == PAGE_EXECUTE_WRITECOPY;

    /* A SHARED writable view of a file-backed section writes the file's page
     * cache -- and with immediate writeback (Art. 3) that IS a write to the
     * file. Nothing checked the backing handle's access at map time, so
     * opening a file FILE_READ_DATA, creating a section over it, and mapping
     * the section PAGE_READWRITE wrote a file the caller could not write
     * (docs/review-2026-07 §11). The oracle refuses that with
     * STATUS_ACCESS_DENIED -- verified against the pinned Wine, which also
     * shows the gate is the HANDLE's access and not the section's creation
     * protection: a PAGE_READONLY section over a read-write handle maps
     * PAGE_READWRITE quite happily there. A private copy writes nothing back
     * and stays legal. */
    if (!privateCopy && !section->backingWritable &&
        (bits == PAGE_READWRITE || bits == PAGE_EXECUTE_READWRITE))
    {
        return STATUS_ACCESS_DENIED;
    }

    uint64_t base = *baseInOut;
    if (base != 0)
    {
        /* The limits bound a named base too, and they are checked BEFORE the
         * range is looked at — the oracle's map_view tests limit_low /
         * limit_high above its map_fixed_area (dlls/ntdll/unix/virtual.c).
         * Both answer STATUS_CONFLICTING_ADDRESSES, so the order is not
         * observable through the status; it is written this way because the
         * two questions are separate and only one of them is about the
         * address space. */
        if (!MiRangeWithinLimits(base, size, limitLow, limitHigh) ||
            !MiViewRangeIsFree(space, base, size))
        {
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }
    else
    {
        base = MiFindFreeViewBaseEx(space, size, limitLow, limitHigh, 0);
        if (base == 0)
        {
            return STATUS_NO_MEMORY;
        }
    }

    ObfReferenceObject(section); /* the view's pin, owned by the VAD */
    PMI_VAD vad =
        MiCreateMappedVad(space, base, size, protect, MEM_MAPPED, section, privateCopy, offset);
    if (vad == 0)
    {
        ObDereferenceObject(section);
        return STATUS_NO_MEMORY;
    }

    ULONG firstPage = (ULONG)(offset / PAGE_SIZE);
    ULONG pageCount = (ULONG)(size / PAGE_SIZE);
    /* File-backed data sections map the file's page cache; anonymous
     * sections map their own frames. */
    const uint64_t *frames = section->cache != 0 ? section->cache->frames : section->frames;
    ASSERT(section->cache == 0 || firstPage + pageCount <= section->cache->pageCount);
    for (ULONG i = 0; i < pageCount; i++)
    {
        uint64_t frame = frames[firstPage + i];
        if (frame == 0)
        {
            /* A SEC_RESERVE section's page that nobody has committed yet.
             * The VAD page stays uncommitted here and MiCommitReserveSection-
             * Range fills it in for THIS view the moment ANY view commits it
             * — which is why the view is on the section's list before this
             * loop runs. Nothing else can hold a 0 frame: a SEC_COMMIT
             * section allocates all of its at creation and a page cache
             * every page it reports. */
            ASSERT((section->attributes & SEC_RESERVE) != 0);
            continue;
        }
        if (privateCopy)
        {
            uint64_t copy = MiAllocatePage();
            if (copy == 0)
            {
                MiDeleteMappedVad(space, vad);
                return STATUS_NO_MEMORY;
            }
            memcpy(MiPhysicalToVirtual(copy), MiPhysicalToVirtual(frame), PAGE_SIZE);
            frame = copy;
        }
        MiCommitFrameInVad(space, vad, base + (uint64_t)i * PAGE_SIZE, frame, protect, privateCopy);
    }

    *baseInOut = base;
    *viewSizeInOut = size;
    return STATUS_SUCCESS;
}

/* --- the Nt* surface ---------------------------------------------------------- */

/* Wine's NtCreateSection protection switch: which protections may create a
 * section at all. */
static NTSTATUS MipCheckSectionProtect(ULONG protect)
{
    switch (protect & 0xff)
    {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
    case PAGE_NOACCESS:
        return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_PAGE_PROTECTION;
    }
}

/* Wine's virtual_map_section access switch: what a view protection demands
 * of the section handle. */
static NTSTATUS MipViewProtectToAccess(ULONG protect, ACCESS_MASK *access)
{
    switch (protect)
    {
    case PAGE_NOACCESS:
    case PAGE_READONLY:
    case PAGE_WRITECOPY:
        *access = SECTION_MAP_READ;
        return STATUS_SUCCESS;
    case PAGE_READWRITE:
        *access = SECTION_MAP_WRITE;
        return STATUS_SUCCESS;
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_WRITECOPY:
        *access = SECTION_MAP_READ | SECTION_MAP_EXECUTE;
        return STATUS_SUCCESS;
    case PAGE_EXECUTE_READWRITE:
        *access = SECTION_MAP_WRITE | SECTION_MAP_EXECUTE;
        return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_PAGE_PROTECTION;
    }
}

NTSTATUS NtCreateSection(HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                         const LARGE_INTEGER *size, ULONG protect, ULONG secFlags, HANDLE file)
{
    if (handle == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = MipCheckSectionProtect(protect);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    LARGE_INTEGER capturedSize;
    const LARGE_INTEGER *sizeArg = 0;
    if (size != 0)
    {
        status = KiCopyFromUser(&capturedSize, size, sizeof(capturedSize));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        sizeArg = &capturedSize;
    }

    /* A file handle brings the M6 Io backing: the file's page cache for
     * data sections, a raw-bytes snapshot for SEC_IMAGE. */
    MI_SECTION_BACKING backing;
    BOOLEAN haveBacking = FALSE;
    if (file != 0)
    {
        status = IopBuildSectionBacking(file, secFlags, protect, sizeArg, &backing);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        haveBacking = TRUE;
    }

    /* Build first (fallible), then bind the name/handle (Ob) and move the
     * contents in — a name collision under OBJ_OPENIF must not disturb the
     * existing object. */
    MI_SECTION scratch;
    status = MipBuildSection(&scratch, sizeArg, protect, secFlags, haveBacking ? &backing : 0);
    if (!NT_SUCCESS(status))
    {
        if (haveBacking)
        {
            if (backing.ownsRawData && scratch.rawData == 0)
            {
                MiFreePool((void *)(uintptr_t)backing.rawData);
            }
            else if (scratch.rawData != 0)
            {
                MipDeleteSection(&scratch);
            }
            IopSectionBackingReleased(backing.fileObject, secFlags, protect);
            ObDereferenceObject(backing.fileObject);
        }
        return status;
    }

    PVOID body;
    status =
        ObpCreateObjectWithHandle(&MiSectionType, sizeof(MI_SECTION), attr, access, &body, handle);
    if (status == STATUS_SUCCESS)
    {
        if (haveBacking)
        {
            scratch.fileObject = backing.fileObject;
            ObfReferenceObject(scratch.fileObject); /* the section's pin */
        }
        MipPublishSection(body, &scratch);
    }
    else
    {
        MipDeleteSection(&scratch); /* OBJ_OPENIF hit an existing object, or failure */
        if (haveBacking)
        {
            IopSectionBackingReleased(backing.fileObject, secFlags, protect);
        }
    }
    if (haveBacking)
    {
        ObDereferenceObject(backing.fileObject); /* IopBuildSectionBacking's reference */
    }
    return status;
}

NTSTATUS NtCreateSectionEx(HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                           const LARGE_INTEGER *size, ULONG protect, ULONG attributes, HANDLE file,
                           MEM_EXTENDED_PARAMETER *parameters, ULONG count)
{
    /* The parameter array is accepted and ignored, exactly as the pinned
     * oracle does (wine dlls/ntdll/unix/sync.c NtCreateSectionEx: FIXME +
     * delegate; pinned by sem_mm/alloc_ex; docs/03 "CUI-7"). */
    (void)parameters;
    (void)count;
    return NtCreateSection(handle, access, attr, size, protect, attributes, file);
}

NTSTATUS NtOpenSection(HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr)
{
    if (handle == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    return ObpOpenObjectByName(&MiSectionType, attr, access, handle);
}

NTSTATUS NtMapViewOfSection(HANDLE sectionHandle, HANDLE processHandle, PVOID *baseInOut,
                            ULONG_PTR zeroBits, SIZE_T commitSize, const LARGE_INTEGER *offsetPtr,
                            SIZE_T *viewSizeInOut, SECTION_INHERIT inherit, ULONG allocType,
                            ULONG protect)
{
    (void)commitSize; /* meaningful for SEC_RESERVE sections only (not M5) */
    (void)inherit;    /* ViewShare/ViewUnmap matter at fork; no fork before M7 */

    NTSTATUS status = KiProbeForWrite((void *)baseInOut, sizeof(*baseInOut), sizeof(*baseInOut));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(viewSizeInOut, sizeof(*viewSizeInOut), sizeof(*viewSizeInOut));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    uint64_t base = (uint64_t)(uintptr_t)*baseInOut;
    uint64_t viewSize = *viewSizeInOut;

    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    if (offsetPtr != 0)
    {
        status = KiCopyFromUser(&offset, offsetPtr, sizeof(offset));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    /* Parameter conventions exactly as Wine's NtMapViewOfSection (pinned by
     * sem_mm/anonymous_section.c). */
    if (zeroBits > 21 && zeroBits < 32)
    {
        return STATUS_INVALID_PARAMETER_4;
    }
    if (zeroBits != 0 && zeroBits < 32 && (base >> (32 - zeroBits)) != 0)
    {
        return STATUS_INVALID_PARAMETER_4;
    }
    if (zeroBits >= 32 && (base & ~(uint64_t)zeroBits) != 0)
    {
        return STATUS_INVALID_PARAMETER_4;
    }
    if (allocType & AT_ROUND_TO_PAGE)
    {
        return STATUS_INVALID_PARAMETER_9; /* 64-bit processes may not */
    }
    if ((offset.QuadPart & (MI_ALLOCATION_GRANULARITY - 1)) != 0 || offset.QuadPart < 0)
    {
        return STATUS_MAPPED_ALIGNMENT;
    }
    if ((base & (MI_ALLOCATION_GRANULARITY - 1)) != 0)
    {
        return STATUS_MAPPED_ALIGNMENT;
    }

    ACCESS_MASK requiredAccess;
    status = MipViewProtectToAccess(protect, &requiredAccess);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PVOID sectionBody;
    status = ObReferenceObjectByHandle(sectionHandle, requiredAccess, &MiSectionType,
                                       ExGetPreviousMode(), &sectionBody, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PEPROCESS process;
    BOOLEAN referenced;
    status = MiReferenceProcessByHandle(processHandle, PROCESS_VM_OPERATION, &process, &referenced);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(sectionBody);
        return status;
    }

    /* zero_bits is a PLACEMENT CONSTRAINT here as it is on the allocation
     * path, through the same limitHigh MEM_ADDRESS_REQUIREMENTS uses (Art.
     * 11) — but it is passed UNCONDITIONALLY, which is the one thing this
     * syscall does differently. NtAllocateVirtualMemory drops the limit when
     * the caller names a base (`if (!*ret) limit = ...; else limit = 0;`);
     * NtMapViewOfSection has no such arm (`virtual_map_section( handle,
     * addr_ptr, 0, get_zero_bits_limit( zero_bits ), ... )`, the oracle's
     * dlls/ntdll/unix/virtual.c NtMapViewOfSection), so a named base keeps
     * the ceiling and a view that ENDS above it is refused. Both halves are
     * pinned by tests/ntapi/sem_mm/map_zero_bits.c.
     *
     * The checks above have already refused the invalid 22..31 band and a
     * base that is itself above the ceiling; what reaches here is a limit
     * that placement must honour. */
    status =
        MiMapViewOfSectionEx(sectionBody, &process->addressSpace, &base, (uint64_t)offset.QuadPart,
                             &viewSize, protect, 0, MiZeroBitsLimit(zeroBits), 0);
    if (NT_SUCCESS(status))
    {
        *baseInOut = (PVOID)(uintptr_t)base;
        *viewSizeInOut = viewSize;
    }

    if (referenced)
    {
        ObDereferenceObject(process);
    }
    ObDereferenceObject(sectionBody);
    return status;
}

NTSTATUS NtMapViewOfSectionEx(HANDLE sectionHandle, HANDLE processHandle, PVOID *baseInOut,
                              const LARGE_INTEGER *offsetPtr, SIZE_T *viewSizeInOut,
                              ULONG allocType, ULONG protect, MEM_EXTENDED_PARAMETER *parameters,
                              ULONG count)
{
    NTSTATUS status = KiProbeForWrite((void *)baseInOut, sizeof(*baseInOut), sizeof(*baseInOut));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(viewSizeInOut, sizeof(*viewSizeInOut), sizeof(*viewSizeInOut));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t base = (uint64_t)(uintptr_t)*baseInOut;
    uint64_t viewSize = *viewSizeInOut;
    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    if (offsetPtr != 0)
    {
        status = KiCopyFromUser(&offset, offsetPtr, sizeof(offset));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    /* The oracle's ladder (wine dlls/ntdll/unix/virtual.c
     * NtMapViewOfSectionEx; pinned by sem_mm/map_ex): parameters, then an
     * Alignment requirement refuses outright (mapping has no alignment),
     * an explicit address with limits refuses, AT_ROUND_TO_PAGE refuses on
     * win64, then the 64K granularity on offset and address. */
    MI_EXTENDED_PARAMS extended;
    status = MiCaptureExtendedParams(parameters, count, &extended);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (extended.align != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (base != 0 && (extended.limitLow != 0 || extended.limitHigh != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (allocType & AT_ROUND_TO_PAGE)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (allocType & MEM_REPLACE_PLACEHOLDER)
    {
        /* Placeholders stay unbuilt (docs/03 "CUI-7"; Art. 12). */
        return STATUS_NOT_IMPLEMENTED;
    }
    if ((offset.QuadPart & (MI_ALLOCATION_GRANULARITY - 1)) != 0 || offset.QuadPart < 0)
    {
        return STATUS_MAPPED_ALIGNMENT;
    }
    if ((base & (MI_ALLOCATION_GRANULARITY - 1)) != 0)
    {
        return STATUS_MAPPED_ALIGNMENT;
    }

    ACCESS_MASK requiredAccess;
    status = MipViewProtectToAccess(protect, &requiredAccess);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PVOID sectionBody;
    status = ObReferenceObjectByHandle(sectionHandle, requiredAccess, &MiSectionType,
                                       ExGetPreviousMode(), &sectionBody, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PEPROCESS process;
    BOOLEAN referenced;
    status = MiReferenceProcessByHandle(processHandle, PROCESS_VM_OPERATION, &process, &referenced);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(sectionBody);
        return status;
    }
    status = MiMapViewOfSectionEx(sectionBody, &process->addressSpace, &base,
                                  (uint64_t)offset.QuadPart, &viewSize, protect, extended.limitLow,
                                  extended.limitHigh, extended.machine);
    if (NT_SUCCESS(status))
    {
        *baseInOut = (PVOID)(uintptr_t)base;
        *viewSizeInOut = viewSize;
    }
    if (referenced)
    {
        ObDereferenceObject(process);
    }
    ObDereferenceObject(sectionBody);
    return status;
}

NTSTATUS NtUnmapViewOfSection(HANDLE processHandle, PVOID baseAddress)
{
    PEPROCESS process;
    BOOLEAN referenced;
    NTSTATUS status =
        MiReferenceProcessByHandle(processHandle, PROCESS_VM_OPERATION, &process, &referenced);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = MiUnmapView(&process->addressSpace, (uint64_t)(uintptr_t)baseAddress);
    if (referenced)
    {
        ObDereferenceObject(process);
    }
    return status;
}

NTSTATUS NtUnmapViewOfSectionEx(HANDLE processHandle, PVOID baseAddress, ULONG flags)
{
    /* The oracle's flag mask (wine dlls/ntdll/unix/virtual.c
     * NtUnmapViewOfSectionEx; pinned by sem_mm/map_ex): anything outside
     * refuses, the transient boost is an ignored no-op, and the
     * placeholder-preserving unmap stays unbuilt (docs/03 "CUI-7"). */
    if (flags & ~(ULONG)(MEM_UNMAP_WITH_TRANSIENT_BOOST | MEM_PRESERVE_PLACEHOLDER))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (flags & MEM_PRESERVE_PLACEHOLDER)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    return NtUnmapViewOfSection(processHandle, baseAddress);
}

NTSTATUS NtQuerySection(HANDLE handle, SECTION_INFORMATION_CLASS informationClass, PVOID buffer,
                        SIZE_T length, SIZE_T *returnLength)
{
    /* Class/length conventions before handle validity, as Wine. */
    ULONG needed;
    switch (informationClass)
    {
    case SectionBasicInformation:
        needed = sizeof(SECTION_BASIC_INFORMATION);
        break;
    case SectionImageInformation:
        needed = sizeof(SECTION_IMAGE_INFORMATION);
        break;
    default:
        DbgPrint("NtQuerySection: unbuilt info class %d\n", (int)informationClass);
        return STATUS_NOT_IMPLEMENTED;
    }
    if (length < needed)
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    if (buffer == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(buffer, needed, sizeof(uint64_t));
    if (NT_SUCCESS(status) && returnLength != 0)
    {
        status = KiProbeForWrite(returnLength, sizeof(*returnLength), sizeof(*returnLength));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PVOID body;
    status = ObReferenceObjectByHandle(handle, SECTION_QUERY, &MiSectionType, ExGetPreviousMode(),
                                       &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PMI_SECTION section = body;

    if (informationClass == SectionBasicInformation)
    {
        SECTION_BASIC_INFORMATION info;
        memset(&info, 0, sizeof(info));
        info.BaseAddress = 0;
        info.Attributes = section->attributes;
        info.Size.QuadPart = (LONGLONG)section->size;
        memcpy(buffer, &info, sizeof(info));
    }
    else if (section->image == 0)
    {
        ObDereferenceObject(section);
        return STATUS_SECTION_NOT_IMAGE;
    }
    else
    {
        const MI_IMAGE_INFO *image = section->image;
        SECTION_IMAGE_INFORMATION info;
        memset(&info, 0, sizeof(info));
        info.TransferAddress = (PVOID)(uintptr_t)(image->preferredBase + image->entryRva);
        info.ZeroBits = 0;
        info.MaximumStackSize = image->stackReserve;
        info.CommittedStackSize = image->stackCommit;
        info.SubSystemType = image->subsystem;
        info.MinorSubsystemVersion = image->subsystemMinor;
        info.MajorSubsystemVersion = image->subsystemMajor;
        info.MajorOperatingSystemVersion = image->osMajor;
        info.MinorOperatingSystemVersion = image->osMinor;
        info.ImageCharacteristics = image->characteristics;
        info.DllCharacteristics = image->dllCharacteristics;
        info.Machine = image->machine;
        info.ImageContainsCode = image->containsCode;
        info.LoaderFlags = 0;
        info.ImageFileSize = image->fileSize;
        info.CheckSum = image->checksum;
        memcpy(buffer, &info, sizeof(info));
    }
    if (returnLength != 0)
    {
        *returnLength = needed;
    }
    ObDereferenceObject(section);
    return STATUS_SUCCESS;
}
