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
                                MI_SECTION_BACKING *backing);
void IopSectionBackingReleased(PVOID fileObjectBody);

static void MipDeleteSection(PVOID body)
{
    PMI_SECTION section = body;
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
        IopSectionBackingReleased(section->fileObject);
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
    scratch->pageProtection = pageProtection;

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
        /* Commit-on-demand section pages need a pagefile-shaped commit
         * ledger; nothing before M7+ needs one. Loud, not wrong. */
        return STATUS_NOT_IMPLEMENTED;

    default:
        return STATUS_INVALID_PARAMETER;
    }

    if (backing != 0 && backing->cache != 0)
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
                /* NT would extend a writable file here; no caller needs it
                 * yet. Loud, not wrong (Art. 3). */
                return STATUS_NOT_IMPLEMENTED;
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

    /* Anonymous (pagefile-backed): all frames exist, zeroed, from the start
     * (Art. 3: no demand paging) and are shared by every view. */
    if (maximumSize == 0 || maximumSize->QuadPart <= 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    scratch->attributes = SEC_COMMIT;
    scratch->size = ((uint64_t)maximumSize->QuadPart + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1ULL);
    scratch->pageCount = (ULONG)(scratch->size / PAGE_SIZE);
    scratch->frames = MiAllocatePool((uint64_t)scratch->pageCount * sizeof(uint64_t));
    if (scratch->frames == 0)
    {
        return STATUS_NO_MEMORY;
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
    memcpy(body, &scratch, sizeof(scratch));
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
    }
    if (file == 0 && (attributes & SEC_IMAGE) != 0)
    {
        return STATUS_INVALID_FILE_FOR_SECTION;
    }
    return MiCreateBackedSection(maximumSize, pageProtection, attributes,
                                 file != 0 ? &backing : 0, sectionOut);
}

/* --- mapping ----------------------------------------------------------------- */

/* Byte-accurate write into a mapped (committed) range of `space` — reloc
 * fixups may straddle a page boundary. */
static void MipAddDelta(PMI_ADDRESS_SPACE space, uint64_t va, int width, int64_t delta)
{
    unsigned char raw[8] = {0};
    ASSERT(width == 4 || width == 8);
    for (int i = 0; i < width; i++)
    {
        uint64_t frame =
            MiTranslateUserPage(space->pml4Physical, (va + i) & ~(PAGE_SIZE - 1ULL), 0, 0);
        ASSERT(frame != 0);
        raw[i] = ((unsigned char *)MiPhysicalToVirtual(frame))[(va + i) & (PAGE_SIZE - 1)];
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
        uint64_t frame =
            MiTranslateUserPage(space->pml4Physical, (va + i) & ~(PAGE_SIZE - 1ULL), 0, 0);
        ((unsigned char *)MiPhysicalToVirtual(frame))[(va + i) & (PAGE_SIZE - 1)] = raw[i];
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

/* Apply the .reloc directory to the freshly copied image at `base` (which
 * sits `delta` bytes from the preferred base). Blocks are read from the FILE
 * bytes (linear); fixups are applied to the mapped copy. Shape as
 * LdrProcessRelocationBlock (Wine's reimplementation is the reference). */
static NTSTATUS MipRelocateImage(PMI_ADDRESS_SPACE space, PMI_SECTION section, uint64_t base,
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
    const char *cursor = (const char *)section->rawData + fileOffset;
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
            uint64_t va = base + block.VirtualAddress + offset;
            switch (entry >> 12)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                MipAddDelta(space, va, 4, delta);
                break;
            case IMAGE_REL_BASED_DIR64:
                MipAddDelta(space, va, 8, delta);
                break;
            default:
                return STATUS_INVALID_IMAGE_FORMAT;
            }
        }
        cursor += block.SizeOfBlock;
    }
    return STATUS_SUCCESS;
}

/* Commit `pageCount` fresh zeroed frames into a view VAD at `va`, then copy
 * `rawSize` initialized bytes from the file at `rawOffset`. */
static NTSTATUS MipCommitImageRange(PMI_ADDRESS_SPACE space, PMI_VAD vad, PMI_SECTION section,
                                    uint64_t va, ULONG pageCount, ULONG rawOffset, ULONG rawSize,
                                    ULONG protect)
{
    for (ULONG i = 0; i < pageCount; i++)
    {
        uint64_t frame = MiAllocatePage();
        if (frame == 0)
        {
            return STATUS_NO_MEMORY;
        }
        memset(MiPhysicalToVirtual(frame), 0, PAGE_SIZE);
        MiCommitFrameInVad(space, vad, va + (uint64_t)i * PAGE_SIZE, frame, protect);
    }
    if (rawSize != 0)
    {
        MiCopyToUserRange(space, va, (const char *)section->rawData + rawOffset, rawSize);
    }
    return STATUS_SUCCESS;
}

/* Map an image view: a full private copy of the PE, relocated if the
 * preferred base is unavailable, per-PE-section protection (docs/02). */
static NTSTATUS MipMapImageView(PMI_SECTION section, PMI_ADDRESS_SPACE space, uint64_t *baseInOut,
                                uint64_t *viewSizeInOut)
{
    const MI_IMAGE_INFO *image = section->image;
    uint64_t size = image->sizeOfImage;
    uint64_t base = *baseInOut;

    if (base != 0)
    {
        if (!MiViewRangeIsFree(space, base, size))
        {
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }
    else if (image->preferredBase >= MI_ALLOCATION_GRANULARITY &&
             MiViewRangeIsFree(space, image->preferredBase, size))
    {
        base = image->preferredBase;
    }
    else
    {
        base = MiFindFreeViewBase(space, size);
        if (base == 0)
        {
            return STATUS_NO_MEMORY;
        }
    }
    BOOLEAN atBase = base == image->preferredBase;
    if (!atBase && image->relocsStripped)
    {
        return STATUS_CONFLICTING_ADDRESSES; /* nailed-down image, base taken */
    }

    ObfReferenceObject(section); /* the view's pin, owned by the VAD */
    PMI_VAD vad = MiCreateMappedVad(space, base, size, PAGE_EXECUTE_WRITECOPY, MEM_IMAGE, section,
                                    TRUE /* a private full copy */);
    if (vad == 0)
    {
        ObDereferenceObject(section);
        return STATUS_NO_MEMORY;
    }

    /* Headers first (read-only), then each PE section with its own
     * protection; everything is copied — no COW, no demand paging. */
    ULONG headerBytes = image->sizeOfHeaders;
    if (headerBytes > section->rawSize)
    {
        headerBytes = (ULONG)section->rawSize;
    }
    ULONG headerPages = (headerBytes + PAGE_SIZE - 1) / PAGE_SIZE;
    NTSTATUS status =
        MipCommitImageRange(space, vad, section, base, headerPages, 0, headerBytes, PAGE_READONLY);
    for (ULONG i = 0; NT_SUCCESS(status) && i < image->segmentCount; i++)
    {
        const MI_IMAGE_SEGMENT *seg = &image->segments[i];
        ULONG pages = (seg->virtualSize + PAGE_SIZE - 1) / PAGE_SIZE;
        status = MipCommitImageRange(space, vad, section, base + seg->virtualAddress, pages,
                                     seg->rawOffset, seg->rawSize, seg->protect);
    }
    if (NT_SUCCESS(status) && !atBase)
    {
        status = MipRelocateImage(space, section, base, (int64_t)(base - image->preferredBase));
    }
    if (!NT_SUCCESS(status))
    {
        MiDeleteMappedVad(space, vad); /* also drops the view's section pin */
        return status;
    }

    *baseInOut = base;
    *viewSizeInOut = size;
    return atBase ? STATUS_SUCCESS : STATUS_IMAGE_NOT_AT_BASE;
}

NTSTATUS MiMapViewOfSection(PMI_SECTION section, PMI_ADDRESS_SPACE space, uint64_t *baseInOut,
                            uint64_t offset, uint64_t *viewSizeInOut, ULONG protect)
{
    if (section->image != 0)
    {
        if (offset != 0)
        {
            return STATUS_INVALID_PARAMETER; /* image subrange views: not M5 */
        }
        return MipMapImageView(section, space, baseInOut, viewSizeInOut);
    }

    /* Data view: offset/size against the section (Wine's virtual_map_section
     * shape, pinned by anonymous_section.c). */
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

    uint64_t base = *baseInOut;
    if (base != 0)
    {
        if (!MiViewRangeIsFree(space, base, size))
        {
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }
    else
    {
        base = MiFindFreeViewBase(space, size);
        if (base == 0)
        {
            return STATUS_NO_MEMORY;
        }
    }

    ObfReferenceObject(section); /* the view's pin, owned by the VAD */
    PMI_VAD vad = MiCreateMappedVad(space, base, size, protect, MEM_MAPPED, section, privateCopy);
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
        MiCommitFrameInVad(space, vad, base + (uint64_t)i * PAGE_SIZE, frame, protect);
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
        status = IopBuildSectionBacking(file, secFlags, protect, &backing);
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
            IopSectionBackingReleased(backing.fileObject);
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
        memcpy(body, &scratch, sizeof(scratch));
    }
    else
    {
        MipDeleteSection(&scratch); /* OBJ_OPENIF hit an existing object, or failure */
        if (haveBacking)
        {
            IopSectionBackingReleased(backing.fileObject);
        }
    }
    if (haveBacking)
    {
        ObDereferenceObject(backing.fileObject); /* IopBuildSectionBacking's reference */
    }
    return status;
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

    status = MiMapViewOfSection(sectionBody, &process->addressSpace, &base,
                                (uint64_t)offset.QuadPart, &viewSize, protect);
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
