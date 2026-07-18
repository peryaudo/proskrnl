/* kernel/mm/pecoff.c — PE/COFF image parsing (M5). See pecoff.h.
 *
 * Behaviour reference: Wine's server/mapping.c get_image_params and
 * dlls/ntdll/unix/virtual.c map_image_into_view (reference for behaviour,
 * not code) + the public PE/COFF specification
 * (https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
 * Only the boundary-shaped
 * subset is validated: PE32+ (x86_64), page-aligned sections. Native-
 * subsystem flat images (SectionAlignment < page) stay unimplemented.
 */
#include "kernel/mm/pecoff.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/virtual.h"
#include "kernel/lib/string.h"

#include "abi/ntmmapi.h"
#include "abi/ntstatus.h"

static ULONG MipSegmentProtect(ULONG characteristics)
{
    /* The NT mapping of section characteristics to page protection: writable
     * image pages are WRITECOPY-flavoured (each view is a private full copy
     * under Art. 3, so the copy-on-write name is already satisfied). */
    BOOLEAN r = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    BOOLEAN w = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    BOOLEAN x = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    if (x)
    {
        if (w)
        {
            return PAGE_EXECUTE_WRITECOPY;
        }
        return r ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
    }
    if (w)
    {
        return PAGE_WRITECOPY;
    }
    return r ? PAGE_READONLY : PAGE_NOACCESS;
}

NTSTATUS MiParseImage(const void *data, uint64_t size, MI_IMAGE_INFO *info)
{
    const char *bytes = data;

    if (size < sizeof(IMAGE_DOS_HEADER))
    {
        return STATUS_INVALID_IMAGE_NOT_MZ;
    }
    const IMAGE_DOS_HEADER *dos = data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return STATUS_INVALID_IMAGE_NOT_MZ;
    }
    if (dos->e_lfanew == 0 || (uint64_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > size)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)(bytes + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        return STATUS_INVALID_IMAGE_FORMAT; /* x86_64 PE32+ only (ADR 0006) */
    }
    if (nt->OptionalHeader.SectionAlignment < PAGE_SIZE ||
        (nt->OptionalHeader.SectionAlignment & (nt->OptionalHeader.SectionAlignment - 1)) != 0)
    {
        return STATUS_INVALID_IMAGE_FORMAT; /* flat native images: not M5 */
    }
    if ((nt->OptionalHeader.ImageBase & (MI_ALLOCATION_GRANULARITY - 1)) != 0)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    if (nt->FileHeader.NumberOfSections == 0 ||
        nt->FileHeader.NumberOfSections > MI_IMAGE_MAX_SEGMENTS)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    const IMAGE_SECTION_HEADER *sections =
        (const IMAGE_SECTION_HEADER *)((const char *)&nt->OptionalHeader +
                                       nt->FileHeader.SizeOfOptionalHeader);
    uint64_t sectionTableEnd =
        (uint64_t)((const char *)(sections + nt->FileHeader.NumberOfSections) - bytes);
    if (sectionTableEnd > size || sectionTableEnd > nt->OptionalHeader.SizeOfHeaders)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    memset(info, 0, sizeof(*info));
    info->preferredBase = nt->OptionalHeader.ImageBase;
    info->sizeOfImage = (nt->OptionalHeader.SizeOfImage + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1ULL);
    info->sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
    info->entryRva = nt->OptionalHeader.AddressOfEntryPoint;
    info->machine = nt->FileHeader.Machine;
    info->characteristics = nt->FileHeader.Characteristics;
    info->dllCharacteristics = nt->OptionalHeader.DllCharacteristics;
    info->subsystem = nt->OptionalHeader.Subsystem;
    info->subsystemMajor = nt->OptionalHeader.MajorSubsystemVersion;
    info->subsystemMinor = nt->OptionalHeader.MinorSubsystemVersion;
    info->osMajor = nt->OptionalHeader.MajorOperatingSystemVersion;
    info->osMinor = nt->OptionalHeader.MinorOperatingSystemVersion;
    info->stackReserve = nt->OptionalHeader.SizeOfStackReserve;
    info->stackCommit = nt->OptionalHeader.SizeOfStackCommit;
    info->checksum = nt->OptionalHeader.CheckSum;
    info->fileSize = (ULONG)size;
    info->relocsStripped = (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0;

    if (info->sizeOfHeaders > size || info->sizeOfHeaders > info->sizeOfImage ||
        info->sizeOfImage == 0)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
    {
        const IMAGE_DATA_DIRECTORY *dir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (dir->Size != 0 && dir->VirtualAddress != 0 && dir->VirtualAddress < info->sizeOfImage &&
            dir->Size <= info->sizeOfImage - dir->VirtualAddress)
        {
            info->relocRva = dir->VirtualAddress;
            info->relocSize = dir->Size;
        }
    }

    /* Segments must sit above the headers, page-aligned, ascending and
     * non-overlapping — the map path commits every image page exactly once. */
    uint64_t nextFreeRva = (info->sizeOfHeaders + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1ULL);

    info->segmentCount = nt->FileHeader.NumberOfSections;
    for (ULONG i = 0; i < info->segmentCount; i++)
    {
        const IMAGE_SECTION_HEADER *sec = &sections[i];
        MI_IMAGE_SEGMENT *seg = &info->segments[i];
        seg->virtualAddress = sec->VirtualAddress;
        seg->virtualSize = sec->Misc.VirtualSize != 0 ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        seg->rawOffset = sec->PointerToRawData;
        seg->rawSize = sec->SizeOfRawData;
        seg->protect = MipSegmentProtect(sec->Characteristics);
        if (sec->Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE))
        {
            info->containsCode = TRUE;
        }

        if ((seg->virtualAddress & (PAGE_SIZE - 1)) != 0 ||
            seg->virtualAddress >= info->sizeOfImage || seg->virtualSize == 0 ||
            seg->virtualSize > info->sizeOfImage - seg->virtualAddress ||
            seg->virtualAddress < nextFreeRva)
        {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        nextFreeRva =
            (seg->virtualAddress + seg->virtualSize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1ULL);
        if (seg->rawSize > seg->virtualSize)
        {
            seg->rawSize = seg->virtualSize; /* the rest is alignment padding */
        }
        if (seg->rawSize != 0 && (seg->rawOffset >= size || seg->rawSize > size - seg->rawOffset))
        {
            return STATUS_INVALID_IMAGE_FORMAT; /* truncated file */
        }
    }

    return STATUS_SUCCESS;
}
