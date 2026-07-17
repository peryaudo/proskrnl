/* kernel/mm/section.h — section objects: anonymous, file-backed, and PE
 * image (M5, docs/02).
 *
 * The boundary is NT's: a Section is an Ob object created/opened by
 * NtCreateSection/NtOpenSection, mapped and unmapped as views via
 * NtMapViewOfSection/NtUnmapViewOfSection, queried via NtQuerySection —
 * semantics pinned by tests/ntapi/sem_mm/{anonymous,image}_section.c on the
 * Wine oracle. The internals are the simplest correct thing (Art. 3):
 *
 *  - Anonymous SEC_COMMIT sections allocate ALL their (zeroed) frames at
 *    creation; every view maps those same frames — genuine sharing, no COW,
 *    no demand paging, nothing to page out.
 *  - File-backed sections run over the M5 RAM-disk: the file's pages live in
 *    its page cache (initrd.h), filled once, shared by every view, and read
 *    by KiReadRamdiskFile — mapped-view/read consistency is structural.
 *  - SEC_IMAGE sections parse the PE up front (pecoff.h); each map is a full
 *    private copy (Art. 3: "private/image mappings copy fully on map") with
 *    relocations applied when the preferred base is taken
 *    (STATUS_IMAGE_NOT_AT_BASE) and per-PE-section page protection.
 */
#ifndef PROSKRNL_KERNEL_MM_SECTION_H
#define PROSKRNL_KERNEL_MM_SECTION_H

#include "abi/ntdef.h"
#include "abi/ntmmapi.h"
#include "kernel/ob/ob.h"
#include "kernel/mm/virtual.h"
#include "kernel/mm/pecoff.h"
#include "kernel/init/initrd.h"

typedef struct
{
    ULONG attributes;     /* SEC_COMMIT / SEC_FILE / SEC_IMAGE as NT reports them */
    ULONG pageProtection; /* creation protection */
    uint64_t size;        /* section byte size (page-rounded when anonymous) */
    ULONG pageCount;
    uint64_t *frames;            /* data sections: one frame per page. Anonymous: owned
                                  * by the section; file-backed: the file's page cache
                                  * (owned by the RAM-disk file). 0 for images. */
    BOOLEAN ownsFrames;          /* the delete procedure frees `frames` */
    const KI_RAMDISK_FILE *file; /* backing file; 0 = pagefile-backed */
    MI_IMAGE_INFO *image;        /* SEC_IMAGE: parsed PE metadata (pool) */
} MI_SECTION, *PMI_SECTION;

extern OBJECT_TYPE MiSectionType;

/* Kernel-internal creation (unnamed, creator-referenced): what Ps uses to
 * build a process image and what the Nt surface funnels into. `file` backs
 * SEC_IMAGE and file data sections; 0 with SEC_COMMIT is anonymous. */
NTSTATUS MiCreateSection(const LARGE_INTEGER *maximumSize, ULONG pageProtection, ULONG attributes,
                         PKI_RAMDISK_FILE file, PMI_SECTION *sectionOut);

/* Map a view (data or image) into `space`. *baseInOut = 0 picks an address
 * (an image prefers its header base; taken -> relocated + the success status
 * STATUS_IMAGE_NOT_AT_BASE). `offset`/`viewSize` follow NtMapViewOfSection
 * (images ignore both at M5). `protect` is the view protection for data
 * sections (images carry per-PE-section protection). */
NTSTATUS MiMapViewOfSection(PMI_SECTION section, PMI_ADDRESS_SPACE space, uint64_t *baseInOut,
                            uint64_t offset, uint64_t *viewSizeInOut, ULONG protect);

#endif /* PROSKRNL_KERNEL_MM_SECTION_H */
