/* kernel/mm/section.h — section objects: anonymous, file-backed, and PE
 * image (M5; file-backed generalized over the M6 I/O manager).
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
 *  - File-backed data sections map the file's unified page cache
 *    (mm/pagecache.h) — the same frames NtReadFile/NtWriteFile copy through
 *    (M6), so mapped-view/read-write consistency is structural.
 *  - SEC_IMAGE sections parse the PE up front (pecoff.h) from a contiguous
 *    raw-bytes snapshot; each map is a full private copy (Art. 3) with
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
#include "kernel/mm/pagecache.h"
#include "kernel/init/initrd.h"

/* What a file-backed section is built over (filled by the caller: the
 * RAM-disk shim below, or the M6 Io manager for real File objects). */
typedef struct
{
    PMI_PAGE_CACHE cache; /* data sections: the frames views map */
    const void *rawData;  /* SEC_IMAGE: contiguous raw file bytes */
    uint64_t rawSize;
    BOOLEAN ownsRawData; /* ownership of rawData passes to Mm ON CALL —
                          * freed on failure too */
    PVOID fileObject;    /* Ob File body the section pins (may be 0);
                          * referenced on success */
    BOOLEAN writable;    /* the backing handle granted FILE_WRITE_DATA */
    PVOID fcb;           /* CUI-9: the on-disk-file identity image masters
                          * key on (IO_FCB — one per file however many
                          * opens/sections; the ramdisk path passes the
                          * KI_RAMDISK_FILE instead) */
} MI_SECTION_BACKING;

/* CUI-9 (docs/17 §4, docs/03 "CUI-9 COW notes"): ONE shared,
 * already-relocated image master per (identity, base) — the frames every
 * matching SEC_IMAGE view maps. `identity` is the IO_FCB for file-backed
 * images (pointer equality — the IoIsSameUnderlyingFile precedent) or the
 * PKI_RAMDISK_FILE for boot modules; `base` is in the key because a
 * different base means different relocation fixups (docs/17 §6F).
 *
 * Ownership (the G11 audit): every bound VAD holds one refCount, taken in
 * MipMapImageView, released by MiUnlinkAndFreeVad through
 * MiDereferenceImageMaster; the LAST release unlinks the master and frees
 * its frames. There is no idle cache — master lifetime is contained in the
 * union of its views' lifetimes — so `identity` can never dangle: a live
 * view pins its section, the section pins its File object, and the File
 * pins the FCB (ramdisk files are immortal). The fault path never parks
 * (no kernel preemption, no blocking allocation), so a process dying at
 * the earliest legal moment still runs the ordinary VAD teardown. */
typedef struct MI_IMAGE_MASTER
{
    LIST_ENTRY listEntry; /* MipImageMasterList (section.c) */
    PVOID identity;
    uint64_t base;
    ULONG pageCount;
    uint64_t *frames; /* owned, one per page; 0 = never committed */
    LONG refCount;    /* one per bound VAD */
} MI_IMAGE_MASTER, *PMI_IMAGE_MASTER;

/* The VAD-teardown seam (virtual.c calls these; bodies in section.c). */
void MiDereferenceImageMaster(PVOID master);
uint64_t MiImageMasterFrame(PVOID master, ULONG index);
/* The sharing metric (docs/17 §8: "a non-sharing implementation passes
 * every semantic test", so the win is pinned as a machine verdict). */
void MiGetImageMasterStats(ULONG *builds, ULONG *hits, ULONG *live, uint64_t *masterFrames);

typedef struct MI_SECTION
{
    ULONG attributes;     /* SEC_COMMIT / SEC_FILE / SEC_IMAGE as NT reports them */
    ULONG pageProtection; /* creation protection */
    uint64_t size;        /* section byte size (page-rounded when anonymous) */
    ULONG pageCount;
    uint64_t *frames;     /* anonymous sections: one owned frame per page */
    PMI_PAGE_CACHE cache; /* file-backed data sections: the file's page cache */
    const void *rawData;  /* image sections: raw file bytes for copy/reloc */
    uint64_t rawSize;
    BOOLEAN ownsRawData;
    PVOID fileObject; /* referenced backing File object body; 0 = none */
    /* Did the FILE HANDLE this section was created from grant write? A
     * writable view of a file-backed section is a write to the file (with
     * immediate writeback, Art. 3), so a section built over a read-only
     * handle may only be mapped read-only or write-copy. The creation
     * PROTECTION is deliberately NOT the gate: the oracle allows a
     * PAGE_READONLY section over a read-write handle to be mapped
     * PAGE_READWRITE, and denies the same map over a read-only handle
     * (verified against the pinned Wine; sem_mm/section_protect). */
    BOOLEAN backingWritable;
    MI_IMAGE_INFO *image; /* SEC_IMAGE: parsed PE metadata (pool) */
    PVOID masterIdentity; /* SEC_IMAGE: the (identity, base) key half the
                           * image masters use — the backing's fcb */
} MI_SECTION, *PMI_SECTION;

extern OBJECT_TYPE MiSectionType;

/* Kernel-internal creation (unnamed, creator-referenced) over the M5
 * RAM-disk: what Ps uses to run boot modules and what kmt exercises.
 * `file` backs SEC_IMAGE and file data sections; 0 with SEC_COMMIT is
 * anonymous. */
NTSTATUS MiCreateSection(const LARGE_INTEGER *maximumSize, ULONG pageProtection, ULONG attributes,
                         PKI_RAMDISK_FILE file, PMI_SECTION *sectionOut);

/* General form over an explicit backing (the M6 NtCreateFile path). */
NTSTATUS MiCreateBackedSection(const LARGE_INTEGER *maximumSize, ULONG pageProtection,
                               ULONG attributes, const MI_SECTION_BACKING *backing,
                               PMI_SECTION *sectionOut);

/* Borrow an image section's raw file bytes (the create-time snapshot, or a
 * transient resident-cache re-read after the first master bind released
 * it). *tempOut non-0 means the caller frees via MiReleaseImageRawBytes.
 * The one re-source authority — the master build and Ps's export lookups
 * both resolve here. */
NTSTATUS MiAcquireImageRawBytes(PMI_SECTION section, const void **rawOut, void **tempOut);
void MiReleaseImageRawBytes(void *temp);

/* Map a view (data or image) into `space`. *baseInOut = 0 picks an address
 * (an image prefers its header base; taken -> relocated + the success status
 * STATUS_IMAGE_NOT_AT_BASE). `offset`/`viewSize` follow NtMapViewOfSection
 * (images ignore both at M5). `protect` is the view protection for data
 * sections (images carry per-PE-section protection). */
NTSTATUS MiMapViewOfSection(PMI_SECTION section, PMI_ADDRESS_SPACE space, uint64_t *baseInOut,
                            uint64_t offset, uint64_t *viewSizeInOut, ULONG protect);

/* CUI-7 constrained form (NtMapViewOfSectionEx placement limits, inclusive
 * of the last byte; zeros mean unconstrained). `machine` is the caller's
 * MemExtendedParameterImageMachine: zero is unconstrained, and a non-zero
 * value the IMAGE does not declare refuses STATUS_NOT_SUPPORTED (a data
 * section ignores it). The classic entry delegates here — one mapping
 * engine (Art. 11). */
NTSTATUS MiMapViewOfSectionEx(PMI_SECTION section, PMI_ADDRESS_SPACE space, uint64_t *baseInOut,
                              uint64_t offset, uint64_t *viewSizeInOut, ULONG protect,
                              uint64_t limitLow, uint64_t limitHigh, USHORT machine);

#endif /* PROSKRNL_KERNEL_MM_SECTION_H */
