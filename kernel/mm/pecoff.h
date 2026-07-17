/* kernel/mm/pecoff.h — PE/COFF image parsing for SEC_IMAGE sections (M5,
 * docs/04). x86_64 PE32+ only (ADR 0006).
 *
 * The on-disk format comes from the generated abi/ntimage.h (Wine's winnt.h
 * — the same layout Microsoft's PE/COFF specification documents); this
 * header is the parsed, validated summary an image section carries. The
 * validation statuses at the boundary (STATUS_INVALID_IMAGE_NOT_MZ for a
 * non-MZ file) are pinned by tests/ntapi/sem_mm/image_section.c.
 */
#ifndef PROSKRNL_KERNEL_MM_PECOFF_H
#define PROSKRNL_KERNEL_MM_PECOFF_H

#include <stdint.h>

#include "abi/ntdef.h"
#include "abi/ntimage.h"

#define MI_IMAGE_MAX_SEGMENTS 16

/* One PE section ("segment" here — `section` is taken by the Ob object). */
typedef struct
{
    ULONG virtualAddress; /* RVA, section-aligned */
    ULONG virtualSize;    /* bytes occupied in memory */
    ULONG rawOffset;      /* file offset of initialized data */
    ULONG rawSize;        /* bytes of initialized data in the file */
    ULONG protect;        /* PAGE_* from the section characteristics */
} MI_IMAGE_SEGMENT;

typedef struct
{
    uint64_t preferredBase;
    uint64_t sizeOfImage; /* page-rounded */
    uint64_t stackReserve;
    uint64_t stackCommit;
    ULONG sizeOfHeaders;
    ULONG entryRva;
    ULONG relocRva; /* 0 = no relocation directory */
    ULONG relocSize;
    ULONG checksum;
    ULONG fileSize;
    USHORT machine;
    USHORT characteristics;
    USHORT dllCharacteristics;
    USHORT subsystem;
    USHORT subsystemMajor;
    USHORT subsystemMinor;
    USHORT osMajor;
    USHORT osMinor;
    BOOLEAN containsCode;
    BOOLEAN relocsStripped;
    ULONG segmentCount;
    MI_IMAGE_SEGMENT segments[MI_IMAGE_MAX_SEGMENTS];
} MI_IMAGE_INFO;

/* Parse + validate a PE image from its raw file bytes. */
NTSTATUS MiParseImage(const void *data, uint64_t size, MI_IMAGE_INFO *info);

#endif /* PROSKRNL_KERNEL_MM_PECOFF_H */
