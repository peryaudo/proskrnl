/* kernel/mm/pecoff.h — PE/COFF image parsing for SEC_IMAGE sections (M5,
 * docs/04). x86_64 PE32+ only (ADR 0006).
 *
 * The on-disk format comes from the generated abi/ntimage.h (Wine's winnt.h
 * — the same layout Microsoft's PE/COFF specification documents:
 * https://learn.microsoft.com/en-us/windows/win32/debug/pe-format); this
 * header is the parsed, validated summary an image section carries. The
 * validation statuses at the boundary (STATUS_INVALID_IMAGE_NOT_MZ for a
 * non-MZ file) are pinned by tests/ntapi/sem_mm/image_section.c.
 */
#ifndef PROSKRNL_KERNEL_MM_PECOFF_H
#define PROSKRNL_KERNEL_MM_PECOFF_H

#include <stdint.h>

#include "abi/ntdef.h"
#include "abi/ntimage.h"

/* The Windows loader's own per-image section limit (Microsoft "PE Format",
 * COFF File Header / NumberOfSections: "the Windows loader limits the number
 * of sections to 96"). Wine's mingw-built PE dlls carry ~20 (debug sections
 * included), so the M5-era 16 was too small for the M7 Wine bring-up. */
#define MI_IMAGE_MAX_SEGMENTS 96

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
    ULONG exportRva; /* 0 = no export directory (M7: dispatcher lookup) */
    ULONG exportSize;
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

/* Resolve a named export to its RVA, reading from the image's RAW file bytes
 * (M7: the loader finds LdrInitializeThunk / KiUser{Exception,Apc}Dispatcher
 * in ntdll — or, for a native single-image client, in the image itself —
 * exactly as NT does). Works pre-map: RVAs in the export tables are converted
 * to file offsets via the parsed segment table, so the caller need not have
 * the (non-current) target address space mapped. Returns 0 if not found. */
uint32_t MiLookupImageExport(const void *rawData, uint64_t rawSize, const MI_IMAGE_INFO *info,
                             const char *name);

#endif /* PROSKRNL_KERNEL_MM_PECOFF_H */
