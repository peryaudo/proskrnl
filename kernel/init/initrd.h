/* kernel/init/initrd.h — the M5 seed RAM-disk: a trivial read-only "file
 * system" over Limine boot modules (docs/02: "Seed a RAM-disk + trivial
 * read-only FS first", docs/04).
 *
 * Purpose: break the Mm↔Io circular dependency. Sections (M5) need files to
 * back image and data mappings, but the I/O manager and a real filesystem
 * are M6 — so until then a "file" is a named, physically contiguous,
 * page-aligned blob Limine loaded for us. The internal shape is free (Art. 1:
 * nothing here is user-observable); the M6 FILE_OBJECT will subsume it.
 */
#ifndef PROSKRNL_KERNEL_INIT_INITRD_H
#define PROSKRNL_KERNEL_INIT_INITRD_H

#include <stdint.h>

#include "abi/ntdef.h"

typedef struct
{
    const char *name; /* basename of the module path (pool copy) */
    const void *data; /* module contents through the HHDM; page-aligned */
    uint64_t size;    /* exact byte size */

    /* The file's resident pages — the M5 seed of the unified page cache
     * (docs/04 mm/pagecache.c). OWNED AND FILLED BY Mm (mm/section.c) on
     * first mapping: fresh frames, tail page zero-filled past EOF, shared by
     * every view of every section over this file. 0 until then. Reads go
     * through the cache once it exists, so a mapped view and a read can
     * never disagree (Art. 3: no eviction — the cache never shrinks). */
    uint64_t *pageCache;
} KI_RAMDISK_FILE, *PKI_RAMDISK_FILE;

/* Register one boot module as a RAM-disk file. `path` may carry directories
 * ("boot():/sample.dat" or "/sample.dat"); the stored name is the basename.
 * Returns the registered file (or 0 when the table is full / out of pool). */
PKI_RAMDISK_FILE KiRegisterRamdiskFile(const char *path, const void *data, uint64_t size);

/* Look a file up by (case-sensitive) basename. 0 when absent. */
PKI_RAMDISK_FILE KiFindRamdiskFile(const char *name);

/* The basename a path registers under. */
const char *KiRamdiskBasename(const char *path);

/* Read [offset, offset+length) into `buffer`, short reads at EOF. Reads come
 * from the page cache when Mm has built it, else from the module bytes. */
NTSTATUS KiReadRamdiskFile(const KI_RAMDISK_FILE *file, uint64_t offset, void *buffer,
                           uint64_t length, uint64_t *bytesRead);

#endif /* PROSKRNL_KERNEL_INIT_INITRD_H */
