/* fs/fat32/fat.h — FAT32 over virtio-blk (M6, docs/02, docs/04).
 *
 * On-disk format written from the Microsoft FAT specification ("Microsoft
 * FAT Specification", Aug 30 2005 — the fatgen103 successor; sections cited
 * inline per Art. 4/G8; provenance: public spec, docs/11). The volume is
 * found via a minimal GPT scan (UEFI Specification 2.10 §5).
 *
 * Internals (all free, Art. 3): the whole FAT lives in pool and is written
 * through per touched sector; file data lives in the unified page cache
 * (kernel/mm/pagecache.h) and is written through on every NtWriteFile;
 * directories are read/written sector-at-a-time. One FAT_FCB per on-disk
 * file carries the NT share/lock/delete state (IO_FCB) the Io layer
 * accounts against.
 */
#ifndef PROSKRNL_FS_FAT32_FAT_H
#define PROSKRNL_FS_FAT32_FAT_H

#include <stdint.h>

#include "abi/ntdef.h"
#include "kernel/io/vfs.h"
#include "kernel/lib/list.h"
#include "kernel/mm/pagecache.h"

#define FAT_SECTOR_SIZE  512
#define FAT_END_OF_CHAIN 0x0FFFFFF8u /* masked value >= this = end (spec §4 entry table) */
#define FAT_ENTRY_MASK   0x0FFFFFFFu /* high 4 bits reserved (spec §4) */

/* Directory-entry attribute bits (spec §6, DIR_Attr). */
#define FAT_ATTR_READ_ONLY      0x01
#define FAT_ATTR_HIDDEN         0x02
#define FAT_ATTR_SYSTEM         0x04
#define FAT_ATTR_VOLUME_ID      0x08
#define FAT_ATTR_DIRECTORY      0x10
#define FAT_ATTR_ARCHIVE        0x20
#define FAT_ATTR_LONG_NAME      0x0F /* spec §6: RO|HID|SYS|VOLID */
#define FAT_ATTR_LONG_NAME_MASK 0x3F /* spec §7: membership test mask */

typedef struct FAT_VOLUME
{
    uint64_t partitionFirstLba; /* absolute disk LBA of the FAT volume */
    ULONG bytesPerSector;       /* == FAT_SECTOR_SIZE (BPB validated) */
    ULONG sectorsPerCluster;
    ULONG reservedSectors;
    ULONG fatCount;
    ULONG fatSizeSectors;
    ULONG rootCluster;
    ULONG totalSectors;
    ULONG firstDataSector;    /* volume-relative (spec §6.7) */
    ULONG clusterCount;       /* CountofClusters (spec §3.5) */
    ULONG volumeSerial;       /* BS_VolID (spec §3.3, offset 67) */
    WCHAR volumeLabel[11];    /* BS_VolLab (spec §3.3, offset 71), trailing
                               * spaces stripped; empty for "NO NAME" */
    USHORT volumeLabelLength; /* bytes */
    uint32_t *fat;            /* the whole first FAT in pool; write-through */
    ULONG nextFreeHint;       /* allocation cursor */
    ULONG fsInfoSector;       /* BPB_FSInfo (spec §3.3 offset 48); 0 = absent */
    ULONG freeClusters;       /* live count, maintained by FatSetFatEntry */
    LIST_ENTRY fcbList;       /* live FAT_FCBs, for the one-FCB-per-file rule */
    struct FAT_FCB *root;     /* the root directory's FCB (never dies) */
} FAT_VOLUME, *PFAT_VOLUME;

typedef struct FAT_FCB
{
    IO_FCB header; /* MUST be first: the Io layer's per-file state */
    PFAT_VOLUME volume;
    LONG referenceCount;    /* open FILE_OBJECTs + section backings + parent pins */
    struct FAT_FCB *parent; /* referenced; 0 for the root */
    LIST_ENTRY volumeEntry;

    BOOLEAN isDirectory;
    BOOLEAN isRoot;
    ULONG parentDirCluster; /* identity key: where our SFN entry lives... */
    ULONG dirEntryIndex;    /* ...and its 32-byte slot index in that directory */
    /* ...and whether that key still names US. A deleted entry's slot is
     * immediately reusable (deletion writes 0xE5 in place, spec §6.1), so a
     * new file landing on it would otherwise ALIAS this FCB through the
     * identity lookup -- inheriting its isDirectory, its name, its cached
     * size and its page cache (docs/review-2026-07 §12). Set when the entry
     * goes away (delete, or a rename's replace); such an FCB is never
     * matched again, only released by its remaining references. */
    BOOLEAN entryDeleted;
    ULONG lfnStartIndex;    /* first slot of our LFN run (== dirEntryIndex if none) */

    ULONG firstCluster; /* 0 = no data allocated yet (spec §6.7) */
    uint64_t fileSize;
    UCHAR attributes;            /* FAT_ATTR_* */
    USHORT writeTime, writeDate; /* spec §6.3 encodings */
    USHORT createTime, createDate;
    UCHAR createTimeTenth;
    USHORT accessDate;

    UNICODE_STRING longName; /* pool copy of the display name (case kept) */
    MI_PAGE_CACHE cache;     /* file data (files only) */
    BOOLEAN cacheLoaded;
    /* Every live FILE_OBJECT bound to this FCB, data access or not (the
     * share-slot openCount tracks only data-access opens). Wine's oracle
     * defers a delete-on-close unlink while ANY open of the inode remains
     * (server/fd.c: the unlink runs when the fd list empties), so the FS
     * must know when the truly-last open leaves. */
    LONG openObjectCount;
    BOOLEAN unlinkPending; /* a delete intent deferred past its own close */
} FAT_FCB, *PFAT_FCB;

/* The directory cluster half of the FCB identity key: the cluster whose
 * chain holds `dir`'s entries (FatGetFcb dedups on it; spec §6.7 makes the
 * root's own first cluster the BPB's rootCluster). */
static inline ULONG FatDirCluster(PFAT_FCB dir)
{
    return dir->isRoot ? dir->volume->rootCluster : dir->firstCluster;
}

/* The 64-bit NT file id (FileInternalInformation IndexNumber, IO_FILE_INFO
 * fileId): the FCB identity key (directory cluster, SFN slot) serialized —
 * the SAME pair FatGetFcb dedups FCBs on, so id equality and one-FCB-per-file
 * can never disagree. Stable while the file exists: deletion marks slots
 * 0xE5 in place, never compacts (spec §6.1). The root has no directory
 * entry; its key is (0, 0) and so its id is 0. */
static inline uint64_t FatFileId(ULONG dirCluster, ULONG sfnSlot)
{
    return ((uint64_t)dirCluster << 32) | sfnSlot;
}

/* --- fat.c: mount, FAT chains, cluster allocation, sector I/O -------------- */

/* Scan the GPT boot disk, mount the first FAT32 data partition. */
NTSTATUS FatMountBootVolume(PFAT_VOLUME *volumeOut);

/* The volume's identity + geometry raw facts (IO_VFS_OPS.QueryVolumeInfo);
 * free units counted live off the in-pool FAT. */
NTSTATUS FatQueryVolumeInfo(PFAT_VOLUME volume, IO_VOLUME_INFO *info);

/* CUI-5: set the volume label (BS_VolLab + the root volume-id entry). */
NTSTATUS FatSetVolumeLabel(PFAT_VOLUME volume, const WCHAR *label, ULONG labelBytes);

/* Volume-relative sector I/O. */
NTSTATUS FatReadSector(PFAT_VOLUME volume, uint64_t sector, void *buffer);
NTSTATUS FatWriteSector(PFAT_VOLUME volume, uint64_t sector, const void *buffer);

/* Is `cluster` a real data cluster of this volume, i.e. in [2, count+2)?
 * THE authority for the question: every cluster number that arrives from the
 * media -- a FAT entry, a directory entry's DIR_FstClus -- passes through
 * here before it is used to index anything. */
BOOLEAN FatIsDataCluster(PFAT_VOLUME volume, ULONG cluster);

/* First volume-relative sector of cluster N (spec §6.7). */
uint64_t FatClusterToSector(PFAT_VOLUME volume, ULONG cluster);

/* FAT chain primitives over the in-pool FAT (write-through both copies). */
ULONG FatGetNextCluster(PFAT_VOLUME volume, ULONG cluster); /* 0 = end/bad */
NTSTATUS FatSetFatEntry(PFAT_VOLUME volume, ULONG cluster, ULONG value);
NTSTATUS FatAllocateCluster(PFAT_VOLUME volume, ULONG previousOrZero, ULONG *clusterOut);
/* Release a whole cluster chain. Returns the first FatSetFatEntry failure
 * (the walk still releases the rest), so a caller whose user is waiting on a
 * status can report one. */
NTSTATUS FatFreeChain(PFAT_VOLUME volume, ULONG firstCluster);

/* Rewrite the FSInfo sector's free count + next-free hint (spec §5). Best
 * effort: FSInfo is a hint and the FAT is authoritative, so a failure never
 * fails the operation that triggered it. */
void FatUpdateFsInfo(PFAT_VOLUME volume);
/* The Nth cluster of a chain (0-based); 0 when the chain is shorter. */
ULONG FatWalkChain(PFAT_VOLUME volume, ULONG firstCluster, ULONG index);
ULONG FatChainLength(PFAT_VOLUME volume, ULONG firstCluster);

/* --- dir.c: directory entries, LFN, lookup, create, delete ----------------- */

/* Read/write the 32-byte entry at `slot` of the directory `dir`. */
NTSTATUS FatReadDirSlot(PFAT_FCB dir, ULONG slot, unsigned char entry[32]);
NTSTATUS FatWriteDirSlot(PFAT_FCB dir, ULONG slot, const unsigned char entry[32]);

/* Look `component` (case-insensitive; long or 8.3 name) up in `dir`.
 * Returns the referenced FCB. */
NTSTATUS FatLookup(PFAT_FCB dir, const UNICODE_STRING *component, PFAT_FCB *fcbOut);

/* Create a file or directory named `component` in `dir` (assumes it does
 * not exist). Returns the referenced new FCB. */
NTSTATUS FatCreateEntry(PFAT_FCB dir, const UNICODE_STRING *component, BOOLEAN directory,
                        UCHAR attributes, PFAT_FCB *fcbOut);

/* Remove `fcb`'s directory entries + data chain (caller checked the NT
 * rules); the FCB stays alive until its references drop. */
NTSTATUS FatDeleteEntry(PFAT_FCB fcb);

/* CUI-5 rename primitives: write one name's LFN run + short entry into
 * `dir` (shortEntry carries metadata in; its name bytes are replaced), and
 * free a slot run without touching the data chain. */
NTSTATUS FatWriteEntrySlots(PFAT_FCB dir, const UNICODE_STRING *component,
                            unsigned char shortEntry[32], ULONG *sfnSlotOut, ULONG *lfnStartOut);
NTSTATUS FatFreeEntrySlots(PFAT_FCB dir, ULONG lfnStart, ULONG sfnSlot);
/* Point a moved directory's ".." entry at its new parent. */
NTSTATUS FatRewriteDotDot(PFAT_FCB dir, PFAT_FCB newParent);
/* Move fcb's directory entry under (newParent, newName), rewriting the live
 * FCB's identity key in place (caller checked the NT replace rules). */
NTSTATUS FatRenameEntry(PFAT_FCB fcb, PFAT_FCB newParent, const UNICODE_STRING *newName);

/* Is the directory empty ("." / ".." only)? */
NTSTATUS FatIsDirectoryEmpty(PFAT_FCB dir, BOOLEAN *empty);

/* Enumerate: read the logical entry at *slot (skipping free/volume-id
 * slots, assembling LFN runs), advance *slot past it. */
NTSTATUS FatReadDirectoryEntry(PFAT_FCB dir, ULONG *slot, IO_DIR_ENTRY *out);

/* Persist fcb's metadata (size, first cluster, attributes, times) into its
 * SFN slot. No-op for the root. */
NTSTATUS FatFlushFcbMetadata(PFAT_FCB fcb);

/* FCB reference management (fat.c). */
void FatReferenceFcb(PFAT_FCB fcb);
void FatDereferenceFcb(PFAT_FCB fcb);
/* Find-or-create the FCB for the entry at (dir, slot). */
NTSTATUS FatGetFcb(PFAT_FCB dir, ULONG sfnSlot, ULONG lfnStartSlot, const unsigned char sfn[32],
                   const UNICODE_STRING *longName, PFAT_FCB *out);

/* --- file.c: data I/O, the IO_VFS_OPS table -------------------------------- */

extern const IO_VFS_OPS FatVfsOps;

/* Load the file's bytes into its page cache (idempotent). */
NTSTATUS FatEnsureCache(PFAT_FCB fcb);
/* Write cache bytes [offset, offset+length) through to disk. */
NTSTATUS FatWritebackRange(PFAT_FCB fcb, uint64_t offset, uint64_t length);
/* Grow/shrink: clusters + directory entry + cache. */
NTSTATUS FatSetFileSize(PFAT_FCB fcb, uint64_t newSize);

/* The geometry FatValidateBpb derives from a boot sector. */
typedef struct _FAT_BPB_GEOMETRY
{
    ULONG bytesPerSector;
    ULONG sectorsPerCluster;
    ULONG reservedSectors;
    ULONG fatCount;
    ULONG fatSizeSectors;
    ULONG totalSectors;
    ULONG firstDataSector;
    ULONG clusterCount;
    ULONG rootCluster;
} FAT_BPB_GEOMETRY, *PFAT_BPB_GEOMETRY;

/* Validate a 512-byte boot sector and derive the volume geometry from it, or
 * return STATUS_UNRECOGNIZED_VOLUME. Split out of FatMountBootVolume so the
 * hostile shapes can be pinned directly (tests/kmt/fat_interop.c): the BPB is
 * wholly attacker-controlled input, and every cluster bound the rest of
 * fs/fat32 asserts is derived from it. `boot` must be FAT_SECTOR_SIZE bytes;
 * the 0x55AA signature is the caller's check, not this one's. */
NTSTATUS FatValidateBpb(const unsigned char *boot, PFAT_BPB_GEOMETRY out);

/* NT time <-> FAT date/time (spec §6.3); fat.c. */
LARGE_INTEGER FatTimeToNtTime(USHORT fatDate, USHORT fatTime, UCHAR tenths);
void FatNtTimeToFatTime(LARGE_INTEGER ntTime, USHORT *fatDate, USHORT *fatTime);
/* The kernel's current NT time (no RTC yet: a fixed base + uptime). */
LARGE_INTEGER FatCurrentNtTime(void);

#endif /* PROSKRNL_FS_FAT32_FAT_H */
