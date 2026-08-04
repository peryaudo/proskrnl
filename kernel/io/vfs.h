/* kernel/io/vfs.h — the internal Io<->filesystem interface (M6, docs/04:
 * "file_operations-style; FREE").
 *
 * Nothing here is user-observable (Art. 1): the NT contract lives in the
 * Nt* wrappers (kernel/io/ *.c); a filesystem implements this table plus the
 * IO_FCB header that carries the NT per-file state (share modes, byte-range
 * locks, delete-pending) the Io layer accounts for. No IRP, no stack
 * locations, no layering (docs/03).
 */
#ifndef PROSKRNL_KERNEL_IO_VFS_H
#define PROSKRNL_KERNEL_IO_VFS_H

#include <stdint.h>

#include "abi/ntdef.h"
#include "abi/ntioapi.h"
#include "kernel/lib/list.h"
#include "kernel/mm/pagecache.h"

struct FILE_OBJECT; /* kernel/io/io.h */
struct IO_DEVICE;   /* kernel/io/io.h */
struct KTHREAD;     /* kernel/ke/ke.h */

/* What a DeviceControl op needs to PEND an operation (CUI-3): the caller's
 * completion event handle and IOSB, captured into an IOP_PENDING_REQUEST by
 * IopPreparePendingRequest while still in the issuer's context
 * (kernel/io/async.c). Synchronous-only devices never look at it. */
typedef struct IO_CONTROL_CONTEXT
{
    HANDLE eventHandle;        /* optional completion event (0 = none) */
    PIO_STATUS_BLOCK userIosb; /* the caller's IOSB (probed writable) */
} IO_CONTROL_CONTEXT;

/* NT share-mode accounting state (the SHARE_ACCESS concept, kept internal).
 * Owned by the Io layer (kernel/io/file.c Io*ShareAccess). */
typedef struct
{
    ULONG openCount;
    ULONG readers, writers, deleters;
    ULONG sharedRead, sharedWrite, sharedDelete;
} IO_SHARE_ACCESS;

/* The per-file header every filesystem FCB embeds FIRST. One IO_FCB exists
 * per on-disk file however many times it is opened — exactly the NT shape
 * share modes and byte-range locks require. */
typedef struct IO_FCB
{
    IO_SHARE_ACCESS shareAccess;
    LIST_ENTRY lockList;   /* IO_FILE_LOCK, kernel/io/lock.c */
    BOOLEAN deletePending; /* FileDispositionInformation state */
    LONG sectionCount;     /* live sections backed by this file */
    /* Live SEC_IMAGE sections (a subset of sectionCount). While nonzero, an
     * open asking write access answers STATUS_SHARING_VIOLATION — the NT
     * running-image rule, and what the pinned oracle's image-mapping fd
     * enforces (wine server/fd.c sharing checks; pinned by
     * sem_mm/image_deny_write). CUI-9's shared masters depend on it: a file
     * mutating under a live relocated master would be cross-process
     * corruption (docs/17 §6F; docs/03 "CUI-9 COW notes"). */
    LONG imageSectionCount;
} IO_FCB, *PIO_FCB;

/* What GetInfo reports (the FS's raw facts; info-class shaping happens in
 * kernel/io/query.c). Times are NT time (100 ns since 1601). */
typedef struct
{
    LARGE_INTEGER creationTime;
    LARGE_INTEGER lastAccessTime;
    LARGE_INTEGER lastWriteTime;
    uint64_t endOfFile;
    uint64_t allocationSize;
    uint64_t fileId;      /* FileInternalInformation IndexNumber: unique and
                           * stable per on-disk file; 0 = the backend has no
                           * per-file identity (devices, the FAT root) */
    ULONG fileAttributes; /* FILE_ATTRIBUTE_* */
    BOOLEAN isDirectory;
} IO_FILE_INFO;

/* One directory entry out of ReadDirectory. */
typedef struct
{
    WCHAR name[256];
    USHORT nameLength; /* bytes */
    IO_FILE_INFO info;
} IO_DIR_ENTRY;

/* What QueryVolumeInfo reports (the FS's raw volume facts; info-class
 * shaping — truncation, Information accounting, short-buffer statuses —
 * happens in kernel/io/query.c). String lengths are bytes. */
typedef struct
{
    ULONG serialNumber;
    USHORT labelLength;
    WCHAR label[16];     /* FAT: at most 11 units (spec §6.4 volume label) */
    uint64_t totalUnits; /* allocation units (clusters) on the volume */
    uint64_t freeUnits;
    ULONG sectorsPerUnit;
    ULONG bytesPerSector;
    const WCHAR *fsName; /* static storage, e.g. WSTR("FAT32") */
    USHORT fsNameLength;
    ULONG fsAttributes; /* FILE_FS_ATTRIBUTE_INFORMATION.FileSystemAttributes */
    LONG maxComponentLength;
    BOOLEAN supportsObjects; /* Wine: TRUE exactly for NTFS */
} IO_VOLUME_INFO;

/* NOLINTBEGIN(readability-identifier-naming) — the dispatch slots below are
 * names of code, not runtime values, so they take the PascalCase of docs/15's
 * function row (and of the IRP_MJ_* operations they stand for), not the
 * camelCase of a data member. */
typedef struct IO_VFS_OPS
{
    /* Resolve `path` (relative to the volume root, or to relativeTo when
     * non-0; no leading backslash; empty = the root itself) and apply the
     * create disposition. Fills file->fsContext (the FCB) and
     * file->isDirectory; *information gets FILE_CREATED/OPENED/OVERWRITTEN.
     * Must call IoCheckShareAccess/IoSetShareAccess at the NT point: after
     * the existing file is found, before any overwrite side effect. */
    NTSTATUS(*Create)
    (struct IO_DEVICE *device, struct FILE_OBJECT *file, const UNICODE_STRING *path,
     struct FILE_OBJECT *relativeTo, ACCESS_MASK grantedAccess, ULONG shareAccess,
     ULONG fileAttributes, ULONG disposition, ULONG options, ULONG_PTR *information);

    /* Last handle to this open is gone (NT's IRP_MJ_CLEANUP moment): the Io
     * layer has already released share access and byte-range locks; the FS
     * performs delete-on-close/disposition deletion here. */
    void (*Cleanup)(struct FILE_OBJECT *file);

    /* Optional. The file's LAST section backing has just been released.
     * Only a filesystem that DEFERS work while a file is mapped needs this:
     * fat32 defers a delete-on-close (a mapped file cannot be unlinked), and
     * without a re-entry at this moment the deferred delete was simply
     * dropped, since nothing else calls into the FS when a section goes away
     * (docs/review-2026-07 §7). NOT Cleanup: no handle is closing here, so
     * the per-open bookkeeping must not run again. */
    void (*SectionsReleased)(struct FILE_OBJECT *file);

    /* Last reference to this open is gone: release the FCB. */
    void (*Close)(struct FILE_OBJECT *file);

    /* The file's page cache, loaded from disk on first use. Data files
     * only. */
    NTSTATUS (*GetCache)(struct FILE_OBJECT *file, PMI_PAGE_CACHE *cache);

    /* Write the cache's bytes [offset, offset+length) through to disk
     * (Art. 3: immediate writeback). */
    NTSTATUS (*WritebackRange)(struct FILE_OBJECT *file, uint64_t offset, uint64_t length);

    /* Grow/shrink the file (cluster allocation, directory entry, cache). */
    NTSTATUS (*SetEndOfFile)(struct FILE_OBJECT *file, uint64_t endOfFile);

    /* CUI-8: resolve and commit a data write's placement in ONE
     * serialization hold. Once a writer can park mid-syscall, an
     * append/extend decision made from a fileSize snapshot goes stale
     * across the park — two writers each "extending" truncated each
     * other's clusters through SetEndOfFile. This op re-reads the size
     * under the volume gate, resolves writeToEnd (append) to the CURRENT
     * end of file, and grows the file — never shrinks — when
     * offset+length runs past it. *offsetInOut carries the caller's
     * offset in and the resolved one out. NULL = the device's size facts
     * cannot change across a park (no blocking points anywhere in its
     * ops), so the caller may decide from GetCache's snapshot. */
    NTSTATUS(*PrepareWrite)
    (struct FILE_OBJECT *file, uint64_t *offsetInOut, ULONG length, BOOLEAN writeToEnd);

    NTSTATUS (*GetInfo)(struct FILE_OBJECT *file, IO_FILE_INFO *info);
    NTSTATUS (*SetBasic)(struct FILE_OBJECT *file, const FILE_BASIC_INFORMATION *basic);

    /* Mark/unmark delete-pending (checks: read-only file, non-empty
     * directory, live sections). */
    NTSTATUS (*SetDisposition)(struct FILE_OBJECT *file, BOOLEAN deleteFile);

    /* CUI-5 FileRenameInformation(Ex): move the open file to `path`
     * (volume-relative, or relative to the open directory `relativeTo` when
     * non-NULL), applying the NT replace rules for an existing target.
     * `renameFlags` carries the FILE_RENAME_* bits (abi/ntioapi.h). NULL =
     * the device cannot rename (streams). */
    NTSTATUS(*Rename)
    (struct FILE_OBJECT *file, struct FILE_OBJECT *relativeTo, const UNICODE_STRING *path,
     ULONG renameFlags);

    /* Read the directory entry at *cursor (an opaque FS position), advance
     * the cursor. STATUS_NO_MORE_FILES at the end. */
    NTSTATUS (*ReadDirectory)(struct FILE_OBJECT *file, ULONG *cursor, IO_DIR_ENTRY *entry);

    /* The file's volume-relative NT path ("\dir\file.txt"; "\" for the
     * root), written into `buffer` of `capacity` bytes; *lengthOut is the
     * full length in bytes even when truncated (STATUS_BUFFER_OVERFLOW). */
    NTSTATUS(*QueryName)
    (struct FILE_OBJECT *file, WCHAR *buffer, ULONG capacity, ULONG *lengthOut);

    /* The volume's identity and geometry, for the FileFsVolume/Size/
     * AttributeInformation classes. NULL = not a filesystem volume: those
     * classes are unbuilt for it and refuse with STATUS_NOT_IMPLEMENTED
     * (Art. 12 — the dispatcher's armed panic convicts a ring-3 caller that
     * reaches one). Wine's pipe/console server objects refuse them too
     * (server/named_pipe.c pipe_end_get_volume_info default arm), which
     * makes the oracle unbuilt here as well — so nothing pins it. */
    NTSTATUS (*QueryVolumeInfo)(struct IO_DEVICE *device, IO_VOLUME_INFO *info);

    /* CUI-5 NtSetVolumeInformationFile(FileFsLabelInformation): set the
     * volume label (labelBytes counts bytes; 0 clears it). NULL = not a
     * filesystem volume. */
    NTSTATUS(*SetVolumeLabel)
    (struct IO_DEVICE *device, const WCHAR *label, ULONG labelBytes);

    /* --- M9 optional device ops (NULL = the page-cache file behaviour) ----
     * Devices whose data is a live stream (npfs, condrv, the serial port)
     * implement these instead of GetCache. Buffers are kernel pool copies
     * (kernel/io/rw.c, ioctl.c bounce them) because these ops may block in
     * KeWaitFor* — the NT completion protocol is unchanged: the caller
     * writes the IOSB and signals only after the op returns (docs/19 §1:
     * the IOSB precedes every completion signal). */

    /* Read up to `length` bytes; may block until data or a peer state
     * change. *infoOut = bytes read (also on STATUS_BUFFER_OVERFLOW). */
    NTSTATUS (*Read)(struct FILE_OBJECT *file, void *buffer, ULONG length, ULONG_PTR *infoOut);

    /* Write `length` bytes; may block on quota. *infoOut = bytes written. */
    NTSTATUS(*Write)
    (struct FILE_OBJECT *file, const void *buffer, ULONG length, ULONG_PTR *infoOut);

    /* One NtDeviceIoControlFile/NtFsControlFile verb (both funnel here: the
     * NT split by device type is not observable through this boundary).
     * *infoOut = bytes placed in `output`. A verb on an asynchronous handle
     * may return STATUS_PENDING after parking an IOP_PENDING_REQUEST built
     * from `request` (kernel/io/async.c; CUI-3 npfs listen) — the Io layer
     * then leaves the caller's IOSB untouched. Everything else ignores
     * `request` and completes before returning (docs/19 §2). */
    NTSTATUS(*DeviceControl)
    (struct FILE_OBJECT *file, ULONG code, const void *input, ULONG inputLength, void *output,
     ULONG outputLength, ULONG_PTR *infoOut, const struct IO_CONTROL_CONTEXT *request);

    /* CUI-3: cancel-complete (STATUS_CANCELLED) every pending request this
     * FILE_OBJECT issued that matches the filter — `issuer` non-0 restricts
     * to that thread's requests (NtCancelIoFile), `userIosb` non-0 to the
     * request with that IOSB VA (NtCancelIoFileEx; compared, never
     * dereferenced). Returns how many were cancelled. NULL = the device
     * never pends, so there is never anything to cancel. */
    ULONG(*CancelPending)
    (struct FILE_OBJECT *file, struct KTHREAD *issuer, PIO_STATUS_BLOCK userIosb);

    /* FilePipeInformation / FilePipeLocalInformation (query), and
     * FilePipeInformation (set) — kernel/io/query.c routes the classes here
     * so the shapes stay next to the pipe state that fills them. */
    NTSTATUS(*QueryPipeInfo)
    (struct FILE_OBJECT *file, FILE_INFORMATION_CLASS informationClass, void *buffer, ULONG length,
     ULONG_PTR *infoOut);
    NTSTATUS (*SetPipeInfo)(struct FILE_OBJECT *file, const FILE_PIPE_INFORMATION *info);
} IO_VFS_OPS;
/* NOLINTEND(readability-identifier-naming) */

#endif /* PROSKRNL_KERNEL_IO_VFS_H */
