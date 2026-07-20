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

    NTSTATUS (*GetInfo)(struct FILE_OBJECT *file, IO_FILE_INFO *info);
    NTSTATUS (*SetBasic)(struct FILE_OBJECT *file, const FILE_BASIC_INFORMATION *basic);

    /* Mark/unmark delete-pending (checks: read-only file, non-empty
     * directory, live sections). */
    NTSTATUS (*SetDisposition)(struct FILE_OBJECT *file, BOOLEAN deleteFile);

    /* Read the directory entry at *cursor (an opaque FS position), advance
     * the cursor. STATUS_NO_MORE_FILES at the end. */
    NTSTATUS (*ReadDirectory)(struct FILE_OBJECT *file, ULONG *cursor, IO_DIR_ENTRY *entry);

    /* The file's volume-relative NT path ("\dir\file.txt"; "\" for the
     * root), written into `buffer` of `capacity` bytes; *lengthOut is the
     * full length in bytes even when truncated (STATUS_BUFFER_OVERFLOW). */
    NTSTATUS(*QueryName)
    (struct FILE_OBJECT *file, WCHAR *buffer, ULONG capacity, ULONG *lengthOut);

    /* --- M9 optional device ops (NULL = the page-cache file behaviour) ----
     * Devices whose data is a live stream (npfs, condrv, the serial port)
     * implement these instead of GetCache. Buffers are kernel pool copies
     * (kernel/io/rw.c, ioctl.c bounce them) because these ops may block in
     * KeWaitFor* — the NT completion protocol is unchanged: the caller
     * writes the IOSB and signals only after the op returns (Art. 3). */

    /* Read up to `length` bytes; may block until data or a peer state
     * change. *infoOut = bytes read (also on STATUS_BUFFER_OVERFLOW). */
    NTSTATUS (*Read)(struct FILE_OBJECT *file, void *buffer, ULONG length, ULONG_PTR *infoOut);

    /* Write `length` bytes; may block on quota. *infoOut = bytes written. */
    NTSTATUS(*Write)
    (struct FILE_OBJECT *file, const void *buffer, ULONG length, ULONG_PTR *infoOut);

    /* One NtDeviceIoControlFile/NtFsControlFile verb (both funnel here: the
     * NT split by device type is not observable through this boundary).
     * *infoOut = bytes placed in `output`. */
    NTSTATUS(*DeviceControl)
    (struct FILE_OBJECT *file, ULONG code, const void *input, ULONG inputLength, void *output,
     ULONG outputLength, ULONG_PTR *infoOut);

    /* FilePipeInformation / FilePipeLocalInformation (query), and
     * FilePipeInformation (set) — kernel/io/query.c routes the classes here
     * so the shapes stay next to the pipe state that fills them. */
    NTSTATUS(*QueryPipeInfo)
    (struct FILE_OBJECT *file, FILE_INFORMATION_CLASS informationClass, void *buffer, ULONG length,
     ULONG_PTR *infoOut);
    NTSTATUS (*SetPipeInfo)(struct FILE_OBJECT *file, const FILE_PIPE_INFORMATION *info);
} IO_VFS_OPS;

#endif /* PROSKRNL_KERNEL_IO_VFS_H */
