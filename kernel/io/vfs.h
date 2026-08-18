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
#include "kernel/ps/ps.h" /* PS_IO_CHARGE (the completion's IO_COUNTERS leg) */

struct FILE_OBJECT;       /* kernel/io/io.h */
struct IO_DEVICE;         /* kernel/io/io.h */
struct KTHREAD;           /* kernel/ke/ke.h */
struct KAPC;              /* kernel/ke/ke.h */
struct IOP_CANCEL_FILTER; /* kernel/io/io.h */

/* What a DeviceControl op needs to PEND an operation (CUI-3): the caller's
 * completion event handle and IOSB, captured into an IOP_PENDING_REQUEST by
 * IopPreparePendingRequest while still in the issuer's context
 * (kernel/io/async.c). Synchronous-only devices never look at it. */
typedef struct IO_CONTROL_CONTEXT
{
    HANDLE eventHandle;        /* optional completion event (0 = none) */
    PIO_STATUS_BLOCK userIosb; /* the caller's IOSB (probed writable) */

    /* W4a: the completion APC block, already allocated by the Io layer
     * (IopPrepareCompletionApc) before the verb ran, or 0. A device that
     * PENDS hands it to IopPreparePendingRequest along with the rest and
     * never touches it again; a device that completes inline leaves it
     * alone and the Io layer queues it. */
    struct KAPC *apcBlock;

    /* The caller's ApcContext, carried for the COMPLETION-PACKET rule rather
     * than for the APC (which already holds its own copy): the packet's value
     * is this word, and only when there is no ApcRoutine. A pended request
     * needs it at completion time, in a context that no longer has the
     * syscall's arguments. */
    PVOID apcContext;

    /* CUI-8: the DATA legs, for a verb that pends with a REPLY outstanding —
     * the npfs read (kernel/io/rw.c) and FSCTL_PIPE_TRANSCEIVE, whose reply is
     * the ioctl's output buffer (kernel/io/ioctl.c).
     * `userBuffer` is the caller's buffer VA in the OWNING process — it is
     * not valid in the completer's context, so the completion copies through
     * MiCopyToUserRangeChecked exactly as it does for the IOSB;
     * `kernelBuffer` is the Io layer's pool bounce of `bufferLength` bytes,
     * which the FS fills at completion.
     *
     * OWNERSHIP, and it is the apcBlock rule above word for word: a device
     * that PENDS hands the bounce to IopPreparePendingRequest and never
     * touches it again (the request frees it), a device that completes
     * inline leaves it alone and the Io layer frees it.
     *
     * Zero when the ENTRY POINT has no reply to place (a watch, a write). Not
     * "zero unless this verb uses them": ioctl.c fills them for EVERY verb,
     * because the engine cannot know which one will pend and a device that had
     * to say so could forget — the same argument `pended` itself makes. What
     * decides how much is placed is the count the device reports at
     * completion, so a verb that completes with `information == 0` (every
     * pended FSCTL_PIPE_LISTEN) places nothing whatever these hold. */
    PVOID userBuffer;
    PVOID kernelBuffer;
    ULONG bufferLength;

    /* The one OUT field, and the reason the whole struct is non-const: DID
     * this operation park an IOP_PENDING_REQUEST? NT answers the same
     * question with a FLAG on the IRP (`IoMarkIrpPending`) rather than with
     * a status, and it is right to, because STATUS_PENDING as a *status* is
     * ambiguous — condrv's server fetch returns it as a FINAL answer
     * meaning "nothing deliverable, wait on the handle" (drivers/condrv.c
     * CondrvServerRead, mirroring wineserver), with its IOSB written and
     * everything already freed.
     *
     * Reading the status instead cost a day: `if (status == STATUS_PENDING)
     * return` in the read path leaked conhost's bounce buffer on every poll
     * of an idle console, and the pool exhaustion downstream of that read
     * as a 3x per-process memory regression in the cui9 ceiling.
     *
     * Set by IopPreparePendingRequest itself, never by the device — so a
     * device cannot park a request and forget to say so. FALSE in, always. */
    BOOLEAN pended;

    /* Which IO_COUNTERS pair this request charges its issuer when it
     * completes (kernel/ps/ps.h PsChargeIoCounters). Carried here because
     * the charge lands in IopCompletePendingRequest, in a context that no
     * longer knows which verb parked — the same reason apcContext is
     * carried. PsIoChargeRead is the zero value, so the read path needs no
     * store; the ioctl path — which also pends with a data leg, for
     * FSCTL_PIPE_TRANSCEIVE — states PsIoChargeOther explicitly. */
    PS_IO_CHARGE charge;
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
    /* The three counters IoCheckShareAccess reads back as a live section's
     * hold on the file. They are proskrnl's spelling of the magic access
     * bits the pinned oracle's mapping fd carries — FILE_MAPPING_ACCESS /
     * FILE_MAPPING_IMAGE / FILE_MAPPING_WRITE, wine server/file.h:303-305,
     * set in server/mapping.c create_mapping — and IopSectionFileAccess
     * (kernel/io/file.c) is the one place that decides which a section takes.
     *
     * sectionCount: every live section backed by this file. A truncating
     * create over one answers STATUS_USER_MAPPED_FILE. */
    LONG sectionCount;
    /* Live SEC_IMAGE sections (a subset of sectionCount). While nonzero, an
     * open asking FILE_WRITE_DATA answers STATUS_SHARING_VIOLATION and a
     * FILE_DELETE_ON_CLOSE open answers STATUS_CANNOT_DELETE — the NT
     * running-image rule (pinned by sem_mm/image_deny_write and
     * sem_mm/section_file_hold). CUI-9's shared masters depend on it: a file
     * mutating under a live relocated master would be cross-process
     * corruption (docs/17 §6F; docs/03 "CUI-9 COW notes"). */
    LONG imageSectionCount;
    /* Live non-image sections whose own file access carried FILE_WRITE_DATA
     * (a PAGE_READWRITE / PAGE_EXECUTE_READWRITE data section). While
     * nonzero, an open that does not SHARE write answers
     * STATUS_SHARING_VIOLATION whatever access it asks for — including none
     * at all. */
    LONG writableSectionCount;
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
    /* The entry's 8.3 short name as the FS stores it, and its length in
     * bytes; 0 when the backend has none. Transport only — whether the
     * BOUNDARY reports it is decided once, in kernel/io/query.c, on whether
     * the long name is already an 8.3 name. A backend must not second-guess
     * that: it reports what it has and lets the one authority suppress. */
    WCHAR shortName[12];
    USHORT shortNameLength;
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

    /* Are this device's files NAMED IN THE OBJECT NAMESPACE — i.e. does
     * NtQueryObject(ObjectNameInformation) on one of its handles report
     * `<this device's object name>` + `QueryName`, and refuse when QueryName
     * has no path to give? kernel/io/file.c IopQueryFileObjectName is the one
     * place that composition happens, so this is an opt-in and not a second
     * name source (Art. 11).
     *
     * FALSE — the default — answers SUCCESS with an EMPTY name rather than a
     * refusal, and for a STREAM device that is the oracle's own answer
     * (server/object.c no_get_full_name, which every console object carries).
     * It is NOT the oracle's answer for every device that declines: a Wine
     * device file reports its device's name (server/device.c
     * device_file_get_full_name, which dlls/ntdll/tests/om.c pins for
     * \Device\Null with no todo_wine). \Device\Null and \Device\MountPointManager
     * are exactly that case and still answer empty here — a KNOWN remaining gap,
     * recorded in docs/03, not a measured answer.
     *
     * What keeps them out is mechanical: a device that opts in owes QueryName
     * the VOLUME-RELATIVE form its contract above states, because the
     * composition prepends the device's own name, and those two return their
     * full device path there. Opting them in means changing that first, which
     * moves what FileNameInformation reports for them and needs its own pin. */
    BOOLEAN namedInObjectNamespace;

    /* Optional: WHOSE security descriptor a handle on this device reports.
     * A device whose files share their security with something LONGER-LIVED
     * than the handle answers here — npfs does, because on the oracle a pipe
     * END has no descriptor of its own and defers to its PIPE, which every
     * end and every instance of that name shares (server/named_pipe.c
     * pipe_end_get_sd/pipe_end_set_sd). The slot is Ob's shape and Se still
     * does all the reading and writing of it (ob.h
     * OBJECT_TYPE.securityStorage), so this points at storage rather than
     * answering the question.
     *
     * `*slot` arrives holding this OPEN's own — the descriptor on the FILE
     * OBJECT, which is what every device that leaves this NULL keeps and what
     * the oracle gives a handle on the pipe DEVICE ROOT too — so a device
     * answers only for the handles it has something else to say about. A
     * refusal here is the caller's status: a pipe end whose pipe is gone
     * answers STATUS_PIPE_DISCONNECTED, which is the same fact
     * FileNameInformation already reports through a different syscall. */
    NTSTATUS (*SecurityStorage)(struct FILE_OBJECT *file, PVOID **slot);

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
     * change. *infoOut = bytes read (also on STATUS_BUFFER_OVERFLOW).
     *
     * On an ASYNCHRONOUS handle a device may instead PEND — park an
     * IOP_PENDING_REQUEST built from `request` (whose data legs carry
     * `buffer` itself) and answer STATUS_PENDING, leaving the caller's IOSB
     * and buffer untouched until something else completes it. npfs does
     * (CUI-8): a read on an empty pipe that parked the CALLING thread
     * deadlocked every caller that satisfies its own overlapped read from
     * the same thread. A device that never pends ignores `request`. */
    NTSTATUS(*Read)
    (struct FILE_OBJECT *file, void *buffer, ULONG length, ULONG_PTR *infoOut,
     struct IO_CONTROL_CONTEXT *request);

    /* Write `length` bytes; may block on quota. *infoOut = bytes written. */
    NTSTATUS(*Write)
    (struct FILE_OBJECT *file, const void *buffer, ULONG length, ULONG_PTR *infoOut);

    /* NtFlushBuffersFile on a stream device. There is no cache to push, so
     * this is not a writeback: for a pipe it is the NT promise that the
     * call does not return until the PEER has consumed everything this end
     * wrote, and it may block for exactly that long. NULL = the device
     * really has nothing to flush (the answer is then STATUS_SUCCESS). */
    NTSTATUS (*Flush)(struct FILE_OBJECT *file);

    /* One NtDeviceIoControlFile/NtFsControlFile verb (both funnel here: the
     * NT split by device type is not observable through this boundary).
     * *infoOut = bytes placed in `output`. A verb on an asynchronous handle
     * may return STATUS_PENDING after parking an IOP_PENDING_REQUEST built
     * from `request` (kernel/io/async.c; CUI-3 npfs listen) — the Io layer
     * then leaves the caller's IOSB untouched. Everything else ignores
     * `request` and completes before returning (docs/19 §2). */
    NTSTATUS(*DeviceControl)
    (struct FILE_OBJECT *file, ULONG code, const void *input, ULONG inputLength, void *output,
     ULONG outputLength, ULONG_PTR *infoOut, struct IO_CONTROL_CONTEXT *request);

    /* CUI-3: cancel-complete (STATUS_CANCELLED) every pending request parked
     * on this FILE_OBJECT that matches `filter`. The device WALKS its queues;
     * it never restates the filter's terms — IOP_CANCEL_FILTER (kernel/io/io.h)
     * says what they are and IopCancelFilterMatches decides them, so a term
     * added for one caller reaches every device that parks an
     * IOP_PENDING_REQUEST (Art. 11). Parked directory WATCHES are a different
     * record (IOP_DIR_WATCH) with its own sweep, and it still open-codes the
     * two terms it has. Returns how many
     * were cancelled. NULL = the device never pends, so there is never
     * anything to cancel — which is also what decides whether it owes the
     * handle-close sweep (kernel/io/async.c IopCancelProcessRequestsOnClose). */
    ULONG(*CancelPending)
    (struct FILE_OBJECT *file, const struct IOP_CANCEL_FILTER *filter);

    /* FilePipeInformation / FilePipeLocalInformation (query), and
     * FilePipeInformation (set) — kernel/io/query.c routes the classes here
     * so the shapes stay next to the pipe state that fills them.
     *
     * The set direction is handed the caller's HANDLE as well as the file
     * object, and that is not redundancy: its access requirement depends on
     * WHICH END this is (a server end owes FILE_WRITE_ATTRIBUTES, a client
     * end owes nothing — docs/03 "The FilePipeInformation SET ladder"), so it
     * cannot be expressed as the class's required access at the one
     * IopReferenceFileByHandle above. The FS learns the end from the file
     * object and then asks Ob for the bit, rather than reading an access word
     * off the file object: FILE_OBJECT.grantedAccess is the access of the
     * ORIGINAL OPEN and a duplicate can carry less (kernel/ob/handle.c
     * NtDuplicateObject grants the specific bits verbatim), while the rule is
     * about the handle in the caller's hand. */
    NTSTATUS(*QueryPipeInfo)
    (struct FILE_OBJECT *file, FILE_INFORMATION_CLASS informationClass, void *buffer, ULONG length,
     ULONG_PTR *infoOut);
    NTSTATUS(*SetPipeInfo)
    (struct FILE_OBJECT *file, HANDLE handle, const FILE_PIPE_INFORMATION *info);
} IO_VFS_OPS;
/* NOLINTEND(readability-identifier-naming) */

#endif /* PROSKRNL_KERNEL_IO_VFS_H */
