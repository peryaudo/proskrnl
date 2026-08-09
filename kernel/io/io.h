/* kernel/io/io.h — the Io department: devices, file objects, the Nt* file
 * surface (M6, docs/02).
 *
 * The forced part (docs/05): the async-completion protocol — final status
 * in the return value, the IO_STATUS_BLOCK written before any completion
 * signal, event/APC completion — and NT file semantics (share modes,
 * case-insensitivity, delete-on-close, byte-range locks), pinned by
 * tests/ntapi/sem_file/ on the Wine oracle. Everything internal is free:
 * no IRP, no device stacks; a device is an Ob object holding a vfs.h op
 * table, and data transfers currently complete before the syscall returns.
 * That is a legal point inside the NT contract (STATUS_PENDING is permitted,
 * never required — docs/19 "Asynchronous I/O Strategy" §1), NOT an Art. 3
 * mandate: Art. 3's list is no-COW / no-eviction / one-lock-uniprocessor-
 * no-preemption / one-pool, and says nothing about I/O. It holds only for
 * devices that always complete in bounded time; the pended verbs already
 * exist (kernel/io/async.c) and docs/19 is the plan for widening them.
 *
 * APC completion (sem_file/apc_completion.c): a transfer carrying a user
 * ApcRoutine queues a user APC when the request completes — the IOSB is
 * written first — and the M7 KiUserApcDispatcher delivers it at the next
 * alertable wait as PIO_APC_ROUTINE(ApcContext, iosb, reserved).
 */
#ifndef PROSKRNL_KERNEL_IO_IO_H
#define PROSKRNL_KERNEL_IO_IO_H

#include "abi/ntdef.h"
#include "abi/ntstatus.h"
#include "abi/ntioapi.h"
#include "kernel/ob/ob.h"
#include "kernel/ke/ke.h"
#include "kernel/io/vfs.h"
#include "kernel/mm/pagecache.h"

/* --- Device objects -------------------------------------------------------- */

/* Body of an Ob "Device" object (\Device\HarddiskVolume1). */
typedef struct IO_DEVICE
{
    const IO_VFS_OPS *ops;
    PVOID context;    /* the mounted FAT_VOLUME */
    ULONG deviceType; /* FILE_DEVICE_*: FileFsDeviceInformation / GetFileType (M10) */
} IO_DEVICE, *PIO_DEVICE;

extern OBJECT_TYPE IoDeviceType;
extern OBJECT_TYPE IoFileObjectType;

/* --- File objects ---------------------------------------------------------- */

/* Body of an Ob "File" object: one open of one file. NT's FILE_OBJECT
 * concept; internal layout ours (docs/03). File handles are waitable — NT
 * signals the file object at I/O completion and leaves it UNSIGNALLED while
 * a request is outstanding. Almost everything here completes inline
 * (docs/19 §2), so the object is born signalled and never observably
 * clears; the one service that genuinely pends is
 * NtNotifyChangeDirectoryFile, and for the interval it is armed the object
 * really is busy and callers really do look (ntdll:change waits on the
 * DIRECTORY HANDLE and requires a timeout, change.c:106/:112/:143).
 * kernel/io/notify.c clears it at arm and signals it at completion; pinned
 * by tests/ntapi/sem_file/dir_handle_signal.c.
 *
 * Spelled KEVENT rather than a bare DISPATCHER_HEADER so the clear and the
 * signal go through the Ke event engine that already owns those two
 * transitions (Art. 11) instead of a second open-coded dispatcher-lock
 * dance. The layout is identical — KEVENT is exactly one DISPATCHER_HEADER
 * — so nothing that reads the header at offset 0 changes. */
/* The completion-port object (kernel/io/completion.c); a file handle may be
 * bound to one. */
typedef struct IO_COMPLETION IO_COMPLETION, *PIO_COMPLETION;

typedef struct FILE_OBJECT
{
    KEVENT header;     /* notification-shaped: signalled == no request outstanding */
    PIO_DEVICE device; /* referenced via the Ob device body */
    PIO_FCB fcb;       /* the FS's per-file node (fs/fat32 FAT_FCB) */
    PVOID fsContext;   /* == fcb, typed for the FS's convenience */
    BOOLEAN isDirectory;
    BOOLEAN synchronousIo; /* FILE_SYNCHRONOUS_IO_* at create */
    BOOLEAN deleteOnClose; /* FILE_DELETE_ON_CLOSE at create */
    BOOLEAN nonBuffered;   /* FILE_NO_INTERMEDIATE_BUFFERING at create
                            * (CUI-5: the scatter/gather qualifier) */
    ULONG modeFlags;       /* the FileModeInformation word: the create
                            * options masked exactly as the pinned Wine's
                            * server serves them (third_party/wine
                            * server/fd.c default_fd_get_file_info) */
    BOOLEAN shareCounted;  /* this open holds share-access slots */
    ACCESS_MASK grantedAccess;
    ULONG shareAccess; /* this open's FILE_SHARE_* */
    LARGE_INTEGER currentByteOffset;

    /* M10 change-notify: the completion FILTER is established by the FIRST
     * NtNotifyChangeDirectoryFile on this file object and is STICKY — every
     * later arm on the same handle reuses it and its own filter argument is
     * ignored.
     *
     * That is not a shortcut, it is the contract. The pinned server says so
     * in a comment (`/ * assign it once * /`, third_party/wine
     * server/change.c DECL_HANDLER(read_directory_changes): the filter,
     * subtree and want_data are stored only `if (!dir->filter)`), NT does
     * the same by reusing the existing notify entry for a repeated
     * FsContext, and ntdll:change measures it — it arms a watch for
     * everything, then re-arms the same handle for FILE_NOTIFY_CHANGE_SIZE
     * alone and requires a DIRECTORY REMOVAL to complete it
     * (change.c:132-:155). A kernel that honours the second filter leaves
     * that watch parked forever.
     *
     * notifyArmed says whether the filter has been set yet; a watch that
     * completes does not clear it, because the association is with the
     * HANDLE and lasts as long as the handle does.
     *
     * The SUBTREE flag and "did the caller pass a buffer" are fixed by that
     * same first arm — they are stored in the same `if (!dir->filter)` block
     * — and pinned by sem_file/notify_queue.c. notifyWantData clear is not a
     * shortcut: with it clear the server queues NO RECORD at all and only
     * wakes the request, so every completion on such a handle is
     * STATUS_NOTIFY_ENUM_DIR with Information 0 however big a buffer a later
     * arm supplies.
     *
     * notifyRecords is the CHANGE QUEUE: changes accumulate on the handle
     * whether or not a watch is parked, and a later arm that finds it
     * non-empty completes at once. notifyWake carries the same signal for a
     * change that queued no record (notifyWantData clear, or a pool
     * failure): something happened, but nothing can be reported.
     * notifyPath is the handle's volume-relative path — the match key, taken
     * once with the filter because matching now happens at CHANGE time
     * rather than per parked watch. kernel/io/notify.c owns all of it. */
    BOOLEAN notifyArmed;
    BOOLEAN notifySubtree;
    BOOLEAN notifyWantData;
    BOOLEAN notifyWake;
    ULONG notifyFilter;
    LIST_ENTRY notifyEntry;   /* the armed-directory list, while notifyArmed */
    LIST_ENTRY notifyRecords; /* queued IOP_DIR_RECORD, oldest first */
    UNICODE_STRING notifyPath;

    /* CUI-8: the NT file-object lock (IopLockFileObject's role), scoped to
     * what it observably protects here: NT serializes all I/O on a
     * synchronous handle, and once the data path can park, two threads
     * sharing one sync handle both captured currentByteOffset == 0 across
     * a park, transferred the same range, and stored the same advance.
     * A synchronization event born signalled (the same binary-semaphore
     * shape as the fat32 volume gate, acquired via KiAcquireEventGate);
     * taken only for synchronousIo handles around the seekable data leg —
     * offset capture, transfer, offset advance — and released before the
     * completion touches user memory (a ring-0 fault there unwinds without
     * cleanup and would leak the lock; docs/20 R3's rule for gates). */
    KEVENT syncIoLock;

    /* CUI: the completion port this handle is BOUND to
     * (NtSetInformationFile, FileCompletionInformation — what
     * CreateIoCompletionPort(file, port, key, 0) is). NULL = unbound, which
     * is every handle until something binds it. The reference is the file
     * object's and is dropped in IopDeleteFileObject, so a port whose own
     * handles all close stays alive exactly as long as a file still names
     * it — the ownership answer for "what if every handle closes at the
     * earliest legal moment" (Art. 11). Binding is once-only and
     * asynchronous-only; kernel/io/query.c holds the rules. */
    PIO_COMPLETION completionPort;
    ULONG_PTR completionKey;

    /* Directory enumeration state: the mask binds to the handle (pinned
     * Wine: a NULL mask on a later call reuses the previous one). */
    /* Directory enumeration is served from a SNAPSHOT taken when the scan
     * begins, not read live from the filesystem per call — which is what
     * lets the entries come back sorted, and is what the oracle does
     * (dlls/ntdll/unix/file.c init_cached_dir_data). `dirPosition` indexes
     * dirOrder, which is a permutation of dirSnapshot; both are pool,
     * allocated only in NtQueryDirectoryFile and freed only in
     * IopDeleteFileObject beside dirMask.
     *
     * The free belongs to DELETE and not to cleanup, and not for symmetry:
     * an enumerator holds an object reference for the whole call, which
     * excludes delete but NOT cleanup — the last handle can close while a
     * snapshot build is parked between two gated ReadDirectory calls
     * (docs/20 §9). Freeing at cleanup would hand that build a dangling
     * array. Putting it in delete makes the hazard structurally impossible
     * instead of argued away.
     *
     * Consequence, accepted: a FILE_OBJECT can outlive its last handle
     * while a section references it, so the snapshot can sit in pool past
     * the last NtClose — the same window dirMask and completionPort
     * already live in. NOT an obligation-ledger entry: its owner is the
     * object, not the calling frame. */
    IO_DIR_ENTRY *dirSnapshot;
    ULONG *dirOrder;
    ULONG dirSnapshotCount;
    ULONG dirPosition;
    BOOLEAN dirScanStarted; /* first-query state: empty result is
                             * NO_SUCH_FILE only on the first scan */
    UNICODE_STRING dirMask; /* pool copy; Buffer 0 = no mask yet */
} FILE_OBJECT, *PFILE_OBJECT;

/* --- initialization (kernel/io/file.c) ------------------------------------- */

/* Two-phase bring-up. IoInitializeTransport probes virtio-blk and maps its
 * MMIO window — it MUST run before PsInitializeProcessSubsystem (the window
 * may claim a fresh kernel PML4 slot, frozen there). IoMountBootVolume
 * mounts FAT32 and publishes \Device\HarddiskVolume1 + \??\C:; it creates
 * handles, so it runs on the first kernel thread (a process context).
 * Absence of a disk is tolerated. */
void IoInitializeTransport(void);
void IoMountBootVolume(void);

/* \Device\Null + \??\NUL (kernel/io/null.c). Namespace only — no disk,
 * no transport — so it may be published as early as a thread exists. */
void IoInitializeNullDevice(void);

/* \Device\MountPointManager + \??\MountPointManager + the boot volume's
 * \??\Volume{...} name (kernel/io/mountmgr.c). Called from
 * IoMountBootVolume, after the volume device and \??\C: exist — the volume
 * GUID link targets that device. */
void IoInitializeMountManager(void);

/* Create a permanent \Device\... object over `ops` and return its body (the
 * namespace owns it; the transient handle is closed here). The one device
 * publication path — every driver and filesystem in the tree mints its
 * device object through this call (G10/Art. 11). Publication needs a handle
 * table, so callers run on a thread with a process context. Failure is a
 * boot-time panic: the namespace is fresh and a collision is a bug. */
PIO_DEVICE IoPublishDevice(const WCHAR *name, const IO_VFS_OPS *ops, PVOID context,
                           ULONG deviceType);

/* --- share-mode accounting (kernel/io/file.c; NT's Io*ShareAccess) --------- */

NTSTATUS IoCheckShareAccess(ACCESS_MASK desiredAccess, ULONG shareAccess, PIO_FCB fcb);
void IoSetShareAccess(ACCESS_MASK desiredAccess, ULONG shareAccess, PIO_FCB fcb);
void IoRemoveShareAccess(ACCESS_MASK desiredAccess, ULONG shareAccess, PIO_FCB fcb);

/* --- byte-range locks (kernel/io/lock.c) ----------------------------------- */

void IopInitializeFcb(PIO_FCB fcb);
/* Grant/refuse [offset, offset+length) for `owner`. */
NTSTATUS IopLockRange(PIO_FCB fcb, PFILE_OBJECT owner, uint64_t offset, uint64_t length,
                      BOOLEAN exclusive);
NTSTATUS IopUnlockRange(PIO_FCB fcb, PFILE_OBJECT owner, uint64_t offset, uint64_t length);
void IopReleaseAllLocks(PIO_FCB fcb, PFILE_OBJECT owner);

/* --- helpers shared across the io department ------------------------------- */

/* Resolve a file handle with an access check. Caller dereferences. */
NTSTATUS IopReferenceFileByHandle(HANDLE handle, ACCESS_MASK desiredAccess, PFILE_OBJECT *fileOut);

/* Attribute-only internal open of a rename/link target: SUCCESS when the
 * target exists or only its leaf is missing, the open's failure otherwise
 * (kernel/io/file.c; the Wine pre-handle target-resolution gate). */
NTSTATUS IopProbeTargetPath(POBJECT_ATTRIBUTES attributes);

/* Kernel-internal: open `ntPath` (e.g. \??\C:\windows\system32\ntdll.dll) and
 * build a SEC_IMAGE section over it (the M7 process bootstrap + the NLS
 * mapping syscalls use the data flavour below). The caller owns the returned
 * section reference. Runs on a thread with a handle table (any process). */
struct MI_SECTION; /* kernel/mm/section.h */
NTSTATUS IoOpenImageSection(const WCHAR *ntPath, struct MI_SECTION **sectionOut);
/* Same open, but a PAGE_READONLY data (SEC_COMMIT) section over the file. */
NTSTATUS IoOpenDataSection(const WCHAR *ntPath, struct MI_SECTION **sectionOut);

/* Kernel-internal: enumerate the directory at `ntPath`, handing every entry
 * ("." / ".." included) to `callback`; return FALSE to stop the sweep. The
 * ntapi test runner (kernel/init/main.c) sweeps \??\C:\ntapi with this. */
NTSTATUS IoEnumerateDirectory(const WCHAR *ntPath,
                              BOOLEAN (*callback)(const IO_DIR_ENTRY *entry, PVOID context),
                              PVOID context);

/* Complete one operation: write the IOSB, then signal the optional event —
 * in exactly that order (the docs/08 contract). `eventHandle` may be 0. */
/* Check a completion-event handle BEFORE the operation runs, for the
 * services whose oracle refuses a bad one: the ioctl/FSCTL pair, whose
 * request the wineserver rejects up front, and the directory enumeration,
 * whose cursor a refused call must not advance. The read/write pair
 * deliberately does NOT call this -- the oracle discards an event-signal
 * failure there and returns the transfer's own status (see
 * IopCompleteRequest). A 0 handle (no event) succeeds. */
NTSTATUS IopValidateEventHandle(HANDLE eventHandle);

/* Failure path twin: reset the caller's event, leave the IOSB alone.
 * See kernel/io/file.c for why the two move together. */
void IopAbandonRequest(HANDLE eventHandle);

NTSTATUS IopCompleteRequest(IO_STATUS_BLOCK *iosb, HANDLE eventHandle, NTSTATUS status,
                            ULONG_PTR information);

/* --- completion ports (kernel/io/completion.c) ----------------------------- */

/* Opaque port body (an Ob object of IoCompletionType); layout private to
 * completion.c. */
extern OBJECT_TYPE IoCompletionType;

/* Queue one packet on a REFERENCED port body — the engine NtSetIoCompletion
 * itself uses; kernel-internal producers (Ps job objects, CUI-3) post
 * through it too (G10: one path). */
NTSTATUS IopPostCompletionPacket(PIO_COMPLETION port, ULONG_PTR key, ULONG_PTR value,
                                 NTSTATUS packetStatus, ULONG_PTR information);

/* --- pending requests (kernel/io/async.c; CUI-3) --------------------------- */

/* THE DEPARTMENT'S CROSS-CONTEXT OWNERSHIP CONVENTION (docs/19 §5d, G11 —
 * stated once here, inherited by every in-flight verb rather than
 * re-derived). An operation that outlives its syscall, whoever completes
 * it and in whatever context:
 *
 *  1. Everything context-dependent is resolved in the ISSUER's context at
 *     issue time: object BODIES not handles (the event), the owning
 *     process (whose address space holds the IOSB/buffer), the issuer
 *     thread — referenced if it will be dereferenced later (the dir-watch
 *     issuerObject), compared-only otherwise (the cancel scoping here).
 *  2. Exactly one party holds the request and ALWAYS completes it — every
 *     exit (success, cancel, handle cleanup, thread teardown) reaches a
 *     completer; none abandons. Handles close before the owner's address
 *     space dies (PspExitCurrentProcess vs. PspDeleteProcess), so the
 *     IOSB write cannot hit a torn-down space; cross-context user writes
 *     go through the CHECKED copies, never a faulting path.
 *  3. When the holder is a caller FRAME rather than a heap record (the
 *     CUI-8 data park: VIO_BLK_REQUEST / fs FAT_IO_BATCH), the frame
 *     never unwinds past an in-flight request — a refused park polls the
 *     request home first (docs/20 R4).
 *
 * The instances: this struct (npfs's parked listens), IOP_DIR_WATCH
 * (kernel/io/notify.c), and the CUI-8 block-layer park. A future genuinely
 * pended DATA transfer (Net-1's AFD is the expected consumer) grows THIS
 * engine — buffer/length legs beside the IOSB — rather than a fourth
 * bookkeeping shape. */
typedef struct IOP_PENDING_REQUEST
{
    struct EPROCESS *owner;    /* referenced; the IOSB's address space */
    PIO_STATUS_BLOCK userIosb; /* IOSB VA in `owner` (probed at issue) */
    BOOLEAN kernelIosb;        /* issuer was kernel mode: write directly */
    PKEVENT event;             /* referenced event body, or 0 */
    PKTHREAD issuer;           /* NtCancelIoFile scoping; compared, never
                                * dereferenced */
    LIST_ENTRY queueEntry;     /* for a device that queues several pending
                                * requests of one kind (npfs's listen
                                * queue); unused when a device holds one */
} IOP_PENDING_REQUEST, *PIOP_PENDING_REQUEST;

/* Build a pending request in the ISSUER's context (references the event and
 * the current process). The caller's IOSB must already be probed. */
NTSTATUS IopPreparePendingRequest(const IO_CONTROL_CONTEXT *request, PIOP_PENDING_REQUEST *out);

/* The completion-APC leg, one authority (Art. 11; the rw.c and notify.c
 * copies drifted apart on allocation timing before this): allocate the KAPC
 * at ISSUE time so completion itself cannot fail, queue it at completion —
 * after the IOSB is in place — to the ISSUER, whose next alertable wait
 * delivers PIO_APC_ROUTINE(ApcContext, iosb, 0) via KiUserApcDispatcher.
 * Prepare returns 0 in *apcOut for a NULL routine or a kernel-mode issuer;
 * queue eats the block for a dead or dying issuer (its next edge is the
 * reaper, not the dispatcher). */
NTSTATUS IopPrepareCompletionApc(PIO_APC_ROUTINE apcRoutine, PVOID apcContext,
                                 PIO_STATUS_BLOCK iosb, PKAPC *apcOut);
void IopQueueCompletionApc(PKTHREAD issuer, PKAPC apc);

/* CUI-5 NtCancelSynchronousIoFile (kernel/io/async.c): mark the current
 * thread's in-flight synchronous I/O around a potentially-blocking device
 * op, and the cancellable park npfs's blocking waits use. */
void IopEnterSyncIo(void *userIosb);
void IopLeaveSyncIo(void);
NTSTATUS IoWaitCancellable(PKEVENT event, PLARGE_INTEGER timeout);

/* CUI-8 (docs/19 §9.9): has the current thread's marked synchronous I/O
 * been cancelled? The data path's loops poll this between transfers: a
 * cancelled fill/writeback stops ISSUING and returns STATUS_CANCELLED, but
 * every transfer already submitted is still awaited — the device owns
 * those frames until it is done (docs/20 R4), so cancel latency is bounded
 * by one in-flight batch, never by abandonment. FALSE outside a marked
 * span (a section-create cache fill is not cancellable I/O). */
BOOLEAN IoSyncIoCancelled(void);

/* CUI-8 (docs/20 R7; PR #95 review round 2, F3): release the object
 * references of dir watches whose completion ran under the volume gate.
 * IopCompleteDirWatch retires them instead of dereferencing inline — a
 * last reference dropped under the gate runs a teardown that re-enters a
 * gated wrapper and self-deadlocks (docs/20 §10.5.1). Called from the
 * gate's release path (FatReleaseVolumeGate) and the non-gated sweeps;
 * must NEVER be called with the volume gate held. */
void IoReapRetiredDirWatches(void);

/* CUI-5 NtNotifyChangeDirectoryFile (kernel/io/notify.c): the FS mutation
 * sites report changes here (cheap when no directory handle is armed); the
 * cancel and close paths sweep the kernel-owned watch list. */
BOOLEAN IoDirectoryWatchesActive(void);
void IoReportDirectoryChange(struct IO_DEVICE *device, const UNICODE_STRING *parentPath,
                             const UNICODE_STRING *name, ULONG filterBit, ULONG action);
ULONG IopCancelDirectoryWatches(struct FILE_OBJECT *file, PKTHREAD issuer,
                                PIO_STATUS_BLOCK targetIosb);

/* Queue-then-deliver, and the split is the contract rather than a
 * convenience: one FS operation may report SEVERAL changes that NT owes the
 * caller in ONE completion — an in-place rename is FILE_ACTION_RENAMED_OLD_NAME
 * chained to FILE_ACTION_RENAMED_NEW_NAME (sem_file/notify_queue.c). So
 * IoReportDirectoryChange only appends, and the batch is delivered at the end
 * of the operation. Called from the volume gate's release path — the one
 * place that is both "the operation is over" and outside the gate — and from
 * the arm itself, for a queue that was already non-empty. */
void IoDeliverDirectoryChanges(void);

/* Drop the notification state of a dying file object: unregister it from the
 * armed list and free its queued records (the server's dir_destroy). */
void IopDetachDirectoryNotify(struct FILE_OBJECT *file);

/* Complete a pending request from any context: IOSB into the owner's
 * address space strictly BEFORE the event signal (docs/08), then drop both
 * references and free. */
void IopCompletePendingRequest(PIOP_PENDING_REQUEST request, NTSTATUS status,
                               ULONG_PTR information);

#endif /* PROSKRNL_KERNEL_IO_IO_H */
