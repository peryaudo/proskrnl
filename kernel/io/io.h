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
 * a request is outstanding. The object is born signalled; four services clear
 * it and put it back through the one engine that states the rule
 * (kernel/io/async.c IopMarkRequestOutstanding / IopSignalRequestCompletion):
 * NtNotifyChangeDirectoryFile (ntdll:change waits on the DIRECTORY HANDLE and
 * requires a timeout, change.c:106/:112/:143; pinned
 * sem_file/dir_handle_signal.c), the CUI-8 npfs pended read (pinned
 * sem_pipe/pended_read.c), and — through IopBeginBlockingRequest /
 * IopEndBlockingRequest — the BLOCKING device transfer and the blocking flush
 * (pinned sem_pipe/blocking_signal.c).
 *
 * NOT every service that can park: kernel/io/ioctl.c's verbs park too
 * (FSCTL_PIPE_WAIT, a blocking listen) and take no Begin/End pair, where the
 * oracle queues those asyncs like any other. Unpinned gap rather than a
 * measured divergence — no winetest assertion samples a handle under a parked
 * ioctl — and the fix is to wrap ioctl.c's device call the same way.
 *
 * Two things about it that read as bugs and are the contract: exactly ONE
 * of the caller's event and this object is signalled at completion, so a
 * request that pended with an event leaves the object down; and there is no
 * outstanding-request count anywhere, so an unrelated inline completion on
 * the handle re-signals it with the pended request still parked.
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

    /* What the caller ASKED for at create, before ObpMapDesiredAccess — the
     * only place the GENERIC_* bits survive, since mapping folds
     * GENERIC_READ, GENERIC_ALL and MAXIMUM_ALLOWED into overlapping
     * grantedAccess masks that cannot be told apart afterwards.
     *
     * A filesystem needs it when a rule is about the caller's REQUEST rather
     * than about the rights it ended up with: npfs refuses a client that
     * explicitly names a direction the pipe does not offer, and must NOT
     * refuse one that named no direction at all (fs/npfs/pipe.c
     * NpfsVfsCreate; pinned sem_pipe/create_refusals.c). NT hands its FSDs
     * the same word — IO_STACK_LOCATION.Parameters.Create.SecurityContext->
     * DesiredAccess, which is what fastfat and npfs read — and proskrnl's
     * vfs op has no IRP to carry it, so the file object does. */
    ACCESS_MASK desiredAccess;
    ULONG shareAccess; /* this open's FILE_SHARE_* */

    /* FileIoCompletionNotificationInformation (class 41), the word
     * SetFileCompletionNotificationModes reads and writes. It lives on the
     * FILE_OBJECT, so duplicated handles SHARE it — which is the oracle's
     * shape too (its `struct fd` carries it and dup copies it); what the
     * pin demonstrates is only that the two ENDS of one pipe differ, which
     * is a weaker claim than per-handle.
     *
     * Bits ACCUMULATE: a second set ORs in, unknown bits are masked out, and
     * nothing can clear one (all measured — sem_pipe/ioctl_event.c).
     *
     * FILE_SKIP_COMPLETION_PORT_ON_SUCCESS is HONOURED (kernel/io/rw.c
     * IopCompleteTransfer): a completion that did not report STATUS_PENDING
     * to its caller posts no packet. Its axis is pendedness, NOT the
     * completion status — keyed on NT_SUCCESS instead, an async port-bound
     * handle would answer STATUS_PENDING and post nothing, hanging
     * GetQueuedCompletionStatus forever.
     *
     * FILE_SKIP_SET_EVENT_ON_HANDLE is HONOURED as of CUI-8 (kernel/io/
     * async.c IopFileSignalFrozen): it freezes `header` below, in both
     * directions and for the handle's whole life. It had nothing to say
     * while every request completed inline; the pended read is what gave
     * the file object a signalled state that moves.
     *
     * FILE_SKIP_SET_USER_EVENT_ON_FAST_IO is stored and reported back
     * truthfully and does nothing else — there is no fast path to suppress,
     * since every completion here goes through IopCompleteRequest, which is
     * why the oracle accepts it with a FIXME too. So a caller reading its
     * own mode back gets the truth about what was RECORDED rather than a
     * claim that it took effect. docs/16 carries the split. */
    ULONG completionFlags;

    /* This DEVICE drives `header` itself, so the Io layer's own
     * outstanding/completion transitions must not touch it (kernel/io/async.c
     * IopFileSignalSuppressed, the same predicate
     * FILE_SKIP_SET_EVENT_ON_HANDLE goes through).
     *
     * condrv is the one setter and the reason the field exists: its server
     * handle IS conhost's wait handle, signalled while requests are queued
     * and cleared by CondrvServerRead when the queue empties
     * (drivers/condrv.c CondrvSignalServer). An I/O completion that
     * re-signals it re-arms conhost's park on the very read that just
     * drained the queue, and its poll loop spins — measured, at the cost of
     * kernel32:virtual's run (docs/03 "CUI-8 async notes"). Saying so here
     * is what lets every other device get the NT rule; the exit is still to
     * give condrv an event of its own and delete this field. */
    BOOLEAN deviceManagedSignal;

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

/* The create-time conflict authority: ordinary share modes AND the hold a
 * live SECTION keeps on the file, in the pinned oracle's one order (wine
 * server/fd.c check_sharing). `disposition`/`options` are the create's own —
 * the section rules read a truncating disposition and FILE_DELETE_ON_CLOSE,
 * which is why this takes more than NT's IoCheckShareAccess does. */
NTSTATUS IoCheckShareAccess(ACCESS_MASK desiredAccess, ULONG shareAccess, ULONG disposition,
                            ULONG options, PIO_FCB fcb);
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

/* The two bare transitions on a caller's completion-event HANDLE, through
 * the one IopReferenceCompletionEvent authority and with the same
 * discard-the-failure rule IopCompleteRequest has. They exist because a
 * blocking request's ISSUE and its FAILING completion move the event without
 * touching the IOSB, which is the one thing IopCompleteRequest cannot do. */
void IopResetRequestEvent(HANDLE eventHandle);
void IopSetRequestEvent(HANDLE eventHandle);

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
    PKTHREAD issuer;           /* NtCancelIoFile scoping — and, since W4a,
                                * the thread the completion APC is queued
                                * to, which is why issuerObject below now
                                * exists */
    void *issuerObject;        /* referenced ETHREAD body: keeps `issuer`
                                * alive. Before W4a `issuer` was compared and
                                * never dereferenced, so a bare pointer was
                                * safe; queueing an APC to it reads
                                * ->terminating and inserts into its list, so
                                * the KTHREAD must still BE there. A parked
                                * listen is not swept at its issuer's exit
                                * (docs/03 "CUI-3 SCM notes"), so the thread
                                * can die with the request still queued and a
                                * later client connect would complete into
                                * freed pool. Same shape and same fix as
                                * IOP_DIR_WATCH.issuerObject (kernel/io/
                                * notify.c). */

    /* CUI-3/W4a: the completion APC, allocated at ISSUE time by
     * IopPrepareCompletionApc so completion itself cannot fail, and owned by
     * this request until IopCompletePendingRequest hands it to
     * IopQueueCompletionApc. Every way a parked request ends — a client
     * attaching, NtCancelIoFile, the owner's cleanup — runs through that one
     * function, so the block is queued or freed exactly once whichever ends
     * it (G11). 0 when the caller passed no ApcRoutine. */
    PKAPC apcBlock;

    /* The handle the request was issued on, REFERENCED — a request that
     * pends always owes a completion PACKET when the handle is bound to a
     * port, and the port is reachable only through the file object.
     *
     * Read at COMPLETION time rather than captured at issue, because the
     * oracle re-reads: `create_async` takes the fd's port up front, and
     * `add_async_completion` looks again for a request that was issued while
     * the fd was still unbound (third_party/wine server/async.c). Measured —
     * binding a port AFTER an async listen has pended still posts its packet
     * (tests/ntapi/sem_pipe/pending_packet.c). Since a bind is once-only,
     * reading late is the whole rule and capturing early is a subset of it.
     *
     * The reference is what makes that read safe, and it also makes "a
     * parked request cannot outlive its file object" structural instead of a
     * per-filesystem convention: with it held, the object cannot reach a
     * refcount of zero while a request is queued, so the delete path can
     * never find one. The handle's own reference outlives the cleanup hook
     * (ObpCloseHandleEntryIn drops it after closeProcedure), so releasing
     * this one from inside a cleanup-driven completion is never the last. */
    PFILE_OBJECT file;

    /* The caller's ApcContext — the packet's VALUE when there is no
     * ApcRoutine (kernel/io/rw.c IopPostRequestPacket states the rule). */
    PVOID apcContext;

    /* CUI-8: the DATA legs docs/19 §5d anticipated ("buffer/length legs
     * beside the IOSB"), grown into THIS engine rather than a fourth
     * bookkeeping shape. Their owner is the request:
     *
     *  - `kernelBuffer` is pool the ISSUER allocated (rw.c's bounce), handed
     *    over at IopPreparePendingRequest and freed by the one completer, so
     *    "allocated once, freed once" holds for every way a park can end
     *    exactly as it does for apcBlock;
     *  - `userBuffer` is a VA in `owner`, which is not this address space at
     *    completion time — so the bytes go out through
     *    MiCopyToUserRangeChecked, the same checked copy the IOSB uses and
     *    for the same reason (the owner may have freed it while parked).
     *
     * Zero for a request with no data leg (every pended listen and watch).
     * The FS fills kernelBuffer at completion and reports the count as the
     * completion's `information`; nothing past that count is copied. */
    PVOID userBuffer;
    PVOID kernelBuffer;
    ULONG bufferLength;

    LIST_ENTRY queueEntry; /* for a device that queues several pending
                            * requests of one kind (npfs's listen
                            * queue); unused when a device holds one */

    /* The IO_COUNTERS pair this request charges `owner` when it completes,
     * captured at issue from IO_CONTROL_CONTEXT.charge (vfs.h says why it
     * has to travel with the request). */
    PS_IO_CHARGE charge;
} IOP_PENDING_REQUEST, *PIOP_PENDING_REQUEST;

/* Build a pending request in the ISSUER's context (references the event, the
 * current process, the issuing thread and `file`). The caller's IOSB must
 * already be probed. */
NTSTATUS IopPreparePendingRequest(PFILE_OBJECT file, IO_CONTROL_CONTEXT *request,
                                  PIOP_PENDING_REQUEST *out);

/* The completion-APC leg, one authority (Art. 11; the rw.c and notify.c
 * copies drifted apart on allocation timing before this): allocate the KAPC
 * at ISSUE time so completion itself cannot fail, queue it at completion —
 * after the IOSB is in place — to the ISSUER, whose next alertable wait
 * delivers PIO_APC_ROUTINE(ApcContext, iosb, 0) via KiUserApcDispatcher.
 * Prepare returns 0 in *apcOut for a NULL routine or a kernel-mode issuer;
 * queue eats the block for a dead or dying issuer (its next edge is the
 * reaper, not the dispatcher). */
/* The ONE inline-completion tail (kernel/io/rw.c): write the IOSB, signal
 * the event, post the completion PACKET when the handle is bound to a port
 * and the mode flags do not suppress it, then queue the completion APC.
 * Shared with the ioctl path so an ioctl produces the same three effects a
 * transfer does — a second tail is how the two would drift (G10).
 *
 * `reportsPending` says whether this call will answer STATUS_PENDING to its
 * caller, which only the caller knows: the device paths return the status
 * unchanged, while the disk paths run it through IopAsyncReturnShape
 * afterwards. It is the axis FILE_SKIP_COMPLETION_PORT_ON_SUCCESS turns on.
 *
 * `charge` is the fourth effect: an operation that completes here is one
 * operation on the ISSUER's IO_COUNTERS, which is this thread's process
 * (an inline completion never crosses a process). The pended twin charges
 * the same way from IopCompletePendingRequest. */
/* Does a completion with this final status count as an I/O OPERATION on the
 * issuer's IO_COUNTERS? One predicate for every charging site (Art. 11): the
 * inline tail, the pended tail (kernel/io/async.c) and the two scatter/gather
 * completions all ask it, so they cannot disagree about what an operation is
 * — which they did when the pended tail filtered on NT_SUCCESS alone while
 * the inline one charged STATUS_END_OF_FILE.
 *
 * A request counts once it has COMPLETED with a transfer decided: success,
 * the short-buffer overflow, and end-of-file (a read that found nothing is
 * still a read the device performed — NT counts the IRP, and the byte count
 * it contributes is simply zero). A CANCELLED park never completed one. */
static inline BOOLEAN IopChargesIoCounters(NTSTATUS status)
{
    return NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW || status == STATUS_END_OF_FILE;
}

NTSTATUS IopCompleteTransfer(PFILE_OBJECT file, PIO_STATUS_BLOCK iosb, HANDLE event, PKAPC apc,
                             PVOID apcContext, NTSTATUS status, ULONG_PTR information,
                             BOOLEAN reportsPending, PS_IO_CHARGE charge);

/* Just the completion-PACKET leg of that tail, for the pended path, which
 * writes the IOSB and signals the event by itself (kernel/io/async.c). Both
 * halves of the rule live here: the handle's bound port, and the value
 * (`apc ? 0 : apcContext`, posted only when non-zero). `suppressed` is the
 * FILE_SKIP_COMPLETION_PORT_ON_SUCCESS verdict — FALSE for anything that
 * pended, since pendedness is the flag's axis. */
void IopPostRequestPacket(PFILE_OBJECT file, PKAPC apc, PVOID apcContext, BOOLEAN suppressed,
                          NTSTATUS status, ULONG_PTR information);

NTSTATUS IopPrepareCompletionApc(PIO_APC_ROUTINE apcRoutine, PVOID apcContext,
                                 PIO_STATUS_BLOCK iosb, PKAPC *apcOut);
void IopQueueCompletionApc(PKTHREAD issuer, PKAPC apc);

/* The completion SIGNAL leg of an operation that PENDED, one authority
 * (Art. 11 — the pended-request engine and the directory-watch engine both
 * owe it and stated it separately before): NT signals the caller's EVENT
 * when it supplied one and the FILE OBJECT otherwise, never both. The
 * pinned oracle is one `else if`:
 *
 *     if (async->event) set_event( async->event );
 *     else if (async->fd && !async->is_system) set_fd_signaled( async->fd, 1 );
 *                                        (third_party/wine server/async.c
 *                                         async_set_result)
 *
 * It fires for EVERY outcome, a cancel and an error included: what is being
 * reported is "nothing outstanding", not "something succeeded". Pinned by
 * sem_file/notify_change.c (the watch leg) and sem_pipe/pended_read.c (the
 * data leg, both halves of the exclusivity). */
void IopSignalRequestCompletion(PKEVENT event, struct FILE_OBJECT *file);

/* Its twin at ISSUE: a request that really parks leaves the file object
 * UNSIGNALLED until it completes (`set_fd_signaled( async->fd, 0 )`,
 * server/async.c queue_async — unconditionally, whether or not an event was
 * also supplied). Called by IopPreparePendingRequest for the pended verbs
 * and by the watch arm for its own engine. */
void IopMarkRequestOutstanding(struct FILE_OBJECT *file);

/* --- the BLOCKING twin of the two calls above (M10) ------------------------
 *
 * A request that PARKS ITS CALLER owes the caller's event and the file object
 * exactly what a pended one does: the oracle queues a blocking async through
 * the very same code, and `async->blocking = !is_fd_overlapped( fd )`
 * (server/async.c create_async) decides only how the CALLER waits. So a
 * synchronous pipe read takes the handle down for the duration and puts
 * exactly one of the two back up at the end. Pinned by
 * sem_pipe/blocking_signal.c; ntdll:pipe's test_blocking is the winetest
 * consumer.
 *
 * Begin is create_async's event reset plus queue_async's clear. The two are
 * separate statements in the oracle — the reset a frame above the device's
 * state checks, the clear below them — and are merged here deliberately: the
 * split is observable only for a request the DEVICE refuses without ever
 * parking, and IopRequestRefused below RESTORES the handle to what Begin
 * found for exactly that case, rather than teaching every device where the
 * boundary is. Restores, not signals: a handle can already be down when the
 * refused request arrives (the previous request completed through an event),
 * and the oracle leaves it down. */
typedef struct IOP_BLOCKING_REQUEST
{
    struct FILE_OBJECT *file;
    HANDLE eventHandle;
    BOOLEAN handleWasSignalled;
} IOP_BLOCKING_REQUEST;

void IopBeginBlockingRequest(IOP_BLOCKING_REQUEST *request, struct FILE_OBJECT *file,
                             HANDLE eventHandle);

/* How a blocking request ended, which is what decides the signal. The three
 * arms are the pinned oracle's, measured rather than reasoned about:
 *
 *   Completed     the IOSB is written; the event, when there was one, has
 *                 already been set by IopCompleteRequest, so only the
 *                 FILE-OBJECT arm of "exactly one" is left to take.
 *   FailedParked  it was queued and then failed (a peer closing under a
 *                 parked read or a quota-blocked write). server/async.c
 *                 async_set_result's guard is
 *                 `async->pending || !NT_ERROR( status )`, so a QUEUED
 *                 request reaches the signal block even when it fails — and
 *                 takes the same event-or-handle arm a success takes. A
 *                 failing request therefore SIGNALS the caller's event,
 *                 which is the opposite of what the direct-fd path does and
 *                 is why this arm is not IopAbandonRequest. The caller must
 *                 not reset the event afterwards; this call is the last word
 *                 on it.
 *   Refused       the device answered above the queue (a read on an already
 *                 broken pipe): `async->pending` is still 0 there, so the
 *                 signal block is skipped entirely — the handle keeps
 *                 whatever state it had and the event stays reset.
 */
typedef enum
{
    IopRequestCompleted,
    IopRequestFailedParked,
    IopRequestRefused
} IOP_BLOCKING_OUTCOME;

void IopEndBlockingRequest(IOP_BLOCKING_REQUEST *request, IOP_BLOCKING_OUTCOME outcome);

/* CUI-5 NtCancelSynchronousIoFile (kernel/io/async.c): mark the current
 * thread's in-flight synchronous I/O around a potentially-blocking device
 * op, and the cancellable park npfs's blocking waits use. */
void IopEnterSyncIo(void *userIosb);
void IopLeaveSyncIo(void);
NTSTATUS IoWaitCancellable(PKEVENT event, PLARGE_INTEGER timeout);

/* Did the current thread's marked span actually PARK? The engine's own
 * answer to "was this request queued" (KTHREAD.syncIoParked, set by
 * IoWaitCancellable) — which is the only thing separating IopRequestRefused
 * from IopRequestFailedParked. */
BOOLEAN IoSyncIoParked(void);

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
