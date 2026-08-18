/* kernel/io/file.c — Io initialization, Device/File object types, share
 * access, NtCreateFile/NtOpenFile/NtQueryAttributesFile, and the Mm seam
 * for file-backed sections (see io.h).
 *
 * Boundary semantics pinned by tests/ntapi/sem_file/ on the Wine oracle
 * (create dispositions and IOSB Information verdicts, share modes,
 * delete-on-close, typing errors, case-insensitivity).
 */
#include "kernel/io/io.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/mm/pool.h"
#include "kernel/mm/section.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/init/panic.h"
#include "kernel/ke/ke.h"
#include "drivers/virtio/blk.h"
#include "drivers/virtio/input.h"
#include "drivers/virtio/snd.h"
#include "drivers/virtio/net.h"
#include "fs/fat32/fat.h"

/* --- object types ----------------------------------------------------------- */

static void IopDeleteFileObject(PVOID body)
{
    PFILE_OBJECT file = body;
    if (file->fsContext != 0)
    {
        file->device->ops->Close(file);
    }
    if (file->dirMask.Buffer != 0)
    {
        MiFreePool(file->dirMask.Buffer);
    }
    /* The enumeration snapshot, freed here rather than at cleanup — io.h
     * says why (a parked snapshot build outlives the last handle close). */
    if (file->dirSnapshot != 0)
    {
        MiFreePool(file->dirSnapshot);
    }
    if (file->dirOrder != 0)
    {
        MiFreePool(file->dirOrder);
    }
    /* CUI-5: the handle's change queue and its place on the armed-directory
     * list (kernel/io/notify.c). Here rather than at cleanup, because a
     * parked watch holds a reference and so outlives the last handle. */
    IopDetachDirectoryNotify(file);
    if (file->completionPort != 0)
    {
        /* The bind's reference, released with the file object rather than
         * with its last handle: a port must outlive every file that names
         * it, or a completion posted during teardown would post into freed
         * pool. */
        ObDereferenceObject(file->completionPort);
    }
    if (file->device != 0)
    {
        ObDereferenceObject(file->device);
    }
}

/* NT's IRP_MJ_CLEANUP moment: the last HANDLE in the system is gone
 * (references may remain — sections). Release this open's locks and share
 * slots, then let the FS apply delete-on-close. Its own function because one
 * caller reaches it WITHOUT a handle ever having existed (IopCreateFile's
 * handle-allocation failure, below) — synthesising a count for that caller
 * would be a lie about which moment it is. */
void IopCleanupFileObject(PFILE_OBJECT file)
{
    if (file->fsContext == 0)
    {
        return;
    }
    /* CUI-5: a watch parked on this handle dies with it (event signalled,
     * IOSB untouched — the cancel shape). */
    IopCancelDirectoryWatches(file, 0, 0);
    IopReleaseAllLocks(file->fcb, file);
    if (file->shareCounted)
    {
        IoRemoveShareAccess(file->grantedAccess, file->shareAccess, file->fcb);
        file->shareCounted = FALSE;
    }
    file->device->ops->Cleanup(file);
}

static void IopCloseFileObject(PEPROCESS process, PVOID body, ULONG processHandleCount,
                               ULONG systemHandleCount)
{
    PFILE_OBJECT file = body;
    /* The hook now fires on EVERY close (ob.h); this type's one subject so far
     * is the last handle in the SYSTEM. */
    (void)process;
    (void)processHandleCount;
    if (systemHandleCount != 1)
    {
        return;
    }
    IopCleanupFileObject(file);
}

OBJECT_TYPE IoDeviceType = {
    .name = "Device",
    .validAccess = FILE_ALL_ACCESS,
    .waitable = FALSE,
    .deleteProcedure = 0,
    .closeProcedure = 0,
};

/* IoFileObjectType.queryName: what NtQueryObject(ObjectNameInformation)
 * reports for a FILE handle.
 *
 * A file object is never linked into the Ob namespace -- the DEVICE is, and
 * everything past it belongs to that device -- so the generic walk finds no
 * name for any of them and reports every one as nameless. That is Art. 12's
 * fabricated answer with no stub in it (a caller told a named pipe has no name
 * cannot tell two pipes apart, and is not told that it cannot), and it is the
 * same defect CmpQueryKeyObjectName removed one type over.
 *
 * The name is composed here rather than by each filesystem, so there is ONE
 * statement of "device plus volume-relative path" (Art. 11) and a device's
 * only say is whether its files are in the namespace at all
 * (IO_VFS_OPS.namedInObjectNamespace). That mirrors the oracle, where the
 * answer is per object type: an end defers to its pipe and the pipe walks to
 * the device (server/named_pipe.c pipe_end_get_full_name ->
 * named_pipe_get_full_name -> default_get_full_name), a disk file reports the
 * name its fd captured (server/fd.c default_fd_get_full_name), and a console
 * object has none at all (no_get_full_name).
 *
 * A device that HAS a namespace but no path for THIS file refuses with
 * STATUS_OBJECT_PATH_INVALID, which is what the oracle turns its own
 * "no name" into on this query (named_pipe_get_full_name's `if (!(ret =
 * default_get_full_name(...))) set_error( STATUS_OBJECT_PATH_INVALID )`) --
 * the FS spells the same fact STATUS_PIPE_DISCONNECTED through
 * FileNameInformation, because that is what the oracle's OTHER arm says
 * (pipe_end_get_file_info). One fact, two syscalls, two names for it.
 * Pinned by tests/ntapi/sem_pipe/object_name.c. */
static NTSTATUS IopQueryFileObjectName(PVOID body, WCHAR *out, ULONG *nameBytes)
{
    PFILE_OBJECT file = body;
    const IO_VFS_OPS *ops = file->device->ops;
    if (!ops->namedInObjectNamespace)
    {
        *nameBytes = 0; /* nameless as a class, not nameless by accident */
        return STATUS_SUCCESS;
    }

    USHORT deviceBytes = ObpFullNameLength(ObpGetHeader(file->device));
    /* Every device this arm can reach was published by name (IoPublishDevice
     * panics otherwise), so the walk cannot come back empty. */
    ASSERT(deviceBytes != 0);

    /* The measuring pass has no caller buffer, and QueryName reports the full
     * length whatever it can store -- so it gets a staging buffer of its own,
     * the same 260-WCHAR local kernel/io/query.c IopFillName measures into. */
    WCHAR staging[260];
    WCHAR *relativeOut = staging;
    ULONG relativeCapacity = sizeof(staging);
    if (out != 0)
    {
        ASSERT(*nameBytes >= deviceBytes);
        relativeOut = out + deviceBytes / sizeof(WCHAR);
        relativeCapacity = *nameBytes - deviceBytes;
    }
    ULONG relativeBytes = 0;
    NTSTATUS status = ops->QueryName(file, relativeOut, relativeCapacity, &relativeBytes);
    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW)
    {
        /* The device has a namespace and no path for THIS file. Every refusal
         * QueryName can make today is that statement -- npfs's
         * STATUS_PIPE_DISCONNECTED for an unnamed or unlinked pipe, fat32's
         * STATUS_OBJECT_PATH_INVALID for a chain past 64 components -- and the
         * object namespace has one name for it. */
        return STATUS_OBJECT_PATH_INVALID;
    }
    /* The two passes must agree, and the second is the one with the caller's
     * buffer: an overflow there would mean the length moved between them,
     * which nothing can do (no blocking point separates the calls, Art. 3). */
    ASSERT(out == 0 || status == STATUS_SUCCESS);

    /* No ceiling here: a name too long to REPORT is the caller's contract with
     * OBJECT_NAME_INFORMATION, refused once at kernel/ob/handle.c rather than
     * per type. */
    *nameBytes = (ULONG)deviceBytes + relativeBytes;
    if (out != 0)
    {
        ObpWriteFullName(ObpGetHeader(file->device), out);
    }
    return STATUS_SUCCESS;
}

/* IoFileObjectType.securityStorage: whose descriptor a FILE handle reports.
 *
 * Ob's default is the file object's own header, i.e. one descriptor per OPEN,
 * which is what every device here has always had. That is wrong for a device
 * whose files ARE something else's — a named pipe's descriptor belongs to the
 * PIPE, shared by both ends and every instance of the name (server/named_pipe.c
 * pipe_end_get_sd) — so the device gets the say, once, rather than Se growing a
 * per-device branch (Art. 11). */
static NTSTATUS IopFileObjectSecurityStorage(PVOID body, PVOID **slot)
{
    PFILE_OBJECT file = body;
    if (file->device->ops->SecurityStorage != 0)
    {
        /* `*slot` already holds this open's own (ob.h), so a device answers
         * only for the handles it has something else to say about. */
        return file->device->ops->SecurityStorage(file, slot);
    }
    return STATUS_SUCCESS;
}

OBJECT_TYPE IoFileObjectType = {
    .name = "File",
    .validAccess = FILE_ALL_ACCESS,
    .waitable = TRUE, /* born signaled; see io.h */
    .deleteProcedure = IopDeleteFileObject,
    .closeProcedure = IopCloseFileObject,
    .queryName = IopQueryFileObjectName,
    .securityStorage = IopFileObjectSecurityStorage,
    /* Every file-ish get_full_name in the oracle sets this one explicitly
     * where the generic walk leaves STATUS_INFO_LENGTH_MISMATCH (ob.h). */
    .nameTooShortStatus = STATUS_BUFFER_OVERFLOW,
    /* The real NT generic mapping, as wineserver's file_type
     * (third_party/wine server/file.c). Without it a GENERIC_READ open fell
     * into the always-allow branch and was granted FILE_ALL_ACCESS — whose
     * write/delete bits then counted in the share-mode ledger, so TWO
     * read-sharing GENERIC_READ opens of one file collided
     * (sem_mm/mapped_same's double open of ntdll.dll convicted it). */
    .genericRead = FILE_GENERIC_READ,
    .genericWrite = FILE_GENERIC_WRITE,
    .genericExecute = FILE_GENERIC_EXECUTE,
    .genericAll = FILE_ALL_ACCESS,
};

/* --- share-mode accounting (NT's IoCheckShareAccess/IoSetShareAccess) ------ */

/* The three access bits share modes govern; attribute-only opens carry none
 * of them and bypass the check entirely (the NT rule sem_file/share_modes
 * pins). */
static void IopShareRelevantAccess(ACCESS_MASK desiredAccess, BOOLEAN *reads, BOOLEAN *writes,
                                   BOOLEAN *deletes)
{
    *reads = (desiredAccess & (FILE_READ_DATA | FILE_EXECUTE)) != 0;
    *writes = (desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;
    *deletes = (desiredAccess & DELETE) != 0;
}

/* Does this disposition arrive at the file with the intent to truncate? The
 * pinned oracle asks the question as `open_flags & O_TRUNC`, and its three
 * O_TRUNC dispositions are FILE_SUPERSEDE, FILE_OVERWRITE_IF and
 * FILE_OVERWRITE (wine server/file.c create_file's switch, :233-:241). */
static BOOLEAN IopDispositionTruncates(ULONG disposition)
{
    return disposition == FILE_SUPERSEDE || disposition == FILE_OVERWRITE ||
           disposition == FILE_OVERWRITE_IF;
}

NTSTATUS IoCheckShareAccess(ACCESS_MASK desiredAccess, ULONG shareAccess, ULONG disposition,
                            ULONG options, PIO_FCB fcb)
{
    BOOLEAN reads, writes, deletes;
    IopShareRelevantAccess(desiredAccess, &reads, &writes, &deletes);
    IO_SHARE_ACCESS *share = &fcb->shareAccess;
    BOOLEAN sharesRead = (shareAccess & FILE_SHARE_READ) != 0;
    BOOLEAN sharesWrite = (shareAccess & FILE_SHARE_WRITE) != 0;
    BOOLEAN sharesDelete = (shareAccess & FILE_SHARE_DELETE) != 0;

    /* The ladder below is the pinned oracle's, in ITS order (wine
     * server/fd.c check_sharing): the two share-mode directions are NOT
     * adjacent — the section rules sit between them, and above the
     * attribute-only escape. Both placements are observable and pinned by
     * sem_mm/section_file_hold. */

    /* 1. What I want must be shared by every existing opener. */
    if ((reads && share->sharedRead != share->openCount) ||
        (writes && share->sharedWrite != share->openCount) ||
        (deletes && share->sharedDelete != share->openCount))
    {
        return STATUS_SHARING_VIOLATION;
    }

    /* 2. What live SECTIONS hold. A section is a pseudo-open carrying no
     * read/write/delete bit of its own, so it constrains an opener only
     * through these three counters — and it constrains one that asks for no
     * data access at all, which step 4 below would let through. */
    if ((fcb->writableSectionCount != 0 && !sharesWrite) ||
        (fcb->imageSectionCount != 0 && (desiredAccess & FILE_WRITE_DATA) != 0))
    {
        return STATUS_SHARING_VIOLATION;
    }
    if (fcb->imageSectionCount != 0 && (options & FILE_DELETE_ON_CLOSE) != 0)
    {
        return STATUS_CANNOT_DELETE;
    }
    if (fcb->sectionCount != 0 && IopDispositionTruncates(disposition))
    {
        return STATUS_USER_MAPPED_FILE;
    }

    /* 3. An attribute-only open is exempt from ordinary share modes (the NT
     * rule sem_file/share_modes pins) — but not, per step 2, from a
     * section's. */
    if (!reads && !writes && !deletes)
    {
        return STATUS_SUCCESS;
    }

    /* 4. And what I share must cover what every existing opener holds. */
    if ((!sharesRead && share->readers != 0) || (!sharesWrite && share->writers != 0) ||
        (!sharesDelete && share->deleters != 0))
    {
        return STATUS_SHARING_VIOLATION;
    }
    return STATUS_SUCCESS;
}

void IoSetShareAccess(ACCESS_MASK desiredAccess, ULONG shareAccess, PIO_FCB fcb)
{
    BOOLEAN reads, writes, deletes;
    IopShareRelevantAccess(desiredAccess, &reads, &writes, &deletes);
    if (!reads && !writes && !deletes)
    {
        return;
    }
    IO_SHARE_ACCESS *share = &fcb->shareAccess;
    share->openCount++;
    share->readers += reads ? 1 : 0;
    share->writers += writes ? 1 : 0;
    share->deleters += deletes ? 1 : 0;
    share->sharedRead += (shareAccess & FILE_SHARE_READ) ? 1 : 0;
    share->sharedWrite += (shareAccess & FILE_SHARE_WRITE) ? 1 : 0;
    share->sharedDelete += (shareAccess & FILE_SHARE_DELETE) ? 1 : 0;
}

void IoRemoveShareAccess(ACCESS_MASK desiredAccess, ULONG shareAccess, PIO_FCB fcb)
{
    BOOLEAN reads, writes, deletes;
    IopShareRelevantAccess(desiredAccess, &reads, &writes, &deletes);
    if (!reads && !writes && !deletes)
    {
        return;
    }
    IO_SHARE_ACCESS *share = &fcb->shareAccess;
    ASSERT(share->openCount > 0);
    share->openCount--;
    share->readers -= reads ? 1 : 0;
    share->writers -= writes ? 1 : 0;
    share->deleters -= deletes ? 1 : 0;
    share->sharedRead -= (shareAccess & FILE_SHARE_READ) ? 1 : 0;
    share->sharedWrite -= (shareAccess & FILE_SHARE_WRITE) ? 1 : 0;
    share->sharedDelete -= (shareAccess & FILE_SHARE_DELETE) ? 1 : 0;
}

/* --- helpers ---------------------------------------------------------------- */

NTSTATUS IopReferenceFileByHandle(HANDLE handle, ACCESS_MASK desiredAccess, PFILE_OBJECT *fileOut,
                                  POBJECT_HANDLE_INFORMATION handleInformation)
{
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(handle, desiredAccess, &IoFileObjectType,
                                                ExGetPreviousMode(), &body, handleInformation);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *fileOut = body;
    return STATUS_SUCCESS;
}

/* Resolve a completion-event handle. THE authority for the question, used
 * both by the up-front check every operation makes before doing any work and
 * by the completion below. */
static NTSTATUS IopReferenceCompletionEvent(HANDLE eventHandle, PVOID *eventOut)
{
    return ObReferenceObjectByHandle(eventHandle, EVENT_MODIFY_STATE, &ObpEventType,
                                     ExGetPreviousMode(), eventOut, 0);
}

NTSTATUS IopValidateEventHandle(HANDLE eventHandle)
{
    if (eventHandle == 0)
    {
        return STATUS_SUCCESS;
    }
    PVOID eventBody;
    NTSTATUS status = IopReferenceCompletionEvent(eventHandle, &eventBody);
    if (NT_SUCCESS(status))
    {
        ObDereferenceObject(eventBody);
    }
    return status;
}

/* The failure twin of IopCompleteRequest's event half: the caller's event is
 * RESET, and the IOSB is left untouched. That is the oracle's shape for a
 * request that fails after its handle resolved — dlls/ntdll/unix/file.c
 * NtWriteFile ends with
 *
 *     if (status == STATUS_SUCCESS) { set_sync_iosb(...); if (event) NtSetEvent(event, NULL); }
 *     else if (status != STATUS_PENDING && event) NtResetEvent(event, NULL);
 *
 * so a caller that pre-signalled its event sees it go DOWN on failure, with
 * no IOSB write to tell it apart. Callers couple the two (ntdll:file's
 * "event is not signaled" check reads the event and the IOSB together), so
 * leaving a pre-signalled event alone is observably wrong even when the
 * returned status is right. Signalling goes through the same
 * IopReferenceCompletionEvent authority (Art. 11), and a failure to reset
 * is discarded for the same reason it is at completion. */
void IopAbandonRequest(HANDLE eventHandle)
{
    IopResetRequestEvent(eventHandle);
}

/* Everything a FILE_OBJECT derives from the create OPTIONS word, in one
 * place (Art. 11). There are two construction sites — IopCreateFile below
 * and NtCreateNamedPipeFile (fs/npfs/pipe.c), whose comment says it builds
 * the object "exactly as IopCreateFile does" — and the second one had
 * drifted: it set `synchronousIo` and nothing else, so a pipe handle
 * reported a zero FileModeInformation whatever it was opened with, its
 * syncIoLock was never initialised, and FILE_SYNCHRONOUS_IO_ALERT could not
 * be seen at all (the park is keyed on `modeFlags`, io.h IoSyncIoAlerted).
 * Two paths that are only currently equivalent drift; this one already had. */
void IopCaptureCreateOptions(PFILE_OBJECT file, ULONG options)
{
    file->synchronousIo =
        (options & (FILE_SYNCHRONOUS_IO_NONALERT | FILE_SYNCHRONOUS_IO_ALERT)) != 0;
    /* Born signalled: free until its first synchronous-I/O holder. */
    KeInitializeEvent(&file->syncIoLock, SynchronizationEvent, TRUE);
    file->deleteOnClose = (options & FILE_DELETE_ON_CLOSE) != 0;
    file->nonBuffered = (options & FILE_NO_INTERMEDIATE_BUFFERING) != 0;
    /* The FileModeInformation word: exactly the bits the pinned Wine's
     * server masks in (third_party/wine server/fd.c
     * default_fd_get_file_info; pinned sem_file/async_inline.c). */
    file->modeFlags =
        options & (FILE_WRITE_THROUGH | FILE_SEQUENTIAL_ONLY | FILE_NO_INTERMEDIATE_BUFFERING |
                   FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT);
}

void IopResetRequestEvent(HANDLE eventHandle)
{
    if (eventHandle == 0)
    {
        return;
    }
    PVOID eventBody;
    if (NT_SUCCESS(IopReferenceCompletionEvent(eventHandle, &eventBody)))
    {
        KeResetEvent(eventBody);
        ObDereferenceObject(eventBody);
    }
}

void IopSetRequestEvent(HANDLE eventHandle)
{
    if (eventHandle == 0)
    {
        return;
    }
    PVOID eventBody;
    if (NT_SUCCESS(IopReferenceCompletionEvent(eventHandle, &eventBody)))
    {
        KeSetEvent(eventBody, 0, FALSE);
        ObDereferenceObject(eventBody);
    }
}

NTSTATUS IopCompleteRequest(IO_STATUS_BLOCK *iosb, HANDLE eventHandle, NTSTATUS status,
                            ULONG_PTR information)
{
    /* The contract order (docs/08): the IOSB is visible BEFORE any
     * completion signal fires.
     *
     * Re-validated here, at the one authority every completion funnels
     * through (Art. 11): completions run AFTER the operation's parks, so
     * the caller's entry probe is stale — a sibling may have unmapped the
     * IOSB, and a raw store would ring-0-fault and unwind past the
     * caller's cleanup (the rw.c re-probe rule; PR #95 review round 2,
     * F2). A vanished IOSB skips the store only: the transfer HAS
     * happened, so the operation's own status still returns and the event
     * still fires — NT's I/O manager writes the requestor's IOSB under the
     * same swallow-the-fault guard. No park separates probe and store;
     * no-op success for a KernelMode caller's kernel IOSB (uaccess.h). */
    KI_PROBE_TOKEN iosbToken;
    if (NT_SUCCESS(KiProbeForWriteToken(iosb, sizeof(*iosb), sizeof(void *), &iosbToken)))
    {
        IO_STATUS_BLOCK final;
        final.Status = status;
        final.Information = information;
        /* Through the token, so a park reintroduced between this probe and
         * this store is fatal here rather than a ring-0 fault unwinding past
         * every caller's cleanup (issue #96 C). */
        KiWriteUser(&iosbToken, iosb, &final, sizeof(final));
    }
    /* A failure to signal the event is DISCARDED, and the operation's own
     * status is returned. That is the oracle's behaviour -- third_party/wine
     * dlls/ntdll/unix/file.c spells it `if (event) NtSetEvent( event, NULL );`
     * at every completion, with no test of the result -- and it is also the
     * only answer that can be honest: by the time this runs the transfer HAS
     * happened, so reporting STATUS_INVALID_HANDLE would tell the caller
     * nothing occurred while the bytes were already gone
     * (docs/review-2026-07 §7). Services whose oracle refuses a bad event
     * handle do so BEFORE any work, through IopValidateEventHandle. */
    IopSetRequestEvent(eventHandle);
    return status;
}

/* --- initialization --------------------------------------------------------- */

PIO_DEVICE IoPublishDevice(const WCHAR *name, const IO_VFS_OPS *ops, PVOID context,
                           ULONG deviceType)
{
    UNICODE_STRING deviceName;
    OBJECT_ATTRIBUTES attributes;
    RtlInitUnicodeString(&deviceName, name);
    memset(&attributes, 0, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &deviceName;
    attributes.Attributes = OBJ_PERMANENT;

    PVOID body;
    HANDLE handle;
    NTSTATUS status = ObpCreateObjectWithHandle(&IoDeviceType, sizeof(IO_DEVICE), &attributes,
                                                FILE_ALL_ACCESS, &body, &handle);
    if (status != STATUS_SUCCESS)
    {
        DbgPrint("io: cannot publish %ls: %08lx\n", name, (unsigned long)status);
        KiPanic("IoPublishDevice: cannot create a device object");
    }
    PIO_DEVICE device = body;
    device->ops = ops;
    device->context = context;
    device->deviceType = deviceType;
    /* The namespace holds the object (OBJ_PERMANENT); the transient handle
     * has done its job. */
    NtClose(handle);
    return device;
}

static PIO_DEVICE IopBootVolumeDevice;

/* The one completion-drain authority (CUI-8, docs/19 §5b/§11) the blk
 * completion ISR, the tick's latency-bound backstop, and every
 * thread-context waiter call (contract in ke.h — dispatcher lock held;
 * the ISR holds it by arriving, docs/18 §6d). The KiInCompletionDrain
 * bracket is docs/20 R2's arming: any allocator call the drain ever grows
 * asserts immediately instead of corrupting a free list once in a
 * thousand boots. */
ULONG IoDrainDeviceCompletions(void)
{
    BOOLEAN blkPresent = VioBlkIsPresent();
    BOOLEAN sndPresent = VioSndIsPresent();
    if (!blkPresent && !sndPresent && !VioNetIsPresent())
    {
        return 0;
    }
    /* Two prohibitions, deliberately separate: KiInCompletionDrain forbids
     * ALLOCATION (docs/20 R2, asserted in mm), the no-block region forbids
     * PARKING (issue #96 A, asserted at every blocking primitive). The drain
     * is reached from the completion ISR, from the tick, and from
     * thread-context awaiters, so the region must nest — it counts. The snd
     * arm EXTENDS this one authority rather than adding a second harvest
     * path (Art. 11; docs/23 §4a) — its tick-tail call is what bounds a
     * period completion at 1 ms without an MSI-X vector (docs/19 §11f). */
    KiEnterNoBlockRegion("completion drain");
    KiInCompletionDrain = TRUE;
    if (blkPresent)
    {
        VioBlkDrain();
    }
    if (sndPresent)
    {
        VioSndDrain();
    }
    /* Net-1 (docs/24 §4a): the net arm of the same one authority —
     * harvest-store-wake against the tick tail's 1 ms bound (docs/19
     * §11f: no MSI-X vector for net; the escape stays named there). */
    VioNetDrain();
    KiInCompletionDrain = FALSE;
    KiLeaveNoBlockRegion();
    return (blkPresent ? VioBlkInFlightCount() : 0) + (sndPresent ? VioSndInFlightCount() : 0);
}

void IoInitializeTransport(void)
{
    if (!VioBlkInitialize())
    {
        DbgPrint("io: no boot disk; file surface disabled\n");
    }
    /* GUI-1: the raw input source behind \Device\Input0 (HACK-002). Absent
     * on every image but the gui one, which is why this says so and moves
     * on -- drivers/hid.c then publishes no device at all. */
    if (!VioInputInitialize())
    {
        DbgPrint("io: no input device; \\Device\\Input0 disabled\n");
    }
    /* AUD-1: the PCM transport behind \Device\Snd* (HACK-007). Absent on
     * every run but the audio leg's -- drivers/snd.c then publishes no
     * device at all. */
    if (!VioSndInitialize())
    {
        DbgPrint("io: no sound device; \\Device\\Snd* disabled\n");
    }
    /* Net-1: the NIC probe joins blk and input here because the virtio BAR
     * map and every DMA allocation must precede MiFreezeKernelPml4
     * (docs/24 §4a); bring-up — lwIP, netd, DHCP — is deliberately later
     * (NetInitialize). Absent on every image but the net leg's. */
    if (!VioNetInitialize())
    {
        DbgPrint("io: no network device\n");
    }
}

void IoMountBootVolume(void)
{
    if (!VioBlkIsPresent())
    {
        return;
    }
    PFAT_VOLUME volume;
    NTSTATUS status = FatMountBootVolume(&volume);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("io: FAT32 mount failed %08lx\n", (unsigned long)status);
        return;
    }

    /* \Device\HarddiskVolume1 (permanent), then \??\C: -> it. A mounted disk
     * filesystem, as the pinned oracle reports one (Wine
     * dlls/ntdll/unix/file.c get_device_info: regular files/directories →
     * FILE_DEVICE_DISK_FILE_SYSTEM; GetFileType maps it to FILE_TYPE_DISK). */
    IopBootVolumeDevice = IoPublishDevice(WSTR("\\Device\\HarddiskVolume1"), &FatVfsOps, volume,
                                          FILE_DEVICE_DISK_FILE_SYSTEM);

    HANDLE handle;
    OBJECT_ATTRIBUTES attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.Attributes = OBJ_PERMANENT;
    UNICODE_STRING linkName, target;
    RtlInitUnicodeString(&linkName, WSTR("\\??\\C:"));
    RtlInitUnicodeString(&target, WSTR("\\Device\\HarddiskVolume1"));
    attributes.ObjectName = &linkName;
    status = NtCreateSymbolicLinkObject(&handle, SYMBOLIC_LINK_ALL_ACCESS, &attributes, &target);
    if (!NT_SUCCESS(status))
    {
        KiPanic("IoInitialize: cannot create \\??\\C:");
    }
    NtClose(handle);

    /* The volume's OTHER name, and the device that says the two are the
     * same volume. Strictly after \??\C: and the device object above: the
     * mount manager's \??\Volume{...} link targets that device, and its
     * QUERY_POINTS reply describes that drive letter. */
    IoInitializeMountManager();
}

/* --- NtCreateFile / NtOpenFile ---------------------------------------------- */

/* The create-path IOSB store, re-probed at each use: every store runs after
 * the gated Create (and, on the handle-mint failure leg, after a parking
 * cleanup), so the entry probe is stale — the IopCompleteRequest convention
 * (PR #95 review round 2, F2): a vanished IOSB skips the store only, never
 * unwinds the create. No park separates probe and store. */
static void IopWriteCreateIosb(PIO_STATUS_BLOCK iosb, NTSTATUS status, ULONG_PTR information)
{
    KI_PROBE_TOKEN iosbToken;
    if (NT_SUCCESS(KiProbeForWriteToken(iosb, sizeof(*iosb), sizeof(void *), &iosbToken)))
    {
        IO_STATUS_BLOCK final;
        final.Status = status;
        final.Information = information;
        /* Through the token, so a park reintroduced between this probe and
         * this store is fatal here rather than a ring-0 fault unwinding past
         * every caller's cleanup (issue #96 C). */
        KiWriteUser(&iosbToken, iosb, &final, sizeof(final));
    }
}

/* Resolve an OBJECT_ATTRIBUTES.RootDirectory that names an open FILE into the
 * (root, device) pair a relative name is resolved against, with the device
 * reference the caller then owns.
 *
 * One statement of the pair because the ownership is the whole content: the
 * root's reference keeps the FILE_OBJECT alive for the Create call that reads
 * it, and the device's is what moves into the new FILE_OBJECT. Two entry
 * points take a relative root — IopCreateFile below and
 * NtCreateNamedPipeFile (fs/npfs/pipe.c) — and their LADDERS around this
 * differ (which roots are legal, and what an absolute name under one
 * answers), so what is shared is this step and not the ladder.
 *
 * A root that is not a File is reported as ObReferenceObjectByHandle reports
 * it; the callers decide what that means. */
NTSTATUS IopReferenceRelativeRoot(HANDLE rootDirectory, PFILE_OBJECT *rootOut,
                                  PIO_DEVICE *deviceOut)
{
    PVOID rootBody;
    NTSTATUS status = ObReferenceObjectByHandle(rootDirectory, 0, &IoFileObjectType,
                                                ExGetPreviousMode(), &rootBody, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PFILE_OBJECT root = rootBody;
    *rootOut = root;
    *deviceOut = root->device;
    ObfReferenceObject(root->device);
    return STATUS_SUCCESS;
}

static NTSTATUS IopCreateFile(PHANDLE handleOut, ACCESS_MASK desiredAccess,
                              POBJECT_ATTRIBUTES attributes, PIO_STATUS_BLOCK iosb,
                              ULONG fileAttributes, ULONG shareAccess, ULONG disposition,
                              ULONG options)
{
    if (handleOut == 0 || iosb == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(iosb, sizeof(*iosb), sizeof(void *));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (disposition > FILE_MAXIMUM_DISPOSITION)
    {
        return STATUS_INVALID_PARAMETER;
    }
    /* Io parses attributes->ObjectName into a filesystem path itself rather
     * than through the Ob namespace engine, so it has to ask for the same
     * validation the engine does -- otherwise a ring-3 pointer is read here
     * with no check at all. */
    NTSTATUS probeStatus = ObProbeObjectAttributes(attributes);
    if (!NT_SUCCESS(probeStatus))
    {
        return probeStatus;
    }
    if (attributes == 0 || attributes->ObjectName == 0)
    {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    ACCESS_MASK granted = ObpMapDesiredAccess(&IoFileObjectType, desiredAccess);
    /* Overwrite dispositions carry an implicit FILE_WRITE_ATTRIBUTES grant
     * (Wine server/file.c create_file: FILE_OVERWRITE / FILE_OVERWRITE_IF do
     * `access |= FILE_WRITE_ATTRIBUTES`), which also makes the handle's
     * backing writable for set-EOF (sem_file/info_classes pins this). */
    if (disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF)
    {
        granted |= FILE_WRITE_ATTRIBUTES;
    }

    /* Resolve the device + FS-remaining path. RootDirectory may be an open
     * directory File (a relative open) or an Ob container. */
    PIO_DEVICE device = 0;
    PFILE_OBJECT relativeTo = 0;
    UNICODE_STRING fsPath;
    PWSTR reparseBuffer = 0;
    PWSTR fsPathCopy = 0;

    if (attributes->RootDirectory != 0)
    {
        status = IopReferenceRelativeRoot(attributes->RootDirectory, &relativeTo, &device);
        if (NT_SUCCESS(status))
        {
            fsPath = *attributes->ObjectName;
            /* An ABSOLUTE name under a RootDirectory handle is
             * STATUS_INVALID_PARAMETER, not a syntax error. The two are easy
             * to conflate — both mean "this name is wrong" — but NT keeps
             * them apart by which argument is at fault, and the oracle says
             * so in one line at the top of its with-root path:
             *
             *   if (name_len && name[0] == '\\') return STATUS_INVALID_PARAMETER;
             *   (third_party/wine dlls/ntdll/unix/file.c)
             *
             * STATUS_OBJECT_PATH_SYNTAX_BAD is the answer for the OPPOSITE
             * mistake — a relative name with NO root — which
             * ObpLookupName still gives. ntdll:path asserts both (entry 59
             * for the syntax error, entry 53 for this one). */
            if (fsPath.Length >= sizeof(WCHAR) && fsPath.Buffer[0] == '\\')
            {
                ObDereferenceObject(relativeTo);
                ObDereferenceObject(device);
                return STATUS_INVALID_PARAMETER;
            }
        }
    }
    if (device == 0)
    {
        PVOID deviceBody;
        status = ObpLookupParseObject(attributes, &IoDeviceType, 0, &deviceBody, &fsPath,
                                      &reparseBuffer);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        device = deviceBody;
    }

    /* Both resolutions can leave fsPath pointing into the CALLER'S buffer
     * (the relative form aliases attributes->ObjectName outright; the parse
     * walk's remaining-name contract says so, kernel/ob/namespace.c). The FS
     * walks it under the volume gate, across parks — where a sibling's unmap
     * would turn the walk into a ring-0 fault whose unwind skips
     * FatReleaseVolumeGate and orphans the gate for good (docs/20 R3a). So
     * capture it to kernel memory HERE, where a fault still has nothing to
     * leak — the IopSetRenameInformation / volume-label precedent. */
    if (fsPath.Length != 0)
    {
        fsPathCopy = MiAllocatePool(fsPath.Length);
        if (fsPathCopy == 0)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto out_device;
        }
        memcpy(fsPathCopy, fsPath.Buffer, fsPath.Length);
        fsPath.Buffer = fsPathCopy;
        fsPath.MaximumLength = fsPath.Length;
    }

    /* Build the File object and hand the rest to the FS. */
    PVOID body;
    status = ObpAllocateObject(&IoFileObjectType, sizeof(FILE_OBJECT), &body);
    if (!NT_SUCCESS(status))
    {
        goto out_device;
    }
    PFILE_OBJECT file = body;
    KeInitializeEvent(&file->header, NotificationEvent, TRUE);
    file->device = device; /* the allocation's device reference moves in */
    device = 0;
    IopCaptureCreateOptions(file, options);
    file->grantedAccess = granted;
    file->desiredAccess = desiredAccess;
    file->shareAccess = shareAccess;

    ULONG_PTR information = 0;
    status =
        file->device->ops->Create(file->device, file, &fsPath, relativeTo, granted, shareAccess,
                                  fileAttributes, disposition, options, &information);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(file);
        /* NtCreateFile writes the IOSB on FS-level failure too (pinned
         * Wine: iosb.Status carries the failing status). */
        IopWriteCreateIosb(iosb, status, 0);
        goto out;
    }

    status = ObpCreateHandle(file, granted, attributes->Attributes, handleOut);
    if (!NT_SUCCESS(status))
    {
        /* The comment here used to say "close/cleanup run via the type
         * hooks". Only HALF of that was true: deleteProcedure runs on the
         * last reference, while the CLEANUP half is reached only through a
         * handle close and no handle was ever made -- so IoRemoveShareAccess,
         * IopReleaseAllLocks and ops->Cleanup were all skipped, and the
         * FCB's share counts stayed inflated for its whole lifetime, i.e.
         * STATUS_SHARING_VIOLATION on every later open of that file
         * (docs/review-2026-07 §7). The create SUCCEEDED, so this open needs
         * the cleanup half explicitly, which is why IopCleanupFileObject is
         * its own function rather than an arm of the hook. */
        IopCleanupFileObject(file);
        ObDereferenceObject(file);
        IopWriteCreateIosb(iosb, status, 0);
        goto out;
    }
    /* One handle now exists, and the CLEANUP arm of closeProcedure runs
     * only when handleCount returns to zero; drop the creator's reference. */
    ObDereferenceObject(file);
    IopWriteCreateIosb(iosb, STATUS_SUCCESS, information);
    status = STATUS_SUCCESS;

out:
    if (relativeTo != 0)
    {
        ObDereferenceObject(relativeTo);
    }
    if (reparseBuffer != 0)
    {
        MiFreePool(reparseBuffer);
    }
    if (fsPathCopy != 0)
    {
        MiFreePool(fsPathCopy);
    }
    return status;

out_device:
    if (device != 0)
    {
        ObDereferenceObject(device);
    }
    goto out;
}

NTSTATUS NtCreateFile(PHANDLE handle, ACCESS_MASK access, POBJECT_ATTRIBUTES attr,
                      PIO_STATUS_BLOCK ioStatus, PLARGE_INTEGER allocSize, ULONG attributes,
                      ULONG sharing, ULONG disposition, ULONG options, PVOID eaBuffer,
                      ULONG eaLength)
{
    (void)allocSize; /* advisory pre-allocation; FAT ignores it */
    /* The clear sits at the ENTRY POINT, not in IopCreateFile, because that
     * is where the oracle states it (dlls/ntdll/unix/file.c NtCreateFile
     * opens with `*handle = 0;`; NtOpenFile reaches it by tail-calling
     * NtCreateFile) and because the engine also serves the transient
     * kernel-internal opens below. Above the EA refusal: a refusal of the
     * operation owes the cleared slot too. */
    NTSTATUS status = ObpClearOutHandle(handle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (eaBuffer != 0 && eaLength != 0)
    {
        return STATUS_EAS_NOT_SUPPORTED; /* FAT has no extended attributes */
    }
    return IopCreateFile(handle, access, attr, ioStatus, attributes, sharing, disposition, options);
}

NTSTATUS NtOpenFile(PHANDLE handle, ACCESS_MASK access, POBJECT_ATTRIBUTES attr,
                    PIO_STATUS_BLOCK ioStatus, ULONG sharing, ULONG options)
{
    NTSTATUS status = ObpClearOutHandle(handle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    return IopCreateFile(handle, access, attr, ioStatus, FILE_ATTRIBUTE_NORMAL, sharing, FILE_OPEN,
                         options);
}

/* --- transient kernel-internal handles ------------------------------------
 *
 * Several services compose their answer out of an internal open, one
 * operation, and a close (NtDeleteFile, IopProbeTargetPath, the
 * attribute-only queries). The handle lives in the CALLER's table, so an exit
 * between the two halves leaks a handle the caller never asked for and cannot
 * name — and since CUI-8 the operation in the middle parks under the volume
 * gate, so a ring-0 fault there really can unwind past the close
 * (kernel/syscall/uaccess.h: an unwind runs no cleanup).
 *
 * One pair of helpers so that the previousMode dance and the obligation
 * ledger (issue #96 B) are stated once instead of at four call sites. */
static NTSTATUS IopOpenTransientFile(PHANDLE handle, ACCESS_MASK access,
                                     POBJECT_ATTRIBUTES attributes, KPROCESSOR_MODE attributesMode,
                                     PIO_STATUS_BLOCK iosb, ULONG fileAttributes, ULONG sharing,
                                     ULONG disposition, ULONG options)
{
    PKTHREAD thread = KeGetCurrentThread();
    KPROCESSOR_MODE saved = thread->previousMode;
    /* The HANDLE is kernel-internal; the NAME usually is not. Three of the
     * four callers hand this their own caller's OBJECT_ATTRIBUTES, and the
     * elevation below switches off every probe under IopCreateFile (probes
     * are previous-mode aware — kernel/syscall/uaccess.h), so without this
     * the block, the UNICODE_STRING inside it and that string's Buffer are
     * all read at ring 0 with nothing checked: ring 3 halts the machine with
     * a misaligned name pointer, because a UBSan trap is a #UD and the
     * service's fault-recovery frame only catches page faults. So the block
     * is validated HERE, while previousMode is still the caller's, and
     * `attributesMode` is how a caller with a kernel-built block
     * (IopProbeTargetPath) says the question does not apply to it. Pinned by
     * tests/ntapi/sem_file/hostile_name.c; found by the pointer-torture
     * matrix (issue #32 A1). */
    if (attributesMode != KernelMode)
    {
        NTSTATUS probeStatus = ObProbeObjectAttributes(attributes);
        if (!NT_SUCCESS(probeStatus))
        {
            return probeStatus;
        }
    }
    thread->previousMode = KernelMode; /* the handle is kernel-internal */
    NTSTATUS status = IopCreateFile(handle, access, attributes, iosb, fileAttributes, sharing,
                                    disposition, options);
    thread->previousMode = saved;
    if (NT_SUCCESS(status))
    {
        KiPushObligation(KI_OBLIGATION_TRANSIENT, *handle);
    }
    return status;
}

static void IopCloseTransientFile(HANDLE handle)
{
    PKTHREAD thread = KeGetCurrentThread();
    KPROCESSOR_MODE saved = thread->previousMode;
    thread->previousMode = KernelMode;
    KiPopObligation(KI_OBLIGATION_TRANSIENT, handle);
    NtClose(handle);
    thread->previousMode = saved;
}

/* CUI-5: the by-name delete. The pinned Wine implements it as exactly this
 * open (GENERIC_READ|GENERIC_WRITE|DELETE, full sharing, FILE_OPEN,
 * FILE_DELETE_ON_CLOSE) followed by a close (dlls/ntdll/unix/file.c
 * NtDeleteFile), so proskrnl composes the same primitives through the one
 * create engine (Art. 11). Pinned by sem_file/delete_file.c. */
NTSTATUS NtDeleteFile(POBJECT_ATTRIBUTES attributes)
{
    HANDLE handle;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status = IopOpenTransientFile(
        &handle, GENERIC_READ | GENERIC_WRITE | DELETE, attributes, ExGetPreviousMode(), &iosb, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_DELETE_ON_CLOSE);
    if (NT_SUCCESS(status))
    {
        IopCloseTransientFile(handle);
    }
    return status;
}

/* CUI-5 rename support: the pinned Wine resolves the caller's whole target
 * path (dlls/ntdll/unix/file.c get_nt_and_unix_names with FILE_OPEN_IF)
 * before it ever references the rename handle, so a dead intermediate
 * directory in the target answers even over a bad handle (fuzzer-found;
 * pinned by sem_file/rename.c). Mirror the gate with an attribute-only
 * internal open: an existing target or a merely missing leaf passes, any
 * other failure is the caller's answer. */
NTSTATUS IopProbeTargetPath(POBJECT_ATTRIBUTES attributes)
{
    HANDLE handle;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status =
        IopOpenTransientFile(&handle, FILE_READ_ATTRIBUTES, attributes, KernelMode, &iosb, 0,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0);
    if (NT_SUCCESS(status))
    {
        IopCloseTransientFile(handle);
    }
    return status == STATUS_OBJECT_NAME_NOT_FOUND ? STATUS_SUCCESS : status;
}

NTSTATUS NtQueryAttributesFile(const OBJECT_ATTRIBUTES *attr, FILE_BASIC_INFORMATION *info)
{
    if (info == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    /* Alignment 1, not 8. The WOW64 thunk hands the caller's 32-bit pointer
     * straight down (`return NtQueryAttributesFile( attr, info )` after only
     * the OBJECT_ATTRIBUTES conversion — third_party/wine dlls/wow64/file.c
     * wow64_NtQueryAttributesFile), and an i386 caller's stack
     * FILE_BASIC_INFORMATION is 4-aligned, so refusing a 4-mod-8 output is a
     * STATUS_DATATYPE_MISALIGNMENT the oracle never answers — the same
     * divergence sem_ps/misaligned_out.c pinned for the time queries. The
     * fill below already stages in a local and copies out as bytes, so
     * nothing here dereferences the caller's pointer at width. */
    NTSTATUS status = KiProbeForWrite(info, sizeof(*info), 1);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* An attribute-only internal open (bypasses share modes), query, close. */
    HANDLE handle;
    IO_STATUS_BLOCK iosb;
    PKTHREAD thread = KeGetCurrentThread();
    KPROCESSOR_MODE saved = thread->previousMode;
    status =
        IopOpenTransientFile(&handle, FILE_READ_ATTRIBUTES, (POBJECT_ATTRIBUTES)(uintptr_t)attr,
                             ExGetPreviousMode(), &iosb, FILE_ATTRIBUTE_NORMAL,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* The transient handle lives in the CALLER's handle table, so it is
     * user-closable: a sibling thread racing NtClose against this window
     * makes the reference fail, and an ASSERT here would turn that into a
     * machine halt (docs/review-2026-07 §2). Today Art. 3's no-preemption
     * mandate closes the window, but the mandate has a named exit
     * (docs/18 §13) and this outlives it. */
    PFILE_OBJECT file;
    thread->previousMode = KernelMode;
    NTSTATUS refStatus = IopReferenceFileByHandle(handle, 0, &file, 0);
    thread->previousMode = saved;
    if (!NT_SUCCESS(refStatus))
    {
        IopCloseTransientFile(handle);
        return refStatus;
    }
    IO_FILE_INFO raw;
    status = file->device->ops->GetInfo(file, &raw);
    if (NT_SUCCESS(status))
    {
        FILE_BASIC_INFORMATION out;
        memset(&out, 0, sizeof(out));
        out.CreationTime = raw.creationTime;
        out.LastAccessTime = raw.lastAccessTime;
        out.LastWriteTime = raw.lastWriteTime;
        out.ChangeTime = raw.lastWriteTime;
        out.FileAttributes = raw.fileAttributes;
        memcpy(info, &out, sizeof(out));
    }
    ObDereferenceObject(file);
    IopCloseTransientFile(handle);
    return status;
}

/* NtQueryAttributesFile's wide sibling: same by-name open, the
 * FILE_NETWORK_OPEN_INFORMATION shape (times + sizes + attributes) that
 * kernelbase's GetFileAttributesExW and msvcrt's stat family consume (Wine
 * dlls/ntdll/unix/file.c NtQueryFullAttributesFile). */
NTSTATUS NtQueryFullAttributesFile(const OBJECT_ATTRIBUTES *attr,
                                   FILE_NETWORK_OPEN_INFORMATION *info)
{
    if (info == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    /* Alignment 1, for the reason NtQueryAttributesFile's probe gives. */
    NTSTATUS status = KiProbeForWrite(info, sizeof(*info), 1);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    HANDLE handle;
    IO_STATUS_BLOCK iosb;
    PKTHREAD thread = KeGetCurrentThread();
    KPROCESSOR_MODE saved = thread->previousMode;
    status =
        IopOpenTransientFile(&handle, FILE_READ_ATTRIBUTES, (POBJECT_ATTRIBUTES)(uintptr_t)attr,
                             ExGetPreviousMode(), &iosb, FILE_ATTRIBUTE_NORMAL,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* The transient handle lives in the CALLER's handle table, so it is
     * user-closable: a sibling thread racing NtClose against this window
     * makes the reference fail, and an ASSERT here would turn that into a
     * machine halt (docs/review-2026-07 §2). Today Art. 3's no-preemption
     * mandate closes the window, but the mandate has a named exit
     * (docs/18 §13) and this outlives it. */
    PFILE_OBJECT file;
    thread->previousMode = KernelMode;
    NTSTATUS refStatus = IopReferenceFileByHandle(handle, 0, &file, 0);
    thread->previousMode = saved;
    if (!NT_SUCCESS(refStatus))
    {
        IopCloseTransientFile(handle);
        return refStatus;
    }
    IO_FILE_INFO raw;
    status = file->device->ops->GetInfo(file, &raw);
    if (NT_SUCCESS(status))
    {
        FILE_NETWORK_OPEN_INFORMATION out;
        memset(&out, 0, sizeof(out));
        out.CreationTime = raw.creationTime;
        out.LastAccessTime = raw.lastAccessTime;
        out.LastWriteTime = raw.lastWriteTime;
        out.ChangeTime = raw.lastWriteTime;
        out.AllocationSize.QuadPart = (LONGLONG)raw.allocationSize;
        out.EndOfFile.QuadPart = (LONGLONG)raw.endOfFile;
        out.FileAttributes = raw.fileAttributes;
        memcpy(info, &out, sizeof(out));
    }
    ObDereferenceObject(file);
    IopCloseTransientFile(handle);
    return status;
}

/* --- the Mm seam: file-backed sections (kernel/mm/section.c) ---------------- */

/* The file access a section over this file exercises: all three rows of the
 * pinned oracle's protection switch (third_party/wine dlls/ntdll/unix/sync.c
 * NtCreateSection, :2986-:3004), pinned by sem_mm/section_file_access.
 *
 *   PAGE_READONLY / PAGE_EXECUTE_READ /
 *   PAGE_WRITECOPY / PAGE_EXECUTE_WRITECOPY  -> FILE_READ_DATA
 *   PAGE_READWRITE / PAGE_EXECUTE_READWRITE  -> FILE_READ_DATA | FILE_WRITE_DATA
 *                                               (FILE_READ_DATA under SEC_IMAGE)
 *   PAGE_EXECUTE / PAGE_NOACCESS             -> nothing at all
 *
 * The third row is not decoration: an EMPTY required mask is satisfied by a
 * handle carrying no data right, so `CreateFileA(name, 0, ...)` can back a
 * PAGE_NOACCESS section. Reading the switch as "read always" refuses that,
 * and only an assertion with a no-access handle can see it.
 *
 * ONE function, because the same answer decides two things that must never
 * disagree — what the creating handle has to grant, and whether the resulting
 * section takes the writableSectionCount slot the oracle spells
 * FILE_MAPPING_WRITE (server/mapping.c create_mapping's `else if (file_access
 * & FILE_WRITE_DATA)`). The acquire and release sides both derive from
 * (attributes, protection) through here, so a count cannot leak. */
static ACCESS_MASK IopSectionFileAccess(ULONG sectionAttributes, ULONG pageProtection)
{
    ULONG bits = pageProtection & 0xFF;
    if (bits == PAGE_EXECUTE || bits == PAGE_NOACCESS)
    {
        return 0;
    }
    ACCESS_MASK needed = FILE_READ_DATA;
    if ((sectionAttributes & SEC_IMAGE) == 0 &&
        (bits == PAGE_READWRITE || bits == PAGE_EXECUTE_READWRITE))
    {
        needed |= FILE_WRITE_DATA;
    }
    return needed;
}

/* Does a section with these attributes hold the file write-shared-or-nothing?
 * The oracle's `else if` is exclusive: an IMAGE section never takes the write
 * hold however it was built. */
static BOOLEAN IopSectionHoldsWrite(ULONG sectionAttributes, ULONG pageProtection)
{
    return (sectionAttributes & SEC_IMAGE) == 0 &&
           (IopSectionFileAccess(sectionAttributes, pageProtection) & FILE_WRITE_DATA) != 0;
}

NTSTATUS IopBuildSectionBacking(HANDLE fileHandle, ULONG sectionAttributes, ULONG pageProtection,
                                const LARGE_INTEGER *maximumSize, MI_SECTION_BACKING *backing)
{
    ACCESS_MASK needed = IopSectionFileAccess(sectionAttributes, pageProtection);
    PFILE_OBJECT file;
    NTSTATUS status = IopReferenceFileByHandle(fileHandle, needed, &file, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (file->isDirectory || file->device->ops->GetCache == 0)
    {
        /* Directories and cache-less stream devices (M9 pipes/console)
         * cannot back a section. */
        ObDereferenceObject(file);
        return STATUS_INVALID_FILE_FOR_SECTION;
    }

    /* CreateFileMapping with a size LARGER than the file is an everyday
     * Win32 pattern, and NT extends the file to match when the protection
     * allows writing ("If an application specifies a size for the file
     * mapping object that is larger than the size of the actual named file
     * on disk and if the page protection allows write access, then the file
     * on disk is increased" -- Microsoft, CreateFileMappingW). proskrnl
     * answered STATUS_NOT_IMPLEMENTED, which under the default-on arming
     * flag is a kernel panic (docs/review-2026-07 §5). Without write
     * access, NT refuses with STATUS_SECTION_TOO_BIG. The extension happens
     * HERE, before the cache is measured, so the section is built over the
     * grown file rather than the old size. */
    if (maximumSize != 0 && maximumSize->QuadPart > 0 && (sectionAttributes & SEC_IMAGE) == 0)
    {
        PMI_PAGE_CACHE existing;
        status = file->device->ops->GetCache(file, &existing);
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(file);
            return status;
        }
        if ((uint64_t)maximumSize->QuadPart > existing->fileSize)
        {
            if ((needed & FILE_WRITE_DATA) == 0 || file->device->ops->SetEndOfFile == 0)
            {
                ObDereferenceObject(file);
                return STATUS_SECTION_TOO_BIG;
            }
            status = file->device->ops->SetEndOfFile(file, (uint64_t)maximumSize->QuadPart);
            if (!NT_SUCCESS(status))
            {
                ObDereferenceObject(file);
                return status;
            }
        }
    }

    PMI_PAGE_CACHE cache;
    status = file->device->ops->GetCache(file, &cache);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(file);
        return status;
    }

    memset(backing, 0, sizeof(*backing));
    backing->cache = cache;
    backing->fileObject = file; /* the caller inherits this reference */
    backing->writable = (file->grantedAccess & FILE_WRITE_DATA) != 0;
    backing->fcb = file->fcb; /* one per on-disk file: the image-master key */

    if (sectionAttributes & SEC_IMAGE)
    {
        /* SEC_IMAGE parses and copies from a contiguous raw snapshot. */
        if (cache->fileSize == 0)
        {
            ObDereferenceObject(file);
            return STATUS_INVALID_FILE_FOR_SECTION;
        }
        void *raw = MiAllocatePool(cache->fileSize);
        if (raw == 0)
        {
            ObDereferenceObject(file);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        KI_PROBE_TOKEN token = KiKernelToken(raw, cache->fileSize);
        MiCacheRead(cache, 0, &token, raw, cache->fileSize);
        backing->rawData = raw;
        backing->rawSize = cache->fileSize;
        backing->ownsRawData = TRUE;
    }

    file->fcb->sectionCount++;
    if (sectionAttributes & SEC_IMAGE)
    {
        file->fcb->imageSectionCount++;
    }
    if (IopSectionHoldsWrite(sectionAttributes, pageProtection))
    {
        file->fcb->writableSectionCount++;
    }
    return STATUS_SUCCESS;
}

void IopSectionBackingReleased(PVOID fileObjectBody, ULONG sectionAttributes, ULONG pageProtection)
{
    PFILE_OBJECT file = fileObjectBody;
    ASSERT(file->fcb->sectionCount > 0);
    file->fcb->sectionCount--;
    if (sectionAttributes & SEC_IMAGE)
    {
        ASSERT(file->fcb->imageSectionCount > 0);
        file->fcb->imageSectionCount--;
    }
    if (IopSectionHoldsWrite(sectionAttributes, pageProtection))
    {
        ASSERT(file->fcb->writableSectionCount > 0);
        file->fcb->writableSectionCount--;
    }
    /* The last section is gone: give the FS its chance to apply a
     * delete-on-close it had to defer while the file was mapped. Nothing
     * else re-enters the FS at this moment, so without this the deferred
     * delete was simply dropped (docs/review-2026-07 §7). */
    if (file->fcb->sectionCount == 0 && file->device->ops->SectionsReleased != 0)
    {
        file->device->ops->SectionsReleased(file);
    }
}

/* --- kernel-internal path -> section (the M7 process bootstrap + NLS) ------ */

/* Open `ntPath` with a kernel-internal handle and wrap it in a section:
 * SEC_IMAGE + PAGE_EXECUTE for images, SEC_COMMIT + PAGE_READONLY for data
 * (the same shapes ntdll's own NtCreateSection calls use). The transient
 * handle lives in the current process's handle table; the returned section
 * reference is the caller's. */
static NTSTATUS IopOpenFileSection(const WCHAR *ntPath, ULONG sectionAttributes,
                                   ULONG pageProtection, PMI_SECTION *sectionOut)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, ntPath);
    OBJECT_ATTRIBUTES attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;

    PKTHREAD thread = KeGetCurrentThread();
    KPROCESSOR_MODE saved = thread->previousMode;
    thread->previousMode = KernelMode; /* kernel pointers + a kernel handle */

    HANDLE handle;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status =
        IopCreateFile(&handle, FILE_GENERIC_READ, &attributes, &iosb, FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_OPEN, FILE_NON_DIRECTORY_FILE);
    if (NT_SUCCESS(status))
    {
        MI_SECTION_BACKING backing;
        status = IopBuildSectionBacking(handle, sectionAttributes, pageProtection, 0, &backing);
        if (NT_SUCCESS(status))
        {
            status =
                MiCreateBackedSection(0, pageProtection, sectionAttributes, &backing, sectionOut);
            if (!NT_SUCCESS(status))
            {
                IopSectionBackingReleased(backing.fileObject, sectionAttributes, pageProtection);
            }
            ObDereferenceObject(backing.fileObject); /* the section holds its own */
        }
        NtClose(handle);
    }
    thread->previousMode = saved;
    return status;
}

NTSTATUS IoOpenImageSection(const WCHAR *ntPath, PMI_SECTION *sectionOut)
{
    return IopOpenFileSection(ntPath, SEC_IMAGE, PAGE_EXECUTE, sectionOut);
}

NTSTATUS IoOpenDataSection(const WCHAR *ntPath, PMI_SECTION *sectionOut)
{
    return IopOpenFileSection(ntPath, SEC_COMMIT, PAGE_READONLY, sectionOut);
}

/* Mm's NtAreMappedFilesTheSame seam: do two File bodies name the same
 * on-disk file? FCB identity answers it — one live FCB per on-disk file is
 * the fs contract (fs/fat32 "one-FCB-per-file rule"), so two opens of one
 * path share the pointer. */
BOOLEAN IoIsSameUnderlyingFile(PVOID fileBody1, PVOID fileBody2)
{
    PFILE_OBJECT file1 = fileBody1;
    PFILE_OBJECT file2 = fileBody2;
    return file1->fcb != 0 && file1->fcb == file2->fcb;
}

/* Kernel-internal directory sweep (the ntapi test runner, kernel/init):
 * open `ntPath` as a directory through the same IopCreateFile path a user
 * open takes and hand every entry — "." and ".." included, as the vfs
 * ReadDirectory op yields them — to `callback`; FALSE stops the sweep. */
NTSTATUS IoEnumerateDirectory(const WCHAR *ntPath,
                              BOOLEAN (*callback)(const IO_DIR_ENTRY *entry, PVOID context),
                              PVOID context)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, ntPath);
    OBJECT_ATTRIBUTES attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;

    PKTHREAD thread = KeGetCurrentThread();
    KPROCESSOR_MODE saved = thread->previousMode;
    thread->previousMode = KernelMode; /* kernel pointers + a kernel handle */

    HANDLE handle;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status = IopCreateFile(&handle, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attributes, &iosb,
                                    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    FILE_OPEN, FILE_DIRECTORY_FILE);
    if (NT_SUCCESS(status))
    {
        PFILE_OBJECT file;
        status = IopReferenceFileByHandle(handle, 0, &file, 0);
        if (NT_SUCCESS(status))
        {
            if (file->device->ops->ReadDirectory == 0)
            {
                status = STATUS_INVALID_DEVICE_REQUEST;
            }
            else
            {
                IO_DIR_ENTRY *entry = MiAllocatePool(sizeof(*entry));
                if (entry == 0)
                {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                }
                else
                {
                    ULONG cursor = 0;
                    for (;;)
                    {
                        status = file->device->ops->ReadDirectory(file, &cursor, entry);
                        if (status == STATUS_NO_MORE_FILES)
                        {
                            status = STATUS_SUCCESS;
                            break;
                        }
                        if (!NT_SUCCESS(status))
                        {
                            break;
                        }
                        if (!callback(entry, context))
                        {
                            break;
                        }
                    }
                    MiFreePool(entry);
                }
            }
            ObDereferenceObject(file);
        }
        NtClose(handle);
    }
    thread->previousMode = saved;
    return status;
}
