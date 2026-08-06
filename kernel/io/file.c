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

static void IopCloseFileObject(PVOID body)
{
    /* NT's IRP_MJ_CLEANUP moment: the last HANDLE is gone (references may
     * remain — sections). Release this open's locks and share slots, then
     * let the FS apply delete-on-close. */
    PFILE_OBJECT file = body;
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

OBJECT_TYPE IoDeviceType = {
    .name = "Device",
    .validAccess = FILE_ALL_ACCESS,
    .waitable = FALSE,
    .deleteProcedure = 0,
    .closeProcedure = 0,
};

OBJECT_TYPE IoFileObjectType = {
    .name = "File",
    .validAccess = FILE_ALL_ACCESS,
    .waitable = TRUE, /* born signaled; see io.h */
    .deleteProcedure = IopDeleteFileObject,
    .closeProcedure = IopCloseFileObject,
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

NTSTATUS IoCheckShareAccess(ACCESS_MASK desiredAccess, ULONG shareAccess, PIO_FCB fcb)
{
    BOOLEAN reads, writes, deletes;
    IopShareRelevantAccess(desiredAccess, &reads, &writes, &deletes);
    if (!reads && !writes && !deletes)
    {
        return STATUS_SUCCESS; /* attribute-only open */
    }
    /* A live SEC_IMAGE section (or any view of one) holds the file
     * non-write-shared, whatever handles exist: the NT running-image rule,
     * matching the pinned oracle (sem_mm/image_deny_write). */
    if (writes && fcb->imageSectionCount != 0)
    {
        return STATUS_SHARING_VIOLATION;
    }
    IO_SHARE_ACCESS *share = &fcb->shareAccess;
    BOOLEAN sharesRead = (shareAccess & FILE_SHARE_READ) != 0;
    BOOLEAN sharesWrite = (shareAccess & FILE_SHARE_WRITE) != 0;
    BOOLEAN sharesDelete = (shareAccess & FILE_SHARE_DELETE) != 0;

    /* Both directions (the NT rule): what I want must be shared by every
     * existing opener, and what I share must cover what they hold. */
    if ((reads && share->sharedRead != share->openCount) ||
        (writes && share->sharedWrite != share->openCount) ||
        (deletes && share->sharedDelete != share->openCount) ||
        (!sharesRead && share->readers != 0) || (!sharesWrite && share->writers != 0) ||
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

NTSTATUS IopReferenceFileByHandle(HANDLE handle, ACCESS_MASK desiredAccess, PFILE_OBJECT *fileOut)
{
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(handle, desiredAccess, &IoFileObjectType,
                                                ExGetPreviousMode(), &body, 0);
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
    if (eventHandle != 0)
    {
        PVOID eventBody;
        /* A failure to signal the event is DISCARDED, and the operation's
         * own status is returned. That is the oracle's behaviour --
         * third_party/wine dlls/ntdll/unix/file.c spells it
         * `if (event) NtSetEvent( event, NULL );` at every completion, with
         * no test of the result -- and it is also the only answer that can
         * be honest: by the time this runs the transfer HAS happened, so
         * reporting STATUS_INVALID_HANDLE would tell the caller nothing
         * occurred while the bytes were already gone
         * (docs/review-2026-07 §7). Services whose oracle refuses a bad
         * event handle do so BEFORE any work, through
         * IopValidateEventHandle. */
        if (NT_SUCCESS(IopReferenceCompletionEvent(eventHandle, &eventBody)))
        {
            KeSetEvent(eventBody, 0, FALSE);
            ObDereferenceObject(eventBody);
        }
    }
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

/* CUI-8 (docs/19 §5b): the one completion-drain authority the tick, idle,
 * and every thread-context waiter call (contract in ke.h — dispatcher lock
 * held). The KiInCompletionDrain bracket is docs/20 R2's arming: any
 * allocator call the drain ever grows asserts immediately instead of
 * corrupting a free list once in a thousand boots. */
ULONG IoDrainDeviceCompletions(void)
{
    if (!VioBlkIsPresent())
    {
        return 0;
    }
    /* Two prohibitions, deliberately separate: KiInCompletionDrain forbids
     * ALLOCATION (docs/20 R2, asserted in mm), the no-block region forbids
     * PARKING (issue #96 A, asserted at every blocking primitive). The drain
     * is reached from the tick, from idle, and from thread-context awaiters,
     * so the region must nest — it counts. */
    KiEnterNoBlockRegion("completion drain");
    KiInCompletionDrain = TRUE;
    VioBlkDrain();
    KiInCompletionDrain = FALSE;
    KiLeaveNoBlockRegion();
    return VioBlkInFlightCount();
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
        PVOID rootBody;
        status = ObReferenceObjectByHandle(attributes->RootDirectory, 0, &IoFileObjectType,
                                           ExGetPreviousMode(), &rootBody, 0);
        if (NT_SUCCESS(status))
        {
            relativeTo = rootBody;
            device = relativeTo->device;
            ObfReferenceObject(device);
            fsPath = *attributes->ObjectName;
            if (fsPath.Length >= sizeof(WCHAR) && fsPath.Buffer[0] == '\\')
            {
                ObDereferenceObject(relativeTo);
                ObDereferenceObject(device);
                return STATUS_OBJECT_PATH_SYNTAX_BAD;
            }
        }
    }
    if (device == 0)
    {
        PVOID deviceBody;
        status =
            ObpLookupParseObject(attributes, &IoDeviceType, &deviceBody, &fsPath, &reparseBuffer);
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
    file->grantedAccess = granted;
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
         * last reference, but closeProcedure fires on handle count 1 -> 0
         * and no handle was ever made -- so IoRemoveShareAccess,
         * IopReleaseAllLocks and ops->Cleanup were all skipped, and the
         * FCB's share counts stayed inflated for its whole lifetime, i.e.
         * STATUS_SHARING_VIOLATION on every later open of that file
         * (docs/review-2026-07 §7). The create SUCCEEDED, so this open needs
         * the cleanup half explicitly. */
        IopCloseFileObject(file);
        ObDereferenceObject(file);
        IopWriteCreateIosb(iosb, status, 0);
        goto out;
    }
    /* One handle now exists but closeProcedure fires only when handleCount
     * returns to zero; drop the creator's reference. */
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
    if (eaBuffer != 0 && eaLength != 0)
    {
        return STATUS_EAS_NOT_SUPPORTED; /* FAT has no extended attributes */
    }
    return IopCreateFile(handle, access, attr, ioStatus, attributes, sharing, disposition, options);
}

NTSTATUS NtOpenFile(PHANDLE handle, ACCESS_MASK access, POBJECT_ATTRIBUTES attr,
                    PIO_STATUS_BLOCK ioStatus, ULONG sharing, ULONG options)
{
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
                                     POBJECT_ATTRIBUTES attributes, PIO_STATUS_BLOCK iosb,
                                     ULONG fileAttributes, ULONG sharing, ULONG disposition,
                                     ULONG options)
{
    PKTHREAD thread = KeGetCurrentThread();
    KPROCESSOR_MODE saved = thread->previousMode;
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
        &handle, GENERIC_READ | GENERIC_WRITE | DELETE, attributes, &iosb, 0,
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
        IopOpenTransientFile(&handle, FILE_READ_ATTRIBUTES, attributes, &iosb, 0,
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
    NTSTATUS status = KiProbeForWrite(info, sizeof(*info), sizeof(uint64_t));
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
                             &iosb, FILE_ATTRIBUTE_NORMAL,
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
    NTSTATUS refStatus = IopReferenceFileByHandle(handle, 0, &file);
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
    NTSTATUS status = KiProbeForWrite(info, sizeof(*info), sizeof(uint64_t));
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
                             &iosb, FILE_ATTRIBUTE_NORMAL,
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
    NTSTATUS refStatus = IopReferenceFileByHandle(handle, 0, &file);
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

NTSTATUS IopBuildSectionBacking(HANDLE fileHandle, ULONG sectionAttributes, ULONG pageProtection,
                                const LARGE_INTEGER *maximumSize, MI_SECTION_BACKING *backing)
{
    /* The file handle must grant what the section will exercise (the NT
     * rule Wine also applies): read always; write for a writable non-image
     * data section. */
    ACCESS_MASK needed = FILE_READ_DATA;
    if ((sectionAttributes & SEC_IMAGE) == 0)
    {
        ULONG bits = pageProtection & 0xFF;
        if (bits == PAGE_READWRITE || bits == PAGE_EXECUTE_READWRITE)
        {
            needed |= FILE_WRITE_DATA;
        }
    }
    PFILE_OBJECT file;
    NTSTATUS status = IopReferenceFileByHandle(fileHandle, needed, &file);
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
    return STATUS_SUCCESS;
}

void IopSectionBackingReleased(PVOID fileObjectBody, BOOLEAN image)
{
    PFILE_OBJECT file = fileObjectBody;
    ASSERT(file->fcb->sectionCount > 0);
    file->fcb->sectionCount--;
    if (image)
    {
        ASSERT(file->fcb->imageSectionCount > 0);
        file->fcb->imageSectionCount--;
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
                IopSectionBackingReleased(backing.fileObject, (sectionAttributes & SEC_IMAGE) != 0);
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
        status = IopReferenceFileByHandle(handle, 0, &file);
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
