/* kernel/io/notify.c — NtNotifyChangeDirectoryFile (CUI-5).
 *
 * The second genuinely-pended verb (after CUI-3's FSCTL_PIPE_LISTEN): a
 * watch parks until a directory change, a cancel, or the handle's close
 * completes it. Watches are KERNEL-owned (one global list) rather than an
 * FS op: the filesystems only report changes (IoReportDirectoryChange from
 * fs/fat32's mutation sites), so cancel and close sweep one list and no
 * second CancelPending path exists (Art. 11).
 *
 * The delivery contract is the pinned Wine's (dlls/ntdll/unix/file.c +
 * server/change.c), pinned by sem_file/notify_change.c: one
 * FILE_NOTIFY_INFORMATION record (name relative to the watched directory),
 * payload before IOSB before event before APC (docs/08); a record that
 * cannot be delivered completes STATUS_NOTIFY_ENUM_DIR with Information 0;
 * an NT_ERROR completion (cancel, close) signals the event but leaves the
 * IOSB untouched — the server's error-completion convention. One
 * DELIBERATE narrowing, recorded in docs/03 "CUI-5 notes": changes are not
 * buffered between watches (a change with no watch parked is dropped),
 * where the oracle queues them on the directory handle.
 */
#include "kernel/io/io.h"
#include "kernel/ob/ob.h"
#include "kernel/ke/ke.h"
#include "kernel/mm/pool.h"
#include "kernel/mm/virtual.h"
#include "kernel/ps/ps.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

typedef struct IOP_DIR_WATCH
{
    LIST_ENTRY listEntry;
    PEPROCESS owner;    /* referenced: the IOSB/buffer live in its space */
    void *issuerObject; /* referenced ETHREAD body: keeps `issuer` alive */
    PKTHREAD issuer;    /* cancel scoping + the APC target */
    PFILE_OBJECT file;  /* REFERENCED: the completion signals this object's
                         * event, so the pointer must stay live even though
                         * the close sweep normally removes us first. The
                         * release retires with the others (docs/20 R7). */
    PIO_DEVICE device;
    IO_STATUS_BLOCK *userIosb;
    void *userBuffer;
    ULONG bufferLength;
    PKAPC apcBlock;         /* pre-allocated at arm (engine authority, io.h);
                             * queued to `issuer` on a non-error completion */
    PKEVENT event;          /* referenced; 0 = none */
    UNICODE_STRING dirPath; /* pool copy, volume-relative ("\" = root) */
    ULONG filter;
    BOOLEAN watchTree;
    BOOLEAN kernelIosb;
} IOP_DIR_WATCH, *PIOP_DIR_WATCH;

static LIST_ENTRY IopDirWatchListHead = {&IopDirWatchListHead, &IopDirWatchListHead};
static LONG IopDirWatchCount;

/* Watches whose completion ran but whose object releases are still owed
 * (docs/20 R7; PR #95 review round 2, F3): IopCompleteDirWatch runs UNDER
 * the fat32 volume gate when the producer is a gated FS mutation
 * (FatReportChange), and an ObDereferenceObject there can be a LAST
 * reference — whose teardown re-enters a gated wrapper
 * (PspDeleteProcess -> handle sweep -> FatVfsCleanup, or
 * FatVfsSectionsReleased) and self-deadlocks on the gate the caller holds
 * (docs/20 §10.5.1). Completed watches are parked here instead;
 * IoReapRetiredDirWatches drops the references OUTSIDE the gate — from the
 * gate's own release path and from the non-gated sweeps. */
static LIST_ENTRY IopRetiredWatchListHead = {&IopRetiredWatchListHead, &IopRetiredWatchListHead};

BOOLEAN IoDirectoryWatchesActive(void)
{
    return IopDirWatchCount != 0;
}

/* The accepted filter mask, transcribed from the pinned Wine
 * (dlls/ntdll/unix/file.c FILE_NOTIFY_ALL — no stream bits). */
#define IOP_FILE_NOTIFY_ALL                                                                        \
    (FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES |  \
     FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_LAST_ACCESS |    \
     FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_SECURITY)

/* Completion, in the docs/08 order: payload, IOSB, event, APC.
 *
 * AN ERROR COMPLETION WRITES THE IOSB ONLY IF THE WATCH HAS NO EVENT, and
 * that clause was measured rather than reasoned. Two tests park a watch,
 * cancel it and then look at the IOSB, and they differ in exactly one
 * argument:
 *
 *   sem_file/notify_sticky.c   no event  -> IOSB reads STATUS_CANCELLED
 *   sem_file/notify_change.c   an event  -> IOSB untouched
 *
 * Both are green on the pinned oracle, so both are the boundary, and the
 * event is the only thing between them. It makes sense of the pair: with an
 * event the completion has somewhere else to report to, and with none the
 * IOSB is the caller's only channel — ntdll:change's watches carry no event
 * for precisely that reason and it requires STATUS_CANCELLED with
 * Information 0 in both of theirs (change.c:304-:309).
 *
 * What was here before was "an NT_ERROR status skips the IOSB", full stop,
 * cited to the pinned server's error-completion convention. That rule is
 * about a request that never STARTED — the caller still holds the status
 * the syscall returned — and it was applied to requests that had already
 * returned STATUS_PENDING, where there is no such status to hold.
 *
 * `isError` still gates the APC, unchanged: no test in either suite queues
 * an APC on a watch and then cancels it, so that leg has not been measured
 * and is not being changed on a guess (Art. 6). */
static void IopCompleteDirWatch(PIOP_DIR_WATCH watch, NTSTATUS status, const void *record,
                                ULONG recordBytes, ULONG_PTR information)
{
    BOOLEAN isError = ((ULONG)status >> 30) == 3;
    BOOLEAN writeIosb = !isError || watch->event == 0;
    if (record != 0 && recordBytes != 0)
    {
        if (watch->kernelIosb)
        {
            memcpy(watch->userBuffer, record, recordBytes);
        }
        else
        {
            /* Checked, not asserting: the owner may have freed the buffer
             * while the watch was parked (docs/review-2026-07 §2). */
            MiCopyToUserRangeChecked(&watch->owner->addressSpace,
                                     (uint64_t)(uintptr_t)watch->userBuffer, record, recordBytes);
        }
    }
    if (writeIosb)
    {
        IO_STATUS_BLOCK result;
        result.Status = status;
        result.Information = information;
        if (watch->kernelIosb)
        {
            *watch->userIosb = result;
        }
        else
        {
            MiCopyToUserRangeChecked(&watch->owner->addressSpace,
                                     (uint64_t)(uintptr_t)watch->userIosb, &result, sizeof(result));
        }
    }
    /* The request is over. NT signals the caller's EVENT if it supplied
     * one and the FILE OBJECT otherwise — not both, which is the half an
     * implementation gets wrong: ntdll:change completes an event-carrying
     * watch and then requires the wait on the DIRECTORY to keep timing out
     * (change.c:112) while the wait on the event succeeds (:115).
     *
     * Either way it fires for EVERY outcome, cancel and error included:
     * what is being reported is "nothing outstanding", not "something
     * succeeded". */
    if (watch->event != 0)
    {
        KeSetEvent(watch->event, 0, FALSE);
    }
    else
    {
        KeSetEvent(&watch->file->header, 0, FALSE);
    }
    if (!isError)
    {
        /* The engine's APC leg (io.h): pre-allocated at arm, queued to the
         * issuer now that the IOSB above is in place. */
        IopQueueCompletionApc(watch->issuer, watch->apcBlock);
    }
    else if (watch->apcBlock != 0)
    {
        MiFreePool(watch->apcBlock); /* error completion: the APC never fires */
    }
    watch->apcBlock = 0; /* consumed either way; the reaper never touches it */

    /* NO object release here (docs/20 R7): this may run under the volume
     * gate, where a last-reference teardown re-enters a gated wrapper and
     * self-deadlocks. Everything context-dependent is done above; the
     * references (event, issuerObject, owner) and the frees retire to the
     * list the gate's release path reaps (IoReapRetiredDirWatches). */
    InsertTailList(&IopRetiredWatchListHead, &watch->listEntry);
}

void IoReapRetiredDirWatches(void)
{
    /* Pop-first: a release below can run a whole teardown that re-enters
     * the FS, releases the gate again and reaps recursively — the popped
     * node is already off the list when that happens. Never call this with
     * the volume gate held. */
    while (!IsListEmpty(&IopRetiredWatchListHead))
    {
        PLIST_ENTRY entry = RemoveHeadList(&IopRetiredWatchListHead);
        PIOP_DIR_WATCH watch = CONTAINING_RECORD(entry, IOP_DIR_WATCH, listEntry);
        if (watch->event != 0)
        {
            ObDereferenceObject(watch->event);
        }
        if (watch->issuerObject != 0)
        {
            ObDereferenceObject(watch->issuerObject);
        }
        ObDereferenceObject(watch->file);
        ObDereferenceObject(watch->owner);
        MiFreePool(watch->dirPath.Buffer);
        MiFreePool(watch);
    }
}

NTSTATUS NtNotifyChangeDirectoryFile(HANDLE handle, HANDLE eventHandle, PIO_APC_ROUTINE apcRoutine,
                                     PVOID apcContext, PIO_STATUS_BLOCK iosb, PVOID buffer,
                                     ULONG length, ULONG filter, BOOLEAN watchTree)
{
    if (iosb == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(iosb, sizeof(*iosb), sizeof(void *));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (filter == 0 || (filter & ~IOP_FILE_NOTIFY_ALL) != 0)
    {
        return STATUS_INVALID_PARAMETER; /* before pending (pinned) */
    }
    if (buffer != 0 && length != 0)
    {
        status = KiProbeForWrite(buffer, length, 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    PFILE_OBJECT file;
    status = IopReferenceFileByHandle(handle, 0, &file);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (!file->isDirectory || file->device->ops->ReadDirectory == 0 ||
        file->device->ops->QueryName == 0)
    {
        ObDereferenceObject(file);
        return STATUS_INVALID_PARAMETER;
    }

    /* The watched directory's volume-relative path — the match key (and
     * subtree prefix) for change reports. */
    WCHAR pathBuffer[260];
    ULONG pathBytes = 0;
    status = file->device->ops->QueryName(file, pathBuffer, sizeof(pathBuffer), &pathBytes);
    if (NT_SUCCESS(status) && pathBytes > sizeof(pathBuffer))
    {
        status = STATUS_OBJECT_PATH_INVALID;
    }
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(file);
        return status;
    }

    PIOP_DIR_WATCH watch = MiAllocatePool(sizeof(*watch));
    PWSTR pathCopy = MiAllocatePool(pathBytes != 0 ? pathBytes : sizeof(WCHAR));
    if (watch == 0 || pathCopy == 0)
    {
        if (watch != 0)
        {
            MiFreePool(watch);
        }
        if (pathCopy != 0)
        {
            MiFreePool(pathCopy);
        }
        ObDereferenceObject(file);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memset(watch, 0, sizeof(*watch));
    memcpy(pathCopy, pathBuffer, pathBytes);
    watch->dirPath.Buffer = pathCopy;
    watch->dirPath.Length = (USHORT)pathBytes;
    watch->dirPath.MaximumLength = (USHORT)pathBytes;

    /* The completion APC, pre-allocated so completion cannot fail — the
     * engine authority (io.h; the old at-completion allocation dropped the
     * APC silently on a full pool). */
    status = IopPrepareCompletionApc(apcRoutine, apcContext, iosb, &watch->apcBlock);
    if (!NT_SUCCESS(status))
    {
        MiFreePool(pathCopy);
        MiFreePool(watch);
        ObDereferenceObject(file);
        return status;
    }
    if (eventHandle != 0)
    {
        /* Resolve now — the completer runs in another context; reset at
         * submit, the pended-request convention (kernel/io/async.c). */
        PVOID eventBody;
        status = ObReferenceObjectByHandle(eventHandle, EVENT_MODIFY_STATE, &ObpEventType,
                                           ExGetPreviousMode(), &eventBody, 0);
        if (!NT_SUCCESS(status))
        {
            if (watch->apcBlock != 0)
            {
                MiFreePool(watch->apcBlock);
            }
            MiFreePool(pathCopy);
            MiFreePool(watch);
            ObDereferenceObject(file);
            return status;
        }
        watch->event = eventBody;
        KeClearEvent(watch->event);
    }
    watch->owner = KeGetCurrentThread()->process;
    ObfReferenceObject(watch->owner);
    watch->issuer = KeGetCurrentThread();
    watch->issuerObject = watch->issuer->threadObject;
    if (watch->issuerObject != 0)
    {
        ObfReferenceObject(watch->issuerObject);
    }
    watch->file = file;
    /* The watch outlives this call, and its completion SIGNALS this object
     * (below), so it owns a reference rather than a bare pointer. Released
     * on the retire path, never here (docs/20 R7). */
    ObfReferenceObject(file);
    watch->device = file->device;
    watch->userIosb = iosb;
    watch->userBuffer = buffer;
    watch->bufferLength = length;
    /* The filter is the HANDLE's, not this call's (kernel/io/io.h has the
     * rule and its citation): the first arm on a file object fixes it, and
     * every later one reuses it. The caller's `filter` has still been
     * validated above — an unarmed handle stores it, and an armed one must
     * still refuse a malformed value rather than quietly substituting the
     * stored one. */
    if (!file->notifyArmed)
    {
        file->notifyArmed = TRUE;
        file->notifyFilter = filter;
    }
    watch->filter = file->notifyFilter;
    /* The subtree flag is NOT made sticky with it. The server stores the two
     * in the same "assign it once" block, so the symmetry is tempting — but
     * nothing on either side measures a re-arm that changes it, and
     * sem_file/notify_change.c's subtree case is a beyond_oracle block
     * whose handle has already been armed non-subtree, so making it sticky
     * would break a pinned behaviour to satisfy a rule no test states.
     * Only a differential test convicts (Art. 6); this half has none. */
    watch->watchTree = watchTree;
    watch->kernelIosb = ExGetPreviousMode() == KernelMode;

    InsertTailList(&IopDirWatchListHead, &watch->listEntry);
    IopDirWatchCount++;
    /* A request is now outstanding on this handle, so the file object is
     * BUSY: NT leaves it unsignalled until the request completes, and
     * ntdll:change waits on the directory handle expecting a timeout
     * (change.c:106). Every other service here completes inline, so this is
     * the only place the transition is observable. */
    KeClearEvent(&file->header);
    ObDereferenceObject(file);
    return STATUS_PENDING;
}

/* The producer: a filesystem mutation site reports one change —
 * `parentPath` is the mutated directory's volume-relative path, `name` the
 * affected leaf, `filterBit` the FILE_NOTIFY_CHANGE_* class, `action` the
 * FILE_ACTION_*. Every matching watch completes (one-shot). */
void IoReportDirectoryChange(PIO_DEVICE device, const UNICODE_STRING *parentPath,
                             const UNICODE_STRING *name, ULONG filterBit, ULONG action)
{
    if (IopDirWatchCount == 0)
    {
        return;
    }
    PLIST_ENTRY entry = IopDirWatchListHead.Flink;
    while (entry != &IopDirWatchListHead)
    {
        PIOP_DIR_WATCH watch = CONTAINING_RECORD(entry, IOP_DIR_WATCH, listEntry);
        entry = entry->Flink;
        if (watch->device != device || (watch->filter & filterBit) == 0)
        {
            continue;
        }

        /* A direct child completes with the leaf alone; a subtree watch
         * with the path below the watched directory prefixed. Both sides of
         * the comparison come from the same FCB name storage, so byte
         * equality is case-correct. */
        const WCHAR *tail = 0;
        ULONG tailBytes = 0;
        if (watch->dirPath.Length == parentPath->Length &&
            memcmp(watch->dirPath.Buffer, parentPath->Buffer, parentPath->Length) == 0)
        {
            /* direct child */
        }
        else if (watch->watchTree && parentPath->Length > watch->dirPath.Length)
        {
            /* The root watch's dirPath is "\"; deeper watches have no
             * trailing separator, so the child path continues with one. */
            ULONG prefix = watch->dirPath.Length;
            if (prefix == sizeof(WCHAR) && watch->dirPath.Buffer[0] == '\\')
            {
                prefix = 0;
            }
            if (memcmp(watch->dirPath.Buffer, parentPath->Buffer, prefix) != 0 ||
                parentPath->Buffer[prefix / sizeof(WCHAR)] != '\\')
            {
                continue;
            }
            tail = parentPath->Buffer + prefix / sizeof(WCHAR) + 1;
            tailBytes = parentPath->Length - prefix - sizeof(WCHAR);
        }
        else
        {
            continue;
        }

        ULONG nameBytes = tailBytes != 0 ? tailBytes + sizeof(WCHAR) + name->Length : name->Length;
        ULONG recordBytes = (ULONG)offsetof(FILE_NOTIFY_INFORMATION, FileName) + nameBytes;
        RemoveEntryList(&watch->listEntry);
        IopDirWatchCount--;

        if (watch->userBuffer != 0 && watch->bufferLength >= recordBytes)
        {
            FILE_NOTIFY_INFORMATION *record = MiAllocatePool(recordBytes);
            if (record != 0)
            {
                record->NextEntryOffset = 0;
                record->Action = action;
                record->FileNameLength = nameBytes;
                WCHAR *out = record->FileName;
                if (tailBytes != 0)
                {
                    memcpy(out, tail, tailBytes);
                    out += tailBytes / sizeof(WCHAR);
                    *out++ = '\\';
                }
                memcpy(out, name->Buffer, name->Length);
                IopCompleteDirWatch(watch, STATUS_SUCCESS, record, recordBytes, recordBytes);
                MiFreePool(record);
                continue;
            }
        }
        /* No buffer, a record that cannot fit, or no pool: the caller must
         * re-enumerate (the pinned degradation). */
        IopCompleteDirWatch(watch, STATUS_NOTIFY_ENUM_DIR, 0, 0, 0);
    }
}

/* The cancel/close sweep: complete this file's watches (issuer/IOSB
 * filters as in IopCancelIo; both 0 = every watch on the file). Returns
 * how many completed. */
ULONG IopCancelDirectoryWatches(PFILE_OBJECT file, PKTHREAD issuer, PIO_STATUS_BLOCK targetIosb)
{
    ULONG cancelled = 0;
    PLIST_ENTRY entry = IopDirWatchListHead.Flink;
    while (entry != &IopDirWatchListHead)
    {
        PIOP_DIR_WATCH watch = CONTAINING_RECORD(entry, IOP_DIR_WATCH, listEntry);
        entry = entry->Flink;
        if (watch->file != file)
        {
            continue;
        }
        if (issuer != 0 && watch->issuer != issuer)
        {
            continue;
        }
        if (targetIosb != 0 && watch->userIosb != targetIosb)
        {
            continue;
        }
        RemoveEntryList(&watch->listEntry);
        IopDirWatchCount--;
        IopCompleteDirWatch(watch, STATUS_CANCELLED, 0, 0, 0);
        cancelled++;
    }
    /* The sweep's callers (the cancel verbs, IopCloseFileObject) never hold
     * the volume gate, so the retired releases can run right here. */
    IoReapRetiredDirWatches();
    return cancelled;
}
