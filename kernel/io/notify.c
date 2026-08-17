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
 * server/change.c), pinned by sem_file/notify_change.c and
 * sem_file/notify_queue.c: FILE_NOTIFY_INFORMATION records (names relative
 * to the watched directory) chained by NextEntryOffset, payload before IOSB
 * before event before APC (docs/08); records that cannot be delivered
 * complete STATUS_NOTIFY_ENUM_DIR with Information 0; an NT_ERROR
 * completion (cancel, close) signals the event but leaves the IOSB
 * untouched — the server's error-completion convention.
 *
 * THE NOTIFICATION STATE LIVES ON THE DIRECTORY HANDLE, NOT ON THE REQUEST.
 * That is the server's shape (`struct dir` in server/change.c) and it is
 * what makes the four rules below one rule: the FIRST arm fixes the filter,
 * the subtree flag and want_data ("assign it once"), and from then on
 * changes are matched against the HANDLE and queued on it — with or without
 * a watch parked. A later arm that finds the queue non-empty completes
 * immediately, and it drains the WHOLE queue into one completion, which is
 * how an in-place rename's two records reach the caller chained.
 *
 * The queue is why reporting and delivering are separate calls. One FS
 * operation can report several changes (that rename), and completing on the
 * first would hand the caller a bare RENAMED_OLD_NAME — indistinguishable
 * from a delete. IoReportDirectoryChange only appends; IoDeliverDirectoryChanges
 * runs at the end of the operation, from the volume gate's release path.
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
    IO_STATUS_BLOCK *userIosb;
    void *userBuffer;
    ULONG bufferLength;
    PKAPC apcBlock; /* pre-allocated at arm (engine authority, io.h);
                     * queued to `issuer` on a non-error completion */
    PKEVENT event;  /* referenced; 0 = none */
    BOOLEAN kernelIosb;
} IOP_DIR_WATCH, *PIOP_DIR_WATCH;

/* One queued change on an armed directory handle: what the server's
 * `struct change_record` holds, minus the rename cookie. The cookie exists
 * there only because inotify can deliver the two halves of a rename
 * separately and they have to be paired back up; here the FS reports the
 * pair itself, adjacently and inside one operation (fs/fat32/file.c
 * FatVfsRename), so there is nothing to pair. */
typedef struct IOP_DIR_RECORD
{
    LIST_ENTRY listEntry;
    ULONG action;
    ULONG nameBytes; /* `name` is relative to the watched directory */
    WCHAR name[1];
} IOP_DIR_RECORD, *PIOP_DIR_RECORD;

/* IopDeliverRecords writes the three leading fields as one ULONG[3] (a
 * record can land 2-aligned, so it cannot go through the struct type); these
 * are what make that the same thing. */
_Static_assert(offsetof(FILE_NOTIFY_INFORMATION, NextEntryOffset) == 0, "notify record layout");
_Static_assert(offsetof(FILE_NOTIFY_INFORMATION, Action) == 4, "notify record layout");
_Static_assert(offsetof(FILE_NOTIFY_INFORMATION, FileNameLength) == 8, "notify record layout");

static LIST_ENTRY IopDirWatchListHead = {&IopDirWatchListHead, &IopDirWatchListHead};

/* The armed directory handles — the server's `change_list`. Entries are
 * bare FILE_OBJECT pointers held under no reference: a file object leaves
 * this list in IopDetachDirectoryNotify, which its own delete procedure
 * runs, so the list can never outlive a member. */
static LIST_ENTRY IopArmedDirListHead = {&IopArmedDirListHead, &IopArmedDirListHead};
static LONG IopArmedDirCount;
static BOOLEAN IopDeliveryPending;

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

/* The FS's cheap gate before it builds a change report. It asks about ARMED
 * HANDLES, not parked watches: a change with nothing parked is still queued
 * for the next arm, so "no watch is waiting" is not "nobody cares". */
BOOLEAN IoDirectoryWatchesActive(void)
{
    return IopArmedDirCount != 0;
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
    /* The request is over: the caller's EVENT if it supplied one and the
     * FILE OBJECT otherwise, never both — through the one authority that
     * states the rule (io.h IopSignalRequestCompletion), which the pended
     * data path owes identically. ntdll:change is what convicts it here: it
     * completes an event-carrying watch and then requires the wait on the
     * DIRECTORY to keep timing out (change.c:112) while the wait on the
     * event succeeds (:115). */
    IopSignalRequestCompletion(watch->event, watch->file);
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
        MiFreePool(watch);
    }
}

/* --- the change queue and its delivery ------------------------------------- */

static void IopFreeDirRecords(PLIST_ENTRY head)
{
    while (!IsListEmpty(head))
    {
        PLIST_ENTRY entry = RemoveHeadList(head);
        MiFreePool(CONTAINING_RECORD(entry, IOP_DIR_RECORD, listEntry));
    }
}

/* Hand one watch the WHOLE of its handle's queue, chained, and complete it.
 *
 * The serialization is the pinned client's byte for byte
 * (dlls/ntdll/unix/file.c read_changes_apc): NextEntryOffset is
 * offsetof(FILE_NOTIFY_INFORMATION, FileName) + FileNameLength with no
 * padding to a 4-byte boundary, so a name of an odd number of WCHARs leaves
 * the next record 2-aligned and the caller walks it anyway.
 *
 * A queue that does not fit the caller's buffer takes the completion to
 * STATUS_NOTIFY_ENUM_DIR with Information 0 and DISCARDS it — the server
 * drains its list into the reply before it can fail, so the records are gone
 * either way, and "re-enumerate" is precisely what the caller has been told
 * to do instead of reading a partial history. The OBSERVABLE pair matches the
 * pinned client exactly (that status, Information 0, queue consumed); what
 * differs is the buffer RESIDUE, since the client fills in the records that
 * fit before it flips (file.c:7074-:7104) and this leaves the buffer
 * untouched. Nothing measures the residue — a caller told to re-enumerate has
 * been told the buffer means nothing — so it is stated rather than pinned. */
static void IopDeliverRecords(PFILE_OBJECT file, PIOP_DIR_WATCH watch)
{
    LIST_ENTRY drained = {&drained, &drained};
    while (!IsListEmpty(&file->notifyRecords))
    {
        InsertTailList(&drained, RemoveHeadList(&file->notifyRecords));
    }

    ULONG total = 0;
    for (PLIST_ENTRY entry = drained.Flink; entry != &drained; entry = entry->Flink)
    {
        PIOP_DIR_RECORD record = CONTAINING_RECORD(entry, IOP_DIR_RECORD, listEntry);
        total += (ULONG)offsetof(FILE_NOTIFY_INFORMATION, FileName) + record->nameBytes;
    }
    ASSERT(total != 0);

    UCHAR *payload = 0;
    if (watch->userBuffer != 0 && total <= watch->bufferLength)
    {
        payload = MiAllocatePool(total);
    }
    if (payload == 0)
    {
        IopFreeDirRecords(&drained);
        IopCompleteDirWatch(watch, STATUS_NOTIFY_ENUM_DIR, 0, 0, 0);
        return;
    }

    /* Written FIELD BY FIELD into a byte buffer rather than through a
     * FILE_NOTIFY_INFORMATION *, because a record after an odd-length name
     * starts on a 2-byte boundary and a struct pointer there is undefined
     * behaviour (the kernel builds with -fsanitize=undefined, which traps on
     * it). The unpadded chain is the contract, not an accident: the pinned
     * client advances by offsetof(FILE_NOTIFY_INFORMATION,
     * FileName[FileNameLength]) with no rounding. */
    ULONG offset = 0;
    ULONG lastOffset = 0;
    for (PLIST_ENTRY entry = drained.Flink; entry != &drained; entry = entry->Flink)
    {
        PIOP_DIR_RECORD record = CONTAINING_RECORD(entry, IOP_DIR_RECORD, listEntry);
        ULONG size = (ULONG)offsetof(FILE_NOTIFY_INFORMATION, FileName) + record->nameBytes;
        ULONG header[3] = {size, record->action, record->nameBytes};
        memcpy(payload + offset, header, sizeof(header));
        memcpy(payload + offset + offsetof(FILE_NOTIFY_INFORMATION, FileName), record->name,
               record->nameBytes);
        lastOffset = offset;
        offset += size;
    }
    ULONG endOfChain = 0; /* the last record's NextEntryOffset */
    memcpy(payload + lastOffset, &endOfChain, sizeof(endOfChain));

    IopFreeDirRecords(&drained);
    IopCompleteDirWatch(watch, STATUS_SUCCESS, payload, total, total);
    MiFreePool(payload);
}

/* Pay out what this handle owes its parked watches.
 *
 * The FIRST parked watch takes the whole queue and any others behind it get
 * STATUS_NOTIFY_ENUM_DIR: the server wakes EVERY async queued on the
 * directory, and the one that gets to read_change first empties the list, so
 * the losers see STATUS_NO_DATA_DETECTED — which read_changes_apc turns into
 * exactly that status with Information 0. Records with nothing parked stay
 * queued for the next arm; that is the whole point of the queue. */
static void IopDeliverDirWatches(PFILE_OBJECT file)
{
    if (IsListEmpty(&file->notifyRecords) && !file->notifyWake)
    {
        return;
    }
    file->notifyWake = FALSE;
    for (;;)
    {
        PIOP_DIR_WATCH watch = 0;
        for (PLIST_ENTRY entry = IopDirWatchListHead.Flink; entry != &IopDirWatchListHead;
             entry = entry->Flink)
        {
            PIOP_DIR_WATCH candidate = CONTAINING_RECORD(entry, IOP_DIR_WATCH, listEntry);
            if (candidate->file == file)
            {
                watch = candidate;
                break;
            }
        }
        if (watch == 0)
        {
            return;
        }
        RemoveEntryList(&watch->listEntry);
        if (IsListEmpty(&file->notifyRecords))
        {
            IopCompleteDirWatch(watch, STATUS_NOTIFY_ENUM_DIR, 0, 0, 0);
        }
        else
        {
            IopDeliverRecords(file, watch);
        }
    }
}

void IoDeliverDirectoryChanges(void)
{
    if (IopDeliveryPending)
    {
        IopDeliveryPending = FALSE;
        PLIST_ENTRY entry = IopArmedDirListHead.Flink;
        while (entry != &IopArmedDirListHead)
        {
            PFILE_OBJECT file = CONTAINING_RECORD(entry, FILE_OBJECT, notifyEntry);
            entry = entry->Flink;
            IopDeliverDirWatches(file);
        }
    }
    /* The reap comes after the walk, never inside it: a release there can run
     * a whole teardown, and a teardown detaches an armed handle from the very
     * list being walked (docs/20 R7 is the other half of the same rule). */
    IoReapRetiredDirWatches();
}

void IopDetachDirectoryNotify(PFILE_OBJECT file)
{
    if (!file->notifyArmed)
    {
        return;
    }
    /* Runs from the DELETE procedure, not from close: a parked watch holds a
     * reference on this file object, so nothing can be waiting on the queue
     * being freed here. The server frees the same list in dir_destroy for
     * the same reason. */
    RemoveEntryList(&file->notifyEntry);
    IopArmedDirCount--;
    file->notifyArmed = FALSE;
    ASSERT((IopArmedDirCount == 0) == IsListEmpty(&IopArmedDirListHead));
    IopFreeDirRecords(&file->notifyRecords);
    if (file->notifyPath.Buffer != 0)
    {
        MiFreePool(file->notifyPath.Buffer);
        file->notifyPath.Buffer = 0;
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
    status = IopReferenceFileByHandle(handle, 0, &file, 0);
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
     * subtree prefix) for change reports. Taken on the FIRST arm only,
     * because it belongs to the handle with the rest of the notification
     * state; a later arm neither re-reads nor re-checks it. */
    PWSTR pathCopy = 0;
    ULONG pathBytes = 0;
    WCHAR pathBuffer[260];
    if (!file->notifyArmed)
    {
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
        pathCopy = MiAllocatePool(pathBytes != 0 ? pathBytes : sizeof(WCHAR));
        if (pathCopy == 0)
        {
            ObDereferenceObject(file);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memcpy(pathCopy, pathBuffer, pathBytes);
    }

    PIOP_DIR_WATCH watch = MiAllocatePool(sizeof(*watch));
    if (watch == 0)
    {
        if (pathCopy != 0)
        {
            MiFreePool(pathCopy);
        }
        ObDereferenceObject(file);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memset(watch, 0, sizeof(*watch));

    /* The completion APC, pre-allocated so completion cannot fail — the
     * engine authority (io.h; the old at-completion allocation dropped the
     * APC silently on a full pool). */
    status = IopPrepareCompletionApc(apcRoutine, apcContext, iosb, &watch->apcBlock);
    if (!NT_SUCCESS(status))
    {
        if (pathCopy != 0)
        {
            MiFreePool(pathCopy);
        }
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
            if (pathCopy != 0)
            {
                MiFreePool(pathCopy);
            }
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
    watch->userIosb = iosb;
    watch->userBuffer = buffer;
    watch->bufferLength = length;
    watch->kernelIosb = ExGetPreviousMode() == KernelMode;

    /* "Assign it once" (io.h has the rule and its citation): the FIRST arm
     * on a file object fixes the filter, the subtree flag, whether the
     * handle can report record data, and the path they are matched against;
     * every later arm reuses all four and its own arguments are ignored. The
     * caller's `filter` has still been validated above — an unarmed handle
     * stores it, and an armed one must still refuse a malformed value rather
     * than quietly substituting the stored one. */
    if (!file->notifyArmed)
    {
        file->notifyPath.Buffer = pathCopy;
        file->notifyPath.Length = (USHORT)pathBytes;
        file->notifyPath.MaximumLength = (USHORT)pathBytes;
        file->notifyFilter = filter;
        file->notifySubtree = watchTree;
        file->notifyWantData = buffer != 0;
        file->notifyWake = FALSE;
        InitializeListHead(&file->notifyRecords);
        file->notifyArmed = TRUE;
        InsertTailList(&IopArmedDirListHead, &file->notifyEntry);
        IopArmedDirCount++;
    }

    InsertTailList(&IopDirWatchListHead, &watch->listEntry);
    /* A request is now outstanding on this handle, so the file object is
     * BUSY: NT leaves it unsignalled until the request completes, and
     * ntdll:change waits on the directory handle expecting a timeout
     * (change.c:106). The npfs data park owes the same transition, so the
     * rule lives with its twin in the engine (io.h). */
    IopMarkRequestOutstanding(file);
    /* A change that arrived with nothing parked is waiting on the handle:
     * the server's `if (!list_empty( &dir->change_records ))` wake at the
     * end of the same handler. The syscall still answers STATUS_PENDING —
     * the IOSB, the event and the APC are all in place before it returns. */
    IopDeliverDirWatches(file);
    IoReapRetiredDirWatches();
    ObDereferenceObject(file);
    return STATUS_PENDING;
}

/* The producer: a filesystem mutation site reports one change —
 * `parentPath` is the mutated directory's volume-relative path, `name` the
 * affected leaf, `filterBit` the FILE_NOTIFY_CHANGE_* class, `action` the
 * FILE_ACTION_*. Every armed handle that matches QUEUES it; nothing is
 * completed here (see IoDeliverDirectoryChanges and the header). */
void IoReportDirectoryChange(PIO_DEVICE device, const UNICODE_STRING *parentPath,
                             const UNICODE_STRING *name, ULONG filterBit, ULONG action)
{
    if (IopArmedDirCount == 0)
    {
        return;
    }
    PLIST_ENTRY entry = IopArmedDirListHead.Flink;
    while (entry != &IopArmedDirListHead)
    {
        PFILE_OBJECT file = CONTAINING_RECORD(entry, FILE_OBJECT, notifyEntry);
        entry = entry->Flink;
        /* Being on this list IS being armed, and an armed handle always
         * carries the path the match below dereferences: both are installed
         * together, once, and leave together in IopDetachDirectoryNotify. */
        ASSERT(file->notifyArmed && file->notifyPath.Buffer != 0);
        if (file->device != device || (file->notifyFilter & filterBit) == 0)
        {
            continue;
        }

        /* A direct child is reported by its leaf alone; a subtree watch
         * prefixes the path below the watched directory. Both sides of the
         * comparison come from the same FCB name storage, so byte equality
         * is case-correct. */
        const WCHAR *tail = 0;
        ULONG tailBytes = 0;
        if (file->notifyPath.Length == parentPath->Length &&
            memcmp(file->notifyPath.Buffer, parentPath->Buffer, parentPath->Length) == 0)
        {
            /* direct child */
        }
        else if (file->notifySubtree && parentPath->Length > file->notifyPath.Length)
        {
            /* The root's notifyPath is "\"; deeper directories have no
             * trailing separator, so the child path continues with one. */
            ULONG prefix = file->notifyPath.Length;
            if (prefix == sizeof(WCHAR) && file->notifyPath.Buffer[0] == '\\')
            {
                prefix = 0;
            }
            if (memcmp(file->notifyPath.Buffer, parentPath->Buffer, prefix) != 0 ||
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

        IopDeliveryPending = TRUE;
        /* A handle whose first arm carried no buffer stores no record — the
         * server's `if (dir->want_data)` — and only wakes what is parked.
         * A pool failure takes the same exit: the change HAPPENED, so the
         * caller must be told to re-enumerate rather than told nothing. */
        ULONG nameBytes = tailBytes != 0 ? tailBytes + sizeof(WCHAR) + name->Length : name->Length;
        PIOP_DIR_RECORD record =
            file->notifyWantData ? MiAllocatePool(offsetof(IOP_DIR_RECORD, name) + nameBytes) : 0;
        if (record == 0)
        {
            file->notifyWake = TRUE;
            continue;
        }
        record->action = action;
        record->nameBytes = nameBytes;
        WCHAR *out = record->name;
        if (tailBytes != 0)
        {
            memcpy(out, tail, tailBytes);
            out += tailBytes / sizeof(WCHAR);
            *out++ = '\\';
        }
        memcpy(out, name->Buffer, name->Length);
        InsertTailList(&file->notifyRecords, &record->listEntry);
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
        IopCompleteDirWatch(watch, STATUS_CANCELLED, 0, 0, 0);
        cancelled++;
    }
    /* The sweep's callers (the cancel verbs, IopCloseFileObject) never hold
     * the volume gate, so the retired releases can run right here. */
    IoReapRetiredDirWatches();
    return cancelled;
}
