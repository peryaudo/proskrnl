/* kernel/io/lock.c — byte-range locks: NtLockFile / NtUnlockFile (M6).
 *
 * Semantics pinned by tests/ntapi/sem_file/byte_locks.c on the Wine oracle:
 * a FailImmediately conflict is STATUS_FILE_LOCK_CONFLICT; unlock demands
 * the exact previously-locked range and owner; a handle's locks die with
 * its last handle (IopCloseFileObject).
 */
#include "kernel/io/io.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/ke/ke.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

typedef struct
{
    LIST_ENTRY listEntry;
    PFILE_OBJECT owner; /* the open that took the lock */
    uint64_t offset;
    uint64_t length;
    BOOLEAN exclusive;
} IO_FILE_LOCK, *PIO_FILE_LOCK;

void IopInitializeFcb(PIO_FCB fcb)
{
    memset(&fcb->shareAccess, 0, sizeof(fcb->shareAccess));
    InitializeListHead(&fcb->lockList);
    fcb->deletePending = FALSE;
    fcb->sectionCount = 0;
}

/* Do two ranges overlap? Ends are exclusive, and an end of exactly 0 means
 * "to the end of the address space" -- the oracle's own model
 * (third_party/wine server/fd.c lock_overlaps: `if (lock->end && start >=
 * lock->end) return 0;`), which is why the wrap is not an accident there.
 *
 * The ends are computed once by IopLockEnd and never inside a comparison:
 * `bOffset + bLength` used to overflow to a small value, and two
 * "exclusive" locks over the same bytes could both be granted
 * (docs/review-2026-07 §3). A range that wraps to anything OTHER than 0 is
 * refused outright at IopLockRange, so it never reaches this function. */
static uint64_t IopLockEnd(uint64_t offset, uint64_t length)
{
    return offset + length; /* 0 == unbounded, as the oracle spells it */
}

static BOOLEAN IopRangesOverlap(uint64_t aOffset, uint64_t aLength, uint64_t bOffset,
                                uint64_t bLength)
{
    if (aLength == 0 || bLength == 0)
    {
        return FALSE;
    }
    uint64_t aEnd = IopLockEnd(aOffset, aLength);
    uint64_t bEnd = IopLockEnd(bOffset, bLength);
    if (aEnd != 0 && bOffset >= aEnd)
    {
        return FALSE;
    }
    if (bEnd != 0 && aOffset >= bEnd)
    {
        return FALSE;
    }
    return TRUE;
}

/* Would [offset, offset+length) as exclusive/shared conflict now? */
static BOOLEAN IopLockConflicts(PIO_FCB fcb, uint64_t offset, uint64_t length, BOOLEAN exclusive)
{
    for (PLIST_ENTRY entry = fcb->lockList.Flink; entry != &fcb->lockList; entry = entry->Flink)
    {
        PIO_FILE_LOCK lock = CONTAINING_RECORD(entry, IO_FILE_LOCK, listEntry);
        if (!IopRangesOverlap(offset, length, lock->offset, lock->length))
        {
            continue;
        }
        if (exclusive || lock->exclusive)
        {
            return TRUE;
        }
    }
    return FALSE;
}

NTSTATUS IopLockRange(PIO_FCB fcb, PFILE_OBJECT owner, uint64_t offset, uint64_t length,
                      BOOLEAN exclusive)
{
    /* A range whose end wraps past 2^64 is refused, exactly as the oracle
     * refuses it (third_party/wine server/fd.c lock_fd: "don't allow
     * wrapping locks", `if (end && end < start) set_error(
     * STATUS_INVALID_PARAMETER )`). An end of exactly 0 is NOT a wrap there:
     * it is the unbounded lock, and it stays legal. */
    uint64_t end = IopLockEnd(offset, length);
    if (end != 0 && end < offset)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (IopLockConflicts(fcb, offset, length, exclusive))
    {
        return STATUS_FILE_LOCK_CONFLICT;
    }
    PIO_FILE_LOCK lock = MiAllocatePool(sizeof(IO_FILE_LOCK));
    if (lock == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    lock->owner = owner;
    lock->offset = offset;
    lock->length = length;
    lock->exclusive = exclusive;
    InsertTailList(&fcb->lockList, &lock->listEntry);
    return STATUS_SUCCESS;
}

NTSTATUS IopUnlockRange(PIO_FCB fcb, PFILE_OBJECT owner, uint64_t offset, uint64_t length)
{
    for (PLIST_ENTRY entry = fcb->lockList.Flink; entry != &fcb->lockList; entry = entry->Flink)
    {
        PIO_FILE_LOCK lock = CONTAINING_RECORD(entry, IO_FILE_LOCK, listEntry);
        if (lock->owner == owner && lock->offset == offset && lock->length == length)
        {
            RemoveEntryList(&lock->listEntry);
            MiFreePool(lock);
            return STATUS_SUCCESS;
        }
    }
    return STATUS_RANGE_NOT_LOCKED;
}

void IopReleaseAllLocks(PIO_FCB fcb, PFILE_OBJECT owner)
{
    PLIST_ENTRY entry = fcb->lockList.Flink;
    while (entry != &fcb->lockList)
    {
        PIO_FILE_LOCK lock = CONTAINING_RECORD(entry, IO_FILE_LOCK, listEntry);
        entry = entry->Flink;
        if (lock->owner == owner)
        {
            RemoveEntryList(&lock->listEntry);
            MiFreePool(lock);
        }
    }
}

/* --- the Nt surface --------------------------------------------------------- */

NTSTATUS NtLockFile(HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apcContext,
                    PIO_STATUS_BLOCK iosb, PLARGE_INTEGER byteOffset, PLARGE_INTEGER length,
                    ULONG *key, BOOLEAN failImmediately, BOOLEAN exclusive)
{
    (void)apcContext;
    /* Only the bare form is built: a non-NULL apc, io_status, or key is an
     * unbuilt case refusing loudly (Art. 12). The pinned Wine refuses these
     * too, but an oracle refusal is not a contract — it is the oracle being
     * unbuilt — so nothing pins this and the dispatcher convicts it. */
    if (apc != 0 || iosb != 0 || key != 0)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    if (byteOffset == 0 || length == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    LARGE_INTEGER offsetValue, lengthValue;
    NTSTATUS status = KiCopyFromUser(&offsetValue, byteOffset, sizeof(offsetValue));
    if (NT_SUCCESS(status))
    {
        status = KiCopyFromUser(&lengthValue, length, sizeof(lengthValue));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PFILE_OBJECT file;
    status = IopReferenceFileByHandle(handle, 0, &file, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (file->isDirectory)
    {
        ObDereferenceObject(file);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    for (;;)
    {
        status = IopLockRange(file->fcb, file, (uint64_t)offsetValue.QuadPart,
                              (uint64_t)lengthValue.QuadPart, exclusive);
        if (status != STATUS_FILE_LOCK_CONFLICT || failImmediately)
        {
            break;
        }
        /* Wait-mode: retry until the range frees (another process's close
         * or unlock; Wine polls the same way). 10 ms, relative. */
        LARGE_INTEGER interval;
        interval.QuadPart = -100000;
        NTSTATUS napStatus = KeDelayExecutionThread(KernelMode, FALSE, &interval);
        if (napStatus != STATUS_SUCCESS)
        {
            status = napStatus; /* CUI-4: foreign terminate — stop retrying */
            break;
        }
    }

    if (NT_SUCCESS(status) && event != 0)
    {
        PVOID eventBody;
        NTSTATUS eventStatus = ObReferenceObjectByHandle(event, EVENT_MODIFY_STATE, &ObpEventType,
                                                         ExGetPreviousMode(), &eventBody, 0);
        if (NT_SUCCESS(eventStatus))
        {
            KeSetEvent(eventBody, 0, FALSE);
            ObDereferenceObject(eventBody);
        }
    }
    ObDereferenceObject(file);
    return status;
}

NTSTATUS NtUnlockFile(HANDLE handle, PIO_STATUS_BLOCK iosb, PLARGE_INTEGER byteOffset,
                      PLARGE_INTEGER length, PULONG key)
{
    if (key != 0)
    {
        return STATUS_NOT_IMPLEMENTED; /* the keyed form is unbuilt (Art. 12) */
    }
    if (iosb == 0 || byteOffset == 0 || length == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = IopProbeIosb(iosb);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    LARGE_INTEGER offsetValue, lengthValue;
    status = KiCopyFromUser(&offsetValue, byteOffset, sizeof(offsetValue));
    if (NT_SUCCESS(status))
    {
        status = KiCopyFromUser(&lengthValue, length, sizeof(lengthValue));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PFILE_OBJECT file;
    status = IopReferenceFileByHandle(handle, 0, &file, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = IopUnlockRange(file->fcb, file, (uint64_t)offsetValue.QuadPart,
                            (uint64_t)lengthValue.QuadPart);
    IopWriteIosb(iosb, status, 0);
    ObDereferenceObject(file);
    return status;
}
