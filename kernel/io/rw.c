/* kernel/io/rw.c — NtReadFile / NtWriteFile / NtFlushBuffersFile (M6).
 *
 * The async-completion protocol on a synchronous kernel (Art. 3): every
 * operation completes before the syscall returns, the IOSB is written
 * before the optional event is signalled (IopCompleteRequest), and the
 * final status is the return value — semantics pinned by
 * tests/ntapi/sem_file/read_write.c on the Wine oracle. All data moves
 * through the file's unified page cache, then writes go straight to disk
 * (immediate writeback), which is what makes the sem_mm/file_coherence
 * stress test structural rather than lucky.
 */
#include "kernel/io/io.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/init/panic.h"
#include "kernel/lib/string.h"
#include "kernel/mm/pool.h"

/* The APC leg of the async-completion protocol (pinned by
 * sem_file/apc_completion.c on the oracle): a transfer carrying a user
 * ApcRoutine queues a user APC when the request completes — i.e. exactly
 * when the IOSB is written — and KiUserApcDispatcher later calls
 * PIO_APC_ROUTINE(ApcContext, iosb, reserved) at the next alertable wait.
 * The block is allocated up front so completion itself cannot fail. */
static NTSTATUS IopPrepareCompletionApc(PIO_APC_ROUTINE apcRoutine, PVOID apcContext,
                                        PIO_STATUS_BLOCK iosb, PKAPC *apcOut)
{
    *apcOut = 0;
    if (apcRoutine == 0 || ExGetPreviousMode() != UserMode)
    {
        return STATUS_SUCCESS;
    }
    PKAPC apc = MiAllocatePool(sizeof(KAPC));
    if (apc == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    apc->normalRoutine = (uint64_t)(uintptr_t)apcRoutine;
    apc->normalContext = (ULONG_PTR)apcContext;
    apc->systemArgument1 = (ULONG_PTR)iosb; /* the caller's very IOSB */
    apc->systemArgument2 = 0;               /* the reserved argument */
    *apcOut = apc;
    return STATUS_SUCCESS;
}

/* Write the IOSB / signal the event (IopCompleteRequest), then queue the
 * completion APC — the IOSB is in place before the routine can run. */
static NTSTATUS IopCompleteTransfer(PIO_STATUS_BLOCK iosb, HANDLE event, PKAPC apc, NTSTATUS status,
                                    ULONG_PTR information)
{
    NTSTATUS final = IopCompleteRequest(iosb, event, status, information);
    if (apc != 0)
    {
        KiInsertQueueUserApc(KeGetCurrentThread(), apc);
    }
    return final;
}

/* Shared argument shaping for NtReadFile/NtWriteFile. */
static NTSTATUS IopStartTransfer(HANDLE handle, ACCESS_MASK needed, PIO_APC_ROUTINE apc,
                                 PVOID apcContext, PIO_STATUS_BLOCK iosb, PLARGE_INTEGER byteOffset,
                                 PFILE_OBJECT *fileOut, uint64_t *offsetOut, PKAPC *apcOut)
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
    PFILE_OBJECT file;
    status = IopReferenceFileByHandle(handle, needed, &file);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (file->isDirectory)
    {
        ObDereferenceObject(file);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    uint64_t offset;
    if (byteOffset == 0)
    {
        /* NULL ByteOffset: legal only on a synchronous handle, where it
         * means "the current file position" (pinned read_write.c). */
        if (!file->synchronousIo)
        {
            ObDereferenceObject(file);
            return STATUS_INVALID_PARAMETER;
        }
        offset = (uint64_t)file->currentByteOffset.QuadPart;
    }
    else
    {
        LARGE_INTEGER captured;
        status = KiCopyFromUser(&captured, byteOffset, sizeof(captured));
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(file);
            return status;
        }
        if (captured.QuadPart < 0)
        {
            ObDereferenceObject(file);
            return STATUS_INVALID_PARAMETER;
        }
        offset = (uint64_t)captured.QuadPart;
    }
    /* Last, so no failure path below needs to unwind it. */
    status = IopPrepareCompletionApc(apc, apcContext, iosb, apcOut);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(file);
        return status;
    }
    *fileOut = file;
    *offsetOut = offset;
    return STATUS_SUCCESS;
}

NTSTATUS NtReadFile(HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, PVOID apcContext,
                    PIO_STATUS_BLOCK iosb, PVOID buffer, ULONG length, PLARGE_INTEGER byteOffset,
                    PULONG key)
{
    (void)key;
    PFILE_OBJECT file;
    uint64_t offset;
    PKAPC apcBlock = 0;
    NTSTATUS status = IopStartTransfer(handle, FILE_READ_DATA, apc, apcContext, iosb, byteOffset,
                                       &file, &offset, &apcBlock);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = KiProbeForWrite(buffer, length, 1);
    if (!NT_SUCCESS(status))
    {
        goto abandon;
    }

    /* M9 device path: a stream device (npfs/condrv/serial) reads through its
     * own op — which may block — via a pool bounce buffer; byte offsets do
     * not apply to a stream. */
    if (file->device->ops->Read != 0)
    {
        void *bounce = length != 0 ? MiAllocatePool(length) : 0;
        if (length != 0 && bounce == 0)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto abandon;
        }
        ULONG_PTR transferred = 0;
        status = file->device->ops->Read(file, bounce, length, &transferred);
        if ((NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) && transferred != 0)
        {
            memcpy(buffer, bounce, transferred); /* probed above */
        }
        if (bounce != 0)
        {
            MiFreePool(bounce);
        }
        if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW)
        {
            status = IopCompleteTransfer(iosb, event, apcBlock, status, transferred);
        }
        else
        {
            goto abandon;
        }
        ObDereferenceObject(file);
        return status;
    }

    PMI_PAGE_CACHE cache;
    status = file->device->ops->GetCache(file, &cache);
    if (!NT_SUCCESS(status))
    {
        goto abandon;
    }

    if (offset >= cache->fileSize)
    {
        /* Reading at (or past) EOF completes with STATUS_END_OF_FILE — and
         * the IOSB carries it (pinned read_write.c). */
        status = IopCompleteTransfer(iosb, event, apcBlock, STATUS_END_OF_FILE, 0);
        ObDereferenceObject(file);
        return status;
    }
    uint64_t bytes = length;
    if (bytes > cache->fileSize - offset)
    {
        bytes = cache->fileSize - offset; /* the short read across EOF */
    }
    MiCacheRead(cache, offset, buffer, bytes);
    if (file->synchronousIo)
    {
        file->currentByteOffset.QuadPart = (LONGLONG)offset + (LONGLONG)bytes;
    }
    status = IopCompleteTransfer(iosb, event, apcBlock, STATUS_SUCCESS, (ULONG_PTR)bytes);
    ObDereferenceObject(file);
    return status;

abandon:
    /* The request never completed (no IOSB write): the APC must not fire. */
    if (apcBlock != 0)
    {
        MiFreePool(apcBlock);
    }
    ObDereferenceObject(file);
    return status;
}

NTSTATUS NtWriteFile(HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, PVOID apcContext,
                     PIO_STATUS_BLOCK iosb, const void *buffer, ULONG length,
                     PLARGE_INTEGER byteOffset, PULONG key)
{
    (void)key;
    PFILE_OBJECT file;
    uint64_t offset;
    PKAPC apcBlock = 0;
    NTSTATUS status = IopStartTransfer(handle, FILE_WRITE_DATA, apc, apcContext, iosb, byteOffset,
                                       &file, &offset, &apcBlock);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = KiProbeForRead(buffer, length, 1);
    if (!NT_SUCCESS(status))
    {
        goto abandon;
    }

    /* M9 device path: stream devices write through their own (possibly
     * blocking) op via a pool copy of the user bytes. */
    if (file->device->ops->Write != 0)
    {
        void *bounce = 0;
        if (length != 0)
        {
            bounce = MiAllocatePool(length);
            if (bounce == 0)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto abandon;
            }
            memcpy(bounce, buffer, length); /* probed above */
        }
        ULONG_PTR transferred = 0;
        status = file->device->ops->Write(file, bounce, length, &transferred);
        if (bounce != 0)
        {
            MiFreePool(bounce);
        }
        if (NT_SUCCESS(status))
        {
            status = IopCompleteTransfer(iosb, event, apcBlock, status, transferred);
        }
        else
        {
            goto abandon;
        }
        ObDereferenceObject(file);
        return status;
    }

    PMI_PAGE_CACHE cache;
    status = file->device->ops->GetCache(file, &cache);
    if (!NT_SUCCESS(status))
    {
        goto abandon;
    }

    /* A write past EOF extends the file; the gap reads as zeroes (the
     * cache's new pages are zero-filled, and the FS zeroed the clusters). */
    if (offset + length > cache->fileSize)
    {
        status = file->device->ops->SetEndOfFile(file, offset + length);
        if (!NT_SUCCESS(status))
        {
            goto abandon;
        }
    }
    if (length != 0)
    {
        MiCacheWrite(cache, offset, buffer, length);
        status = file->device->ops->WritebackRange(file, offset, length);
        if (!NT_SUCCESS(status))
        {
            goto abandon;
        }
    }
    if (file->synchronousIo)
    {
        file->currentByteOffset.QuadPart = (LONGLONG)offset + length;
    }
    status = IopCompleteTransfer(iosb, event, apcBlock, STATUS_SUCCESS, length);
    ObDereferenceObject(file);
    return status;

abandon:
    /* The request never completed (no IOSB write): the APC must not fire. */
    if (apcBlock != 0)
    {
        MiFreePool(apcBlock);
    }
    ObDereferenceObject(file);
    return status;
}

NTSTATUS NtFlushBuffersFile(HANDLE handle, IO_STATUS_BLOCK *iosb)
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
    PFILE_OBJECT file;
    status = IopReferenceFileByHandle(handle, 0, &file);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* Writes are already through (immediate writeback); what may be dirty
     * is mapped-view stores into the cache — push the whole stream out. A
     * cache-less stream device (M9) has nothing to flush. */
    if (file->device->ops->GetCache == 0)
    {
        status = STATUS_SUCCESS;
        iosb->Status = STATUS_SUCCESS;
        iosb->Information = 0;
        ObDereferenceObject(file);
        return status;
    }
    if (!file->isDirectory)
    {
        PMI_PAGE_CACHE cache;
        status = file->device->ops->GetCache(file, &cache);
        if (NT_SUCCESS(status))
        {
            status = file->device->ops->WritebackRange(file, 0, cache->fileSize);
        }
    }
    else
    {
        status = STATUS_SUCCESS;
    }
    if (NT_SUCCESS(status))
    {
        iosb->Status = STATUS_SUCCESS;
        iosb->Information = 0;
    }
    ObDereferenceObject(file);
    return status;
}
