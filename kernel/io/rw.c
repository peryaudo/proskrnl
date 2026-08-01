/* kernel/io/rw.c — NtReadFile / NtWriteFile / NtFlushBuffersFile (M6).
 *
 * The async-completion protocol, with every transfer completing inline:
 * the IOSB is written before the optional event is signalled
 * (IopCompleteRequest) and the final status is the return value —
 * semantics pinned by tests/ntapi/sem_file/read_write.c on the Wine
 * oracle. Inline completion is a legal point inside the NT contract
 * (STATUS_PENDING is permitted, never required — docs/19 §1) rather than
 * an Art. 3 mandate; docs/19 is the plan for genuinely pending transfers.
 *
 * All data moves through the file's unified page cache, then writes go
 * straight to disk (immediate writeback), which is what makes the
 * sem_mm/file_coherence stress test structural rather than lucky.
 */
#include "kernel/io/io.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/init/panic.h"
#include "kernel/lib/string.h"
#include "kernel/mm/pool.h"
#include "kernel/mm/phys.h" /* CUI-5: PAGE_SIZE for the scatter/gather segments */

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

/* Shared argument shaping for NtReadFile/NtWriteFile. `writeToEndOut`
 * non-0 (the write path) accepts the FILE_WRITE_TO_END_OF_FILE sentinel —
 * QuadPart == -1, the value the pinned tree fixes
 * (third_party/wine/dlls/ntdll/unix/unix_private.h
 * FILE_WRITE_TO_END_OF_FILE) and sem_file/append.c pins at the boundary.
 * Every other negative offset is refused, including the -2
 * FILE_USE_FILE_POINTER_POSITION sentinel (same header) — unpinned, no
 * baked caller; a consumer would get a distinguishable
 * STATUS_INVALID_PARAMETER, never a fabricated position (docs/03). */
static NTSTATUS IopStartTransfer(HANDLE handle, HANDLE event, ACCESS_MASK needed,
                                 PIO_APC_ROUTINE apc, PVOID apcContext, PIO_STATUS_BLOCK iosb,
                                 PLARGE_INTEGER byteOffset, PFILE_OBJECT *fileOut,
                                 uint64_t *offsetOut, PKAPC *apcOut, BOOLEAN *writeToEndOut)
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
        /* NULL ByteOffset: the current position on a synchronous handle
         * (pinned read_write.c). On a STREAM device offsets are meaningless
         * and NULL is what overlapped callers pass (rpcrt4_conn_np_read/
         * write on FILE_FLAG_OVERLAPPED pipes — pinned async_listen.c);
         * only an asynchronous DISK handle rejects it. */
        if (!file->synchronousIo && file->device->ops->Read == 0)
        {
            ObDereferenceObject(file);
            return STATUS_INVALID_PARAMETER;
        }
        offset = file->synchronousIo ? (uint64_t)file->currentByteOffset.QuadPart : 0;
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
            if (writeToEndOut != 0 && captured.QuadPart == -1)
            {
                /* FILE_WRITE_TO_END_OF_FILE: the write lands at EOF. */
                *writeToEndOut = TRUE;
                offset = 0;
            }
            else
            {
                ObDereferenceObject(file);
                return STATUS_INVALID_PARAMETER;
            }
        }
        else
        {
            offset = (uint64_t)captured.QuadPart;
        }
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
    NTSTATUS status = IopStartTransfer(handle, event, FILE_READ_DATA, apc, apcContext, iosb,
                                       byteOffset, &file, &offset, &apcBlock, 0);
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
        IopEnterSyncIo(iosb); /* CUI-5: cancellable while parked in the op */
        status = file->device->ops->Read(file, bounce, length, &transferred);
        IopLeaveSyncIo();
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
    BOOLEAN writeToEnd = FALSE;
    /* The access gate is NOT plain FILE_WRITE_DATA: an APPEND-ONLY handle
     * (FILE_APPEND_DATA without WRITE_DATA — kernelbase's append-mode
     * loggers) writes too, forced to EOF below (pinned sem_file/append.c). */
    NTSTATUS status = IopStartTransfer(handle, event, 0, apc, apcContext, iosb, byteOffset, &file,
                                       &offset, &apcBlock, &writeToEnd);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if ((file->grantedAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) == 0)
    {
        status = STATUS_ACCESS_DENIED;
        goto abandon;
    }
    if ((file->grantedAccess & FILE_WRITE_DATA) == 0)
    {
        writeToEnd = TRUE; /* append-only: every write lands at EOF */
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
        IopEnterSyncIo(iosb); /* CUI-5: cancellable while parked in the op */
        status = file->device->ops->Write(file, bounce, length, &transferred);
        IopLeaveSyncIo();
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

    /* Falling out of the device branch above means ops->Write is absent; a
     * device that also has no GetCache cannot be written at all, and calling
     * through the NULL pointer would be a ring-0 fault -- which KiDispatchTrap
     * does not contain, so a KiPanic. HidInputOps/HidPointerOps are exactly
     * that shape (Read, no Write, no GetCache) and their Create does not
     * filter grantedAccess, so ring 3 reaches here with one open + one write.
     * STATUS_INVALID_DEVICE_REQUEST is NT's answer for a major function the
     * device does not implement. */
    if (file->device->ops->GetCache == 0)
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto abandon;
    }

    PMI_PAGE_CACHE cache;
    status = file->device->ops->GetCache(file, &cache);
    if (!NT_SUCCESS(status))
    {
        goto abandon;
    }

    if (writeToEnd)
    {
        offset = cache->fileSize; /* append semantics: EOF at write time */
    }

    /* A write past EOF extends the file; the gap reads as zeroes (the
     * cache's new pages are zero-filled, and the FS zeroed the clusters).
     * A cache device with no SetEndOfFile cannot be resized -- FbOps is one
     * (the scanout is a fixed mode), and its Create ignores grantedAccess
     * too, so this was the same NULL dispatch one write past EOF away. */
    if (offset + length > cache->fileSize)
    {
        if (file->device->ops->SetEndOfFile == 0)
        {
            status = STATUS_INVALID_DEVICE_REQUEST;
            goto abandon;
        }
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

static NTSTATUS IopFlushBuffers(HANDLE handle, IO_STATUS_BLOCK *iosb)
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
    /* A flush needs a writable handle (CUI-5, pinned sem_file/ea_volume.c:
     * the pinned Wine's flush asks the server for FILE_WRITE_DATA and
     * falls back to FILE_APPEND_DATA — dlls/ntdll/unix/file.c
     * NtFlushBuffersFileEx). */
    if ((file->grantedAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) == 0)
    {
        ObDereferenceObject(file);
        return STATUS_ACCESS_DENIED;
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

/* CUI-7 (NtFlushVirtualMemory): write one file's cached byte range through
 * to the device — the range form of the IopFlushBuffers writeback above.
 * Declared at its Mm call site (kernel/mm/virtual.c), the same seam
 * direction as IopBuildSectionBacking. */
NTSTATUS IoWritebackSectionRange(PVOID fileObjectBody, uint64_t offset, uint64_t length)
{
    PFILE_OBJECT file = fileObjectBody;
    if (file->device->ops->GetCache == 0 || file->device->ops->WritebackRange == 0)
    {
        return STATUS_SUCCESS; /* a cache-less device has nothing to flush */
    }
    PMI_PAGE_CACHE cache;
    NTSTATUS status = file->device->ops->GetCache(file, &cache);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (offset >= cache->fileSize)
    {
        return STATUS_SUCCESS; /* the view extends past EOF: nothing on disk */
    }
    if (length > cache->fileSize - offset)
    {
        length = cache->fileSize - offset;
    }
    return file->device->ops->WritebackRange(file, offset, length);
}

NTSTATUS NtFlushBuffersFile(HANDLE handle, IO_STATUS_BLOCK *iosb)
{
    return IopFlushBuffers(handle, iosb);
}

NTSTATUS NtFlushBuffersFileEx(HANDLE handle, ULONG flags, void *parameters, ULONG parametersSize,
                              IO_STATUS_BLOCK *iosb)
{
    /* CUI-5: the plain form IS the Ex form with flags 0 in the pinned tree
     * (dlls/ntdll/unix/file.c NtFlushBuffersFile), and the oracle ignores
     * flags/params with a FIXME — pinned by sem_file/ea_volume.c. */
    (void)flags;
    (void)parameters;
    (void)parametersSize;
    return IopFlushBuffers(handle, iosb);
}

/* --- CUI-5: NtReadFileScatter / NtWriteFileGather --------------------------- */

/* The pinned Wine's contract (dlls/ntdll/unix/file.c, pinned by
 * sem_file/scatter_gather.c): only a regular file opened NON-synchronous
 * with FILE_NO_INTERMEDIATE_BUFFERING qualifies — anything else refuses
 * STATUS_INVALID_PARAMETER; gather refuses a non-page-multiple length
 * before touching the handle; `length` counts bytes, spread across
 * one-page FILE_SEGMENT_ELEMENTs; the scatter side returns STATUS_PENDING
 * with the IOSB already completed while the gather side returns the final
 * status directly (an oracle asymmetry, pinned as-is). Both complete
 * inline against the page cache (docs/19 §2). */
static NTSTATUS IopSegmentedTransfer(BOOLEAN isWrite, HANDLE handle, HANDLE event,
                                     PIO_APC_ROUTINE apc, PIO_STATUS_BLOCK iosb,
                                     FILE_SEGMENT_ELEMENT *segments, ULONG length,
                                     PLARGE_INTEGER byteOffset)
{
    if (isWrite && (length % PAGE_SIZE) != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (iosb == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(iosb, sizeof(*iosb), sizeof(void *));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (apc != 0 && ExGetPreviousMode() == UserMode)
    {
        /* No baked caller passes an APC (kernelbase sends NULL and uses the
         * event/key legs); unbuilt refuses loudly (Art. 12). */
        return STATUS_NOT_IMPLEMENTED;
    }

    PFILE_OBJECT file;
    status = IopReferenceFileByHandle(handle, isWrite ? FILE_WRITE_DATA : FILE_READ_DATA, &file);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (file->device->ops->GetCache == 0 || file->isDirectory || file->synchronousIo ||
        !file->nonBuffered)
    {
        ObDereferenceObject(file);
        return STATUS_INVALID_PARAMETER;
    }

    ULONG segmentCount = (ULONG)(((uint64_t)length + PAGE_SIZE - 1) / PAGE_SIZE);
    if (segmentCount != 0)
    {
        status =
            KiProbeForRead(segments, segmentCount * sizeof(FILE_SEGMENT_ELEMENT), sizeof(void *));
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(file);
            return status;
        }
    }

    /* The cache is resolved BEFORE the offset, because the
     * FILE_WRITE_TO_END_OF_FILE sentinel needs the current file size. */
    PMI_PAGE_CACHE cache;
    status = file->device->ops->GetCache(file, &cache);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(file);
        return status;
    }

    uint64_t offset = (uint64_t)file->currentByteOffset.QuadPart;
    if (byteOffset != 0)
    {
        LARGE_INTEGER stackOffset;
        status = KiProbeForRead(byteOffset, sizeof(*byteOffset), sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(file);
            return status;
        }
        memcpy(&stackOffset, byteOffset, sizeof(stackOffset));
        if (stackOffset.QuadPart >= 0)
        {
            offset = (uint64_t)stackOffset.QuadPart;
        }
        else if (isWrite && stackOffset.QuadPart == -1)
        {
            /* FILE_WRITE_TO_END_OF_FILE, the same sentinel NtWriteFile
             * honours (third_party/wine dlls/ntdll/unix/unix_private.h).
             * Silently keeping offset 0 for a negative value meant
             * NtWriteFileGather with this sentinel overwrote the START of
             * the file instead of appending (docs/review-2026-07 §9). */
            offset = cache->fileSize;
        }
        else
        {
            /* Every other negative offset is refused rather than folded to
             * 0 -- including the -2 FILE_USE_FILE_POINTER_POSITION sentinel,
             * which NtReadFile/NtWriteFile also refuse. */
            ObDereferenceObject(file);
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (isWrite)
    {
        if (offset + length > cache->fileSize)
        {
            /* Same unresizable-cache-device case as NtWriteFile: the gate at
             * the top of this function checks GetCache but not SetEndOfFile,
             * so FILE_NO_INTERMEDIATE_BUFFERING + NtWriteFileGather reached
             * the NULL pointer by this route instead. */
            if (file->device->ops->SetEndOfFile == 0)
            {
                ObDereferenceObject(file);
                return STATUS_INVALID_DEVICE_REQUEST;
            }
            status = file->device->ops->SetEndOfFile(file, offset + length);
            if (!NT_SUCCESS(status))
            {
                ObDereferenceObject(file);
                return status;
            }
        }
        for (ULONG i = 0; i < segmentCount; i++)
        {
            const void *page = (const void *)segments[i].Buffer;
            status = KiProbeForRead((void *)(uintptr_t)page, PAGE_SIZE, 1);
            if (!NT_SUCCESS(status))
            {
                ObDereferenceObject(file);
                return status;
            }
            MiCacheWrite(cache, offset + (uint64_t)i * PAGE_SIZE, page, PAGE_SIZE);
        }
        if (length != 0)
        {
            status = file->device->ops->WritebackRange(file, offset, length);
            if (!NT_SUCCESS(status))
            {
                ObDereferenceObject(file);
                return status;
            }
        }
        status = IopCompleteRequest(iosb, event, STATUS_SUCCESS, length);
        ObDereferenceObject(file);
        return status; /* gather returns the final status (oracle shape) */
    }

    /* Scatter: short reads across EOF; nothing at all is END_OF_FILE. */
    NTSTATUS finalStatus = STATUS_SUCCESS;
    uint64_t total = 0;
    if (offset >= cache->fileSize)
    {
        finalStatus = STATUS_END_OF_FILE;
    }
    else
    {
        uint64_t avail = cache->fileSize - offset;
        if (avail > length)
        {
            avail = length;
        }
        for (uint64_t position = 0; position < avail;)
        {
            uint64_t chunk = PAGE_SIZE;
            if (chunk > avail - position)
            {
                chunk = avail - position;
            }
            void *page = (void *)segments[position / PAGE_SIZE].Buffer;
            status = KiProbeForWrite(page, (SIZE_T)chunk, 1);
            if (!NT_SUCCESS(status))
            {
                ObDereferenceObject(file);
                return status;
            }
            MiCacheRead(cache, offset + position, page, chunk);
            position += chunk;
        }
        total = avail;
    }
    IopCompleteRequest(iosb, event, finalStatus, (ULONG_PTR)total);
    ObDereferenceObject(file);
    return STATUS_PENDING; /* scatter always answers PENDING (oracle shape) */
}

NTSTATUS NtReadFileScatter(HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, PVOID apcContext,
                           PIO_STATUS_BLOCK iosb, FILE_SEGMENT_ELEMENT *segments, ULONG length,
                           PLARGE_INTEGER byteOffset, PULONG key)
{
    (void)apcContext;
    (void)key;
    return IopSegmentedTransfer(FALSE, handle, event, apc, iosb, segments, length, byteOffset);
}

NTSTATUS NtWriteFileGather(HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, PVOID apcContext,
                           PIO_STATUS_BLOCK iosb, FILE_SEGMENT_ELEMENT *segments, ULONG length,
                           PLARGE_INTEGER byteOffset, PULONG key)
{
    (void)apcContext;
    (void)key;
    return IopSegmentedTransfer(TRUE, handle, event, apc, iosb, segments, length, byteOffset);
}
