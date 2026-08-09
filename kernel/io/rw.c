/* kernel/io/rw.c — NtReadFile / NtWriteFile / NtFlushBuffersFile (M6).
 *
 * The async-completion protocol, with every transfer completing inline:
 * the IOSB is written before the optional event is signalled
 * (IopCompleteRequest); a synchronous handle returns the final status
 * (pinned sem_file/read_write.c) and an asynchronous one answers the
 * pending shape over the same inline completion (IopAsyncReturnShape,
 * pinned sem_file/async_inline.c — CUI-8 §7). Inline completion is a
 * legal point inside the NT contract (STATUS_PENDING is permitted, never
 * required — docs/19 §1) rather than an Art. 3 mandate; docs/19 is the
 * plan for genuinely pending transfers.
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

/* Write the IOSB / signal the event (IopCompleteRequest), then post the
 * completion PACKET if the handle is bound to a port, then queue the
 * completion APC through the engine authority (io.h) — the IOSB is in
 * place before the routine can run, and the issuer here is the completing
 * thread itself (inline completion). Pinned by sem_file/apc_completion.c
 * and sem_port/file_completion.c.
 *
 * The packet's VALUE is the caller's ApcContext, and only when there is no
 * ApcRoutine: the pinned oracle computes it as
 * `cvalue = apc ? 0 : (ULONG_PTR)apc_user` and posts nothing when it is
 * zero (dlls/ntdll/unix/file.c:6053, :6215). So an APC-driven completion
 * and a port-driven one are alternatives, never both, and a caller that
 * asked for neither gets neither. Win32 never hits the quiet case — the
 * OVERLAPPED pointer is always the context. */
NTSTATUS IopCompleteTransfer(PFILE_OBJECT file, PIO_STATUS_BLOCK iosb, HANDLE event, PKAPC apc,
                             PVOID apcContext, NTSTATUS status, ULONG_PTR information,
                             BOOLEAN reportsPending)
{
    NTSTATUS final = IopCompleteRequest(iosb, event, status, information);
    ULONG_PTR completionValue = apc != 0 ? 0 : (ULONG_PTR)apcContext;
    /* FILE_SKIP_COMPLETION_PORT_ON_SUCCESS, and its axis is the one thing
     * about it worth reading twice: the packet is skipped only when the call
     * did NOT report STATUS_PENDING to its caller. A request that pends
     * ALWAYS posts, flag or no flag — a caller holding ERROR_IO_PENDING has
     * nothing else to wait on, so skipping there hangs it forever.
     *
     * The oracle says this in three places that agree: add_completion's
     * `ret_status == STATUS_PENDING` argument (dlls/ntdll/unix/file.c),
     * set_fd_completion's `req->async ||` (server/fd.c) and async_terminate's
     * `async->pending ||` (server/async.c). Note what those guards do NOT
     * carry: a status term. The skip is decided by pendedness alone, and the
     * `!NT_ERROR` that sits beside it in server/async.c is the separate
     * outer question of whether to signal completion at all — folding it in
     * here would post where the oracle stays silent. The name
     * "…_ON_SUCCESS" is the misleading part of this whole contract.
     *
     * `reportsPending` is the caller's answer because only the caller knows:
     * the device paths return this status as-is, while the disk paths run it
     * through IopAsyncReturnShape afterwards. It comes from
     * IopWillReportPending, which IS that shape's predicate — one statement
     * of the rule, not two that can drift. */
    if ((file->completionFlags & FILE_SKIP_COMPLETION_PORT_ON_SUCCESS) != 0 && !reportsPending)
    {
        completionValue = 0;
    }
    if (file->completionPort != 0 && completionValue != 0)
    {
        /* Through the one packet-posting engine (G10), never a second
         * queue. A failure to post is discarded for the same reason a
         * failed event signal is: the transfer HAS happened. */
        (void)IopPostCompletionPacket(file->completionPort, file->completionKey, completionValue,
                                      status, information);
    }
    IopQueueCompletionApc(KeGetCurrentThread(), apc);
    return final;
}

/* WILL this call answer STATUS_PENDING to its caller? Factored out of
 * IopAsyncReturnShape below because IopCompleteTransfer needs the same
 * question answered for the completion-packet rule, and two spellings of it
 * would drift (G10). */
static BOOLEAN IopWillReportPending(PFILE_OBJECT file, NTSTATUS final, BOOLEAN isWrite)
{
    if (file->synchronousIo)
    {
        return FALSE;
    }
    return final == STATUS_SUCCESS || (!isWrite && final == STATUS_END_OF_FILE);
}

/* The CUI-8 §7 pin (tests/ntapi/sem_file/async_inline.c against the pinned
 * Wine — dlls/ntdll/unix/file.c, the NtReadFile/NtWriteFile ret_status
 * tails): a data transfer on an ASYNCHRONOUS disk-file handle completes
 * inline but ANSWERS the pending shape — STATUS_PENDING from the call, the
 * IOSB already final, the event already signalled, the APC already queued.
 * Reads convert SUCCESS and END_OF_FILE; writes convert only SUCCESS; a
 * refusal that never wrote the IOSB stays inline. The scatter/gather tails
 * below pinned the same shape first (CUI-5). */
static NTSTATUS IopAsyncReturnShape(PFILE_OBJECT file, NTSTATUS final, BOOLEAN isWrite)
{
    return IopWillReportPending(file, final, isWrite) ? STATUS_PENDING : final;
}

/* Shared argument shaping for NtReadFile/NtWriteFile. `writeToEndOut`
 * non-0 (the write path) accepts the FILE_WRITE_TO_END_OF_FILE sentinel —
 * QuadPart == -1, the value the pinned tree fixes
 * (third_party/wine/dlls/ntdll/unix/unix_private.h
 * FILE_WRITE_TO_END_OF_FILE) and sem_file/append.c pins at the boundary.
 * The -2 FILE_USE_FILE_POINTER_POSITION sentinel (same header) means "use
 * the handle's current position" — exactly what a NULL ByteOffset means —
 * on BOTH directions. It was refused as unpinned/no-baked-caller until
 * ntdll:file produced the caller (file.c:5183 writes "DCBA" at -2 after a
 * SetFilePointer and expects STATUS_SUCCESS); pinned by
 * sem_file/file_pointer_offset.c. Every OTHER negative offset is still
 * refused with STATUS_INVALID_PARAMETER, which is the same file.c loop's
 * expectation for -3 and below. */
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
            else if (captured.QuadPart == -2)
            {
                /* FILE_USE_FILE_POINTER_POSITION: the NULL-ByteOffset rule
                 * above, spelled as a value. Same admissibility test, so an
                 * asynchronous disk handle refuses it exactly as it refuses
                 * NULL — one rule, one place. */
                if (!file->synchronousIo && file->device->ops->Read == 0)
                {
                    ObDereferenceObject(file);
                    return STATUS_INVALID_PARAMETER;
                }
                offset = file->synchronousIo ? (uint64_t)file->currentByteOffset.QuadPart : 0;
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
    /* Every release of the gate below is a whole unit — test, release,
     * clear — so the clear stays even where nothing reads the flag
     * again (the NOLINTs mark those). */
    BOOLEAN syncLocked = FALSE;
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
            /* Re-validated, not "probed above": the op parked, so the entry
             * probe is stale — a sibling may have unmapped the buffer, and
             * a ring-0 fault here unwinds past this frame without cleanup
             * (uaccess.h), leaking the APC block and the FILE_OBJECT
             * reference. No park separates this probe from the copy, which
             * is what makes the probe carry the contract again. */
            NTSTATUS probe = KiProbeForWrite(buffer, transferred, 1);
            if (NT_SUCCESS(probe))
            {
                /* bounce is non-0 whenever length is, and a device never
                 * reports more transferred than it was given. */
                /* NOLINTNEXTLINE(clang-analyzer-unix.cstring.NullArg) */
                memcpy(buffer, bounce, transferred);
            }
            else
            {
                status = probe;
            }
        }
        if (bounce != 0)
        {
            MiFreePool(bounce);
        }
        if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW)
        {
            status =
                IopCompleteTransfer(file, iosb, event, apcBlock, apcContext, status, transferred,
                                    /* reportsPending */ FALSE);
        }
        else
        {
            goto abandon;
        }
        /* The DEVICE path returns this status unchanged — there is no
         * IopAsyncReturnShape below it — so it never reports pending. */
        ObDereferenceObject(file);
        return status;
    }

    /* NT serializes I/O on a synchronous handle with the file-object lock
     * (io.h syncIoLock): once the fill below can park, two threads sharing
     * one sync handle otherwise both capture the same position and both
     * store the same advance — the pinned Wine gets this atomicity from
     * the unix fd. The position is re-read UNDER the lock; the value from
     * IopStartTransfer may predate another holder's advance. */
    if (file->synchronousIo)
    {
        KiAcquireEventGate(&file->syncIoLock);
        syncLocked = TRUE;
        if (byteOffset == 0)
        {
            offset = (uint64_t)file->currentByteOffset.QuadPart;
        }
    }

    PMI_PAGE_CACHE cache;
    /* CUI-8 (docs/19 §9.9): the cold cache fill parks; mark the span so
     * NtCancelSynchronousIoFile finds it. A landed cancel surfaces as
     * STATUS_CANCELLED from GetCache with the IOSB untouched — the same
     * shape as npfs's cancelled reads (pinned sem_pipe/cancel_sync.c;
     * sem_file/cancel_data_io.c holds the race-tolerant boundary). */
    IopEnterSyncIo(iosb);
    status = file->device->ops->GetCache(file, &cache);
    IopLeaveSyncIo();
    if (!NT_SUCCESS(status))
    {
        goto abandon;
    }

    if (offset >= cache->fileSize)
    {
        if (syncLocked)
        {
            KiReleaseEventGate(&file->syncIoLock);
            syncLocked = FALSE; /* NOLINT(clang-analyzer-deadcode.DeadStores) */
        }
        /* Reading at (or past) EOF completes with STATUS_END_OF_FILE — and
         * the IOSB carries it (pinned read_write.c). */
        status = IopCompleteTransfer(file, iosb, event, apcBlock, apcContext, STATUS_END_OF_FILE, 0,
                                     IopWillReportPending(file, STATUS_END_OF_FILE, FALSE));
        status = IopAsyncReturnShape(file, status, FALSE);
        ObDereferenceObject(file);
        return status;
    }
    uint64_t bytes = length;
    if (bytes > cache->fileSize - offset)
    {
        bytes = cache->fileSize - offset; /* the short read across EOF */
    }
    /* Re-validate the buffer: the fill above parked, so the entry probe is
     * stale — a sibling may have unmapped it, and a fault inside
     * MiCacheRead would unwind past the cleanup below (leaking the APC
     * block and the FILE_OBJECT reference — permanently, since the FCB and
     * its cache pages go with it). The token carries that freshness INTO
     * MiCacheRead (issue #96 C), so a park reintroduced between these two
     * lines is a panic here rather than a leak found by a later sweep. */
    KI_PROBE_TOKEN bufferToken;
    status = KiProbeForWriteToken(buffer, bytes, 1, &bufferToken);
    if (!NT_SUCCESS(status))
    {
        goto abandon;
    }
    MiCacheRead(cache, offset, &bufferToken, buffer, bytes);
    if (file->synchronousIo)
    {
        file->currentByteOffset.QuadPart = (LONGLONG)offset + (LONGLONG)bytes;
    }
    if (syncLocked)
    {
        /* Released before the completion writes user memory (io.h). */
        KiReleaseEventGate(&file->syncIoLock);
        syncLocked = FALSE; /* NOLINT(clang-analyzer-deadcode.DeadStores) */
    }
    status =
        IopCompleteTransfer(file, iosb, event, apcBlock, apcContext, STATUS_SUCCESS,
                            (ULONG_PTR)bytes, IopWillReportPending(file, STATUS_SUCCESS, FALSE));
    status = IopAsyncReturnShape(file, status, FALSE);
    ObDereferenceObject(file);
    return status;

abandon:
    /* The request never completed (no IOSB write): the APC must not fire. */
    if (syncLocked)
    {
        KiReleaseEventGate(&file->syncIoLock);
    }
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
    /* Every release of the gate below is a whole unit — test, release,
     * clear — so the clear stays even where nothing reads the flag
     * again (the NOLINTs mark those). */
    BOOLEAN syncLocked = FALSE;
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
    /* An unreadable write buffer is STATUS_INVALID_USER_BUFFER, NOT the
     * probe's own STATUS_ACCESS_VIOLATION — and the read direction above
     * really does differ. The pinned Wine states both in one line each
     * (dlls/ntdll/unix/file.c): NtReadFile returns STATUS_ACCESS_VIOLATION
     * for an unwritable buffer (file.c:6064), NtWriteFile sets
     * STATUS_INVALID_USER_BUFFER for an unreadable one (file.c:6354).
     * Pinned by tests/ntapi/sem_file/bad_buffer.c; ntdll:file (file.c:5077,
     * 5085) is the winetest consumer. */
    status = KiProbeForRead(buffer, length, 1);
    if (!NT_SUCCESS(status))
    {
        status = STATUS_INVALID_USER_BUFFER;
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
            status =
                IopCompleteTransfer(file, iosb, event, apcBlock, apcContext, status, transferred,
                                    /* reportsPending */ FALSE);
        }
        else
        {
            goto abandon;
        }
        /* The DEVICE path returns this status unchanged — there is no
         * IopAsyncReturnShape below it — so it never reports pending. */
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

    /* The synchronous-handle file-object lock, exactly as NtReadFile: the
     * position capture, the transfer, and the advance are one serialized
     * unit per handle. */
    if (file->synchronousIo)
    {
        KiAcquireEventGate(&file->syncIoLock);
        syncLocked = TRUE;
        if (byteOffset == 0)
        {
            offset = (uint64_t)file->currentByteOffset.QuadPart;
        }
    }

    PMI_PAGE_CACHE cache;
    /* CUI-8 (docs/19 §9.9): the disk-touching legs before the cache
     * mutates — the fill, the append/extend placement with its zero-fill —
     * park inside one marked span and are cancellable (STATUS_CANCELLED,
     * IOSB untouched, the cancel_data_io.c boundary). The cache write and
     * its writeback are one durability unit: once the cache is modified
     * the operation is too late to cancel (fs/fat32 FatWritebackRange). */
    IopEnterSyncIo(iosb);
    status = file->device->ops->GetCache(file, &cache);
    if (!NT_SUCCESS(status))
    {
        goto abandonSyncIo;
    }

    /* A write past EOF extends the file; the gap reads as zeroes (the
     * cache's new pages are zero-filled, and the FS zeroed the clusters).
     * PrepareWrite decides the placement — the append offset and the
     * grow-only extension — in ONE serialization hold, against the size as
     * it is NOW: this thread may have parked since GetCache's snapshot,
     * and a stale extend decision pushed through SetEndOfFile silently
     * truncated a concurrent writer's extension (data loss). */
    if (file->device->ops->PrepareWrite != 0)
    {
        status = file->device->ops->PrepareWrite(file, &offset, length, writeToEnd);
        if (!NT_SUCCESS(status))
        {
            goto abandonSyncIo;
        }
    }
    else
    {
        /* No PrepareWrite: the device has no blocking points, so the
         * snapshot cannot go stale — and no way to grow either. FbOps is
         * exactly that shape (the scanout is a fixed mode), and its Create
         * ignores grantedAccess, so a write one byte past EOF lands here. */
        if (writeToEnd)
        {
            offset = cache->fileSize;
        }
        /* length != 0: a zero-length write extends nothing, so it needs no
         * resize either (pinned sem_file/zero_length_write.c). */
        if (length != 0 && offset + length > cache->fileSize)
        {
            status = STATUS_INVALID_DEVICE_REQUEST;
            goto abandonSyncIo;
        }
    }
    if (length != 0)
    {
        /* The cancel point: a cancel that lands in any park after this
         * check is too late — skipping the writeback with the cache
         * already modified left readers seeing bytes the caller was told
         * were NOT written, and a remount losing them (no dirty tracking
         * exists to reconcile the divergence later). */
        if (IoSyncIoCancelled())
        {
            status = STATUS_CANCELLED;
            goto abandonSyncIo;
        }
        /* Re-validate the buffer after the parks above (the NtReadFile
         * reasoning): a fault inside MiCacheWrite would skip every
         * cleanup below. No park separates probe and copy. */
        KI_PROBE_TOKEN bufferToken;
        status = KiProbeForReadToken(buffer, length, 1, &bufferToken);
        if (!NT_SUCCESS(status))
        {
            goto abandonSyncIo;
        }
        MiCacheWrite(cache, offset, &bufferToken, buffer, length);
        status = file->device->ops->WritebackRange(file, offset, length);
        if (!NT_SUCCESS(status))
        {
            goto abandonSyncIo;
        }
    }
    IopLeaveSyncIo();
    if (file->synchronousIo)
    {
        file->currentByteOffset.QuadPart = (LONGLONG)offset + length;
    }
    if (syncLocked)
    {
        /* Released before the completion writes user memory (io.h). */
        KiReleaseEventGate(&file->syncIoLock);
        syncLocked = FALSE; /* NOLINT(clang-analyzer-deadcode.DeadStores) */
    }
    status = IopCompleteTransfer(file, iosb, event, apcBlock, apcContext, STATUS_SUCCESS, length,
                                 IopWillReportPending(file, STATUS_SUCCESS, TRUE));
    status = IopAsyncReturnShape(file, status, TRUE);
    ObDereferenceObject(file);
    return status;

abandonSyncIo:
    IopLeaveSyncIo();
abandon:
    /* The request never completed (no IOSB write): the APC must not fire.
     * The caller's event is RESET, though — the oracle's NtWriteFile does
     * that for every non-pending failure past the handle resolution
     * (dlls/ntdll/unix/file.c err:), and a caller that pre-signalled it
     * reads the event and the IOSB together. */
    IopAbandonRequest(event);
    if (syncLocked)
    {
        KiReleaseEventGate(&file->syncIoLock);
    }
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
    if (NT_SUCCESS(status) && NT_SUCCESS(KiProbeForWrite(iosb, sizeof(*iosb), sizeof(void *))))
    {
        /* IOSB re-probed after the gated writeback's parks — the
         * IopCompleteRequest convention (PR #95 review round 2, F2). */
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
    FILE_SEGMENT_ELEMENT *segmentCopy = 0;
    if (segmentCount != 0)
    {
        status =
            KiProbeForRead(segments, segmentCount * sizeof(FILE_SEGMENT_ELEMENT), sizeof(void *));
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(file);
            return status;
        }
        /* Capture the segment ARRAY to kernel memory: GetCache and
         * PrepareWrite below park, so reading segments[i] from the caller's
         * memory after them would ride the stale entry probe — a sibling's
         * unmap turns that read into a ring-0 fault whose unwind skips the
         * file dereference (the rw.c re-probe rule; PR #95 review round 2,
         * F1). The per-page BUFFERS the elements name are re-probed fresh
         * at each use below. No park separates this probe from the copy. */
        segmentCopy = MiAllocatePool(segmentCount * sizeof(FILE_SEGMENT_ELEMENT));
        if (segmentCopy == 0)
        {
            ObDereferenceObject(file);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memcpy(segmentCopy, segments, segmentCount * sizeof(FILE_SEGMENT_ELEMENT));
    }

    /* The cache is resolved BEFORE the offset, because the
     * FILE_WRITE_TO_END_OF_FILE sentinel needs the current file size. */
    PMI_PAGE_CACHE cache;
    status = file->device->ops->GetCache(file, &cache);
    if (!NT_SUCCESS(status))
    {
        goto out;
    }

    uint64_t offset = (uint64_t)file->currentByteOffset.QuadPart;
    BOOLEAN writeToEnd = FALSE;
    if (byteOffset != 0)
    {
        LARGE_INTEGER stackOffset;
        status = KiProbeForRead(byteOffset, sizeof(*byteOffset), sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            goto out;
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
             * the file instead of appending (docs/review-2026-07 §9).
             * Resolved by PrepareWrite below, under the FS serialization —
             * a snapshot taken here goes stale across its parks. */
            writeToEnd = TRUE;
        }
        else
        {
            /* Every other negative offset is refused rather than folded to
             * 0 -- including the -2 FILE_USE_FILE_POINTER_POSITION sentinel,
             * which NtReadFile/NtWriteFile also refuse. */
            status = STATUS_INVALID_PARAMETER;
            goto out;
        }
    }

    if (isWrite)
    {
        /* Placement under the FS serialization, exactly as NtWriteFile:
         * the append offset and the grow-only extension come from
         * PrepareWrite's own re-read of the size, never from the cache
         * snapshot above. A device without PrepareWrite cannot be resized
         * (the unresizable-cache-device case: FILE_NO_INTERMEDIATE_BUFFERING
         * + NtWriteFileGather used to reach SetEndOfFile's NULL pointer by
         * this route). */
        if (file->device->ops->PrepareWrite != 0)
        {
            status = file->device->ops->PrepareWrite(file, &offset, length, writeToEnd);
            if (!NT_SUCCESS(status))
            {
                goto out;
            }
        }
        else
        {
            if (writeToEnd)
            {
                offset = cache->fileSize;
            }
            /* length != 0: a zero-length gather extends nothing (the
             * sem_file/zero_length_write.c rule). */
            if (length != 0 && offset + length > cache->fileSize)
            {
                status = STATUS_INVALID_DEVICE_REQUEST;
                goto out;
            }
        }
        for (ULONG i = 0; i < segmentCount; i++)
        {
            const void *page = (const void *)segmentCopy[i].Buffer;
            KI_PROBE_TOKEN pageToken;
            status = KiProbeForReadToken((void *)(uintptr_t)page, PAGE_SIZE, 1, &pageToken);
            if (!NT_SUCCESS(status))
            {
                goto out;
            }
            MiCacheWrite(cache, offset + (uint64_t)i * PAGE_SIZE, &pageToken, page, PAGE_SIZE);
        }
        if (length != 0)
        {
            status = file->device->ops->WritebackRange(file, offset, length);
            if (!NT_SUCCESS(status))
            {
                goto out;
            }
        }
        status = IopCompleteRequest(iosb, event, STATUS_SUCCESS, length);
        goto out; /* gather returns the final status (oracle shape) */
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
            void *page = (void *)segmentCopy[position / PAGE_SIZE].Buffer;
            KI_PROBE_TOKEN pageToken;
            status = KiProbeForWriteToken(page, (SIZE_T)chunk, 1, &pageToken);
            if (!NT_SUCCESS(status))
            {
                goto out;
            }
            MiCacheRead(cache, offset + position, &pageToken, page, chunk);
            position += chunk;
        }
        total = avail;
    }
    IopCompleteRequest(iosb, event, finalStatus, (ULONG_PTR)total);
    status = STATUS_PENDING; /* scatter always answers PENDING (oracle shape) */

out:
    if (segmentCopy != 0)
    {
        MiFreePool(segmentCopy);
    }
    ObDereferenceObject(file);
    return status;
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
