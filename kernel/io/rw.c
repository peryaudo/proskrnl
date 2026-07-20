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

/* A user-mode ApcRoutine needs the M7 KiUserApcDispatcher return path;
 * refuse loudly rather than dropping the completion (io.h). */
static BOOLEAN IopApcUnsupported(PIO_APC_ROUTINE apcRoutine)
{
    return apcRoutine != 0 && ExGetPreviousMode() == UserMode;
}

/* Shared argument shaping for NtReadFile/NtWriteFile. */
static NTSTATUS IopStartTransfer(HANDLE handle, ACCESS_MASK needed, PIO_APC_ROUTINE apc,
                                 PIO_STATUS_BLOCK iosb, PLARGE_INTEGER byteOffset,
                                 PFILE_OBJECT *fileOut, uint64_t *offsetOut)
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
    if (IopApcUnsupported(apc))
    {
        return STATUS_NOT_IMPLEMENTED;
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
    *fileOut = file;
    *offsetOut = offset;
    return STATUS_SUCCESS;
}

NTSTATUS NtReadFile(HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, PVOID apcContext,
                    PIO_STATUS_BLOCK iosb, PVOID buffer, ULONG length, PLARGE_INTEGER byteOffset,
                    PULONG key)
{
    (void)apcContext;
    (void)key;
    PFILE_OBJECT file;
    uint64_t offset;
    NTSTATUS status =
        IopStartTransfer(handle, FILE_READ_DATA, apc, iosb, byteOffset, &file, &offset);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = KiProbeForWrite(buffer, length, 1);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(file);
        return status;
    }

    /* M9 device path: a stream device (npfs/condrv/serial) reads through its
     * own op — which may block — via a pool bounce buffer; byte offsets do
     * not apply to a stream. */
    if (file->device->ops->Read != 0)
    {
        void *bounce = length != 0 ? MiAllocatePool(length) : 0;
        if (length != 0 && bounce == 0)
        {
            ObDereferenceObject(file);
            return STATUS_INSUFFICIENT_RESOURCES;
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
            status = IopCompleteRequest(iosb, event, status, transferred);
        }
        ObDereferenceObject(file);
        return status;
    }

    PMI_PAGE_CACHE cache;
    status = file->device->ops->GetCache(file, &cache);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(file);
        return status;
    }

    if (offset >= cache->fileSize)
    {
        /* Reading at (or past) EOF completes with STATUS_END_OF_FILE — and
         * the IOSB carries it (pinned read_write.c). */
        status = IopCompleteRequest(iosb, event, STATUS_END_OF_FILE, 0);
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
    status = IopCompleteRequest(iosb, event, STATUS_SUCCESS, (ULONG_PTR)bytes);
    ObDereferenceObject(file);
    return status;
}

NTSTATUS NtWriteFile(HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, PVOID apcContext,
                     PIO_STATUS_BLOCK iosb, const void *buffer, ULONG length,
                     PLARGE_INTEGER byteOffset, PULONG key)
{
    (void)apcContext;
    (void)key;
    PFILE_OBJECT file;
    uint64_t offset;
    NTSTATUS status =
        IopStartTransfer(handle, FILE_WRITE_DATA, apc, iosb, byteOffset, &file, &offset);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = KiProbeForRead(buffer, length, 1);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(file);
        return status;
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
                ObDereferenceObject(file);
                return STATUS_INSUFFICIENT_RESOURCES;
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
            status = IopCompleteRequest(iosb, event, status, transferred);
        }
        ObDereferenceObject(file);
        return status;
    }

    PMI_PAGE_CACHE cache;
    status = file->device->ops->GetCache(file, &cache);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(file);
        return status;
    }

    /* A write past EOF extends the file; the gap reads as zeroes (the
     * cache's new pages are zero-filled, and the FS zeroed the clusters). */
    if (offset + length > cache->fileSize)
    {
        status = file->device->ops->SetEndOfFile(file, offset + length);
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(file);
            return status;
        }
    }
    if (length != 0)
    {
        MiCacheWrite(cache, offset, buffer, length);
        status = file->device->ops->WritebackRange(file, offset, length);
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(file);
            return status;
        }
    }
    if (file->synchronousIo)
    {
        file->currentByteOffset.QuadPart = (LONGLONG)offset + length;
    }
    status = IopCompleteRequest(iosb, event, STATUS_SUCCESS, length);
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
