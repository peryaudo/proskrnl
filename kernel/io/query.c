/* kernel/io/query.c — NtQueryInformationFile / NtSetInformationFile /
 * NtQueryDirectoryFile info classes (M6; docs/05 calls this the mechanical
 * file). Class coverage and error conventions pinned by
 * tests/ntapi/sem_file/{info_classes,query_dir,read_write,delete_on_close}.c
 * on the Wine oracle — including the pinned-Wine choices: an unsupported
 * class is STATUS_NOT_IMPLEMENTED, and a directory mask binds to the handle
 * (a NULL mask on a later call reuses the previous one).
 */
#include "kernel/io/io.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

/* --- NtQueryInformationFile ------------------------------------------------- */

static void IopFillBasic(const IO_FILE_INFO *raw, FILE_BASIC_INFORMATION *out)
{
    memset(out, 0, sizeof(*out));
    out->CreationTime = raw->creationTime;
    out->LastAccessTime = raw->lastAccessTime;
    out->LastWriteTime = raw->lastWriteTime;
    out->ChangeTime = raw->lastWriteTime; /* FAT has no change time */
    out->FileAttributes = raw->fileAttributes;
}

static void IopFillStandard(const IO_FILE_INFO *raw, PIO_FCB fcb, FILE_STANDARD_INFORMATION *out)
{
    memset(out, 0, sizeof(*out));
    out->AllocationSize.QuadPart = (LONGLONG)raw->allocationSize;
    out->EndOfFile.QuadPart = (LONGLONG)raw->endOfFile;
    out->NumberOfLinks = 1;
    out->DeletePending = fcb->deletePending ? TRUE : FALSE;
    out->Directory = raw->isDirectory ? TRUE : FALSE;
}

/* Fill a FILE_NAME_INFORMATION-shaped blob; *writtenOut counts bytes
 * consumed in `buffer`. STATUS_BUFFER_OVERFLOW when the name is cut. */
static NTSTATUS IopFillName(PFILE_OBJECT file, void *buffer, ULONG capacity, ULONG *writtenOut)
{
    FILE_NAME_INFORMATION *out = buffer;
    ULONG fixed = (ULONG)offsetof(FILE_NAME_INFORMATION, FileName);
    if (capacity < fixed)
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    ULONG nameBytes = 0;
    NTSTATUS status =
        file->device->ops->QueryName(file, out->FileName, capacity - fixed, &nameBytes);
    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW)
    {
        return status;
    }
    out->FileNameLength = nameBytes;
    *writtenOut = fixed + (nameBytes <= capacity - fixed ? nameBytes : capacity - fixed);
    return status;
}

NTSTATUS NtQueryInformationFile(HANDLE handle, PIO_STATUS_BLOCK iosb, PVOID buffer, ULONG length,
                                FILE_INFORMATION_CLASS informationClass)
{
    if (iosb == 0 || buffer == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(iosb, sizeof(*iosb), sizeof(void *));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(buffer, length, 1);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    ULONG needed;
    switch (informationClass)
    {
    case FileBasicInformation:
        needed = sizeof(FILE_BASIC_INFORMATION);
        break;
    case FileStandardInformation:
        needed = sizeof(FILE_STANDARD_INFORMATION);
        break;
    case FilePositionInformation:
        needed = sizeof(FILE_POSITION_INFORMATION);
        break;
    case FileNameInformation:
        needed = (ULONG)offsetof(FILE_NAME_INFORMATION, FileName);
        break;
    case FileAllInformation:
        needed = (ULONG)offsetof(FILE_ALL_INFORMATION, NameInformation.FileName);
        break;
    default:
        /* Unsupported class: STATUS_NOT_IMPLEMENTED (pinned Wine; real NT
         * says INVALID_INFO_CLASS — Wine wins, Art. 6). */
        return STATUS_NOT_IMPLEMENTED;
    }
    if (length < needed)
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    PFILE_OBJECT file;
    status = IopReferenceFileByHandle(handle, 0, &file);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    IO_FILE_INFO raw;
    status = file->device->ops->GetInfo(file, &raw);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(file);
        return status;
    }

    ULONG_PTR information = needed;
    switch (informationClass)
    {
    case FileBasicInformation:
        IopFillBasic(&raw, buffer);
        break;
    case FileStandardInformation:
        IopFillStandard(&raw, file->fcb, buffer);
        break;
    case FilePositionInformation:
    {
        FILE_POSITION_INFORMATION *out = buffer;
        out->CurrentByteOffset = file->currentByteOffset;
        break;
    }
    case FileNameInformation:
    {
        ULONG written = 0;
        status = IopFillName(file, buffer, length, &written);
        information = written;
        break;
    }
    case FileAllInformation:
    {
        FILE_ALL_INFORMATION *out = buffer;
        memset(out, 0, offsetof(FILE_ALL_INFORMATION, NameInformation));
        IopFillBasic(&raw, &out->BasicInformation);
        IopFillStandard(&raw, file->fcb, &out->StandardInformation);
        out->PositionInformation.CurrentByteOffset = file->currentByteOffset;
        out->AccessInformation.AccessFlags = file->grantedAccess;
        out->ModeInformation.Mode = file->synchronousIo ? FILE_SYNCHRONOUS_IO_NONALERT : 0;
        ULONG nameOffset = (ULONG)offsetof(FILE_ALL_INFORMATION, NameInformation);
        ULONG written = 0;
        status = IopFillName(file, (char *)buffer + nameOffset, length - nameOffset, &written);
        information = nameOffset + written;
        break;
    }
    default:
        break;
    }

    if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW)
    {
        iosb->Status = status;
        iosb->Information = information;
    }
    ObDereferenceObject(file);
    return status;
}

/* --- NtSetInformationFile --------------------------------------------------- */

/* The pinned Wine statuses for resizing through a handle without
 * FILE_WRITE_DATA (fuzzer-found; pinned by sem_file/info_classes.c):
 * shrinking is STATUS_INVALID_PARAMETER, growing (or staying) is
 * STATUS_INVALID_HANDLE — artifacts of its unix backend, but the boundary
 * behaviour nonetheless (Art. 6). */
static NTSTATUS IopCheckSetEofAccess(PFILE_OBJECT file, uint64_t target)
{
    if (file->grantedAccess & FILE_WRITE_DATA)
    {
        return STATUS_SUCCESS;
    }
    IO_FILE_INFO raw;
    NTSTATUS status = file->device->ops->GetInfo(file, &raw);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    return target < raw.endOfFile ? STATUS_INVALID_PARAMETER : STATUS_INVALID_HANDLE;
}

NTSTATUS NtSetInformationFile(HANDLE handle, PIO_STATUS_BLOCK iosb, PVOID buffer, ULONG length,
                              FILE_INFORMATION_CLASS informationClass)
{
    if (iosb == 0 || buffer == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(iosb, sizeof(*iosb), sizeof(void *));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForRead(buffer, length, 1);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    ULONG needed;
    ACCESS_MASK requiredAccess;
    switch (informationClass)
    {
    case FileBasicInformation:
        needed = sizeof(FILE_BASIC_INFORMATION);
        requiredAccess = FILE_WRITE_ATTRIBUTES;
        break;
    case FilePositionInformation:
        needed = sizeof(FILE_POSITION_INFORMATION);
        requiredAccess = 0;
        break;
    case FileEndOfFileInformation:
        needed = sizeof(FILE_END_OF_FILE_INFORMATION);
        requiredAccess = 0; /* checked below: the pinned Wine statuses differ
                             * by direction, not a flat ACCESS_DENIED */
        break;
    case FileAllocationInformation:
        needed = sizeof(FILE_ALLOCATION_INFORMATION);
        requiredAccess = 0;
        break;
    case FileDispositionInformation:
        needed = sizeof(FILE_DISPOSITION_INFORMATION);
        requiredAccess = DELETE;
        break;
    default:
        return STATUS_NOT_IMPLEMENTED; /* pinned Wine, as in query above */
    }
    if (length < needed)
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    PFILE_OBJECT file;
    status = IopReferenceFileByHandle(handle, requiredAccess, &file);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    switch (informationClass)
    {
    case FileBasicInformation:
    {
        FILE_BASIC_INFORMATION basic;
        memcpy(&basic, buffer, sizeof(basic));
        status = file->device->ops->SetBasic(file, &basic);
        break;
    }
    case FilePositionInformation:
    {
        FILE_POSITION_INFORMATION position;
        memcpy(&position, buffer, sizeof(position));
        if (position.CurrentByteOffset.QuadPart < 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        file->currentByteOffset = position.CurrentByteOffset;
        status = STATUS_SUCCESS;
        break;
    }
    case FileEndOfFileInformation:
    {
        FILE_END_OF_FILE_INFORMATION eof;
        memcpy(&eof, buffer, sizeof(eof));
        if (eof.EndOfFile.QuadPart < 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = IopCheckSetEofAccess(file, (uint64_t)eof.EndOfFile.QuadPart);
        if (NT_SUCCESS(status))
        {
            status = file->device->ops->SetEndOfFile(file, (uint64_t)eof.EndOfFile.QuadPart);
        }
        break;
    }
    case FileAllocationInformation:
    {
        /* Shrinking the allocation truncates; growth is advisory (the FS
         * allocates on demand). */
        FILE_ALLOCATION_INFORMATION allocation;
        memcpy(&allocation, buffer, sizeof(allocation));
        IO_FILE_INFO raw;
        status = file->device->ops->GetInfo(file, &raw);
        if (NT_SUCCESS(status) && allocation.AllocationSize.QuadPart >= 0 &&
            (uint64_t)allocation.AllocationSize.QuadPart < raw.endOfFile)
        {
            status =
                file->device->ops->SetEndOfFile(file, (uint64_t)allocation.AllocationSize.QuadPart);
        }
        break;
    }
    case FileDispositionInformation:
    {
        FILE_DISPOSITION_INFORMATION disposition;
        memcpy(&disposition, buffer, sizeof(disposition));
        status = file->device->ops->SetDisposition(file, disposition.DoDeleteFile);
        break;
    }
    default:
        break;
    }

    if (NT_SUCCESS(status))
    {
        iosb->Status = status;
        iosb->Information = 0;
    }
    ObDereferenceObject(file);
    return status;
}

/* --- NtQueryDirectoryFile --------------------------------------------------- */

/* Case-insensitive wildcard match: '*' any run, '?' one unit. The masks
 * Wine's PE stack passes are simple globs; the DOS-special forms ('<' '>'
 * '"') are not generated by it and not implemented. */
static BOOLEAN IopMatchMask(const WCHAR *name, ULONG nameUnits, const WCHAR *mask, ULONG maskUnits)
{
    if (maskUnits == 0)
    {
        return nameUnits == 0;
    }
    WCHAR m = mask[0];
    if (m == '*')
    {
        for (ULONG skip = 0; skip <= nameUnits; skip++)
        {
            if (IopMatchMask(name + skip, nameUnits - skip, mask + 1, maskUnits - 1))
            {
                return TRUE;
            }
        }
        return FALSE;
    }
    if (nameUnits == 0)
    {
        return FALSE;
    }
    if (m != '?')
    {
        WCHAR a = m, b = name[0];
        if (a >= 'a' && a <= 'z')
        {
            a = (WCHAR)(a - 'a' + 'A');
        }
        if (b >= 'a' && b <= 'z')
        {
            b = (WCHAR)(b - 'a' + 'A');
        }
        if (a != b)
        {
            return FALSE;
        }
    }
    return IopMatchMask(name + 1, nameUnits - 1, mask + 1, maskUnits - 1);
}

/* Per-class fixed sizes (offset of the trailing FileName array). */
static ULONG IopDirEntryFixedSize(FILE_INFORMATION_CLASS informationClass)
{
    switch (informationClass)
    {
    case FileDirectoryInformation:
        return (ULONG)offsetof(FILE_DIRECTORY_INFORMATION, FileName);
    case FileFullDirectoryInformation:
        return (ULONG)offsetof(FILE_FULL_DIRECTORY_INFORMATION, FileName);
    case FileBothDirectoryInformation:
        return (ULONG)offsetof(FILE_BOTH_DIRECTORY_INFORMATION, FileName);
    case FileNamesInformation:
        return (ULONG)offsetof(FILE_NAMES_INFORMATION, FileName);
    default:
        return 0;
    }
}

/* Serialize one IO_DIR_ENTRY at `out`. */
static void IopFillDirEntry(FILE_INFORMATION_CLASS informationClass, const IO_DIR_ENTRY *entry,
                            void *out, ULONG nameBytes)
{
    switch (informationClass)
    {
    case FileDirectoryInformation:
    {
        FILE_DIRECTORY_INFORMATION *d = out;
        memset(d, 0, offsetof(FILE_DIRECTORY_INFORMATION, FileName));
        d->CreationTime = entry->info.creationTime;
        d->LastAccessTime = entry->info.lastAccessTime;
        d->LastWriteTime = entry->info.lastWriteTime;
        d->ChangeTime = entry->info.lastWriteTime;
        d->EndOfFile.QuadPart = (LONGLONG)entry->info.endOfFile;
        d->AllocationSize.QuadPart = (LONGLONG)entry->info.allocationSize;
        d->FileAttributes = entry->info.fileAttributes;
        d->FileNameLength = entry->nameLength;
        memcpy(d->FileName, entry->name, nameBytes);
        break;
    }
    case FileFullDirectoryInformation:
    {
        FILE_FULL_DIRECTORY_INFORMATION *d = out;
        memset(d, 0, offsetof(FILE_FULL_DIRECTORY_INFORMATION, FileName));
        d->CreationTime = entry->info.creationTime;
        d->LastAccessTime = entry->info.lastAccessTime;
        d->LastWriteTime = entry->info.lastWriteTime;
        d->ChangeTime = entry->info.lastWriteTime;
        d->EndOfFile.QuadPart = (LONGLONG)entry->info.endOfFile;
        d->AllocationSize.QuadPart = (LONGLONG)entry->info.allocationSize;
        d->FileAttributes = entry->info.fileAttributes;
        d->FileNameLength = entry->nameLength;
        memcpy(d->FileName, entry->name, nameBytes);
        break;
    }
    case FileBothDirectoryInformation:
    {
        FILE_BOTH_DIRECTORY_INFORMATION *d = out;
        memset(d, 0, offsetof(FILE_BOTH_DIRECTORY_INFORMATION, FileName));
        d->CreationTime = entry->info.creationTime;
        d->LastAccessTime = entry->info.lastAccessTime;
        d->LastWriteTime = entry->info.lastWriteTime;
        d->ChangeTime = entry->info.lastWriteTime;
        d->EndOfFile.QuadPart = (LONGLONG)entry->info.endOfFile;
        d->AllocationSize.QuadPart = (LONGLONG)entry->info.allocationSize;
        d->FileAttributes = entry->info.fileAttributes;
        d->FileNameLength = entry->nameLength;
        /* ShortName: Wine leaves it empty on unix filesystems; the tests do
         * not pin it — keep it empty for both backends. */
        memcpy(d->FileName, entry->name, nameBytes);
        break;
    }
    case FileNamesInformation:
    {
        FILE_NAMES_INFORMATION *d = out;
        memset(d, 0, offsetof(FILE_NAMES_INFORMATION, FileName));
        d->FileNameLength = entry->nameLength;
        memcpy(d->FileName, entry->name, nameBytes);
        break;
    }
    default:
        break;
    }
}

NTSTATUS NtQueryDirectoryFile(HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, PVOID apcContext,
                              PIO_STATUS_BLOCK iosb, PVOID buffer, ULONG length,
                              FILE_INFORMATION_CLASS informationClass, BOOLEAN returnSingleEntry,
                              PUNICODE_STRING mask, BOOLEAN restartScan)
{
    (void)apcContext;
    if (iosb == 0 || buffer == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(iosb, sizeof(*iosb), sizeof(void *));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(buffer, length, 1);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (apc != 0 && ExGetPreviousMode() == UserMode)
    {
        return STATUS_NOT_IMPLEMENTED; /* io.h: user APCs arrive with M7 */
    }
    ULONG fixedSize = IopDirEntryFixedSize(informationClass);
    if (fixedSize == 0)
    {
        return STATUS_INVALID_INFO_CLASS;
    }
    if (length < fixedSize)
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    PFILE_OBJECT file;
    status = IopReferenceFileByHandle(handle, FILE_LIST_DIRECTORY, &file);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (!file->isDirectory)
    {
        ObDereferenceObject(file);
        return STATUS_INVALID_PARAMETER;
    }

    /* The mask binds to the handle; a fresh non-empty mask replaces it
     * (pinned Wine: NULL reuses the stored one). */
    if (mask != 0 && mask->Length != 0 && mask->Buffer != 0)
    {
        PWSTR copy = MiAllocatePool(mask->Length);
        if (copy == 0)
        {
            ObDereferenceObject(file);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memcpy(copy, mask->Buffer, mask->Length);
        if (file->dirMask.Buffer != 0)
        {
            MiFreePool(file->dirMask.Buffer);
        }
        file->dirMask.Buffer = copy;
        file->dirMask.Length = mask->Length;
        file->dirMask.MaximumLength = mask->Length;
    }
    if (restartScan)
    {
        file->dirCursor = 0;
    }
    BOOLEAN firstScan = !file->dirScanStarted;
    file->dirScanStarted = TRUE;

    ULONG written = 0;
    ULONG *previousNextOffset = 0;
    ULONG emitted = 0;
    for (;;)
    {
        IO_DIR_ENTRY entry;
        ULONG cursor = file->dirCursor;
        status = file->device->ops->ReadDirectory(file, &cursor, &entry);
        if (status == STATUS_NO_MORE_FILES)
        {
            break;
        }
        if (!NT_SUCCESS(status))
        {
            break;
        }

        if (file->dirMask.Buffer != 0 &&
            !IopMatchMask(entry.name, entry.nameLength / sizeof(WCHAR), file->dirMask.Buffer,
                          file->dirMask.Length / sizeof(WCHAR)))
        {
            file->dirCursor = cursor; /* consumed, filtered out */
            continue;
        }

        /* Entries are 8-byte aligned (the LARGE_INTEGER members). */
        ULONG start = (written + 7) & ~7u;
        ULONG nameBytes = entry.nameLength;
        if (start + fixedSize > length)
        {
            status = emitted == 0 ? STATUS_INFO_LENGTH_MISMATCH : STATUS_SUCCESS;
            break;
        }
        if (start + fixedSize + nameBytes > length)
        {
            if (emitted != 0)
            {
                status = STATUS_SUCCESS;
                break;
            }
            /* One entry that fits except for its name: truncated name +
             * STATUS_BUFFER_OVERFLOW (the FileNameInformation convention). */
            nameBytes = length - start - fixedSize;
            status = STATUS_BUFFER_OVERFLOW;
        }
        IopFillDirEntry(informationClass, &entry, (char *)buffer + start, nameBytes);
        if (previousNextOffset != 0)
        {
            *previousNextOffset = start - (ULONG)((char *)previousNextOffset - (char *)buffer);
        }
        previousNextOffset = (ULONG *)((char *)buffer + start); /* NextEntryOffset is first */
        written = start + fixedSize + nameBytes;
        emitted++;
        file->dirCursor = cursor;
        if (status == STATUS_BUFFER_OVERFLOW || returnSingleEntry)
        {
            break;
        }
    }

    if (emitted == 0)
    {
        if (status == STATUS_NO_MORE_FILES && firstScan)
        {
            status = STATUS_NO_SUCH_FILE;
        }
        ObDereferenceObject(file);
        if (status == STATUS_NO_MORE_FILES || status == STATUS_NO_SUCH_FILE)
        {
            return status;
        }
        return status;
    }

    NTSTATUS finalStatus = status == STATUS_BUFFER_OVERFLOW ? status : STATUS_SUCCESS;
    status = IopCompleteRequest(iosb, event, finalStatus, written);
    ObDereferenceObject(file);
    return status;
}
