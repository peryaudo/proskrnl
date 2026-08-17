/* kernel/io/query.c — NtQueryInformationFile / NtSetInformationFile /
 * NtQueryDirectoryFile info classes (M6; docs/05 calls this the mechanical
 * file). Class coverage and error conventions pinned by
 * tests/ntapi/sem_file/{info_classes,query_dir,read_write,delete_on_close}.c
 * on the Wine oracle — including the pinned-Wine choice that a directory
 * mask binds to the handle (a NULL mask on a later call reuses the previous
 * one). An unsupported class is an unbuilt case, not a contract: it refuses
 * with STATUS_NOT_IMPLEMENTED and nothing pins it (Art. 12).
 */
#include "kernel/io/io.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/mm/pool.h"
#include "kernel/ob/ob.h" /* CUI-5: ObpLookupParseObject for rename targets */
#include "kernel/ke/ke.h"
#include "kernel/lib/string.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/dbgprint.h"
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

/* The one authority for a handle's I/O mode word (Art. 11): the masked
 * create options captured at create (io.h modeFlags), exactly what the
 * pinned Wine's server reports — serving only the synchronous flag
 * under-reported FILE_NO_INTERMEDIATE_BUFFERING/FILE_WRITE_THROUGH, and
 * folded ALERT into NONALERT, which the oracle does not. Served directly
 * as FileModeInformation (CUI-8, pinned sem_file/async_inline.c) and
 * inside FileAllInformation. */
static ULONG IopFileMode(PFILE_OBJECT file)
{
    return file->modeFlags;
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
 * consumed in `buffer`. STATUS_BUFFER_OVERFLOW when the name is cut.
 *
 * `buffer` is the CALLER's, at the caller's alignment (the probe asks for 1),
 * so neither the ULONG length field nor the WCHARs behind it may be stored
 * through a struct pointer into it — the dir-entry serializer above says why
 * at length. The name is built in an aligned kernel staging buffer and copied
 * out as bytes; the 260-WCHAR local covers every path this FS can produce
 * (fs/fat32 walks at most 64 components) and the pool fallback keeps a longer
 * one from being silently cut by the STAGING rather than by the caller's
 * capacity. */
static NTSTATUS IopFillName(PFILE_OBJECT file, void *buffer, ULONG capacity, ULONG *writtenOut)
{
    ULONG fixed = (ULONG)offsetof(FILE_NAME_INFORMATION, FileName);
    if (capacity < fixed)
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    ULONG nameCapacity = capacity - fixed;
    WCHAR inlineName[260];
    WCHAR *staging = inlineName;
    ULONG stagingBytes = sizeof(inlineName);
    if (nameCapacity < stagingBytes)
    {
        stagingBytes = nameCapacity;
    }
    ULONG nameBytes = 0;
    NTSTATUS status = file->device->ops->QueryName(file, staging, stagingBytes, &nameBytes);
    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW)
    {
        return status;
    }
    /* A name longer than the local AND than what the local could hold for the
     * caller: re-ask into a pool buffer, so the bytes handed back are the
     * caller's capacity worth of the REAL name. */
    WCHAR *pooled = 0;
    if (nameBytes > stagingBytes && nameCapacity > stagingBytes)
    {
        ULONG wanted = nameBytes < nameCapacity ? nameBytes : nameCapacity;
        pooled = MiAllocatePool(wanted);
        if (pooled == 0)
        {
            return STATUS_NO_MEMORY;
        }
        staging = pooled;
        stagingBytes = wanted;
        status = file->device->ops->QueryName(file, staging, stagingBytes, &nameBytes);
        if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW)
        {
            MiFreePool(pooled);
            return status;
        }
    }

    ULONG copy = nameBytes <= stagingBytes ? nameBytes : stagingBytes;
    ULONG header = nameBytes; /* FileNameLength always reports the FULL name */
    memcpy((char *)buffer + offsetof(FILE_NAME_INFORMATION, FileNameLength), &header,
           sizeof(header));
    memcpy((char *)buffer + fixed, staging, copy);
    if (pooled != 0)
    {
        MiFreePool(pooled);
    }
    *writtenOut = fixed + copy;
    return nameBytes <= nameCapacity ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;
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
    case FileInternalInformation:
        needed = sizeof(FILE_INTERNAL_INFORMATION);
        break;
    case FileIdInformation:
        needed = sizeof(FILE_ID_INFORMATION);
        break;
    case FileEndOfFileInformation:
        needed = sizeof(FILE_END_OF_FILE_INFORMATION);
        break;
    case FileNameInformation:
        needed = (ULONG)offsetof(FILE_NAME_INFORMATION, FileName);
        break;
    case FileAllInformation:
        needed = (ULONG)offsetof(FILE_ALL_INFORMATION, NameInformation.FileName);
        break;
    case FilePipeInformation:
        needed = sizeof(FILE_PIPE_INFORMATION);
        break;
    case FilePipeLocalInformation:
        needed = sizeof(FILE_PIPE_LOCAL_INFORMATION);
        break;
    case FileIoCompletionNotificationInformation:
        needed = sizeof(FILE_IO_COMPLETION_NOTIFICATION_INFORMATION);
        break;
    case FileNetworkOpenInformation:
        needed = sizeof(FILE_NETWORK_OPEN_INFORMATION); /* CUI-5 */
        break;
    case FileModeInformation:
        needed = sizeof(FILE_MODE_INFORMATION); /* CUI-8 */
        break;
    case FileAttributeTagInformation:
        needed = sizeof(FILE_ATTRIBUTE_TAG_INFORMATION); /* CUI-5 */
        break;
    case FileStreamInformation:
        needed = 0; /* refused below with the handle validated first */
        break;
    default:
        /* An unbuilt class refuses loudly (Art. 12). The pinned Wine answers
         * STATUS_NOT_IMPLEMENTED here as well, which makes it unbuilt too —
         * not a contract, so no test pins it. The class goes on serial: the
         * dispatcher's armed-panic line names the syscall but not its
         * arguments, and "which class" is the whole content of this refusal
         * (one guiwtest boot was spent inferring it from the caller). */
        DbgPrint("NtQueryInformationFile: unbuilt info class %d\n", (int)informationClass);
        return STATUS_NOT_IMPLEMENTED;
    }
    if (length < needed)
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    /* The two pipe classes are the ones the oracle guards with an ACCESS
     * check on the HANDLE: a SYNCHRONIZE-only pipe end may not read them back
     * (wine server/named_pipe.c pipe_end_get_file_info, the
     * FilePipeInformation / FilePipeLocalInformation arms; pinned
     * sem_pipe/create_refusals.c). Expressed as the reference's required
     * access so Ob decides it at its one check site rather than a mask test
     * open-coded here (G10), and placed after the class-size switch because
     * the oracle answers INFO_LENGTH_MISMATCH ahead of ACCESS_DENIED —
     * measured, not assumed. */
    ACCESS_MASK required =
        (informationClass == FilePipeInformation || informationClass == FilePipeLocalInformation)
            ? FILE_READ_ATTRIBUTES
            : 0;
    PFILE_OBJECT file;
    status = IopReferenceFileByHandle(handle, required, &file);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* CUI-8: the mode is the FILE_OBJECT's own fact — no backend query, so
     * it answers before (and independently of) GetInfo, on every device.
     * The value is IopFileMode's, the same authority FileAllInformation
     * uses (docs/19 §7: FileModeInformation keeps reporting what the create
     * established; pinned sem_file/async_inline.c). */
    if (informationClass == FileModeInformation)
    {
        FILE_MODE_INFORMATION mode;
        mode.Mode = IopFileMode(file);
        memcpy(buffer, &mode, sizeof(mode)); /* caller-aligned buffer */
        iosb->Status = STATUS_SUCCESS;
        iosb->Information = sizeof(mode);
        ObDereferenceObject(file);
        return STATUS_SUCCESS;
    }

    /* The completion-notification modes are the FILE_OBJECT's own fact too,
     * so they answer before (and independently of) any backend query — the
     * same shape as FileModeInformation above. Pinned by
     * sem_pipe/ioctl_event.c, which also pins that the two ends of one pipe
     * carry their own word. */
    if (informationClass == FileIoCompletionNotificationInformation)
    {
        FILE_IO_COMPLETION_NOTIFICATION_INFORMATION notification;
        notification.Flags = file->completionFlags;
        memcpy(buffer, &notification, sizeof(notification)); /* caller-aligned buffer */
        iosb->Status = STATUS_SUCCESS;
        iosb->Information = sizeof(notification);
        ObDereferenceObject(file);
        return STATUS_SUCCESS;
    }

    /* M9: the pipe classes route to the pipe FS before any GetInfo — a
     * non-pipe file has no pipe view at all. */
    if (informationClass == FilePipeInformation || informationClass == FilePipeLocalInformation)
    {
        if (file->device->ops->QueryPipeInfo == 0)
        {
            ObDereferenceObject(file);
            return STATUS_INVALID_PARAMETER;
        }
        ULONG_PTR pipeInformation = 0;
        status = file->device->ops->QueryPipeInfo(file, informationClass, buffer, length,
                                                  &pipeInformation);
        if (NT_SUCCESS(status))
        {
            iosb->Status = status;
            iosb->Information = pipeInformation;
        }
        ObDereferenceObject(file);
        return status;
    }
    /* Backends without a per-file identity (devices) never touch fileId;
     * zeroing here keeps their FileInternalInformation answer 0 rather
     * than stack garbage. */
    IO_FILE_INFO raw;
    memset(&raw, 0, sizeof(raw));
    status = file->device->ops->GetInfo(file, &raw);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(file);
        return status;
    }
    /* Re-validate the caller's buffer and IOSB: GetInfo goes through the
     * volume gate since CUI-8, so it can park — and the fills below write
     * user memory directly on the strength of the entry probes, which a
     * sibling's unmap while parked makes stale (a fault here unwinds past
     * the file dereference — the rw.c re-probe rule; PR #95 review round
     * 2, F2). No park separates these probes from the fills. */
    status = KiProbeForWrite(buffer, length, 1);
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(iosb, sizeof(*iosb), sizeof(void *));
    }
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(file);
        return status;
    }

    ULONG_PTR information = needed;
    /* Every fixed-size class below is built HERE, in an aligned local, and
     * copied out as bytes at the end. `buffer` carries the caller's own
     * alignment (the probe asks for 1, as NtQueryDirectoryFile's does and for
     * the same reason): a WOW64 caller's i386 stack struct is 4-aligned, so a
     * `FILE_BASIC_INFORMATION *out = buffer; out->CreationTime = ...` is an
     * 8-byte store at a 4-mod-8 address — undefined in C and a UBSan #UD in
     * this build. The classes with variable tails (FileName*, FileAll) copy
     * their own bytes and set `staged` to 0 to say so. */
    union
    {
        FILE_BASIC_INFORMATION basic;
        FILE_STANDARD_INFORMATION standard;
        FILE_POSITION_INFORMATION position;
        FILE_INTERNAL_INFORMATION internal;
        FILE_ID_INFORMATION id;
        FILE_END_OF_FILE_INFORMATION endOfFile;
        FILE_NETWORK_OPEN_INFORMATION networkOpen;
        FILE_ATTRIBUTE_TAG_INFORMATION attributeTag;
    } staged;
    ULONG stagedBytes = 0;
    memset(&staged, 0, sizeof(staged));
    switch (informationClass)
    {
    case FileBasicInformation:
        IopFillBasic(&raw, &staged.basic);
        stagedBytes = sizeof(staged.basic);
        break;
    case FileStandardInformation:
        IopFillStandard(&raw, file->fcb, &staged.standard);
        stagedBytes = sizeof(staged.standard);
        break;
    case FilePositionInformation:
        staged.position.CurrentByteOffset = file->currentByteOffset;
        stagedBytes = sizeof(staged.position);
        break;
    case FileInternalInformation:
    {
        /* A backend without a per-file identity (devices, pipes; also the
         * FAT root, whose key is (0,0)) refuses loudly rather than serving
         * a fabricated constant id — the pinned Wine answers with a real
         * unix inode there, so 0 would be a silent divergence (Art. 12).
         * The refusal is unbuilt, not a contract: nothing pins it, and the
         * dispatcher's armed panic convicts a ring-3 caller that reaches it
         * — which is how the missing identity gets built rather than
         * tolerated. */
        if (raw.fileId == 0)
        {
            DbgPrint("NtQueryInformationFile: FileInternalInformation on a backing with no "
                     "file identity\n");
            ObDereferenceObject(file);
            return STATUS_NOT_IMPLEMENTED;
        }
        staged.internal.IndexNumber.QuadPart = (LONGLONG)raw.fileId;
        stagedBytes = sizeof(staged.internal);
        break;
    }
    case FileIdInformation:
    {
        /* The join of the two identities the two classes above and
         * FileFsVolumeInformation already serve — never a third source for
         * either (Art. 11): the id is raw.fileId, exactly as
         * FileInternalInformation reports it, and the serial comes from the
         * device's own QueryVolumeInfo, exactly as FileFsVolumeInformation
         * reports it. The pinned Wine builds it the same way
         * (dlls/ntdll/unix/file.c FileIdInformation: st_ino for the id,
         * the mount manager's serial).
         *
         * A backing with no per-file identity refuses here for the same
         * reason FileInternalInformation does, and loudly. */
        if (raw.fileId == 0 || file->device->ops->QueryVolumeInfo == 0)
        {
            DbgPrint("NtQueryInformationFile: FileIdInformation on a backing with no "
                     "file identity or no volume\n");
            ObDereferenceObject(file);
            return STATUS_NOT_IMPLEMENTED;
        }
        IO_VOLUME_INFO facts;
        status = file->device->ops->QueryVolumeInfo(file->device, &facts);
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(file);
            return status;
        }
        /* QueryVolumeInfo goes through the volume gate, so it can park —
         * re-probe before writing, the same rule the entry probes follow. */
        status = KiProbeForWrite(buffer, length, 1);
        if (NT_SUCCESS(status))
        {
            status = KiProbeForWrite(iosb, sizeof(*iosb), sizeof(void *));
        }
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(file);
            return status;
        }
        staged.id.VolumeSerialNumber = facts.serialNumber;
        /* The staged copy is already zeroed, which is what makes the upper
         * eight bytes of the 128-bit id WRITTEN rather than left as the
         * caller's bytes — ntdll:file's test_file_id_information poisons the
         * buffer with 0x11 and checks the poison is gone. */
        uint64_t low = raw.fileId;
        memcpy(&staged.id.FileId, &low, sizeof(low));
        stagedBytes = sizeof(staged.id);
        break;
    }
    case FileEndOfFileInformation:
    {
        /* The query side of the set-EOF class: the same size
         * FileStandardInformation reports, which is how the pinned Wine
         * answers it (dlls/ntdll/unix/file.c fills it from the same fstat).
         * ntdll's actctx.c asks it of every manifest file it maps. */
        staged.endOfFile.EndOfFile.QuadPart = (LONGLONG)raw.endOfFile;
        stagedBytes = sizeof(staged.endOfFile);
        break;
    }
    case FileNetworkOpenInformation:
    {
        /* CUI-5: the by-handle sibling of NtQueryFullAttributesFile — the
         * same times/sizes/attributes facts (pinned Wine fill_file_info;
         * sem_file/info_classes holds it to the basic/standard answers). */
        staged.networkOpen.CreationTime = raw.creationTime;
        staged.networkOpen.LastAccessTime = raw.lastAccessTime;
        staged.networkOpen.LastWriteTime = raw.lastWriteTime;
        staged.networkOpen.ChangeTime = raw.lastWriteTime;
        staged.networkOpen.AllocationSize.QuadPart = (LONGLONG)raw.allocationSize;
        staged.networkOpen.EndOfFile.QuadPart = (LONGLONG)raw.endOfFile;
        staged.networkOpen.FileAttributes = raw.fileAttributes;
        stagedBytes = sizeof(staged.networkOpen);
        break;
    }
    case FileAttributeTagInformation:
    {
        /* CUI-5: GetFileInformationByHandleEx(FileAttributeTagInfo) and
         * GetVolumePathNameW's reparse-point walk. No reparse points exist
         * on FAT; the pinned Wine answers tag 0 for a plain file too. */
        staged.attributeTag.FileAttributes = raw.fileAttributes;
        staged.attributeTag.ReparseTag = 0;
        stagedBytes = sizeof(staged.attributeTag);
        break;
    }
    case FileStreamInformation:
        /* CUI-5: FAT has no alternate data streams, and NT's own FAT driver
         * refuses the class with STATUS_INVALID_PARAMETER
         * (microsoft/Windows-driver-samples filesys/fastfat/fileinfo.c
         * FatCommonQueryInformation — FileStreamInformation is not in the
         * case list; the default arm refuses). The pinned Wine has no arm
         * at all, so the pin is beyond_oracle (sem_file/info_classes.c). */
        status = STATUS_INVALID_PARAMETER;
        break;
    case FileNameInformation:
    {
        ULONG written = 0;
        status = IopFillName(file, buffer, length, &written);
        information = written;
        break;
    }
    case FileAllInformation:
    {
        /* The five leading classes in one struct, staged for the same reason
         * as each of them on its own, then the name behind them. */
        FILE_ALL_INFORMATION all;
        ULONG nameOffset = (ULONG)offsetof(FILE_ALL_INFORMATION, NameInformation);
        memset(&all, 0, nameOffset);
        IopFillBasic(&raw, &all.BasicInformation);
        IopFillStandard(&raw, file->fcb, &all.StandardInformation);
        all.InternalInformation.IndexNumber.QuadPart = (LONGLONG)raw.fileId;
        all.PositionInformation.CurrentByteOffset = file->currentByteOffset;
        all.AccessInformation.AccessFlags = file->grantedAccess;
        all.ModeInformation.Mode = IopFileMode(file);
        memcpy(buffer, &all, nameOffset);
        ULONG written = 0;
        status = IopFillName(file, (char *)buffer + nameOffset, length - nameOffset, &written);
        information = nameOffset + written;
        break;
    }
    default:
        break;
    }

    if (stagedBytes != 0)
    {
        memcpy(buffer, &staged, stagedBytes);
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
    /* Wine gates set-EOF on the unix fd being writable, which any of the
     * write-ish access bits produces (server/file.h FILE_UNIX_WRITE_ACCESS =
     * WRITE_DATA | APPEND_DATA | WRITE_ATTRIBUTES | WRITE_EA; fd.c rw_mode) —
     * including the implicit FILE_WRITE_ATTRIBUTES an overwrite disposition
     * granted (kernel/io/file.c). */
    if (file->grantedAccess &
        (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA))
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

/* FileRenameInformation(Ex) / FileLinkInformation (CUI-5): resolve the
 * caller's target name to (device, volume-relative path) and drive the FS
 * rename op. The contract is the pinned Wine's (dlls/ntdll/unix/file.c
 * NtSetInformationFile rename/link cases + server/fd.c set_fd_name), pinned
 * by sem_file/rename.c: kernelbase's MoveFileWithProgressW sends
 * offsetof(FileName)+FileNameLength bytes with the union's bytes 1-3
 * uninitialized, so the non-Ex classes read only the BOOLEAN arm; a buffer
 * shorter than the full struct is STATUS_INVALID_PARAMETER_3; unknown flag
 * bits are ignored (the oracle FIXMEs and continues); a target on another
 * device is STATUS_NOT_SAME_DEVICE (MoveFileExW keys its copy+delete
 * fallback on it). The ORDER is wine's too (fuzzer-found, pinned): the
 * target path resolves before the handle is ever referenced, so a bad
 * handle with a bad target reports the path error. */
static NTSTATUS IopSetRenameInformation(HANDLE handle, const void *buffer, ULONG length,
                                        FILE_INFORMATION_CLASS informationClass)
{
    if (length < sizeof(FILE_RENAME_INFORMATION))
    {
        return STATUS_INVALID_PARAMETER_3;
    }
    PFILE_RENAME_INFORMATION info = MiAllocatePool(length);
    if (info == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memcpy(info, buffer, length);

    NTSTATUS status;
    PFILE_OBJECT file = 0;
    PFILE_OBJECT relativeTo = 0;
    PIO_DEVICE parsedDevice = 0;
    PWSTR reparseBuffer = 0;

    if (info->FileNameLength > length - offsetof(FILE_RENAME_INFORMATION, FileName) ||
        info->FileNameLength > 0xFFFE || info->FileNameLength % sizeof(WCHAR) != 0)
    {
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }
    UNICODE_STRING name;
    name.Buffer = info->FileName;
    name.Length = (USHORT)info->FileNameLength;
    name.MaximumLength = name.Length;
    if (name.Length == 0)
    {
        status = STATUS_OBJECT_PATH_SYNTAX_BAD;
        goto out;
    }

    ULONG flags;
    if (informationClass == FileRenameInformationEx)
    {
        flags = info->Flags;
    }
    else
    {
        /* The BOOLEAN arm only — the Flags arm's upper bytes are heap
         * garbage on every real kernelbase call. */
        flags = info->ReplaceIfExists ? FILE_RENAME_REPLACE_IF_EXISTS : 0;
    }

    /* Wine resolves the caller's whole target path before referencing the
     * rename handle (get_nt_and_unix_names with FILE_OPEN_IF: an existing
     * target or a merely missing leaf passes; a dead intermediate directory
     * is the answer). Fuzzer-found; pinned by sem_file/rename.c. */
    {
        OBJECT_ATTRIBUTES probeAttributes;
        probeAttributes.Length = sizeof(probeAttributes);
        probeAttributes.RootDirectory = info->RootDirectory;
        probeAttributes.ObjectName = &name;
        probeAttributes.Attributes = OBJ_CASE_INSENSITIVE;
        probeAttributes.SecurityDescriptor = 0;
        probeAttributes.SecurityQualityOfService = 0;
        status = IopProbeTargetPath(&probeAttributes);
        if (!NT_SUCCESS(status))
        {
            goto out;
        }
    }

    /* Resolve the target to a device + volume-relative path, mirroring
     * IopCreateFile's two forms. */
    PIO_DEVICE targetDevice;
    UNICODE_STRING fsPath;
    if (info->RootDirectory != 0)
    {
        status = IopReferenceFileByHandle(info->RootDirectory, 0, &relativeTo);
        if (!NT_SUCCESS(status))
        {
            goto out;
        }
        fsPath = name;
        if (fsPath.Buffer[0] == '\\')
        {
            status = STATUS_OBJECT_PATH_SYNTAX_BAD;
            goto out;
        }
        targetDevice = relativeTo->device;
    }
    else
    {
        OBJECT_ATTRIBUTES attributes;
        attributes.Length = sizeof(attributes);
        attributes.RootDirectory = 0;
        attributes.ObjectName = &name;
        attributes.Attributes = OBJ_CASE_INSENSITIVE;
        attributes.SecurityDescriptor = 0;
        attributes.SecurityQualityOfService = 0;
        /* Kernel-built attributes over a pool copy: skip the user probes
         * (the NtQueryAttributesFile internal-open pattern). */
        PKTHREAD thread = KeGetCurrentThread();
        KPROCESSOR_MODE saved = thread->previousMode;
        thread->previousMode = KernelMode;
        PVOID deviceBody;
        status = ObpLookupParseObject(&attributes, &IoDeviceType, 0, &deviceBody, &fsPath,
                                      &reparseBuffer);
        thread->previousMode = saved;
        if (!NT_SUCCESS(status))
        {
            goto out;
        }
        parsedDevice = deviceBody;
        targetDevice = parsedDevice;
    }

    /* Only now the handle (no specific access — server/fd.c
     * set_fd_name_info takes it with 0). */
    status = IopReferenceFileByHandle(handle, 0, &file);
    if (!NT_SUCCESS(status))
    {
        goto out;
    }
    if (targetDevice != file->device)
    {
        status = STATUS_NOT_SAME_DEVICE;
        goto out;
    }
    if (informationClass == FileLinkInformation)
    {
        /* FAT has no hard links (MS "Hard Links and Junctions": NTFS only;
         * kernelbase surfaces ERROR_INVALID_FUNCTION). Pinned beyond_oracle
         * in sem_file/rename.c — the oracle's ext4 backing store can link,
         * so it cannot answer for a FAT volume. */
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto out;
    }
    status = file->device->ops->Rename != 0
                 ? file->device->ops->Rename(file, relativeTo, &fsPath, flags)
                 : STATUS_INVALID_DEVICE_REQUEST;

out:
    if (file != 0)
    {
        ObDereferenceObject(file);
    }
    if (relativeTo != 0)
    {
        ObDereferenceObject(relativeTo);
    }
    if (parsedDevice != 0)
    {
        ObDereferenceObject(parsedDevice);
    }
    if (reparseBuffer != 0)
    {
        MiFreePool(reparseBuffer);
    }
    MiFreePool(info);
    return status;
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

    /* CUI-5 rename/link dispatch before the common handle reference: the
     * pinned Wine resolves the target path first and only the server call
     * touches the handle (fuzzer-found order, pinned by rename.c). */
    if (informationClass == FileRenameInformation || informationClass == FileRenameInformationEx ||
        informationClass == FileLinkInformation)
    {
        status = IopSetRenameInformation(handle, buffer, length, informationClass);
        if (NT_SUCCESS(status))
        {
            iosb->Status = status;
            iosb->Information = 0;
        }
        return status;
    }

    ULONG needed;
    ACCESS_MASK requiredAccess;
    switch (informationClass)
    {
    case FileBasicInformation:
        needed = sizeof(FILE_BASIC_INFORMATION);
        /* NO access requirement, and deliberately so — docs/03 "the set-basic
         * access check". Documented NT wants FILE_WRITE_ATTRIBUTES, but the
         * caller that matters opens without it: kernelbase's
         * SetFileAttributesW (dlls/kernelbase/file.c) does NtOpenFile with
         * SYNCHRONIZE and nothing else, then sets this class through that
         * handle. Requiring the bit refused every SetFileAttributes call in
         * the userland above — which is how msvcrt:file's read-only
         * "_creat.tst" outlived its own cleanup and took the three blocks
         * after it down with it. The pinned oracle grants it; pinned by
         * tests/ntapi/sem_file/readonly_attr.c step 5. */
        requiredAccess = 0;
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
    case FileIoCompletionNotificationInformation:
        needed = sizeof(FILE_IO_COMPLETION_NOTIFICATION_INFORMATION);
        requiredAccess = 0;
        break;
    case FileCompletionInformation:
        /* Binding a handle to an I/O completion port —
         * CreateIoCompletionPort(file, port, key, 0) and
         * BindIoCompletionCallback. A short buffer here is
         * STATUS_INVALID_PARAMETER_3, NOT the INFO_LENGTH_MISMATCH every
         * other class answers: the pinned oracle checks the length in ntdll
         * (dlls/ntdll/unix/file.c:5302) and the server never sees the call,
         * so the two mistakes carry different statuses. With the unixlib
         * seam replaced by a syscall on proskrnl, this kernel owns both.
         * Handled below rather than through `needed`, which drives the
         * shared INFO_LENGTH_MISMATCH path. */
        needed = 0;
        requiredAccess = 0;
        break;
    case FilePipeInformation:
        /* M9: read/completion mode. Both of this class's argument checks run
         * ABOVE the handle and neither is the shared INFO_LENGTH_MISMATCH, so
         * `needed` is 0 and the block below owns them — see it for why. */
        needed = 0;
        requiredAccess = 0;
        break;
    default:
        /* Names itself, as the query direction above does and for the same
         * reason: the dispatcher's armed-panic line gives the syscall but not
         * its arguments, and "which class" is the whole content of this
         * refusal. Four winetest pairs stopped here at once (kernel32:file,
         * kernel32:pipe, kernel32:sync, ntdll:threadpool) and the logs could
         * not tell them apart. */
        DbgPrint("NtSetInformationFile: unbuilt info class %d\n", (int)informationClass);
        return STATUS_NOT_IMPLEMENTED;
    }
    if (length < needed)
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    /* FilePipeInformation's two argument checks live in the pinned oracle's
     * NTDLL (dlls/ntdll/unix/file.c NtSetInformationFile, case
     * FilePipeInformation), above the set_named_pipe_info server call — so
     * above the handle entirely, which is measurable and is measured
     * (sem_pipe/pipe_mode_set.c: an out-of-range value on a handle that names
     * no pipe reports the value, not the handle).
     *
     * Neither is the shared refusal it looks like:
     *
     *   - a SHORT buffer is STATUS_INVALID_PARAMETER_3, not the
     *     INFO_LENGTH_MISMATCH the QUERY direction gives for the very same
     *     class. The query side is table-driven (the oracle's info_sizes[]);
     *     this side is hand-written per class, and the two disagree. Same
     *     shape as FileCompletionInformation below;
     *   - the value bound is `(CompletionMode | ReadMode) & ~1`, i.e. every
     *     bit above the low one is out of range — not "greater than 1".
     *
     * Captured ONCE here and handed to the class arm below, so the values the
     * range check accepted are the values the device stores: read twice, a
     * caller could pass the check and then have the second read see an
     * out-of-range word. */
    FILE_PIPE_INFORMATION pipeInfo;
    if (informationClass == FilePipeInformation)
    {
        if (length < sizeof(pipeInfo))
        {
            return STATUS_INVALID_PARAMETER_3;
        }
        memcpy(&pipeInfo, buffer, sizeof(pipeInfo)); /* caller-aligned buffer */
        if (((pipeInfo.CompletionMode | pipeInfo.ReadMode) & ~1u) != 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
    }

    PFILE_OBJECT file;
    status = IopReferenceFileByHandle(handle, requiredAccess, &file);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    switch (informationClass)
    {
    case FileIoCompletionNotificationInformation:
    {
        /* SetFileCompletionNotificationModes. The bits ACCUMULATE — this ORs
         * into the handle's word rather than replacing it, which is measured
         * (sem_pipe/ioctl_event.c: setting SKIP_SET_EVENT_ON_HANDLE after
         * SKIP_COMPLETION_PORT_ON_SUCCESS reads back as both) and is also
         * what wineserver's set_fd_completion_mode does. There is no way to
         * clear a mode once set, and the Win32 surface has no paired clear.
         *
         * FILE_SKIP_SET_USER_EVENT_ON_FAST_IO is accepted and NOT honoured,
         * exactly as the oracle accepts it with a FIXME
         * (dlls/ntdll/unix/file.c). That is not a fabricated answer: the bit
         * is stored and reported back truthfully, and the behaviour it would
         * select — suppressing the caller-supplied event on a fast-path
         * completion — has no fast path to suppress here, because every
         * completion this kernel makes goes through IopCompleteRequest.
         *
         * FILE_SKIP_SET_EVENT_ON_HANDLE, by contrast, IS honoured, and its
         * one subtlety is the ORDER below: the oracle clears the handle
         * BEFORE recording the bit (server/fd.c set_fd_completion_mode),
         * and its `set_fd_signaled` is a no-op once the bit is set — so the
         * clear must happen while the flag is still absent, and the handle
         * is frozen unsignalled from then on. Written the other way round
         * the clear does nothing and the handle stays signalled forever,
         * which is the exact inverse of the contract. */
        if (file->synchronousIo)
        {
            /* The modes are an OVERLAPPED-handle concept and a synchronous
             * one is REFUSED, not quietly accepted (wineserver's
             * set_fd_completion_mode: `if (!is_fd_overlapped(fd))
             * STATUS_INVALID_PARAMETER`). */
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        FILE_IO_COMPLETION_NOTIFICATION_INFORMATION modes;
        memcpy(&modes, buffer, sizeof(modes));
        if ((modes.Flags & FILE_SKIP_SET_EVENT_ON_HANDLE) != 0)
        {
            /* "Take the handle unsignalled" — the same transition a park
             * makes, through the same authority, which is why it borrows
             * that name. Called while the bit is still absent because the
             * guard inside it makes the call a no-op once the bit is set. */
            IopMarkRequestOutstanding(file);
        }
        /* Masked to the bits the contract defines, as the oracle masks:
         * without this a caller could park arbitrary bits in the handle's
         * word and read them back out, which is a fact the boundary never
         * promised to keep. */
        file->completionFlags |= modes.Flags & (ULONG)(FILE_SKIP_COMPLETION_PORT_ON_SUCCESS |
                                                       FILE_SKIP_SET_EVENT_ON_HANDLE |
                                                       FILE_SKIP_SET_USER_EVENT_ON_FAST_IO);
        status = STATUS_SUCCESS;
        break;
    }
    case FileCompletionInformation:
    {
        /* The oracle's rules are its server's, in four lines
         * (third_party/wine server/fd.c set_completion_info): an
         * OVERLAPPED fd that is not already bound takes the port and key;
         * anything else is a flat STATUS_INVALID_PARAMETER. So a
         * synchronous handle and a second bind are refused identically, and
         * neither is distinguishable from the other by status alone.
         * Pinned by tests/ntapi/sem_port/file_completion.c. */
        if (length < sizeof(FILE_COMPLETION_INFORMATION))
        {
            status = STATUS_INVALID_PARAMETER_3;
            break;
        }
        if (file->synchronousIo || file->completionPort != 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        FILE_COMPLETION_INFORMATION completion;
        memcpy(&completion, buffer, sizeof(completion));
        PVOID portBody;
        status = ObReferenceObjectByHandle(completion.CompletionPort, IO_COMPLETION_MODIFY_STATE,
                                           &IoCompletionType, ExGetPreviousMode(), &portBody, 0);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        file->completionPort = portBody; /* reference kept by the file object */
        file->completionKey = completion.CompletionKey;
        status = STATUS_SUCCESS;
        break;
    }
    case FileBasicInformation:
    {
        FILE_BASIC_INFORMATION basic;
        memcpy(&basic, buffer, sizeof(basic));
        status = file->device->ops->SetBasic != 0 ? file->device->ops->SetBasic(file, &basic)
                                                  : STATUS_INVALID_PARAMETER; /* M9 streams */
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
        if (file->device->ops->SetEndOfFile == 0)
        {
            status = STATUS_INVALID_PARAMETER; /* M9 streams have no EOF */
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
        if (file->device->ops->SetEndOfFile == 0)
        {
            status = STATUS_INVALID_PARAMETER; /* M9 streams */
            break;
        }
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
        status = file->device->ops->SetDisposition != 0
                     ? file->device->ops->SetDisposition(file, disposition.DoDeleteFile)
                     : STATUS_INVALID_PARAMETER; /* M9 streams */
        break;
    }
    case FilePipeInformation:
    {
        /* M9: per-end read/completion mode (sem_pipe pins the switch). The
         * values were captured and range-checked above the handle. */
        if (file->device->ops->SetPipeInfo == 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = file->device->ops->SetPipeInfo(file, handle, &pipeInfo);
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

/* Case-insensitive wildcard match: '*' any run, '?' one unit, plus the
 * DOS-special forms of FsRtlIsNameInExpression (MS docs) — DOS_STAR '<'
 * (any run stopping at or before the name's final '.'), DOS_QM '>' (one
 * unit, collapsing at a '.' or the end), DOS_DOT '"' (a '.' or nothing at
 * the end). Wine's PE stack emits these on EVERY wildcard FindFirstFile:
 * kernelbase fixup_mask (third_party/wine/dlls/kernelbase/file.c) rewrites
 * the DOS glob before NtQueryDirectoryFile — cmd.exe's bare-name PATH
 * search sends winemine"* for `winemine`. Pinned differentially by
 * tests/ntapi/sem_file/query_dir.c. */
static BOOLEAN IopMatchMask(const WCHAR *name, ULONG nameUnits, const WCHAR *mask, ULONG maskUnits)
{
    while (maskUnits != 0)
    {
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
        if (m == '<')
        {
            /* DOS_STAR. Microsoft's FsRtlIsNameInExpression documentation:
             * "matches zero or more characters until encountering and
             * matching the final . in the name". Both halves of that
             * sentence are load-bearing, and the winetest truth table
             * (ntdll:directory mask_tests) decides between the readings:
             *
             *   "until ... the final ." — the rest of the mask may resume
             *   at the start of ANY dot-delimited segment, not only at or
             *   before the last dot. This is what lets `<tmp` match
             *   `n.tmp` and `ea.tmp.tmp`; the old code stopped at the final
             *   dot and matched neither.
             *
             *   "and matching" — once the final dot is passed DOS_STAR is
             *   SPENT, so the mask resumes at that last segment's start and
             *   never partway inside it: `<a` matches `ea` but must not
             *   match `.aa`.
             *
             * Derived from that table (third-party Windows-verified spec,
             * docs/08) and the MS documentation above — not translated from
             * the oracle's matcher, which is off-limits as kernel reference
             * material (docs/11). Pinned by
             * tests/ntapi/sem_file/dir_mask_dosstar.c. */
            const WCHAR *rest = mask + 1;
            ULONG restUnits = maskUnits - 1;
            BOOLEAN sawDot = FALSE;
            while (nameUnits != 0)
            {
                ULONG segment = 0;
                while (segment < nameUnits && name[segment] != '.')
                {
                    segment++;
                }
                if (segment == nameUnits)
                {
                    if (sawDot)
                    {
                        /* The tail past the final dot: one resume point,
                         * at its start. */
                        return restUnits != 0 && IopMatchMask(name, nameUnits, rest, restUnits);
                    }
                }
                else
                {
                    sawDot = TRUE;
                    segment++; /* the dot belongs to the segment it ends */
                }
                for (ULONG skip = 0; skip < segment; skip++)
                {
                    if (restUnits != 0 &&
                        IopMatchMask(name + skip, nameUnits - skip, rest, restUnits))
                    {
                        return TRUE;
                    }
                }
                name += segment;
                nameUnits -= segment;
            }
            mask = rest;
            maskUnits = restUnits;
            continue;
        }
        if (nameUnits == 0)
        {
            /* Name exhausted: a remaining run of the zero-width-capable
             * forms still matches ('"' at the end, '>' runs, ...). */
            if (m == '>' || m == '"')
            {
                mask++;
                maskUnits--;
                continue;
            }
            return FALSE;
        }
        if (m == '>')
        {
            mask++;
            maskUnits--;
            if (name[0] == '.')
            {
                /* Zero-width at a dot: the whole contiguous DOS_QM run
                 * collapses; a mask ENDING in the run consumes the dot. */
                while (maskUnits != 0 && mask[0] == '>')
                {
                    mask++;
                    maskUnits--;
                }
                if (maskUnits == 0)
                {
                    name++;
                    nameUnits--;
                }
            }
            else
            {
                name++;
                nameUnits--;
            }
            continue;
        }
        if (m != '?')
        {
            WCHAR want = (m == '"') ? (WCHAR)'.' : m;
            if (RtlUpcaseUnicodeChar(want) != RtlUpcaseUnicodeChar(name[0]))
            {
                return FALSE;
            }
        }
        name++;
        nameUnits--;
        mask++;
        maskUnits--;
    }
    return nameUnits == 0;
}

/* The mask is applied to ".." as if it were "." (the pinned oracle's
 * parent-directory special case: ntdll match_filename) — so *"* and < both
 * list it. */
static BOOLEAN IopMatchEntryName(const WCHAR *name, ULONG nameUnits, const WCHAR *mask,
                                 ULONG maskUnits)
{
    if (nameUnits == 2 && name[0] == '.' && name[1] == '.')
    {
        nameUnits = 1;
    }
    return IopMatchMask(name, nameUnits, mask, maskUnits);
}

/* The ShortName the Both-shaped classes report, and the ONE place that
 * decides whether to report one at all (Art. 11 — both classes call this,
 * so they cannot disagree about an entry).
 *
 * The rule is not "whatever the volume stored". A short name is reported
 * only when the entry's LONG name is not already a legal 8.3 name, which is
 * how the oracle behaves (measured: it reports nothing for `lower.txt`) and
 * is a different question from whether the FS chose to store a short entry.
 * FAT stores one for every name it cannot hold verbatim — `lower.txt`
 * included, since a bare 8.3 entry cannot carry lower case — so a backend's
 * having a short name says nothing about whether the boundary shows it.
 * RtlIsNameLegalDOS8Dot3 is the single authority for the question
 * (kernel/lib/rtl.c says why it is not fs/fat32's FatBuildExact83).
 *
 * Pinned by tests/ntapi/sem_file/short_names.c. */
static void IopFillShortName(const IO_DIR_ENTRY *entry, WCHAR *shortName, CHAR *shortNameLength)
{
    UNICODE_STRING longName;
    longName.Buffer = (PWSTR)(uintptr_t)entry->name;
    longName.Length = entry->nameLength;
    longName.MaximumLength = entry->nameLength;
    if (entry->shortNameLength == 0 || RtlIsNameLegalDOS8Dot3(&longName, 0, 0))
    {
        *shortNameLength = 0;
        return;
    }
    memcpy(shortName, entry->shortName, entry->shortNameLength);
    *shortNameLength = (CHAR)entry->shortNameLength;
}

/* Does this entry match the mask? The LONG name decides first, and the 8.3
 * SHORT name is a second chance — NT matches both, which is why
 * ntdll:directory's truth table has cells no long-name matcher can satisfy
 * (masks `<`, `<"`, `<""` against `.a`, `..a`, `.aa`: the short name of a
 * dot-leading name carries no dot, so DOS_STAR reaches it).
 *
 * A short-name hit still returns the entry under its LONG name — the fill
 * path never consults the mask, so this is automatic, and it is what
 * GetShortPathName's caller depends on.
 *
 * The short name used here is the one the FS stored, NOT the one the
 * boundary reports: IopFillShortName suppresses the report for a name that
 * is already 8.3-legal, and such an entry matches by its long name anyway,
 * so the two rules never disagree about membership.
 *
 * Pinned by tests/ntapi/sem_file/short_names.c. */
static BOOLEAN IopEntryMatchesMask(const IO_DIR_ENTRY *entry, const UNICODE_STRING *mask)
{
    ULONG maskUnits = mask->Length / sizeof(WCHAR);
    if (IopMatchEntryName(entry->name, entry->nameLength / sizeof(WCHAR), mask->Buffer, maskUnits))
    {
        return TRUE;
    }
    return entry->shortNameLength != 0 &&
           IopMatchEntryName(entry->shortName, entry->shortNameLength / sizeof(WCHAR), mask->Buffer,
                             maskUnits);
}

/* Order the snapshot the way NT returns it: "." first, ".." second, then
 * case-insensitive ascending.
 *
 * The comparator is RtlCompareUnicodeString(..., TRUE) — the SAME authority
 * Ob name resolution, FAT lookup and Cm's subkey enumeration order already
 * fold through (Art. 11), and structurally the same fold ntdll's own
 * RtlCompareUnicodeString applies in the test that checks this
 * (ntdll:directory directory.c:322). Fold direction matters and is not
 * symmetric: upcasing puts `_x` AFTER `Bx` while lowercasing puts it
 * before, and `_`-prefixed names are common. RtlUpcaseUnicodeChar upcases.
 *
 * A case-insensitive tie falls back to a case-SENSITIVE compare so the
 * order is total (the oracle's own tiebreak). Two byte-identical names can
 * only come from a corrupt volume; both are emitted, in snapshot order.
 * Dropping one would lose a directory entry silently, which is worse than
 * reporting an unsorted pair — and no assert here, because a corrupt volume
 * read from ring 3 must not halt the machine.
 *
 * The dot entries are skipped POSITIONALLY, not searched for: FAT stores
 * them as a subdirectory's first two entries and the oracle likewise
 * prepends them, so if they are present they are already at 0 and 1. They
 * are mask-filtered like any other entry on both runners, so under a mask
 * that excludes them the skip simply does not fire — and the FAT root has
 * none at all.
 *
 * Insertion sort over the permutation, not the records: comparisons are
 * string compares but moves are 4 bytes, where sorting 600-byte entries in
 * place would shuffle megabytes for nothing. n is a directory's entry
 * count, so the quadratic term is not worth avoiding (Art. 3). */
static int IopCompareEntries(const IO_DIR_ENTRY *a, const IO_DIR_ENTRY *b)
{
    UNICODE_STRING left, right;
    left.Buffer = (PWSTR)(uintptr_t)a->name;
    left.Length = a->nameLength;
    left.MaximumLength = a->nameLength;
    right.Buffer = (PWSTR)(uintptr_t)b->name;
    right.Length = b->nameLength;
    right.MaximumLength = b->nameLength;
    LONG order = RtlCompareUnicodeString(&left, &right, TRUE);
    if (order != 0)
    {
        return order < 0 ? -1 : 1;
    }
    order = RtlCompareUnicodeString(&left, &right, FALSE);
    return order < 0 ? -1 : (order > 0 ? 1 : 0);
}

static BOOLEAN IopEntryIsDots(const IO_DIR_ENTRY *entry, ULONG units)
{
    if (entry->nameLength != units * sizeof(WCHAR))
    {
        return FALSE;
    }
    for (ULONG i = 0; i < units; i++)
    {
        if (entry->name[i] != '.')
        {
            return FALSE;
        }
    }
    return TRUE;
}

static void IopSortDirSnapshot(IO_DIR_ENTRY *entries, ULONG *order, ULONG count)
{
    ULONG first = 0;
    if (first < count && IopEntryIsDots(&entries[order[first]], 1))
    {
        first++;
    }
    if (first < count && IopEntryIsDots(&entries[order[first]], 2))
    {
        first++;
    }
    for (ULONG i = first + 1; i < count; i++)
    {
        ULONG value = order[i];
        ULONG j = i;
        while (j > first && IopCompareEntries(&entries[order[j - 1]], &entries[value]) > 0)
        {
            order[j] = order[j - 1];
            j--;
        }
        order[j] = value;
    }
}

/* Build the handle's enumeration snapshot: every entry the directory has
 * right now that the bound mask accepts, sorted the way NT returns them.
 *
 * This is the model the oracle uses (dlls/ntdll/unix/file.c
 * init_cached_dir_data) and the one the rest of this file already assumes —
 * the mask binds at scan start precisely because the snapshot is built
 * then. Until now the "snapshot" was conceptual and entries were read live;
 * making it literal is what allows a sort at all, since sorting needs the
 * whole set before the first entry can be emitted.
 *
 * Grown by doubling in ONE pass rather than counted first and then filled.
 * A count pass is separated from the fill pass by parks (the FAT volume
 * gate is taken and released per entry), so the two can disagree, and the
 * only ways out of that are to truncate — which is the silent-plausible
 * answer G12 forbids, since a caller cannot tell a truncated listing from a
 * short directory — or to reallocate anyway. There is deliberately NO CAP:
 * running out of pool is STATUS_INSUFFICIENT_RESOURCES, a status a caller
 * can act on.
 *
 * Pinned by tests/ntapi/sem_file/dir_sort.c. */
static NTSTATUS IopBuildDirSnapshot(PFILE_OBJECT file)
{
    IO_DIR_ENTRY *entries = 0;
    ULONG capacity = 0, count = 0;
    ULONG cursor = 0;
    NTSTATUS status = STATUS_SUCCESS;

    for (;;)
    {
        IO_DIR_ENTRY entry;
        entry.shortNameLength = 0;
        status = file->device->ops->ReadDirectory(file, &cursor, &entry);
        if (status == STATUS_NO_MORE_FILES)
        {
            status = STATUS_SUCCESS;
            break;
        }
        if (!NT_SUCCESS(status))
        {
            break;
        }
        if (file->dirMask.Buffer != 0 && !IopEntryMatchesMask(&entry, &file->dirMask))
        {
            continue;
        }
        if (count == capacity)
        {
            ULONG grown = capacity == 0 ? 64 : capacity * 2;
            IO_DIR_ENTRY *bigger = MiAllocatePool(grown * sizeof(IO_DIR_ENTRY));
            if (bigger == 0)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
            if (entries != 0)
            {
                memcpy(bigger, entries, count * sizeof(IO_DIR_ENTRY));
                MiFreePool(entries);
            }
            entries = bigger;
            capacity = grown;
        }
        entries[count++] = entry;
    }
    if (!NT_SUCCESS(status))
    {
        if (entries != 0)
        {
            MiFreePool(entries);
        }
        return status;
    }

    ULONG *order = 0;
    if (count != 0)
    {
        order = MiAllocatePool(count * sizeof(ULONG));
        if (order == 0)
        {
            MiFreePool(entries);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        for (ULONG i = 0; i < count; i++)
        {
            order[i] = i;
        }
        IopSortDirSnapshot(entries, order, count);
    }

    /* Allocated everything before releasing anything: a failed rebuild
     * leaves the handle's existing snapshot intact, the same order the mask
     * copy above follows. */
    if (file->dirSnapshot != 0)
    {
        MiFreePool(file->dirSnapshot);
    }
    if (file->dirOrder != 0)
    {
        MiFreePool(file->dirOrder);
    }
    file->dirSnapshot = entries;
    file->dirOrder = order;
    file->dirSnapshotCount = count;
    file->dirPosition = 0;
    return STATUS_SUCCESS;
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
    case FileIdBothDirectoryInformation: /* CUI-5 */
        return (ULONG)offsetof(FILE_ID_BOTH_DIRECTORY_INFORMATION, FileName);
    case FileIdFullDirectoryInformation:
        return (ULONG)offsetof(FILE_ID_FULL_DIRECTORY_INFORMATION, FileName);
    default:
        return 0;
    }
}

/* The smallest buffer this class will accept before it complains about the
 * LENGTH rather than about itself — and the two rules here are both a step
 * away from the obvious implementation, so both are pinned
 * (tests/ntapi/sem_file/dir_class_sizing.c).
 *
 * For an ENUMERATION class it is the fixed part plus ONE name character,
 * rounded up to the 8-byte entry alignment — not the fixed part alone. A
 * buffer that holds only the fixed part is still too small, and an
 * implementation that checks `length < fixedSize` reports
 * STATUS_BUFFER_OVERFLOW eight bytes early.
 *
 * Three classes are NOT enumeration classes and refuse with
 * STATUS_INVALID_INFO_CLASS — but only once the buffer is at least their
 * struct's size; below that they answer the LENGTH complaint like anyone
 * else. So "is this class supported" is decided AFTER "is this buffer big
 * enough", which is the reverse of how a refusal is normally written, and
 * it is what distinguishes a KNOWN-but-unsupported class from an unknown
 * one — an unknown class refuses immediately, at any size (the `0` below,
 * which the caller reads as "no length rule, refuse now"). */
static ULONG IopDirEntryMinimumLength(FILE_INFORMATION_CLASS informationClass)
{
    ULONG fixed = IopDirEntryFixedSize(informationClass);
    if (fixed != 0)
    {
        return (fixed + (ULONG)sizeof(WCHAR) + 7u) & ~7u;
    }
    switch (informationClass)
    {
    case FileObjectIdInformation:
        return (ULONG)sizeof(FILE_OBJECTID_INFORMATION);
    case FileQuotaInformation:
        return (ULONG)sizeof(FILE_QUOTA_INFORMATION);
    case FileReparsePointInformation:
        return (ULONG)sizeof(FILE_REPARSE_POINT_INFORMATION);
    default:
        return 0;
    }
}

/* No entry has been written to the buffer yet (NtQueryDirectoryFile's
 * previousOffset). */
#define IOP_NO_PREVIOUS_ENTRY 0xFFFFFFFFu

/* Serialize one IO_DIR_ENTRY at `out`, whose alignment is the CALLER's
 * business and not this code's.
 *
 * Entries are laid out on 8-byte boundaries RELATIVE TO THE BUFFER, which
 * invites the reading that the buffer itself is 8-aligned — it is not, and NT
 * imposes no such requirement (tests/ntapi/sem_file/dir_unaligned_buffer.c
 * pins buffer+1/+2/+4 answering exactly like buffer+0; the probe above asks
 * for alignment 1 for the same reason). The real caller that convicted this:
 * a WOW64 process's SxS lookup, which enumerates with i386's 4-byte-aligned
 * `char buffer[8192]` (third_party/wine dlls/ntdll/actctx.c
 * lookup_manifest_file) — every LARGE_INTEGER field then landed on a
 * 4-aligned address and the kernel took a UBSan #UD before the first WOW64
 * window could be painted.
 *
 * So the fields are staged in an ALIGNED LOCAL and the result is copied out
 * as bytes. `fixedSize` comes from the caller rather than being re-derived
 * here: IopDirEntryFixedSize is the one authority for a class's fixed part
 * (Art. 11), and the caller has already asked it. */
static void IopFillDirEntry(FILE_INFORMATION_CLASS informationClass, const IO_DIR_ENTRY *entry,
                            void *out, ULONG fixedSize, ULONG nameBytes)
{
    union
    {
        FILE_DIRECTORY_INFORMATION dir;
        FILE_FULL_DIRECTORY_INFORMATION full;
        FILE_BOTH_DIRECTORY_INFORMATION both;
        FILE_NAMES_INFORMATION names;
        FILE_ID_FULL_DIRECTORY_INFORMATION idFull;
        FILE_ID_BOTH_DIRECTORY_INFORMATION idBoth;
    } staged;

    switch (informationClass)
    {
    case FileDirectoryInformation:
    {
        FILE_DIRECTORY_INFORMATION *d = &staged.dir;
        memset(d, 0, offsetof(FILE_DIRECTORY_INFORMATION, FileName));
        d->CreationTime = entry->info.creationTime;
        d->LastAccessTime = entry->info.lastAccessTime;
        d->LastWriteTime = entry->info.lastWriteTime;
        d->ChangeTime = entry->info.lastWriteTime;
        d->EndOfFile.QuadPart = (LONGLONG)entry->info.endOfFile;
        d->AllocationSize.QuadPart = (LONGLONG)entry->info.allocationSize;
        d->FileAttributes = entry->info.fileAttributes;
        d->FileNameLength = entry->nameLength;
        break;
    }
    case FileFullDirectoryInformation:
    {
        FILE_FULL_DIRECTORY_INFORMATION *d = &staged.full;
        memset(d, 0, offsetof(FILE_FULL_DIRECTORY_INFORMATION, FileName));
        d->CreationTime = entry->info.creationTime;
        d->LastAccessTime = entry->info.lastAccessTime;
        d->LastWriteTime = entry->info.lastWriteTime;
        d->ChangeTime = entry->info.lastWriteTime;
        d->EndOfFile.QuadPart = (LONGLONG)entry->info.endOfFile;
        d->AllocationSize.QuadPart = (LONGLONG)entry->info.allocationSize;
        d->FileAttributes = entry->info.fileAttributes;
        d->FileNameLength = entry->nameLength;
        break;
    }
    case FileBothDirectoryInformation:
    {
        FILE_BOTH_DIRECTORY_INFORMATION *d = &staged.both;
        memset(d, 0, offsetof(FILE_BOTH_DIRECTORY_INFORMATION, FileName));
        d->CreationTime = entry->info.creationTime;
        d->LastAccessTime = entry->info.lastAccessTime;
        d->LastWriteTime = entry->info.lastWriteTime;
        d->ChangeTime = entry->info.lastWriteTime;
        d->EndOfFile.QuadPart = (LONGLONG)entry->info.endOfFile;
        d->AllocationSize.QuadPart = (LONGLONG)entry->info.allocationSize;
        d->FileAttributes = entry->info.fileAttributes;
        d->FileNameLength = entry->nameLength;
        IopFillShortName(entry, d->ShortName, &d->ShortNameLength);
        break;
    }
    case FileNamesInformation:
    {
        FILE_NAMES_INFORMATION *d = &staged.names;
        memset(d, 0, offsetof(FILE_NAMES_INFORMATION, FileName));
        d->FileNameLength = entry->nameLength;
        break;
    }
    case FileIdFullDirectoryInformation:
    {
        /* The Full shape + the file id — same fields as IdBoth without the
         * short name, which is the only difference between the two. */
        FILE_ID_FULL_DIRECTORY_INFORMATION *d = &staged.idFull;
        memset(d, 0, offsetof(FILE_ID_FULL_DIRECTORY_INFORMATION, FileName));
        d->CreationTime = entry->info.creationTime;
        d->LastAccessTime = entry->info.lastAccessTime;
        d->LastWriteTime = entry->info.lastWriteTime;
        d->ChangeTime = entry->info.lastWriteTime;
        d->EndOfFile.QuadPart = (LONGLONG)entry->info.endOfFile;
        d->AllocationSize.QuadPart = (LONGLONG)entry->info.allocationSize;
        d->FileAttributes = entry->info.fileAttributes;
        d->FileNameLength = entry->nameLength;
        d->FileId.QuadPart = (LONGLONG)entry->info.fileId;
        break;
    }
    case FileIdBothDirectoryInformation:
    {
        /* CUI-5: the Both shape + the listed entry's file id (the same
         * identity FileInternalInformation serves — fat.h FatFileId).
         * EaSize stays 0 (no EAs on FAT); ShortName is filled through the
         * same one authority as the Both class, so the two classes cannot
         * disagree about an entry. */
        FILE_ID_BOTH_DIRECTORY_INFORMATION *d = &staged.idBoth;
        memset(d, 0, offsetof(FILE_ID_BOTH_DIRECTORY_INFORMATION, FileName));
        d->CreationTime = entry->info.creationTime;
        d->LastAccessTime = entry->info.lastAccessTime;
        d->LastWriteTime = entry->info.lastWriteTime;
        d->ChangeTime = entry->info.lastWriteTime;
        d->EndOfFile.QuadPart = (LONGLONG)entry->info.endOfFile;
        d->AllocationSize.QuadPart = (LONGLONG)entry->info.allocationSize;
        d->FileAttributes = entry->info.fileAttributes;
        d->FileNameLength = entry->nameLength;
        d->FileId.QuadPart = (LONGLONG)entry->info.fileId;
        IopFillShortName(entry, d->ShortName, &d->ShortNameLength);
        break;
    }
    default:
        return; /* not an enumeration class; the caller refused it already */
    }

    memcpy(out, &staged, fixedSize);
    memcpy((char *)out + fixedSize, entry->name, nameBytes);
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
    if (NT_SUCCESS(status))
    {
        /* The mask is the third ring-3 pointer here, and the one that used to
         * be read raw: its Buffer is memcpy'd into the handle's retained
         * dirMask below (docs/review-2026-07 §1a). Same authority as every
         * other counted-string argument. */
        status = ObProbeUnicodeStringRead(mask);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (apc != 0 && ExGetPreviousMode() == UserMode)
    {
        return STATUS_NOT_IMPLEMENTED; /* io.h: user APCs arrive with M7 */
    }
    /* Before the enumeration runs, not at completion time (io.h): a failed
     * call must not have advanced the directory cursor. */
    status = IopValidateEventHandle(event);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    ULONG fixedSize = IopDirEntryFixedSize(informationClass);
    ULONG minimumLength = IopDirEntryMinimumLength(informationClass);
    if (minimumLength == 0)
    {
        return STATUS_INVALID_INFO_CLASS; /* not a class this call knows */
    }
    if (length < minimumLength)
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    if (fixedSize == 0)
    {
        /* Known, big enough, and still not an enumeration class. */
        return STATUS_INVALID_INFO_CLASS;
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
    if (file->device->ops->ReadDirectory == 0)
    {
        /* A directory-shaped device open with no enumeration (the npfs
         * device root, CUI-3): refuse rather than fault. */
        ObDereferenceObject(file);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    /* The mask binds to the handle, and it binds only at the START of a
     * scan: on a handle that has never enumerated, or on a call that also
     * asks to restart. A CONTINUATION call's mask is ignored outright — not
     * merged, not intersected, ignored (the oracle's rule, dlls/ntdll/unix/
     * file.c get_cached_dir_data: the snapshot is discarded and rebuilt only
     * `if (cached && restart_scan && mask && mask differs)`).
     *
     * Rebinding on every call is the same bug from the caller's side: an
     * enumeration is a cursor over a snapshot chosen when the scan began,
     * and callers that pass their mask on every call — kernelbase's
     * FindNextFile, and ntdll:directory's own continuation loop, which
     * passes a matches-nothing `dummy_mask` (directory.c:241) — would lose
     * the rest of the directory. It did: this was worth ~150 of the 203
     * failures at directory.c:620 and all 34 at :265.
     *
     * Pinned by tests/ntapi/sem_file/dir_mask_binding.c. */
    BOOLEAN scanBegins = !file->dirScanStarted || restartScan;
    if (scanBegins && mask != 0 && mask->Length != 0 && mask->Buffer != 0)
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
    BOOLEAN firstScan = !file->dirScanStarted;
    if (scanBegins)
    {
        /* Take the snapshot. A failure here leaves dirScanStarted alone: a
         * call that could not begin a scan must not have begun one. */
        NTSTATUS build = IopBuildDirSnapshot(file);
        if (!NT_SUCCESS(build))
        {
            ObDereferenceObject(file);
            return build;
        }
    }
    else if (restartScan)
    {
        file->dirPosition = 0;
    }
    file->dirScanStarted = TRUE;

    ULONG written = 0;
    /* The previous entry's offset INTO the buffer, not a pointer to it: the
     * NextEntryOffset it needs is a byte-copy to an address whose alignment
     * is the caller's (see IopFillDirEntry), and an offset is what the copy
     * wants anyway. IOP_NO_PREVIOUS_ENTRY rather than 0 — 0 is where the
     * FIRST entry lives, so it cannot double as "there isn't one". */
    ULONG previousOffset = IOP_NO_PREVIOUS_ENTRY;
    ULONG emitted = 0;
    /* No pre-loop seed for `status`: the first thing every iteration does is
     * assign it (the position check or the buffer probe), so a seed here is a
     * store no path can read — which `make format`'s dead-store analysis
     * rejects, and rightly: a seed that can never be observed hides which
     * assignment actually produced the answer. */
    for (;;)
    {
        if (file->dirPosition >= file->dirSnapshotCount)
        {
            status = STATUS_NO_MORE_FILES;
            break;
        }
        IO_DIR_ENTRY entry = file->dirSnapshot[file->dirOrder[file->dirPosition]];
        ULONG cursor = file->dirPosition + 1;

        /* The mask was applied when the snapshot was built; nothing is
         * filtered here. The buffer probe stays per-round even though the
         * loop no longer parks — every ReadDirectory now happens during the
         * build, before a byte of user memory is touched — because it is
         * cheap and keeps the store paths uniform. */
        status = KiProbeForWrite(buffer, length, 1);
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(file);
            return status;
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
        IopFillDirEntry(informationClass, &entry, (char *)buffer + start, fixedSize, nameBytes);
        if (previousOffset != IOP_NO_PREVIOUS_ENTRY)
        {
            /* NextEntryOffset is the first field of every class, and it is
             * written through memcpy for the same reason the entry's fields
             * are: the buffer's alignment belongs to the caller. */
            ULONG delta = start - previousOffset;
            memcpy((char *)buffer + previousOffset, &delta, sizeof(delta));
        }
        previousOffset = start;
        written = start + fixedSize + nameBytes;
        emitted++;
        file->dirPosition = cursor;
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
        /* This class writes the caller's IOSB on FAILURE too — every failure
         * but one. The oracle states it in a line (dlls/ntdll/unix/file.c,
         * the tail of NtQueryDirectoryFile):
         *
         *     if (status != STATUS_NO_SUCH_FILE) io->Status = status;
         *
         * so it is NOT the wineserver's write-only-on-success convention the
         * rest of io/ follows (docs/03) — this call is served by ntdll's own
         * unix path on the oracle, and ntdll:directory depends on the
         * difference: it poisons the block and asserts `io.Status == status`
         * after every continuation query (directory.c:243, 117 failures
         * before this). STATUS_NO_SUCH_FILE alone leaves the bytes alone.
         * Pinned by tests/ntapi/sem_file/dir_iosb.c. */
        if (status != STATUS_NO_SUCH_FILE)
        {
            /* Through the one completion authority (Art. 11) rather than a
             * raw store: the enumeration above parks in the volume gate, so
             * the caller's entry probe is stale and a bare write would
             * ring-0-fault and unwind past this function's cleanup.
             *
             * eventHandle 0 deliberately: whether an empty scan signals the
             * caller's event is NOT pinned — the oracle's path never touches
             * the event in this call at all — so this keeps the event
             * behaviour exactly as it was rather than inventing one. */
            (void)IopCompleteRequest(iosb, 0, status, 0);
        }
        return status;
    }

    NTSTATUS finalStatus = status == STATUS_BUFFER_OVERFLOW ? status : STATUS_SUCCESS;
    status = IopCompleteRequest(iosb, event, finalStatus, written);
    ObDereferenceObject(file);
    return status;
}

/* --- NtQueryVolumeInformationFile (M7 stub -> per-device, M10; the volume
 * classes cmd.exe's dir/vol consume land as CUI polish) ---------------------- */

NTSTATUS NtQueryVolumeInformationFile(HANDLE fileHandle, PIO_STATUS_BLOCK ioStatusBlock,
                                      PVOID buffer, ULONG length, FS_INFORMATION_CLASS infoClass)
{
    if (ioStatusBlock == 0 || buffer == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(ioStatusBlock, sizeof(*ioStatusBlock), sizeof(void *));
    if (NT_SUCCESS(status) && length != 0)
    {
        status = KiProbeForWrite(buffer, length, 1);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* Past the probes the IOSB is written only on SUCCESS: a failing query
     * leaves it untouched, the shape tests/ntapi/sem_file/volume_info.c pins
     * on the drive-root handle (pinned Wine serves that handle through the
     * wineserver, whose synchronous NT_ERROR completions never fill the
     * caller's IOSB — server/async.c async_terminate passes sb as NULL; real
     * NT agrees). Wine's unix-fd path (plain file handles) fills it on
     * failure too; that Wine-internal split is not reproduced — see
     * docs/03-nt-deviations.md. */
    ULONG_PTR information = 0;

    PFILE_OBJECT file;
    status = IopReferenceFileByHandle(fileHandle, 0, &file);
    if (!NT_SUCCESS(status))
    {
        /* Pinned Wine writes iosb.Status (and only Status) for a bad handle
         * on either of its paths: dlls/ntdll/unix/file.c, the early
         * `return io->Status = status` before the fd/device split. */
        ioStatusBlock->Status = status;
        return status;
    }

    switch (infoClass)
    {
    case FileFsDeviceInformation:
    {
        if (length < sizeof(FILE_FS_DEVICE_INFORMATION))
        {
            /* Pinned Wine: a short FileFsDeviceInformation buffer is
             * STATUS_BUFFER_TOO_SMALL (dlls/ntdll/unix/file.c). */
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        /* GetFileType's whole input: the owning device's type (disk vs pipe
         * vs console/serial — kernelbase switches on it,
         * dlls/kernelbase/file.c). */
        FILE_FS_DEVICE_INFORMATION info;
        memset(&info, 0, sizeof(info));
        info.DeviceType = file->device->deviceType;
        memcpy(buffer, &info, sizeof(info));
        information = sizeof(info);
        break;
    }

    /* The three classes kernelbase's GetVolumeInformation(ByHandle)W and
     * GetDiskFreeSpaceExW issue (dlls/kernelbase/volume.c) — cmd.exe's dir
     * silently prints NOTHING when the first one fails. Shapes pinned by
     * tests/ntapi/sem_file/volume_info.c: a short fixed part is
     * INFO_LENGTH_MISMATCH for volume/attribute but BUFFER_TOO_SMALL for
     * size, and label/fs-name truncate silently to the room left. */
    case FileFsVolumeInformation:
    {
        if (file->device->ops->QueryVolumeInfo == 0)
        {
            status = STATUS_NOT_IMPLEMENTED; /* pipes/console: no volume, unbuilt */
            break;
        }
        if (length < sizeof(FILE_FS_VOLUME_INFORMATION))
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        IO_VOLUME_INFO facts;
        status = file->device->ops->QueryVolumeInfo(file->device, &facts);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        /* Re-probed: the gated query above parked, so the entry probe is
         * stale; no park separates this probe from the fill (PR #95 review
         * round 2, F2). */
        status = KiProbeForWrite(buffer, length, 1);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        /* Filled in a local and copied as bytes: the buffer is the caller's
         * and carries the caller's alignment — every WOW64 caller's is
         * 4-aligned (wow64_NtQueryVolumeInformationFile passes it through
         * untranslated), and a store through a struct pointer would inherit
         * that on the LARGE_INTEGER. Same defect class as IopFillDirEntry;
         * pinned by sem_file/volume_unaligned.c. */
        FILE_FS_VOLUME_INFORMATION out;
        ULONG room = length - (ULONG)offsetof(FILE_FS_VOLUME_INFORMATION, VolumeLabel);
        ULONG labelBytes = facts.labelLength < room ? facts.labelLength : room;
        memset(&out, 0, sizeof(out));
        out.VolumeCreationTime.QuadPart = 0; /* pinned Wine reports 0 */
        out.VolumeSerialNumber = facts.serialNumber;
        out.VolumeLabelLength = labelBytes;
        out.SupportsObjects = facts.supportsObjects;
        memcpy(buffer, &out, offsetof(FILE_FS_VOLUME_INFORMATION, VolumeLabel));
        memcpy((char *)buffer + offsetof(FILE_FS_VOLUME_INFORMATION, VolumeLabel), facts.label,
               labelBytes);
        information = offsetof(FILE_FS_VOLUME_INFORMATION, VolumeLabel) + labelBytes;
        break;
    }

    case FileFsSizeInformation:
    {
        if (file->device->ops->QueryVolumeInfo == 0)
        {
            status = STATUS_NOT_IMPLEMENTED; /* no volume behind it, as above */
            break;
        }
        if (length < sizeof(FILE_FS_SIZE_INFORMATION))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        IO_VOLUME_INFO facts;
        status = file->device->ops->QueryVolumeInfo(file->device, &facts);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        /* Re-probed: the gated query above parked, so the entry probe is
         * stale; no park separates this probe from the fill (PR #95 review
         * round 2, F2). */
        status = KiProbeForWrite(buffer, length, 1);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        /* Local + memcpy: the caller's buffer carries the caller's
         * alignment (volume class above). */
        FILE_FS_SIZE_INFORMATION out;
        out.TotalAllocationUnits.QuadPart = (LONGLONG)facts.totalUnits;
        out.AvailableAllocationUnits.QuadPart = (LONGLONG)facts.freeUnits;
        out.SectorsPerAllocationUnit = facts.sectorsPerUnit;
        out.BytesPerSector = facts.bytesPerSector;
        memcpy(buffer, &out, sizeof(out));
        information = sizeof(FILE_FS_SIZE_INFORMATION);
        break;
    }

    case FileFsFullSizeInformation:
    {
        /* CUI-5: the size class's wide form. FAT has no quotas, so caller-
         * available == actual-available (sem_file/volume_info pins caller
         * <= actual — the oracle's statvfs f_bavail excludes ext4's root
         * reserve). Same BUFFER_TOO_SMALL short shape as the size class
         * (pinned Wine dlls/ntdll/unix/file.c). */
        if (file->device->ops->QueryVolumeInfo == 0)
        {
            status = STATUS_NOT_IMPLEMENTED; /* no volume behind it, as above */
            break;
        }
        if (length < sizeof(FILE_FS_FULL_SIZE_INFORMATION))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        IO_VOLUME_INFO facts;
        status = file->device->ops->QueryVolumeInfo(file->device, &facts);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        /* Re-probed: the gated query above parked, so the entry probe is
         * stale; no park separates this probe from the fill (PR #95 review
         * round 2, F2). */
        status = KiProbeForWrite(buffer, length, 1);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        /* Local + memcpy: the caller's buffer carries the caller's
         * alignment (volume class above). */
        FILE_FS_FULL_SIZE_INFORMATION out;
        out.TotalAllocationUnits.QuadPart = (LONGLONG)facts.totalUnits;
        out.CallerAvailableAllocationUnits.QuadPart = (LONGLONG)facts.freeUnits;
        out.ActualAvailableAllocationUnits.QuadPart = (LONGLONG)facts.freeUnits;
        out.SectorsPerAllocationUnit = facts.sectorsPerUnit;
        out.BytesPerSector = facts.bytesPerSector;
        memcpy(buffer, &out, sizeof(out));
        information = sizeof(FILE_FS_FULL_SIZE_INFORMATION);
        break;
    }

    case FileFsAttributeInformation:
    {
        if (file->device->ops->QueryVolumeInfo == 0)
        {
            status = STATUS_NOT_IMPLEMENTED; /* no volume behind it, as above */
            break;
        }
        if (length < sizeof(FILE_FS_ATTRIBUTE_INFORMATION))
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        IO_VOLUME_INFO facts;
        status = file->device->ops->QueryVolumeInfo(file->device, &facts);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        /* Re-probed: the gated query above parked, so the entry probe is
         * stale; no park separates this probe from the fill (PR #95 review
         * round 2, F2). */
        status = KiProbeForWrite(buffer, length, 1);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        /* Local + memcpy: the caller's buffer carries the caller's
         * alignment (volume class above). */
        FILE_FS_ATTRIBUTE_INFORMATION out;
        ULONG room = length - (ULONG)offsetof(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName);
        ULONG nameBytes = facts.fsNameLength < room ? facts.fsNameLength : room;
        memset(&out, 0, sizeof(out));
        out.FileSystemAttributes = facts.fsAttributes;
        out.MaximumComponentNameLength = facts.maxComponentLength;
        out.FileSystemNameLength = nameBytes;
        memcpy(buffer, &out, offsetof(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName));
        memcpy((char *)buffer + offsetof(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName),
               facts.fsName, nameBytes);
        information = offsetof(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName) + nameBytes;
        break;
    }

    default:
        status = STATUS_NOT_IMPLEMENTED; /* the other classes stay off the path */
        break;
    }

    ObDereferenceObject(file);
    if (NT_SUCCESS(status) &&
        NT_SUCCESS(KiProbeForWrite(ioStatusBlock, sizeof(*ioStatusBlock), sizeof(void *))))
    {
        /* IOSB re-probed after the gated queries' parks, the
         * IopCompleteRequest convention: a vanished IOSB skips the store
         * only — the query itself happened, so its status still returns. */
        ioStatusBlock->Status = status;
        ioStatusBlock->Information = information;
    }
    return status;
}

/* --- CUI-5: the EA pair ------------------------------------------------------ */

/* FAT has no extended attributes on either backend, and the pinned Wine
 * answers exactly this shape (dlls/ntdll/unix/file.c: query zeroes the
 * caller's buffer and returns STATUS_NO_EAS_ON_FILE with the IOSB
 * untouched; set refuses STATUS_ACCESS_DENIED). Pinned by
 * sem_file/ea_volume.c. */
NTSTATUS NtQueryEaFile(HANDLE handle, PIO_STATUS_BLOCK iosb, PVOID buffer, ULONG length,
                       BOOLEAN returnSingleEntry, PVOID eaList, ULONG eaListLength, PULONG eaIndex,
                       BOOLEAN restartScan)
{
    (void)iosb; /* deliberately untouched (pinned) */
    (void)returnSingleEntry;
    (void)eaList;
    (void)eaListLength;
    (void)eaIndex;
    (void)restartScan;
    NTSTATUS status;
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
    ObDereferenceObject(file);
    if (buffer != 0 && length != 0)
    {
        memset(buffer, 0, length);
    }
    return STATUS_NO_EAS_ON_FILE;
}

NTSTATUS NtSetEaFile(HANDLE handle, PIO_STATUS_BLOCK iosb, PVOID buffer, ULONG length)
{
    /* Unconditional, never touching the handle — the pinned Wine's arm is
     * exactly this stub (fuzzer-found when a bad-handle call answered
     * INVALID_HANDLE here; pinned by ea_volume.c). */
    (void)handle;
    (void)iosb;
    (void)buffer;
    (void)length;
    return STATUS_ACCESS_DENIED;
}

/* --- CUI-5: NtSetVolumeInformationFile --------------------------------------- */

/* FILE_FS_LABEL_INFORMATION is absent from the pinned Wine's headers (its
 * own set-volume-info is an unconditional-success FIXME stub), so the
 * layout is hand-typed against the official Microsoft documentation
 * ("FILE_FS_LABEL_INFORMATION structure", ntifs.h): the label byte count
 * followed by the label characters (G8). */
/* NOLINTBEGIN(readability-identifier-naming) — a struct transcribed from an
 * external contract keeps the contract's member names (docs/15). */
typedef struct
{
    ULONG VolumeLabelLength;
    WCHAR VolumeLabel[1];
} IOP_FS_LABEL_INFORMATION;
/* NOLINTEND(readability-identifier-naming) */

NTSTATUS NtSetVolumeInformationFile(HANDLE handle, PIO_STATUS_BLOCK iosb, PVOID buffer,
                                    ULONG length, FS_INFORMATION_CLASS infoClass)
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
    /* FILE_WRITE_DATA, not 0. This service MUTATES the on-disk volume label,
     * and a zero-access reference let a FILE_READ_ATTRIBUTES handle do it
     * (docs/review-2026-07 §11). The oracle cannot arbitrate the access
     * here -- its NtSetVolumeInformationFile is a FIXME stub that returns
     * STATUS_SUCCESS without touching anything, i.e. unbuilt in the sense
     * Art. 12 means -- so the requirement follows NT's own rule for
     * IRP_MJ_SET_VOLUME_INFORMATION, which is the same write access the
     * equivalent data mutation needs. The read-side sibling
     * (NtQueryVolumeInformationFile) keeps its zero-access reference,
     * because there the oracle IS built and uses 0. */
    PFILE_OBJECT file;
    status = IopReferenceFileByHandle(handle, FILE_WRITE_DATA, &file);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    switch (infoClass)
    {
    case FileFsLabelInformation:
    {
        /* The one class NT's FAT driver sets (fastfat volinfo.c
         * FatCommonSetVolumeInfo -> FatSetFsLabelInfo); the oracle's stub
         * pins only the SUCCESS status, the write-back is beyond_oracle
         * (sem_file/ea_volume.c). */
        if (length < (ULONG)offsetof(IOP_FS_LABEL_INFORMATION, VolumeLabel))
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        IOP_FS_LABEL_INFORMATION header;
        memcpy(&header, buffer, offsetof(IOP_FS_LABEL_INFORMATION, VolumeLabel));
        if (header.VolumeLabelLength > length - offsetof(IOP_FS_LABEL_INFORMATION, VolumeLabel))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (file->device->ops->SetVolumeLabel == 0)
        {
            status = STATUS_INVALID_PARAMETER; /* no volume behind the handle */
            break;
        }
        /* Capture the label to kernel memory BEFORE the FS op: the op runs
         * under the volume gate (CUI-8), where a fault on a user address
         * would unwind past the gate's release (docs/20 R3 — no user memory
         * under the gate). */
        WCHAR *labelCopy = 0;
        if (header.VolumeLabelLength != 0)
        {
            labelCopy = MiAllocatePool(header.VolumeLabelLength);
            if (labelCopy == 0)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
            /* Probe-then-copy rather than a bare memcpy: a fault on the
             * user label would unwind past this frame without cleanup
             * (uaccess.h), leaking the pool block just allocated. */
            status = KiCopyFromUser(
                labelCopy, (const char *)buffer + offsetof(IOP_FS_LABEL_INFORMATION, VolumeLabel),
                header.VolumeLabelLength);
            if (!NT_SUCCESS(status))
            {
                MiFreePool(labelCopy);
                break;
            }
        }
        status =
            file->device->ops->SetVolumeLabel(file->device, labelCopy, header.VolumeLabelLength);
        if (labelCopy != 0)
        {
            MiFreePool(labelCopy);
        }
        break;
    }
    default:
        /* NT's FAT driver refuses every other set class (fastfat volinfo.c
         * default arm: STATUS_INVALID_PARAMETER); the oracle's arm is an
         * unconditional-success stub — unbuilt, never pinned (Art. 12). */
        status = STATUS_INVALID_PARAMETER;
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
