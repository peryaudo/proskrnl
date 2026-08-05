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
    case FileInternalInformation:
        needed = sizeof(FILE_INTERNAL_INFORMATION);
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
    case FilePipeLocalInformation:
        needed = 0; /* length checking lives in the pipe FS (M9) */
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

    PFILE_OBJECT file;
    status = IopReferenceFileByHandle(handle, 0, &file);
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
        FILE_MODE_INFORMATION *out = buffer;
        out->Mode = IopFileMode(file);
        iosb->Status = STATUS_SUCCESS;
        iosb->Information = sizeof(*out);
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
        FILE_INTERNAL_INFORMATION *out = buffer;
        out->IndexNumber.QuadPart = (LONGLONG)raw.fileId;
        break;
    }
    case FileEndOfFileInformation:
    {
        /* The query side of the set-EOF class: the same size
         * FileStandardInformation reports, which is how the pinned Wine
         * answers it (dlls/ntdll/unix/file.c fills it from the same fstat).
         * ntdll's actctx.c asks it of every manifest file it maps. */
        FILE_END_OF_FILE_INFORMATION *out = buffer;
        out->EndOfFile.QuadPart = (LONGLONG)raw.endOfFile;
        break;
    }
    case FileNetworkOpenInformation:
    {
        /* CUI-5: the by-handle sibling of NtQueryFullAttributesFile — the
         * same times/sizes/attributes facts (pinned Wine fill_file_info;
         * sem_file/info_classes holds it to the basic/standard answers). */
        FILE_NETWORK_OPEN_INFORMATION *out = buffer;
        memset(out, 0, sizeof(*out));
        out->CreationTime = raw.creationTime;
        out->LastAccessTime = raw.lastAccessTime;
        out->LastWriteTime = raw.lastWriteTime;
        out->ChangeTime = raw.lastWriteTime;
        out->AllocationSize.QuadPart = (LONGLONG)raw.allocationSize;
        out->EndOfFile.QuadPart = (LONGLONG)raw.endOfFile;
        out->FileAttributes = raw.fileAttributes;
        break;
    }
    case FileAttributeTagInformation:
    {
        /* CUI-5: GetFileInformationByHandleEx(FileAttributeTagInfo) and
         * GetVolumePathNameW's reparse-point walk. No reparse points exist
         * on FAT; the pinned Wine answers tag 0 for a plain file too. */
        FILE_ATTRIBUTE_TAG_INFORMATION *out = buffer;
        out->FileAttributes = raw.fileAttributes;
        out->ReparseTag = 0;
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
        FILE_ALL_INFORMATION *out = buffer;
        memset(out, 0, offsetof(FILE_ALL_INFORMATION, NameInformation));
        IopFillBasic(&raw, &out->BasicInformation);
        IopFillStandard(&raw, file->fcb, &out->StandardInformation);
        out->InternalInformation.IndexNumber.QuadPart = (LONGLONG)raw.fileId;
        out->PositionInformation.CurrentByteOffset = file->currentByteOffset;
        out->AccessInformation.AccessFlags = file->grantedAccess;
        out->ModeInformation.Mode = IopFileMode(file);
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
        status =
            ObpLookupParseObject(&attributes, &IoDeviceType, &deviceBody, &fsPath, &reparseBuffer);
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
        needed = sizeof(FILE_PIPE_INFORMATION); /* M9: read/completion mode */
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

    PFILE_OBJECT file;
    status = IopReferenceFileByHandle(handle, requiredAccess, &file);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    switch (informationClass)
    {
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
        /* M9: per-end read/completion mode (sem_pipe pins the switch). */
        if (file->device->ops->SetPipeInfo == 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        FILE_PIPE_INFORMATION pipeInfo;
        memcpy(&pipeInfo, buffer, sizeof(pipeInfo));
        status = file->device->ops->SetPipeInfo(file, &pipeInfo);
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
            /* Remainder may start at or before the final '.', anywhere if
             * the name has none — plus consume-all when the name ends with
             * one ("." itself: DOS_STAR alone matches it). */
            ULONG limit = nameUnits;
            BOOLEAN endsWithDot = nameUnits != 0 && name[nameUnits - 1] == '.';
            for (ULONG i = nameUnits; i-- > 0;)
            {
                if (name[i] == '.')
                {
                    limit = i;
                    break;
                }
            }
            for (ULONG skip = 0; skip <= limit; skip++)
            {
                if (IopMatchMask(name + skip, nameUnits - skip, mask + 1, maskUnits - 1))
                {
                    return TRUE;
                }
            }
            return endsWithDot && IopMatchMask(name + nameUnits, 0, mask + 1, maskUnits - 1);
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
    case FileIdBothDirectoryInformation:
    {
        /* CUI-5: the Both shape + the listed entry's file id (the same
         * identity FileInternalInformation serves — fat.h FatFileId).
         * EaSize stays 0 (no EAs on FAT) and ShortName stays empty like
         * the Both class above. */
        FILE_ID_BOTH_DIRECTORY_INFORMATION *d = out;
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
    if (file->device->ops->ReadDirectory == 0)
    {
        /* A directory-shaped device open with no enumeration (the npfs
         * device root, CUI-3): refuse rather than fault. */
        ObDereferenceObject(file);
        return STATUS_INVALID_DEVICE_REQUEST;
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
            !IopMatchEntryName(entry.name, entry.nameLength / sizeof(WCHAR), file->dirMask.Buffer,
                               file->dirMask.Length / sizeof(WCHAR)))
        {
            file->dirCursor = cursor; /* consumed, filtered out */
            continue;
        }

        /* Re-validate the whole output buffer each round: ReadDirectory
         * above goes through the volume gate (CUI-8) and can park, so the
         * probe that last covered the buffer — entry or a previous
         * iteration — is stale. The fill below and the NextEntryOffset
         * back-patch into an earlier record both write inside this range,
         * with no park between probe and store (PR #95 review round 2,
         * F2). */
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
        FILE_FS_VOLUME_INFORMATION *out = buffer;
        ULONG room = length - (ULONG)offsetof(FILE_FS_VOLUME_INFORMATION, VolumeLabel);
        ULONG labelBytes = facts.labelLength < room ? facts.labelLength : room;
        out->VolumeCreationTime.QuadPart = 0; /* pinned Wine reports 0 */
        out->VolumeSerialNumber = facts.serialNumber;
        out->VolumeLabelLength = labelBytes;
        out->SupportsObjects = facts.supportsObjects;
        memcpy(out->VolumeLabel, facts.label, labelBytes);
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
        FILE_FS_SIZE_INFORMATION *out = buffer;
        out->TotalAllocationUnits.QuadPart = (LONGLONG)facts.totalUnits;
        out->AvailableAllocationUnits.QuadPart = (LONGLONG)facts.freeUnits;
        out->SectorsPerAllocationUnit = facts.sectorsPerUnit;
        out->BytesPerSector = facts.bytesPerSector;
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
        FILE_FS_FULL_SIZE_INFORMATION *out = buffer;
        out->TotalAllocationUnits.QuadPart = (LONGLONG)facts.totalUnits;
        out->CallerAvailableAllocationUnits.QuadPart = (LONGLONG)facts.freeUnits;
        out->ActualAvailableAllocationUnits.QuadPart = (LONGLONG)facts.freeUnits;
        out->SectorsPerAllocationUnit = facts.sectorsPerUnit;
        out->BytesPerSector = facts.bytesPerSector;
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
        FILE_FS_ATTRIBUTE_INFORMATION *out = buffer;
        ULONG room = length - (ULONG)offsetof(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName);
        ULONG nameBytes = facts.fsNameLength < room ? facts.fsNameLength : room;
        out->FileSystemAttributes = facts.fsAttributes;
        out->MaximumComponentNameLength = facts.maxComponentLength;
        out->FileSystemNameLength = nameBytes;
        memcpy(out->FileSystemName, facts.fsName, nameBytes);
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
