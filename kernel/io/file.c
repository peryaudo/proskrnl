/* kernel/io/file.c — Io initialization, Device/File object types, share
 * access, NtCreateFile/NtOpenFile/NtQueryAttributesFile, and the Mm seam
 * for file-backed sections (see io.h).
 *
 * Boundary semantics pinned by tests/ntapi/sem_file/ on the Wine oracle
 * (create dispositions and IOSB Information verdicts, share modes,
 * delete-on-close, typing errors, case-insensitivity).
 */
#include "kernel/io/io.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/mm/pool.h"
#include "kernel/mm/section.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/init/panic.h"
#include "kernel/ke/ke.h"
#include "drivers/virtio/blk.h"
#include "fs/fat32/fat.h"

/* --- object types ----------------------------------------------------------- */

static void IopDeleteFileObject(PVOID body)
{
    PFILE_OBJECT file = body;
    if (file->fsContext != 0)
    {
        file->device->ops->Close(file);
    }
    if (file->dirMask.Buffer != 0)
    {
        MiFreePool(file->dirMask.Buffer);
    }
    if (file->device != 0)
    {
        ObDereferenceObject(file->device);
    }
}

static void IopCloseFileObject(PVOID body)
{
    /* NT's IRP_MJ_CLEANUP moment: the last HANDLE is gone (references may
     * remain — sections). Release this open's locks and share slots, then
     * let the FS apply delete-on-close. */
    PFILE_OBJECT file = body;
    if (file->fsContext == 0)
    {
        return;
    }
    IopReleaseAllLocks(file->fcb, file);
    if (file->shareCounted)
    {
        IoRemoveShareAccess(file->grantedAccess, file->shareAccess, file->fcb);
        file->shareCounted = FALSE;
    }
    file->device->ops->Cleanup(file);
}

OBJECT_TYPE IoDeviceType = {
    .name = "Device",
    .validAccess = FILE_ALL_ACCESS,
    .waitable = FALSE,
    .deleteProcedure = 0,
    .closeProcedure = 0,
};

OBJECT_TYPE IoFileObjectType = {
    .name = "File",
    .validAccess = FILE_ALL_ACCESS,
    .waitable = TRUE, /* born signaled; see io.h */
    .deleteProcedure = IopDeleteFileObject,
    .closeProcedure = IopCloseFileObject,
};

/* --- share-mode accounting (NT's IoCheckShareAccess/IoSetShareAccess) ------ */

/* The three access bits share modes govern; attribute-only opens carry none
 * of them and bypass the check entirely (the NT rule sem_file/share_modes
 * pins). */
static void IopShareRelevantAccess(ACCESS_MASK desiredAccess, BOOLEAN *reads, BOOLEAN *writes,
                                   BOOLEAN *deletes)
{
    *reads = (desiredAccess & (FILE_READ_DATA | FILE_EXECUTE)) != 0;
    *writes = (desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;
    *deletes = (desiredAccess & DELETE) != 0;
}

NTSTATUS IoCheckShareAccess(ACCESS_MASK desiredAccess, ULONG shareAccess, PIO_FCB fcb)
{
    BOOLEAN reads, writes, deletes;
    IopShareRelevantAccess(desiredAccess, &reads, &writes, &deletes);
    if (!reads && !writes && !deletes)
    {
        return STATUS_SUCCESS; /* attribute-only open */
    }
    IO_SHARE_ACCESS *share = &fcb->shareAccess;
    BOOLEAN sharesRead = (shareAccess & FILE_SHARE_READ) != 0;
    BOOLEAN sharesWrite = (shareAccess & FILE_SHARE_WRITE) != 0;
    BOOLEAN sharesDelete = (shareAccess & FILE_SHARE_DELETE) != 0;

    /* Both directions (the NT rule): what I want must be shared by every
     * existing opener, and what I share must cover what they hold. */
    if ((reads && share->sharedRead != share->openCount) ||
        (writes && share->sharedWrite != share->openCount) ||
        (deletes && share->sharedDelete != share->openCount) ||
        (!sharesRead && share->readers != 0) || (!sharesWrite && share->writers != 0) ||
        (!sharesDelete && share->deleters != 0))
    {
        return STATUS_SHARING_VIOLATION;
    }
    return STATUS_SUCCESS;
}

void IoSetShareAccess(ACCESS_MASK desiredAccess, ULONG shareAccess, PIO_FCB fcb)
{
    BOOLEAN reads, writes, deletes;
    IopShareRelevantAccess(desiredAccess, &reads, &writes, &deletes);
    if (!reads && !writes && !deletes)
    {
        return;
    }
    IO_SHARE_ACCESS *share = &fcb->shareAccess;
    share->openCount++;
    share->readers += reads ? 1 : 0;
    share->writers += writes ? 1 : 0;
    share->deleters += deletes ? 1 : 0;
    share->sharedRead += (shareAccess & FILE_SHARE_READ) ? 1 : 0;
    share->sharedWrite += (shareAccess & FILE_SHARE_WRITE) ? 1 : 0;
    share->sharedDelete += (shareAccess & FILE_SHARE_DELETE) ? 1 : 0;
}

void IoRemoveShareAccess(ACCESS_MASK desiredAccess, ULONG shareAccess, PIO_FCB fcb)
{
    BOOLEAN reads, writes, deletes;
    IopShareRelevantAccess(desiredAccess, &reads, &writes, &deletes);
    if (!reads && !writes && !deletes)
    {
        return;
    }
    IO_SHARE_ACCESS *share = &fcb->shareAccess;
    ASSERT(share->openCount > 0);
    share->openCount--;
    share->readers -= reads ? 1 : 0;
    share->writers -= writes ? 1 : 0;
    share->deleters -= deletes ? 1 : 0;
    share->sharedRead -= (shareAccess & FILE_SHARE_READ) ? 1 : 0;
    share->sharedWrite -= (shareAccess & FILE_SHARE_WRITE) ? 1 : 0;
    share->sharedDelete -= (shareAccess & FILE_SHARE_DELETE) ? 1 : 0;
}

/* --- helpers ---------------------------------------------------------------- */

NTSTATUS IopReferenceFileByHandle(HANDLE handle, ACCESS_MASK desiredAccess, PFILE_OBJECT *fileOut)
{
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(handle, desiredAccess, &IoFileObjectType,
                                                ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *fileOut = body;
    return STATUS_SUCCESS;
}

NTSTATUS IopCompleteRequest(IO_STATUS_BLOCK *iosb, HANDLE eventHandle, NTSTATUS status,
                            ULONG_PTR information)
{
    /* The contract order (docs/08): the IOSB is visible BEFORE any
     * completion signal fires. */
    iosb->Status = status;
    iosb->Information = information;
    if (eventHandle != 0)
    {
        PVOID eventBody;
        NTSTATUS eventStatus = ObReferenceObjectByHandle(
            eventHandle, EVENT_MODIFY_STATE, &ObpEventType, ExGetPreviousMode(), &eventBody, 0);
        if (!NT_SUCCESS(eventStatus))
        {
            return eventStatus;
        }
        KeSetEvent(eventBody, 0, FALSE);
        ObDereferenceObject(eventBody);
    }
    return status;
}

/* --- initialization --------------------------------------------------------- */

static PIO_DEVICE IopBootVolumeDevice;

void IoInitializeTransport(void)
{
    if (!VioBlkInitialize())
    {
        DbgPrint("io: no boot disk; file surface disabled\n");
    }
}

void IoMountBootVolume(void)
{
    if (!VioBlkIsPresent())
    {
        return;
    }
    PFAT_VOLUME volume;
    NTSTATUS status = FatMountBootVolume(&volume);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("io: FAT32 mount failed %08lx\n", (unsigned long)status);
        return;
    }

    /* \Device\HarddiskVolume1 (permanent), then \??\C: -> it. */
    PVOID body;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    RtlInitUnicodeString(&name, WSTR("\\Device\\HarddiskVolume1"));
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = 0;
    attributes.ObjectName = &name;
    attributes.Attributes = OBJ_PERMANENT;
    attributes.SecurityDescriptor = 0;
    attributes.SecurityQualityOfService = 0;
    HANDLE handle;
    status = ObpCreateObjectWithHandle(&IoDeviceType, sizeof(IO_DEVICE), &attributes,
                                       FILE_ALL_ACCESS, &body, &handle);
    if (status != STATUS_SUCCESS)
    {
        KiPanic("IoInitialize: cannot create the volume device");
    }
    PIO_DEVICE device = body;
    device->ops = &FatVfsOps;
    device->context = volume;
    /* A mounted disk filesystem, as the pinned oracle reports one (Wine
     * dlls/ntdll/unix/file.c get_device_info: regular files/directories →
     * FILE_DEVICE_DISK_FILE_SYSTEM; GetFileType maps it to FILE_TYPE_DISK). */
    device->deviceType = FILE_DEVICE_DISK_FILE_SYSTEM;
    IopBootVolumeDevice = device;
    NtClose(handle);

    UNICODE_STRING linkName, target;
    RtlInitUnicodeString(&linkName, WSTR("\\??\\C:"));
    RtlInitUnicodeString(&target, WSTR("\\Device\\HarddiskVolume1"));
    attributes.ObjectName = &linkName;
    status = NtCreateSymbolicLinkObject(&handle, SYMBOLIC_LINK_ALL_ACCESS, &attributes, &target);
    if (!NT_SUCCESS(status))
    {
        KiPanic("IoInitialize: cannot create \\??\\C:");
    }
    NtClose(handle);
}

/* --- NtCreateFile / NtOpenFile ---------------------------------------------- */

static NTSTATUS IopCreateFile(PHANDLE handleOut, ACCESS_MASK desiredAccess,
                              POBJECT_ATTRIBUTES attributes, PIO_STATUS_BLOCK iosb,
                              ULONG fileAttributes, ULONG shareAccess, ULONG disposition,
                              ULONG options)
{
    if (handleOut == 0 || iosb == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(iosb, sizeof(*iosb), sizeof(void *));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (disposition > FILE_MAXIMUM_DISPOSITION)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (attributes == 0 || attributes->ObjectName == 0)
    {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    ACCESS_MASK granted = ObpMapDesiredAccess(&IoFileObjectType, desiredAccess);
    /* Overwrite dispositions carry an implicit FILE_WRITE_ATTRIBUTES grant
     * (Wine server/file.c create_file: FILE_OVERWRITE / FILE_OVERWRITE_IF do
     * `access |= FILE_WRITE_ATTRIBUTES`), which also makes the handle's
     * backing writable for set-EOF (sem_file/info_classes pins this). */
    if (disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF)
    {
        granted |= FILE_WRITE_ATTRIBUTES;
    }

    /* Resolve the device + FS-remaining path. RootDirectory may be an open
     * directory File (a relative open) or an Ob container. */
    PIO_DEVICE device = 0;
    PFILE_OBJECT relativeTo = 0;
    UNICODE_STRING fsPath;
    PWSTR reparseBuffer = 0;

    if (attributes->RootDirectory != 0)
    {
        PVOID rootBody;
        status = ObReferenceObjectByHandle(attributes->RootDirectory, 0, &IoFileObjectType,
                                           ExGetPreviousMode(), &rootBody, 0);
        if (NT_SUCCESS(status))
        {
            relativeTo = rootBody;
            device = relativeTo->device;
            ObfReferenceObject(device);
            fsPath = *attributes->ObjectName;
            if (fsPath.Length >= sizeof(WCHAR) && fsPath.Buffer[0] == '\\')
            {
                ObDereferenceObject(relativeTo);
                ObDereferenceObject(device);
                return STATUS_OBJECT_PATH_SYNTAX_BAD;
            }
        }
    }
    if (device == 0)
    {
        PVOID deviceBody;
        status =
            ObpLookupParseObject(attributes, &IoDeviceType, &deviceBody, &fsPath, &reparseBuffer);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        device = deviceBody;
    }

    /* Build the File object and hand the rest to the FS. */
    PVOID body;
    status = ObpAllocateObject(&IoFileObjectType, sizeof(FILE_OBJECT), &body);
    if (!NT_SUCCESS(status))
    {
        goto out_device;
    }
    PFILE_OBJECT file = body;
    KiInitializeDispatcherHeader(&file->header, KI_OBJECT_NOTIFICATION_EVENT, 1);
    file->device = device; /* the allocation's device reference moves in */
    device = 0;
    file->synchronousIo =
        (options & (FILE_SYNCHRONOUS_IO_NONALERT | FILE_SYNCHRONOUS_IO_ALERT)) != 0;
    file->deleteOnClose = (options & FILE_DELETE_ON_CLOSE) != 0;
    file->grantedAccess = granted;
    file->shareAccess = shareAccess;

    ULONG_PTR information = 0;
    status =
        file->device->ops->Create(file->device, file, &fsPath, relativeTo, granted, shareAccess,
                                  fileAttributes, disposition, options, &information);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(file);
        /* NtCreateFile writes the IOSB on FS-level failure too (pinned
         * Wine: iosb.Status carries the failing status). */
        iosb->Status = status;
        iosb->Information = 0;
        goto out;
    }

    status = ObpCreateHandle(file, granted, attributes->Attributes, handleOut);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(file); /* close/cleanup run via the type hooks */
        iosb->Status = status;
        iosb->Information = 0;
        goto out;
    }
    /* One handle now exists but closeProcedure fires only when handleCount
     * returns to zero; drop the creator's reference. */
    ObDereferenceObject(file);
    iosb->Status = STATUS_SUCCESS;
    iosb->Information = information;
    status = STATUS_SUCCESS;

out:
    if (relativeTo != 0)
    {
        ObDereferenceObject(relativeTo);
    }
    if (reparseBuffer != 0)
    {
        MiFreePool(reparseBuffer);
    }
    return status;

out_device:
    if (device != 0)
    {
        ObDereferenceObject(device);
    }
    goto out;
}

NTSTATUS NtCreateFile(PHANDLE handle, ACCESS_MASK access, POBJECT_ATTRIBUTES attr,
                      PIO_STATUS_BLOCK ioStatus, PLARGE_INTEGER allocSize, ULONG attributes,
                      ULONG sharing, ULONG disposition, ULONG options, PVOID eaBuffer,
                      ULONG eaLength)
{
    (void)allocSize; /* advisory pre-allocation; FAT ignores it */
    if (eaBuffer != 0 && eaLength != 0)
    {
        return STATUS_EAS_NOT_SUPPORTED; /* FAT has no extended attributes */
    }
    return IopCreateFile(handle, access, attr, ioStatus, attributes, sharing, disposition, options);
}

NTSTATUS NtOpenFile(PHANDLE handle, ACCESS_MASK access, POBJECT_ATTRIBUTES attr,
                    PIO_STATUS_BLOCK ioStatus, ULONG sharing, ULONG options)
{
    return IopCreateFile(handle, access, attr, ioStatus, FILE_ATTRIBUTE_NORMAL, sharing, FILE_OPEN,
                         options);
}

NTSTATUS NtQueryAttributesFile(const OBJECT_ATTRIBUTES *attr, FILE_BASIC_INFORMATION *info)
{
    if (info == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(info, sizeof(*info), sizeof(uint64_t));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* An attribute-only internal open (bypasses share modes), query, close. */
    HANDLE handle;
    IO_STATUS_BLOCK iosb;
    PKTHREAD thread = KeGetCurrentThread();
    KPROCESSOR_MODE saved = thread->previousMode;
    thread->previousMode = KernelMode; /* the handle is kernel-internal */
    status = IopCreateFile(&handle, FILE_READ_ATTRIBUTES, (POBJECT_ATTRIBUTES)(uintptr_t)attr,
                           &iosb, FILE_ATTRIBUTE_NORMAL,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0);
    thread->previousMode = saved;
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PFILE_OBJECT file;
    thread->previousMode = KernelMode;
    NTSTATUS refStatus = IopReferenceFileByHandle(handle, 0, &file);
    thread->previousMode = saved;
    ASSERT(NT_SUCCESS(refStatus));
    IO_FILE_INFO raw;
    status = file->device->ops->GetInfo(file, &raw);
    if (NT_SUCCESS(status))
    {
        FILE_BASIC_INFORMATION out;
        memset(&out, 0, sizeof(out));
        out.CreationTime = raw.creationTime;
        out.LastAccessTime = raw.lastAccessTime;
        out.LastWriteTime = raw.lastWriteTime;
        out.ChangeTime = raw.lastWriteTime;
        out.FileAttributes = raw.fileAttributes;
        memcpy(info, &out, sizeof(out));
    }
    ObDereferenceObject(file);
    thread->previousMode = KernelMode;
    NtClose(handle);
    thread->previousMode = saved;
    return status;
}

/* NtQueryAttributesFile's wide sibling: same by-name open, the
 * FILE_NETWORK_OPEN_INFORMATION shape (times + sizes + attributes) that
 * kernelbase's GetFileAttributesExW and msvcrt's stat family consume (Wine
 * dlls/ntdll/unix/file.c NtQueryFullAttributesFile). */
NTSTATUS NtQueryFullAttributesFile(const OBJECT_ATTRIBUTES *attr,
                                   FILE_NETWORK_OPEN_INFORMATION *info)
{
    if (info == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(info, sizeof(*info), sizeof(uint64_t));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    HANDLE handle;
    IO_STATUS_BLOCK iosb;
    PKTHREAD thread = KeGetCurrentThread();
    KPROCESSOR_MODE saved = thread->previousMode;
    thread->previousMode = KernelMode; /* the handle is kernel-internal */
    status = IopCreateFile(&handle, FILE_READ_ATTRIBUTES, (POBJECT_ATTRIBUTES)(uintptr_t)attr,
                           &iosb, FILE_ATTRIBUTE_NORMAL,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0);
    thread->previousMode = saved;
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PFILE_OBJECT file;
    thread->previousMode = KernelMode;
    NTSTATUS refStatus = IopReferenceFileByHandle(handle, 0, &file);
    thread->previousMode = saved;
    ASSERT(NT_SUCCESS(refStatus));
    IO_FILE_INFO raw;
    status = file->device->ops->GetInfo(file, &raw);
    if (NT_SUCCESS(status))
    {
        FILE_NETWORK_OPEN_INFORMATION out;
        memset(&out, 0, sizeof(out));
        out.CreationTime = raw.creationTime;
        out.LastAccessTime = raw.lastAccessTime;
        out.LastWriteTime = raw.lastWriteTime;
        out.ChangeTime = raw.lastWriteTime;
        out.AllocationSize.QuadPart = (LONGLONG)raw.allocationSize;
        out.EndOfFile.QuadPart = (LONGLONG)raw.endOfFile;
        out.FileAttributes = raw.fileAttributes;
        memcpy(info, &out, sizeof(out));
    }
    ObDereferenceObject(file);
    thread->previousMode = KernelMode;
    NtClose(handle);
    thread->previousMode = saved;
    return status;
}

/* --- the Mm seam: file-backed sections (kernel/mm/section.c) ---------------- */

NTSTATUS IopBuildSectionBacking(HANDLE fileHandle, ULONG sectionAttributes, ULONG pageProtection,
                                MI_SECTION_BACKING *backing)
{
    /* The file handle must grant what the section will exercise (the NT
     * rule Wine also applies): read always; write for a writable non-image
     * data section. */
    ACCESS_MASK needed = FILE_READ_DATA;
    if ((sectionAttributes & SEC_IMAGE) == 0)
    {
        ULONG bits = pageProtection & 0xFF;
        if (bits == PAGE_READWRITE || bits == PAGE_EXECUTE_READWRITE)
        {
            needed |= FILE_WRITE_DATA;
        }
    }
    PFILE_OBJECT file;
    NTSTATUS status = IopReferenceFileByHandle(fileHandle, needed, &file);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (file->isDirectory || file->device->ops->GetCache == 0)
    {
        /* Directories and cache-less stream devices (M9 pipes/console)
         * cannot back a section. */
        ObDereferenceObject(file);
        return STATUS_INVALID_FILE_FOR_SECTION;
    }

    PMI_PAGE_CACHE cache;
    status = file->device->ops->GetCache(file, &cache);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(file);
        return status;
    }

    memset(backing, 0, sizeof(*backing));
    backing->cache = cache;
    backing->fileObject = file; /* the caller inherits this reference */

    if (sectionAttributes & SEC_IMAGE)
    {
        /* SEC_IMAGE parses and copies from a contiguous raw snapshot. */
        if (cache->fileSize == 0)
        {
            ObDereferenceObject(file);
            return STATUS_INVALID_FILE_FOR_SECTION;
        }
        void *raw = MiAllocatePool(cache->fileSize);
        if (raw == 0)
        {
            ObDereferenceObject(file);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        MiCacheRead(cache, 0, raw, cache->fileSize);
        backing->rawData = raw;
        backing->rawSize = cache->fileSize;
        backing->ownsRawData = TRUE;
    }

    file->fcb->sectionCount++;
    return STATUS_SUCCESS;
}

void IopSectionBackingReleased(PVOID fileObjectBody)
{
    PFILE_OBJECT file = fileObjectBody;
    ASSERT(file->fcb->sectionCount > 0);
    file->fcb->sectionCount--;
}

/* --- kernel-internal path -> section (the M7 process bootstrap + NLS) ------ */

/* Open `ntPath` with a kernel-internal handle and wrap it in a section:
 * SEC_IMAGE + PAGE_EXECUTE for images, SEC_COMMIT + PAGE_READONLY for data
 * (the same shapes ntdll's own NtCreateSection calls use). The transient
 * handle lives in the current process's handle table; the returned section
 * reference is the caller's. */
static NTSTATUS IopOpenFileSection(const WCHAR *ntPath, ULONG sectionAttributes,
                                   ULONG pageProtection, PMI_SECTION *sectionOut)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, ntPath);
    OBJECT_ATTRIBUTES attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;

    PKTHREAD thread = KeGetCurrentThread();
    KPROCESSOR_MODE saved = thread->previousMode;
    thread->previousMode = KernelMode; /* kernel pointers + a kernel handle */

    HANDLE handle;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status =
        IopCreateFile(&handle, FILE_GENERIC_READ, &attributes, &iosb, FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_OPEN, FILE_NON_DIRECTORY_FILE);
    if (NT_SUCCESS(status))
    {
        MI_SECTION_BACKING backing;
        status = IopBuildSectionBacking(handle, sectionAttributes, pageProtection, &backing);
        if (NT_SUCCESS(status))
        {
            status =
                MiCreateBackedSection(0, pageProtection, sectionAttributes, &backing, sectionOut);
            if (!NT_SUCCESS(status))
            {
                IopSectionBackingReleased(backing.fileObject);
            }
            ObDereferenceObject(backing.fileObject); /* the section holds its own */
        }
        NtClose(handle);
    }
    thread->previousMode = saved;
    return status;
}

NTSTATUS IoOpenImageSection(const WCHAR *ntPath, PMI_SECTION *sectionOut)
{
    return IopOpenFileSection(ntPath, SEC_IMAGE, PAGE_EXECUTE, sectionOut);
}

NTSTATUS IoOpenDataSection(const WCHAR *ntPath, PMI_SECTION *sectionOut)
{
    return IopOpenFileSection(ntPath, SEC_COMMIT, PAGE_READONLY, sectionOut);
}

/* Mm's NtAreMappedFilesTheSame seam: do two File bodies name the same
 * on-disk file? FCB identity answers it — one live FCB per on-disk file is
 * the fs contract (fs/fat32 "one-FCB-per-file rule"), so two opens of one
 * path share the pointer. */
BOOLEAN IoIsSameUnderlyingFile(PVOID fileBody1, PVOID fileBody2)
{
    PFILE_OBJECT file1 = fileBody1;
    PFILE_OBJECT file2 = fileBody2;
    return file1->fcb != 0 && file1->fcb == file2->fcb;
}

/* Kernel-internal directory sweep (the ntapi test runner, kernel/init):
 * open `ntPath` as a directory through the same IopCreateFile path a user
 * open takes and hand every entry — "." and ".." included, as the vfs
 * ReadDirectory op yields them — to `callback`; FALSE stops the sweep. */
NTSTATUS IoEnumerateDirectory(const WCHAR *ntPath,
                              BOOLEAN (*callback)(const IO_DIR_ENTRY *entry, PVOID context),
                              PVOID context)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, ntPath);
    OBJECT_ATTRIBUTES attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;

    PKTHREAD thread = KeGetCurrentThread();
    KPROCESSOR_MODE saved = thread->previousMode;
    thread->previousMode = KernelMode; /* kernel pointers + a kernel handle */

    HANDLE handle;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status = IopCreateFile(&handle, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attributes, &iosb,
                                    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    FILE_OPEN, FILE_DIRECTORY_FILE);
    if (NT_SUCCESS(status))
    {
        PFILE_OBJECT file;
        status = IopReferenceFileByHandle(handle, 0, &file);
        if (NT_SUCCESS(status))
        {
            if (file->device->ops->ReadDirectory == 0)
            {
                status = STATUS_INVALID_DEVICE_REQUEST;
            }
            else
            {
                IO_DIR_ENTRY *entry = MiAllocatePool(sizeof(*entry));
                if (entry == 0)
                {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                }
                else
                {
                    ULONG cursor = 0;
                    for (;;)
                    {
                        status = file->device->ops->ReadDirectory(file, &cursor, entry);
                        if (status == STATUS_NO_MORE_FILES)
                        {
                            status = STATUS_SUCCESS;
                            break;
                        }
                        if (!NT_SUCCESS(status))
                        {
                            break;
                        }
                        if (!callback(entry, context))
                        {
                            break;
                        }
                    }
                    MiFreePool(entry);
                }
            }
            ObDereferenceObject(file);
        }
        NtClose(handle);
    }
    thread->previousMode = saved;
    return status;
}
