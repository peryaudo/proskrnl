/* kernel/io/null.c — \Device\Null and its \??\NUL DOS name.
 *
 * The bit bucket every NT has had: reads see end-of-file, writes are
 * consumed and discarded, and any number of openers may hold it at once.
 * Nothing here is invented (Art. 2): NUL is a device the boundary's callers
 * name directly — ntdll's DOS-path resolution turns the reserved name "nul"
 * into \??\NUL, so CreateFileW("nul") and fopen("nul") land here.
 *
 * Convicted by ucrtbase:file's test_std_stream_open, which does
 * `f = fopen("nul", "r")` and then `_fileno(f)` — with no NUL device the
 * open returned NULL and the subtest died on the dereference, printing
 * nothing at all. Pinned by tests/ntapi/sem_file/null_device.c.
 *
 * One FCB for the whole device, like drivers/hid.c: there is no per-open
 * state to keep, and the share-access engine still needs somewhere to put
 * its slots. Unlike hid, the slots are never CLAIMED — NUL is shareable
 * without limit, which is the one behaviour a caller can observe.
 */
#include "kernel/io/io.h"
#include "kernel/io/vfs.h"
#include "kernel/init/panic.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "abi/ntstatus.h"

static IO_FCB IopNullFcb;

static NTSTATUS IopNullCreate(PIO_DEVICE device, PFILE_OBJECT file, const UNICODE_STRING *path,
                              PFILE_OBJECT relativeTo, ACCESS_MASK grantedAccess, ULONG shareAccess,
                              ULONG fileAttributes, ULONG disposition, ULONG options,
                              ULONG_PTR *information)
{
    (void)device;
    (void)relativeTo;
    (void)grantedAccess;
    (void)shareAccess;
    (void)fileAttributes;
    (void)disposition;
    (void)options;
    if (path->Length != 0)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND; /* the device has no namespace */
    }
    /* No IoCheckShareAccess/IoSetShareAccess: NUL imposes no sharing rule,
     * so file->shareCounted stays FALSE and the Io layer's close path has
     * no slots to release. A device that took the slots would start
     * refusing a second opener, which is the divergence this device exists
     * to avoid — ucrtbase:file holds one while opening another. */
    file->fsContext = &IopNullFcb;
    file->fcb = &IopNullFcb;
    file->isDirectory = FALSE;
    *information = FILE_OPENED;
    return STATUS_SUCCESS;
}

static void IopNullCleanup(PFILE_OBJECT file)
{
    (void)file;
}

static void IopNullClose(PFILE_OBJECT file)
{
    (void)file;
}

/* Always empty: zero length, zero allocation, a plain file's attributes. */
static NTSTATUS IopNullGetInfo(PFILE_OBJECT file, IO_FILE_INFO *info)
{
    (void)file;
    memset(info, 0, sizeof(*info));
    info->fileAttributes = FILE_ATTRIBUTE_NORMAL;
    return STATUS_SUCCESS;
}

static NTSTATUS IopNullQueryName(PFILE_OBJECT file, WCHAR *buffer, ULONG capacity, ULONG *lengthOut)
{
    (void)file;
    static const WCHAR name[] = WSTR("\\Device\\Null");
    ULONG full = (ULONG)KiWideStringLength(name) * sizeof(WCHAR);
    *lengthOut = full;
    ULONG copy = full <= capacity ? full : capacity;
    memcpy(buffer, name, copy);
    return full <= capacity ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;
}

/* End of file, always — never a zero-length SUCCESS, which a caller reading
 * in a loop would spin on forever. */
static NTSTATUS IopNullRead(PFILE_OBJECT file, void *buffer, ULONG length, ULONG_PTR *infoOut,
                            IO_CONTROL_CONTEXT *request)
{
    (void)file;
    (void)buffer;
    (void)length;
    (void)request; /* \Device\Null never pends (vfs.h) */
    *infoOut = 0;
    return STATUS_END_OF_FILE;
}

/* Consumed whole: a short write would make callers retry against a device
 * that can never make progress. */
static NTSTATUS IopNullWrite(PFILE_OBJECT file, const void *buffer, ULONG length,
                             ULONG_PTR *infoOut)
{
    (void)file;
    (void)buffer;
    *infoOut = length;
    return STATUS_SUCCESS;
}

static const IO_VFS_OPS IopNullOps = {
    .Create = IopNullCreate,
    .Cleanup = IopNullCleanup,
    .Close = IopNullClose,
    .GetInfo = IopNullGetInfo,
    .QueryName = IopNullQueryName,
    .Read = IopNullRead,
    .Write = IopNullWrite,
};

void IoInitializeNullDevice(void)
{
    IopInitializeFcb(&IopNullFcb);

    /* FILE_DEVICE_NULL is what GetFileType switches on (Wine
     * dlls/kernelbase/file.c: anything not DISK/PIPE/CONSOLE reads as
     * FILE_TYPE_CHAR). */
    IoPublishDevice(WSTR("\\Device\\Null"), &IopNullOps, 0, FILE_DEVICE_NULL);

    HANDLE handle;
    OBJECT_ATTRIBUTES attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.Attributes = OBJ_PERMANENT;
    UNICODE_STRING linkName, target;
    RtlInitUnicodeString(&linkName, WSTR("\\??\\NUL"));
    RtlInitUnicodeString(&target, WSTR("\\Device\\Null"));
    attributes.ObjectName = &linkName;
    NTSTATUS status =
        NtCreateSymbolicLinkObject(&handle, SYMBOLIC_LINK_ALL_ACCESS, &attributes, &target);
    if (!NT_SUCCESS(status))
    {
        KiPanic("IoInitializeNullDevice: cannot create \\??\\NUL");
    }
    NtClose(handle);
}
