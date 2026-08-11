/* kernel/io/mountmgr.c — \Device\MountPointManager.
 *
 * NT's mount-point database, and an NT-PRESENT device rather than an
 * invention (G2): every Windows since 2000 has it, kernelbase opens it by
 * its documented DOS name \\.\MountPointManager, and the ioctl codes and
 * reply shapes come from abi/ntmountmgr.h, generated from the pinned Wine
 * headers (G4).
 *
 * WHY IT EXISTS HERE. A volume has two names — the drive letter \??\C: and
 * the volume GUID \??\Volume{...} — and nothing in the object namespace
 * says they are the same volume. GetVolumeNameForVolumeMountPointW does not
 * search the namespace for the answer; it reads the drive letter's symlink
 * target and then ASKS THIS DEVICE which mount points name that target
 * (dlls/kernelbase/volume.c). With the device absent the call failed
 * ERROR_FILE_NOT_FOUND and took kernel32:drive's remaining four assertions
 * and most of kernel32:volume with it.
 *
 * WHAT IT IS NOT. It is not a database: this kernel mounts exactly one
 * volume, at boot, and never mounts another (fs/fat32, kernel/io/file.c
 * IoMountBootVolume). So the "database" is that one volume's two names, and
 * the query is a comparison against them. When a second volume becomes
 * possible this file grows a list; inventing the list now would be
 * inventing the thing the list is for.
 *
 * Every other verb refuses with STATUS_INVALID_DEVICE_REQUEST and NAMES
 * ITSELF on serial. What matters for G12 is that it is a specific NT
 * failure rather than STATUS_NOT_IMPLEMENTED — a caller can act on the
 * first. Which specific one is NOT measured: the oracle's default arm
 * answers STATUS_NOT_SUPPORTED (dlls/mountmgr.sys/mountmgr.c), no test
 * pins either, and no baked caller sends a verb that reaches here. If one
 * ever does, take the oracle's.
 */
#include "kernel/io/io.h"
#include "kernel/io/vfs.h"
#include "kernel/init/panic.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "abi/ntstatus.h"
#include "abi/ntmountmgr.h"

static IO_FCB IopMountMgrFcb;

/* The boot volume's three names. The GUID is this kernel's own — it names a
 * volume nothing outside the machine has ever seen, so there is no external
 * contract to match, only an internal one: the SAME string must appear in
 * the \??\Volume{...} symlink and in every QUERY_POINTS reply, or
 * GetVolumeNameForVolumeMountPointW returns a name that cannot be opened.
 * Spelled once, here, and used by both (Art. 11).
 *
 * The braces and the 8-4-4-4-12 shape are not decoration: kernelbase
 * recognises a volume name by the literal prefix L"\\??\\Volume{"
 * (dlls/kernelbase/volume.c) and kernel32:volume checks the length of what
 * comes back, so a differently-shaped GUID would be silently skipped. */
#define IOP_BOOT_VOLUME_GUID   WSTR("\\??\\Volume{00000000-0000-0000-0000-000000000001}")
#define IOP_BOOT_VOLUME_DEVICE WSTR("\\Device\\HarddiskVolume1")
#define IOP_BOOT_VOLUME_LETTER WSTR("\\DosDevices\\C:")

static NTSTATUS IopMountMgrCreate(PIO_DEVICE device, PFILE_OBJECT file, const UNICODE_STRING *path,
                                  PFILE_OBJECT relativeTo, ACCESS_MASK grantedAccess,
                                  ULONG shareAccess, ULONG fileAttributes, ULONG disposition,
                                  ULONG options, ULONG_PTR *information)
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
    /* Shareable without limit, like \Device\Null: kernelbase opens it for
     * the duration of one query and a second caller must not be refused. */
    file->fsContext = &IopMountMgrFcb;
    file->fcb = &IopMountMgrFcb;
    file->isDirectory = FALSE;
    *information = FILE_OPENED;
    return STATUS_SUCCESS;
}

static void IopMountMgrCleanup(PFILE_OBJECT file)
{
    (void)file;
}

static void IopMountMgrClose(PFILE_OBJECT file)
{
    (void)file;
}

static NTSTATUS IopMountMgrGetInfo(PFILE_OBJECT file, IO_FILE_INFO *info)
{
    (void)file;
    memset(info, 0, sizeof(*info));
    info->fileAttributes = FILE_ATTRIBUTE_NORMAL;
    return STATUS_SUCCESS;
}

static NTSTATUS IopMountMgrQueryName(PFILE_OBJECT file, WCHAR *buffer, ULONG capacity,
                                     ULONG *lengthOut)
{
    (void)file;
    static const WCHAR name[] = WSTR("\\Device\\MountPointManager");
    ULONG full = (ULONG)KiWideStringLength(name) * sizeof(WCHAR);
    *lengthOut = full;
    ULONG copy = full <= capacity ? full : capacity;
    memcpy(buffer, name, copy);
    return full <= capacity ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;
}

/* One (offset, length) field of the caller's spec against one of this
 * volume's names, case-insensitively.
 *
 * Compared through const WCHAR pointers rather than through a
 * UNICODE_STRING: the caller's buffer is const here, UNICODE_STRING's
 * Buffer is not, and casting the constness away to reach
 * RtlEqualUnicodeString buys nothing this loop does not do in four lines.
 *
 * The offsets are the CALLER's. QueryPoints has already bounded every one
 * of them against inputLength, so the read below is inside the buffer the
 * Io layer bounced into kernel memory. */
static BOOLEAN IopMountMgrNameEquals(const void *input, ULONG offset, USHORT byteLength,
                                     const WCHAR *name)
{
    if ((byteLength % sizeof(WCHAR)) != 0)
    {
        return FALSE;
    }
    ULONG units = byteLength / (ULONG)sizeof(WCHAR);
    if (units != (ULONG)KiWideStringLength(name))
    {
        return FALSE;
    }
    const UCHAR *base = input;
    const WCHAR *wanted = (const WCHAR *)(base + offset);
    for (ULONG i = 0; i < units; i++)
    {
        if (RtlUpcaseUnicodeChar(wanted[i]) != RtlUpcaseUnicodeChar(name[i]))
        {
            return FALSE;
        }
    }
    return TRUE;
}

/* Does the caller's MOUNTMGR_MOUNT_POINT select the mount point whose
 * symbolic link is `link`?
 *
 * The spec is a FILTER with three independent fields, and each one applies
 * only if its OFFSET is non-zero — that is the oracle's rule verbatim
 * (third_party/wine dlls/mountmgr.sys/mountmgr.c, matching_mount_point:
 * three `if (spec->...Offset)` blocks, each comparing length then
 * characters). A spec with every offset zero selects everything, which is
 * what FindFirstVolume sends.
 *
 * Keying on the OFFSET and not on the length is the part worth stating,
 * because it is the difference between a filter and a fabrication. This
 * device used to consider `DeviceName` alone and treat a zero LENGTH as
 * "match everything" — so a spec naming only a SymbolicLinkName or a
 * UniqueId fell into that branch and was told the boot volume matched.
 * Those are not hypothetical callers: GetVolumePathNamesForVolumeNameW
 * sends exactly those two shapes (dlls/kernelbase/volume.c), so an
 * arbitrary non-existent \??\Volume{...} was being told it is mounted at
 * C:. A wrong answer no caller can distinguish from a right one is the
 * shape G12 exists to forbid, and it was reachable.
 *
 * All three fields are checked against THIS mount point: the two entries
 * this device reports share a device name and a unique id and differ only
 * in their link, so a device-name-only match must still produce both and a
 * link match must produce one. */
static BOOLEAN IopMountMgrMatchesPoint(const void *input, const WCHAR *link)
{
    const MOUNTMGR_MOUNT_POINT *spec = input;
    if (spec->SymbolicLinkNameOffset != 0 &&
        !IopMountMgrNameEquals(input, spec->SymbolicLinkNameOffset, spec->SymbolicLinkNameLength,
                               link))
    {
        return FALSE;
    }
    if (spec->DeviceNameOffset != 0 &&
        !IopMountMgrNameEquals(input, spec->DeviceNameOffset, spec->DeviceNameLength,
                               IOP_BOOT_VOLUME_DEVICE))
    {
        return FALSE;
    }
    /* The unique id is a byte blob to NT (the oracle memcmp's it), and this
     * device's is the device NAME — so it compares like the others, and a
     * caller that echoes back what a previous reply gave it still
     * matches. */
    if (spec->UniqueIdOffset != 0 &&
        !IopMountMgrNameEquals(input, spec->UniqueIdOffset, spec->UniqueIdLength,
                               IOP_BOOT_VOLUME_DEVICE))
    {
        return FALSE;
    }
    return TRUE;
}

/* Append one name to the reply's string pool and fill in its (offset,
 * length) pair. */
static void IopMountMgrAddName(UCHAR *buffer, ULONG *cursor, const WCHAR *name, ULONG *offsetOut,
                               USHORT *lengthOut)
{
    ULONG bytes = (ULONG)KiWideStringLength(name) * sizeof(WCHAR);
    *offsetOut = *cursor;
    *lengthOut = (USHORT)bytes;
    memcpy(buffer + *cursor, name, bytes);
    *cursor += bytes;
}

/* IOCTL_MOUNTMGR_QUERY_POINTS.
 *
 * The reply is one buffer: a MOUNTMGR_MOUNT_POINTS header, then the
 * MOUNTMGR_MOUNT_POINT array, then a pool of NON-terminated strings the
 * entries point into by byte offset from the START of the buffer.
 *
 * A buffer too small for the whole reply is not an error the caller has to
 * guess at: NT fills in Size with the length it needs and answers
 * STATUS_BUFFER_OVERFLOW, and kernelbase's callers pass a fixed 1 KiB and
 * would loop forever on anything else.
 *
 * Two mount points are reported for the one volume — the drive letter and
 * the volume GUID — because that is what the caller is asking for: it hands
 * over a device name and looks through the answers for the one beginning
 * L"\\??\\Volume{". A reply carrying only the GUID would satisfy that
 * caller and would misdescribe the volume to any other. */
static NTSTATUS IopMountMgrQueryPoints(const void *input, ULONG inputLength, void *output,
                                       ULONG outputLength, ULONG_PTR *infoOut)
{
    static const WCHAR *const names[] = {IOP_BOOT_VOLUME_LETTER, IOP_BOOT_VOLUME_GUID};
    const ULONG count = sizeof(names) / sizeof(names[0]);

    /* The oracle's own guard, in its shape (query_mount_points,
     * third_party/wine dlls/mountmgr.sys/mountmgr.c): a short INPUT, a
     * short OUTPUT, or any (offset, length) pair that leaves the input
     * buffer is STATUS_INVALID_PARAMETER, decided before anything is
     * written anywhere.
     *
     * The output floor is sizeof(MOUNTMGR_MOUNT_POINTS) — not the offset of
     * its MountPoints member. The struct declares MountPoints[1], so a
     * buffer with room for the header but not for one entry is REFUSED
     * rather than overflowed, and kernel32:volume asserts exactly that
     * boundary by passing sizeof(*output) - 1 and then sizeof(*output) and
     * requiring different statuses (volume.c:2092 vs :2102). */
    if (input == 0 || inputLength < sizeof(MOUNTMGR_MOUNT_POINT) ||
        outputLength < sizeof(MOUNTMGR_MOUNT_POINTS))
    {
        return STATUS_INVALID_PARAMETER;
    }
    {
        const MOUNTMGR_MOUNT_POINT *point = input;
        /* 64-bit arithmetic so the sum cannot wrap back inside the buffer —
         * the oracle spells the same protection as three explicit
         * `offset + length < offset` tests. */
        uint64_t spans[3][2] = {
            {point->SymbolicLinkNameOffset, point->SymbolicLinkNameLength},
            {point->UniqueIdOffset, point->UniqueIdLength},
            {point->DeviceNameOffset, point->DeviceNameLength},
        };
        for (ULONG i = 0; i < 3; i++)
        {
            if (spans[i][0] + spans[i][1] > inputLength)
            {
                return STATUS_INVALID_PARAMETER;
            }
        }
    }

    /* PER MOUNT POINT, not once for the whole reply: the spec is a FILTER
     * and the two entries differ in their link, so one can match while the
     * other does not. */
    BOOLEAN selected[sizeof(names) / sizeof(names[0])];
    ULONG entries = 0;
    for (ULONG i = 0; i < count; i++)
    {
        selected[i] = IopMountMgrMatchesPoint(input, names[i]);
        if (selected[i])
        {
            entries++;
        }
    }

    ULONG needed = (ULONG)offsetof(MOUNTMGR_MOUNT_POINTS, MountPoints) +
                   entries * (ULONG)sizeof(MOUNTMGR_MOUNT_POINT);
    for (ULONG i = 0; i < count; i++)
    {
        if (!selected[i])
        {
            continue;
        }
        /* The unique id is the device name: this kernel has no persistent
         * per-volume signature to offer, and the device name IS a unique id
         * for a machine with one volume. Reported rather than left empty
         * because a zero-length UniqueId is a claim too. */
        needed +=
            (ULONG)(KiWideStringLength(names[i]) + KiWideStringLength(IOP_BOOT_VOLUME_DEVICE) +
                    KiWideStringLength(IOP_BOOT_VOLUME_DEVICE)) *
            sizeof(WCHAR);
    }

    MOUNTMGR_MOUNT_POINTS *reply = output;
    if (needed > outputLength)
    {
        /* ONLY Size is written, and the reported information is the four
         * bytes OF Size — not the header, not the whole reply. That is the
         * oracle's `info->Size = size; iosb->Information = sizeof(info->Size);`
         * and it is what lets kernel32:volume assert that
         * NumberOfMountPoints still holds the caller's 0xcccccccc poison
         * afterwards (volume.c:2097). A kernel that helpfully zeroed the
         * header here would fail an assertion about untouched memory. */
        reply->Size = needed;
        *infoOut = sizeof(reply->Size);
        return STATUS_BUFFER_OVERFLOW;
    }

    memset(reply, 0, needed);
    reply->Size = needed;
    reply->NumberOfMountPoints = entries;
    ULONG cursor = (ULONG)offsetof(MOUNTMGR_MOUNT_POINTS, MountPoints) +
                   entries * (ULONG)sizeof(MOUNTMGR_MOUNT_POINT);
    ULONG written = 0;
    for (ULONG i = 0; i < count; i++)
    {
        if (!selected[i])
        {
            continue;
        }
        MOUNTMGR_MOUNT_POINT *point = &reply->MountPoints[written++];
        IopMountMgrAddName(output, &cursor, names[i], &point->SymbolicLinkNameOffset,
                           &point->SymbolicLinkNameLength);
        IopMountMgrAddName(output, &cursor, IOP_BOOT_VOLUME_DEVICE, &point->UniqueIdOffset,
                           &point->UniqueIdLength);
        IopMountMgrAddName(output, &cursor, IOP_BOOT_VOLUME_DEVICE, &point->DeviceNameOffset,
                           &point->DeviceNameLength);
    }
    ASSERT(written == entries);
    ASSERT(cursor == needed);
    *infoOut = needed;
    return STATUS_SUCCESS;
}

static NTSTATUS IopMountMgrDeviceControl(PFILE_OBJECT file, ULONG code, const void *input,
                                         ULONG inputLength, void *output, ULONG outputLength,
                                         ULONG_PTR *infoOut, struct IO_CONTROL_CONTEXT *request)
{
    (void)file;
    (void)request;
    *infoOut = 0;
    if (code == IOCTL_MOUNTMGR_QUERY_POINTS)
    {
        return IopMountMgrQueryPoints(input, inputLength, output, outputLength, infoOut);
    }
    /* Named, not silent (Art. 9): the next person to reach this device with
     * a verb it has not got should read which verb off the serial log, not
     * have to bisect for it. */
    DbgPrint("mountmgr: unsupported ioctl %08lx\n", (unsigned long)code);
    return STATUS_INVALID_DEVICE_REQUEST;
}

static const IO_VFS_OPS IopMountMgrOps = {
    .Create = IopMountMgrCreate,
    .Cleanup = IopMountMgrCleanup,
    .Close = IopMountMgrClose,
    .GetInfo = IopMountMgrGetInfo,
    .QueryName = IopMountMgrQueryName,
    .DeviceControl = IopMountMgrDeviceControl,
};

/* One permanent symbolic link, created the way \??\NUL is. */
static void IopMountMgrLink(const WCHAR *linkName, const WCHAR *target)
{
    HANDLE handle;
    OBJECT_ATTRIBUTES attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.Attributes = OBJ_PERMANENT;
    UNICODE_STRING linkString, targetString;
    RtlInitUnicodeString(&linkString, linkName);
    RtlInitUnicodeString(&targetString, target);
    attributes.ObjectName = &linkString;
    NTSTATUS status =
        NtCreateSymbolicLinkObject(&handle, SYMBOLIC_LINK_ALL_ACCESS, &attributes, &targetString);
    if (!NT_SUCCESS(status))
    {
        KiPanic("IoInitializeMountManager: cannot create a boot symbolic link");
    }
    NtClose(handle);
}

/* Called from IoMountBootVolume, AFTER \Device\HarddiskVolume1 and \??\C:
 * exist — the volume GUID link points at the same device and would dangle
 * otherwise. */
void IoInitializeMountManager(void)
{
    IopInitializeFcb(&IopMountMgrFcb);
    /* Device type 0, which is what the oracle passes: `IoCreateDevice(
     * driver, 0, &device_mount_point_manager, 0, 0, FALSE, &device )`
     * (third_party/wine dlls/mountmgr.sys/mountmgr.c) — the second 0 is
     * DeviceType. NOT FILE_DEVICE_UNKNOWN, which is 0x22 and would make
     * FileFsDeviceInformation on this handle answer something the oracle
     * does not. Nothing reads it today; it is 0 because 0 is what the
     * boundary says, not because nothing looks. */
    IoPublishDevice(WSTR("\\Device\\MountPointManager"), &IopMountMgrOps, 0, 0);
    IopMountMgrLink(WSTR("\\??\\MountPointManager"), WSTR("\\Device\\MountPointManager"));
    /* The volume's second name. FindFirstVolume enumerates \?? looking for
     * exactly this prefix, and GetVolumeNameForVolumeMountPoint returns a
     * string the caller then OPENS — so the link has to resolve, not merely
     * be reported. */
    IopMountMgrLink(IOP_BOOT_VOLUME_GUID, IOP_BOOT_VOLUME_DEVICE);
}
