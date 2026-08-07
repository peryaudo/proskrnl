/* kernel/io/mountmgr.c — \Device\MountPointManager and the volume GUID name.
 *
 * WHY A DEVICE AND NOT A NAME. GetVolumeNameForVolumeMountPointW does not
 * read the object namespace: it opens \\.\MountPointManager and issues
 * IOCTL_MOUNTMGR_QUERY_POINTS, then reads the \??\Volume{...} name out of
 * the reply (Wine dlls/kernelbase/volume.c). So publishing a GUID symlink
 * alone moves nothing — the ioctl is the interface, and the symlink only
 * has to make the name the ioctl reports actually resolve.
 *
 * \Device\MountPointManager is an NT device, so this is not an NT-absent
 * addition (Art. 2), and it is reached through the same Ob namespace and
 * the same IO_VFS_OPS every other device uses rather than through a parser
 * special case (Art. 11).
 *
 * ONE GUID, THREE PLACES. The reply names the volume, the symlink resolves
 * it, and a caller compares the two — so the GUID has exactly one
 * definition here (MountmgrVolumeGuidName) and everything reads it. A
 * second spelling would let the ioctl and the namespace disagree while both
 * looked right in isolation, which is the trap \DosDevices avoided by being
 * a link rather than a second directory. The VALUE is ours: nothing in the
 * boundary pins it (docs/21), so it is a fixed, obviously-synthetic GUID
 * rather than something derived from volume state that could change across
 * a boot and break a caller that cached it.
 */
#include "kernel/io/io.h"
#include "kernel/io/vfs.h"
#include "kernel/ob/ob.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/init/panic.h"

#include "abi/ntioapi.h"
#include "abi/ntobapi.h"

/* The one definition of the volume's GUID name (see the header comment).
 * The braces and hyphens are NT's registry-GUID spelling, which is what
 * kernelbase compares against when it strips the \??\ prefix. */
static const WCHAR MountmgrVolumeGuidName[] =
    WSTR("\\??\\Volume{00000000-0000-0000-0000-000000000001}");

/* The DOS name and the device the mount point maps between. Only the boot
 * volume exists on this machine, so the reply carries exactly one point. */
static const WCHAR MountmgrDosName[] = WSTR("\\DosDevices\\C:");
static const WCHAR MountmgrDeviceName[] = WSTR("\\Device\\HarddiskVolume1");

static IO_FCB IopMountmgrFcb;

static NTSTATUS IopMountmgrCreate(PIO_DEVICE device, PFILE_OBJECT file,
                                  const UNICODE_STRING *path, PFILE_OBJECT relativeTo,
                                  ACCESS_MASK grantedAccess, ULONG shareAccess,
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
    /* No sharing rule, as for \\Device\\Null: file->shareCounted stays FALSE
     * and the Io layer's close path has nothing to release. */
    file->fcb = &IopMountmgrFcb;
    *information = FILE_OPENED;
    return STATUS_SUCCESS;
}

static void IopMountmgrCleanup(PFILE_OBJECT file)
{
    (void)file;
}

static void IopMountmgrClose(PFILE_OBJECT file)
{
    (void)file;
}

static NTSTATUS IopMountmgrGetInfo(PFILE_OBJECT file, IO_FILE_INFO *info)
{
    (void)file;
    memset(info, 0, sizeof(*info));
    info->fileAttributes = FILE_ATTRIBUTE_NORMAL;
    return STATUS_SUCCESS;
}

static NTSTATUS IopMountmgrQueryName(PFILE_OBJECT file, WCHAR *buffer, ULONG capacity,
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

/* Append one name to the reply and fill in its offset/length pair.
 * Offsets are from the START OF THE OUTPUT BUFFER, not from the entry — the
 * detail a hand-built reply gets wrong and the pin checks explicitly. */
static void IopMountmgrAppendName(UCHAR *output, ULONG *cursor, const WCHAR *name, ULONG *offsetOut,
                                  USHORT *lengthOut)
{
    ULONG bytes = (ULONG)KiWideStringLength(name) * sizeof(WCHAR);
    memcpy(output + *cursor, name, bytes);
    *offsetOut = *cursor;
    *lengthOut = (USHORT)bytes;
    *cursor += bytes;
}

static NTSTATUS IopMountmgrQueryPoints(void *output, ULONG outputLength, ULONG_PTR *infoOut)
{
    /* The three names this one mount point carries. UniqueId stays empty:
     * it is a device-identity blob NT fills from the disk, and no caller
     * this boundary serves reads it — a fabricated one would be a
     * plausible-looking invention (Art. 12). */
    /* TWO mount points, not one. NT lists every symbolic link that names the
     * volume as its own entry — the \??\Volume{...} name AND the drive
     * letter — because the reply is what both directions of the mapping are
     * built on: GetVolumeNameForVolumeMountPoint reads the GUID entry, and
     * GetVolumePathNamesForVolumeName scans for entries whose device matches
     * and returns their DOS names. A one-entry reply serves the first and
     * silently returns an empty list from the second (kernel32:volume
     * volume.c:1086 "expected \\C: got """). */
    ULONG needed = (ULONG)sizeof(MOUNTMGR_MOUNT_POINTS) + (ULONG)sizeof(MOUNTMGR_MOUNT_POINT);
    needed += (ULONG)KiWideStringLength(MountmgrVolumeGuidName) * sizeof(WCHAR);
    needed += (ULONG)KiWideStringLength(MountmgrDosName) * sizeof(WCHAR);
    needed += 2 * (ULONG)KiWideStringLength(MountmgrDeviceName) * sizeof(WCHAR);

    /* Below the fixed header the caller cannot even learn the size, so the
     * two-call pattern needs the refusal rather than a truncated answer. */
    if (outputLength < sizeof(MOUNTMGR_MOUNT_POINTS))
    {
        *infoOut = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    MOUNTMGR_MOUNT_POINTS *points = (MOUNTMGR_MOUNT_POINTS *)output;
    if (outputLength < needed)
    {
        /* Enough for the header: report the full size so the caller can
         * allocate, and say the buffer was short. STATUS_BUFFER_OVERFLOW is
         * the "here is the size" answer; BUFFER_TOO_SMALL above is the "I
         * could not even tell you" one. */
        memset(points, 0, sizeof(*points));
        points->Size = needed;
        points->NumberOfMountPoints = 0;
        *infoOut = sizeof(*points);
        return STATUS_BUFFER_OVERFLOW;
    }

    memset(output, 0, needed);
    points->Size = needed;
    points->NumberOfMountPoints = 2;

    /* The names start after BOTH entry slots — MountPoints[] is declared
     * [1], so the second slot's bytes are the ones reserved above. */
    ULONG cursor = (ULONG)sizeof(MOUNTMGR_MOUNT_POINTS) + (ULONG)sizeof(MOUNTMGR_MOUNT_POINT);
    IopMountmgrAppendName((UCHAR *)output, &cursor, MountmgrVolumeGuidName,
                          &points->MountPoints[0].SymbolicLinkNameOffset,
                          &points->MountPoints[0].SymbolicLinkNameLength);
    IopMountmgrAppendName((UCHAR *)output, &cursor, MountmgrDeviceName,
                          &points->MountPoints[0].DeviceNameOffset,
                          &points->MountPoints[0].DeviceNameLength);
    IopMountmgrAppendName((UCHAR *)output, &cursor, MountmgrDosName,
                          &points->MountPoints[1].SymbolicLinkNameOffset,
                          &points->MountPoints[1].SymbolicLinkNameLength);
    IopMountmgrAppendName((UCHAR *)output, &cursor, MountmgrDeviceName,
                          &points->MountPoints[1].DeviceNameOffset,
                          &points->MountPoints[1].DeviceNameLength);
    ASSERT(cursor == needed);

    *infoOut = needed;
    return STATUS_SUCCESS;
}

static NTSTATUS IopMountmgrDeviceControl(PFILE_OBJECT file, ULONG code, const void *input,
                                         ULONG inputLength, void *output, ULONG outputLength,
                                         ULONG_PTR *infoOut, const IO_CONTROL_CONTEXT *request)
{
    (void)file;
    (void)input;
    (void)inputLength;
    (void)request;

    if (code == IOCTL_MOUNTMGR_QUERY_POINTS)
    {
        return IopMountmgrQueryPoints(output, outputLength, infoOut);
    }

    /* Everything else is REFUSED, and the status is the refusal NT gives a
     * device an ioctl it does not implement — not STATUS_NOT_IMPLEMENTED.
     * G12 draws exactly this line: "a refusal a real caller depends on is
     * not this status; it is the specific NT failure
     * (STATUS_INVALID_DEVICE_REQUEST, ...), implemented and pinned like
     * anything else."
     *
     * The caller that forced the distinction is IOCTL_MOUNTMGR_QUERY_UNIX_DRIVE
     * (function 33), which kernel32:volume reaches. It is a WINE EXTENSION —
     * the pinned tree files it under "Wine extensions" in
     * include/ddk/mountmgr.h, alongside DEFINE_UNIX_DRIVE and the shell-folder
     * verbs — so NT has no such ioctl and a conforming mountmgr refuses it.
     * Answering NOT_IMPLEMENTED would claim proskrnl owes an implementation
     * it does not: there is no unix drive to describe on this boundary, and
     * building one would be reproducing Wine rather than NT (Art. 1).
     *
     * This is deliberately NOT an oracle-matching answer. Wine's own mountmgr
     * SERVES this verb, so the oracle cannot be the spec here — pinned in
     * tests/ntapi as a beyond_oracle case against NT's contract for an
     * unrecognized ioctl. */
    DbgPrint("[KTEST] mountmgr: refusing ioctl %#lx\n", (unsigned long)code);
    *infoOut = 0;
    return STATUS_INVALID_DEVICE_REQUEST;
}

static const IO_VFS_OPS IopMountmgrOps = {
    .Create = IopMountmgrCreate,
    .Cleanup = IopMountmgrCleanup,
    .Close = IopMountmgrClose,
    .GetInfo = IopMountmgrGetInfo,
    .QueryName = IopMountmgrQueryName,
    .DeviceControl = IopMountmgrDeviceControl,
};

void IoInitializeMountPointManager(void)
{
    IopInitializeFcb(&IopMountmgrFcb);

    /* FILE_DEVICE_DISK_FILE_SYSTEM is what NT's mountmgr reports; the
     * device type is observable through NtQueryVolumeInformationFile, so it
     * is the real one rather than a convenient default. */
    IoPublishDevice(WSTR("\\Device\\MountPointManager"), &IopMountmgrOps, 0,
                    FILE_DEVICE_DISK_FILE_SYSTEM);

    /* \??\MountPointManager is the name CreateFileW resolves \\.\ to, and
     * \??\Volume{...} is the name the ioctl above hands back — both must
     * exist or the reply names something unopenable. Same helper and same
     * one namespace engine as \??\NUL and \DosDevices (Art. 11). */
    IoCreatePermanentDosLink(WSTR("\\??\\MountPointManager"), WSTR("\\Device\\MountPointManager"));
    IoCreatePermanentDosLink(MountmgrVolumeGuidName, WSTR("\\Device\\HarddiskVolume1"));
}
