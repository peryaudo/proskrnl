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

/* The volume's mount points: every symbolic link that names it. NT lists
 * each as its own entry, and both directions of the volume/path mapping are
 * built on that (a one-entry reply serves
 * GetVolumeNameForVolumeMountPoint and returns an empty list from
 * GetVolumePathNamesForVolumeName). */
static const struct
{
    const WCHAR *symbolicLink;
    const WCHAR *device;
} IopMountmgrPoints[] = {
    {MountmgrVolumeGuidName, MountmgrDeviceName},
    {MountmgrDosName, MountmgrDeviceName},
};

/* Does `candidate` equal the `length`-byte name at `input + offset`? */
static BOOLEAN IopMountmgrNameMatches(const UCHAR *input, ULONG inputLength, ULONG offset,
                                      USHORT length, const WCHAR *candidate)
{
    if ((ULONGLONG)offset + length > inputLength)
    {
        return FALSE;
    }
    ULONG bytes = (ULONG)KiWideStringLength(candidate) * sizeof(WCHAR);
    if (bytes != length)
    {
        return FALSE;
    }
    return memcmp(input + offset, candidate, bytes) == 0;
}

static NTSTATUS IopMountmgrQueryPoints(const void *input, ULONG inputLength, void *output,
                                       ULONG outputLength, ULONG_PTR *infoOut)
{
    /* The input MOUNTMGR_MOUNT_POINT is a FILTER, not a placeholder, and
     * ignoring it is not a harmless simplification.
     * GetVolumePathNamesForVolumeNameW queries once by symbolic-link name
     * and then AGAIN by DeviceName for each point it got back
     * (dlls/kernelbase/volume.c) — so a handler that always returns every
     * point makes the second pass re-match everything and emit each drive
     * letter once per entry. kernel32:volume sees the doubled list as
     * "expected 5 got9" (volume.c:1121), which reads like a length bug and
     * is really a missing filter.
     *
     * All-zero means "every mount point", which is the query kernelbase
     * opens with. */
    /* The argument checks, and their status is STATUS_INVALID_PARAMETER —
     * NOT a buffer status. kernel32:volume states the contract directly
     * (volume.c:2062-2096): a missing or short INPUT, a missing OUTPUT, and
     * an output below the fixed header all take INVALID_PARAMETER, and in
     * every case the IOSB is left untouched (the test seeds it with
     * 0xdeadf00d and asserts it survives) and the output buffer is not
     * written (it seeds 0xcc and asserts output->Size still reads
     * 0xcccccccc).
     *
     * This arm returned STATUS_BUFFER_TOO_SMALL until that pair convicted
     * it. The mistake was not the code but the PIN: sem_ob/mountmgr.c
     * asserted `BUFFER_OVERFLOW || BUFFER_TOO_SMALL || INVALID_PARAMETER`,
     * a disjunction wide enough that no implementation could fail it. A
     * pin that accepts three answers pins none of them. */
    if (input == 0 || inputLength < sizeof(MOUNTMGR_MOUNT_POINT))
    {
        *infoOut = 0;
        return STATUS_INVALID_PARAMETER;
    }
    if (output == 0 || outputLength < sizeof(MOUNTMGR_MOUNT_POINTS))
    {
        *infoOut = 0;
        return STATUS_INVALID_PARAMETER;
    }


    BOOLEAN matched[sizeof(IopMountmgrPoints) / sizeof(IopMountmgrPoints[0])];
    ULONG matchCount = 0;
    const MOUNTMGR_MOUNT_POINT *filter = (const MOUNTMGR_MOUNT_POINT *)input;
    BOOLEAN filtered = filter->SymbolicLinkNameLength != 0 || filter->DeviceNameLength != 0 ||
                       filter->UniqueIdLength != 0;

    for (ULONG i = 0; i < sizeof(IopMountmgrPoints) / sizeof(IopMountmgrPoints[0]); i++)
    {
        BOOLEAN take = TRUE;
        if (filtered)
        {
            /* Each supplied field must match; an entry carrying none of
             * them cannot be selected by it. UniqueId is never matched
             * because this device reports none (see below), so a query by
             * UniqueId alone selects nothing rather than everything. */
            take = FALSE;
            if (filter->SymbolicLinkNameLength != 0 &&
                IopMountmgrNameMatches((const UCHAR *)input, inputLength,
                                       filter->SymbolicLinkNameOffset,
                                       filter->SymbolicLinkNameLength,
                                       IopMountmgrPoints[i].symbolicLink))
            {
                take = TRUE;
            }
            if (filter->DeviceNameLength != 0 &&
                IopMountmgrNameMatches((const UCHAR *)input, inputLength,
                                       filter->DeviceNameOffset, filter->DeviceNameLength,
                                       IopMountmgrPoints[i].device))
            {
                take = TRUE;
            }
        }
        matched[i] = take;
        if (take)
        {
            matchCount++;
        }
    }

    /* Sizing: the header carries one entry slot, so only the entries beyond
     * the first need their own. UniqueId stays empty — it is a disk-identity
     * blob no caller here reads, and a fabricated one is the
     * plausible-looking invention Art. 12 forbids. */
    ULONG needed = (ULONG)sizeof(MOUNTMGR_MOUNT_POINTS);
    if (matchCount > 1)
    {
        needed += (matchCount - 1) * (ULONG)sizeof(MOUNTMGR_MOUNT_POINT);
    }
    for (ULONG i = 0; i < sizeof(IopMountmgrPoints) / sizeof(IopMountmgrPoints[0]); i++)
    {
        if (matched[i])
        {
            needed += (ULONG)KiWideStringLength(IopMountmgrPoints[i].symbolicLink) * sizeof(WCHAR);
            needed += (ULONG)KiWideStringLength(IopMountmgrPoints[i].device) * sizeof(WCHAR);
        }
    }

    MOUNTMGR_MOUNT_POINTS *points = (MOUNTMGR_MOUNT_POINTS *)output;
    if (outputLength < needed)
    {
        /* Enough for the header: report the full size so the caller can
         * allocate. BUFFER_OVERFLOW is the "here is the size" answer;
         * BUFFER_TOO_SMALL above is the "I could not even tell you" one. */
        memset(points, 0, sizeof(*points));
        points->Size = needed;
        points->NumberOfMountPoints = 0;
        *infoOut = sizeof(*points);
        return STATUS_BUFFER_OVERFLOW;
    }

    memset(output, 0, needed);
    points->Size = needed;
    points->NumberOfMountPoints = matchCount;

    ULONG cursor = (ULONG)sizeof(MOUNTMGR_MOUNT_POINTS);
    if (matchCount > 1)
    {
        cursor += (matchCount - 1) * (ULONG)sizeof(MOUNTMGR_MOUNT_POINT);
    }
    ULONG slot = 0;
    for (ULONG i = 0; i < sizeof(IopMountmgrPoints) / sizeof(IopMountmgrPoints[0]); i++)
    {
        if (!matched[i])
        {
            continue;
        }
        IopMountmgrAppendName((UCHAR *)output, &cursor, IopMountmgrPoints[i].symbolicLink,
                              &points->MountPoints[slot].SymbolicLinkNameOffset,
                              &points->MountPoints[slot].SymbolicLinkNameLength);
        IopMountmgrAppendName((UCHAR *)output, &cursor, IopMountmgrPoints[i].device,
                              &points->MountPoints[slot].DeviceNameOffset,
                              &points->MountPoints[slot].DeviceNameLength);
        slot++;
    }
    ASSERT(cursor == needed);
    ASSERT(slot == matchCount);

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
        return IopMountmgrQueryPoints(input, inputLength, output, outputLength, infoOut);
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
