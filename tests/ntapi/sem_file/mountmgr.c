/*
 * sem_file/mountmgr.c — \Device\MountPointManager and
 * IOCTL_MOUNTMGR_QUERY_POINTS.
 *
 * A volume has two names — the drive letter \??\C: and the volume GUID
 * \??\Volume{...} — and NOTHING in the object namespace records that they
 * are the same volume. GetVolumeNameForVolumeMountPointW does not go
 * looking: it reads the drive letter's symlink target and then asks this
 * device which mount points name that target (dlls/kernelbase/volume.c).
 * So the device is not an optimisation over a namespace walk; it is the
 * only place the association exists.
 *
 * What is pinned here is the ioctl's PROTOCOL rather than the answer, since
 * the answer is one machine's volume GUID and means nothing to another:
 *
 *   - a short input, a short output, or an (offset, length) pair that
 *     leaves the input buffer -> STATUS_INVALID_PARAMETER, with nothing
 *     written to the output at all;
 *   - the output floor is sizeof(MOUNTMGR_MOUNT_POINTS), not the offset of
 *     its MountPoints member — the struct declares MountPoints[1], so a
 *     header-sized buffer is REFUSED rather than overflowed;
 *   - too small for the real reply -> STATUS_BUFFER_OVERFLOW with ONLY
 *     Size written, and Information == sizeof(Size). Not the header, not
 *     the whole reply: kernel32:volume checks that NumberOfMountPoints
 *     still holds its own poison afterwards (volume.c:2097), so a kernel
 *     that helpfully zeroed the header would fail an assertion about
 *     untouched memory;
 *   - exactly Size -> success, Information == Size, and at least one mount
 *     point.
 *
 * And the round trip that is the whole point: the volume GUID the device
 * reports must be a name that can actually be OPENED, because
 * GetVolumeNameForVolumeMountPoint's callers open it. A device that
 * reported a plausible GUID with no symbolic link behind it would pass
 * every assertion above.
 *
 * Oracle-first (G5).
 */
#include "util.h"

/* ddk/mountmgr.h — not in mingw's headers. The ioctl code is built from
 * MOUNTMGRCONTROLTYPE ('m') exactly as that header builds it; the oracle
 * run validates it, since a wrong code would answer
 * STATUS_INVALID_DEVICE_REQUEST there. */
#ifndef CTL_CODE
#define CTL_CODE(t, f, m, a) (((t) << 16) | ((a) << 14) | ((f) << 2) | (m))
#endif
#define PRS_MOUNTMGRCONTROLTYPE         ((ULONG)'m')
#define PRS_IOCTL_MOUNTMGR_QUERY_POINTS CTL_CODE(PRS_MOUNTMGRCONTROLTYPE, 2, 0 /* BUFFERED */, 0)

typedef struct
{
    ULONG SymbolicLinkNameOffset;
    USHORT SymbolicLinkNameLength;
    ULONG UniqueIdOffset;
    USHORT UniqueIdLength;
    ULONG DeviceNameOffset;
    USHORT DeviceNameLength;
} PRS_MOUNTMGR_MOUNT_POINT;

typedef struct
{
    ULONG Size;
    ULONG NumberOfMountPoints;
    PRS_MOUNTMGR_MOUNT_POINT MountPoints[1];
} PRS_MOUNTMGR_MOUNT_POINTS;

START_TEST(mountmgr)
{
    HANDLE mgr;
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    PRS_MOUNTMGR_MOUNT_POINT input;
    UCHAR outputBuffer[2048];
    PRS_MOUNTMGR_MOUNT_POINTS *output = (PRS_MOUNTMGR_MOUNT_POINTS *)outputBuffer;

    mgr = CreateFileW(L"\\\\.\\MountPointManager", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                      OPEN_EXISTING, 0, NULL);
    ok(mgr != INVALID_HANDLE_VALUE, "open \\\\.\\MountPointManager -> %lu",
       (unsigned long)GetLastError());
    if (mgr == INVALID_HANDLE_VALUE)
    {
        return;
    }

    /* --- the refusals, and the IOSB they must NOT touch ----------------- */
    iosb.Status = (NTSTATUS)0xdeadf00d;
    iosb.Information = (ULONG_PTR)0xdeadf00d;
    status = NtDeviceIoControlFile(mgr, NULL, NULL, NULL, &iosb, PRS_IOCTL_MOUNTMGR_QUERY_POINTS,
                                   NULL, 0, NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "QUERY_POINTS with no buffers -> %08lx",
       (unsigned long)status);

    memset(&input, 0, sizeof(input));
    iosb.Status = (NTSTATUS)0xdeadf00d;
    status = NtDeviceIoControlFile(mgr, NULL, NULL, NULL, &iosb, PRS_IOCTL_MOUNTMGR_QUERY_POINTS,
                                   &input, sizeof(input) - 1, NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "QUERY_POINTS with a short input -> %08lx",
       (unsigned long)status);

    iosb.Status = (NTSTATUS)0xdeadf00d;
    status = NtDeviceIoControlFile(mgr, NULL, NULL, NULL, &iosb, PRS_IOCTL_MOUNTMGR_QUERY_POINTS,
                                   &input, sizeof(input), NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "QUERY_POINTS with no output -> %08lx",
       (unsigned long)status);

    /* One byte short of a whole MOUNTMGR_MOUNT_POINTS: still a refusal, not
     * an overflow. This is the assertion that separates the two floors. */
    memset(outputBuffer, 0xcc, sizeof(outputBuffer));
    iosb.Status = (NTSTATUS)0xdeadf00d;
    status = NtDeviceIoControlFile(mgr, NULL, NULL, NULL, &iosb, PRS_IOCTL_MOUNTMGR_QUERY_POINTS,
                                   &input, sizeof(input), output, sizeof(*output) - 1);
    ok(status == STATUS_INVALID_PARAMETER, "QUERY_POINTS one byte under the floor -> %08lx",
       (unsigned long)status);
    ok(output->Size == 0xcccccccc, "the refused call wrote Size: %08lx",
       (unsigned long)output->Size);

    /* --- the overflow, and exactly what it writes ----------------------- */
    memset(outputBuffer, 0xcc, sizeof(outputBuffer));
    iosb.Status = (NTSTATUS)0xdeadf00d;
    iosb.Information = (ULONG_PTR)0xdeadf00d;
    status = NtDeviceIoControlFile(mgr, NULL, NULL, NULL, &iosb, PRS_IOCTL_MOUNTMGR_QUERY_POINTS,
                                   &input, sizeof(input), output, sizeof(*output));
    ok(status == STATUS_BUFFER_OVERFLOW, "QUERY_POINTS at the floor -> %08lx",
       (unsigned long)status);
    ok(output->Size > sizeof(*output), "the overflow reported Size %lu, wanted > %lu",
       (unsigned long)output->Size, (unsigned long)sizeof(*output));
    ok(output->NumberOfMountPoints == 0xcccccccc, "the overflow wrote NumberOfMountPoints: %08lx",
       (unsigned long)output->NumberOfMountPoints);

    /* --- the real reply ------------------------------------------------- */
    {
        ULONG needed = output->Size;
        ok(needed <= sizeof(outputBuffer), "the reply wants %lu bytes; widen this test",
           (unsigned long)needed);
        if (needed <= sizeof(outputBuffer))
        {
            ULONG i;
            int sawVolumeGuid = 0;

            memset(outputBuffer, 0xcc, sizeof(outputBuffer));
            iosb.Status = (NTSTATUS)0xdeadf00d;
            iosb.Information = (ULONG_PTR)0xdeadf00d;
            status =
                NtDeviceIoControlFile(mgr, NULL, NULL, NULL, &iosb, PRS_IOCTL_MOUNTMGR_QUERY_POINTS,
                                      &input, sizeof(input), output, needed);
            ok(status == STATUS_SUCCESS, "QUERY_POINTS with the right size -> %08lx",
               (unsigned long)status);
            ok(iosb.Information == needed, "Information %lu, wanted %lu",
               (unsigned long)iosb.Information, (unsigned long)needed);
            ok(output->NumberOfMountPoints > 0, "no mount points reported");

            for (i = 0; i < output->NumberOfMountPoints && i < 16; i++)
            {
                const PRS_MOUNTMGR_MOUNT_POINT *point = &output->MountPoints[i];
                const WCHAR *link =
                    (const WCHAR *)(void *)(outputBuffer + point->SymbolicLinkNameOffset);
                ULONG units = point->SymbolicLinkNameLength / sizeof(WCHAR);
                WCHAR name[128];

                ok(point->SymbolicLinkNameOffset + point->SymbolicLinkNameLength <= needed,
                   "mount point %lu names memory outside the reply", (unsigned long)i);
                if (units == 0 || units >= 100)
                {
                    continue;
                }
                memcpy(name, link, point->SymbolicLinkNameLength);
                name[units] = 0;
                if (units > 11 && memcmp(name, L"\\??\\Volume{", 11 * sizeof(WCHAR)) == 0)
                {
                    HANDLE volume;
                    sawVolumeGuid = 1;
                    /* THE round trip. The reported GUID has to be openable:
                     * GetVolumeNameForVolumeMountPoint's callers open what
                     * it returns, and a device reporting a plausible name
                     * with no symbolic link behind it passes every other
                     * assertion in this file. The Win32 spelling of the
                     * same name replaces "\??\" with "\\.\". */
                    name[1] = L'\\';
                    name[2] = L'.';
                    volume = CreateFileW(name, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                         OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
                    ok(volume != INVALID_HANDLE_VALUE, "open the reported volume name -> %lu",
                       (unsigned long)GetLastError());
                    if (volume != INVALID_HANDLE_VALUE)
                    {
                        CloseHandle(volume);
                    }
                }
            }
            ok(sawVolumeGuid, "no \\??\\Volume{...} mount point in the reply");
        }
    }

    CloseHandle(mgr);
}
