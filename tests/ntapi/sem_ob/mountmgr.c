/*
 * sem_io/mountmgr.c — \Device\MountPointManager and PRS_IOCTL_MOUNTMGR_QUERY_POINTS.
 *
 * WHY THIS EXISTS. kernel32:volume is at 53 failures and kernel32:drive at
 * 4, and they are the SAME defect: there is no volume GUID namespace, so
 * GetVolumeNameForVolumeMountPoint("C:\\") cannot produce a
 * \\?\Volume{...}\ path, FindFirstVolume has nothing to enumerate, and
 * everything downstream fails behind them (docs/21).
 *
 * The interface is not the namespace. GetVolumeNameForVolumeMountPointW
 * opens MOUNTMGR_DOS_DEVICE_NAME and issues PRS_IOCTL_MOUNTMGR_QUERY_POINTS,
 * passing a PRS_MOUNTMGR_MOUNT_POINT and reading back PRS_MOUNTMGR_MOUNT_POINTS
 * (wine/dlls/kernelbase/volume.c). So this file pins the three things that
 * make that call work, and NOTHING about which volumes exist:
 *
 *   1. the device opens under its \?? name;
 *   2. the ioctl answers, sizes itself the way a two-call caller needs, and
 *      returns entries whose offset/length pairs land INSIDE the buffer;
 *   3. the \??\Volume{...} name it hands back actually RESOLVES, and
 *      resolves to the same device as \??\C:.
 *
 * (3) is the one that is easy to half-build: an ioctl that reports a GUID
 * name nothing can open moves some of kernel32:volume's assertions and
 * leaves GetDiskFreeSpace on a GUID path still failing. The GUID's VALUE is
 * ours to choose — nothing pins it — so this file asserts only that the
 * same GUID comes back consistently and that the path resolves to the same
 * volume as C:, which is the property a second, disagreeing allocation site
 * would break.
 *
 * Oracle-first (G5).
 */
#include "util.h"

/* mingw ships no ddk/mountmgr.h, so the shapes are spelled here. Both are
 * transcribed from the pinned tree's wine/include/ddk/mountmgr.h
 * (_MOUNTMGR_MOUNT_POINT, _PRS_MOUNTMGR_MOUNT_POINTS), which is the same header
 * abi/ntioapi.h generates the kernel-side copy from — so the two halves of
 * this boundary cannot drift without that one file changing. The ioctl is
 * its CTL_CODE expression verbatim; MOUNTMGRCONTROLTYPE is 'm' there. */
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

#define PRS_MOUNTMGRCONTROLTYPE ((ULONG)'m')
#define PRS_IOCTL_MOUNTMGR_QUERY_POINTS                                                            \
    CTL_CODE(PRS_MOUNTMGRCONTROLTYPE, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSYSAPI NTSTATUS NTAPI NtOpenFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                   ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                              PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtOpenSymbolicLinkObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI NtQuerySymbolicLinkObject(HANDLE, PUNICODE_STRING, PULONG);

/* Open \??\MountPointManager the way kernelbase does (it spells the same
 * object \\.\MountPointManager, which is the Win32 form of \??\). */
static NTSTATUS open_mountmgr(HANDLE *handle)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    init_ustr(&name, W("\\??\\MountPointManager"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    memset(&iosb, 0, sizeof(iosb));
    return NtOpenFile(handle, GENERIC_READ | SYNCHRONIZE, &attr, &iosb,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
}

START_TEST(mountmgr)
{
    NTSTATUS status;
    HANDLE mgr = NULL;
    IO_STATUS_BLOCK iosb;
    PRS_MOUNTMGR_MOUNT_POINT input;
    static UCHAR out[8192];
    WCHAR volumeName[128];
    ULONG volumeUnits = 0;

    /* --- 1: the device opens ------------------------------------------- */
    status = open_mountmgr(&mgr);
    ok(status == STATUS_SUCCESS, "open \\??\\MountPointManager -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        skip("no MountPointManager; the rest of this file is about its ioctl");
        return;
    }

    /* An all-zero PRS_MOUNTMGR_MOUNT_POINT means "every mount point" — the
     * query kernelbase issues. */
    memset(&input, 0, sizeof(input));

    /* --- 2: the ioctl answers, and sizes itself -------------------------
     * A buffer too small for even the header is the caller's first call in
     * the two-call pattern; it must be refused rather than truncated. */
    memset(&iosb, 0, sizeof(iosb));
    status =
        NtDeviceIoControlFile(mgr, NULL, NULL, NULL, &iosb, PRS_IOCTL_MOUNTMGR_QUERY_POINTS, &input,
                              sizeof(input), out, (ULONG)(sizeof(PRS_MOUNTMGR_MOUNT_POINTS) - 1));
    ok(status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL ||
           status == STATUS_INVALID_PARAMETER,
       "a header-sized-minus-one query -> %08lx", (unsigned long)status);

    memset(&iosb, 0, sizeof(iosb));
    memset(out, 0, sizeof(out));
    status = NtDeviceIoControlFile(mgr, NULL, NULL, NULL, &iosb, PRS_IOCTL_MOUNTMGR_QUERY_POINTS,
                                   &input, sizeof(input), out, (ULONG)sizeof(out));
    ok(status == STATUS_SUCCESS, "query all mount points -> %08lx", (unsigned long)status);

    if (NT_SUCCESS(status))
    {
        PRS_MOUNTMGR_MOUNT_POINTS *points = (PRS_MOUNTMGR_MOUNT_POINTS *)out;
        ok(points->NumberOfMountPoints > 0, "no mount points at all");
        ok(points->Size >= sizeof(PRS_MOUNTMGR_MOUNT_POINTS), "Size %lu is below the header",
           (unsigned long)points->Size);
        ok(points->Size <= sizeof(out), "Size %lu overruns the buffer given",
           (unsigned long)points->Size);

        /* Every entry's offset/length pair must land inside the reported
         * Size. This is the assertion that a hand-built reply gets wrong:
         * offsets are from the START OF THE BUFFER, not from the entry. */
        ULONG bounded = 0, withGuid = 0;
        for (ULONG i = 0; i < points->NumberOfMountPoints; i++)
        {
            PRS_MOUNTMGR_MOUNT_POINT *point = &points->MountPoints[i];
            BOOLEAN symbolicOk =
                point->SymbolicLinkNameLength == 0 ||
                ((ULONGLONG)point->SymbolicLinkNameOffset + point->SymbolicLinkNameLength <=
                 points->Size);
            BOOLEAN deviceOk =
                point->DeviceNameLength == 0 ||
                ((ULONGLONG)point->DeviceNameOffset + point->DeviceNameLength <= points->Size);
            if (symbolicOk && deviceOk)
            {
                bounded++;
            }
            /* Remember the first \??\Volume{...} name for step 3. */
            if (volumeUnits == 0 && symbolicOk &&
                point->SymbolicLinkNameLength > 8 * sizeof(WCHAR) &&
                point->SymbolicLinkNameLength < sizeof(volumeName))
            {
                const WCHAR *link = (const WCHAR *)(out + point->SymbolicLinkNameOffset);
                ULONG units = point->SymbolicLinkNameLength / sizeof(WCHAR);
                /* "\??\Volume{" — compared unit by unit so this needs no
                 * wide-string helpers from the CRT under test. */
                static const WCHAR prefix[] = {'\\', '?', '?', '\\', 'V', 'o',
                                               'l',  'u', 'm', 'e',  '{'};
                BOOLEAN match = TRUE;
                for (unsigned p = 0; p < sizeof(prefix) / sizeof(prefix[0]); p++)
                {
                    if (link[p] != prefix[p])
                    {
                        match = FALSE;
                        break;
                    }
                }
                if (match)
                {
                    memcpy(volumeName, link, point->SymbolicLinkNameLength);
                    volumeUnits = units;
                    withGuid++;
                }
            }
        }
        ok(bounded == points->NumberOfMountPoints,
           "%lu of %lu entries have out-of-bounds name offsets",
           (unsigned long)(points->NumberOfMountPoints - bounded),
           (unsigned long)points->NumberOfMountPoints);
        ok(volumeUnits != 0, "no \\??\\Volume{...} name among the mount points");
    }

    /* --- 3: the GUID name RESOLVES, and names the same volume as C: -----
     * The half-built failure mode is an ioctl that reports a GUID nothing
     * can open. Both opens below are symbolic-link opens, so this compares
     * what the two names point AT, which is the property a second GUID
     * allocation site would break. */
    if (volumeUnits != 0)
    {
        HANDLE viaGuid = NULL, viaLetter = NULL;
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;

        name.Buffer = volumeName;
        name.Length = (USHORT)(volumeUnits * sizeof(WCHAR));
        name.MaximumLength = name.Length;
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        status = NtOpenSymbolicLinkObject(&viaGuid, SYMBOLIC_LINK_QUERY, &attr);
        ok(status == STATUS_SUCCESS, "open the reported \\??\\Volume{...} -> %08lx",
           (unsigned long)status);

        init_ustr(&name, W("\\??\\C:"));
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        status = NtOpenSymbolicLinkObject(&viaLetter, SYMBOLIC_LINK_QUERY, &attr);
        ok(status == STATUS_SUCCESS, "open \\??\\C: -> %08lx", (unsigned long)status);

        if (viaGuid != NULL && viaLetter != NULL)
        {
            WCHAR a[128], b[128];
            UNICODE_STRING ta, tb;
            ULONG ra = 0, rb = 0;
            ta.Buffer = a;
            ta.Length = 0;
            ta.MaximumLength = sizeof(a);
            tb.Buffer = b;
            tb.Length = 0;
            tb.MaximumLength = sizeof(b);
            ok(NtQuerySymbolicLinkObject(viaGuid, &ta, &ra) == STATUS_SUCCESS,
               "query the GUID link");
            ok(NtQuerySymbolicLinkObject(viaLetter, &tb, &rb) == STATUS_SUCCESS,
               "query the C: link");
            ok(ta.Length == tb.Length && memcmp(a, b, ta.Length) == 0,
               "the GUID name and C: resolve to different devices");
        }
        if (viaGuid != NULL)
            NtClose(viaGuid);
        if (viaLetter != NULL)
            NtClose(viaLetter);
    }

    /* --- the GUID is STABLE: a second query reports the same name -------
     * Not a tautology — it is the assertion that fails the moment the GUID
     * is minted per call rather than once (Art. 11, one allocation site). */
    if (volumeUnits != 0)
    {
        static UCHAR again[8192];
        memset(&iosb, 0, sizeof(iosb));
        memset(again, 0, sizeof(again));
        memset(&input, 0, sizeof(input));
        status = NtDeviceIoControlFile(mgr, NULL, NULL, NULL, &iosb, PRS_IOCTL_MOUNTMGR_QUERY_POINTS,
                                       &input, sizeof(input), again, (ULONG)sizeof(again));
        ok(status == STATUS_SUCCESS, "a second query -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            PRS_MOUNTMGR_MOUNT_POINTS *points = (PRS_MOUNTMGR_MOUNT_POINTS *)again;
            BOOLEAN found = FALSE;
            for (ULONG i = 0; i < points->NumberOfMountPoints && !found; i++)
            {
                PRS_MOUNTMGR_MOUNT_POINT *point = &points->MountPoints[i];
                if (point->SymbolicLinkNameLength == volumeUnits * sizeof(WCHAR) &&
                    (ULONGLONG)point->SymbolicLinkNameOffset + point->SymbolicLinkNameLength <=
                        points->Size &&
                    memcmp(again + point->SymbolicLinkNameOffset, volumeName,
                           point->SymbolicLinkNameLength) == 0)
                {
                    found = TRUE;
                }
            }
            ok(found, "the volume GUID changed between two queries");
        }
    }

    NtClose(mgr);
}
