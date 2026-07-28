/*
 * sem_file/volume_info.c — NtQueryVolumeInformationFile: the volume classes
 * cmd.exe's `dir` and `vol` hit (CUI polish).
 *
 * kernelbase's GetVolumeInformationW opens the drive root and issues
 * FileFsVolumeInformation (label + serial) then FileFsAttributeInformation
 * (fs name / flags / component length); GetDiskFreeSpaceExW issues
 * FileFsSizeInformation (third_party/wine dlls/kernelbase/volume.c). cmd's
 * `dir` aborts silently — prints nothing at all — when the volume query
 * fails (programs/cmd/directory.c WCMD_dir_trailer path), which is exactly
 * what a kernel without these classes looks like at the prompt.
 *
 * Pinned shapes (Wine dlls/ntdll/unix/file.c NtQueryVolumeInformationFile):
 *   - volume/attribute short buffer (< sizeof of the fixed struct) is
 *     STATUS_INFO_LENGTH_MISMATCH; the size class is STATUS_BUFFER_TOO_SMALL;
 *   - label / fs name are truncated SILENTLY to the buffer room (min(),
 *     no overflow status), and Information counts offsetof + name bytes;
 *   - on FAILURE the IOSB is left untouched. The drive-root handle these
 *     legs run on is a mountmgr DEVICE file under the pinned Wine (no unix
 *     fd: dlls/ntdll/unix/file.c STATUS_BAD_DEVICE_TYPE branch -> the
 *     wineserver get_volume_info request, answered by dlls/mountmgr.sys
 *     device.c harddisk_query_volume), and a synchronous NT_ERROR
 *     completion never fills the caller's IOSB (server/async.c
 *     async_terminate: "the client should not fill the IOSB", sb passed as
 *     NULL) — real NT's shape as well. Wine's OTHER path (plain file
 *     handles, which do have a unix fd) fills the IOSB on failure; that
 *     split is Wine-internal and deliberately NOT pinned here — see
 *     docs/03-nt-deviations.md.
 *
 * Filesystem-dependent values differ across the gate (the oracle prefix
 * reports NTFS, proskrnl's boot volume FAT32), so those legs assert
 * cross-class consistency — SupportsObjects is TRUE exactly for NTFS (both
 * Wine's table and real NT) — never a fixed fs name.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryVolumeInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
                                                     FS_INFORMATION_CLASS);
NTSYSAPI NTSTATUS NTAPI NtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                     PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtOpenFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                   ULONG, ULONG);

START_TEST(volume_info)
{
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    /* The exact handle `vol` ends up on: kernelbase GetVolumeInformationW's
     * directory fallback — NtOpenFile of \??\C: (no trailing slash),
     * SYNCHRONIZE only, share 0, FILE_DIRECTORY_FILE. */
    HANDLE root = NULL;
    init_ustr(&name, W("\\??\\C:"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenFile(&root, SYNCHRONIZE, &attr, &iosb, 0,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    ok(status == STATUS_SUCCESS, "open \\??\\C: -> %08lx", (unsigned long)status);

    /* --- FileFsVolumeInformation ------------------------------------------- */
    char volbuf[sizeof(FILE_FS_VOLUME_INFORMATION) + 256 * sizeof(WCHAR)];
    FILE_FS_VOLUME_INFORMATION *vol = (FILE_FS_VOLUME_INFORMATION *)volbuf;
    ULONG label_off = (ULONG)offsetof(FILE_FS_VOLUME_INFORMATION, VolumeLabel);

    poison_iosb(&iosb);
    memset(volbuf, 0xcc, sizeof(volbuf));
    status =
        NtQueryVolumeInformationFile(root, &iosb, volbuf, sizeof(volbuf), FileFsVolumeInformation);
    ok(status == STATUS_SUCCESS, "volume info -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "volume iosb.Status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == label_off + vol->VolumeLabelLength,
       "volume Information %lu (label %lu bytes)", (unsigned long)iosb.Information,
       (unsigned long)vol->VolumeLabelLength);
    ok((vol->VolumeLabelLength & 1) == 0, "odd label length %lu",
       (unsigned long)vol->VolumeLabelLength);
    ok(vol->SupportsObjects == 0 || vol->SupportsObjects == 1, "SupportsObjects %u",
       vol->SupportsObjects);
    ULONG serial = vol->VolumeSerialNumber;
    BOOLEAN supports_objects = vol->SupportsObjects;

    /* Short buffer: the fixed part must fit whole; failure leaves the IOSB
     * untouched (header comment). */
    poison_iosb(&iosb);
    status = NtQueryVolumeInformationFile(root, &iosb, volbuf, label_off, FileFsVolumeInformation);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short volume buffer -> %08lx",
       (unsigned long)status);
    ok(iosb.Status == IOSB_POISON_STATUS, "short volume iosb.Status %08lx",
       (unsigned long)iosb.Status);
    ok(iosb.Information == (ULONG_PTR)~0ULL, "short volume Information %lu",
       (unsigned long)iosb.Information);

    /* Exactly sizeof: success, label silently truncated to the room left
     * after the fixed part (no overflow status). */
    poison_iosb(&iosb);
    memset(volbuf, 0xcc, sizeof(volbuf));
    status = NtQueryVolumeInformationFile(root, &iosb, volbuf, sizeof(FILE_FS_VOLUME_INFORMATION),
                                          FileFsVolumeInformation);
    ok(status == STATUS_SUCCESS, "sizeof volume buffer -> %08lx", (unsigned long)status);
    ok(vol->VolumeLabelLength <= sizeof(FILE_FS_VOLUME_INFORMATION) - label_off,
       "truncated label %lu bytes", (unsigned long)vol->VolumeLabelLength);
    ok(iosb.Information == label_off + vol->VolumeLabelLength, "truncated volume Information %lu",
       (unsigned long)iosb.Information);

    /* --- FileFsSizeInformation --------------------------------------------- */
    FILE_FS_SIZE_INFORMATION size;
    poison_iosb(&iosb);
    memset(&size, 0xcc, sizeof(size));
    status = NtQueryVolumeInformationFile(root, &iosb, &size, sizeof(size), FileFsSizeInformation);
    ok(status == STATUS_SUCCESS, "size info -> %08lx", (unsigned long)status);
    ok(iosb.Information == sizeof(size), "size Information %lu", (unsigned long)iosb.Information);
    /* Both sides answer in 512-byte sectors: Wine's non-CD branch fixes 512
     * (dlls/ntdll/unix/file.c get_full_size_info), FAT32's BPB is validated
     * to 512 on proskrnl. */
    ok(size.BytesPerSector == 512, "BytesPerSector %lu", (unsigned long)size.BytesPerSector);
    ok(size.SectorsPerAllocationUnit > 0, "SectorsPerAllocationUnit %lu",
       (unsigned long)size.SectorsPerAllocationUnit);
    ok(size.TotalAllocationUnits.QuadPart > 0, "TotalAllocationUnits %lld",
       (long long)size.TotalAllocationUnits.QuadPart);
    ok(size.AvailableAllocationUnits.QuadPart >= 0 &&
           size.AvailableAllocationUnits.QuadPart <= size.TotalAllocationUnits.QuadPart,
       "AvailableAllocationUnits %lld of %lld", (long long)size.AvailableAllocationUnits.QuadPart,
       (long long)size.TotalAllocationUnits.QuadPart);

    poison_iosb(&iosb);
    status =
        NtQueryVolumeInformationFile(root, &iosb, &size, sizeof(size) - 1, FileFsSizeInformation);
    ok(status == STATUS_BUFFER_TOO_SMALL, "short size buffer -> %08lx", (unsigned long)status);
    ok(iosb.Status == IOSB_POISON_STATUS, "short size iosb.Status %08lx",
       (unsigned long)iosb.Status);
    ok(iosb.Information == (ULONG_PTR)~0ULL, "short size Information %lu",
       (unsigned long)iosb.Information);

    /* --- CUI-5: FileFsFullSizeInformation ----------------------------------- */
    /* No baked kernelbase caller (GetDiskFreeSpaceEx uses the size class
     * above), but the class completes the volume query surface (docs/16).
     * Pinned Wine (dlls/ntdll/unix/file.c get_full_size_info): same facts,
     * with caller-available == actual-available (no quotas on either
     * backend), and the same BUFFER_TOO_SMALL short-buffer shape. */
    {
        FILE_FS_FULL_SIZE_INFORMATION full_size;
        poison_iosb(&iosb);
        memset(&full_size, 0xcc, sizeof(full_size));
        status = NtQueryVolumeInformationFile(root, &iosb, &full_size, sizeof(full_size),
                                              FileFsFullSizeInformation);
        ok(status == STATUS_SUCCESS, "full-size info -> %08lx", (unsigned long)status);
        ok(iosb.Information == sizeof(full_size), "full-size Information %lu",
           (unsigned long)iosb.Information);
        ok(full_size.BytesPerSector == 512, "full-size BytesPerSector %lu",
           (unsigned long)full_size.BytesPerSector);
        ok(full_size.SectorsPerAllocationUnit == size.SectorsPerAllocationUnit,
           "full-size SectorsPerAllocationUnit %lu vs %lu",
           (unsigned long)full_size.SectorsPerAllocationUnit,
           (unsigned long)size.SectorsPerAllocationUnit);
        ok(full_size.TotalAllocationUnits.QuadPart == size.TotalAllocationUnits.QuadPart,
           "full-size TotalAllocationUnits %lld",
           (long long)full_size.TotalAllocationUnits.QuadPart);
        /* Caller-available <= actual-available (the oracle's statvfs
         * f_bavail excludes ext4's root reserve; FAT has no reserve, so
         * proskrnl answers them equal). */
        ok(full_size.CallerAvailableAllocationUnits.QuadPart <=
               full_size.ActualAvailableAllocationUnits.QuadPart,
           "full-size caller vs actual available");
        ok(full_size.ActualAvailableAllocationUnits.QuadPart >= 0 &&
               full_size.ActualAvailableAllocationUnits.QuadPart <=
                   full_size.TotalAllocationUnits.QuadPart,
           "full-size available %lld of %lld",
           (long long)full_size.ActualAvailableAllocationUnits.QuadPart,
           (long long)full_size.TotalAllocationUnits.QuadPart);

        poison_iosb(&iosb);
        status = NtQueryVolumeInformationFile(root, &iosb, &full_size, sizeof(full_size) - 1,
                                              FileFsFullSizeInformation);
        ok(status == STATUS_BUFFER_TOO_SMALL, "short full-size buffer -> %08lx",
           (unsigned long)status);
        ok(iosb.Status == IOSB_POISON_STATUS, "short full-size iosb untouched %08lx",
           (unsigned long)iosb.Status);
    }

    /* --- FileFsAttributeInformation ---------------------------------------- */
    char attrbuf[sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + 32 * sizeof(WCHAR)];
    FILE_FS_ATTRIBUTE_INFORMATION *fsattr = (FILE_FS_ATTRIBUTE_INFORMATION *)attrbuf;
    ULONG name_off = (ULONG)offsetof(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName);

    poison_iosb(&iosb);
    memset(attrbuf, 0xcc, sizeof(attrbuf));
    status = NtQueryVolumeInformationFile(root, &iosb, attrbuf, sizeof(attrbuf),
                                          FileFsAttributeInformation);
    ok(status == STATUS_SUCCESS, "attribute info -> %08lx", (unsigned long)status);
    ok(iosb.Information == name_off + fsattr->FileSystemNameLength,
       "attribute Information %lu (name %lu bytes)", (unsigned long)iosb.Information,
       (unsigned long)fsattr->FileSystemNameLength);
    ok(fsattr->FileSystemNameLength >= 3 * sizeof(WCHAR) && (fsattr->FileSystemNameLength & 1) == 0,
       "fs name length %lu", (unsigned long)fsattr->FileSystemNameLength);
    /* Every fs in Wine's answer table except CDFS/UDF (which no writable
     * volume reports) preserves case and allows 255-unit components. */
    ok(fsattr->MaximumComponentNameLength == 255, "MaximumComponentNameLength %ld",
       (long)fsattr->MaximumComponentNameLength);
    ok((fsattr->FileSystemAttributes & FILE_CASE_PRESERVED_NAMES) != 0,
       "FileSystemAttributes %08lx", (unsigned long)fsattr->FileSystemAttributes);
    /* SupportsObjects is TRUE exactly for NTFS (Wine's table and real NT
     * agree) — ties the two classes together without pinning the fs name,
     * which differs across the gate (oracle NTFS / proskrnl FAT32). */
    BOOLEAN is_ntfs = fsattr->FileSystemNameLength == 8 && fsattr->FileSystemName[0] == 'N' &&
                      fsattr->FileSystemName[1] == 'T' && fsattr->FileSystemName[2] == 'F' &&
                      fsattr->FileSystemName[3] == 'S';
    ok(supports_objects == is_ntfs, "SupportsObjects %u for fs name of %lu bytes", supports_objects,
       (unsigned long)fsattr->FileSystemNameLength);

    poison_iosb(&iosb);
    status =
        NtQueryVolumeInformationFile(root, &iosb, attrbuf, name_off, FileFsAttributeInformation);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short attribute buffer -> %08lx",
       (unsigned long)status);
    ok(iosb.Status == IOSB_POISON_STATUS, "short attribute iosb.Status %08lx",
       (unsigned long)iosb.Status);
    ok(iosb.Information == (ULONG_PTR)~0ULL, "short attribute Information %lu",
       (unsigned long)iosb.Information);

    /* Exactly sizeof: success, name truncated to the room past the fixed
     * part (4 bytes here — every name in the answer table is longer). */
    poison_iosb(&iosb);
    memset(attrbuf, 0xcc, sizeof(attrbuf));
    status = NtQueryVolumeInformationFile(
        root, &iosb, attrbuf, sizeof(FILE_FS_ATTRIBUTE_INFORMATION), FileFsAttributeInformation);
    ok(status == STATUS_SUCCESS, "sizeof attribute buffer -> %08lx", (unsigned long)status);
    ok(fsattr->FileSystemNameLength == sizeof(FILE_FS_ATTRIBUTE_INFORMATION) - name_off,
       "truncated fs name %lu bytes", (unsigned long)fsattr->FileSystemNameLength);
    ok(iosb.Information == name_off + fsattr->FileSystemNameLength,
       "truncated attribute Information %lu", (unsigned long)iosb.Information);

    NtClose(root);

    /* --- any handle on the volume answers, with the same serial ------------
     * (GetVolumeInformationByHandleW runs on whatever handle the caller
     * has — dlls/kernelbase/volume.c.) */
    HANDLE dir = open_test_dir(W("\\??\\C:\\prstest\\volinfo"));
    HANDLE file = NULL;
    status =
        open_file(&file, dir, W("volfile.dat"), FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OVERWRITE_IF,
                  FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, &iosb);
    ok(status == STATUS_SUCCESS, "create volfile.dat -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    memset(volbuf, 0xcc, sizeof(volbuf));
    status =
        NtQueryVolumeInformationFile(file, &iosb, volbuf, sizeof(volbuf), FileFsVolumeInformation);
    ok(status == STATUS_SUCCESS, "file-handle volume info -> %08lx", (unsigned long)status);
    ok(vol->VolumeSerialNumber == serial, "file-handle serial %08lx vs root %08lx",
       (unsigned long)vol->VolumeSerialNumber, (unsigned long)serial);

    NtClose(file);
    NtClose(dir);
}
